#!/usr/bin/env python3
"""Remote Git OpenPGP signing for hosts that have no key of their own.

Two roles, one file, standard library only:

``serve`` runs on the machine that holds the hardware key (the operator's Mac).
It listens on that machine's Tailscale address, accepts signing requests only
from tailnet nodes the operator allowed, shows the same review window the
local ``git-gpg-preview`` wrapper shows, waits for the hardware touch, and
returns the signature.

``client`` runs on a host such as a Linux dev VM as Git's ``gpg.openpgp.program``.
Signing requests are captured, described from the host's own Git objects, and
sent to the service; everything else (``--verify``, key listing) is handed to
the host's real ``gpg``.

Nothing except real GPG output is ever written to the client's stdout, and the
exact captured payload bytes are the only thing GPG ever signs.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

PROGRAM = 'git-gpg-preview-remote'
PROTOCOL_VERSION = 1
DEFAULT_PORT = 24824
# Single source of truth for rejected fixture-style commits; both must match
# FIXTURE_SUBJECTS and FIXTURE_EMAIL_DOMAINS in the git-gpg-preview wrapper.
FIXTURE_SUBJECTS = frozenset('base fixture init initial main production seed work more msg message x'.split())
# Blocked documentation, testing, and local-use domains (RFC 2606, 6761, 6762).
# This fixture heuristic deliberately includes .local, even though legitimate
# identities can use it. A listed domain or any subdomain matches.
FIXTURE_EMAIL_DOMAINS = ('example.com', 'example.net', 'example.org', 'example', 'invalid', 'localhost', 'test', 'local')
TAILNET_V4 = ipaddress.ip_network('100.64.0.0/10')
TAILNET_V6 = ipaddress.ip_network('fd7a:115c:a1e0::/48')
EX_CANCELLED = 1
EX_POLICY = 65
EX_SOFTWARE = 70
MAX_PAYLOAD = 64 * 1024 * 1024
MAX_CONTEXT_TEXT = 4 * 1024 * 1024


class RemoteError(Exception):
    def __init__(self, message: str, status: int = EX_SOFTWARE) -> None:
        super().__init__(message)
        self.status = status


def error(message: str) -> None:
    sys.stderr.write(f'{PROGRAM}: {message}\n')
    sys.stderr.flush()


def config_home() -> Path:
    return Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config'))) / 'git-gpg-preview'


def read_kv(path: Path) -> dict[str, str]:
    """The wrapper's ``key=value`` config format; unknown keys are kept."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text().splitlines():
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        values[key.strip()] = value.strip()
    return values


def write_kv(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    tmp = Path(tempfile.mkstemp(dir=path.parent, prefix='.config.')[1])
    tmp.write_text(''.join(f'{k}={v}\n' for k, v in values.items()))
    tmp.chmod(0o600)
    tmp.replace(path)


# --- Git's GPG interface ----------------------------------------------------

def is_signing_request(args: list[str]) -> bool:
    verify = signing = False
    for arg in args:
        if arg == '--':
            break
        if arg == '--verify':
            verify = True
        elif arg in ('--sign', '--detach-sign', '--clear-sign', '--clearsign'):
            signing = True
        elif arg.startswith('-') and not arg.startswith('--'):
            if 's' in arg[1:] or 'b' in arg[1:]:
                signing = True
    return signing and not verify


def key_selector(args: list[str]) -> str:
    expect = False
    for arg in args:
        if expect:
            return arg
        if arg in ('-u', '--local-user', '--default-key'):
            expect = True
        elif arg.startswith('--local-user=') or arg.startswith('--default-key='):
            return arg.split('=', 1)[1]
        elif arg.startswith('-') and not arg.startswith('--') and arg.endswith('u'):
            expect = True
    return '(not supplied)'


def validate_signing_args(args: list[str]) -> None:
    """Accept only the argument shapes Git uses to sign; refuse anything that
    could redirect output, change the GnuPG home, or alter the key policy."""
    if not is_signing_request(args):
        raise RemoteError('not a signing request', EX_POLICY)
    expect_value = False
    for arg in args:
        if expect_value:
            if arg.startswith('-'):
                raise RemoteError(f'key selector must not be an option: {arg!r}', EX_POLICY)
            expect_value = False
            continue
        if re.fullmatch(r'--status-fd=[0-9]+', arg) or arg in ('--detach-sign', '--sign', '--armor'):
            continue
        if arg == '--status-fd':
            expect_value = True
            continue
        if arg in ('-u', '--local-user'):
            expect_value = True
            continue
        if arg.startswith('--local-user='):
            continue
        if re.fullmatch(r'-[bsau]+', arg):
            expect_value = arg.endswith('u')
            continue
        raise RemoteError(f'unsupported gpg argument for remote signing: {arg!r}', EX_POLICY)
    if expect_value:
        raise RemoteError('key selector missing', EX_POLICY)


def pin_key_selector(args: list[str], fingerprint: str) -> list[str]:
    """Replace the request's key selector with the service fingerprint.
    Refuses a selector that does not name that key."""
    pinned: list[str] = []
    selector = None
    expect = False
    for arg in args:
        if expect:
            selector = arg
            expect = False
            continue
        if arg in ('-u', '--local-user'):
            expect = True
            continue
        if arg.startswith('--local-user='):
            selector = arg.split('=', 1)[1]
            continue
        if re.fullmatch(r'-[bsa]*u', arg):          # -bsau: the u takes the next arg
            pinned.append(arg[:-1] if len(arg) > 2 else '-a')
            if len(arg) == 2:
                pinned.pop()
            expect = True
            continue
        pinned.append(arg)
    if selector is not None:
        wanted = selector.rstrip('!').upper().removeprefix('0X')
        if not wanted or not fingerprint.upper().endswith(wanted):
            raise RemoteError(f'this service signs with {fingerprint}, not the requested key {selector!r}', EX_POLICY)
    return [*pinned, '--local-user', fingerprint]


def sanitize(text: str) -> str:
    return ''.join('?' if (ord(c) < 32 and c not in '\n\t') or ord(c) == 127 else c for c in text)


def one_line(text: str) -> str:
    return sanitize(text).replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')


def limited(text: str, limit: int) -> str:
    if len(text) <= limit:
        return sanitize(text)
    return sanitize(text[:limit]) + '\n[truncated in summary; View Details shows the complete report]\n'


def hexdump(data: bytes) -> str:
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        left = ' '.join(f'{b:02x}' for b in chunk[:8])
        right = ' '.join(f'{b:02x}' for b in chunk[8:])
        text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{offset:08x}  {left:<23}  {right:<23}  |{text}|')
    lines.append(f'{len(data):08x}')
    return '\n'.join(lines) + '\n'


def parse_payload(payload: bytes) -> dict:
    """Classify a Git signing payload the way the wrapper does."""
    text = payload.decode('utf-8', 'replace')
    header, _, message = text.partition('\n\n')
    first = header.split('\n', 1)[0]
    info = {'type': 'unknown', 'tree': '', 'parents': [], 'object': '', 'header': header, 'message': message}
    fields = [line.split(' ', 1) for line in header.split('\n') if ' ' in line]
    if first.startswith('tree '):
        info['type'] = 'commit'
        info['tree'] = next((v for k, v in fields if k == 'tree'), '')
        info['parents'] = [v for k, v in fields if k == 'parent']
    elif first.startswith('object ') and any(k == 'tag' for k, _ in fields):
        info['type'] = 'tag'
        info['object'] = next((v for k, v in fields if k == 'object'), '')
    elif first.startswith('certificate version '):
        info['type'] = 'push certificate'
    return info


def fixture_subject(message: str) -> str | None:
    for line in message.splitlines():
        subject = line.strip().lower()
        if not subject:
            continue
        return subject if subject in FIXTURE_SUBJECTS else None
    return None


def fixture_identity(header: str) -> str | None:
    """Match the wrapper's LC_ALL=C awk parser, including malformed identities."""
    for line in header.split('\n'):
        if not line:
            break
        if not re.match(r'^[ \t]*(author|committer)(?:[ \t]|$)', line) or '<' not in line:
            continue
        email, close, _ = line.rpartition('<')[2].partition('>')
        if not close:
            continue
        email = email.strip(' \t').translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))
        domain = email.rpartition('@')[2].removesuffix('.')
        if any(domain == d or (len(domain) > len(d) + 1 and domain.endswith('.' + d))
               for d in FIXTURE_EMAIL_DOMAINS):
            return email
    return None


def fixture_reason(info: dict) -> str | None:
    """Why a commit payload looks like it came from a test repository."""
    if info['type'] != 'commit':
        return None
    subject = fixture_subject(info['message'])
    if subject:
        return f"subject '{subject}'"
    email = fixture_identity(info['header'])
    return f"identity '{email}'" if email else None


def valid_oid(value: str) -> bool:
    return bool(re.fullmatch(r'[0-9a-fA-F]{40}|[0-9a-fA-F]{64}', value))


# --- Tailscale --------------------------------------------------------------

def tailscale_binary() -> str:
    for candidate in ('tailscale', '/Applications/Tailscale.app/Contents/MacOS/Tailscale',
                      '/usr/local/bin/tailscale', '/opt/homebrew/bin/tailscale'):
        found = shutil.which(candidate) if '/' not in candidate else (candidate if os.access(candidate, os.X_OK) else None)
        if found:
            return found
    raise RemoteError('tailscale CLI not found; the signing service only speaks over the tailnet')


def tailscale_json(*args: str) -> dict:
    result = subprocess.run([tailscale_binary(), *args], capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RemoteError(f'tailscale {" ".join(args)} failed: {result.stderr.strip()}')
    return json.loads(result.stdout)


def tailnet_ip(value: str) -> str | None:
    try:
        ip = ipaddress.ip_address(value.split('/')[0])
    except ValueError:
        return None
    return str(ip) if ip in TAILNET_V4 or ip in TAILNET_V6 else None


def resolve_peer(dns_name: str, port: int) -> tuple[str, int]:
    """Address of the unique online peer with this DNS name, from the local
    daemon's authenticated netmap; never from ordinary DNS."""
    hostname = dns_name.rstrip('.').lower()
    if not hostname.endswith('.ts.net'):
        raise RemoteError('server must be a full Tailscale DNS name ending in .ts.net')
    netmap = tailscale_json('status', '--json')
    if netmap.get('BackendState') != 'Running':
        raise RemoteError('Tailscale is not running on this host')
    peers = [p for p in netmap.get('Peer', {}).values()
             if p.get('DNSName', '').rstrip('.').lower() == hostname]
    if len(peers) != 1 or not peers[0].get('ID'):
        raise RemoteError(f'{hostname} is not a unique Tailscale peer')
    if peers[0].get('Online') is not True:
        raise RemoteError(f'{hostname} is offline; the signing service needs the Mac awake and online')
    for value in peers[0].get('TailscaleIPs', []):
        ip = tailnet_ip(value)
        if ip and ':' not in ip:
            return ip, port
    raise RemoteError(f'{hostname} has no IPv4 Tailscale address')


def self_identity() -> dict:
    netmap = tailscale_json('status', '--json')
    me = netmap.get('Self', {})
    user = netmap.get('User', {}).get(str(me.get('UserID')), {})
    ips = [tailnet_ip(v) for v in me.get('TailscaleIPs', [])]
    return {
        'node': me.get('DNSName', '').rstrip('.').lower(),
        'user_id': str(me.get('UserID', '')),
        'login': user.get('LoginName', ''),
        'ips': [ip for ip in ips if ip],
    }


def whois(ip: str) -> dict:
    data = tailscale_json('whois', '--json', ip)
    node = data.get('Node', {})
    profile = data.get('UserProfile', {})
    return {
        'node': node.get('Name', '').rstrip('.').lower(),
        'user_id': str(node.get('User', '')),
        'login': profile.get('LoginName', ''),
    }


# --- serve ------------------------------------------------------------------

def secret_key_blocks(real_gpg: str, selector: str = '') -> list[list[str]]:
    """Fingerprints of each secret key gpg lists: the primary, then its subkeys."""
    listing = subprocess.run([real_gpg, '--batch', '--with-colons', '--list-secret-keys', *([selector] if selector else [])],
                             stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    blocks: list[list[str]] = []
    for line in listing.stdout.splitlines():
        fields = line.split(':')
        if fields[0] == 'sec':
            blocks.append([])
        elif fields[0] == 'fpr' and blocks and len(fields) > 9:
            blocks[-1].append(fields[9].upper())
    return [block for block in blocks if block]


def resolve_signing_key(real_gpg: str, configured: str = '') -> tuple[str, str]:
    """The fingerprint of the one key the service signs with, and what named it.

    A configured selector wins, then Git's global ``user.signingkey`` (the key
    the operator's own commits carry), then a GnuPG home's only secret key.
    Several secret keys with nothing naming one is refused: the order gpg
    lists them in says nothing about which one the operator signs with.
    A trailing ``!`` is dropped; hosts are handed a plain fingerprint.
    """
    selector, source = configured.strip(), 'signing_key'
    if not selector:
        try:
            git_key = subprocess.run(['git', 'config', '--global', '--get', 'user.signingkey'],
                                     stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
            selector = git_key.stdout.strip() if git_key.returncode == 0 else ''
        except (OSError, subprocess.TimeoutExpired):
            selector = ''
        source = "Git's global user.signingkey"
    if selector:
        wanted = selector.rstrip('!')
        blocks = secret_key_blocks(real_gpg, wanted)
        if len(blocks) != 1:
            found = 'no' if not blocks else 'more than one'
            raise RemoteError(f'{source} {selector!r} names {found} secret key in this GnuPG home; '
                              'set signing_key in the serve config to a full fingerprint (serve-install --signing-key FPR)')
        hexed = wanted.upper().removeprefix('0X')
        if re.fullmatch(r'[0-9A-F]{8,}', hexed):
            # A subkey named by id or fingerprint stays that subkey.
            exact = [fpr for fpr in blocks[0] if fpr.endswith(hexed)]
            if exact:
                return exact[0], source
        return blocks[0][0], source
    blocks = secret_key_blocks(real_gpg)
    if not blocks:
        raise RemoteError('no secret key to sign with; add one to this GnuPG home')
    if len(blocks) > 1:
        raise RemoteError(f'{len(blocks)} secret keys in this GnuPG home and nothing says which one signs '
                          f'({", ".join(block[0] for block in blocks)}); set signing_key in the serve config '
                          "(serve-install --signing-key FPR) or Git's global user.signingkey")
    return blocks[0][0], 'the only secret key'


class ServeConfig:
    def __init__(self, base: Path) -> None:
        wrapper = read_kv(base / 'config')
        own = read_kv(base / 'serve')
        self.real_gpg = own.get('real_gpg') or wrapper.get('real_gpg', '')
        self.ui_helper = own.get('ui_helper') or wrapper.get('ui_helper', '')
        self.lock_root = own.get('lock_root') or wrapper.get('lock_root') or str(Path.home() / 'Library/Caches/git-gpg-preview')
        self.audit_log = own.get('audit_log') or wrapper.get('audit_log', '')
        self.dialog_runner = own.get('dialog_runner', '')
        self.allow_nodes = {n.strip().rstrip('.').lower() for n in own.get('allow_nodes', '').split(',') if n.strip()}
        # Fleet rule: delegated workers run on minidev* hosts, so those nodes
        # may ask for signatures without per-host allowlisting. Every request
        # still needs the operator's touch.
        prefixes = own.get('allow_node_prefixes', 'minidev')
        self.allow_node_prefixes = tuple(x.strip().lower() for x in prefixes.split(',') if x.strip())
        self.port = int(own.get('port') or DEFAULT_PORT)
        self.bind = own.get('bind', '')
        self.sign_timeout = float(own.get('sign_timeout_seconds') or 120)
        self.signing_key = own.get('signing_key', '')
        if not self.real_gpg.startswith('/') or not os.access(self.real_gpg, os.X_OK):
            raise RemoteError('real_gpg must name an executable absolute path (run git-gpg-preview install first)')
        if not self.dialog_runner and (not self.ui_helper.startswith('/') or not Path(self.ui_helper).is_file()):
            raise RemoteError('ui_helper must name the installed dialog (run git-gpg-preview install first)')


class DialogLock:
    """The wrapper's `shlock -p $$ -f dialog.lock` protocol, in Python.

    The lock file holds the owner's pid; it is free when absent or when that
    pid is dead. Sharing the protocol (not just the path) with the local
    wrapper is what guarantees that a local `git commit` and a remote request
    are never both waiting on the one hardware touch at the same time.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.held = False

    @staticmethod
    def _alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def acquire(self) -> None:
        # The pid is written to a private file first and linked onto the lock
        # path: link() is atomic and fails if the lock exists, so the lock
        # file is never seen empty. A stale lock is claimed by renaming it to a
        # private name before its owner is re-read, so two acquirers can never
        # both decide it is stale and both proceed.
        pid = os.getpid()
        mine = self.path.with_name(f'{self.path.name}.{pid}.{os.urandom(4).hex()}')
        mine.write_text(str(pid))
        mine.chmod(0o600)
        try:
            while True:
                try:
                    os.link(mine, self.path)
                except FileExistsError:
                    pass
                else:
                    self.held = True
                    return
                try:
                    owner = int(self.path.read_text().strip() or '0')
                except (OSError, ValueError):
                    owner = 0
                if owner and self._alive(owner):
                    time.sleep(0.2)
                    continue
                claim = self.path.with_name(f'{self.path.name}.stale.{pid}.{os.urandom(4).hex()}')
                try:
                    os.rename(self.path, claim)   # atomic: only one acquirer gets the stale file
                except FileNotFoundError:
                    continue
                try:
                    still = int(claim.read_text().strip() or '0')
                except (OSError, ValueError):
                    still = 0
                if still and self._alive(still) and still != owner:
                    # The file was replaced by a live owner between our read
                    # and the rename: give it back and wait.
                    try:
                        os.rename(claim, self.path)
                    except OSError:
                        pass
                    time.sleep(0.2)
                    continue
                claim.unlink(missing_ok=True)
        finally:
            mine.unlink(missing_ok=True)

    def release(self) -> None:
        if not self.held:
            return
        try:
            if self.path.read_text().strip() == str(os.getpid()):
                self.path.unlink()
        except OSError:
            pass
        self.held = False

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()


class Service:
    """One signing request at a time, behind the same dialog lock as the wrapper."""

    def __init__(self, config: ServeConfig, me: dict) -> None:
        self.config = config
        self.me = me
        self.lock = threading.Lock()
        self.allowed_logins = {me['login']} if me.get('login') else set()
        self._fingerprint = ''
        self.key_source = ''

    # -- authorization
    def authorize(self, peer_ip: str) -> dict:
        if tailnet_ip(peer_ip) is None and self.config.bind == '':
            raise RemoteError(f'peer {peer_ip} is not a tailnet address', 403)
        who = whois(peer_ip)
        if who['node'] in self.config.allow_nodes:
            return who
        if who['node'] and who['node'].startswith(self.config.allow_node_prefixes):
            return who
        if who['user_id'] and who['user_id'] == self.me.get('user_id'):
            return who
        raise RemoteError(f'peer {who["node"] or peer_ip} is not allowed to request signatures', 403)

    # -- identity
    def service_fingerprint(self) -> str:
        """The one key this service signs with (see resolve_signing_key),
        resolved once and cached. Requests may not choose another."""
        if not self._fingerprint:
            self._fingerprint, self.key_source = resolve_signing_key(self.config.real_gpg, self.config.signing_key)
        return self._fingerprint

    def identity(self) -> dict:
        gpg = self.config.real_gpg
        fingerprint = self.service_fingerprint()
        if not fingerprint:
            raise RemoteError('no secret key available to advertise', 503)
        export = subprocess.run([gpg, '--batch', '--armor', '--export', fingerprint],
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
        if export.returncode or 'BEGIN PGP PUBLIC KEY BLOCK' not in export.stdout:
            raise RemoteError('could not export the signing public key', 503)
        uid = subprocess.run([gpg, '--batch', '--with-colons', '--list-keys', fingerprint],
                             stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30).stdout
        uids = [line.split(':')[9] for line in uid.splitlines() if line.startswith('uid:')]
        return {'version': PROTOCOL_VERSION, 'node': self.me['node'], 'login': self.me['login'],
                'fingerprint': fingerprint, 'uids': uids, 'public_key': export.stdout}

    # -- audit
    def audit(self, decision: str, repo: str, kind: str, digest: str, peer: str) -> None:
        log = self.config.audit_log
        if not log:
            return
        path = Path(log)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.parent.chmod(0o700)
        with path.open('a') as f:
            path.chmod(0o600)
            stamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            f.write(f'{stamp}\trepository={one_line(repo)}\ttype={kind}\tpayload_sha256={digest}'
                    f'\tpeer={one_line(peer)}\tcaller=remote\tdecision={decision}\n')

    # -- the review + sign flow
    def sign(self, request: dict, who: dict) -> dict:
        args = request.get('args')
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise RemoteError('args must be a list of strings', 400)
        validate_signing_args(args)
        try:
            payload = base64.b64decode(request.get('payload', ''), validate=True)
        except (ValueError, TypeError) as exc:
            raise RemoteError('payload must be base64', 400) from exc
        if not payload or len(payload) > MAX_PAYLOAD:
            raise RemoteError('payload is empty or too large', 400)
        context = request.get('context') or {}
        if not isinstance(context, dict):
            raise RemoteError('context must be an object', 400)
        for key in ('diffstat', 'full_diff', 'repository', 'branch'):
            value = context.get(key, '')
            if not isinstance(value, str) or len(value) > MAX_CONTEXT_TEXT:
                raise RemoteError(f'context.{key} must be a bounded string', 400)

        # The requester never chooses the key. Its selector must name the
        # service's key (suffix of the fingerprint, `!` and 0x allowed), and gpg
        # is invoked with that fingerprint explicitly, so a peer cannot steer
        # signing to another secret key in this GnuPG home, such as a software
        # key with a cached passphrase that would complete without a touch.
        fingerprint = self.service_fingerprint()
        if not fingerprint:
            raise RemoteError('no signing key configured on the service', 503)
        args = pin_key_selector(args, fingerprint)
        info = parse_payload(payload)
        digest = hashlib.sha256(payload).hexdigest()
        repo = context.get('repository', '(unknown repository)')
        peer = f"{who['node'] or '?'} ({who['login'] or 'no login'})"
        rejected = fixture_reason(info)
        if rejected:
            self.audit('policy-reject', repo, info['type'], digest, peer)
            return {'status': EX_POLICY, 'decision': 'policy-reject', 'stdout': '',
                    'stderr': f"git-gpg-preview: refusing to sign fixture-style commit {one_line(rejected)}\n"}

        summary = self._summary(info, args, payload, digest, context, peer)
        details = self._details(info, args, payload, digest, context, peer)
        with self.lock:
            return self._review_and_sign(args, payload, info, digest, repo, peer, summary, details)

    def _summary(self, info, args, payload, digest, context, peer) -> str:
        return (f"Request type: {info['type']}\n"
                f"Requested by: {one_line(peer)}\n"
                f"Branch: {one_line(context.get('branch', '(unknown)'))}\n"
                f"Signing key: {one_line(key_selector(args))}\n"
                f"Exact payload: {len(payload)} bytes\n"
                f"SHA-256: {digest}\n\nMessage:\n{limited(info['message'], 600)}")

    def _details(self, info, args, payload, digest, context, peer) -> str:
        out = ['GIT OPENPGP SIGNING REVIEW — FULL DETAILS (REMOTE REQUEST)\n',
               f"Request type: {info['type']}",
               f"Requested by tailnet node: {one_line(peer)}",
               f"Repository/worktree on that host: {one_line(context.get('repository', '(unknown)'))}",
               f"Branch: {one_line(context.get('branch', '(unknown)'))}",
               f"Signing-key selector: {one_line(key_selector(args))}",
               f"Exact payload: {len(payload)} bytes",
               f"Exact payload SHA-256: {digest}"]
        if info['tree']:
            out.append(f"Tree: {info['tree']}")
            out.append('Parents: (initial commit; none)' if not info['parents']
                       else 'Parents/objects:\n' + ''.join(f'  {p}\n' for p in info['parents']).rstrip('\n'))
        elif info['object']:
            out.append(f"Target object: {info['object']}")
        out.append('\nEXACT vs. DERIVED\nGPG will receive only the exact captured payload identified above.\n'
                   'The message and payload sections below are taken from those bytes on this machine.\n'
                   'The diffstat and diff were DERIVED ON THE REQUESTING HOST from its Git objects and are a\n'
                   'review aid only; the signed tree hash, not the rendered diff, is authoritative.')
        out.append('\nCOMMIT/TAG MESSAGE OR PAYLOAD BODY\n' + limited(info['message'], 4000))
        if info['type'] == 'commit':
            out.append('\n\nDERIVED CHANGED-FILE SUMMARY / DIFFSTAT (from requesting host)\n'
                       + limited(context.get('diffstat', '(not supplied)'), 12000))
        out.append('\n\n' + '=' * 60 + '\nEXACT SIGNED PAYLOAD — VERBATIM BYTES BETWEEN MARKERS\n'
                   'Only these captured bytes are passed to GPG.\n' + '=' * 60)
        out.append(sanitize(payload.decode('utf-8', 'replace')))
        out.append('=' * 60 + '\nEND EXACT SIGNED PAYLOAD\n' + '=' * 60 + '\n')
        out.append('BYTE-PRESERVING HEX VIEW OF EXACT PAYLOAD\n\n' + hexdump(payload))
        if info['type'] == 'commit':
            out.append('\n' + '=' * 60 + '\nDERIVED FULL DIFF — REVIEW AID FROM REQUESTING HOST, NOT LITERAL GPG INPUT\n'
                       + '=' * 60 + '\n' + sanitize(context.get('full_diff', '(not supplied)')))
        return '\n'.join(out) + '\n'

    def _review_and_sign(self, args, payload, info, digest, repo, peer, summary, details) -> dict:
        config = self.config
        lock_root = Path(config.lock_root)
        lock_root.mkdir(parents=True, exist_ok=True)
        lock_root.chmod(0o700)
        with tempfile.TemporaryDirectory(prefix='git-gpg-preview-remote.') as tmp_name:
            tmp = Path(tmp_name)
            tmp.chmod(0o700)
            paths = {name: tmp / name for name in ('payload', 'summary.txt', 'details.txt', 'decision', 'ready')}
            paths['payload'].write_bytes(payload)
            paths['summary.txt'].write_text(summary)
            paths['details.txt'].write_text(details)
            paths['decision'].write_text('')
            for p in ('payload', 'summary.txt', 'details.txt', 'decision'):
                paths[p].chmod(0o600)

            with DialogLock(lock_root / 'dialog.lock'):
                return self._run_dialog_and_gpg(args, paths, info, digest, repo, peer)

    def _run_dialog_and_gpg(self, args, paths, info, digest, repo, peer) -> dict:
        config = self.config
        if config.dialog_runner:
            dialog_cmd = [config.dialog_runner]
        else:
            dialog_cmd = ['/usr/bin/osascript', '-l', 'JavaScript', config.ui_helper]
        dialog_cmd += [str(paths['summary.txt']), str(paths['details.txt']), str(paths['decision']), str(paths['ready'])]
        dialog = subprocess.Popen(dialog_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 5
        while not paths['ready'].exists() and dialog.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)

        with paths['payload'].open('rb') as stdin:
            gpg = subprocess.Popen([config.real_gpg, *args], stdin=stdin,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        started = time.monotonic()
        outcome = ''
        while True:
            if gpg.poll() is not None:
                outcome = 'signed'
                break
            if dialog.poll() is not None:
                outcome = 'dialog'
                break
            if time.monotonic() - started > config.sign_timeout:
                outcome = 'timeout'
                break
            time.sleep(0.1)

        def stop(proc):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

        if outcome == 'dialog':
            decision = paths['decision'].read_text().strip()
            if decision == 'sign':
                outcome = 'signed'
            elif decision == 'cancel':
                stop(gpg)
                self.audit('cancel', repo, info['type'], digest, peer)
                return {'status': EX_CANCELLED, 'decision': 'cancel', 'stdout': '',
                        'stderr': 'git-gpg-preview: signing cancelled by operator\n'}
            else:
                stop(gpg)
                self.audit('invalid-ui-decision', repo, info['type'], digest, peer)
                return {'status': EX_SOFTWARE, 'decision': 'invalid-ui-decision', 'stdout': '',
                        'stderr': 'git-gpg-preview: preview returned no valid decision; refusing to sign\n'}
        if outcome == 'signed' and gpg.poll() is None:
            # Approved in the window but the hardware has not confirmed yet:
            # keep waiting, but only until the same deadline. An operator who
            # approves and walks away must not wedge every later request.
            while gpg.poll() is None and time.monotonic() - started <= config.sign_timeout:
                time.sleep(0.1)
            if gpg.poll() is None:
                outcome = 'timeout'
        if outcome == 'timeout':
            stop(gpg)
            stop(dialog)
            self.audit('timeout', repo, info['type'], digest, peer)
            return {'status': EX_SOFTWARE, 'decision': 'timeout', 'stdout': '',
                    'stderr': f'git-gpg-preview: no hardware confirmation within {int(config.sign_timeout)}s; refusing to sign\n'}

        stdout, stderr = gpg.communicate(timeout=30)
        stop(dialog)
        # gpg finishing first does not override the operator: a Cancel pressed
        # in the same instant as the touch (or a key that needs no touch) must
        # still yield no signature. The decision file is the last word.
        try:
            decision = paths['decision'].read_text().strip()
        except OSError:
            decision = ''
        if decision == 'cancel':
            self.audit('cancel', repo, info['type'], digest, peer)
            return {'status': EX_CANCELLED, 'decision': 'cancel', 'stdout': '',
                    'stderr': 'git-gpg-preview: signing cancelled by operator\n'}
        status = gpg.returncode
        self.audit('sign' if status == 0 else 'gpg-error', repo, info['type'], digest, peer)
        return {'status': status, 'decision': 'sign' if status == 0 else 'gpg-error',
                'stdout': base64.b64encode(stdout).decode('ascii'),
                'stderr': stderr.decode('utf-8', 'replace')}


class Handler(BaseHTTPRequestHandler):
    service: Service
    server_version = f'{PROGRAM}/{PROTOCOL_VERSION}'
    sys_version = ''

    def log_message(self, fmt, *args):  # quiet; the audit log is the record
        return

    def _send(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self) -> dict | None:
        try:
            return self.service.authorize(self.client_address[0])
        except RemoteError as exc:
            self._send(exc.status if exc.status >= 400 else 403, {'error': str(exc)})
            return None

    def do_GET(self):
        if self.path != '/identity':
            self._send(404, {'error': 'not found'})
            return
        if self._authorized() is None:
            return
        try:
            self._send(200, self.service.identity())
        except RemoteError as exc:
            self._send(exc.status if exc.status >= 400 else 500, {'error': str(exc)})

    def do_POST(self):
        if self.path != '/sign':
            self._send(404, {'error': 'not found'})
            return
        who = self._authorized()
        if who is None:
            return
        length = int(self.headers.get('Content-Length') or 0)
        if length <= 0 or length > MAX_PAYLOAD * 2 + MAX_CONTEXT_TEXT * 3:
            self._send(400, {'error': 'bad content length'})
            return
        try:
            request = json.loads(self.rfile.read(length))
            if request.get('version') != PROTOCOL_VERSION:
                raise RemoteError('unsupported protocol version', 400)
            self._send(200, self.service.sign(request, who))
        except RemoteError as exc:
            self._send(exc.status if exc.status >= 400 else 200,
                       {'error': str(exc), 'status': exc.status, 'decision': 'refused', 'stdout': '', 'stderr': f'{PROGRAM}: {exc}\n'}
                       if exc.status < 400 else {'error': str(exc)})
        except (ValueError, TypeError) as exc:
            self._send(400, {'error': f'bad request: {exc}'})


def cmd_resolve_key(args) -> int:
    config = ServeConfig(Path(args.config_dir) if args.config_dir else config_home())
    fingerprint, source = resolve_signing_key(config.real_gpg, args.signing_key or config.signing_key)
    error(f'signing key {fingerprint} (from {source})')
    print(fingerprint)
    return 0


def cmd_serve(args) -> int:
    config = ServeConfig(Path(args.config_dir) if args.config_dir else config_home())
    me = self_identity()
    bind = config.bind or next((ip for ip in me['ips'] if ':' not in ip), '')
    if not bind:
        raise RemoteError('this machine has no Tailscale address to bind to')
    service = Service(config, me)
    key = service.service_fingerprint()
    handler = type('BoundHandler', (Handler,), {'service': service})
    server = ThreadingHTTPServer((bind, config.port), handler)
    server.daemon_threads = True
    allowed = ', '.join(sorted(config.allow_nodes)) or '(none)'
    prefixes = ', '.join(f'{p}*' for p in config.allow_node_prefixes) or '(none)'
    sys.stderr.write(f'{PROGRAM}: serving on {bind}:{config.port} as {me["node"]} ({me["login"]}); signing key {key} (from {service.key_source}); '
                     f'allowed nodes: {allowed}; allowed prefixes: {prefixes}; '
                     f'other nodes of the same login are allowed\n')
    sys.stderr.flush()
    if args.ready_file:
        Path(args.ready_file).write_text(f'{bind}:{config.port}\n')
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stop.wait()
    server.shutdown()
    return 0


# --- client -----------------------------------------------------------------

class ClientConfig:
    def __init__(self, base: Path) -> None:
        own = read_kv(base / 'client')
        self.server = own.get('server', '')
        self.port = int(own.get('port') or DEFAULT_PORT)
        self.real_gpg = own.get('real_gpg') or shutil.which('gpg') or ''
        self.timeout = float(own.get('timeout_seconds') or 180)
        self.address = own.get('address', '')  # tests only: skip tailnet resolution


def git(*args: str) -> str | None:
    result = subprocess.run(['git', '--no-pager', *args], capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else None


def describe_locally(info: dict) -> dict:
    """What the wrapper derives from the local repository, done on the host."""
    context = {'repository': '(not in a Git worktree)', 'branch': '(not on a branch)', 'diffstat': '', 'full_diff': ''}
    top = git('rev-parse', '--show-toplevel') or git('rev-parse', '--absolute-git-dir')
    if top:
        context['repository'] = top.strip()
    branch = git('symbolic-ref', '--quiet', '--short', 'HEAD')
    if branch:
        context['branch'] = branch.strip()
    else:
        short = git('rev-parse', '--short', 'HEAD')
        if short:
            context['branch'] = f'detached at {short.strip()}'
    if info['type'] == 'commit':
        tree = info['tree']
        if not valid_oid(tree) or git('cat-file', '-e', f'{tree}^{{tree}}') is None:
            raise RemoteError('commit payload has an invalid or unavailable tree; refusing to sign', EX_POLICY)
        for parent in info['parents']:
            if not valid_oid(parent) or git('cat-file', '-e', f'{parent}^{{commit}}') is None:
                raise RemoteError('commit payload has an invalid or unavailable parent; refusing to sign', EX_POLICY)
        bases = info['parents'] or [(git('hash-object', '-t', 'tree', '--stdin') or '').strip()]
        if not bases[0]:
            raise RemoteError('could not derive the empty tree for an initial commit', EX_POLICY)
        stat_parts, diff_parts = [], []
        for index, base in enumerate(bases, 1):
            if not info['parents']:
                label = 'Initial commit (empty tree to proposed tree)'
            elif len(bases) == 1:
                label = f'Changes from parent {base}'
            else:
                label = f'Changes from parent {index}: {base}'
            stat = git('diff', '--stat', '--summary', '--no-ext-diff', '--no-textconv', '--no-color', base, tree, '--')
            full = git('diff', '--no-ext-diff', '--no-textconv', '--no-color', base, tree, '--')
            if stat is None or full is None:
                raise RemoteError('could not safely derive the commit diff; refusing to sign', EX_POLICY)
            stat_parts.append(f'{label}\n{stat}\n')
            diff_parts.append(f'{label}\n\n{full}\n')
        context['diffstat'] = ''.join(stat_parts)[:MAX_CONTEXT_TEXT]
        context['full_diff'] = ''.join(diff_parts)[:MAX_CONTEXT_TEXT]
    elif info['type'] == 'tag':
        if not valid_oid(info['object']) or git('cat-file', '-e', info['object']) is None:
            raise RemoteError('tag payload has an invalid or unavailable target object; refusing to sign', EX_POLICY)
    return context


def server_url(config: ClientConfig) -> str:
    if config.address:
        return f'http://{config.address}'
    if not config.server:
        raise RemoteError('client config has no server= (run signing-setup on this host)')
    ip, port = resolve_peer(config.server, config.port)
    return f'http://{ip}:{port}'


# The service is a tailnet peer, reached directly by design. urllib would
# otherwise honour http_proxy/https_proxy from the environment, and an agent
# runtime that routes its own traffic through an egress proxy (NO_PROXY set to
# localhost only) then sends the signing request to a proxy that cannot reach
# the operator's machine: "signing service refused (502): Upstream unreachable".
DIRECT = build_opener(ProxyHandler({}))


def open_direct(request: Request, timeout: float):
    return DIRECT.open(request, timeout=timeout)


def post_json(url: str, body: dict, timeout: float) -> dict:
    data = json.dumps(body).encode()
    request = Request(url, data=data, headers={'Content-Type': 'application/json'}, method='POST')
    try:
        with open_direct(request, timeout) as response:
            return json.loads(response.read())
    except HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get('error', '')
        except Exception:
            detail = ''
        raise RemoteError(f'signing service refused the request ({exc.code}): {detail or exc.reason}',
                          EX_POLICY if exc.code in (400, 403) else EX_SOFTWARE) from exc
    except URLError as exc:
        raise RemoteError(f'signing service unreachable: {exc.reason}') from exc
    except TimeoutError as exc:
        raise RemoteError('signing service did not answer in time') from exc


def get_json(url: str, timeout: float) -> dict:
    try:
        with open_direct(Request(url), timeout) as response:
            return json.loads(response.read())
    except HTTPError as exc:
        raise RemoteError(f'signing service refused ({exc.code})', EX_POLICY if exc.code == 403 else EX_SOFTWARE) from exc
    except (URLError, TimeoutError) as exc:
        raise RemoteError(f'signing service unreachable: {exc}') from exc


def cmd_client(gpg_args: list[str], config_dir: str | None) -> int:
    config = ClientConfig(Path(config_dir) if config_dir else config_home())
    if not is_signing_request(gpg_args):
        if not config.real_gpg:
            raise RemoteError('no local gpg for non-signing operations')
        os.execv(config.real_gpg, [config.real_gpg, *gpg_args])
    validate_signing_args(gpg_args)
    payload = sys.stdin.buffer.read()
    if not payload:
        raise RemoteError('could not capture signing payload')
    info = parse_payload(payload)
    rejected = fixture_reason(info)
    if rejected:
        raise RemoteError(f'refusing to sign fixture-style commit {one_line(rejected)}', EX_POLICY)
    context = describe_locally(info)
    context['host'] = os.uname().nodename
    url = server_url(config)
    error(f'requesting signature from {config.server or url}; touch the key on that machine when its preview appears')
    reply = post_json(f'{url}/sign', {'version': PROTOCOL_VERSION, 'args': gpg_args,
                                      'payload': base64.b64encode(payload).decode('ascii'),
                                      'context': context}, config.timeout)
    stdout = base64.b64decode(reply.get('stdout', '') or '')
    if stdout:
        sys.stdout.buffer.write(stdout)
        sys.stdout.buffer.flush()
    stderr = reply.get('stderr', '')
    if stderr:
        sys.stderr.write(stderr)
        sys.stderr.flush()
    return int(reply.get('status', EX_SOFTWARE))


def cmd_identity(args) -> int:
    config = ClientConfig(Path(args.config_dir) if args.config_dir else config_home())
    if args.server:
        config.server = args.server
    if args.address:
        config.address = args.address
    print(json.dumps(get_json(f'{server_url(config)}/identity', 30), indent=2))
    return 0


def cmd_resolve(args) -> int:
    ip, port = resolve_peer(args.server, args.port)
    print(f'{ip}:{port}')
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # `client` passes everything after it straight to the gpg interface.
    if argv and argv[0] == 'client':
        config_dir = None
        rest = argv[1:]
        if rest[:1] == ['--config-dir'] and len(rest) >= 2:
            config_dir, rest = rest[1], rest[2:]
        if rest[:1] == ['--']:
            rest = rest[1:]
        try:
            return cmd_client(rest, config_dir)
        except RemoteError as exc:
            error(str(exc))
            return exc.status
    parser = argparse.ArgumentParser(prog=PROGRAM, description=__doc__.split('\n\n')[0])
    sub = parser.add_subparsers(dest='command', required=True)
    serve = sub.add_parser('serve', help='run the signing service on the machine with the key')
    serve.add_argument('--config-dir')
    serve.add_argument('--ready-file', help='write bind address here once listening (tests, launchd checks)')
    serve.set_defaults(func=cmd_serve)
    identity = sub.add_parser('identity', help='print the service identity JSON (fingerprint, public key)')
    identity.add_argument('--config-dir')
    identity.add_argument('--server', help='full Tailscale DNS name of the machine running serve')
    identity.add_argument('--address', help=argparse.SUPPRESS)
    identity.set_defaults(func=cmd_identity)
    resolve = sub.add_parser('resolve', help='print the authenticated tailnet address of a server')
    resolve.add_argument('--server', required=True)
    resolve.add_argument('--port', type=int, default=DEFAULT_PORT)
    resolve.set_defaults(func=cmd_resolve)
    resolve_key = sub.add_parser('resolve-key', help='print the fingerprint serve would sign with')
    resolve_key.add_argument('--config-dir')
    resolve_key.add_argument('--signing-key', help='key id, fingerprint or user id; default: the serve config, then Git')
    resolve_key.set_defaults(func=cmd_resolve_key)
    sub.add_parser('client', help='gpg.openpgp.program entry point; pass gpg arguments after it')
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except RemoteError as exc:
        error(str(exc))
        return exc.status if exc.status < 256 else EX_SOFTWARE


if __name__ == '__main__':
    sys.exit(main())
