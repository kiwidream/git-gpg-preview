"""End-to-end tests for remote signing: a real serve process behind fake
tailscale/gpg/dialog helpers, driven by the real client, plus one run
against real GnuPG with a disposable key."""
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'git_gpg_preview_remote.py'
CLIENT = ROOT / 'git-gpg-preview-client'
HELPERS = ROOT / 'tests' / 'helpers'


def free_port() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Harness:
    """A serve process plus the environment its fakes read."""

    def __init__(self, tmp: Path, real_gpg: str | None = None, extra_env: dict | None = None,
                 serve_extra: str = '', git_signingkey: str = ''):
        self.tmp = tmp
        self.port = free_port()
        self.serve_dir = tmp / 'serve-config'
        self.client_dir = tmp / 'client-config'
        self.calls = tmp / 'gpg-calls'
        self.captures = tmp / 'captures'
        self.decision = tmp / 'decision.ctl'
        self.audit = tmp / 'audit.log'
        tmp.mkdir(parents=True, exist_ok=True)
        self.decision.write_text('sign')
        for d in (self.serve_dir, self.client_dir, self.calls, self.captures, tmp / 'bin'):
            d.mkdir(parents=True, exist_ok=True)
        (tmp / 'bin' / 'tailscale').symlink_to(HELPERS / 'fake-tailscale.py')
        gpg = real_gpg or str(HELPERS / 'fake-gpg.py')
        (self.serve_dir / 'config').write_text(f'real_gpg={gpg}\nui_helper=/nonexistent\nlock_root={tmp}/lock\naudit_log={self.audit}\n')
        (self.serve_dir / 'serve').write_text(
            f'bind=127.0.0.1\nport={self.port}\ndialog_runner={HELPERS}/fake-dialog.sh\n'
            f'sign_timeout_seconds=3\n{serve_extra}')
        (self.client_dir / 'client').write_text(
            f'address=127.0.0.1:{self.port}\nreal_gpg={gpg}\ntimeout_seconds=20\nserver=operator-mac.example.ts.net\n')
        # What the client reads through XDG_CONFIG_HOME when git invokes it.
        self.xdg = tmp / 'xdg'
        (self.xdg / 'git-gpg-preview').mkdir(parents=True, exist_ok=True)
        shutil.copy(self.client_dir / 'client', self.xdg / 'git-gpg-preview' / 'client')
        self.env = {**os.environ,
                    'PATH': f'{tmp}/bin:{os.environ["PATH"]}',
                    'FAKE_GPG_CALL_DIR': str(self.calls),
                    'FAKE_DIALOG_CAPTURE_DIR': str(self.captures),
                    'FAKE_DIALOG_DECISION_FILE': str(self.decision),
                    'FAKE_TOUCH_FILE': str(tmp / 'touch'),
                    'FAKE_GPG_STDOUT': 'signature:remote',
                    'TMPDIR': str(tmp / 'temp'),
                    # The service falls back to Git's global user.signingkey, so
                    # the developer's own configuration must not reach it.
                    'GIT_CONFIG_GLOBAL': str(tmp / 'gitconfig'),
                    'GIT_CONFIG_NOSYSTEM': '1',
                    **(extra_env or {})}
        (tmp / 'gitconfig').write_text(f'[user]\n\tsigningkey = {git_signingkey}\n' if git_signingkey else '')
        (tmp / 'temp').mkdir(exist_ok=True)
        ready = tmp / 'ready'
        self.proc = subprocess.Popen([sys.executable, str(MODULE), 'serve', '--config-dir', str(self.serve_dir),
                                      '--ready-file', str(ready)], env=self.env,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 10
        while not ready.exists():
            if self.proc.poll() is not None or time.monotonic() > deadline:
                self.proc.kill()
                _, stderr = self.proc.communicate()
                raise RuntimeError('serve did not start: ' + stderr.decode())
            time.sleep(0.05)

    def stop(self):
        self.proc.terminate()
        self.proc.wait(10)

    def client(self, gpg_args, stdin: bytes, cwd: Path, env=None):
        return subprocess.run([str(CLIENT), *gpg_args], input=stdin, cwd=cwd,
                              env={**self.env, 'XDG_CONFIG_HOME': str(self.xdg), **(env or {})},
                              capture_output=True)

    def post(self, body: dict, path='/sign'):
        request = urllib.request.Request(f'http://127.0.0.1:{self.port}{path}', data=json.dumps(body).encode(),
                                         headers={'Content-Type': 'application/json'}, method='POST')
        try:
            with urllib.request.urlopen(request, timeout=20) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def latest_capture(self):
        summaries = sorted(self.captures.glob('*.summary'), key=lambda p: p.stat().st_mtime)
        return summaries[-1].read_text(), summaries[-1].with_suffix('.details').read_text()

    def gpg_calls(self):
        """Signing calls only: the service lists its own key once at startup."""
        ids = (self.calls / 'calls').read_text().split() if (self.calls / 'calls').exists() else []
        calls = [((self.calls / f'{i}.args').read_bytes().split(b'\0')[:-1], (self.calls / f'{i}.stdin').read_bytes()) for i in ids]
        return [c for c in calls if not any(a in (b'--list-secret-keys', b'--list-keys', b'--export') for a in c[0])]


def fixture_repo(tmp: Path) -> tuple[Path, bytes, bytes]:
    repo = tmp / 'repo with spaces'
    repo.mkdir()
    g = lambda *a: subprocess.run(['git', '-C', str(repo), *a], check=True, capture_output=True, text=True).stdout
    g('init', '-q', '-b', 'main')
    g('config', 'user.name', 'Preview Tester')
    g('config', 'user.email', 'preview@example.invalid')
    g('config', 'commit.gpgsign', 'false')
    (repo / 'initial.txt').write_text('initial\n')
    g('add', '.')
    g('commit', '-q', '-m', 'Initial message')
    initial = g('cat-file', 'commit', 'HEAD').encode()
    (repo / 'second.txt').write_text('second $(touch bad)\n')
    g('add', '.')
    g('commit', '-q', '-m', 'Second commit Ω\n\n$(touch bad); `touch bad`')
    second = g('cat-file', 'commit', 'HEAD').encode()
    return repo, initial, second


class RemoteSigningTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(prefix='ggp-remote.')
        self.tmp = Path(self.tmpdir.name)
        self.addCleanup(self.tmpdir.cleanup)
        self.h = Harness(self.tmp)
        self.addCleanup(self.h.stop)
        self.repo, self.initial, self.second = fixture_repo(self.tmp)

    def sign_args(self):
        # The fake service key ends in ...3DB3F5612E33B6BC; git passes the host's user.signingkey.
        return ['--status-fd=2', '-bsau', '3DB3F5612E33B6BC']

    def test_signs_through_the_service_and_the_operator_sees_the_request(self):
        result = self.h.client(self.sign_args(), self.second, self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'signature:remote', 'only real GPG output may reach stdout')
        self.assertIn(b'touch the key', result.stderr)
        args, stdin = self.h.gpg_calls()[-1]
        self.assertEqual(stdin, self.second, 'the exact payload bytes reach GPG')
        self.assertEqual(args, [b'--status-fd=2', b'-bsa', b'--local-user', b'041CE6A7BED57FE579D43B6C3DB3F5612E33B6BC'],
                         'the selector is pinned to the service key; nothing else changes')
        summary, details = self.h.latest_capture()
        self.assertIn('Request type: commit', summary)
        self.assertIn('Requested by: minidev-test.example.ts.net', summary)
        self.assertIn('Signing key: 041CE6A7BED57FE579D43B6C3DB3F5612E33B6BC', summary)
        self.assertIn('Branch: main', summary)
        self.assertIn('Changes from parent', details)
        self.assertIn('second.txt', details)
        self.assertIn('DERIVED ON THE REQUESTING HOST', details)
        self.assertIn('BYTE-PRESERVING HEX VIEW', details)
        self.assertFalse((self.repo / 'bad').exists(), 'hostile-looking content never executes')
        audit = self.h.audit.read_text()
        self.assertIn('decision=sign', audit)
        self.assertIn('peer=minidev-test.example.ts.net', audit)

    def test_initial_commit_describes_the_empty_tree_base(self):
        result = self.h.client(self.sign_args(), self.initial, self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        _, details = self.h.latest_capture()
        self.assertIn('Parents: (initial commit; none)', details)
        self.assertIn('Initial commit (empty tree to proposed tree)', details)

    def test_cancel_on_the_operator_side_fails_the_commit_and_writes_nothing(self):
        self.h.decision.write_text('cancel')
        result = self.h.client(self.sign_args(), self.second, self.repo)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertIn(b'cancelled by operator', result.stderr)
        self.assertIn('decision=cancel', self.h.audit.read_text())
        self.assertEqual(self.h.gpg_calls(), [], 'GPG was killed before it recorded a signature')

    def test_no_touch_within_the_deadline_refuses(self):
        self.h.decision.write_text('hang')
        result = self.h.client(self.sign_args(), self.second, self.repo)
        self.assertEqual(result.returncode, 70)
        self.assertIn(b'no hardware confirmation within', result.stderr)
        self.assertEqual(result.stdout, b'')

    def test_approval_without_a_touch_still_times_out_and_frees_the_service(self):
        self.h.decision.write_text('approve-no-touch')
        started = time.monotonic()
        result = self.h.client(self.sign_args(), self.second, self.repo)
        self.assertEqual(result.returncode, 70)
        self.assertIn(b'no hardware confirmation within', result.stderr)
        self.assertLess(time.monotonic() - started, 9, 'bounded by sign_timeout_seconds, not the fake key')
        self.assertIn('decision=timeout', self.h.audit.read_text())
        # The next request is served: nothing is wedged behind the abandoned one.
        self.h.decision.write_text('sign')
        again = self.h.client(self.sign_args(), self.second, self.repo)
        self.assertEqual(again.returncode, 0, again.stderr)

    def test_shares_the_local_wrappers_dialog_lock(self):
        """A local `git commit` holding dialog.lock (shlock protocol: a live pid
        in the file) makes the remote request wait; a dead owner is stale."""
        lock = self.tmp / 'lock' / 'dialog.lock'
        lock.parent.mkdir(parents=True, exist_ok=True)
        holder = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(2.5)'])
        # Reap it the moment it exits: a zombie still answers kill -0, exactly
        # as it would for shlock, and would look like a live owner forever.
        import threading
        threading.Thread(target=holder.wait, daemon=True).start()
        lock.write_text(str(holder.pid))
        started = time.monotonic()
        result = self.h.client(self.sign_args(), self.second, self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(time.monotonic() - started, 2.0, 'waited for the local wrapper to finish')
        holder.wait()
        self.assertFalse(lock.exists(), 'released after signing')
        lock.write_text('999999')   # a pid nobody has: stale, proceed at once
        started = time.monotonic()
        result = self.h.client(self.sign_args(), self.second, self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(time.monotonic() - started, 2.0)

    def test_peer_outside_the_allowed_set_is_refused_before_any_review(self):
        h = Harness(self.tmp / 'stranger', extra_env={'FAKE_WHOIS_NODE': 'laptop-x.example.ts.net', 'FAKE_WHOIS_USER': '300'})
        self.addCleanup(h.stop)
        result = h.client(self.sign_args(), self.second, self.repo)
        self.assertEqual(result.returncode, 65)
        self.assertIn(b'not allowed to request signatures', result.stderr)
        self.assertEqual(list(h.captures.glob('*.summary')), [], 'no preview for an unauthorized peer')
        self.assertEqual(h.gpg_calls(), [])

    def test_same_login_peer_is_allowed_without_prefix_match(self):
        h = Harness(self.tmp / 'own', extra_env={'FAKE_WHOIS_NODE': 'other-laptop.example.ts.net', 'FAKE_WHOIS_USER': '100'})
        self.addCleanup(h.stop)
        result = h.client(self.sign_args(), self.second, self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_verify_and_other_operations_stay_local(self):
        result = self.h.client(['--keyid-format=long', '--status-fd=1', '--verify', 'sig', '-'], self.second, self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        args, _ = self.h.gpg_calls()[-1]
        self.assertIn(b'--verify', args)
        self.assertEqual(list(self.h.captures.glob('*.summary')), [], 'no service round trip for verification')

    def test_fixture_subjects_are_refused_on_both_sides(self):
        subprocess.run(['git', '-C', str(self.repo), 'commit', '-q', '--allow-empty', '-m', 'base'], check=True)
        payload = subprocess.run(['git', '-C', str(self.repo), 'cat-file', 'commit', 'HEAD'], check=True, capture_output=True).stdout
        result = self.h.client(self.sign_args(), payload, self.repo)
        self.assertEqual(result.returncode, 65)
        self.assertIn(b"fixture-style commit subject 'base'", result.stderr)
        code, body = self.h.post({'version': 1, 'args': self.sign_args(), 'payload': base64.b64encode(payload).decode(),
                                  'context': {}})
        self.assertEqual((code, body['status'], body['decision']), (200, 65, 'policy-reject'))
        self.assertIn('decision=policy-reject', self.h.audit.read_text())

    def test_requester_cannot_choose_another_key(self):
        for selector in ('DEADBEEFDEADBEEF', 'someone@example.invalid', '0xFFFFFFFFFFFFFFFF!'):
            with self.subTest(selector=selector):
                code, body = self.h.post({'version': 1, 'args': ['--status-fd=2', '-bsau', selector],
                                          'payload': base64.b64encode(self.second).decode(), 'context': {}})
                self.assertEqual((code, body['status'], body['decision']), (200, 65, 'refused'))
                self.assertIn('signs with', body['stderr'])
        self.assertEqual(self.h.gpg_calls(), [], 'gpg never ran for a foreign selector')
        # Suffix, 0x prefix and a forced `!` all name the same key and are accepted.
        for selector in ('3DB3F5612E33B6BC', '0x3db3f5612e33b6bc', '041CE6A7BED57FE579D43B6C3DB3F5612E33B6BC!'):
            with self.subTest(selector=selector):
                result = self.h.client(['--status-fd=2', '-bsau', selector], self.second, self.repo)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(b'--local-user', b'\0'.join(self.h.gpg_calls()[-1][0]))

    def test_service_refuses_arguments_git_never_sends(self):
        for args in (['--status-fd=2', '-bsau', 'K', '--homedir', '/tmp/x'],
                     ['--status-fd=2', '-bsau', '--output'],
                     ['--verify', '-'],
                     ['--status-fd=2', '-bsau', 'K', '--output', '/tmp/x']):
            with self.subTest(args=args):
                code, body = self.h.post({'version': 1, 'args': args, 'payload': base64.b64encode(self.second).decode(), 'context': {}})
                self.assertEqual(code, 200)
                self.assertEqual(body['decision'], 'refused')
                self.assertEqual(body['status'], 65)
        self.assertEqual(self.h.gpg_calls(), [])

    def test_bad_requests_are_rejected(self):
        code, _ = self.h.post({'version': 99, 'args': self.sign_args(), 'payload': 'AA==', 'context': {}})
        self.assertEqual(code, 400)
        code, _ = self.h.post({'version': 1, 'args': self.sign_args(), 'payload': 'not base64!', 'context': {}})
        self.assertEqual(code, 400)
        code, _ = self.h.post({'version': 1, 'args': 'string', 'payload': 'AA==', 'context': {}})
        self.assertEqual(code, 400)

    def test_offline_service_fails_closed(self):
        (self.h.xdg / 'git-gpg-preview' / 'client').write_text(f'address=127.0.0.1:{free_port()}\nreal_gpg={HELPERS}/fake-gpg.py\n')
        result = self.h.client(self.sign_args(), self.second, self.repo)
        self.assertEqual(result.returncode, 70)
        self.assertIn(b'unreachable', result.stderr)
        self.assertEqual(result.stdout, b'')

    def test_identity_endpoint_serves_fingerprint_and_public_key(self):
        result = subprocess.run([sys.executable, str(MODULE), 'identity', '--address', f'127.0.0.1:{self.h.port}',
                                 '--config-dir', str(self.h.client_dir)], env=self.h.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        identity = json.loads(result.stdout)
        self.assertEqual(identity['fingerprint'], '041CE6A7BED57FE579D43B6C3DB3F5612E33B6BC')
        self.assertIn('BEGIN PGP PUBLIC KEY BLOCK', identity['public_key'])
        self.assertEqual(identity['node'], 'operator-mac.example.ts.net')
        self.assertEqual(identity['login'], 'operator@example.invalid')

    def test_resolve_uses_the_authenticated_netmap_and_requires_online(self):
        result = subprocess.run([sys.executable, str(MODULE), 'resolve', '--server', 'operator-mac.example.ts.net'],
                                env=self.h.env, capture_output=True, text=True)
        self.assertEqual(result.stdout.strip(), '100.64.0.1:24824')
        result = subprocess.run([sys.executable, str(MODULE), 'resolve', '--server', 'operator-mac.example.ts.net'],
                                env={**self.h.env, 'FAKE_PEER_ONLINE': '0'}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 70)
        self.assertIn('offline', result.stderr)
        result = subprocess.run([sys.executable, str(MODULE), 'resolve', '--server', 'operator-mac.example.com'],
                                env=self.h.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 70)


PRIMARY_A = 'AAAA' * 9 + '0000000A'
PRIMARY_B = 'BBBB' * 9 + '0000000B'
SUBKEY_B = 'CCCC' * 9 + '0000000C'
TWO_KEYS = f'{PRIMARY_A},{PRIMARY_B}/{SUBKEY_B}'


class SigningKeyTests(unittest.TestCase):
    """Which key the service signs with is never left to gpg's listing order."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.tmp = Path(self.tmpdir.name)

    def resolve(self, keys='', git_signingkey='', configured='', flag=''):
        config = self.tmp / 'config'
        config.mkdir(exist_ok=True)
        (config / 'config').write_text(f'real_gpg={HELPERS}/fake-gpg.py\nui_helper={MODULE}\n')
        (config / 'serve').write_text(f'signing_key={configured}\n')
        (self.tmp / 'gitconfig').write_text(f'[user]\n\tsigningkey = {git_signingkey}\n' if git_signingkey else '')
        env = {**os.environ, 'FAKE_GPG_CALL_DIR': str(self.tmp / 'calls'), 'GIT_CONFIG_GLOBAL': str(self.tmp / 'gitconfig'),
               'GIT_CONFIG_NOSYSTEM': '1', **({'FAKE_GPG_SECRET_KEYS': keys} if keys else {})}
        return subprocess.run([sys.executable, str(MODULE), 'resolve-key', '--config-dir', str(config),
                               *(['--signing-key', flag] if flag else [])], env=env, capture_output=True, text=True)

    def test_the_only_secret_key_needs_no_configuration(self):
        result = self.resolve()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), '041CE6A7BED57FE579D43B6C3DB3F5612E33B6BC')
        self.assertIn('the only secret key', result.stderr)

    def test_several_keys_and_nothing_naming_one_is_refused(self):
        result = self.resolve(keys=TWO_KEYS)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '', 'no fingerprint is offered, first-listed or otherwise')
        self.assertIn('2 secret keys', result.stderr)
        self.assertIn(PRIMARY_A, result.stderr)
        self.assertIn(PRIMARY_B, result.stderr)

    def test_gits_signing_key_decides_between_several(self):
        # The key gpg lists first is not the one the operator commits with.
        for selector in (f'{SUBKEY_B}!', SUBKEY_B[-16:], f'0x{SUBKEY_B[-16:].lower()}'):
            with self.subTest(selector=selector):
                result = self.resolve(keys=TWO_KEYS, git_signingkey=selector)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), SUBKEY_B, 'the full fingerprint of the subkey that was named, without the !')
                self.assertIn("Git's global user.signingkey", result.stderr)

    def test_configuration_and_the_flag_outrank_git(self):
        configured = self.resolve(keys=TWO_KEYS, git_signingkey=SUBKEY_B, configured=PRIMARY_A)
        self.assertEqual(configured.stdout.strip(), PRIMARY_A)
        flagged = self.resolve(keys=TWO_KEYS, git_signingkey=SUBKEY_B, configured=PRIMARY_A, flag=PRIMARY_B)
        self.assertEqual(flagged.stdout.strip(), PRIMARY_B)

    def test_a_key_that_is_not_here_is_refused_rather_than_replaced(self):
        for kwargs in ({'configured': 'DDDD' * 10}, {'git_signingkey': 'DDDD' * 10}):
            with self.subTest(**kwargs):
                result = self.resolve(keys=TWO_KEYS, **kwargs)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertIn('names no secret key', result.stderr)

    def test_serve_refuses_to_start_when_the_key_is_ambiguous(self):
        with self.assertRaises(RuntimeError) as raised:
            Harness(self.tmp / 'ambiguous', extra_env={'FAKE_GPG_SECRET_KEYS': TWO_KEYS})
        self.assertIn('2 secret keys', str(raised.exception))

    def test_serve_signs_with_gits_key_and_says_where_it_came_from(self):
        h = Harness(self.tmp / 'git-key', extra_env={'FAKE_GPG_SECRET_KEYS': TWO_KEYS}, git_signingkey=f'{SUBKEY_B}!')
        self.addCleanup(h.stop)
        with urllib.request.urlopen(f'http://127.0.0.1:{h.port}/identity', timeout=10) as response:
            self.assertEqual(json.loads(response.read())['fingerprint'], SUBKEY_B)
        repo, _, payload = fixture_repo(self.tmp)
        result = h.client(['--status-fd=2', '-bsau', f'{SUBKEY_B}!'], payload, repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(h.gpg_calls()[-1][0][-2:], [b'--local-user', SUBKEY_B.encode()])


class ServeInstallTests(unittest.TestCase):
    """serve-install.sh against a scratch HOME, with launchctl and uname faked."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.tmp = Path(self.tmpdir.name)
        self.home = self.tmp / 'home'
        self.config = self.home / '.config' / 'git-gpg-preview'
        self.config.mkdir(parents=True)
        (self.config / 'config').write_text(f'real_gpg={HELPERS}/fake-gpg.py\nui_helper={MODULE}\n')
        bin_dir = self.tmp / 'bin'
        bin_dir.mkdir()
        self.launchctl_log = self.tmp / 'launchctl.log'
        # launchd as it behaves: after `bootout` the job stays visible to
        # `print` for a while, and a `bootstrap` in that window fails with 5.
        self.lingering = self.tmp / 'lingering'
        launchctl = (f'echo "$*" >> "{self.launchctl_log}"\n'
                     f'left=$(cat "{self.lingering}" 2>/dev/null || echo 0)\n'
                     'case "$1" in\n'
                     f'  bootout) echo "${{FAKE_LAUNCHD_LINGER:-0}}" > "{self.lingering}" ;;\n'
                     f'  print) [ "$left" -gt 0 ] || exit 113; echo $((left - 1)) > "{self.lingering}" ;;\n'
                     '  bootstrap) [ "$left" -eq 0 ] || { echo "Bootstrap failed: 5: Input/output error" >&2; exit 5; } ;;\n'
                     'esac')
        for name, body in (('launchctl', launchctl), ('uname', 'echo Darwin')):
            (bin_dir / name).write_text(f'#!/bin/sh\n{body}\n')
            (bin_dir / name).chmod(0o755)
        (self.tmp / 'gitconfig').write_text('')
        self.env = {**os.environ, 'HOME': str(self.home), 'XDG_CONFIG_HOME': str(self.home / '.config'),
                    'PATH': f'{bin_dir}:{os.environ["PATH"]}', 'FAKE_GPG_CALL_DIR': str(self.tmp / 'calls'),
                    'GIT_CONFIG_GLOBAL': str(self.tmp / 'gitconfig'), 'GIT_CONFIG_NOSYSTEM': '1'}

    def install(self, *args, **env):
        return subprocess.run(['bash', str(ROOT / 'serve-install.sh'), 'install', *args],
                              env={**self.env, **env}, capture_output=True, text=True)

    def serve_config(self):
        return dict(line.split('=', 1) for line in (self.config / 'serve').read_text().splitlines())

    def test_installs_with_the_resolved_key_and_an_audit_log(self):
        (self.tmp / 'gitconfig').write_text(f'[user]\n\tsigningkey = {SUBKEY_B}!\n')
        result = self.install(FAKE_GPG_SECRET_KEYS=TWO_KEYS)
        self.assertEqual(result.returncode, 0, result.stderr)
        config = self.serve_config()
        self.assertEqual(config['signing_key'], SUBKEY_B)
        self.assertEqual(config['audit_log'], str(self.home / 'Library/Logs/git-gpg-preview/audit.log'))
        self.assertIn('bootstrap', self.launchctl_log.read_text())
        # Again: the stored key stands without Git, and nothing is duplicated.
        (self.tmp / 'gitconfig').write_text('')
        again = self.install(FAKE_GPG_SECRET_KEYS=TWO_KEYS)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(self.serve_config(), config)
        self.assertEqual((self.config / 'serve').read_text().count('audit_log='), 1)

    def test_reinstall_waits_for_launchd_to_release_the_job(self):
        result = self.install(FAKE_LAUNCHD_LINGER='3')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [line.split()[0] for line in self.launchctl_log.read_text().splitlines()]
        self.assertEqual(calls, ['bootout', 'print', 'print', 'print', 'print', 'bootstrap'],
                         'bootstrap is not attempted while the old job is still there')

    def test_an_ambiguous_key_installs_nothing(self):
        result = self.install(FAKE_GPG_SECRET_KEYS=TWO_KEYS)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('2 secret keys', result.stderr)
        self.assertFalse((self.config / 'serve').exists(), 'no half-written configuration')
        self.assertFalse((self.home / 'Library/LaunchAgents/dev.git-gpg-preview.serve.plist').exists())
        self.assertFalse(self.launchctl_log.exists(), 'launchd was never touched')

    def test_an_audit_setting_the_operator_made_is_kept(self):
        for existing in ('audit_log=', f'audit_log={self.tmp}/elsewhere.log'):
            with self.subTest(existing=existing):
                (self.config / 'serve').write_text(f'{existing}\nsign_timeout_seconds=45\n')
                result = self.install()
                self.assertEqual(result.returncode, 0, result.stderr)
                text = (self.config / 'serve').read_text()
                self.assertIn(f'{existing}\n', text)
                self.assertEqual(text.count('audit_log='), 1)
                self.assertIn('sign_timeout_seconds=45', text, 'unknown keys survive')


class DialogLockTests(unittest.TestCase):
    """The shlock-compatible lock must never admit two holders, including
    when several acquirers race over a stale file."""

    def test_mutual_exclusion_under_contention_and_stale_recovery(self):
        import importlib.util, threading
        spec = importlib.util.spec_from_file_location('ggp_remote', MODULE)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with tempfile.TemporaryDirectory() as name:
            lock = Path(name) / 'dialog.lock'
            lock.write_text('999999')      # a stale owner nobody has
            holders, errors = [0], []
            inside = threading.Lock()

            def worker():
                try:
                    with mod.DialogLock(lock):
                        if not inside.acquire(blocking=False):
                            errors.append('two holders at once')
                            return
                        holders[0] += 1
                        time.sleep(0.01)
                        inside.release()
                except Exception as exc:   # pragma: no cover
                    errors.append(repr(exc))

            threads = [threading.Thread(target=worker) for _ in range(12)]
            for t in threads: t.start()
            for t in threads: t.join(15)
            self.assertEqual(errors, [])
            self.assertEqual(holders[0], 12)
            self.assertFalse(lock.exists(), 'released')
            self.assertEqual([p.name for p in Path(name).iterdir()], [], 'no private files left behind')
            # The lock file never exists empty: a holder's pid is visible immediately.
            with mod.DialogLock(lock):
                self.assertEqual(lock.read_text().strip(), str(os.getpid()))


@unittest.skipUnless(shutil.which('gpg'), 'real gpg not installed')
class RealGnuPGTests(unittest.TestCase):
    """The real thing minus the hardware: a disposable key in an isolated home
    signs a real git commit through the service, and git verifies it."""

    def test_git_commit_is_signed_and_verifies(self):
        with tempfile.TemporaryDirectory(prefix='ggp-real.') as name:
            tmp = Path(name)
            base = Path(os.environ.get('XDG_RUNTIME_DIR') or str(Path.home() / '.cache'))
            base.mkdir(parents=True, exist_ok=True)  # short path: gpg sockets have a length limit
            home = Path(tempfile.mkdtemp(prefix='ggp-gnupg.', dir=base))
            self.addCleanup(shutil.rmtree, home, True)
            home.chmod(0o700)
            env = {**os.environ, 'GNUPGHOME': str(home)}
            gen = subprocess.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-gen-key',
                                  'Remote Fixture <fixture@example.invalid>', 'ed25519', 'sign', '1d'], env=env, capture_output=True)
            self.assertEqual(gen.returncode, 0, gen.stderr)
            self.addCleanup(subprocess.run, ['gpgconf', '--kill', 'gpg-agent'], env=env)
            fpr = next(line.split(':')[9] for line in subprocess.run(['gpg', '--with-colons', '--list-secret-keys'], env=env, capture_output=True, text=True).stdout.splitlines() if line.startswith('fpr:'))
            h = Harness(tmp, real_gpg=shutil.which('gpg'), extra_env={'GNUPGHOME': str(home)})
            self.addCleanup(h.stop)

            identity = json.loads(subprocess.run([sys.executable, str(MODULE), 'identity', '--address', f'127.0.0.1:{h.port}',
                                                  '--config-dir', str(h.client_dir)], env=h.env, capture_output=True, text=True, check=True).stdout)
            self.assertEqual(identity['fingerprint'], fpr)

            repo = tmp / 'repo'
            repo.mkdir()
            genv = {**h.env, 'XDG_CONFIG_HOME': str(h.xdg), 'GNUPGHOME': str(home)}
            g = lambda *a: subprocess.run(['git', '-C', str(repo), *a], env=genv, capture_output=True, text=True)
            g('init', '-q', '-b', 'main')
            for k, v in (('user.name', 'Remote Fixture'), ('user.email', 'fixture@example.invalid'), ('commit.gpgsign', 'true'),
                         ('user.signingkey', fpr), ('gpg.openpgp.program', str(CLIENT))):
                g('config', k, v)
            (repo / 'a.md').write_text('signed remotely\n')
            g('add', 'a.md')
            commit = g('commit', '-q', '-m', 'docs: signed through the service')
            self.assertEqual(commit.returncode, 0, commit.stderr)
            self.assertEqual(g('log', '-1', '--format=%G? %GF').stdout.strip(), f'G {fpr}')
            summary, _ = h.latest_capture()
            self.assertIn('Request type: commit', summary)
            self.assertIn('decision=sign', h.audit.read_text())
            # A cancel on the Mac leaves the repository untouched.
            h.decision.write_text('cancel')
            (repo / 'b.md').write_text('must not land\n')
            g('add', 'b.md')
            refused = g('commit', '-q', '-m', 'docs: must fail')
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn('cancelled by operator', refused.stderr)
            self.assertEqual(g('rev-list', '--count', 'HEAD').stdout.strip(), '1')


if __name__ == '__main__':
    unittest.main()
