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
                 serve_extra: str = ''):
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
                    **(extra_env or {})}
        (tmp / 'temp').mkdir(exist_ok=True)
        ready = tmp / 'ready'
        self.proc = subprocess.Popen([sys.executable, str(MODULE), 'serve', '--config-dir', str(self.serve_dir),
                                      '--ready-file', str(ready)], env=self.env,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 10
        while not ready.exists():
            if self.proc.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('serve did not start: ' + self.proc.stderr.read().decode())
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
