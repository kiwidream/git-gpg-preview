"""End-to-end tests for remote signing: a real serve process behind fake
tailscale/gpg/dialog helpers, driven by the real client, plus one run
against real GnuPG with a disposable key."""
import base64
import concurrent.futures
import json
import importlib.util
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'git_gpg_preview_remote.py'
CLIENT = ROOT / 'git-gpg-preview-client'
HELPERS = ROOT / 'tests' / 'helpers'
_spec = importlib.util.spec_from_file_location('git_gpg_preview_remote', MODULE)
remote = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(remote)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


SERVICE_KEY = '041CE6A7BED57FE579D43B6C3DB3F5612E33B6BC'   # the fake GPG's one secret key


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
        if not (tmp / 'bin' / 'tailscale').exists():
            (tmp / 'bin' / 'tailscale').symlink_to(HELPERS / 'fake-tailscale.py')
        defaults = {}
        if real_gpg is None:
            # By default the service key is on a card whose touch policy reads
            # on, through the gpg-connect-agent beside GPG, so the preview runs
            # beside GPG and the touch is the gate.
            gnupg = tmp / 'default-gnupg'
            gnupg.mkdir(parents=True, exist_ok=True)
            for name, helper in (('gpg', 'fake-gpg.py'), ('gpg-connect-agent', 'fake-gpg-connect-agent.py')):
                if not (gnupg / name).exists():
                    (gnupg / name).symlink_to(HELPERS / helper)
            (tmp / 'default-card').write_text(f'{SERVICE_KEY} %01+')
            defaults = {'FAKE_GPG_CARD_KEYS': SERVICE_KEY, 'FAKE_CARD_FILE': str(tmp / 'default-card')}
            real_gpg = str(gnupg / 'gpg')
        gpg = real_gpg
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
                    **defaults,
                    **(extra_env or {})}
        (tmp / 'gitconfig').write_text(f'[user]\n\tsigningkey = {git_signingkey}\n' if git_signingkey else '')
        (tmp / 'temp').mkdir(exist_ok=True)
        ready = tmp / 'ready'
        ready.unlink(missing_ok=True)
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
    g('config', 'user.email', 'preview@preview-tester.dev')  # not a reserved test domain
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

    def test_cancel_wins_even_when_gpg_finishes_first(self):
        self.h.decision.write_text('touch-then-cancel')
        result = self.h.client(self.sign_args(), self.second, self.repo)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'', 'no signature leaves the service after a cancel')
        self.assertIn(b'cancelled by operator', result.stderr)
        self.assertIn('decision=cancel', self.h.audit.read_text())

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
        in the file) makes the remote request wait; a dead owner is stale. With
        sign_timeout_seconds=8, 1.5s of waiting leaves the 6s a preview needs."""
        h = Harness(self.tmp / 'shared-lock', serve_extra='sign_timeout_seconds=8\n')
        self.addCleanup(h.stop)
        lock = self.tmp / 'shared-lock' / 'lock' / 'dialog.lock'
        lock.parent.mkdir(parents=True, exist_ok=True)
        holder = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(1.5)'])
        # Reap it the moment it exits: a zombie still answers kill -0, exactly
        # as it would for shlock, and would look like a live owner forever.
        import threading
        threading.Thread(target=holder.wait, daemon=True).start()
        lock.write_text(str(holder.pid))
        started = time.monotonic()
        result = h.client(self.sign_args(), self.second, self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreaterEqual(time.monotonic() - started, 1.2, 'waited for the local wrapper to finish')
        holder.wait()
        self.assertFalse(lock.exists(), 'released after signing')
        lock.write_text('999999')   # a pid nobody has: stale, proceed at once
        started = time.monotonic()
        result = h.client(self.sign_args(), self.second, self.repo)
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

    def test_environment_proxies_never_carry_the_signing_request(self):
        # An agent runtime routes its own traffic through an egress proxy and
        # exempts only localhost; the service is a tailnet peer, reached directly.
        dead = f'http://127.0.0.1:{free_port()}/'
        proxied = {name: dead for name in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY')}
        proxied.update({'no_proxy': 'localhost', 'NO_PROXY': 'localhost'})
        h = Harness(self.tmp / 'proxied', extra_env=proxied)
        self.addCleanup(h.stop)
        result = h.client(['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], self.second, self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'signature:remote')
        result = subprocess.run([sys.executable, str(MODULE), 'identity', '--config-dir', str(h.client_dir),
                                 '--address', f'127.0.0.1:{h.port}'], env={**h.env}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('fingerprint', json.loads(result.stdout))

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

    def test_mark_spam_persists_exact_subject_across_repositories_and_restart(self):
        self.h.decision.write_text('spam')
        result = self.h.client(self.sign_args(), self.second, self.repo)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b'')
        spam_file = self.h.serve_dir / 'spam-subjects'
        self.assertEqual(spam_file.read_bytes(), 'second commit Ω\n'.encode())
        self.assertEqual(spam_file.stat().st_mode & 0o777, 0o600)
        self.assertIn('decision=spam-mark', self.h.audit.read_text())
        self.assertEqual(next(self.h.captures.glob('*.spam-action')).read_text(), 'mark-spam')
        before = len(list(self.h.captures.glob('*.summary')))
        self.h.stop()
        self.h = Harness(self.tmp)
        self.addCleanup(self.h.stop)
        payload = self.second.partition(b'\n\n')[0] + '\n\n \tSECOND COMMIT Ω\t\r\nnew body\n'.encode()
        code, body = self.h.post({'version': 1, 'args': self.sign_args(), 'payload': base64.b64encode(payload).decode(),
                                  'context': {'repository': '/another/repository'}, 'fixture_override': True})
        self.assertEqual((code, body['status'], body['decision']), (200, 65, 'spam-reject'))
        self.assertEqual(body['stdout'], '')
        self.assertEqual(len(list(self.h.captures.glob('*.summary'))), before)
        self.assertEqual(self.h.gpg_calls(), [])
        self.assertIn('decision=spam-reject', self.h.audit.read_text())
        self.h.decision.write_text('sign')
        near = payload.replace('SECOND COMMIT Ω'.encode(), 'SECOND COMMIT Ω follow-up'.encode())
        result = self.h.client(self.sign_args(), near, self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        spam_file.unlink()  # removing the saved rule permits it again
        result = self.h.client(self.sign_args(), payload, self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_touch_then_spam_never_returns_a_signature(self):
        self.h.decision.write_text('touch-then-spam')
        result = self.h.client(self.sign_args(), self.second, self.repo)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b'')
        self.assertIn('decision=spam-mark', self.h.audit.read_text())

    def test_a_decision_cut_off_before_it_lands_refuses_the_signature(self):
        self.h.decision.write_text('touch-then-stall-spam')
        result = self.h.client(self.sign_args(), self.second, self.repo)
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assertEqual(result.stdout, b'', 'no signature leaves the service on an unreadable outcome')
        self.assertIn(b'never completed', result.stderr)
        self.assertIn('decision=pending-decision-lost', self.h.audit.read_text())
        self.assertNotEqual(self.h.gpg_calls(), [], 'the signature existed and was withheld')

    def test_queued_spam_is_rechecked_before_dialog(self):
        self.h.decision.write_text('delayed-spam')
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.h.client, self.sign_args(), self.second, self.repo)
            deadline = time.monotonic() + 5
            while not list(self.h.captures.glob('*.summary')) and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(list(self.h.captures.glob('*.summary')))
            second = pool.submit(self.h.client, self.sign_args(), self.second, self.repo)
            a, b = first.result(timeout=10), second.result(timeout=10)
        self.assertEqual((a.returncode, b.returncode), (1, 65), (a.stderr, b.stderr))
        self.assertEqual((a.stdout, b.stdout), (b'', b''))
        self.assertEqual(len(list(self.h.captures.glob('*.summary'))), 1)

    def test_spam_save_failure_cancels_and_reports_failure(self):
        self.h.decision.write_text('delayed-spam')
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.h.client, self.sign_args(), self.second, self.repo)
            deadline = time.monotonic() + 5
            while not list(self.h.captures.glob('*.summary')) and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(list(self.h.captures.glob('*.summary')))
            (self.h.serve_dir / 'spam-subjects').mkdir()
            result = pending.result(timeout=10)
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assertEqual(result.stdout, b'')
        self.assertIn(b'could not save spam subject', result.stderr)
        self.assertIn('decision=spam-save-error', self.h.audit.read_text())

    def test_remote_request_cannot_mark_spam(self):
        code, body = self.h.post({'version': 1, 'args': self.sign_args(), 'payload': base64.b64encode(self.second).decode(),
                                  'decision': 'spam', 'context': {'decision': 'spam'}})
        self.assertEqual((code, body['status']), (200, 0))
        self.assertFalse((self.h.serve_dir / 'spam-subjects').exists())

    @unittest.skipUnless(sys.platform == 'darwin', 'local wrapper needs macOS')
    def test_local_and_remote_signers_share_spam_rules(self):
        (self.tmp / 'git-gpg-preview').symlink_to(self.h.serve_dir)
        config = self.h.serve_dir / 'config'
        config.write_text(config.read_text().replace('ui_helper=/nonexistent',
                          f'ui_helper={ROOT.parent}/tests/helpers/fake-dialog.jxa'))
        env = {**self.h.env, 'XDG_CONFIG_HOME': str(self.tmp), 'FAKE_DIALOG_DECISION': 'spam'}
        result = subprocess.run([str(ROOT.parent / 'git-gpg-preview'), *self.sign_args()],
                                input=self.second, cwd=self.repo, env=env, capture_output=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b'')
        result = self.h.client(self.sign_args(), self.second, self.repo)
        self.assertEqual(result.returncode, 65, result.stderr)
        self.assertEqual(result.stdout, b'')
        self.h.decision.write_text('spam')
        result = self.h.client(self.sign_args(), self.initial, self.repo)
        self.assertEqual(result.returncode, 1, result.stderr)
        result = subprocess.run([str(ROOT.parent / 'git-gpg-preview'), *self.sign_args()],
                                input=self.initial, cwd=self.repo, env=env, capture_output=True)
        self.assertEqual(result.returncode, 65, result.stderr)
        self.assertEqual(result.stdout, b'')
        self.assertEqual((self.h.serve_dir / 'spam-subjects').read_bytes(),
                         'second commit Ω\ninitial message\n'.encode())

    def test_noncommit_payloads_do_not_offer_mark_spam(self):
        oid = subprocess.check_output(['git', '-C', str(self.repo), 'rev-parse', 'HEAD']).strip()
        for payload in (b'unknown\n\nSecond commit\n',
                        b'object ' + oid + b'\ntype commit\ntag example\n\nSecond commit\n',
                        self.second.partition(b'\n\n')[0] + b'\n\n'):
            result = self.h.client(self.sign_args(), payload, self.repo)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(list(self.h.captures.glob('*.spam-action')))
        for action in self.h.captures.glob('*.spam-action'):
            self.assertEqual(action.read_text(), '')

    def test_spam_parser_matches_wrapper_and_rules_are_literal(self):
        wrapper = (ROOT.parent / 'git-gpg-preview').read_text()
        parser = re.search(r'^spam_subject\(\) \{\n.*?^\}', wrapper, re.M | re.S).group()
        script = 'export LC_ALL=C\nMESSAGE="$1"\nPAYLOAD="$2"\n' + parser + '\nspam_subject\n'
        header = self.second.partition(b'\n\n')[0] + b'\n\n'
        subjects = [b'\n \tFancy Subject \t\r\nbody', 'Subject Ω Ä'.encode(), b'$(touch bad); `id`',
                    b'a\\b.*[0-9]|c', b'-n', b'a\x00b', b'a\tb', b'\n\t\n', b'\xffXYZ']
        message = self.tmp / 'subject.txt'
        payload = self.tmp / 'subject.payload'
        for value in subjects:
            with self.subTest(subject=value):
                message.write_bytes(value)
                payload.write_bytes(header + value)
                result = subprocess.run(['bash', '-c', script, 'bash', str(message), str(payload)], capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.rstrip(b'\n'), remote.spam_subject(header + value))
        spam_file = self.h.serve_dir / 'spam-subjects'
        spam_file.write_bytes(b'existing rule')
        remote.remember_spam_subject(spam_file, b'a\\b.*[0-9]|c')
        remote.remember_spam_subject(spam_file, b'a\\b.*[0-9]|c')
        self.assertEqual(spam_file.read_bytes(), b'existing rule\na\\b.*[0-9]|c\n')
        self.h.decision.write_text('sign')
        result = self.h.client(self.sign_args(), header + b'a\\b.*[0-9]|c\n', self.repo)
        self.assertEqual(result.returncode, 65, result.stderr)
        result = self.h.client(self.sign_args(), header + b'ab1\n', self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_fixture_subjects_match_the_wrapper(self):
        wrapper = (ROOT.parent / 'git-gpg-preview').read_text()
        subjects = re.search(r'^FIXTURE_SUBJECTS="(.*)"$', wrapper, re.M).group(1).split('|')
        domains = re.search(r'^FIXTURE_EMAIL_DOMAINS="(.*)"$', wrapper, re.M).group(1).split()
        self.assertEqual(frozenset(subjects), remote.FIXTURE_SUBJECTS)
        self.assertEqual(tuple(domains), remote.FIXTURE_EMAIL_DOMAINS)

    def test_reported_spam_subjects_are_refused_before_preview_and_gpg(self):
        header = self.initial.partition(b'\n\n')[0]
        for subject in ('pr head', 'mr head', 'initial commit', 'PR HEAD', '  MR HEAD\t', '\n\tInitial Commit \r'):
            with self.subTest(subject=subject):
                payload = header + b'\n\n' + subject.encode() + b'\n'
                result = self.h.client(self.sign_args(), payload, self.repo)
                self.assertEqual(result.returncode, 65, result.stderr)
                self.assertEqual(result.stdout, b'')
                code, body = self.h.post({'version': 1, 'args': self.sign_args(),
                                         'payload': base64.b64encode(payload).decode(), 'context': {}})
                self.assertEqual((code, body['status'], body['decision']), (200, 65, 'policy-reject'))
                self.assertEqual(body['stdout'], '')
        self.assertEqual(self.h.gpg_calls(), [])
        self.assertEqual(list(self.h.captures.iterdir()), [])

    def test_fixture_subject_parser_matches_wrapper(self):
        wrapper = (ROOT.parent / 'git-gpg-preview').read_text()
        subjects = re.search(r'^FIXTURE_SUBJECTS=.*$', wrapper, re.M).group()
        parser = re.search(r'^fixture_style_commit_subject\(\) \{\n.*?^\}', wrapper, re.M | re.S).group()
        script = subjects + '\n' + parser + '\nfixture_style_commit_subject "$1"\n'
        messages = {'pr head': 'pr head', 'mr head': 'mr head', 'initial commit': 'initial commit',
                    '\n \tPR HEAD\t\r\nbody': 'pr head', 'Initial commit: preview tool': None,
                    'pr head update': None, 'mr heading': None, 'head': None, 'pr': None,
                    'base fixture': None, 'Fix preview\n\npr head': None, '': None}
        message = self.tmp / 'subject.txt'
        for value, expected in messages.items():
            with self.subTest(message=value):
                message.write_text(value + '\n')
                result = subprocess.run(['bash', '-c', script, 'bash', str(message)], capture_output=True)
                self.assertEqual(result.returncode, 0 if expected else 1, result.stderr)
                self.assertEqual(result.stdout.decode().strip() or None, expected)
                self.assertEqual(remote.fixture_subject(value), expected)

    def test_remote_fixture_policy_cannot_be_overridden_by_requester(self):
        header = self.initial.partition(b'\n\n')[0]
        payloads = [header + b'\n\nseed\n',
                    self.initial.replace(b'preview@preview-tester.dev', b'tester@example.com', 1),
                    self.initial.replace(b'preview@preview-tester.dev', b'user@MacBook.local')]
        for payload in payloads:
            for override in ('GIT_GPG_PREVIEW_ALLOW_FIXTURE', 'GIT_GPG_PREVIEW_ALLOW_SUBJECT'):
                with self.subTest(payload=payload, override=override):
                    result = self.h.client(self.sign_args(), payload, self.repo, env={override: '1'})
                    self.assertEqual(result.returncode, 65)
                    self.assertEqual(result.stdout, b'')
                    self.assertIn(b'refusing to sign fixture-style commit', result.stderr)
            for flag in (True, 1, '1'):
                with self.subTest(payload=payload, flag=flag):
                    code, body = self.h.post({'version': 1, 'args': self.sign_args(),
                                              'payload': base64.b64encode(payload).decode(),
                                              'fixture_override': flag, 'context': {'fixture_override': flag}})
                    self.assertEqual((code, body['status'], body['decision']), (200, 65, 'policy-reject'))
                    self.assertEqual(body['stdout'], '')
        self.assertEqual(self.h.gpg_calls(), [])
        self.assertEqual(list(self.h.captures.iterdir()), [])
        self.assertNotIn('decision=policy-override', self.h.audit.read_text())

    def test_test_identities_are_refused_on_both_sides(self):
        g = lambda *a, env=None: subprocess.run(['git', '-C', str(self.repo), *a], check=True, capture_output=True,
                                                env={**os.environ, **(env or {})}).stdout
        cases = {'author': (['--author', 'Tester <fingerprint@example.invalid>'], {}),
                 'committer': ([], {'GIT_COMMITTER_EMAIL': 'ci@Orca.TEST'})}
        for role, (flags, env) in cases.items():
            with self.subTest(role=role):
                g('commit', '-q', '--allow-empty', *flags, '-m', 'Descriptive subject from a test', env=env)
                payload = g('cat-file', 'commit', 'HEAD')
                result = self.h.client(self.sign_args(), payload, self.repo)
                self.assertEqual(result.returncode, 65)
                self.assertIn(b"fixture-style commit identity '", result.stderr)
                code, body = self.h.post({'version': 1, 'args': self.sign_args(),
                                          'payload': base64.b64encode(payload).decode(), 'context': {}})
                self.assertEqual((code, body['status'], body['decision']), (200, 65, 'policy-reject'))
        self.assertEqual(self.h.gpg_calls(), [])

    def test_fixture_identity_rule_edges(self):
        def reason(author, committer='R <r@swaplabs.io>', message='Subject\n'):
            payload = (f'tree {"0" * 40}\nauthor {author} 1 +0000\ncommitter {committer} 1 +0000\n\n{message}').encode()
            return remote.fixture_reason(remote.parse_payload(payload))
        self.assertEqual(reason('A <a@sub.example.com>'), "identity 'a@sub.example.com'")
        self.assertEqual(reason('A <a@test.local>'), "identity 'a@test.local'")
        self.assertEqual(reason('A <a@latest>'), None)
        self.assertEqual(reason('A <a@notexample.com>'), None)
        self.assertEqual(reason('A <a@swaplabs.io>', message='Subject\n\nCo-authored-by: T <t@example.com>\n'), None)
        self.assertEqual(reason('A <a@example.com>', message='seed\n'), "subject 'seed'")
        tag = f'object {"0" * 40}\ntype commit\ntag v1\ntagger T <t@example.com> 1 +0000\n\nseed\n'.encode()
        self.assertIsNone(remote.fixture_reason(remote.parse_payload(tag)))

    def test_fixture_identity_parser_matches_wrapper_awk(self):
        wrapper = (ROOT.parent / 'git-gpg-preview').read_text()
        domains = re.search(r'^FIXTURE_EMAIL_DOMAINS=.*$', wrapper, re.M).group()
        parser = re.search(r'^fixture_style_commit_identity\(\) \{\n.*?^\}', wrapper, re.M | re.S).group()
        script = domains + '\n' + parser + '\nfixture_style_commit_identity "$1"\n'
        emails = [f'a@{domain}' for domain in remote.FIXTURE_EMAIL_DOMAINS]
        emails += ['a@Sub.Example.COM', 'a@notexample.com', 'a@latest', 'a@example.com.',
                   'a@example.com..', 'a@.test', 'example.com', ' a@example.com\t',
                   'A\u00c4@example.com', 'a@example.com\u00a0', '', 'a@']
        headers = [f'{role} Tester <{email}> 1 +0000' for role in ('author', 'committer') for email in emails]
        headers += ['author Tester <a@example.com', 'author Tester a@example.com',
                    'author Tester <ignored<a@example.com> 1 +0000',
                    'author\tTester <a@example.com> 1 +0000',
                    '\tcommitter Tester <a@example.com> 1 +0000',
                    'tagger Tester <a@example.com> 1 +0000',
                    'author Tester <a@preview-tester.dev> 1 +0000\n\ncommitter T <a@example.com> 1 +0000']
        for header in headers:
            with self.subTest(header=header):
                payload = self.tmp / 'parser-parity.payload'
                payload.write_text(header + '\n\nDescriptive subject\n')
                result = subprocess.run(['/bin/bash', '-c', script, 'bash', str(payload)],
                                        env={**os.environ, 'LC_ALL': 'C'}, capture_output=True, text=True)
                self.assertIn(result.returncode, (0, 1), result.stderr)
                self.assertEqual(result.stderr, '')
                expected = result.stdout.rstrip('\n') if result.returncode == 0 else None
                self.assertEqual(remote.fixture_identity(header), expected)

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

    def test_a_request_names_one_key_and_u_ends_its_bundle(self):
        """GPG reads -ub as -u b and signs with every key named, so any other
        shape could add a signer of the request's own choosing beside the pinned
        key, and the touch would authorize a key nobody was shown."""
        key = '3DB3F5612E33B6BC'
        for args in (['--status-fd=2', '-ub', '-bsau', key],
                     ['--status-fd=2', '-bsaub', key],
                     ['--status-fd=2', '-bsua', key],
                     ['--status-fd=2', '-uu', key],
                     ['--status-fd=2', '-bsau', key, '-u', key],
                     ['--status-fd=2', '-u', key, '-u', key],
                     ['--status-fd=2', '-bsau', key, '--local-user', key],
                     ['--status-fd=2', '-bsau', key, '--local-user=x'],
                     ['--status-fd=2', '--local-user=x', '-bsau', key],
                     ['--status-fd=2', '-bsau', key, f'--local-user={key}'],
                     ['--status-fd=2', '-bsau', key, '--default-key', key],
                     ['--status-fd=2', '-bsau', key, f'--default-key={key}']):
            with self.subTest(args=args):
                code, body = self.h.post({'version': 1, 'args': args, 'payload': base64.b64encode(self.second).decode(), 'context': {}})
                self.assertEqual((code, body['status'], body['decision']), (200, 65, 'refused'), body)
                self.assertEqual(self.h.gpg_calls(), [], 'GPG started')
                self.assertEqual(list(self.h.captures.iterdir()), [], 'a preview opened')
                with self.assertRaises(remote.RemoteError):
                    remote.validate_signing_args(args)
        # The shapes Git sends and the README documents still pass.
        for args in (['--status-fd=2', '-bsau', key], ['--status-fd', '2', '-bsau', key], ['--status-fd=2', '-bsa', '-u', key],
                     ['--detach-sign', '--armor', '--local-user', key], ['--detach-sign', '--armor', f'--local-user={key}'],
                     ['--status-fd=2', '-bsa']):
            with self.subTest(args=args):
                remote.validate_signing_args(args)
                self.assertEqual(remote.pin_key_selector(args, '041CE6A7BED57FE579D43B6C3DB3F5612E33B6BC')[-2:],
                                 ['--local-user', '041CE6A7BED57FE579D43B6C3DB3F5612E33B6BC'])

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


# A suggestion of the cached touch policy, which nothing may show.
CACHED_HINT = re.compile(r'set-touch\s+sig\s+cached|use cached', re.I)


class TouchPolicyTests(unittest.TestCase):
    """A touch policy of off or cached on the card key the service signs with
    puts the ykman command above the facts, as in the wrapper; signing goes ahead
    either way. The policy is read with the gpg-connect-agent beside real GPG."""
    PRIMARY = '041CE6A7BED57FE579D43B6C3DB3F5612E33B6BC'   # the fake service key
    CARD_SUB = 'AAAA000000000000000000000000000000000002'
    OTHER = 'BBBB000000000000000000000000000000000002'

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(prefix='ggp-touch.')
        self.addCleanup(self.tmpdir.cleanup)
        self.tmp = Path(self.tmpdir.name)
        self.gnupg = self.tmp / 'gnupg-bin'
        self.gnupg.mkdir()
        (self.gnupg / 'gpg').symlink_to(HELPERS / 'fake-gpg.py')
        (self.gnupg / 'gpg-connect-agent').symlink_to(HELPERS / 'fake-gpg-connect-agent.py')
        self.card = self.tmp / 'card'
        self.repo, self.initial, self.payload = fixture_repo(self.tmp)

    def harness(self, name: str, real_gpg: Path | None = None, card_keys: str = CARD_SUB, extra_env: dict | None = None,
                serve_extra: str = '') -> Harness:
        h = Harness(self.tmp / name, real_gpg=str(real_gpg or self.gnupg / 'gpg'),
                    extra_env={'FAKE_GPG_SECRET_KEYS': f'{self.PRIMARY}/{self.CARD_SUB}',
                               'FAKE_GPG_CARD_KEYS': card_keys, 'FAKE_CARD_FILE': str(self.card), **(extra_env or {})},
                    serve_extra=serve_extra)
        self.addCleanup(h.stop)
        return h

    def sign(self, h: Harness, card: str, selector: str = '3DB3F5612E33B6BC') -> tuple[str, str]:
        """Signs through the client with CARD in the reader: its signature key
        and raw UIF-1 value, or '' for no card. Returns the preview summary
        and the client's stderr, after checking that neither they nor the
        details suggest the cached policy."""
        if card:
            self.card.write_text(card)
        else:
            self.card.unlink(missing_ok=True)
        result = h.client(['--status-fd=2', '-bsau', selector], self.payload, self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'signature:remote')
        summary, details = h.latest_capture()
        stderr = result.stderr.decode()
        self.assertNotRegex(summary + details + stderr, CACHED_HINT)
        return summary, stderr

    @staticmethod
    def facts_max_lines() -> int:
        """How many fact lines dialog.jxa's facts pane shows before it scrolls."""
        return int(re.search(r'^const FACTS_MAX_LINES = (\d+);$', (ROOT.parent / 'dialog.jxa').read_text(), re.M).group(1))

    @staticmethod
    def note(policy: str) -> str:
        """The one stderr line that carries POLICY's notice."""
        return 'git-gpg-preview: note from the signing Mac: ' + remote.TOUCH_NOTICES[policy].replace('\n', ' ') + '\n'

    @staticmethod
    def agent_calls(h: Harness) -> int:
        calls = h.calls / 'connect-agent-calls'
        return len(calls.read_text().splitlines()) if calls.exists() else 0

    def test_off_and_cached_go_above_the_facts_and_signing_goes_ahead(self):
        h = self.harness('h')
        for uif, policy in (('%00+', 'off'), ('%03+', 'cached')):
            with self.subTest(policy=policy):
                summary, stderr = self.sign(h, f'{self.CARD_SUB} {uif}')
                self.assertTrue(summary.startswith(remote.TOUCH_NOTICES[policy] + '\n\nRequest type: commit\n'), summary)
                facts, marker, message = summary.partition('\n\nMessage:\n')
                self.assertIn('ykman openpgp keys set-touch sig on', facts)
                self.assertTrue(marker and message.startswith('Second commit'), summary)
                self.assertLessEqual(len(facts.split('\n')), self.facts_max_lines(), 'the facts pane would scroll')
                details = h.latest_capture()[1]
                self.assertTrue(details.startswith(remote.TOUCH_NOTICES[policy] + '\n\nGIT OPENPGP SIGNING REVIEW'), details[:300])
                self.assertIn(self.note(policy), stderr)
                self.assertEqual(stderr.count('note from the signing Mac'), 1, stderr)
        self.assertEqual(self.agent_calls(h), 2, 'the policy is read once per request')

    def test_on_fixed_cached_fixed_and_unreadable_policies_get_no_notice(self):
        h = self.harness('h')
        for card in (f'{self.CARD_SUB} %01+', f'{self.CARD_SUB} %04+', f'{self.CARD_SUB} %02+',
                     f'{self.CARD_SUB} %05+', self.CARD_SUB, f'{self.OTHER} %00+', ''):
            with self.subTest(card=card):
                summary, stderr = self.sign(h, card)
                self.assertTrue(summary.startswith('Request type: commit\n'), summary)
                self.assertTrue(h.latest_capture()[1].startswith('GIT OPENPGP SIGNING REVIEW'))
                self.assertNotIn('ykman', stderr)
                self.assertNotIn('note from the signing Mac', stderr)

    def test_a_software_key_or_no_gpg_connect_agent_gets_no_notice(self):
        for name, h in (('software key', self.harness('software', card_keys='')),
                        ('no gpg-connect-agent', self.harness('plain', real_gpg=HELPERS / 'fake-gpg.py'))):
            with self.subTest(name):
                summary, stderr = self.sign(h, f'{self.CARD_SUB} %00+')
                self.assertTrue(summary.startswith('Request type: commit\n'), summary)
                self.assertNotIn('ykman', stderr)
                self.assertNotIn('note from the signing Mac', stderr)
                self.assertEqual(self.agent_calls(h), 0)

    def test_the_note_reaches_git_beside_a_failure(self):
        h = self.harness('h')
        h.decision.write_text('cancel')
        self.card.write_text(f'{self.CARD_SUB} %00+')
        result = h.client(['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], self.payload, self.repo)
        self.assertEqual((result.returncode, result.stdout), (1, b''))
        stderr = result.stderr.decode()
        self.assertIn(self.note('off'), stderr)
        self.assertNotRegex(stderr, CACHED_HINT)
        self.assertIn('signing cancelled by operator', stderr)

    @staticmethod
    def touch_at_start(h: Harness) -> list[str]:
        """For each signing GPG call, whether the fake dialog's answer (and so
        the touch) already existed when it started: 'before' only when GPG
        waited for the preview."""
        record = h.calls / 'touch-at-start'
        return record.read_text().split() if record.exists() else []

    @staticmethod
    def gate(h: Harness) -> str:
        """What the latest preview was told beyond its files: require-sign and
        the notice, or nothing."""
        return sorted(h.captures.glob('*.gate'), key=lambda p: p.stat().st_mtime)[-1].read_text()

    @staticmethod
    def untouch(h: Harness) -> None:
        """Forgets earlier touches and their records, so the same payload can be
        signed again with a fresh answer."""
        for path in [*h.tmp.glob('touch.*'), h.calls / 'touch-at-start']:
            path.unlink(missing_ok=True)

    REFUSED = 'git-gpg-preview: not signed: touch policy is off and Sign was not clicked\n'

    def test_touch_off_starts_gpg_only_after_sign(self):
        h = self.harness('h')
        h.decision.write_text('delayed-sign')
        _, stderr = self.sign(h, f'{self.CARD_SUB} %00+')
        self.assertEqual(self.touch_at_start(h), ['before'], 'GPG started before Sign')
        self.assertEqual(self.gate(h), 'require-sign\n' + remote.TOUCH_NOTICES['off'])
        self.assertNotIn('not signed', stderr)
        # The client cannot know the policy, so its hint names both answers.
        self.assertIn('on that machine, touch the key when its preview appears (touch policy on or fixed), '
                      'or click Sign in the preview (off, cached, cached-fixed or unknown)\n', stderr)

    def test_an_unknown_policy_needs_sign_too(self):
        """A policy that cannot be read (an unknown value, a reply whose status
        word is not 90 00, no setting, no card, another key on the card, a
        software key or no gpg-connect-agent) may hide touch off: the preview
        asks for Sign with its own notice, GPG waits for Sign, and anything
        else signs nothing."""
        cases = ((self.harness('unknown'), f'{self.CARD_SUB} %05+'), (self.harness('unset'), self.CARD_SUB),
                 (self.harness('apdu-sw', extra_env={'FAKE_CARD_APDU_SW': '6A 82'}), f'{self.CARD_SUB} %01+'),
                 (self.harness('none'), ''), (self.harness('other'), f'{self.OTHER} %01+'),
                 (self.harness('software', card_keys=''), f'{self.CARD_SUB} %01+'),
                 (self.harness('plain', real_gpg=HELPERS / 'fake-gpg.py'), f'{self.CARD_SUB} %01+'))
        for h, card in cases:
            with self.subTest(home=h.tmp.name):
                h.decision.write_text('delayed-sign')
                self.sign(h, card)
                self.assertEqual(self.touch_at_start(h), ['before'], 'GPG started before Sign')
                self.assertEqual(self.gate(h), 'require-sign\n' + remote.UNKNOWN_TOUCH_NOTICE)
        for choice, status in (('cancel', remote.EX_CANCELLED), ('hang', remote.EX_SOFTWARE)):
            with self.subTest(choice=choice):
                h = self.harness(f'refused-{choice}')
                h.decision.write_text(choice)
                self.card.write_text(f'{self.CARD_SUB} %05+')
                result = h.client(['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], self.payload, self.repo)
                self.assertEqual((result.returncode, result.stdout), (status, b''))
                self.assertIn(b'not signed: touch policy is unknown and Sign was not clicked', result.stderr)
                self.assertEqual((h.gpg_calls(), self.touch_at_start(h)), ([], []))

    def test_on_and_fixed_start_gpg_with_the_preview(self):
        h = self.harness('h')
        h.decision.write_text('delayed-sign')
        for card in (f'{self.CARD_SUB} %01+', f'{self.CARD_SUB} %02+'):
            with self.subTest(card=card):
                self.untouch(h)
                self.sign(h, card)
                self.assertEqual(self.touch_at_start(h), ['after'], 'GPG waited for a click')
                self.assertEqual(self.gate(h), '\n')

    def test_cached_and_cached_fixed_always_need_sign(self):
        """One touch on a cached key signs whatever follows for 15 seconds,
        touches made outside this service included, so every signature with it
        waits for Sign, with the notice that says so; Cancel signs nothing."""
        for uif, policy, notice in (('%03+', 'cached', remote.TOUCH_NOTICES['cached']),
                                    ('%04+', 'cached-fixed', remote.CACHED_FIXED_TOUCH_NOTICE)):
            with self.subTest(policy=policy):
                h = self.harness(policy)
                h.decision.write_text('delayed-sign')
                for _ in range(2):
                    self.untouch(h)
                    self.sign(h, f'{self.CARD_SUB} {uif}')
                    self.assertEqual(self.touch_at_start(h), ['before'], 'GPG started before Sign')
                    self.assertEqual(self.gate(h), 'require-sign\n' + notice)
                h = self.harness(f'{policy}-cancel')
                h.decision.write_text('cancel')
                self.card.write_text(f'{self.CARD_SUB} {uif}')
                result = h.client(['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], self.payload, self.repo)
                self.assertEqual((result.returncode, result.stdout), (remote.EX_CANCELLED, b''))
                self.assertIn(f'not signed: touch policy is {policy} and Sign was not clicked'.encode(), result.stderr)
                self.assertEqual((h.gpg_calls(), self.touch_at_start(h)), ([], []))

    def test_any_other_signing_key_in_the_certificate_needs_sign(self):
        """GnuPG 2.3 and later may sign with the certificate's software signing
        key, whose passphrase may be cached, with no touch, and a key on another
        card signs under that card's policy: on and fixed keep the touch as the
        gate only when the card's slot-1 key, whose policy was read, is the only
        usable signing key. A key GPG cannot pick does not count, and that takes in
        a primary key while a subkey can sign, whatever its kind. Kind mixed says
        so whatever the policy, with no advice to change it, and its refusal
        says so too."""
        soft, other_card = '5' * 40, 'B' * 40
        mixed = f'{self.PRIMARY}/{self.CARD_SUB}/{soft}'
        needs_sign = 'require-sign\n' + remote.OTHER_KEY_NOTICE
        for name, keys, extra, uif, gate in (
                ('on', mixed, {}, '%01+', needs_sign),
                ('fixed', mixed, {}, '%02+', needs_sign),
                ('stub primary', f'{self.PRIMARY}/{self.CARD_SUB}', {'FAKE_GPG_STUB_KEYS': self.PRIMARY}, '%01+', '\n'),
                ('card primary', f'{self.PRIMARY}/{self.CARD_SUB}',
                 {'FAKE_GPG_CARD_KEYS': f'{self.PRIMARY},{self.CARD_SUB}'}, '%01+', '\n'),
                ('two card subkeys', f'{self.PRIMARY}/{self.CARD_SUB}/{other_card}',
                 {'FAKE_GPG_CARD_KEYS': f'{self.CARD_SUB},{other_card}'}, '%01+', needs_sign),
                ('off', mixed, {}, '%00+', needs_sign),
                ('cached', mixed, {}, '%03+', needs_sign),
                ('cached-fixed', mixed, {}, '%04+', needs_sign),
                ('software pick', f'{self.PRIMARY}/{soft}/{self.CARD_SUB}', {}, '%01+', needs_sign),
                ('software primary', f'{self.PRIMARY}/{self.CARD_SUB}', {}, '%01+', '\n')):
            with self.subTest(name):
                h = self.harness(name.replace(' ', '-'), extra_env={'FAKE_GPG_SECRET_KEYS': keys, **extra})
                h.decision.write_text('delayed-sign')
                summary, stderr = self.sign(h, f'{self.CARD_SUB} {uif}')
                self.assertEqual(self.gate(h), gate)
                self.assertEqual(self.touch_at_start(h), ['after' if gate == '\n' else 'before'])
                self.assertNotIn('ykman', summary + stderr)
        for uif, in (('%01+',), ('%00+',)):
            with self.subTest(refused=uif):
                h = self.harness(f'cancel-{uif[1:3]}', extra_env={'FAKE_GPG_SECRET_KEYS': mixed})
                h.decision.write_text('cancel')
                self.card.write_text(f'{self.CARD_SUB} {uif}')
                result = h.client(['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], self.payload, self.repo)
                self.assertEqual((result.returncode, result.stdout), (remote.EX_CANCELLED, b''))
                self.assertIn(b'git-gpg-preview: not signed: GPG could sign with more than one key '
                              b'and Sign was not clicked\n', result.stderr)
                self.assertNotIn(b'touch policy is', result.stderr)
                self.assertEqual((h.gpg_calls(), self.touch_at_start(h)), ([], []))

    def test_every_certificate_the_selector_matches_counts(self):
        """GPG need not choose the first certificate a selector matches, so
        another with a different signing key, in software or on another card, needs
        Sign. One listing only the same key leaves the touch as the gate. The
        service names a fingerprint and refuses a user ID, so this takes a second
        certificate listed for that fingerprint once the service has started."""
        soft, other_card = '5' * 40, 'B' * 40
        for name, also, card_keys, gate in (
                ('software', f'{self.OTHER}/{soft}', self.CARD_SUB, 'require-sign\n' + remote.OTHER_KEY_NOTICE),
                ('another-card', f'{self.OTHER}/{other_card}', f'{self.CARD_SUB},{other_card}',
                 'require-sign\n' + remote.OTHER_KEY_NOTICE),
                ('same-key', f'{self.OTHER}/{self.CARD_SUB}', self.CARD_SUB, '\n')):
            with self.subTest(name):
                listed = self.tmp / f'also-{name}'
                h = self.harness(f'also-{name}-home', card_keys=card_keys, extra_env={'FAKE_GPG_ALSO_MATCHES': str(listed)})
                listed.write_text(also)
                h.decision.write_text('delayed-sign')
                self.sign(h, f'{self.CARD_SUB} %01+')
                self.assertEqual(self.gate(h), gate)
                self.assertEqual(self.touch_at_start(h), ['after' if gate == '\n' else 'before'])

    def test_a_trailing_bang_does_not_narrow_the_certificate(self):
        """The service drops a selector's !, so GPG may sign with any usable
        signing key in the certificate, and the whole certificate decides even
        when a card key was named exactly."""
        soft = '5' * 40
        for name, keys, card_keys, named, gate in (
                ('card only', f'{self.PRIMARY}/{self.CARD_SUB}', self.CARD_SUB, self.CARD_SUB, '\n'),
                ('mixed', f'{self.PRIMARY}/{self.CARD_SUB}/{soft}', self.CARD_SUB, self.CARD_SUB,
                 'require-sign\n' + remote.OTHER_KEY_NOTICE),
                ('software', f'{self.PRIMARY}/{soft}', '', soft, 'require-sign\n' + remote.UNKNOWN_TOUCH_NOTICE)):
            with self.subTest(name):
                h = self.harness(name.replace(' ', '-'), card_keys=card_keys, extra_env={'FAKE_GPG_SECRET_KEYS': keys},
                                 serve_extra=f'signing_key={named}!\n')
                h.decision.write_text('delayed-sign')
                self.sign(h, f'{self.CARD_SUB} %01+', selector=f'{named}!')
                self.assertEqual(self.gate(h), gate)
                self.assertEqual(self.touch_at_start(h), ['after' if gate == '\n' else 'before'])
                self.assertEqual(h.gpg_calls()[-1][0][-2:], [b'--local-user', named.encode()], 'GPG was handed no !')

    def test_more_than_one_card_makes_the_policy_unknown(self):
        """The same key may be on two inserted cards, and GPG may sign on the one
        whose policy was not read: where scdaemon lists more than one card, Sign
        is needed. One card, or a scdaemon that refuses the command, changes
        nothing."""
        for name, cards, gate in (('two', 'D2760001240100000006000000010000 D2760001240100000006000000020000',
                                   'require-sign\n' + remote.UNKNOWN_TOUCH_NOTICE),
                                  ('one', 'D2760001240100000006000000010000', '\n'),
                                  ('none-listed', '', '\n'),
                                  ('refused', None, '\n')):
            with self.subTest(name):
                h = self.harness(name, extra_env={} if cards is None else {'FAKE_CARD_LIST': cards})
                h.decision.write_text('delayed-sign')
                self.sign(h, f'{self.CARD_SUB} %01+')
                self.assertEqual(self.gate(h), gate)
                self.assertEqual(self.touch_at_start(h), ['after' if gate == '\n' else 'before'])

    def test_the_other_key_notice_matches_the_wrapper(self):
        wrapper = (ROOT.parent / 'git-gpg-preview').read_text()
        self.assertEqual(re.search(r'^OTHER_KEY_NOTICE="(.*)"$', wrapper, re.M).group(1), remote.OTHER_KEY_NOTICE)
        self.assertLessEqual(len(remote.OTHER_KEY_NOTICE), 80)

    def test_the_gate_follows_require_sign_not_the_notice(self):
        """In process: an empty notice still asks for Sign and still holds GPG
        back until it comes."""
        h = self.harness('h')
        service = remote.Service(remote.ServeConfig(h.serve_dir), {'login': '', 'node': 'mac', 'ips': []})
        info = remote.parse_payload(self.payload)
        for choice, status in (('cancel', remote.EX_CANCELLED), ('delayed-sign', 0)):
            with self.subTest(choice=choice), unittest.mock.patch.dict(os.environ, h.env):
                h.decision.write_text(choice)
                self.untouch(h)
                paths = {name: self.tmp / f'{choice}-{name}' for name in ('payload', 'summary.txt', 'details.txt', 'decision', 'ready')}
                paths['payload'].write_bytes(self.payload)
                digest = remote.hashlib.sha256(self.payload).hexdigest()
                paths['summary.txt'].write_text(f'Request type: commit\nSHA-256: {digest}\n\nMessage:\nSubject')
                paths['details.txt'].write_text('details')
                paths['decision'].write_text('')
                result = service._run_dialog_and_gpg(['--status-fd=2', '-bsau', self.PRIMARY], paths, info, digest,
                                                     'repo', 'peer', time.monotonic(),
                                                     require_sign=True, sign_notice='', policy='off')
                self.assertEqual(result['status'], status, result)
                self.assertEqual(self.gate(h), 'require-sign\n')
                self.assertEqual(self.touch_at_start(h), ['before'] if status == 0 else [])

    def test_touch_off_without_sign_signs_nothing(self):
        for choice, status in (('cancel', remote.EX_CANCELLED), ('garbage', remote.EX_SOFTWARE), ('hang', remote.EX_SOFTWARE)):
            with self.subTest(choice=choice):
                h = self.harness(choice)
                h.decision.write_text(choice)
                self.card.write_text(f'{self.CARD_SUB} %00+')
                started = time.monotonic()
                result = h.client(['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], self.payload, self.repo)
                self.assertLess(time.monotonic() - started, 10, 'sign_timeout_seconds=3 bounds the wait for Sign')
                self.assertEqual((result.returncode, result.stdout), (status, b''))
                self.assertIn(self.REFUSED, result.stderr.decode())
                self.assertEqual((h.gpg_calls(), self.touch_at_start(h)), ([], []), 'GPG started without Sign')
                self.assertIn('decision=' + ('cancel' if choice == 'cancel' else 'sign-not-clicked'), h.audit.read_text())

    def refused(self, h: Harness, choice: str, status: int = remote.EX_SOFTWARE, limit: float = 10):
        """Signs with touch off and the preview answering CHOICE, which must be
        refused within LIMIT seconds with STATUS and no GPG call. Returns the
        stderr and the preview's process id."""
        h.decision.write_text(choice)
        self.card.write_text(f'{self.CARD_SUB} %00+')
        started = time.monotonic()
        result = h.client(['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], self.payload, self.repo)
        self.assertLess(time.monotonic() - started, limit)
        self.assertEqual((result.returncode, result.stdout), (status, b''), result.stderr)
        self.assertIn(self.REFUSED, result.stderr.decode())
        self.assertEqual((h.gpg_calls(), self.touch_at_start(h)), ([], []), 'GPG started without Sign')
        pid = int(sorted(h.captures.glob('*.gate'), key=lambda p: p.stat().st_mtime)[-1].stem)
        return result.stderr.decode(), pid

    def test_only_the_exact_answer_sign_is_a_sign(self):
        for index, answer in enumerate(('raw: sign', 'raw:sign ', 'raw:Sign', 'raw:signsign', 'raw:sign\\n', 'raw:sign\\0', 'marker-sign')):
            with self.subTest(answer=answer):
                self.refused(self.harness(f'h{index}'), answer)
        h = self.harness('exact')
        h.decision.write_text('raw:sign')
        self.sign(h, f'{self.CARD_SUB} %00+')
        self.assertEqual(self.touch_at_start(h), ['before'])

    def test_only_exact_answers_cancel_or_mark_as_spam(self):
        """' cancel', 'cancel\\0' and 'spam\\n' are no answer the preview gives:
        refused as Sign not clicked, with the wrapper's status and audit name,
        neither as Cancel nor as Mark as Spam."""
        for index, answer in enumerate(('raw: cancel', 'raw:cancel\\0', 'raw:spam\\n')):
            with self.subTest(answer=answer):
                h = self.harness(f'x{index}')
                self.refused(h, answer)
                self.assertEqual(re.findall(r'decision=(\S+)', h.audit.read_text()), ['sign-not-clicked'])
                self.assertFalse((h.serve_dir / 'spam-subjects').exists())

    def test_after_sign_a_window_waits_for_the_touch_and_offers_cancel(self):
        """After Sign the preview has closed, and a key that still wants a touch
        gets a window that says so while GPG runs: a touch signs and closes it;
        Cancel in it stops GPG, cancels the card operation and signs nothing.
        When the touch is the gate the preview stays up instead, so no such
        window opens."""
        waiting = self.tmp / 'waiting'
        h = self.harness('touch', extra_env={'FAKE_WAITING_FILE': str(waiting)})
        waiting.write_text('touch')
        h.decision.write_text('approve-no-touch')
        self.sign(h, f'{self.CARD_SUB} %00+')
        self.assertEqual(self.touch_at_start(h), ['after'], 'GPG did not wait for the touch')
        windows = (h.captures / 'waiting-windows').read_text().split('\n')
        self.assertEqual((len(windows), windows[0].split()[0]), (2, 'waiting'))
        with self.assertRaises(ProcessLookupError, msg='the waiting window outlived the signature'):
            os.kill(int(windows[0].split()[1]), 0)
        queue = self.tmp / 'card-queue'
        queue.write_text('')
        h = self.harness('cancel', extra_env={'FAKE_WAITING_FILE': str(waiting), 'FAKE_CARD_QUEUE': str(queue)})
        waiting.write_text('cancel')
        h.decision.write_text('approve-no-touch')
        self.card.write_text(f'{self.CARD_SUB} %00+')
        result = h.client(['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], self.payload, self.repo)
        self.assertEqual((result.returncode, result.stdout), (remote.EX_CANCELLED, b''), result.stderr)
        self.assertIn(b'signing cancelled by operator', result.stderr)
        self.assertEqual(self.touch_at_start(h), ['after'], 'GPG did not run after Sign')
        self.assertIn('SCD KILLSCD /bye', (h.calls / 'connect-agent-calls').read_text().splitlines())
        self.assertEqual(queue.read_text(), '', 'the stopped signature still waits at the card')
        self.assertEqual(re.findall(r'decision=(\S+)', h.audit.read_text()), ['cancel'])
        h = self.harness('on', extra_env={'FAKE_WAITING_FILE': str(waiting)})
        self.sign(h, f'{self.CARD_SUB} %01+')
        self.assertFalse((h.captures / 'waiting-windows').exists())

    def test_the_policy_is_read_from_the_card_not_scdaemons_copy(self):
        """scdaemon answers GETATTR UIF-1 from the card data it read first, so a
        policy changed since (ykman openpgp keys set-touch) would read as the
        old one. The service asks the card itself: a key turned from on to off
        asks for Sign on the next request."""
        h = self.harness('h', extra_env={'FAKE_SCD_CACHE': str(self.tmp / 'scd-cache')})
        h.decision.write_text('delayed-sign')
        self.sign(h, f'{self.CARD_SUB} %01+')
        self.assertEqual(self.gate(h), '\n')
        self.untouch(h)
        self.sign(h, f'{self.CARD_SUB} %00+')
        self.assertEqual(self.gate(h), 'require-sign\n' + remote.TOUCH_NOTICES['off'])
        self.assertEqual(self.touch_at_start(h), ['before'], 'GPG started before Sign')

    def test_sign_timeout_must_be_positive_and_finite(self):
        h = self.harness('h')
        serve = (h.serve_dir / 'serve').read_text()
        self.assertLess(remote.MAX_SIGN_TIMEOUT, threading.TIMEOUT_MAX, 'Lock.acquire would raise OverflowError')
        for value in ('nan', 'inf', '-inf', '0', '-5', 'soon', '3600.5', '1e12', '1e400'):
            with self.subTest(value=value):
                (h.serve_dir / 'serve').write_text(f'{serve}sign_timeout_seconds={value}\n')
                with self.assertRaisesRegex(remote.RemoteError, 'sign_timeout_seconds must be a positive, finite.*at most 3600'):
                    remote.ServeConfig(h.serve_dir)
        for value, expected in (('7.5', 7.5), ('3600', 3600), ('', 120)):
            with self.subTest(value=value):
                (h.serve_dir / 'serve').write_text(f'{serve}sign_timeout_seconds={value}\n')
                self.assertEqual(remote.ServeConfig(h.serve_dir).sign_timeout, expected)

    def test_touch_off_mark_as_spam_saves_the_subject_without_gpg(self):
        h = self.harness('h')
        stderr, _ = self.refused(h, 'spam', remote.EX_CANCELLED)
        self.assertIn('subject marked as spam', stderr)
        self.assertEqual((h.serve_dir / 'spam-subjects').read_bytes(), 'second commit Ω\n'.encode())
        self.assertIn('decision=spam-mark', h.audit.read_text())

    def test_the_wait_for_sign_shares_the_request_time_and_ends_the_preview(self):
        """The request's time from its arrival covers the policy lookup, a
        preview that never shows and the wait for Sign, which ends where only
        GPG's reserve is left; a refused preview does not keep running."""
        # sign_timeout_seconds=8 keeps 4s for GPG, so Sign counts until 4s,
        # even after a 1.5s lookup.
        _, pid = self.refused(self.harness('slow', extra_env={'FAKE_CONNECT_AGENT_SLEEP': '1.5'},
                                           serve_extra='sign_timeout_seconds=8\n'), 'hang', limit=4.8)
        with self.assertRaises(ProcessLookupError, msg='the preview still runs after the refusal'):
            os.kill(pid, 0)
        _, pid = self.refused(self.harness('never'), 'never-ready', limit=3.5)
        with self.assertRaises(ProcessLookupError, msg='the preview still runs after the refusal'):
            os.kill(pid, 0)
        # An answer from a preview still open at the deadline does not count.
        self.refused(self.harness('early'), 'early-sign', limit=3.5)
        h = self.harness('slower', extra_env={'FAKE_CONNECT_AGENT_SLEEP': '4'})
        h.decision.write_text('hang')
        self.card.write_text(f'{self.CARD_SUB} %00+')
        started = time.monotonic()
        result = h.client(['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], self.payload, self.repo)
        self.assertTrue(2.5 < time.monotonic() - started < 3.5, f'{time.monotonic() - started:.1f}s, not about 3s')
        self.assertEqual(result.stdout, b'')
        self.assertNotEqual(result.returncode, 0)

    def test_a_long_wait_in_the_queue_leaves_the_policy_its_own_time(self):
        """The policy lookup's 10 seconds start once the locks are held: a
        request that queued for longer still reads on, and needs no Sign."""
        # sign_timeout_seconds=45 leaves the 32.5s a preview needs after 10.5s.
        h = self.harness('h', serve_extra='sign_timeout_seconds=45\n')
        holder = int(subprocess.run(['sh', '-c', 'sleep 10.5 >/dev/null 2>&1 & echo $!'],
                                    capture_output=True, text=True, check=True).stdout)
        (self.tmp / 'h' / 'lock').mkdir(parents=True, exist_ok=True)
        (self.tmp / 'h' / 'lock' / 'dialog.lock').write_text(str(holder))
        started = time.monotonic()
        self.sign(h, f'{self.CARD_SUB} %01+')
        self.assertGreater(time.monotonic() - started, 10, 'the request did not queue')
        self.assertEqual(self.gate(h), '\n', 'a long queue made the policy unknown')

    def test_sign_leaves_gpg_its_reserve_and_counts_until_then(self):
        """With sign_timeout_seconds=8 GPG keeps half (a minute, or a third of a
        long timeout, at most half) for the PIN and a touch, so Sign counts
        until 4s: at 2.5s it signs, at 3.5s with a 3s PIN and touch it still
        signs, and at 5s it is refused."""
        h = self.harness('in-time', serve_extra='sign_timeout_seconds=8\n')
        h.decision.write_text('late-sign:2.5')
        self.sign(h, f'{self.CARD_SUB} %00+')
        self.assertEqual(self.touch_at_start(h), ['before'])
        h = self.harness('slow-pin', extra_env={'FAKE_GPG_SLOW': '3'}, serve_extra='sign_timeout_seconds=8\n')
        h.decision.write_text('late-sign:3.5')
        self.sign(h, f'{self.CARD_SUB} %00+')
        self.refused(self.harness('late', serve_extra='sign_timeout_seconds=8\n'), 'late-sign:5', limit=5)
        self.assertEqual(remote.sign_budget(120), (60, 70))
        self.assertEqual(remote.sign_budget(300), (100, 110))

    def test_after_sign_a_key_that_never_confirms_is_stopped(self):
        h = self.harness('h')
        h.decision.write_text('approve-no-touch')
        self.card.write_text(f'{self.CARD_SUB} %00+')
        started = time.monotonic()
        result = h.client(['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], self.payload, self.repo)
        self.assertLess(time.monotonic() - started, 4.5)
        self.assertEqual((result.returncode, result.stdout), (remote.EX_SOFTWARE, b''))
        self.assertIn(b'not signed: no touch or PIN before the deadline', result.stderr)
        self.assertEqual(self.touch_at_start(h), ['after'], 'GPG did not run after Sign')
        self.assertIn('decision=gpg-timeout', h.audit.read_text())

    def test_queued_requests_never_outlive_their_time(self):
        """Two requests queued behind a dialog lock that another signer holds
        are refused within sign_timeout_seconds of arriving, and neither ever
        shows a preview."""
        h = self.harness('h')
        holder = subprocess.Popen(['sleep', '30'])
        self.addCleanup(holder.kill)
        (self.tmp / 'h' / 'lock').mkdir(parents=True, exist_ok=True)
        (self.tmp / 'h' / 'lock' / 'dialog.lock').write_text(str(holder.pid))
        self.card.write_text(f'{self.CARD_SUB} %01+')

        def request(_):
            started = time.monotonic()
            result = h.client(['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], self.payload, self.repo)
            return time.monotonic() - started, result

        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results = list(pool.map(request, range(2)))
        for elapsed, result in results:
            self.assertLess(elapsed, 4.5)
            self.assertEqual((result.returncode, result.stdout), (remote.EX_SOFTWARE, b''))
            self.assertIn(b'the signing Mac was busy for most of 3s', result.stderr)
        self.assertEqual(list(h.captures.glob('*.summary')), [], 'a queued request showed a preview')
        self.assertEqual(h.audit.read_text().count('decision=busy'), 2)
        # A request that gets the lock after waiting has only what is left of
        # its time: with sign_timeout_seconds=8, 6.5s after a 1.5s wait. The
        # holder is not this process's child, so it leaves no zombie that would
        # still look alive.
        h = self.harness('later', serve_extra='sign_timeout_seconds=8\n')
        holder = int(subprocess.run(['sh', '-c', 'sleep 1.5 >/dev/null 2>&1 & echo $!'],
                                    capture_output=True, text=True, check=True).stdout)
        (self.tmp / 'later' / 'lock').mkdir(parents=True, exist_ok=True)
        (self.tmp / 'later' / 'lock' / 'dialog.lock').write_text(str(holder))
        h.decision.write_text('hang')
        elapsed, result = request(0)
        self.assertLess(elapsed, 8.6, 'the wait for the lock was not counted')
        self.assertEqual((result.returncode, result.stdout), (remote.EX_SOFTWARE, b''))
        self.assertIn(b'no hardware confirmation within 8s', result.stderr)

    def test_a_stopped_signature_does_not_wait_at_the_card_for_the_next_touch(self):
        """After GPG is stopped while the card waits, for want of a touch (with
        Sign or without), on Cancel, Mark as Spam or a preview closed without
        an answer, the operation it left there is cancelled: the next request's
        touch signs that request, not the stale one."""
        for index, (uif, answer, status) in enumerate((('%00+', 'approve-no-touch', remote.EX_SOFTWARE),
                                                       ('%01+', 'approve-no-touch', remote.EX_SOFTWARE),
                                                       ('%01+', 'delayed-cancel', remote.EX_CANCELLED),
                                                       ('%01+', 'delayed-spam', remote.EX_CANCELLED),
                                                       ('%01+', 'delayed-garbage', remote.EX_SOFTWARE))):
            with self.subTest(uif=uif, answer=answer):
                queue = self.tmp / f'card-queue{index}'
                queue.write_text('')
                h = self.harness(f'stopped{index}', extra_env={'FAKE_CARD_QUEUE': str(queue)})
                h.decision.write_text(answer)
                self.card.write_text(f'{self.CARD_SUB} {uif}')
                result = h.client(['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], self.payload, self.repo)
                self.assertEqual((result.returncode, result.stdout), (status, b''))
                self.assertIn('SCD KILLSCD /bye', (h.calls / 'connect-agent-calls').read_text().splitlines())
                h.decision.write_text('sign')
                result = h.client(['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], self.initial, self.repo)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, f'signed:{remote.hashlib.sha256(self.initial).hexdigest()}'.encode(),
                                 'the next touch went to the stopped signature')

    def test_the_card_cancel_is_only_for_a_card_operation_left_pending(self):
        """Stopping scdaemon drops the PIN it holds and disturbs its other users,
        so the cancel goes only where a card operation may be pending: a GPG
        stopped while it ran, signing from a certificate with a signing key on
        a card (even when its software key is the pick, as GnuPG 2.3 and later
        may sign on the card), or one whose lookup failed. Not a certificate
        with no card signing key, and not a GPG that had already finished when
        the operator's Cancel landed."""
        soft = '5' * 40
        for name, extra, cancels in (('software', {'card_keys': ''}, False),
                                     ('card and software', {'extra_env': {'FAKE_GPG_SECRET_KEYS': f'{self.PRIMARY}/{soft}/{self.CARD_SUB}'}}, True),
                                     ('lookup failed', {'extra_env': {'FAKE_GPG_LIST_FAIL': str(self.tmp / 'list-fails')}}, True),
                                     ('finished', {}, False)):
            with self.subTest(name):
                h = self.harness(name.replace(' ', '-'), **extra)
                if name == 'lookup failed':
                    (self.tmp / 'list-fails').write_text('')  # the service has started; its lookup now fails
                h.decision.write_text('touch-then-late-cancel' if name == 'finished' else 'approve-no-touch')
                self.card.write_text(f'{self.CARD_SUB} {"%01+" if name == "finished" else "%00+"}')
                result = h.client(['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], self.payload, self.repo)
                status = remote.EX_CANCELLED if name == 'finished' else remote.EX_SOFTWARE
                self.assertEqual((result.returncode, result.stdout), (status, b''), result.stderr)
                if name == 'finished':
                    self.assertEqual(len(h.gpg_calls()), 1, 'GPG did not finish before the Cancel')
                else:
                    self.assertIn(b'not signed: no touch or PIN before the deadline', result.stderr)
                    self.assertEqual(self.gate(h).split('\n')[0], 'require-sign', 'the policy was read')
                calls = h.calls / 'connect-agent-calls'
                self.assertEqual('SCD KILLSCD /bye' in (calls.read_text() if calls.exists() else '').splitlines(), cancels)

    def test_a_gpg_that_finished_before_it_was_stopped_gets_no_card_cancel(self):
        """In process: GPG takes 0.4s, and the Cancel the preview wrote with the
        touch is read a second later, after GPG has signed. Stopping it then
        sends no KILLSCD: nothing waits at the card."""
        h = self.harness('h', extra_env={'FAKE_GPG_SLOW': '0.4'})
        service = remote.Service(remote.ServeConfig(h.serve_dir), {'login': '', 'node': 'mac', 'ips': []})
        info = remote.parse_payload(self.payload)
        read = remote.read_decision

        def slow_read(path):
            time.sleep(1)
            return read(path)

        h.decision.write_text('touch-then-cancel')
        paths = {name: self.tmp / f'finished-{name}' for name in ('payload', 'summary.txt', 'details.txt', 'decision', 'ready')}
        paths['payload'].write_bytes(self.payload)
        digest = remote.hashlib.sha256(self.payload).hexdigest()
        paths['summary.txt'].write_text(f'Request type: commit\nSHA-256: {digest}\n\nMessage:\nSubject')
        paths['details.txt'].write_text('details')
        paths['decision'].write_text('')
        with unittest.mock.patch.dict(os.environ, h.env), unittest.mock.patch.object(remote, 'read_decision', slow_read):
            result = service._run_dialog_and_gpg(['--status-fd=2', '-bsau', self.PRIMARY], paths, info, digest,
                                                 'repo', 'peer', time.monotonic(), require_sign=False, policy='on')
        self.assertEqual(result['status'], remote.EX_CANCELLED, result)
        self.assertEqual(len(h.gpg_calls()), 1, 'GPG did not finish')
        calls = h.calls / 'connect-agent-calls'
        self.assertNotIn('KILLSCD', calls.read_text() if calls.exists() else '')

    def test_a_pending_answer_is_read_with_the_one_rule(self):
        """An answer the preview began (its marker exists) is awaited as
        read_decision reads it: only exactly sign, cancel and spam count, so
        'sign ', 'sign\\n', ' cancel', 'cancel\\0' and bytes that are not UTF-8
        are answers but invalid, and an empty file is none yet. Such an answer
        after a touch releases nothing."""
        service = remote.Service.__new__(remote.Service)
        decision = self.tmp / 'decision'
        (self.tmp / 'decision.deciding').write_text('')
        for data, waits, read in ((b'sign ', False, 'invalid'), (b'sign\n', False, 'invalid'),
                                  (b' cancel', False, 'invalid'), (b'cancel\0', False, 'invalid'),
                                  (b'\xff\xfe', False, 'invalid'), (b'', True, ''),
                                  (b'sign', False, 'sign'), (b'cancel', False, 'cancel'),
                                  (b'spam', False, 'spam')):
            with self.subTest(data=data):
                decision.write_bytes(data)
                started = time.monotonic()
                service._await_pending_decision({'decision': decision})
                self.assertEqual(time.monotonic() - started >= remote.DECISION_GRACE_SECONDS * 0.9, waits)
                self.assertEqual(remote.read_decision(decision), read)
        for index, answer in enumerate(('marker-raw:sign ', 'marker-raw:sign\\n')):
            with self.subTest(answer=answer):
                h = self.harness(f'pending{index}')
                h.decision.write_text(answer)
                self.card.write_text(f'{self.CARD_SUB} %01+')
                result = h.client(['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], self.payload, self.repo)
                # Refused as unfinished or as no valid answer, whichever of the
                # preview and GPG ends first; never signed.
                self.assertEqual((result.returncode, result.stdout), (remote.EX_SOFTWARE, b''), result.stderr)
                self.assertNotIn('decision=sign\n', h.audit.read_text())

    def test_a_queued_request_for_a_touch_key_needs_no_time_for_sign(self):
        """With sign_timeout_seconds=8 GPG keeps 4s for the PIN and a touch, and
        a preview that asks for Sign needs 2s more. After 3s in the queue about
        5s are left: enough for a key whose touch is the gate, which still
        signs, too little for one that needs Sign, which is refused as busy."""
        for uif, signs in (('%01+', True), ('%02+', True), ('%00+', False), ('%03+', False)):
            with self.subTest(uif=uif):
                name = f'queued{uif[2]}'
                h = self.harness(name, serve_extra='sign_timeout_seconds=8\n')
                holder = int(subprocess.run(['sh', '-c', 'sleep 3 >/dev/null 2>&1 & echo $!'],
                                            capture_output=True, text=True, check=True).stdout)
                (self.tmp / name / 'lock').mkdir(parents=True, exist_ok=True)
                (self.tmp / name / 'lock' / 'dialog.lock').write_text(str(holder))
                self.card.write_text(f'{self.CARD_SUB} {uif}')
                started = time.monotonic()
                result = h.client(['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], self.payload, self.repo)
                self.assertGreater(time.monotonic() - started, 2.5, 'the request did not queue')
                if signs:
                    self.assertEqual((result.returncode, result.stdout), (0, b'signature:remote'), result.stderr)
                else:
                    self.assertEqual((result.returncode, result.stdout), (remote.EX_SOFTWARE, b''))
                    self.assertIn(b'the signing Mac was busy for most of 8s', result.stderr)
                    self.assertEqual((list(h.captures.glob('*.summary')), h.gpg_calls()), ([], []))

    def test_too_little_time_left_after_the_queue_is_refused_as_busy(self):
        """A lock wait that leaves less than a short read of the preview plus
        GPG's reserve shows no preview and starts no GPG, even for a key that
        needs a touch."""
        h = self.harness('h')
        holder = int(subprocess.run(['sh', '-c', 'sleep 2.6 >/dev/null 2>&1 & echo $!'],
                                    capture_output=True, text=True, check=True).stdout)
        (self.tmp / 'h' / 'lock').mkdir(parents=True, exist_ok=True)
        (self.tmp / 'h' / 'lock' / 'dialog.lock').write_text(str(holder))
        self.card.write_text(f'{self.CARD_SUB} %01+')
        started = time.monotonic()
        result = h.client(['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], self.payload, self.repo)
        self.assertLess(time.monotonic() - started, 3.5)
        self.assertEqual((result.returncode, result.stdout), (remote.EX_SOFTWARE, b''))
        self.assertIn(b'the signing Mac was busy for most of 3s', result.stderr)
        self.assertEqual((list(h.captures.glob('*.summary')), h.gpg_calls()), ([], []), 'a preview or GPG started')
        self.assertIn('decision=busy', h.audit.read_text())

    def test_a_notice_that_cannot_be_written_still_needs_sign(self):
        """In process, so writing the notice can be made to fail. Neither file
        gets it, the operator is told, and the preview still asks for Sign
        with the notice text: GPG waits for Sign, and Cancel signs nothing."""
        h = self.harness('h')
        self.card.write_text(f'{self.CARD_SUB} %00+')
        write_text = Path.write_text

        def details_fail(path, text, *args, **kwargs):
            if path.name == 'details.txt' and text.startswith('Touch policy'):
                raise OSError(28, 'No space left on device')
            return write_text(path, text, *args, **kwargs)

        request = {'args': ['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], 'payload': base64.b64encode(self.payload).decode(),
                   'context': {'repository': str(self.repo), 'branch': 'main'}}
        for choice, status in (('cancel', remote.EX_CANCELLED), ('delayed-sign', 0)):
            with self.subTest(choice=choice), unittest.mock.patch.dict(os.environ, h.env), \
                    unittest.mock.patch.object(Path, 'write_text', details_fail):
                h.decision.write_text(choice)
                self.untouch(h)
                service = remote.Service(remote.ServeConfig(h.serve_dir), {'login': '', 'node': 'mac', 'ips': []})
                result = service.sign(request, {'node': 'minidev-test', 'login': 'tester'})
                summary, details = h.latest_capture()
                self.assertEqual(result['status'], status, result)
                self.assertFalse(summary.startswith('Touch policy') or details.startswith('Touch policy'), 'only one file got the notice')
                self.assertEqual(self.gate(h), 'require-sign\n' + remote.TOUCH_NOTICES['off'])
                self.assertIn('could not add the touch policy notice to the preview or its details', result['stderr'])
                self.assertEqual(self.touch_at_start(h), ['before'] if status == 0 else [])
                if status:
                    self.assertIn(self.REFUSED, result['stderr'])

    def test_the_policy_lookup_counts_against_the_signing_time(self):
        h = self.harness('h', extra_env={'FAKE_CONNECT_AGENT_SLEEP': '2'})
        h.decision.write_text('approve-no-touch')
        self.card.write_text(f'{self.CARD_SUB} %01+')
        started = time.monotonic()
        result = h.client(['--status-fd=2', '-bsau', '3DB3F5612E33B6BC'], self.payload, self.repo)
        # Two of the three seconds went to the lookup: too little is left.
        self.assertEqual(result.returncode, remote.EX_SOFTWARE, result.stderr)
        self.assertIn(b'the signing Mac was busy for most of 3s', result.stderr)
        self.assertLess(time.monotonic() - started, 3.5, 'a 2s lookup and the 3s signing time were added up')

    def test_the_preview_is_the_only_window_and_nothing_is_recorded(self):
        h = self.harness('h')
        files = sorted(p.name for p in h.serve_dir.iterdir())
        for count, uif in enumerate(('%00+', '%01+', '%02+', '%03+', '%04+'), start=1):
            with self.subTest(uif=uif):
                self.sign(h, f'{self.CARD_SUB} {uif}')
                self.assertFalse((h.captures / 'other-windows').exists())
                self.assertEqual(len(list(h.captures.glob('*.summary'))), count)
                self.assertEqual(sorted(p.name for p in h.serve_dir.iterdir()), files)

    def test_an_old_offer_record_is_neither_read_nor_written(self):
        h = self.harness('h')
        record = h.serve_dir / 'touch-offers'
        old = f'{self.CARD_SUB} 3 {int(time.time())}\n'
        record.write_text(old)
        os.utime(record, (1, 1))
        for uif, policy in (('%00+', 'off'), ('%03+', 'cached')):
            with self.subTest(policy=policy):
                summary, stderr = self.sign(h, f'{self.CARD_SUB} {uif}')
                self.assertTrue(summary.startswith(remote.TOUCH_NOTICES[policy]), summary)
                self.assertIn(self.note(policy), stderr)
                self.assertEqual(record.read_text(), old)
                self.assertEqual(record.stat().st_mtime, 1)

    def test_the_summary_splits_at_the_first_message_line_and_keeps_long_messages(self):
        forged = 'x\n\nMessage:\nFORGED'
        info = {'type': 'commit', 'message': 'Subject\n\nMessage:\nBody'}
        summary = remote.Service._summary(None, info, ['-u', forged], b'payload', 'a' * 64, {'branch': forged}, forged)
        facts, marker, message = summary.partition('\n\nMessage:\n')
        self.assertEqual(message, 'Subject\n\nMessage:\nBody')
        self.assertEqual(len(facts.split('\n')), 6, facts)
        for line in ('Requested by: x  Message: FORGED', 'Branch: x  Message: FORGED', 'Signing key: x  Message: FORGED'):
            self.assertIn(line, facts.split('\n'))
        long_message = 'body line of a long commit message\n' * 100
        summary = remote.Service._summary(None, {**info, 'message': long_message}, [], b'payload', 'a' * 64, {}, 'peer')
        self.assertTrue(summary.endswith(long_message), summary)
        summary = remote.Service._summary(None, {**info, 'message': long_message * 2}, [], b'payload', 'a' * 64, {}, 'peer')
        self.assertIn('[truncated in summary; View Details shows the complete report]', summary)

    def test_a_branch_name_cannot_break_or_reorder_its_fact_line(self):
        """NSTextView starts a new line at U+0085, U+2028 and U+2029, and the
        bidirectional controls reorder text, though none is a control
        character: in a fact each becomes '?', as in the wrapper. Other text
        stays."""
        unsafe = '\u0085\u2028\u2029\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069'
        branch = 'facts' + ''.join(c + chr(ord('a') + i) for i, c in enumerate(unsafe)) + '\u00e9'
        info = {'type': 'commit', 'message': 'Subject'}
        summary = remote.Service._summary(None, info, ['-u', 'KEY'], b'payload', 'a' * 64, {'branch': branch}, 'peer')
        facts = summary.partition('\n\nMessage:\n')[0].split('\n')
        self.assertIn('Branch: facts?a?b?c?d?e?f?g?h?i?j?k?l?m?n?o\u00e9', facts)
        self.assertFalse(set(summary) & set(unsafe), summary)

    def test_a_branch_name_holds_no_c1_control(self):
        """U+009B is the 8-bit CSI, and the rest of U+0080-U+009F is no safer in
        a fact or the audit log: each becomes '?', as in the wrapper. U+00A0,
        just past them, stays."""
        c1 = ''.join(map(chr, range(0x80, 0xa0)))
        info = {'type': 'commit', 'message': 'Subject'}
        summary = remote.Service._summary(None, info, ['-u', 'KEY'], b'payload', 'a' * 64,
                                          {'branch': f'c1\u009b{c1}\u00a0\u00e9'}, 'peer')
        facts = summary.partition('\n\nMessage:\n')[0].split('\n')
        self.assertIn('Branch: c1' + '?' * 33 + '\u00a0\u00e9', facts)
        self.assertFalse(set(summary) & set(c1), summary)

    def test_a_failed_slow_or_late_card_query_gives_no_policy(self):
        agent = str(HELPERS / 'fake-gpg-connect-agent.py')
        self.card.write_text(f'{self.CARD_SUB} %01+')
        calls = self.tmp / 'calls' / 'connect-agent-calls'
        with unittest.mock.patch.dict(os.environ, {'FAKE_GPG_CALL_DIR': str(self.tmp / 'calls'),
                                                   'FAKE_CARD_FILE': str(self.card)}):
            self.assertEqual(remote.card_touch_policy(agent, self.CARD_SUB), 'on')
            self.assertEqual(remote.card_touch_policy(agent, self.CARD_SUB, timeout=0), '')
            self.assertEqual(len(calls.read_text().splitlines()), 1, 'no time left asks nothing')
            with unittest.mock.patch.dict(os.environ, {'FAKE_CONNECT_AGENT_EXIT': '2'}):
                self.assertEqual(remote.card_touch_policy(agent, self.CARD_SUB), '')
            with unittest.mock.patch.dict(os.environ, {'FAKE_CONNECT_AGENT_SLEEP': '30'}):
                started = time.monotonic()
                self.assertEqual(remote.card_touch_policy(agent, self.CARD_SUB, timeout=0.5), '')
                self.assertLess(time.monotonic() - started, 5)

    def test_gpg_connect_agent_is_found_through_a_link_to_real_gpg(self):
        linked = self.tmp / 'linked-bin'
        linked.mkdir()
        (linked / 'gpg').symlink_to(Path('..') / 'gnupg-bin' / 'gpg')
        found = remote.gpg_connect_agent(str(linked / 'gpg'))
        self.assertTrue(found and os.path.samefile(found, self.gnupg / 'gpg-connect-agent'), found)
        self.assertEqual(remote.gpg_connect_agent(str(HELPERS / 'fake-gpg.py')), '')

    def test_uif_values_and_the_card_key_decide_the_policy(self):
        agent = str(HELPERS / 'fake-gpg-connect-agent.py')
        cases = {f'{self.CARD_SUB} %00+': 'off', f'{self.CARD_SUB} %01+': 'on', f'{self.CARD_SUB} %02+': 'fixed',
                 f'{self.CARD_SUB} %03+': 'cached', f'{self.CARD_SUB} %04+': 'cached-fixed',
                 f'{self.CARD_SUB.lower()} %03+': 'cached', f'{self.CARD_SUB} %05+': '', f'{self.CARD_SUB} +': '',
                 self.CARD_SUB: '', f'{self.OTHER} %01+': '', '': ''}
        env = {'FAKE_GPG_CALL_DIR': str(self.tmp / 'calls'), 'FAKE_CARD_FILE': str(self.card)}
        with unittest.mock.patch.dict(os.environ, env):
            for card, policy in cases.items():
                with self.subTest(card=card):
                    self.card.write_text(card)
                    self.assertEqual(remote.card_touch_policy(agent, self.CARD_SUB), policy)

    def test_only_off_and_cached_get_a_notice_of_two_short_lines_suggesting_on(self):
        self.assertEqual(sorted(remote.TOUCH_NOTICES), ['cached', 'off'])
        for policy, notice in remote.TOUCH_NOTICES.items():
            with self.subTest(policy=policy):
                lines = notice.split('\n')
                self.assertEqual(len(lines), 2, notice)
                self.assertTrue(lines[0].startswith(f'Touch policy is {policy}: '), notice)
                self.assertTrue(lines[1].endswith('run: ykman openpgp keys set-touch sig on'), notice)
                self.assertTrue(all(len(line) <= 80 for line in lines), 'the facts pane does not wrap')
                self.assertNotRegex(notice, CACHED_HINT)

    def test_touch_notices_match_the_wrapper(self):
        wrapper = (ROOT.parent / 'git-gpg-preview').read_text()
        function = re.search(r'^touch_policy_notice\(\) \{\n.*?^\}', wrapper, re.M | re.S).group()
        for policy in remote.TOUCH_POLICIES:
            with self.subTest(policy=policy):
                result = subprocess.run(['bash', '-c', function + '\ntouch_policy_notice "$1"', 'bash', policy],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0 if policy in remote.TOUCH_NOTICES else 1, result.stderr)
                self.assertEqual(result.stdout, remote.TOUCH_NOTICES.get(policy, ''))

    def test_signing_key_choice_matches_the_wrapper(self):
        wrapper = (ROOT.parent / 'git-gpg-preview').read_text()
        function = re.search(r'^selected_signing_key\(\) \{\n.*?^\}', wrapper, re.M | re.S).group()
        card, primary, sub1, sub2 = 'D2760001240100000006000000010000', 'A' * 40, 'B' * 40, 'C' * 40
        future = '4102444800'

        def cert(fpr, caps, token, *subkeys):
            lines = [f'sec:u:255:22:{fpr[-16:]}:100::::::{caps}:::{token}:::ed25519:::0:', f'fpr:::::::::{fpr}:']
            for sub_fpr, valid, created, sub_token in subkeys:
                lines += [f'ssb:{valid}:255:22:{sub_fpr[-16:]}:{created}::::::s:::{sub_token}:::ed25519::',
                          f'fpr:::::::::{sub_fpr}:']
            return '\n'.join(lines) + '\n'

        listings = {
            'newest subkey on the card': cert(primary, 'cSC', '+', (sub1, 'u', '200', '+'), (sub2, 'u', '300', card)),
            'newest subkey in software': cert(primary, 'cSC', '+', (sub1, 'u', '300', '+'), (sub2, 'u', '200', card)),
            'expired newest subkey': cert(primary, 'cSC', '+', (sub1, 'u', '200', card), (sub2, 'e', '300', '+')),
            'stub without its secret': cert(primary, 'cSC', '+', (sub1, 'u', '200', card), (sub2, 'u', '300', '#')),
            'tie goes to the first listed': cert(primary, 'cSC', '+', (sub1, 'u', '300', card), (sub2, 'u', '300', '+')),
            'subkey from the future': cert(primary, 'cSC', '+', (sub1, 'u', '200', card), (sub2, 'u', future, '+')),
            'primary when no subkey signs': cert(primary, 'scSC', card, (sub1, 'r', '300', '+')),
            'software primary that can sign': cert(primary, 'scSC', '+', (sub1, 'u', '300', card)),
            'stub primary that can sign': cert(primary, 'scSC', '#', (sub1, 'u', '300', card)),
            'card primary with a software subkey': cert(primary, 'scSC', card, (sub1, 'u', '300', '+')),
            'software primary when no subkey signs': cert(primary, 'scSC', '+', (sub1, 'e', '300', card)),
            'one card subkey': cert(primary, 'cSC', '+', (sub1, 'u', '300', card)),
            'two card subkeys': cert(primary, 'cSC', '+', (sub1, 'u', '300', card), (sub2, 'u', '200', card)),
            'one card key in two certificates': cert(primary, 'cSC', '+', (sub1, 'u', '300', card))
                                                + cert('D' * 40, 'cSC', '+', (sub1, 'u', '300', card)),
            'no signing key on a card': cert(primary, 'cSC', card, (sub1, 'u', '300', '+')),
            'a card certificate, then a software one': cert(primary, 'cSC', '+', (sub1, 'u', '300', card))
                                                       + cert('D' * 40, 'cSC', '+', (sub2, 'u', '200', '+')),
            'a software certificate, then a card one': cert(primary, 'cSC', '+', (sub1, 'u', '300', '+'))
                                                       + cert('D' * 40, 'cSC', '+', (sub2, 'u', '200', card)),
            'two card certificates': cert(primary, 'cSC', '+', (sub1, 'u', '300', card))
                                     + cert('D' * 40, 'cSC', '+', (sub2, 'u', '200', card)),
            'two software certificates': cert(primary, 'cSC', '+', (sub1, 'u', '300', '+'))
                                         + cert('D' * 40, 'cSC', '+', (sub2, 'u', '200', '')),
            'a later certificate that cannot sign': cert(primary, 'cSC', '+', (sub1, 'u', '300', card))
                                                    + cert('D' * 40, 'cSC', '+', (sub2, 'e', '200', '+')),
            'a later certificate from the future': cert(primary, 'cSC', '+', (sub1, 'u', '300', card))
                                                   + cert('D' * 40, 'cSC', '+', (sub2, 'u', future, '+')),
            'nothing can sign': cert(primary, 'cSC', '+', (sub1, 'e', '300', card)),
            'first certificate that can sign': cert(primary, 'cSC', '+', (sub1, 'e', '300', '+'))
                                              + cert('D' * 40, 'cSC', '+', (sub2, 'u', '200', card)),
            'empty token is software': cert(primary, 'cSC', '', (sub1, 'u', '300', '')),
            'subkey before any primary': '\n'.join(cert(primary, 'cSC', '+', (sub1, 'u', '300', card)).splitlines()[2:])
                                         + '\n' + cert('D' * 40, 'scSC', '+'),
            'empty listing': '',
        }
        listing = self.tmp / 'listing'
        for name, text in listings.items():
            with self.subTest(name):
                listing.write_text(text)
                result = subprocess.run(['bash', '-c', function + '\nselected_signing_key "$1" "$2"', 'bash',
                                         str(listing), primary], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(remote.selected_signing_key(text, time.time()), result.stdout.strip())
        kinds = {'newest subkey on the card': 'mixed', 'newest subkey in software': 'mixed',
                 'tie goes to the first listed': 'mixed', 'software primary that can sign': 'card',
                 'stub primary that can sign': 'card', 'card primary with a software subkey': 'software',
                 'software primary when no subkey signs': 'software',
                 'expired newest subkey': 'card', 'stub without its secret': 'card',
                 'primary when no subkey signs': 'card', 'one card subkey': 'card', 'two card subkeys': 'mixed',
                 'one card key in two certificates': 'card',
                 'empty token is software': 'software', 'no signing key on a card': 'software',
                 'a card certificate, then a software one': 'mixed', 'a software certificate, then a card one': 'mixed',
                 'two card certificates': 'mixed', 'two software certificates': 'software',
                 'a later certificate that cannot sign': 'card', 'a later certificate from the future': 'mixed'}
        for name, kind in kinds.items():
            with self.subTest(name):
                self.assertEqual(remote.selected_signing_key(listings[name], time.time()).split()[-1], kind)


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
            for k, v in (('user.name', 'Remote Fixture'), ('user.email', 'fixture@preview-tester.dev'), ('commit.gpgsign', 'true'),
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
