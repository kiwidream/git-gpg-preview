#!/usr/bin/env python3
"""Fake gpg for remote tests: records calls, answers identity queries, and
blocks signing on a "touch" file so review and signing overlap like a real
hardware key."""
import hashlib, os, sys, time
from pathlib import Path

call_dir = Path(os.environ['FAKE_GPG_CALL_DIR'])
call_dir.mkdir(parents=True, exist_ok=True)
args = sys.argv[1:]
payload = b'' if any(a in args for a in ('--list-secret-keys', '--list-keys', '--export')) else sys.stdin.buffer.read()
ident = f'{os.getpid()}.{time.time_ns()}'
(call_dir / f'{ident}.stdin').write_bytes(payload)
(call_dir / f'{ident}.args').write_bytes(b'\0'.join(a.encode() for a in args) + b'\0')
with (call_dir / 'calls').open('a') as f:
    f.write(ident + '\n')

if '--list-secret-keys' in args:
    print('sec:u:255:22:3DB3F5612E33B6BC:1789650000:::u:::scESC:::+:::ed25519:::0:')
    print('fpr:::::::::041CE6A7BED57FE579D43B6C3DB3F5612E33B6BC:')
    sys.exit(0)
if '--list-keys' in args:
    print('pub:u:255:22:3DB3F5612E33B6BC:1789650000:::u:::scESC:::+:::ed25519:::0:')
    print('uid:u::::1789650000::HASH::Fixture Operator <operator@example.invalid>::::::::::0:')
    sys.exit(0)
if '--export' in args:
    print('-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEfixture\n-----END PGP PUBLIC KEY BLOCK-----')
    sys.exit(0)

signing = any(a in ('--sign', '--detach-sign') or (a.startswith('-') and not a.startswith('--') and ('s' in a[1:] or 'b' in a[1:])) for a in args)
if signing and '--verify' not in args and os.environ.get('FAKE_TOUCH_FILE'):
    touch = Path(os.environ['FAKE_TOUCH_FILE'] + '.' + hashlib.sha256(payload).hexdigest())
    deadline = time.monotonic() + 10
    while not touch.exists():
        if time.monotonic() > deadline:
            sys.stderr.write('fake-gpg: timed out waiting for touch\n')
            sys.exit(2)
        time.sleep(0.05)
sys.stdout.write(os.environ.get('FAKE_GPG_STDOUT', ''))
sys.stdout.flush()
sys.stderr.write(os.environ.get('FAKE_GPG_STDERR', ''))
sys.exit(int(os.environ.get('FAKE_GPG_EXIT', '0')))
