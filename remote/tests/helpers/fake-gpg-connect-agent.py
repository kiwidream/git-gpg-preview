#!/usr/bin/env python3
"""Fake gpg-connect-agent for remote tests: answers SCD GETATTR the way
scdaemon does for the card in the reader. FAKE_CARD_FILE holds that card's
signature-key fingerprint and its raw UIF-1 value as scdaemon escapes it
("%01+" is touch policy on); no file means no card. Until SERIALNO selects
the OpenPGP application, another one (PIV, say) answers GETATTR.
FAKE_CONNECT_AGENT_SLEEP delays the answer (a wedged agent) and
FAKE_CONNECT_AGENT_EXIT is the exit status after it."""
import os, sys, time
from pathlib import Path

call_dir = Path(os.environ['FAKE_GPG_CALL_DIR'])
call_dir.mkdir(parents=True, exist_ok=True)
with (call_dir / 'connect-agent-calls').open('a') as f:
    f.write(' '.join(sys.argv[1:]) + '\n')
try:
    card, uif = (Path(os.environ['FAKE_CARD_FILE']).read_text().split() + ['', ''])[:2]
except (KeyError, OSError, ValueError):
    card = uif = ''
time.sleep(float(os.environ.get('FAKE_CONNECT_AGENT_SLEEP', '0')))
openpgp = False
for command in sys.argv[1:]:
    if command == '/bye':
        break
    if not card:
        print('ERR 100696144 No such device <SCD>')
    elif command == 'SCD SERIALNO openpgp':
        openpgp = True
        print('S SERIALNO D2760001240100000006000000010000 0\nOK')
    elif command.startswith('SCD GETATTR ') and not openpgp:
        print('ERR 100663423 Not supported <SCD>')
    elif command == 'SCD GETATTR KEY-FPR':
        print(f'S KEY-FPR 1 {card}\nS KEY-FPR 2 DDDD000000000000000000000000000000000002\nOK')
    elif command == 'SCD GETATTR UIF-1':
        print(f'S UIF-1 {uif}\nOK' if uif else 'ERR 100663354 No such object <SCD>')
    else:
        print('ERR 69 Unknown IPC command <User defined source 1>')
sys.exit(int(os.environ.get('FAKE_CONNECT_AGENT_EXIT', '0')))
