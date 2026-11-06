#!/usr/bin/env python3
"""Fake gpg-connect-agent for remote tests: answers SCD GETATTR the way
scdaemon does for the card in the reader. FAKE_CARD_FILE holds that card's
signature-key fingerprint and its raw UIF-1 value as scdaemon escapes it
("%01+" is touch policy on); no file means no card. Until SERIALNO selects
the OpenPGP application, another one (PIV, say) answers GETATTR.
FAKE_CONNECT_AGENT_SLEEP delays the answer (a wedged agent) and
FAKE_CONNECT_AGENT_EXIT is the exit status after it. FAKE_CARD_APDU_SW is the
status word the APDU reply ends with (90 00: done)."""
import os, re, sys, time
from pathlib import Path

# SCD APDU 00CA00D600 (GET DATA for DO D6) reads the card's current policy;
# SCD GETATTR UIF-1 answers from FAKE_SCD_CACHE, when set, the way scdaemon
# answers from the copy it read first, and SCD KILLSCD empties that cache.
call_dir = Path(os.environ['FAKE_GPG_CALL_DIR'])
call_dir.mkdir(parents=True, exist_ok=True)
with (call_dir / 'connect-agent-calls').open('a') as f:
    f.write(' '.join(sys.argv[1:]) + '\n')
try:
    card, uif = (Path(os.environ['FAKE_CARD_FILE']).read_text().split() + ['', ''])[:2]
except (KeyError, OSError, ValueError):
    card = uif = ''
time.sleep(float(os.environ.get('FAKE_CONNECT_AGENT_SLEEP', '0')))
commands = sys.argv[1:]
while commands and commands[0].startswith('--'):
    commands = commands[2:] if commands[0] == '--homedir' else commands[1:]
cache = Path(os.environ['FAKE_SCD_CACHE']) if os.environ.get('FAKE_SCD_CACHE') else None
openpgp = False
for command in commands:
    if command == '/bye':
        break
    if not card:
        print('ERR 100696144 No such device <SCD>')
    elif command == 'SCD SERIALNO openpgp':
        openpgp = True
        print('S SERIALNO D2760001240100000006000000010000 0\nOK')
    elif command.startswith(('SCD GETATTR ', 'SCD APDU ')) and not openpgp:
        print('ERR 100663423 Not supported <SCD>')
    elif command == 'SCD GETATTR KEY-FPR':
        print(f'S KEY-FPR 1 {card}\nS KEY-FPR 2 DDDD000000000000000000000000000000000002\nOK')
    elif command == 'SCD GETATTR UIF-1':
        cached = uif
        if cache:
            if not cache.exists() or not cache.read_text():
                cache.write_text(uif)
            cached = cache.read_text()
        print(f'S UIF-1 {cached}\nOK' if cached else 'ERR 100663354 No such object <SCD>')
    elif command == 'SCD APDU 00CA00D600':
        # As gpg-connect-agent --hex prints it: the policy byte, 0x20, 90 00.
        match = re.fullmatch(r'%(0[0-9A-F])\+', uif)
        sw = os.environ.get('FAKE_CARD_APDU_SW', '90 00')
        print(f'D[0000]  {match.group(1)} 20 {sw}                                         . ..\nOK' if match
              else 'ERR 100663354 No such object <SCD>')
    elif command == 'SCD KILLSCD':
        # scdaemon stops: every operation queued at the card ends.
        if os.environ.get('FAKE_CARD_QUEUE'):
            Path(os.environ['FAKE_CARD_QUEUE']).write_text('')
        if cache:
            cache.write_text('')
        print('OK')
    else:
        print('ERR 69 Unknown IPC command <User defined source 1>')
sys.exit(int(os.environ.get('FAKE_CONNECT_AGENT_EXIT', '0')))
