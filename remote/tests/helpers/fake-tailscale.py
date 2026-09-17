#!/usr/bin/env python3
"""Fake tailscale CLI: a netmap with one Mac peer and a whois answer driven by
FAKE_WHOIS_NODE / FAKE_WHOIS_USER, so authorization paths are testable."""
import json, os, sys

args = sys.argv[1:]
if args[:2] == ['status', '--json']:
    print(json.dumps({
        'BackendState': 'Running',
        'Self': {'ID': 1, 'HostName': 'operator-mac', 'DNSName': 'operator-mac.example.ts.net.',
                 'UserID': 100, 'Online': True, 'TailscaleIPs': ['100.64.0.1', 'fd7a:115c:a1e0::1']},
        'User': {'100': {'LoginName': 'operator@example.invalid', 'DisplayName': 'Operator'},
                 '200': {'LoginName': 'minidev-test.example.ts.net', 'DisplayName': 'minidev-test'},
                 '300': {'LoginName': 'stranger@example.invalid', 'DisplayName': 'Stranger'}},
        'Peer': {'p1': {'ID': 2, 'DNSName': 'operator-mac.example.ts.net.', 'Online': os.environ.get('FAKE_PEER_ONLINE', '1') == '1',
                        'TailscaleIPs': ['100.64.0.1'], 'UserID': 100}},
    }))
    sys.exit(0)
if args[:2] == ['whois', '--json']:
    node = os.environ.get('FAKE_WHOIS_NODE', 'minidev-test.example.ts.net')
    user = os.environ.get('FAKE_WHOIS_USER', '200')
    logins = {'100': 'operator@example.invalid', '200': 'minidev-test.example.ts.net', '300': 'stranger@example.invalid'}
    print(json.dumps({'Node': {'Name': node + '.', 'User': int(user)},
                      'UserProfile': {'LoginName': logins.get(user, '')}}))
    sys.exit(0)
sys.stderr.write('fake-tailscale: unsupported\n')
sys.exit(1)
