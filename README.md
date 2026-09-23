# git-gpg-preview

`git-gpg-preview` is a fail-closed, Git-specific OpenPGP wrapper for macOS. Git invokes it through `gpg.openpgp.program`. For a signing request, the wrapper captures the exact stdin bytes once, shows a concise foreground preview of what Git is asking GPG to sign, and engages real GnuPG concurrently so your hardware key's confirmation prompt is active while the preview is on screen.

Because GnuPG is engaged during the preview, your key blocks on its normal confirmation (a touch, plus the PIN only when gpg-agent has not cached it). Touching the key completes the signature and dismisses the preview; **Cancel** kills GnuPG before it produces a signature, so Git aborts. The physical hardware confirmation — not a software button — is the authorization gate.

Verification and other non-signing GPG operations pass directly to the configured absolute GPG executable without a dialog.

Commit signing requests that look like they came from a test repository are rejected before the dialog and before GPG starts. Test suites routinely create throwaway repositories that inherit a global `commit.gpgSign=true`, and each one would otherwise put a preview on screen and wait for a touch. Two rules, both read from the exact payload:

- **Fixture subject:** the first non-empty subject line is exactly one of `base`, `fixture`, `init`, `initial`, `main`, `production`, `seed`, `work`, `more`, `msg`, `message`, or `x` (case-insensitive, ignoring surrounding horizontal whitespace). Longer subjects such as `production release` are not rejected.
- **Fixture identity:** the author or committer email is at one of this policy's blocked domains, or a subdomain of one: `example.com`, `example.net`, `example.org`, `example`, `invalid`, `localhost`, `test`, or `local`. These cover documentation, testing, and local-use names (RFC 2606, RFC 6761, RFC 6762). This is a heuristic, not proof that a commit came from a test. In particular, `.local` is reserved for Multicast DNS and can occur in legitimate identities; this policy deliberately blocks it too. Only the `author` and `committer` header lines count, so a `Co-authored-by:` trailer in the message never triggers it.

The error names the rule that matched. For a test or fixture repository, disable signing only for that test process or repository. For a legitimate commit, use a descriptive subject and an identity outside the blocked domains. When signing through the **local wrapper with local GnuPG**, re-running once with `GIT_GPG_PREVIEW_ALLOW_FIXTURE=1` (or its original name, `GIT_GPG_PREVIEW_ALLOW_SUBJECT=1`) bypasses the fixture check and records a `policy-override` entry. That audit entry records the policy bypass, not a successful signature; cancellation or a GPG failure can still prevent signing.

**Remote signing has no fixture override.** Both the client and the Mac service enforce the policy regardless of these environment variables or requester-supplied flags. A local wrapper override cannot bypass a remote client or service behind it. For legitimate remote commits, change the subject or identity that triggered the rule. The authoritative lists are the `FIXTURE_SUBJECTS` and `FIXTURE_EMAIL_DOMAINS` lines in the wrapper script; the tests, and the remote service's own copy, are checked against them.

## Requirements

- macOS, including `/usr/bin/osascript`, AppKit, `shlock`, and standard command-line tools
- Git
- GnuPG (`gpg`)

No Python, package runtime, daemon, network service, or third-party GUI framework is used.

## Install

Inspect the scripts, then run:

```sh
cd ~/git-gpg-preview
./tests/run.sh
./install.sh --real-gpg /absolute/path/to/gpg
```

The installer:

- installs the executable as `~/.local/bin/git-gpg-preview`;
- installs the static JXA/AppKit dialog helper under `~/.local/libexec/git-gpg-preview/`;
- installs the standalone touch prompt (see [Reusable touch prompt](#reusable-touch-prompt)) beside it;
- writes a mode-0600 configuration containing the absolute real-GPG path;
- records the exact previous global `gpg.openpgp.program` state once; and
- sets global `gpg.openpgp.program` to the wrapper.

It does not alter `commit.gpgSign`, `tag.gpgSign`, `user.signingkey`, GPG agent configuration, smart-card configuration, PIN policy, or hardware touch/confirmation policy. Re-running `install.sh` updates the installed files without replacing the original recovery state.

To enable the optional metadata-only audit log during installation:

```sh
./install.sh --real-gpg /absolute/path/to/gpg \
  --audit-log "$HOME/Library/Logs/git-gpg-preview/audit.log"
```

The audit file and its directory are restricted to the current user. Each line contains only a UTC timestamp, sanitized repository path, request type, payload SHA-256, calling PID/process, and decision. It never records payloads, messages, diffs, filenames, PINs, passphrases, or signature bytes.

## Review behavior

For signing operations, stdin is copied exactly once into a unique mode-0600 file within a mode-0700 temporary request directory. Each request retains its own payload. Dialogs from simultaneous Git processes are serialized using macOS `shlock`; dead-process locks are recovered atomically. Because each request holds the lock across its preview and signature, one hardware confirmation completes before the next request's preview appears.

The main dialog is deliberately small and concise, showing:

- request type: commit, annotated tag, push certificate, or unknown;
- branch;
- GPG signing-key selector, when present;
- exact byte count and SHA-256;
- the commit/tag message or payload body.

**View Details** opens a selectable, scrollable report containing everything else: the full repository/worktree path, the tree and parent/target object hashes, the per-parent changed-file summary, the verbatim captured payload, a byte-preserving hex view, and the complete safely generated diff for commits.

The preview appears and reports readiness before GPG is engaged, so when a PIN is required the pinentry prompt launches last and stays frontmost and focused rather than opening behind the preview. The preview does not steal focus back, so you can type the PIN and then touch the key.

There is no **Sign** button: the signature is produced by the hardware confirmation that is already pending while the preview is shown. Touching the key completes signing with the captured bytes and original arguments and dismisses the window. **Cancel** kills GPG before it produces a signature and returns nonzero, so Git aborts.

The dialog deliberately labels two different things:

1. **Exact signed payload:** the bytes supplied to GPG. This includes the proposed commit/tag object headers and message.
2. **Derived review information:** repository labels, branch, diffstat, and textual diff reconstructed from Git objects. A commit's signed tree hash commits to file content, but the textual diff is not literally part of GPG's input.

Diffs are generated with `git --no-pager`, `--no-ext-diff`, and `--no-textconv`; repository content is never interpolated into AppleScript, JXA, or shell source. Dialog data travels only through mode-0600 files and argument values. Summary control characters are sanitized.

## Reusable touch prompt

A hardware key that is waiting for a touch gives no indication beyond its own LED. That is fine when you just typed `git commit`, and useless when the request came from somewhere you were not looking — an agent on another machine signing through a forwarded `ssh-agent`, for example.

`touch-prompt.jxa` is the same on-screen idea as the signing preview, factored out so anything holding a pending hardware confirmation can use it:

```sh
/usr/bin/osascript -l JavaScript \
  "$(sed -n 's/^touch_helper=//p' ~/.config/git-gpg-preview/config)" \
  /path/to/context.txt /path/to/decision /path/to/ready &
```

The contract matches the signing preview's:

- `context.txt` — mode-0600 text shown verbatim in a selectable, scrollable field. Sanitize it; the helper renders whatever it is given.
- `decision` — the helper writes `deny` if the user presses **Deny**. Nothing is written when the window is terminated instead.
- `ready` — created as the window is about to appear. Wait for it before engaging the hardware, so the prompt is up before the key starts blinking.

There is no approve button, for the same reason the signing preview has none: the touch itself is the approval. The caller terminates the helper once the signature (or a failure) comes back, which dismisses the window.

Installation records the helper's absolute path in the configuration as `touch_helper=`, so other tools can find it without hardcoding a path or depending on this repository's layout.

Because the touch is the authorization gate, a caller that cannot present the prompt should still forward the request rather than fail: a missing window makes the touch invisible, not unauthorized.

## Remote signing for hosts without a key

A Linux dev VM that runs agents cannot hold your hardware key, and forwarding
an agent socket to it loses the preview. `remote/` turns this machine into a
signing service instead, and gives the VM a client that Git calls as its
`gpg.openpgp.program`:

```
VM: git commit ─▶ git-gpg-preview-client ─▶ HTTP over Tailscale ─▶ serve (this Mac)
                  captures payload, derives                       whois-checks the peer,
                  diff from local objects,                        shows the same preview,
                  runs --verify locally                           waits for your touch,
                                                                  returns the signature
```

Install on the Mac after the wrapper (idempotent; safe to re-run):

```bash
remote/serve-install.sh install            # launchd agent on this machine's Tailscale address
remote/serve-install.sh status
```

`serve` accepts requests only from tailnet nodes the local `tailscale whois`
attributes to your own login, to names listed in `allow_nodes`, or to names
starting with an `allow_node_prefixes` entry (default `minidev`). Every request
still ends in your touch: the review window shows the exact payload bytes and
hex view built on this machine from what arrived, and labels the diff as
derived on the requesting host. Fixture-style subjects and identities are
refused here as well, whatever the client sent. Cancel, a missed touch (`sign_timeout_seconds`,
default 120), an offline Mac and an unknown peer all fail the remote commit;
nothing unsigned is ever written.

On the host, point Git at the client and install the public key once:

```bash
python3 remote/git_gpg_preview_remote.py identity --server your-mac.tailnet.ts.net   # fingerprint + public key
git config --global gpg.openpgp.program /path/to/remote/git-gpg-preview-client
git config --global user.signingkey <fingerprint>
git config --global commit.gpgsign true
printf 'server=your-mac.tailnet.ts.net\n' > ~/.config/git-gpg-preview/client
```

The client resolves the Mac through the local Tailscale daemon's authenticated
netmap, never ordinary DNS, and refuses to sign if the Mac is offline. Only the
argument shapes Git uses to sign are forwarded (`--status-fd`, `-bsau <key>`
and friends); anything else is refused by both sides. `--verify` and key
listing run against the host's own `gpg`, so `git log --show-signature` works
once the public key is imported.

The service and the local wrapper share `dialog.lock` using the same
pid-file protocol as `shlock`, so a local `git commit` and a remote request
are never both waiting on one touch; the touch always answers the request whose
window is on screen.

The service signs with exactly one key and stores its fingerprint as
`signing_key`. `serve-install.sh install` takes it from `--signing-key`, else
the value already stored, else Git's global `user.signingkey` (the key your own
commits carry), else the GnuPG home's only secret key. With several secret keys
and nothing naming one, it installs nothing and lists the candidates: the order
gpg lists keys in says nothing about which one you sign with. A trailing `!` is
dropped, and `remote/git_gpg_preview_remote.py resolve-key` prints the choice
without changing anything.

Because other machines can reach the service, `install` also turns its audit
log on: `audit_log=~/Library/Logs/git-gpg-preview/audit.log` is written to the
serve config unless that file already has an `audit_log` line. Lines from
remote requests carry `peer=<node> (<login>)` and `caller=remote`. An empty
`audit_log=` defers to the wrapper's setting, which is off unless you set it.

Config keys: `~/.config/git-gpg-preview/serve` takes `port`, `allow_nodes`,
`allow_node_prefixes`, `signing_key`, `audit_log`, `sign_timeout_seconds`,
`bind` and `dialog_runner` (tests); `real_gpg`, `ui_helper` and `lock_root`
come from the wrapper's `config`, as does `audit_log` when the serve config
leaves it empty. `~/.config/git-gpg-preview/client` takes `server`, `port`,
`real_gpg` and `timeout_seconds`.

Tests: `python3 -m unittest discover -s remote/tests` runs the service behind
fake `tailscale`, `gpg` and dialog helpers on any platform, plus one real
GnuPG round trip with a disposable key when `gpg` is installed.

## Fail-closed cases

A signing request is rejected before GPG runs when the real-GPG path or UI helper is missing, a recognized commit/tag payload cannot be safely parsed against available Git objects, or a secure temporary area cannot be created. Once the preview and GPG are engaged, a **Cancel** decision, a preview process that exits without approval, or any outcome other than a completed signature kills GPG before it produces a signature. Unknown signing formats still receive a clearly labeled exact-payload review.

Non-signing operations require a valid real-GPG configuration too; when configured correctly, they use `exec` for transparent argument, descriptor, signal, stdout/stderr, and exit behavior. For signing, stdout and stderr remain connected directly to GPG, and the wrapper propagates GPG's exact exit code and forwards termination signals. The wrapper never writes UI or diagnostic text to stdout because Git expects the detached signature there.

## Threat model and limitations

This tool protects against accidentally producing an unexpected Git OpenPGP signature: the payload is reviewed while your hardware key waits, and the deliberate physical confirmation is what completes the signature. It makes concurrent agent-driven requests attributable at review time and serializes them behind a single hardware confirmation. It does not replace GnuPG signature security, hardware-key confirmation, repository access controls, or careful review.

Important limitations:

- The preview is shown while GnuPG is already engaged, so the hardware confirmation is the authorization gate. This is a deliberate trade for the touch-to-sign workflow: unlike a design that contacts GPG only after a software approval, GnuPG and gpg-agent are invoked for every signing request. A key whose policy requires no touch (for example, a cached PIN and touch disabled) can therefore complete signing before the preview is meaningfully reviewed; keep the hardware touch requirement enabled so signing always blocks on a deliberate action.
- A process already running as your macOS account can modify user-owned wrapper/configuration files, tamper with Git objects between review and later use, simulate UI, or invoke GPG directly.
- The derived diff reflects objects available when the preview is built. The signed tree hash—not the rendered diff—is authoritative.
- Binary and very large changes can make a full textual report unwieldy; the exact payload's hex view remains byte-preserving.
- Git object formats that do not resemble standard commit, annotated-tag, or push-certificate payloads appear as `unknown`.
- The wrapper is intentionally for Git's GPG interface, not a general-purpose replacement for every GPG client.
- Remote signing trusts the local Tailscale daemon's identity answers and the requesting host's rendering of the diff. The payload bytes shown and signed are what arrived; a compromised host can ask you to sign a commit it describes misleadingly, which is why the exact payload and hex view are rendered here and the diff is labelled as derived remotely.
- The absolute real-GPG path must remain executable. If a package-manager upgrade removes it, reinstall with the new path.

## Troubleshooting and recovery

If Git reports `gpg failed to sign the data`, check the wrapper's stderr, then verify:

```sh
git config --global --get gpg.openpgp.program
cat ~/.config/git-gpg-preview/config
ls -l ~/.local/bin/git-gpg-preview
```

If no dialog appears, ensure the current macOS session can present AppKit UI and that `dialog.jxa` is installed. Dialog/UI failures intentionally abort signing. A stale lock owned by a dead process is recovered automatically. To inspect the lock without deleting an active request:

```sh
cat ~/Library/Caches/git-gpg-preview/dialog.lock
```

Do not work around a blocked workflow with `--no-gpg-sign`. Recover the original exact Git setting instead:

```sh
cd ~/git-gpg-preview
./uninstall.sh
```

The uninstaller restores all previously recorded `gpg.openpgp.program` values, or unsets the key if it was originally absent. It removes installed wrapper/configuration files but deliberately leaves any audit log. If the repository is unavailable, run its `uninstall.sh` from a backup copy; the recovery state lives in `~/.local/state/git-gpg-preview/`.

## Tests

`./tests/run.sh` uses a fake GPG and a noninteractive fake dialog in an isolated home directory. It covers normal and initial commits, merge commits, annotated tags, push certificates, unknown/binary payloads, hostile Unicode content, fixture-style subject and identity rejection, near-misses, and the override, cancellation, verification pass-through, GPG failure status, stdout purity, exact stdin/argument forwarding, concurrent queueing, stale lock recovery, safe diff options, and audit logging.

## License

MIT. See [LICENSE](LICENSE).
