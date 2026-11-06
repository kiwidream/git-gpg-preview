# git-gpg-preview

`git-gpg-preview` is a fail-closed, Git-specific OpenPGP wrapper for macOS. Git invokes it through `gpg.openpgp.program`. For a signing request, the wrapper captures the exact stdin bytes once, shows a concise foreground preview of what Git is asking GPG to sign, and engages real GnuPG concurrently so your hardware key's confirmation prompt is active while the preview is on screen.

Because GnuPG is engaged during the preview, your key blocks on its normal confirmation (a touch, plus the PIN only when gpg-agent has not cached it). Touching the key completes the signature and dismisses the preview; **Cancel** kills GnuPG before it produces a signature, so Git aborts. The physical hardware confirmation — not a software button — is the authorization gate. The exception is any key whose touch policy is not **on** or **fixed**, the two that make every signature wait for its own touch. With **off**, **cached**, **cached-fixed** or a policy that cannot be read, the key may sign without a touch of its own, so the preview has a **Sign** button, GnuPG starts only after you click it, and that click is the gate.

Verification and other non-signing GPG operations pass directly to the configured absolute GPG executable without a dialog.

Commit signing requests that look like they came from a test repository are rejected before the dialog and before GPG starts. Test suites routinely create throwaway repositories that inherit a global `commit.gpgSign=true`, and each one would otherwise put a preview on screen and wait for a touch. Two rules, both read from the exact payload:

- **Fixture subject:** the first non-empty subject line is exactly one of `base`, `fixture`, `init`, `initial`, `initial commit`, `main`, `production`, `seed`, `work`, `more`, `msg`, `message`, `x`, `pr head`, or `mr head` (case-insensitive, ignoring surrounding horizontal whitespace). Longer subjects such as `production release` or `Initial commit: preview tool` are not rejected.
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

The bundled `scripts/git-gpg-preview-setup` launcher also provides `install`,
`upgrade`, `status`, `uninstall`, `test`, and `serve-*` commands from a checkout
or through a symlink on `PATH`. Its `upgrade` command refreshes the installed
wrapper and helpers while preserving configuration and Git settings. The
launcher was contributed by SwapLabs and is maintained here alongside the
tool; downstream bundles should vendor it with the other upstream files.

The installer:

- installs the executable as `~/.local/bin/git-gpg-preview`;
- installs the static JXA/AppKit dialog helper under `~/.local/libexec/git-gpg-preview/`;
- installs the standalone touch prompt (see [Reusable touch prompt](#reusable-touch-prompt)) beside it;
- writes a mode-0600 configuration containing the absolute real-GPG path;
- records the exact previous global `gpg.openpgp.program` state once; and
- sets global `gpg.openpgp.program` to the wrapper.

It does not alter `commit.gpgSign`, `tag.gpgSign`, `user.signingkey`, GPG agent configuration, smart-card configuration, PIN policy, or hardware touch/confirmation policy; the preview only suggests a touch policy (see [Touch policy](#touch-policy)). Re-running `install.sh` updates the installed files without replacing the original recovery state.

To enable the optional metadata-only audit log during installation:

```sh
./install.sh --real-gpg /absolute/path/to/gpg \
  --audit-log "$HOME/Library/Logs/git-gpg-preview/audit.log"
```

The audit file and its directory are restricted to the current user. Each line contains only a UTC timestamp, sanitized repository path, request type, payload SHA-256, calling PID/process, and decision. It never records payloads, messages, diffs, filenames, PINs, passphrases, or signature bytes.

## Review behavior

For signing operations, stdin is copied exactly once into a unique mode-0600 file within a mode-0700 temporary request directory. Each request retains its own payload. Dialogs from simultaneous Git processes are serialized using macOS `shlock`; dead-process locks are recovered atomically. Because each request holds the lock across its preview and signature, one hardware confirmation completes before the next request's preview appears.

The main dialog leads with the commit/tag message or payload body. It has the largest pane, which wraps long lines and scrolls, and holds up to 4,000 bytes of it. Below it, in a pane of its own that a long message cannot scroll out of sight, are:

- request type: commit, annotated tag, push certificate, or unknown;
- branch;
- GPG signing-key selector, when present;
- exact byte count and SHA-256.

Every one of these is a single sanitized line, and the dialog splits the panes at the first `Message:` line after them, so nothing in a message can pass for one of them. A fact holds no control character, nor one at which the facts pane would start a new line or reorder the text though it is no control: U+0085, U+2028 and U+2029, and the bidirectional controls U+061C, U+200E, U+200F, U+202A–U+202E and U+2066–U+2069 each become `?`, on both paths. The dialog makes the same replacement in the facts it shows, for all C1 controls U+0080–U+009F as well, after it has decoded the summary: one that is not valid UTF-8 is read as Latin-1, where a raw 0x85 byte is NEL. So a branch name cannot draw a fact line of its own or push the SHA-256 out of the pane.

**View Details** opens a selectable, scrollable report containing everything else: the full repository/worktree path, the tree and parent/target object hashes, the per-parent changed-file summary, the verbatim captured payload, a byte-preserving hex view, and the complete safely generated diff for commits.

The preview appears and reports readiness before GPG is engaged, so when a PIN is required the PIN prompt opens last and stays frontmost and focused rather than opening behind the preview. The preview does not steal focus back, so you can type the PIN and then touch the key.

There is no **Sign** button when the key's touch policy is **on** or **fixed**, the only ones that keep the touch as the gate; off, cached, cached-fixed and a policy that cannot be read all get one (see [Touch policy](#touch-policy)). Without it, the signature is produced by the hardware confirmation that is already pending while the preview is shown. Touching the key completes signing with the captured bytes and Git's arguments (plus the PIN options below, when the PIN window is used) and dismisses the window. **Cancel** kills GPG before it produces a signature and returns nonzero, so Git aborts.

### Touch policy

Because the touch is the gate, the wrapper checks the key's touch policy before the preview opens. When the key GPG will sign with is the signature key of the card in the reader, it reads that slot's policy through scdaemon, which already holds the card, with the `gpg-connect-agent` installed beside real GPG. It never runs `ykman`, which kills scdaemon when scdaemon holds the card. If the policy is **off**, a YubiKey's default, the key signs without a touch, so the preview could not hold the signature for your review. If it is **cached**, a touch also covers every signature in the next 15 seconds, so a request queued within 15 seconds of a touch signs without its own touch. In both cases two lines above the request's facts, and above the report in **View Details**, name the policy and the change:

```sh
ykman openpgp keys set-touch sig on
```

`ykman` asks for the Admin PIN. The wrapper never changes the policy itself.

With touch **off** or **cached**, the preview therefore adds a **Sign** button, and GPG starts only after you click it; the PIN window, if any, follows. Cached needs it too because no record here could tell whether a touch in the last 15 seconds, made by this tool or by anything else that uses the key, would let the signature through on its own. Sign is the last button, so Return does not press it. **Cancel**, **Mark as Spam**, a window that closes without an answer, or no click in time signs nothing, and Git reports `not signed: touch policy is off and Sign was not clicked` (or cached, cached-fixed or unknown). A click that lands in time counts. Only the exact answers `sign`, `cancel` and `spam` count, on both paths: anything else the preview's decision file holds, such as ` cancel` or `cancel` with a trailing newline or NUL, is no answer. Before GPG starts that is refused as `sign-not-clicked`; once GPG runs, as `invalid-ui-decision`; both exit 70. After Sign the preview closes. A window that says `Finishing the signature (touch the key if it blinks)`, with **Cancel**, stays up while GPG runs, so a key that still wants a touch or the PIN has something on screen, as the preview does when the touch is the gate; a key with touch off never blinks, so the window does not ask for a touch outright. It closes when GPG ends, and its **Cancel** is a Cancel: GPG is stopped and nothing is signed. Escape presses it; Return does nothing there, so a stray Return cannot stop a signature just approved. The PIN window (or pinentry) and a touch get a deadline of their own. Past it GPG is stopped, nothing is signed, and Git reports `not signed: no touch or PIN before the deadline`. scdaemon is stopped too, as `gpgconf --kill scdaemon` does, before the next request may start: gpg-agent and scdaemon would otherwise keep the stopped signature, and any PIN request for it, pending at the card, and the next touch would complete that instead, or find the card busy. Stopping scdaemon does not end that operation at once, though. Read from GnuPG 2.4's source and not measured, scdaemon exits only after the card has answered the command in progress, so a key already blinking for a touch can keep blinking until it is touched or its own touch timeout passes (about 15 seconds on a YubiKey). A touch in that time completes the stale signature inside scdaemon, where nobody reads it, since GPG has been stopped, and a request in that window may fail once or need a second touch. gpg-agent starts scdaemon again for the next signature, which may ask for the PIN again. The same happens on both paths whenever GPG is stopped before it finishes: for want of a touch, on **Cancel** or **Mark as Spam**, or when the preview, the window after Sign or the PIN window closes without an answer. Only then: a GPG that had already finished leaves nothing at the card, and neither does one signing from a certificate with no signing key on a card, so neither stops scdaemon, which would drop the PIN it holds and disturb its other users. A certificate with a signing key on a card gets the cancel even when the wrapper picks its software key, since GnuPG 2.3 and later may sign on the card instead, and so does a key that could not be looked up. It goes to the GnuPG home the request names, by GPG's own rule: the last `--homedir` wins, under any name GPG takes for it (`--home`, `--hom`). An `--options` file cannot change the home, since GPG reads `homedir` only from its command line, so such a file does not affect where the cancel goes. Locally, a signal that ends the wrapper (Ctrl-C, or the caller ending it) does the same: GPG gets TERM and, if it is still running a second later, KILL, so a GPG waiting on gpg-agent cannot hold the wrapper; scdaemon is then stopped, waiting at most about 3 seconds, and the wrapper ends with the signal's status. The wrapper signals only its own children that have not yet been reaped: the number of one that has may already belong to another process. It clears each number as it reaps the child, and asks `ps` only to rule a number out; where `ps` cannot answer, as in some sandboxes, a number that `kill -0` reaches counts as its child, so GPG is still stopped.

The times differ between the wrapper and the remote signing service because only the service has a client waiting with its own timeout:

- Locally, Git waits for the wrapper as long as it takes, so the click gets two minutes and what follows it 90 seconds, enough to read the request, type a PIN, find the key and touch it.
- The remote service must answer within `sign_timeout_seconds` (default 120; `serve` refuses to start unless it is a positive, finite number) of the request's arrival, inside the client's longer `timeout_seconds` (default 180). Waiting behind other requests and reading the policy count against it. GPG keeps a reserve for the PIN and a touch: a minute, or a third of a longer timeout, but never more than half of it. The click must come before only that reserve is left. A request that has waited so long that less than the reserve remains, or less than the reserve plus 10 seconds when its preview would ask for Sign, is refused as busy, before any preview opens or GPG starts: `the signing Mac was busy for most of …`. With the defaults that is a 60-second reserve: a request for a key whose touch is the gate needs 60 seconds left to be shown, and one that asks for Sign needs 70.

Both paths audit the same decisions: `sign-not-clicked`, `gpg-timeout` after Sign, `cancel`, `spam-mark`, and on the remote service also `busy`. The preview gets the notice text directly, so it asks for Sign even when the notice could not be written into its files. A policy the wrapper cannot read is treated the same way, since the key behind it may sign without a touch: a software key, another card or none, a card without the setting or with a value it does not know, a card query that fails or takes more than 10 seconds, or a request that names its own GnuPG files or more than one key. It gets no notice above the facts or on stderr; its Sign window says `Touch policy unknown: Sign to continue`, and a refusal names the policy as unknown. **Cached-fixed** asks for Sign too, saying `Touch policy cached-fixed: one touch signs for 15 seconds; Sign is required.` A rebase that signs many commits with a cached key needs a click for each. Only **on** and **fixed**, which make every signature wait for its own touch, keep the touch as the gate and show no Sign button.

Beyond the Sign button, the notice is advisory: its suggestion does not change the key. Each line fits the facts pane, which does not wrap, and both go to stderr as one line, which Git shows only when signing fails. If the wrapper cannot add them to the preview, stderr says so and signing goes ahead without them. **On** gets no notice, because every signature already waits for its own touch. **Fixed** cannot be changed without replacing the key, and needs a touch anyway, so it gets none. **Cached-fixed** has the same 15-second window as **cached**, but it cannot be changed without replacing the key either, so it gets no notice of its own, only the Sign button. There is also no notice above the facts or on stderr for a software key, another card or no card, a card that reports no touch policy or one the wrapper does not know, or a GnuPG without `gpg-connect-agent`: as a policy that cannot be read, each gets only the Sign window's `Touch policy unknown: Sign to continue`. The policy is read from the card on every request, and only from a reply that ends in the status word `90 00`. scdaemon answers `SCD GETATTR UIF-1` from the card data it read when it first opened the card, so after `ykman openpgp keys set-touch` that answer can name the old policy until the key is reinserted or scdaemon restarts, and a key turned from on to off would sign without Sign. The wrapper and the service therefore send the card a GET DATA for that object through scdaemon (`SCD APDU 00CA00D600`), and any error or unexpected reply reads as a policy that cannot be read, which asks for Sign. scdaemon keeps the card's OpenPGP application selected for such a command, so per GnuPG's source a PIN the card already holds stays verified, and per the OpenPGP card specification GET DATA does not change PIN state. Confirm on first use with a real YubiKey: that the PIN holds (if it did not, the next signature would ask for it again), and, by pressing Cancel while the key blinks, when the key stops blinking and that the next request signs. The remote signing service shows the same notice, and asks for the same Sign click, for the key it signs with. A key whose policy cannot be read gets the same Sign window there.

Earlier versions offered the cached policy in a window of their own and kept a record of that offer in `~/.config/git-gpg-preview/touch-offers`. The offer is gone, and so is its record: the file is now unused, so nothing reads or writes it. Upgrades leave it in place, and you can delete it. A key that took the offer stays cached and gets the notice above until you change it.

### PIN window

When the signing key is on a smart card (such as a YubiKey) and Git is the caller (it passes `--status-fd=2`), the wrapper asks for the PIN itself instead of gpg-agent's pinentry. It runs GPG with `--pinentry-mode loopback --command-fd 3`; when GPG asks for the PIN, the wrapper shows a **PIN window** with a secure field and, under it, how many attempts the key has left (read with `gpg --card-status` before each attempt). At two or fewer, that line is **bold red**. The PIN travels from the window to GPG through a pipe in the private request directory. It is never written to a file, logged or audited.

The window refuses a PIN shorter than 6 characters. GnuPG rejects such a PIN itself, without sending it to the key, and reports the same `Bad PIN` error as a wrong one. **Cancel** in the PIN window cancels signing, like **Cancel** in the preview. A PIN the key already holds needs no window, so only the touch is asked for. If GPG asks anything other than the PIN while the PIN window is in use (for example an insert-card prompt), the request fails at once with that question named, rather than waiting for an answer the PIN window cannot give.

The key that decides is the one GPG will sign with: the exact primary key or subkey a selector ending in `!` names; otherwise, from the first matching certificate that can sign, its newest usable signing subkey, or its primary key when no subkey can sign. GnuPG 2.3 and later may instead pick a key on a card, or a software key whose passphrase is cached and needs no prompt. So whenever that key is on a card, GPG signs with a card key or asks nothing; any other choice keeps pinentry, which handles card PINs too. A certificate holding both card and software signing keys thus never shows the PIN window for a software key's passphrase. Requests that name more than one key, or their own keyring, home directory or options file, keep pinentry. Software keys, callers other than Git, and callers that choose their own PIN handling keep gpg-agent's pinentry. Add `pin_prompt=pinentry` to `~/.config/git-gpg-preview/config` to always use pinentry. Upgrades and re-installs keep that line. Loopback needs gpg-agent's default `allow-loopback-pinentry`. If `no-allow-loopback-pinentry` is set, use `pin_prompt=pinentry`.

### Wrong PIN

If your security key rejects the PIN, the request does not fail straight away. The wrapper reads how many PIN attempts the key has left and shows an **Incorrect PIN** dialog with that number. If the count did not drop, the dialog says the PIN never reached the key and no attempt was used.

- **Try Again** shows the preview again, with a line saying which attempt this is and how many remain, then asks for the PIN again in a new, empty field. The wrong PIN cannot be submitted twice by accident.
- **Cancel** ends the request; Git receives GPG's `Bad PIN` failure.
- When the key reports no attempts left, the dialog says the PIN is blocked and offers only **OK**. Unblock it with the Admin PIN (`gpg --card-edit`, then `admin`, `passwd` and option `2`) or, if one is set, with a Reset Code (`gpg --card-edit`, then `unblock`).
- If the counter cannot be read, a request allows two attempts in total: wrong PINs from earlier requests may already have been counted, and a third could block the key.

This also works with pinentry (`pin_prompt=pinentry`): each retry opens a new pinentry. The dialog lock stays held across retries, so other queued signing requests wait instead of failing. Audit entries record `bad-pin-retry` for each retry and `bad-pin` when the request stops after a wrong PIN. Only card PIN failures are retried; gpg-agent re-prompts for a wrong software-key passphrase itself. Remote signing does not use the PIN window or retry yet: a wrong PIN fails that remote commit.

For commits, **Mark as Spam** cancels signing and remembers the first non-empty
subject line. Future commits with that exact subject are rejected before the
preview or GPG starts, across repositories and requesting hosts. Matching ignores
surrounding spaces/tabs and ASCII letter case; it does not use patterns or match
longer subjects. Tags, unknown payloads, empty subjects, and subjects containing
control characters do not offer this action. Payloads containing NUL bytes cannot
create rules either.

The local wrapper and remote signing service share the signing Mac's
`~/.config/git-gpg-preview/spam-subjects` (under `XDG_CONFIG_HOME` when set, or
the service's `--config-dir`). This private mode-0600 text file contains one
normalized subject per line. **To undo a mark, remove that line**; the next request
reads the updated file without a restart. Upgrades preserve the list; uninstalling
removes it with the configuration. Fixture override variables do not bypass these
operator-created rules, and remote requesters cannot create rules. If saving a
rule fails, the current request is still cancelled and the error says the subject
was not saved. Audit entries record `spam-mark`, `spam-reject`, or `spam-save-error`
without including the subject. Only the separate spam list stores subject text.

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
still ends in your touch, or in your click on Sign when the key's touch policy is off, cached, cached-fixed or cannot be read: the review window shows the exact payload bytes and
hex view built on this machine from what arrived, and labels the diff as
derived on the requesting host. Fixture-style subjects and identities are
refused here as well, whatever the client sent. Cancel, a missed touch or Sign click (`sign_timeout_seconds`,
default 120, counted from the request's arrival; see [Touch policy](#touch-policy) for how it is shared), an offline Mac and an unknown peer all fail the remote commit;
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
fake `tailscale`, `gpg`, `gpg-connect-agent` and dialog helpers on any platform, plus one real
GnuPG round trip with a disposable key when `gpg` is installed.

## Fail-closed cases

A signing request is rejected before GPG runs when the real-GPG path or UI helper is missing, a recognized commit/tag payload cannot be safely parsed against available Git objects, or a secure temporary area cannot be created. It is also rejected when its arguments would make GPG sign anything but the previewed standard input: a file argument, a lone `-`, anything after `--`, or an option that reads standard input itself, such as `--passphrase-fd=0` or `--recipient-file=-`. Write the value of an option the wrapper does not list as `--option=value`. The wrapper treats a request as signing when any signing command appears, abbreviated or not, even alongside `--verify`. Once the preview and GPG are engaged, a **Cancel** decision, a preview process that exits without approval, or any outcome other than a completed signature kills GPG before it produces a signature. Unknown signing formats still receive a clearly labeled exact-payload review.

Non-signing operations require a valid real-GPG configuration too; when configured correctly, they use `exec` for transparent argument, descriptor, signal, stdout/stderr, and exit behavior. For signing, GPG's stderr is held per attempt and forwarded once the request ends, so a wrong-PIN attempt that is retried never reaches Git; stdout is held in a private request file until the final dialog decision is checked, so a simultaneous touch and cancellation or spam mark cannot return a signature to Git. Because the preview is terminated as soon as GPG exits, a decision could otherwise be cut off before it reaches that file: the preview therefore records a marker the instant a rejection is chosen, and a marked request waits up to two seconds for the decision itself and refuses to sign if it never lands. An outcome that cannot be read is never treated as approval. The wrapper propagates GPG's exact exit code and forwards termination signals. The wrapper never writes UI or diagnostic text to stdout because Git expects the detached signature there.

## Threat model and limitations

This tool protects against accidentally producing an unexpected Git OpenPGP signature: the payload is reviewed while your hardware key waits, and the deliberate physical confirmation is what completes the signature. It makes concurrent agent-driven requests attributable at review time and serializes them behind a single hardware confirmation. It does not replace GnuPG signature security, hardware-key confirmation, repository access controls, or careful review.

Important limitations:

- The preview is shown while GnuPG is already engaged, so the hardware confirmation is the authorization gate. This is a deliberate trade for the touch-to-sign workflow: unlike a design that contacts GPG only after a software approval, GnuPG and gpg-agent are invoked for every signing request. A key whose policy requires no touch (for example, a cached PIN and touch disabled) can therefore complete signing before the preview is meaningfully reviewed; keep the hardware touch requirement enabled so signing always blocks on a deliberate action. When the wrapper or the remote signing service reads any policy but **on** or **fixed** from the card, or cannot read the policy, GnuPG waits for a click on **Sign** instead, so that click is the gate. The cached policy lets one touch cover every signature for the next 15 seconds, including touches made outside this tool, so a request that arrives in that window would sign without a touch of its own; every signature with such a key therefore needs Sign as well, and the preview suggests **on**. **Cached-fixed** has the same 15-second window and the same Sign click, but cannot be changed without replacing the key, so it gets no notice of its own.
- A process already running as your macOS account can modify user-owned wrapper/configuration files, tamper with Git objects between review and later use, simulate UI, or invoke GPG directly. The same goes for GnuPG configuration: the wrapper checks a request's arguments, not what a `gpg.conf`, `--options` file or `GNUPGHOME` tells GPG to do.
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

`./tests/run.sh` uses a fake GPG and a noninteractive fake dialog in an isolated home directory. It covers normal and initial commits, merge commits, annotated tags, push certificates, unknown/binary payloads, hostile Unicode content, fixture-style subject and identity rejection, near-misses, and the override, cancellation, verification pass-through, GPG failure status, stdout purity, the PIN window (remaining-attempts line, short-PIN refusal, cancel), wrong-PIN retry, uncounted and blocked PINs, the pinentry fallback, the touch-policy notice, the Sign gate for off, cached, cached-fixed and unknown policies (and none for on and fixed), a policy changed since scdaemon read the card, the window after Sign, the card operation a stopped signature leaves behind (in the request's own GnuPG home, too), a signal while GPG waits, inherited variables named like the wrapper's own, the split between the message and the request's facts and the characters a fact may not hold, refusal of anything but the previewed standard input as signing input, exact stdin/argument forwarding, concurrent queueing, stale lock recovery, safe diff options, and audit logging.

## License

MIT. See [LICENSE](LICENSE).
