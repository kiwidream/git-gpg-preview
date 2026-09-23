#!/bin/bash

set -euo pipefail
umask 077

ROOT=$(cd -P -- "$(dirname -- "$0")/.." && pwd)
TMP="$ROOT/tests/tmp/run.$$"
ORIGINAL_HOME=$HOME
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/home/.config/git-gpg-preview" "$TMP/temp" "$TMP/calls" "$TMP/captures" "$TMP/lock"

export HOME="$TMP/home"
export XDG_CONFIG_HOME="$HOME/.config"
export TMPDIR="$TMP/temp"
export FAKE_GPG_CALL_DIR="$TMP/calls"
export FAKE_DIALOG_CAPTURE_DIR="$TMP/captures"
export FAKE_DIALOG_DECISION=sign
export FAKE_DIALOG_DELAY=0
export FAKE_DIALOG_LOG="$TMP/dialog.log"
# Shared "hardware touch" signal: the fake dialog creates it for a sign
# decision; the fake GPG blocks on it so signing is concurrent with review.
export FAKE_TOUCH_FILE="$TMP/touch"

cat > "$XDG_CONFIG_HOME/git-gpg-preview/config" <<EOF
real_gpg=$ROOT/tests/helpers/fake-gpg
ui_helper=$ROOT/tests/helpers/fake-dialog.jxa
lock_root=$TMP/lock
audit_log=$TMP/audit.log
EOF
chmod 600 "$XDG_CONFIG_HOME/git-gpg-preview/config"

pass_count=0
fail() {
    printf 'not ok - %s\n' "$*" >&2
    exit 1
}
pass() {
    pass_count=$((pass_count + 1))
    printf 'ok %d - %s\n' "$pass_count" "$1"
}

latest_call() {
    tail -n 1 "$FAKE_GPG_CALL_DIR/calls"
}
latest_capture() {
    ls -t "$TMP/captures"/*.summary | head -n 1
}
details_of() {
    printf '%s\n' "${1%.summary}.details"
}
assert_forwarded() {
    local expected="$1" id
    id=$(latest_call)
    cmp -s "$expected" "$FAKE_GPG_CALL_DIR/$id.stdin" || fail "stdin changed before real GPG"
}
run_preview() {
    local label="$1" payload="$2" expected_type="$3" expected_stdout output summary details id
    expected_stdout="signature:$label"
    export FAKE_GPG_STDOUT="$expected_stdout"
    rm -f "$FAKE_TOUCH_FILE".*
    output=$("$ROOT/git-gpg-preview" --status-fd=2 -bsau 'TEST KEY ! $(touch bad)' < "$payload")
    [[ "$output" == "$expected_stdout" ]] || fail "$label contaminated stdout"
    assert_forwarded "$payload"
    summary=$(latest_capture)
    details=$(details_of "$summary")
    grep -F "Request type: $expected_type" "$summary" >/dev/null || fail "$label classified incorrectly"
    grep -F 'SHA-256:' "$summary" >/dev/null || fail "$label omitted payload hash"
    grep -F 'Signing key: TEST KEY ! $(touch bad)' "$summary" >/dev/null || fail "$label lost key selector"
    grep -F 'Exact payload SHA-256:' "$details" >/dev/null || fail "$label details omitted payload hash"
    [[ ! -e "$FIXTURE/bad" ]] || fail "$label executed hostile-looking key content"
    id=$(latest_call)
    printf '%s\0' --status-fd=2 -bsau 'TEST KEY ! $(touch bad)' > "$TMP/expected.args"
    cmp -s "$TMP/expected.args" "$FAKE_GPG_CALL_DIR/$id.args" || fail "$label changed GPG arguments"
}

FIXTURE="$TMP/repository with spaces"
mkdir -p "$FIXTURE"
git -C "$FIXTURE" init -b main >/dev/null
git -C "$FIXTURE" config user.name 'Preview Tester'
# Not a reserved test domain: fixtures that must reach the dialog cannot
# trip the fixture-identity rule. The rule's own cases set it per commit.
git -C "$FIXTURE" config user.email 'preview@preview-tester.dev'
git -C "$FIXTURE" config commit.gpgSign false
git -C "$FIXTURE" config tag.gpgSign false

printf 'initial\n' > "$FIXTURE/initial.txt"
git -C "$FIXTURE" add -- initial.txt
git -C "$FIXTURE" commit -m 'Initial message' >/dev/null
INITIAL=$(git -C "$FIXTURE" rev-parse HEAD)
git -C "$FIXTURE" cat-file commit "$INITIAL" > "$TMP/initial.payload"

HOSTILE_NAME=$'unicodé $(touch bad)\nsecond line.txt'
printf 'hostile-looking filename content\n' > "$FIXTURE/$HOSTILE_NAME"
git -C "$FIXTURE" add -- "$HOSTILE_NAME"
git -C "$FIXTURE" commit -m $'Unicode Ω and spaces\n\n$(touch bad); `touch bad`; "quoted"' >/dev/null
SECOND=$(git -C "$FIXTURE" rev-parse HEAD)
git -C "$FIXTURE" cat-file commit "$SECOND" > "$TMP/commit.payload"

git -C "$FIXTURE" checkout -b side "$SECOND" >/dev/null
printf 'side\n' > "$FIXTURE/side.txt"
git -C "$FIXTURE" add -- side.txt
git -C "$FIXTURE" commit -m 'Side parent' >/dev/null
git -C "$FIXTURE" checkout main >/dev/null
printf 'main\n' > "$FIXTURE/main.txt"
git -C "$FIXTURE" add -- main.txt
git -C "$FIXTURE" commit -m 'Main parent' >/dev/null
git -C "$FIXTURE" merge --no-ff side -m 'Merge two parents' >/dev/null
MERGE=$(git -C "$FIXTURE" rev-parse HEAD)
git -C "$FIXTURE" cat-file commit "$MERGE" > "$TMP/merge.payload"

git -C "$FIXTURE" tag -a preview-tag -m $'Annotated tag Ω\n\n$(touch bad)'
TAG_OBJECT=$(git -C "$FIXTURE" rev-parse preview-tag)
git -C "$FIXTURE" cat-file tag "$TAG_OBJECT" > "$TMP/tag.payload"

printf 'near miss\n' > "$FIXTURE/policy.txt"
git -C "$FIXTURE" add -- policy.txt
git -C "$FIXTURE" commit -m 'production release' >/dev/null
NEAR_MISS=$(git -C "$FIXTURE" rev-parse HEAD)
git -C "$FIXTURE" cat-file commit "$NEAR_MISS" > "$TMP/policy-near-miss.payload"

# The blocklist's single source of truth is the FIXTURE_SUBJECTS line in
# the wrapper itself; "Production" is added as a case-insensitivity probe.
REJECTED_SUBJECTS="$(sed -n 's/^FIXTURE_SUBJECTS="\(.*\)"$/\1/p' "$ROOT/git-gpg-preview") Production"
[[ "$REJECTED_SUBJECTS" != " Production" ]] || fail 'could not read FIXTURE_SUBJECTS from wrapper'

for rejected_subject in $REJECTED_SUBJECTS; do
    printf '%s\n' "$rejected_subject" > "$FIXTURE/policy.txt"
    git -C "$FIXTURE" add -- policy.txt
    git -C "$FIXTURE" commit -m "$rejected_subject" >/dev/null
    REJECTED_COMMIT=$(git -C "$FIXTURE" rev-parse HEAD)
    git -C "$FIXTURE" cat-file commit "$REJECTED_COMMIT" > "$TMP/policy-$rejected_subject.payload"
done

# The identity rule reads author and committer emails from the payload
# header; one reserved address in either role is enough.
REJECTED_EMAILS=""
for rejected_email in $(sed -n 's/^FIXTURE_EMAIL_DOMAINS="\(.*\)"$/\1/p' "$ROOT/git-gpg-preview"); do
    REJECTED_EMAILS="$REJECTED_EMAILS tester@$rejected_email"
done
[[ -n "$REJECTED_EMAILS" ]] || fail 'could not read FIXTURE_EMAIL_DOMAINS from wrapper'
REJECTED_EMAILS="$REJECTED_EMAILS ci@Sub.Example.COM"
for rejected_email in $REJECTED_EMAILS; do
    git -C "$FIXTURE" commit -q --allow-empty --author="Tester <$rejected_email>" -m 'Descriptive subject from a test' >/dev/null
    git -C "$FIXTURE" cat-file commit HEAD > "$TMP/identity-author-$rejected_email.payload"
    GIT_COMMITTER_EMAIL="$rejected_email" git -C "$FIXTURE" commit -q --allow-empty -m 'Descriptive subject from a test' >/dev/null
    git -C "$FIXTURE" cat-file commit HEAD > "$TMP/identity-committer-$rejected_email.payload"
done
git -C "$FIXTURE" -c user.email='tester@notexample.com' commit -q --allow-empty -m 'Lookalike domain' >/dev/null
git -C "$FIXTURE" cat-file commit HEAD > "$TMP/identity-near-miss.payload"
printf 'body names <someone@example.com>\n' > "$FIXTURE/policy.txt"
git -C "$FIXTURE" add -- policy.txt
git -C "$FIXTURE" commit -q -m $'Reserved address only in the body\n\nCo-authored-by: Test <test@example.com>' >/dev/null
git -C "$FIXTURE" cat-file commit HEAD > "$TMP/identity-body.payload"

git -C "$FIXTURE" tag -a policy-tag -m 'production'
POLICY_TAG_OBJECT=$(git -C "$FIXTURE" rev-parse policy-tag)
git -C "$FIXTURE" cat-file tag "$POLICY_TAG_OBJECT" > "$TMP/policy-tag.payload"

cd "$FIXTURE"

run_preview 'initial commit' "$TMP/initial.payload" commit
summary=$(latest_capture)
details=$(details_of "$summary")
grep -F 'Parents: (initial commit; none)' "$details" >/dev/null || fail 'initial commit parent display'
grep -F 'Initial commit (empty tree to proposed tree)' "$details" >/dev/null || fail 'initial commit diffstat'
pass 'initial signed commit payload and root diffstat'

EVIL="$TMP/evil-diff"
cat > "$EVIL" <<EOF
#!/bin/bash
touch '$TMP/external-diff-ran'
exit 99
EOF
chmod 700 "$EVIL"
git config diff.external "$EVIL"
run_preview 'signed commit' "$TMP/commit.payload" commit
[[ ! -e "$TMP/external-diff-ran" ]] || fail 'external diff executed'
summary=$(latest_capture)
grep -F 'Unicode Ω and spaces' "$summary" >/dev/null || fail 'Unicode message missing'
details=$(details_of "$summary")
grep -F 'DERIVED CHANGED-FILE SUMMARY / DIFFSTAT' "$details" >/dev/null || fail 'diffstat missing'
grep -F 'EXACT SIGNED PAYLOAD — VERBATIM BYTES BETWEEN MARKERS' "$details" >/dev/null || fail 'exact payload detail missing'
grep -F 'DERIVED FULL DIFF — REVIEW AID, NOT LITERAL GPG INPUT' "$details" >/dev/null || fail 'derived diff warning missing'
[[ ! -e "$FIXTURE/bad" ]] || fail 'hostile message or filename executed'
pass 'signed commit, hostile content, safe derived diff, and exact payload details'

run_preview 'merge commit' "$TMP/merge.payload" commit
summary=$(latest_capture)
details=$(details_of "$summary")
[[ $(grep -c '^  [0-9a-f]\{40\}$' "$details") -eq 2 ]] || fail 'merge parents not shown'
grep -F 'Changes from parent 2:' "$details" >/dev/null || fail 'second merge-parent diffstat missing'
pass 'merge commit with multiple parents'

run_preview 'annotated tag' "$TMP/tag.payload" tag
summary=$(latest_capture)
details=$(details_of "$summary")
grep -F 'Annotated tag Ω' "$summary" >/dev/null || fail 'tag message missing'
grep -F 'Target object:' "$details" >/dev/null || fail 'tag target missing'
pass 'annotated tag payload'

before_calls=$(wc -l < "$FAKE_GPG_CALL_DIR/calls")
before_dialogs=$(wc -l < "$FAKE_DIALOG_LOG")
for rejected_subject in $REJECTED_SUBJECTS; do
    set +e
    "$ROOT/git-gpg-preview" -bsau TEST < "$TMP/policy-$rejected_subject.payload" > "$TMP/policy-reject.stdout" 2> "$TMP/policy-reject.stderr"
    rejected_status=$?
    set -e
    [[ "$rejected_status" -eq 65 ]] || fail "fixture-style subject $rejected_subject returned $rejected_status"
    [[ ! -s "$TMP/policy-reject.stdout" ]] || fail "fixture-style subject $rejected_subject contaminated stdout"
    grep -F "refusing to sign fixture-style commit subject '$(printf '%s' "$rejected_subject" | tr '[:upper:]' '[:lower:]')'" "$TMP/policy-reject.stderr" >/dev/null || fail "fixture-style subject $rejected_subject omitted the rejection reason"
    grep -F 'if this is a test or fixture repository: disable signing there' "$TMP/policy-reject.stderr" >/dev/null || fail "fixture-style subject $rejected_subject omitted fixture remediation"
    grep -F 'GIT_GPG_PREVIEW_ALLOW_FIXTURE=1' "$TMP/policy-reject.stderr" >/dev/null || fail "fixture-style subject $rejected_subject omitted the override hint"
    grep -F 'remote signing has no fixture override' "$TMP/policy-reject.stderr" >/dev/null || fail "fixture-style subject $rejected_subject omitted the remote policy limit"
done
for rejected_email in $REJECTED_EMAILS; do
    for role in author committer; do
        set +e
        "$ROOT/git-gpg-preview" -bsau TEST < "$TMP/identity-$role-$rejected_email.payload" > "$TMP/policy-reject.stdout" 2> "$TMP/policy-reject.stderr"
        rejected_status=$?
        set -e
        [[ "$rejected_status" -eq 65 ]] || fail "fixture $role identity $rejected_email returned $rejected_status"
        [[ ! -s "$TMP/policy-reject.stdout" ]] || fail "fixture $role identity $rejected_email contaminated stdout"
        grep -F "refusing to sign fixture-style commit identity '$(printf '%s' "$rejected_email" | tr '[:upper:]' '[:lower:]')'" "$TMP/policy-reject.stderr" >/dev/null || fail "fixture $role identity $rejected_email omitted the rejection reason"
    done
done
after_calls=$(wc -l < "$FAKE_GPG_CALL_DIR/calls")
after_dialogs=$(wc -l < "$FAKE_DIALOG_LOG")
[[ "$before_calls" -eq "$after_calls" ]] || fail 'fixture-style rejection contacted GPG'
[[ "$before_dialogs" -eq "$after_dialogs" ]] || fail 'fixture-style rejection opened a dialog'
grep -F 'decision=policy-reject' "$TMP/audit.log" >/dev/null || fail 'fixture-style rejection was not recorded in the audit log'
pass 'fixture-style commit subjects and test identities fail before the dialog and GPG with clear remediation'

# The audited override signs a blocked commit and records the decision;
# GIT_GPG_PREVIEW_ALLOW_SUBJECT is its original name and still works.
export GIT_GPG_PREVIEW_ALLOW_FIXTURE=1
run_preview 'override init' "$TMP/policy-init.payload" commit
run_preview 'override identity' "$TMP/identity-author-tester@invalid.payload" commit
unset GIT_GPG_PREVIEW_ALLOW_FIXTURE
export GIT_GPG_PREVIEW_ALLOW_SUBJECT=1
run_preview 'override seed' "$TMP/policy-seed.payload" commit
unset GIT_GPG_PREVIEW_ALLOW_SUBJECT
[[ $(grep -c 'decision=policy-override' "$TMP/audit.log") -eq 3 ]] || fail 'fixture override was not recorded in the audit log'
pass 'GIT_GPG_PREVIEW_ALLOW_FIXTURE=1 (or the older ALLOW_SUBJECT) signs a blocked commit and audits the override'

run_preview 'fixture policy near-miss' "$TMP/policy-near-miss.payload" commit
run_preview 'fixture policy tag' "$TMP/policy-tag.payload" tag
run_preview 'fixture identity near-miss' "$TMP/identity-near-miss.payload" commit
run_preview 'fixture identity in body' "$TMP/identity-body.payload" commit
pass 'longer subjects, lookalike domains, reserved addresses in the body, and tags are not rejected'

{
    printf 'unknown signing format\nUnicode Ω\n'
    printf '\000\001hostile $(touch bad)\n'
} > "$TMP/unknown.payload"
run_preview 'unknown payload' "$TMP/unknown.payload" unknown
pass 'unknown and binary signing payload'

cat > "$TMP/push.payload" <<EOF
certificate version 0.1
pusher 0123456789012345678901234567890123456789 1700000000 +0000
pushee ssh://example.invalid/repository

0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/main
EOF
run_preview 'push certificate' "$TMP/push.payload" 'push certificate'
pass 'push certificate payload'

before=$(wc -l < "$FAKE_GPG_CALL_DIR/calls")
export FAKE_DIALOG_DECISION=cancel
rm -f "$FAKE_TOUCH_FILE".*
set +e
cancel_output=$("$ROOT/git-gpg-preview" -bsau TEST < "$TMP/commit.payload" 2>"$TMP/cancel.stderr")
cancel_status=$?
set -e
after=$(wc -l < "$FAKE_GPG_CALL_DIR/calls")
[[ "$cancel_status" -ne 0 ]] || fail 'cancellation returned success'
[[ -z "$cancel_output" ]] || fail 'cancellation wrote stdout'
[[ "$before" -eq "$after" ]] || fail 'cancellation contacted GPG'
pass 'cancellation fails without contacting GPG'

export FAKE_DIALOG_DECISION=sign
export FAKE_GPG_STDOUT='verify-output'
printf 'verification input bytes\000tail' > "$TMP/verify.stdin"
verify_output=$("$ROOT/git-gpg-preview" --status-fd=1 --verify "$TMP/fake.sig" - < "$TMP/verify.stdin")
[[ "$verify_output" == 'verify-output' ]] || fail 'verification stdout changed'
assert_forwarded "$TMP/verify.stdin"
pass 'verification invocation transparently passes through'

export FAKE_GPG_STDOUT='gpg-failure-output'
export FAKE_GPG_EXIT=42
rm -f "$FAKE_TOUCH_FILE".*
set +e
"$ROOT/git-gpg-preview" -bsau TEST < "$TMP/commit.payload" > "$TMP/failure.stdout" 2> "$TMP/failure.stderr"
failure_status=$?
set -e
unset FAKE_GPG_EXIT
[[ "$failure_status" -eq 42 ]] || fail "GPG exit status changed ($failure_status)"
[[ $(<"$TMP/failure.stdout") == 'gpg-failure-output' ]] || fail 'GPG failure stdout changed'
assert_forwarded "$TMP/commit.payload"
pass 'GPG failure and exact exit code propagation'

export FAKE_GPG_STDOUT=''
export FAKE_GPG_SIGNAL=TERM
rm -f "$FAKE_TOUCH_FILE".*
set +e
"$ROOT/git-gpg-preview" -bsau TEST < "$TMP/commit.payload" > "$TMP/signal.stdout" 2> "$TMP/signal.stderr"
signal_status=$?
set -e
unset FAKE_GPG_SIGNAL
[[ "$signal_status" -eq 143 ]] || fail "GPG signal was not propagated ($signal_status)"
[[ ! -s "$TMP/signal.stdout" ]] || fail 'signal path contaminated stdout'
pass 'GPG termination-signal propagation'

: > "$FAKE_DIALOG_LOG"
export FAKE_GPG_STDOUT='parallel-signature'
export FAKE_DIALOG_DELAY=0.35
rm -f "$FAKE_TOUCH_FILE".*
"$ROOT/git-gpg-preview" -bsau TEST < "$TMP/commit.payload" > "$TMP/parallel.1" 2> "$TMP/parallel.1.err" &
p1=$!
"$ROOT/git-gpg-preview" -bsau TEST < "$TMP/merge.payload" > "$TMP/parallel.2" 2> "$TMP/parallel.2.err" &
p2=$!
wait "$p1"
wait "$p2"
export FAKE_DIALOG_DELAY=0
lock_events=()
while IFS= read -r event; do
    lock_events+=("$event")
done < "$FAKE_DIALOG_LOG"
[[ "${#lock_events[@]}" -eq 4 ]] || fail 'concurrent dialog event count'
[[ "${lock_events[0]}" == start\ * && "${lock_events[1]}" == end\ * && "${lock_events[2]}" == start\ * && "${lock_events[3]}" == end\ * ]] || fail 'dialogs overlapped'
[[ $(<"$TMP/parallel.1") == 'parallel-signature' && $(<"$TMP/parallel.2") == 'parallel-signature' ]] || fail 'parallel stdout changed'
pass 'concurrent requests queue dialogs and retain separate payloads'

printf '999999\n' > "$TMP/lock/dialog.lock"
export FAKE_GPG_STDOUT='stale-lock-recovered'
rm -f "$FAKE_TOUCH_FILE".*
stale_output=$("$ROOT/git-gpg-preview" -bsau TEST < "$TMP/commit.payload")
[[ "$stale_output" == 'stale-lock-recovered' ]] || fail 'stale lock recovery failed'
pass 'stale dialog lock recovery'

before=$(wc -l < "$FAKE_GPG_CALL_DIR/calls")
printf 'tree 0000000000000000000000000000000000000000\n\ninvalid tree\n' > "$TMP/invalid-commit.payload"
set +e
"$ROOT/git-gpg-preview" -bsau TEST < "$TMP/invalid-commit.payload" > "$TMP/invalid.stdout" 2> "$TMP/invalid.stderr"
invalid_status=$?
set -e
after=$(wc -l < "$FAKE_GPG_CALL_DIR/calls")
[[ "$invalid_status" -ne 0 && "$before" -eq "$after" ]] || fail 'invalid recognized payload reached GPG'
[[ ! -s "$TMP/invalid.stdout" ]] || fail 'invalid payload contaminated stdout'
pass 'recognized payload parsing/object errors fail closed'

[[ -f "$TMP/audit.log" && $(stat -f '%Lp' "$TMP/audit.log") == 600 ]] || fail 'audit log permissions'
! grep -F 'Unicode Ω and spaces' "$TMP/audit.log" >/dev/null || fail 'audit log contains raw message'
grep -F 'decision=sign' "$TMP/audit.log" >/dev/null || fail 'audit decision missing'
pass 'mode-0600 metadata-only audit log'

INSTALL_TEST="$TMP/install-home"
mkdir -p "$INSTALL_TEST"
(
    export HOME="$INSTALL_TEST"
    export XDG_CONFIG_HOME="$HOME/.config"
    "$ROOT/install.sh" --real-gpg "$ROOT/tests/helpers/fake-gpg" >/dev/null
    [[ $(git config --global --get gpg.openpgp.program) == "$HOME/.local/bin/git-gpg-preview" ]]
    [[ $(stat -f '%Lp' "$HOME/.local/bin/git-gpg-preview") == 700 ]]
    [[ $(stat -f '%Lp' "$XDG_CONFIG_HOME/git-gpg-preview/config") == 600 ]]
    [[ $(stat -f '%Lp' "$HOME/.local/libexec/git-gpg-preview/touch-prompt.jxa") == 600 ]]
    grep -qxF "touch_helper=$HOME/.local/libexec/git-gpg-preview/touch-prompt.jxa" \
        "$XDG_CONFIG_HOME/git-gpg-preview/config"
    [[ $(<"$HOME/.local/state/git-gpg-preview/previous-program-state") == absent ]]
    "$ROOT/install.sh" --real-gpg "$ROOT/tests/helpers/fake-gpg" >/dev/null
    [[ $(<"$HOME/.local/state/git-gpg-preview/previous-program-state") == absent ]]
    "$ROOT/uninstall.sh" >/dev/null
    ! git config --global --get gpg.openpgp.program >/dev/null 2>&1
    [[ ! -e "$HOME/.local/bin/git-gpg-preview" ]]
    [[ ! -e "$HOME/.local/libexec/git-gpg-preview" ]]
) || fail 'idempotent install or absent-value recovery'
pass 'idempotent installation and restoration of an absent previous value'

UPGRADE_TEST="$TMP/upgrade-home"
mkdir -p "$UPGRADE_TEST"
(
    export HOME="$UPGRADE_TEST"
    export XDG_CONFIG_HOME="$HOME/.config"
    config="$XDG_CONFIG_HOME/git-gpg-preview/config"
    state="$HOME/.local/state/git-gpg-preview"
    installed="$HOME/.local/bin/git-gpg-preview"
    libexec="$HOME/.local/libexec/git-gpg-preview"
    "$ROOT/install.sh" --real-gpg "$ROOT/tests/helpers/fake-gpg" \
        --audit-log "$HOME/audit.log" >/dev/null
    cp "$config" "$TMP/upgrade-config.before"
    cp "$state/previous-program-state" "$TMP/upgrade-state.before"
    cp "$state/previous-program-values" "$TMP/upgrade-values.before"
    git config --global --null --get-all gpg.openpgp.program \
        > "$TMP/upgrade-program.before"
    printf 'stale wrapper\n' > "$installed"
    printf 'stale dialog\n' > "$libexec/dialog.jxa"
    printf 'stale touch prompt\n' > "$libexec/touch-prompt.jxa"
    "$ROOT/scripts/git-gpg-preview-setup" upgrade >/dev/null
    cmp -s "$ROOT/git-gpg-preview" "$installed"
    cmp -s "$ROOT/dialog.jxa" "$libexec/dialog.jxa"
    cmp -s "$ROOT/touch-prompt.jxa" "$libexec/touch-prompt.jxa"
    cmp -s "$config" "$TMP/upgrade-config.before"
    cmp -s "$state/previous-program-state" "$TMP/upgrade-state.before"
    cmp -s "$state/previous-program-values" "$TMP/upgrade-values.before"
    git config --global --null --get-all gpg.openpgp.program \
        > "$TMP/upgrade-program.after"
    cmp -s "$TMP/upgrade-program.before" "$TMP/upgrade-program.after"
    "$ROOT/uninstall.sh" >/dev/null
) || fail 'configuration-preserving upgrade'
pass 'upgrade refreshes installed files without changing configuration or Git state'

RESTORE_TEST="$TMP/restore-home"
mkdir -p "$RESTORE_TEST"
(
    export HOME="$RESTORE_TEST"
    export XDG_CONFIG_HOME="$HOME/.config"
    git config --global --add gpg.openpgp.program '/previous/path with spaces/gpg'
    "$ROOT/install.sh" --real-gpg "$ROOT/tests/helpers/fake-gpg" >/dev/null
    "$ROOT/uninstall.sh" >/dev/null
    [[ $(git config --global --get-all gpg.openpgp.program) == '/previous/path with spaces/gpg' ]]
) || fail 'exact previous-value restoration'
pass 'uninstaller restores the exact previous program value'

# The launcher is installed as a symlink on PATH, which is how everyone
# actually runs it, so exercise it that way rather than from the checkout.
SYMLINK_TEST="$TMP/symlink-home"
mkdir -p "$SYMLINK_TEST" "$TMP/fake-bin"
ln -s "$ROOT/scripts/git-gpg-preview-setup" "$TMP/fake-bin/git-gpg-preview-setup"
# Every step needs its own `|| exit`: errexit does not apply inside a subshell
# whose status is being tested by `||`, so without them only the last command
# would decide the result — and "not installed" would read as success.
(
    export HOME="$SYMLINK_TEST"
    export XDG_CONFIG_HOME="$HOME/.config"
    "$TMP/fake-bin/git-gpg-preview-setup" install --real-gpg "$ROOT/tests/helpers/fake-gpg" >/dev/null || exit 1
    [[ -x "$HOME/.local/bin/git-gpg-preview" ]] || exit 1
    [[ -f "$HOME/.local/libexec/git-gpg-preview/touch-prompt.jxa" ]] || exit 1
    printf 'stale wrapper\n' > "$HOME/.local/bin/git-gpg-preview"
    "$TMP/fake-bin/git-gpg-preview-setup" upgrade >/dev/null || exit 1
    cmp -s "$ROOT/git-gpg-preview" "$HOME/.local/bin/git-gpg-preview" || exit 1
    "$TMP/fake-bin/git-gpg-preview-setup" status >/dev/null || exit 1
    "$TMP/fake-bin/git-gpg-preview-setup" uninstall >/dev/null || exit 1
    [[ ! -e "$HOME/.local/bin/git-gpg-preview" ]] || exit 1
) || fail 'launcher invoked through an installed symlink'
pass 'launcher resolves its own symlink when run from PATH'

[[ ! -e "$ORIGINAL_HOME/git-gpg-preview-tests-touched" ]] || fail 'unexpected file outside test area'
printf '1..%d\n' "$pass_count"
