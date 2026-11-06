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
# By default GPG signs with a card key whose touch policy reads on, through the
# gpg-connect-agent beside it, so the preview runs beside GPG and the touch is
# the gate. The touch policy tests below vary this; default_card restores it.
DEFAULT_CARD_KEY=CCCC000000000000000000000000000000000002
default_card() {
    export FAKE_CARD_SIG_KEY=$DEFAULT_CARD_KEY FAKE_CARD_UIF=%01+
}
default_card
mkdir -p "$TMP/default-gnupg"
ln -s "$ROOT/tests/helpers/fake-gpg" "$TMP/default-gnupg/gpg"
ln -s "$ROOT/tests/helpers/fake-gpg-connect-agent" "$TMP/default-gnupg/gpg-connect-agent"

cat > "$XDG_CONFIG_HOME/git-gpg-preview/config" <<EOF
real_gpg=$TMP/default-gnupg/gpg
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
    printf '%s\0' --pinentry-mode loopback --command-fd 3 --status-fd=2 -bsau 'TEST KEY ! $(touch bad)' > "$TMP/expected.args"
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
REJECTED_SUBJECTS=$(sed -n 's/^FIXTURE_SUBJECTS="\(.*\)"$/\1/p' "$ROOT/git-gpg-preview" | tr '|' '\n')
[[ -n "$REJECTED_SUBJECTS" ]] || fail 'could not read FIXTURE_SUBJECTS from wrapper'
REJECTED_SUBJECTS+=$'\nProduction\nPR HEAD\nMR HEAD\nInitial Commit'

while IFS= read -r rejected_subject; do
    printf '%s\n' "$rejected_subject" > "$FIXTURE/policy.txt"
    git -C "$FIXTURE" add -- policy.txt
    git -C "$FIXTURE" commit -m "$rejected_subject" >/dev/null
    REJECTED_COMMIT=$(git -C "$FIXTURE" rev-parse HEAD)
    git -C "$FIXTURE" cat-file commit "$REJECTED_COMMIT" > "$TMP/policy-$rejected_subject.payload"
done <<< "$REJECTED_SUBJECTS"

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
while IFS= read -r rejected_subject; do
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
done <<< "$REJECTED_SUBJECTS"
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
! grep -q '^pin-error' "$FAKE_DIALOG_LOG" || fail 'non-PIN GPG failure offered a PIN retry'
pass 'GPG failure and exact exit code propagation'

# The wrapper asks for the PIN itself (GnuPG loopback) whenever Git reports
# status on stderr. Each attempt reads the key's counter first and shows it
# under the PIN field; a wrong PIN offers Try Again with the new count.
export FAKE_PIN_ENTRY_STATE="$TMP/pin-entry-state"
reset_pin_state() {
    rm -f "$FAKE_TOUCH_FILE".* "$FAKE_GPG_CALL_DIR/bad-pin-calls" "$FAKE_GPG_CALL_DIR/counted-bad-pins" \
        "$FAKE_GPG_CALL_DIR/pins-received" "$FAKE_GPG_CALL_DIR/card-status-calls" "$FAKE_PIN_ENTRY_STATE" "$TMP/captures"/*
    : > "$FAKE_DIALOG_LOG"
    : > "$TMP/audit.log"
}
run_pin_case() {
    set +e
    pin_output=$("$ROOT/git-gpg-preview" "$@" < "$TMP/commit.payload" 2>"$TMP/pin.stderr")
    pin_status=$?
    set -e
}
pin_dialogs() {
    grep -E '^pin-(entry|error) ' "$FAKE_DIALOG_LOG" || true
}

# A PIN the key already holds needs no window; the loopback options are added.
reset_pin_state
export FAKE_GPG_STDOUT='signature-cached-pin' FAKE_PIN_RETRIES=3
run_pin_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 0 && "$pin_output" == 'signature-cached-pin' ]] || fail "cached PIN signing ($pin_status)"
[[ -z $(pin_dialogs) ]] || fail 'PIN window shown although GPG did not ask for a PIN'
printf '%s\0' --pinentry-mode loopback --command-fd 3 --status-fd=2 -bsau TEST > "$TMP/expected.args"
cmp -s "$TMP/expected.args" "$FAKE_GPG_CALL_DIR/$(latest_call).args" || fail 'loopback arguments'
pass 'PIN window appears only when GPG asks for a PIN'

reset_pin_state
export FAKE_GPG_STDOUT='signature-after-retry' FAKE_GPG_PIN=123456
export FAKE_PIN_ENTRIES=654321,123456 FAKE_PIN_ERROR_DECISION=retry
before=$(wc -l < "$FAKE_GPG_CALL_DIR/calls")
run_pin_case --status-fd=2 -bsau TEST
after=$(wc -l < "$FAKE_GPG_CALL_DIR/calls")
[[ "$pin_status" -eq 0 && "$pin_output" == 'signature-after-retry' ]] || fail "PIN retry did not sign ($pin_status)"
[[ $((after - before)) -eq 1 ]] || fail 'PIN retry did not sign exactly once'
assert_forwarded "$TMP/commit.payload"
[[ $(<"$FAKE_GPG_CALL_DIR/pins-received") == $'654321\n123456' ]] || fail 'PINs did not reach GPG through the PIN channel'
[[ $(pin_dialogs) == $'pin-entry 3 1\npin-error 2 retry counted\npin-entry 2 2' ]] \
    || fail "PIN window/error sequence: $(pin_dialogs)"
[[ $(grep -c '^start ' "$FAKE_DIALOG_LOG") -eq 2 ]] || fail 'preview was not shown again for the retry'
grep -lq 'PIN attempt 2: the previous PIN was incorrect (2 PIN attempts remaining)' "$TMP/captures"/*.summary \
    || fail 'retry preview did not show the attempt and remaining count'
! grep -q 'Bad PIN' "$TMP/pin.stderr" || fail 'retried attempt leaked its failure to Git'
! grep -rq '654321\|123456' "$TMPDIR" "$TMP/audit.log" "$TMP/pin.stderr" || fail 'a PIN was written to disk'
grep -q 'decision=bad-pin-retry' "$TMP/audit.log" || fail 'PIN retry not audited'
grep -q 'decision=sign$' "$TMP/audit.log" || fail 'signature after PIN retry not audited'
pass 'wrong PIN shows remaining attempts and signs on Try Again'

# A PIN left unread when an attempt ends must not reach the next attempt.
reset_pin_state
export FAKE_PIN_ENTRIES=654321+111111,123456 FAKE_PIN_ERROR_DECISION=retry
run_pin_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 0 ]] || fail "stale PIN case did not sign ($pin_status)"
[[ $(<"$FAKE_GPG_CALL_DIR/pins-received") == $'654321\n123456' ]] \
    || fail "a stale PIN reached the next attempt: $(tr '\n' ' ' < "$FAKE_GPG_CALL_DIR/pins-received")"
pass 'each attempt reads the PIN from a new pipe'

# A yes/no question on the PIN pipe cannot be answered: fail fast, not hang.
reset_pin_state
export FAKE_GPG_ASK='GET_BOOL cardctrl.insert_card.okay'
before=$(wc -l < "$FAKE_GPG_CALL_DIR/calls")
started=$SECONDS
run_pin_case --status-fd=2 -bsau TEST
after=$(wc -l < "$FAKE_GPG_CALL_DIR/calls")
unset FAKE_GPG_ASK
[[ "$pin_status" -eq 70 && -z "$pin_output" ]] || fail "unanswerable GPG prompt status ($pin_status)"
[[ $((SECONDS - started)) -lt 10 ]] || fail 'unanswerable GPG prompt waited for a timeout'
[[ "$before" -eq "$after" ]] || fail 'unanswerable GPG prompt signed'
grep -q 'cannot answer (GET_BOOL cardctrl.insert_card.okay)' "$TMP/pin.stderr" || fail 'unanswerable prompt message'
grep -q 'decision=unanswerable-gpg-prompt$' "$TMP/audit.log" || fail 'unanswerable prompt not audited'
[[ -z $(pin_dialogs) ]] || fail 'PIN window shown for a non-PIN question'
pass 'a non-PIN GPG question fails fast instead of hanging'

# Cancel in the PIN window is the operator cancelling: nothing is signed.
reset_pin_state
export FAKE_PIN_ENTRIES=CANCEL
before=$(wc -l < "$FAKE_GPG_CALL_DIR/calls")
run_pin_case --status-fd=2 -bsau TEST
after=$(wc -l < "$FAKE_GPG_CALL_DIR/calls")
[[ "$pin_status" -eq 1 && -z "$pin_output" ]] || fail "PIN window cancel status/stdout ($pin_status)"
[[ "$before" -eq "$after" ]] || fail 'PIN window cancel signed'
grep -q 'signing cancelled by user' "$TMP/pin.stderr" || fail 'PIN window cancel message'
grep -q 'decision=cancel$' "$TMP/audit.log" || fail 'PIN window cancel not audited'
pass 'Cancel in the PIN window cancels signing'

# Wrong PIN, then Cancel in the error dialog: GPG's failure reaches Git.
reset_pin_state
export FAKE_PIN_ENTRIES=654321 FAKE_PIN_ERROR_DECISION=cancel
run_pin_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 2 && -z "$pin_output" ]] || fail "cancelled PIN retry status/stdout ($pin_status)"
[[ $(wc -l < "$FAKE_GPG_CALL_DIR/bad-pin-calls") -eq 1 ]] || fail 'cancelled PIN retry ran GPG again'
grep -q 'signing failed: Bad PIN' "$TMP/pin.stderr" || fail 'final GPG failure not forwarded to Git'
grep -q 'incorrect PIN; signing cancelled (2 PIN attempts remaining)' "$TMP/pin.stderr" || fail 'cancel message'
grep -q 'decision=bad-pin$' "$TMP/audit.log" || fail 'cancelled PIN retry not audited'
pass 'Cancel after a wrong PIN fails with the GPG error'

# A PIN too short to reach the key uses no attempt, and the dialog says so.
reset_pin_state
export FAKE_PIN_ENTRIES=1234,123456 FAKE_PIN_ERROR_DECISION=retry
run_pin_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 0 ]] || fail "uncounted PIN retry ($pin_status)"
[[ $(pin_dialogs) == $'pin-entry 3 1\npin-error 3 retry uncounted\npin-entry 3 2' ]] \
    || fail "uncounted PIN sequence: $(pin_dialogs)"
grep -lq 'rejected before reaching the key (3 PIN attempts remaining)' "$TMP/captures"/*.summary \
    || fail 'uncounted retry preview text'
pass 'a PIN that never reached the key is reported as not counted'

# Every PIN wrong: retry until the card reports 0, then say it is blocked.
reset_pin_state
export FAKE_PIN_RETRIES=2 FAKE_PIN_ENTRIES=111111,222222,333333
run_pin_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 2 && -z "$pin_output" ]] || fail "blocked PIN status/stdout ($pin_status)"
[[ $(wc -l < "$FAKE_GPG_CALL_DIR/bad-pin-calls") -eq 2 ]] || fail 'retried past the card retry counter'
[[ $(pin_dialogs) == $'pin-entry 2 1\npin-error 1 retry counted\npin-entry 1 2\npin-error 0 final counted' ]] \
    || fail "blocked PIN sequence: $(pin_dialogs)"
grep -q 'PIN is now blocked' "$TMP/pin.stderr" || fail 'blocked PIN not reported'
grep -qF 'admin, passwd, 2' "$TMP/pin.stderr" || fail 'blocked PIN message lacks the Admin PIN steps'
pass 'wrong PINs stop when the key reports its PIN blocked'
unset FAKE_GPG_PIN FAKE_PIN_ENTRIES

# Without --status-fd=2 GPG's own pinentry is used; retries still work, and
# with no readable counter a request allows two attempts in total.
reset_pin_state
unset FAKE_PIN_RETRIES
export FAKE_GPG_BAD_PINS=99
run_pin_case -bsau TEST
[[ "$pin_status" -eq 2 ]] || fail "pinentry-path PIN status ($pin_status)"
[[ $(wc -l < "$FAKE_GPG_CALL_DIR/bad-pin-calls") -eq 2 ]] || fail 'unknown-counter attempt limit'
[[ $(pin_dialogs) == $'pin-error unknown retry counted\npin-error unknown final counted' ]] \
    || fail "unknown-counter sequence: $(pin_dialogs)"
pass 'pinentry path retries a wrong PIN and limits attempts without a counter'
unset FAKE_GPG_BAD_PINS FAKE_PIN_ERROR_DECISION

# pinentry lets a too-short PIN through; the key never sees it, and the
# error dialog says no attempt was used.
reset_pin_state
export FAKE_PIN_RETRIES=3 FAKE_GPG_BAD_PINS=1 FAKE_GPG_BAD_PIN_COUNTED=uncounted
export FAKE_PIN_ERROR_DECISION=retry FAKE_GPG_STDOUT='signature-after-short-pin'
run_pin_case -bsau TEST
[[ "$pin_status" -eq 0 && "$pin_output" == 'signature-after-short-pin' ]] || fail "pinentry short PIN retry ($pin_status)"
[[ $(pin_dialogs) == 'pin-error 3 retry uncounted' ]] || fail "pinentry short PIN sequence: $(pin_dialogs)"
pass 'pinentry path reports a PIN that never reached the key'
unset FAKE_GPG_BAD_PINS FAKE_GPG_BAD_PIN_COUNTED FAKE_PIN_ERROR_DECISION FAKE_PIN_RETRIES

# pin_prompt=pinentry keeps gpg-agent's pinentry even for Git's arguments.
reset_pin_state
cp "$XDG_CONFIG_HOME/git-gpg-preview/config" "$TMP/config.saved"
printf 'pin_prompt=pinentry\n' >> "$XDG_CONFIG_HOME/git-gpg-preview/config"
export FAKE_GPG_STDOUT='signature-pinentry'
run_pin_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 0 && "$pin_output" == 'signature-pinentry' ]] || fail "pin_prompt=pinentry signing ($pin_status)"
printf '%s\0' --status-fd=2 -bsau TEST > "$TMP/expected.args"
cmp -s "$TMP/expected.args" "$FAKE_GPG_CALL_DIR/$(latest_call).args" || fail 'pin_prompt=pinentry changed GPG arguments'
printf 'pin_prompt=sometimes\n' >> "$XDG_CONFIG_HOME/git-gpg-preview/config"
run_pin_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 70 ]] || fail "invalid pin_prompt accepted ($pin_status)"
cp "$TMP/config.saved" "$XDG_CONFIG_HOME/git-gpg-preview/config"
pass 'pin_prompt=pinentry restores the pinentry path; invalid values fail closed'

# A software key keeps gpg-agent's pinentry (own retries, no PIN length rule).
reset_pin_state
export FAKE_KEY_TOKEN=+ FAKE_GPG_STDOUT='signature-software-key'
run_pin_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 0 && "$pin_output" == 'signature-software-key' ]] || fail "software key signing ($pin_status)"
printf '%s\0' --status-fd=2 -bsau TEST > "$TMP/expected.args"
cmp -s "$TMP/expected.args" "$FAKE_GPG_CALL_DIR/$(latest_call).args" || fail 'software key was switched to the PIN window'
unset FAKE_KEY_TOKEN
pass 'software signing keys keep the pinentry path'

# A listing shows whole certificates whatever the selector, so only the key GPG
# will sign with may switch to the PIN window: the exact key a trailing ! names,
# else the first certificate's newest usable signing subkey, else its primary
# key. GnuPG 2.3 and later may prefer an older card subkey; pinentry handles it.
CARD=D2760001240100000006000000010000
PRIMARY=AAAA000000000000000000000000000000000001
CARD_SUB=AAAA000000000000000000000000000000000002
SOFT_SUB=AAAA000000000000000000000000000000000003
OTHER=BBBB000000000000000000000000000000000001
OTHER_CARD=BBBB000000000000000000000000000000000002
V5_CARD=CCCC000000000000000000000000000000000000000000000000000000000002
export FAKE_SECRET_KEYS="$TMP/secret-keys" FAKE_GPG_STDOUT='signature-selected-key'
# One certificate: primary fingerprint, capabilities and field 15, then the
# fingerprint, validity, creation time and field 15 of each signing subkey.
secret_keys() {
    printf 'sec:u:255:22:%s:100::::::%s:::%s:::ed25519:::0:\nfpr:::::::::%s:\n' "${1:24:16}" "$2" "$3" "$1"
    shift 3
    while [[ "$#" -ge 4 ]]; do
        printf 'ssb:%s:255:22:%s:%s::::::s:::%s:::ed25519::\nfpr:::::::::%s:\n' "$2" "${1:24:16}" "$3" "$4" "$1"
        shift 4
    done
}
assert_key_path() {
    local label="$1" mode="$2"
    shift 2
    reset_pin_state
    run_pin_case --status-fd=2 -bsau "$@"
    [[ "$pin_status" -eq 0 && "$pin_output" == 'signature-selected-key' ]] || fail "$label: signing ($pin_status)"
    if [[ "$mode" == window ]]; then
        printf '%s\0' --pinentry-mode loopback --command-fd 3 --status-fd=2 -bsau "$@" > "$TMP/expected.args"
    else
        printf '%s\0' --status-fd=2 -bsau "$@" > "$TMP/expected.args"
    fi
    cmp -s "$TMP/expected.args" "$FAKE_GPG_CALL_DIR/$(latest_call).args" || fail "$label: expected the $mode path"
}
secret_keys "$PRIMARY" cSC + "$CARD_SUB" u 200 "$CARD" "$SOFT_SUB" u 300 + > "$FAKE_SECRET_KEYS"
assert_key_path 'newest subkey in software' pinentry TEST
assert_key_path 'older card subkey named with !' window "$CARD_SUB!"
assert_key_path 'card key ID named with !' window "0x${CARD_SUB:24}!"
secret_keys "$PRIMARY" cSC + "$CARD_SUB" u 300 "$CARD" "$SOFT_SUB" u 200 + > "$FAKE_SECRET_KEYS"
assert_key_path 'newest subkey on the card' window TEST
assert_key_path 'software subkey named with !' pinentry "$SOFT_SUB!"
assert_key_path 'software subkey named without !' window "$SOFT_SUB"
# Expired subkeys and stubs never sign; a tie goes to the first listed.
secret_keys "$PRIMARY" cSC + "$CARD_SUB" e 300 "$CARD" "$SOFT_SUB" u 200 + > "$FAKE_SECRET_KEYS"
assert_key_path 'expired card subkey' pinentry TEST
secret_keys "$PRIMARY" cSC + "$CARD_SUB" u 200 "$CARD" "$SOFT_SUB" u 300 '#' > "$FAKE_SECRET_KEYS"
assert_key_path 'newer subkey without its secret' window TEST
assert_key_path 'card short key ID named with !' window "${CARD_SUB:32}!"
secret_keys "$PRIMARY" cSC + "$CARD_SUB" u 300 "$CARD" "$SOFT_SUB" u 300 + > "$FAKE_SECRET_KEYS"
assert_key_path 'card subkey listed first at the same time' window TEST
secret_keys "$PRIMARY" cSC '' "$SOFT_SUB" u 300 '' > "$FAKE_SECRET_KEYS"
assert_key_path 'software key with an empty token field' pinentry TEST
# A subkey from the future signs only under ignore-valid-from: unclear, so pinentry.
secret_keys "$PRIMARY" cSC + "$CARD_SUB" u 200 "$CARD" "$SOFT_SUB" u 4102444800 + > "$FAKE_SECRET_KEYS"
assert_key_path 'software subkey from the future' pinentry TEST
secret_keys "$PRIMARY" cSC + "$CARD_SUB" u 4102444800 "$CARD" "$SOFT_SUB" u 200 + > "$FAKE_SECRET_KEYS"
assert_key_path 'card subkey from the future' pinentry TEST
# The primary key signs only when no subkey can; a disabled certificate still signs.
secret_keys "$PRIMARY" scSCD + "$CARD_SUB" u 300 "$CARD" > "$FAKE_SECRET_KEYS"
assert_key_path 'software primary with a card subkey' window TEST
assert_key_path 'software primary named with !' pinentry "$PRIMARY!"
# The first certificate that can sign decides.
{ secret_keys "$PRIMARY" cSC + "$SOFT_SUB" e 300 +; secret_keys "$OTHER" cSC + "$OTHER_CARD" u 200 "$CARD"; } > "$FAKE_SECRET_KEYS"
assert_key_path 'second certificate when the first cannot sign' window TEST
{ secret_keys "$PRIMARY" scSC +; secret_keys "$OTHER" cSC + "$OTHER_CARD" u 200 "$CARD"; } > "$FAKE_SECRET_KEYS"
assert_key_path 'first certificate that can sign' pinentry TEST
# A v5 key ID starts its fingerprint.
secret_keys "$PRIMARY" cSC + "$V5_CARD" u 300 "$CARD" "$SOFT_SUB" u 400 + > "$FAKE_SECRET_KEYS"
assert_key_path 'v5 card key ID named with !' window "${V5_CARD:0:16}!"
# A failed listing, more than one key, or the caller's own keyring: pinentry.
secret_keys "$PRIMARY" cSC + "$CARD_SUB" u 300 "$CARD" > "$FAKE_SECRET_KEYS"
assert_key_path 'card subkey alone' window TEST
export FAKE_SECRET_KEYS_STATUS=2
assert_key_path 'listing that failed' pinentry TEST
unset FAKE_SECRET_KEYS_STATUS
assert_key_path 'a second key named with --default-key' pinentry TEST --default-key OTHER
assert_key_path 'the caller'"'"'s own home directory' pinentry TEST --homedir "$TMP/elsewhere"
unset FAKE_SECRET_KEYS
pass 'only the key GPG will sign with decides the PIN window'

# GPG signs only the whole previewed standard input. Anything that would change
# that is refused before any preview or GPG, while option values are not.
printf 'other content\n' > "$TMP/other"
ln -s /dev/stdin "$TMP/stdin-link"
run_input_case() {
    : > "$TMP/audit.log"
    : > "$FAKE_DIALOG_LOG"
    input_calls=$(wc -l < "$FAKE_GPG_CALL_DIR/calls")
    set +e
    input_output=$("$ROOT/git-gpg-preview" "$@" < "$TMP/commit.payload" 2>"$TMP/input.stderr")
    input_status=$?
    set -e
}
assert_input_refused() {
    local label="$1"
    shift
    run_input_case "$@"
    [[ "$input_status" -eq 65 && -z "$input_output" ]] || fail "$label: not refused ($input_status)"
    [[ $(wc -l < "$FAKE_GPG_CALL_DIR/calls") -eq "$input_calls" ]] || fail "$label: GPG ran"
    ! grep -q '^start ' "$FAKE_DIALOG_LOG" || fail "$label: preview shown"
    grep -q 'other than the previewed standard input' "$TMP/input.stderr" || fail "$label: refusal message"
    grep -q 'decision=input-reject' "$TMP/audit.log" || fail "$label: refusal not audited"
}
assert_input_signed() {
    local label="$1"
    shift
    run_input_case "$@"
    [[ "$input_status" -eq 0 && "$input_output" == 'signature-input' ]] || fail "$label: not signed ($input_status)"
    grep -q '^start ' "$FAKE_DIALOG_LOG" || fail "$label: no preview"
    cmp -s "$TMP/commit.payload" "$FAKE_GPG_CALL_DIR/$(latest_call).stdin" || fail "$label: stdin changed before GPG"
}
export FAKE_GPG_STDOUT='signature-input'
# Files, however they are reached.
assert_input_refused 'file after the options' --status-fd=2 -bsau TEST "$TMP/other"
assert_input_refused 'file after --' --status-fd=2 -bsau TEST -- "$TMP/other"
assert_input_refused 'lone -' --status-fd=2 -bsau TEST -
assert_input_refused 'lone - as an unlisted option value' --status-fd=2 -bsau TEST --passphrase-fi -
assert_input_refused 'option after -, which GPG reads as a file' --status-fd=2 -bsau TEST - --armor
assert_input_refused 'file after a long option value' -bsau TEST --output "$TMP/sig" "$TMP/other"
assert_input_refused 'file after a short option value' -bsau TEST -o "$TMP/sig" "$TMP/other"
assert_input_refused 'file after -- taken as a value' -bsa -u -- "$TMP/other"
assert_input_refused 'file after an attached value' -bsauTEST "$TMP/other"
assert_input_refused 'abbreviated value option' --local TEST -bsa
assert_input_refused 'unlisted option with a separate value' --status-fd=2 -bsau TEST --keyserver-options value
grep -qF 'argument 5 would make GPG' "$TMP/input.stderr" || fail 'refusal does not locate the argument'
assert_input_refused 'unlisted option holding a secret' --passphrase hunter2 -bsau TEST
grep -qF 'argument 2 would make GPG' "$TMP/input.stderr" || fail 'refusal does not locate the secret-holding argument'
! grep -q hunter2 "$TMP/input.stderr" || fail 'refusal printed an argument value'
assert_input_refused 'arguments joined to look like two listed options' -bsau TEST '--local-user logger-fd' "$TMP/other"
# Options that read part of standard input first, leaving the rest to be signed.
assert_input_refused 'passphrase from stdin' --pinentry-mode loopback --passphrase-fd=0 -bsau TEST
assert_input_refused 'passphrase from stdin, separate value' --passphrase-fd 0 -bsau TEST
assert_input_refused 'passphrase from stdin, leading zero' --passphrase-fd=00 -bsau TEST
assert_input_refused 'passphrase from an fd that wraps to 0' --passphrase-fd=4294967296 -bsau TEST
assert_input_refused 'commands from stdin' --command-fd 0 -bsau TEST
assert_input_refused 'session key from stdin' --override-session-key-fd=0 -bsau TEST
assert_input_refused 'session key from stdin, abbreviated' --override-session-key-f=0 -bsau TEST
assert_input_refused 'file that is stdin' --passphrase-file=/dev/stdin -bsau TEST
assert_input_refused 'link to stdin' --passphrase-file="$TMP/stdin-link" -bsau TEST
assert_input_refused 'attached stdin value' -f/dev/stdin -bsau TEST
assert_input_refused 'recipients from stdin' -se -f - -u TEST
assert_input_refused 'recipients from stdin, long option' --recipient-file=- -se -u TEST
assert_input_refused 'recipients from stdin, separate value' -se -u TEST --recipient-file -
assert_input_refused 'recipients from stdin, attached' -se -F- -u TEST
assert_input_refused 'recipients from a descriptor' --enable-special-filenames -se -f '-&0' -u TEST
# Requests that once skipped both this check and the preview.
assert_input_refused 'abbreviated command with a file' --detach -u TEST "$TMP/other"
assert_input_refused '--verify as an option value' --comment --verify -bsau TEST "$TMP/other"
# Clean requests still sign, previewed, on the same standard input.
assert_input_signed 'separate and attached values' --status-fd 2 -bsa -u TEST --output "$TMP/sig" -o "$TMP/sig" -z 6 --keyserver-options=value
assert_input_signed 'value joined to its option' --status-fd=2 -bsauTEST --local-user=TEST
assert_input_signed 'output to standard output' -bsau TEST -o - --output=-
assert_input_signed 'a passphrase value' --passphrase=not-a-file -bsau TEST
assert_input_signed 'another descriptor' --pinentry-mode=loopback --passphrase-fd=5 -bsau TEST
assert_input_signed 'abbreviated command' --detach -u TEST
assert_input_signed 'hyphen-leading value' -bsa -u -odd
# A value is not a command: these verify, and go straight to GPG.
run_input_case -ubob --verify "$TMP/fake.sig" -
[[ "$input_status" -eq 0 ]] && ! grep -q '^start ' "$FAKE_DIALOG_LOG" || fail "attached value read as a signing command ($input_status)"
run_input_case -ostatus --verify "$TMP/fake.sig" -
[[ "$input_status" -eq 0 ]] && ! grep -q '^start ' "$FAKE_DIALOG_LOG" || fail "attached output read as a signing command ($input_status)"
pass 'only the whole previewed standard input can be signed'

# A listed option that took no value would let the file after it through, so
# hold the list to the GnuPG on this machine.
if real_gpg=$(command -v gpg); then
    mkdir -p "$TMP/gnupg"
    long_options=$(sed -n 's/^GPG_VALUE_OPTIONS=" \(.*\) "$/\1/p' "$ROOT/git-gpg-preview")
    short_options=$(sed -n 's/^GPG_VALUE_SHORT_OPTIONS=//p' "$ROOT/git-gpg-preview" | sed 's/./& /g')
    [[ $(printf '%s\n' $long_options | wc -l) -gt 50 && -n "$short_options" ]] || fail 'could not read the value option lists'
    for option in $long_options $short_options; do
        [[ "${#option}" -eq 1 ]] && flag="-$option" || flag="--$option"
        missing=$(LC_ALL=C GNUPGHOME="$TMP/gnupg" "$real_gpg" --batch --no-options "$flag" < /dev/null 2>&1 || true)
        [[ "$missing" == *'missing argument'* ]] || fail "$real_gpg does not require a value for $flag: $missing"
    done
    pass "every option read as taking a value requires one in $($real_gpg --version | head -n 1)"
else
    pass 'no gpg installed to check the value option list against'
fi

# Before the first preview, the touch policy of the key GPG will sign with is
# read through gpg-agent with the gpg-connect-agent beside real GPG, and only
# when that key is the card's signature key. Off and cached put two lines above
# the facts, the policy and the ykman command, and one note on stderr. Nothing
# anywhere suggests the cached policy, the preview is the only window, and
# signing goes ahead either way.
TOUCH_OFF=$'Touch policy is off: this key signs with no touch.\nTo require one, run: ykman openpgp keys set-touch sig on'
TOUCH_CACHED=$'Touch policy is cached: one touch signs for 15 seconds, so Sign is required.\nTo require a touch for every signature, run: ykman openpgp keys set-touch sig on'
CACHED_HINT='set-touch[[:space:]]+sig[[:space:]]+cached|use cached'
TOUCH_UNKNOWN='Touch policy unknown: Sign to continue'
TOUCH_CACHED_FIXED='Touch policy cached-fixed: one touch signs for 15 seconds; Sign is required.'
DETAILS_TITLE='GIT OPENPGP SIGNING REVIEW — FULL DETAILS'
# note_line NOTICE: the one stderr line that carries NOTICE.
note_line() {
    local newline=$'\n'
    printf 'git-gpg-preview: note: %s\n' "${1//$newline/ }"
}
mkdir -p "$TMP/gnupg-bin" "$TMP/linked-bin"
ln -s "$ROOT/tests/helpers/fake-gpg" "$TMP/gnupg-bin/gpg"
ln -s "$ROOT/tests/helpers/fake-gpg-connect-agent" "$TMP/gnupg-bin/gpg-connect-agent"
ln -s ../gnupg-bin/gpg "$TMP/linked-bin/gpg"
cp "$XDG_CONFIG_HOME/git-gpg-preview/config" "$TMP/config.saved"
use_real_gpg() {
    { grep -v '^real_gpg=' "$TMP/config.saved"; printf 'real_gpg=%s\n' "$1"; } > "$XDG_CONFIG_HOME/git-gpg-preview/config"
}
connect_agent_calls() {
    [[ -f "$FAKE_GPG_CALL_DIR/connect-agent-calls" ]] && wc -l < "$FAKE_GPG_CALL_DIR/connect-agent-calls" | tr -d ' ' || echo 0
}
# assert_touch_notice LABEL UIF EXPECTED-NOTICE GPG-ARGS...; an empty notice means none.
assert_touch_notice() {
    local label="$1" uif="$2" expected="$3" summary details
    export FAKE_CARD_UIF="$2"
    shift 3
    reset_pin_state
    rm -f "$FAKE_GPG_CALL_DIR/connect-agent-calls" "$FAKE_GPG_CALL_DIR/secret-key-listings"
    ls -A "$XDG_CONFIG_HOME/git-gpg-preview" > "$TMP/config-files.before"
    run_pin_case "$@"
    [[ "$pin_status" -eq 0 && "$pin_output" == 'signature-touch-policy' ]] || fail "$label: signing ($pin_status)"
    ls -A "$XDG_CONFIG_HOME/git-gpg-preview" | cmp -s - "$TMP/config-files.before" || fail "$label: a file was written beside the configuration"
    [[ $(grep -c '^start ' "$FAKE_DIALOG_LOG") -eq 1 ]] && ! grep -q '^touch-' "$FAKE_DIALOG_LOG" || fail "$label: a window other than the preview opened"
    summary=$(latest_capture)
    details=$(details_of "$summary")
    ! grep -qiE "$CACHED_HINT" "$summary" "$details" "$TMP/pin.stderr" ||
        fail "$label: suggests the cached touch policy"
    # A policy read as on or fixed keeps the touch as the gate. Off and cached
    # ask for Sign with their notice, cached-fixed with its own; a policy that
    # was not read (every case here that does not read one) with the unknown one.
    if [[ "$expected" == "$TOUCH_OFF" || "$expected" == "$TOUCH_CACHED" ]]; then
        [[ $(cat "${summary%.summary}.gate") == require-sign$'\n'"$expected" ]] || fail "$label: the preview was not asked for Sign"
    elif [[ "$uif" == %04+ ]]; then
        [[ $(cat "${summary%.summary}.gate") == require-sign$'\n'"$TOUCH_CACHED_FIXED" ]] || fail "$label: the preview was not asked for Sign"
    elif [[ "$uif" == %0[12]+ ]]; then
        [[ -z $(cat "${summary%.summary}.gate") ]] || fail "$label: the preview was asked for Sign"
    else
        [[ $(cat "${summary%.summary}.gate") == require-sign$'\n'"$TOUCH_UNKNOWN" ]] || fail "$label: the preview was not asked for Sign"
    fi
    if [[ -n "$expected" ]]; then
        [[ $(head -n 2 "$details") == "$expected" && -z $(sed -n 3p "$details") && $(sed -n 4p "$details") == "$DETAILS_TITLE" ]] ||
            fail "$label: the notice is not above the details"
        [[ $(head -n 2 "$summary") == "$expected" ]] || fail "$label: the notice is not above the facts"
        [[ -z $(head -n 2 "$summary" | awk 'length > 80') ]] || fail "$label: a notice line is wider than the facts pane"
        [[ -z $(sed -n 3p "$summary") && $(sed -n 4p "$summary") == 'Request type: commit' ]] || fail "$label: the notice displaced the facts"
        [[ $(sed -n 10p "$summary") == 'Message:' ]] || fail "$label: the notice moved the Message: line"
        [[ $(grep '^git-gpg-preview: note: ' "$TMP/pin.stderr") == "$(note_line "$expected")" ]] ||
            fail "$label: stderr does not carry exactly the notice"
    else
        [[ $(head -n 1 "$summary") == 'Request type: commit' ]] || fail "$label: a line above the facts"
        [[ $(head -n 1 "$details") == "$DETAILS_TITLE" ]] || fail "$label: a line above the details"
        ! grep -q '^git-gpg-preview: note: ' "$TMP/pin.stderr" || fail "$label: a note on stderr"
        ! grep -qF 'ykman' "$summary" "$TMP/pin.stderr" || fail "$label: unexpected touch notice"
    fi
}
use_real_gpg "$TMP/gnupg-bin/gpg"
export FAKE_SECRET_KEYS="$TMP/secret-keys" FAKE_GPG_STDOUT='signature-touch-policy' FAKE_CARD_SIG_KEY=$CARD_SUB
secret_keys "$PRIMARY" cSC + "$CARD_SUB" u 300 "$CARD" > "$FAKE_SECRET_KEYS"
assert_touch_notice 'touch policy off' '%00+' "$TOUCH_OFF" --status-fd=2 -bsau TEST
[[ $(connect_agent_calls) -eq 1 ]] || fail 'touch policy was not read once'
[[ $(wc -l < "$FAKE_GPG_CALL_DIR/secret-key-listings") -eq 1 ]] || fail 'the signing key was looked up more than once'
assert_touch_notice 'touch policy cached' '%03+' "$TOUCH_CACHED" --status-fd=2 -bsau TEST
assert_touch_notice 'touch policy off, pinentry path' '%00+' "$TOUCH_OFF" -bsau TEST
assert_touch_notice 'touch policy on' '%01+' '' --status-fd=2 -bsau TEST
assert_touch_notice 'touch policy cached-fixed' '%04+' '' --status-fd=2 -bsau TEST
assert_touch_notice 'touch policy fixed' '%02+' '' --status-fd=2 -bsau TEST
assert_touch_notice 'unknown touch policy byte' '%05+' '' --status-fd=2 -bsau TEST
assert_touch_notice 'card without a touch setting' '' '' --status-fd=2 -bsau TEST
export FAKE_CARD_SIG_KEY=$OTHER_CARD
assert_touch_notice 'another key in the card signature slot' '%00+' '' --status-fd=2 -bsau TEST
unset FAKE_CARD_SIG_KEY
assert_touch_notice 'no card in the reader' '%00+' '' --status-fd=2 -bsau TEST
export FAKE_CARD_SIG_KEY=$CARD_SUB
assert_touch_notice 'the caller'"'"'s own home directory' '%00+' '' --status-fd=2 -bsau TEST --homedir "$TMP/elsewhere"
[[ $(connect_agent_calls) -eq 0 ]] || fail 'touch policy read for the caller'"'"'s own home directory'
assert_touch_notice 'the caller'"'"'s own keyring' '%00+' '' --status-fd=2 -bsau TEST --keyring "$TMP/elsewhere.kbx"
assert_touch_notice 'a second key named with --default-key' '%00+' '' --status-fd=2 -bsau TEST --default-key OTHER
export FAKE_SECRET_KEYS_STATUS=2
assert_touch_notice 'listing that failed' '%00+' '' --status-fd=2 -bsau TEST
unset FAKE_SECRET_KEYS_STATUS
export FAKE_CONNECT_AGENT_EXIT=2
assert_touch_notice 'gpg-connect-agent that failed' '%00+' '' --status-fd=2 -bsau TEST
unset FAKE_CONNECT_AGENT_EXIT
secret_keys "$PRIMARY" cSC + "$CARD_SUB" u 200 "$CARD" "$SOFT_SUB" u 300 + > "$FAKE_SECRET_KEYS"
assert_touch_notice 'software key signs' '%00+' '' --status-fd=2 -bsau TEST
[[ $(connect_agent_calls) -eq 0 ]] || fail 'touch policy read for a software key'
secret_keys "$PRIMARY" cSC + "$CARD_SUB" u 300 "$CARD" > "$FAKE_SECRET_KEYS"
use_real_gpg "$TMP/linked-bin/gpg"
assert_touch_notice 'gpg-connect-agent beside the linked real GPG' '%00+' "$TOUCH_OFF" --status-fd=2 -bsau TEST
use_real_gpg "$ROOT/tests/helpers/fake-gpg"
assert_touch_notice 'no gpg-connect-agent beside real GPG' '%00+' '' --status-fd=2 -bsau TEST
[[ $(connect_agent_calls) -eq 0 ]] || fail 'a gpg-connect-agent not beside real GPG was used'
pass 'touch policy off or cached puts the ykman command above the facts, no other window opens, and signing goes ahead'

# The remote service keeps its own copy of the notices. What this wrapper shows
# and prints must be exactly that copy, policy by policy, so the two cannot drift.
if command -v python3 >/dev/null; then
    remote_notice() {
        python3 -c 'import importlib.util, sys
spec = importlib.util.spec_from_file_location("git_gpg_preview_remote", sys.argv[1])
remote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remote)
sys.stdout.write(remote.TOUCH_NOTICES.get(sys.argv[2], ""))' "$ROOT/remote/git_gpg_preview_remote.py" "$1"
    }
    [[ -n $(remote_notice off) && -n $(remote_notice cached) ]] || fail 'could not read the remote service notices'
    use_real_gpg "$TMP/gnupg-bin/gpg"
    for policy in 00:off 01:on 02:fixed 03:cached 04:cached-fixed; do
        assert_touch_notice "the remote service's notice for ${policy#*:}" "%${policy%%:*}+" "$(remote_notice "${policy#*:}")" \
            --status-fd=2 -bsau TEST
    done
    pass "the wrapper's notices are the remote service's, policy by policy"
else
    pass "no python3 installed to compare the remote service's notices with"
fi

# An install from before the offer was removed keeps its record, which is neither
# read nor written: a key with every dismissal used still gets the notice.
use_real_gpg "$TMP/gnupg-bin/gpg"
OLD_OFFER_RECORD="$XDG_CONFIG_HOME/git-gpg-preview/touch-offers"
printf '%s 3 %d\n' "$CARD_SUB" "$(date +%s)" > "$OLD_OFFER_RECORD"
cp "$OLD_OFFER_RECORD" "$TMP/touch-offers.before"
touch -t 202001010000 "$OLD_OFFER_RECORD" "$TMP/touch-offers.before"
assert_touch_notice 'an old record, key set to off' '%00+' "$TOUCH_OFF" --status-fd=2 -bsau TEST
assert_touch_notice 'an old record, key set to cached' '%03+' "$TOUCH_CACHED" --status-fd=2 -bsau TEST
cmp -s "$OLD_OFFER_RECORD" "$TMP/touch-offers.before" || fail 'the old offer record was changed'
[[ ! "$OLD_OFFER_RECORD" -nt "$TMP/touch-offers.before" ]] || fail 'the old offer record was rewritten'
rm -f "$OLD_OFFER_RECORD"
pass 'an old offer record is neither read nor written'

# Git shows the stderr copy only when signing fails, so check it there.
use_real_gpg "$TMP/gnupg-bin/gpg"
reset_pin_state
export FAKE_CARD_UIF=%00+ FAKE_GPG_EXIT=42 FAKE_GPG_STDERR=$'gpg: signing failed: Card error\n'
run_pin_case --status-fd=2 -bsau TEST
unset FAKE_GPG_EXIT FAKE_GPG_STDERR
[[ "$pin_status" -eq 42 ]] || fail "the touch notice changed GPG's failure status ($pin_status)"
grep -qxF "$(note_line "$TOUCH_OFF")" "$TMP/pin.stderr" || fail 'a failed signature lost the touch notice'
grep -qxF 'gpg: signing failed: Card error' "$TMP/pin.stderr" || fail "a failed signature lost GPG's error"
pass 'a failed signature reports the touch notice next to the GPG error'

# The notice goes into the summary and the details together or into neither,
# and both stay 0600 like the rest of the request, whatever the umask. A failure
# is reported, leaves both files as they were and no temporary file behind, and
# signing goes ahead. Permissions are restored before anything is checked.
PREPEND_FUNCTION=$(awk '/^error\(\) \{/,/^}/; /^prepend_touch_notice\(\) \{/,/^}/' "$ROOT/git-gpg-preview")
NOTICE_FAILED='git-gpg-preview: note: could not add the touch policy notice to the preview or its details'
# prepend_notice FUNCTION: runs it on fresh 0600 files in $TMP/notice, umask 022.
prepend_notice() {
    rm -rf "$TMP/notice"
    mkdir -p "$TMP/notice"
    printf 'facts\n' > "$TMP/notice/summary"
    printf 'report\n' > "$TMP/notice/details"
    chmod 600 "$TMP/notice/summary" "$TMP/notice/details"
    PROGRAM_NAME=git-gpg-preview bash -c 'umask 022'$'\n'"$1"$'\n''prepend_touch_notice "$@"' \
        bash "$TOUCH_OFF" "$TMP/notice/summary" "$TMP/notice/details" 2> "$TMP/prepend.stderr"
}
notice_files() {
    printf '%s|%s|%s|%s|%s' "$(cat "$TMP/notice/summary")" "$(cat "$TMP/notice/details")" \
        "$(stat -f '%Lp' "$TMP/notice/summary")" "$(stat -f '%Lp' "$TMP/notice/details")" "$(ls -A "$TMP/notice" | tr '\n' ' ')"
}
UNCHANGED='facts|report|600|600|details summary '
prepend_notice "$PREPEND_FUNCTION" || fail 'adding the notice failed'
[[ $(notice_files) == "$TOUCH_OFF"$'\n\nfacts|'"$TOUCH_OFF"$'\n\nreport|600|600|details summary ' ]] ||
    fail "the notice was not put above both files, 0600, alone: $(notice_files)"
[[ ! -s "$TMP/prepend.stderr" ]] || fail "adding the notice reported a failure: $(cat "$TMP/prepend.stderr")"
# An unreadable details file: the summary would have worked, but must not change.
prepend_status=0
PREPEND_UNREADABLE=$(printf '%s' "$PREPEND_FUNCTION" | sed 's/^prepend_touch_notice() {$/prepend_touch_notice() { chmod 000 "$3"/')
prepend_notice "$PREPEND_UNREADABLE" || prepend_status=$?
chmod 600 "$TMP/notice/details"
[[ "$prepend_status" -eq 0 && $(cat "$TMP/prepend.stderr") == "$NOTICE_FAILED" && $(notice_files) == "$UNCHANGED" ]] ||
    fail "an unreadable details file: $prepend_status, $(cat "$TMP/prepend.stderr"), $(notice_files)"
# A directory that takes no new file.
prepend_status=0
PREPEND_LOCKED=$(printf '%s' "$PREPEND_FUNCTION" | sed 's/^prepend_touch_notice() {$/prepend_touch_notice() { chmod 500 "${2%\/*}"/')
prepend_notice "$PREPEND_LOCKED" || prepend_status=$?
chmod 700 "$TMP/notice"
[[ "$prepend_status" -eq 0 && $(cat "$TMP/prepend.stderr") == "$NOTICE_FAILED" && $(notice_files) == "$UNCHANGED" ]] ||
    fail "an unwritable directory: $prepend_status, $(cat "$TMP/prepend.stderr"), $(notice_files)"
# The details cannot be replaced after the summary was: the summary goes back.
prepend_status=0
prepend_notice "$(printf '%s' "$PREPEND_FUNCTION" | sed 's|/bin/mv -f "\$new_details" "\$details"|false|')" || prepend_status=$?
[[ "$prepend_status" -eq 0 && $(cat "$TMP/prepend.stderr") == "$NOTICE_FAILED" && $(notice_files) == "$UNCHANGED" ]] ||
    fail "details that cannot be replaced: $prepend_status, $(cat "$TMP/prepend.stderr"), $(notice_files)"
# ...and if even that fails, stderr says which file has the notice.
prepend_status=0
prepend_notice "$(printf '%s' "$PREPEND_FUNCTION" | sed 's|/bin/mv -f "\$new_details" "\$details"|false|; s|/bin/mv -f "\$old_summary" "\$summary"|false|')" ||
    prepend_status=$?
[[ "$prepend_status" -eq 0 && $(notice_files) == "$TOUCH_OFF"$'\n\nfacts|report|600|600|details summary ' ]] ||
    fail "a summary that cannot go back: $prepend_status, $(notice_files)"
[[ $(cat "$TMP/prepend.stderr") == 'git-gpg-preview: note: the touch policy notice is in the preview but not in its details' ]] ||
    fail "a summary that cannot go back was not reported: $(cat "$TMP/prepend.stderr")"
sed '/^prepend_touch_notice() {/,/^}/ s|/bin/cat "\$details"|/bin/cat "$details.missing"|' "$ROOT/git-gpg-preview" > "$TMP/notice-failing-wrapper"
chmod 700 "$TMP/notice-failing-wrapper"
! cmp -s "$ROOT/git-gpg-preview" "$TMP/notice-failing-wrapper" || fail 'could not make the notice fail'
reset_pin_state
export FAKE_CARD_UIF=%00+
set +e
pin_output=$("$TMP/notice-failing-wrapper" --status-fd=2 -bsau TEST < "$TMP/commit.payload" 2>"$TMP/pin.stderr")
pin_status=$?
set -e
[[ "$pin_status" -eq 0 && "$pin_output" == 'signature-touch-policy' ]] || fail "a failed notice stopped signing ($pin_status)"
grep -qxF "$NOTICE_FAILED" "$TMP/pin.stderr" || fail 'a failed notice was not reported'
grep -qxF "$(note_line "$TOUCH_OFF")" "$TMP/pin.stderr" || fail 'a failed notice lost the stderr note'
[[ $(head -n 1 "$(latest_capture)") == 'Request type: commit' && $(head -n 1 "$(details_of "$(latest_capture)")") == "$DETAILS_TITLE" ]] ||
    fail 'a failed notice changed the preview'
pass 'the notice goes into both files or neither, 0600, and a failure is reported and cleaned up'

# Touch policy off: the key signs without a touch, so GPG waits for Sign in the
# preview, within SIGN_CLICK_SECONDS. The fake dialog answers after
# FAKE_DIALOG_DELAY and, for sign, makes the "touch" only then; fake GPG records
# whether that touch already existed when it started ("before" only when GPG
# waited for the answer), and the dialog log shows the PIN window after it.
gate_case() {
    reset_pin_state
    rm -f "$FAKE_GPG_CALL_DIR/touch-at-start"
    set +e
    rm -f "$TMP/decision-state"
    pin_output=$("${GATE_WRAPPER:-$ROOT/git-gpg-preview}" "$@" < "${GATE_PAYLOAD:-$TMP/commit.payload}" 2>"$TMP/pin.stderr")
    pin_status=$?
    set -e
}
touch_at_start() {
    cat "$FAKE_GPG_CALL_DIR/touch-at-start" 2>/dev/null || true
}
dialog_order() {
    grep -E '^(start|end|pin-entry) ' "$FAKE_DIALOG_LOG" | cut -d' ' -f1 | tr '\n' ' '
}
GATE_REFUSED='git-gpg-preview: not signed: touch policy is off and Sign was not clicked'
use_real_gpg "$TMP/gnupg-bin/gpg"
export FAKE_DIALOG_DELAY=1 FAKE_PIN_RETRIES=3 FAKE_GPG_PIN=123456 FAKE_PIN_ENTRIES=123456
for uif in %00+ %05+ %01+ %02+ %03+ %04+; do
    export FAKE_CARD_UIF=$uif
    gate_case --status-fd=2 -bsau TEST
    [[ "$pin_status" -eq 0 && "$pin_output" == 'signature-touch-policy' ]] || fail "touch $uif: not signed ($pin_status)"
    if [[ "$uif" != %0[12]+ ]]; then
        [[ $(touch_at_start) == before ]] || fail "touch $uif: GPG started before Sign ($(touch_at_start))"
        [[ $(dialog_order) == 'start end pin-entry ' ]] || fail "touch $uif: the PIN window did not follow Sign: $(dialog_order)"
    else
        [[ $(touch_at_start) == after ]] || fail "touch $uif: GPG waited for a click ($(touch_at_start))"
    fi
done
export FAKE_CARD_UIF=%00+
gate_case -bsau TEST
[[ "$pin_status" -eq 0 && $(touch_at_start) == before ]] || fail "touch off, pinentry path: GPG did not wait for Sign ($pin_status, $(touch_at_start))"
# Cancel, a window closed without an answer, and no answer in time sign nothing:
# GPG never starts.
export FAKE_DIALOG_DECISION=cancel
gate_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 1 && -z "$pin_output" && -z $(touch_at_start) ]] || fail "touch off, Cancel: $pin_status, GPG $(touch_at_start)"
grep -qxF "$GATE_REFUSED" "$TMP/pin.stderr" && grep -qxF 'git-gpg-preview: signing cancelled by user' "$TMP/pin.stderr" ||
    fail "touch off, Cancel: $(cat "$TMP/pin.stderr")"
export FAKE_DIALOG_DECISION=garbage
gate_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 70 && -z "$pin_output" && -z $(touch_at_start) ]] || fail "touch off, no answer: $pin_status, GPG $(touch_at_start)"
grep -qxF "$GATE_REFUSED" "$TMP/pin.stderr" || fail "touch off, no answer: $(cat "$TMP/pin.stderr")"
sed 's/^SIGN_CLICK_SECONDS=.*/SIGN_CLICK_SECONDS=1/' "$ROOT/git-gpg-preview" > "$TMP/fast-sign-wrapper"
chmod 700 "$TMP/fast-sign-wrapper"
! cmp -s "$ROOT/git-gpg-preview" "$TMP/fast-sign-wrapper" || fail 'could not shorten SIGN_CLICK_SECONDS'
export FAKE_DIALOG_DECISION=sign FAKE_DIALOG_DELAY=30
gate_started=$SECONDS
GATE_WRAPPER="$TMP/fast-sign-wrapper" gate_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 70 && -z "$pin_output" && -z $(touch_at_start) && $((SECONDS - gate_started)) -lt 10 ]] ||
    fail "touch off, no click in time: $pin_status after $((SECONDS - gate_started))s, GPG $(touch_at_start)"
grep -qxF "$GATE_REFUSED" "$TMP/pin.stderr" || fail "touch off, no click in time: $(cat "$TMP/pin.stderr")"
# A policy that cannot be read is refused the same way, and says so.
export FAKE_CARD_UIF=%05+ FAKE_DIALOG_DECISION=cancel FAKE_DIALOG_DELAY=0
gate_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 1 && -z $(touch_at_start) ]] &&
    grep -qxF 'git-gpg-preview: not signed: touch policy is unknown and Sign was not clicked' "$TMP/pin.stderr" ||
    fail "touch unknown, Cancel: $pin_status, GPG $(touch_at_start), $(cat "$TMP/pin.stderr")"
export FAKE_DIALOG_DECISION=sign FAKE_DIALOG_DELAY=30
GATE_WRAPPER="$TMP/fast-sign-wrapper" gate_case -bsau TEST --homedir "$TMP/elsewhere"
[[ "$pin_status" -eq 70 && -z $(touch_at_start) ]] &&
    grep -qxF 'git-gpg-preview: not signed: touch policy is unknown and Sign was not clicked' "$TMP/pin.stderr" ||
    fail "touch not read, no click in time: $pin_status, GPG $(touch_at_start)"
export FAKE_CARD_UIF=%00+
# The gate does not depend on the notice: with its files unwritable, Sign is
# still needed, and Cancel still signs nothing.
export FAKE_DIALOG_DELAY=1
GATE_WRAPPER="$TMP/notice-failing-wrapper" gate_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 0 && $(touch_at_start) == before ]] || fail "touch off, notice not written: GPG did not wait for Sign ($pin_status, $(touch_at_start))"
grep -qxF "$NOTICE_FAILED" "$TMP/pin.stderr" || fail 'touch off, notice not written: not reported'
export FAKE_DIALOG_DECISION=cancel
GATE_WRAPPER="$TMP/notice-failing-wrapper" gate_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 1 && -z $(touch_at_start) ]] && grep -qxF "$GATE_REFUSED" "$TMP/pin.stderr" ||
    fail "touch off, notice not written, Cancel: $pin_status, GPG $(touch_at_start)"
export FAKE_DIALOG_DECISION=sign FAKE_DIALOG_DELAY=0
pass 'touch off or unknown: GPG starts only after Sign, then the PIN window; Cancel, no answer or no click in time sign nothing'

# Each PIN attempt needs a Sign of its own: after a wrong PIN, a second preview
# that hangs, is cancelled or closes without an answer signs nothing, and GPG
# ran once. Two Signs sign, with two GPG calls.
export FAKE_DIALOG_DECISION_STATE="$TMP/decision-state" FAKE_PIN_ENTRIES=654321,123456 FAKE_PIN_ERROR_DECISION=retry
for answers in sign,hang:70 sign,cancel:1 sign,:70 sign,sign:0; do
    export FAKE_DIALOG_DECISIONS=${answers%:*}
    GATE_WRAPPER="$TMP/fast-sign-wrapper" gate_case --status-fd=2 -bsau TEST
    if [[ "${answers#*:}" -eq 0 ]]; then
        [[ "$pin_status" -eq 0 && "$pin_output" == 'signature-touch-policy' && $(touch_at_start | grep -c .) -eq 2 ]] ||
            fail "touch off, PIN retry with Sign twice: $pin_status, GPG $(touch_at_start | tr '\n' ' ')"
    else
        [[ "$pin_status" -eq "${answers#*:}" && -z "$pin_output" && $(touch_at_start | grep -c .) -eq 1 ]] ||
            fail "touch off, PIN retry answered ${FAKE_DIALOG_DECISIONS#sign,}: $pin_status, GPG $(touch_at_start | tr '\n' ' ')"
        grep -qxF "$GATE_REFUSED" "$TMP/pin.stderr" || fail "touch off, PIN retry answered ${FAKE_DIALOG_DECISIONS#sign,}: $(cat "$TMP/pin.stderr")"
    fi
done
unset FAKE_DIALOG_DECISIONS FAKE_DIALOG_DECISION_STATE FAKE_PIN_ERROR_DECISION
export FAKE_PIN_ENTRIES=123456
# Only the exact bytes "sign" are a Sign: not with a space, another case, twice,
# a trailing newline or NUL, or after the rejection marker. GPG never runs. The
# same rule holds for cancel and spam: ' cancel' or 'cancel\0' is no answer the
# preview gives, refused as Sign not clicked, as the service refuses it.
for answer in 'raw: sign' 'raw:Sign' 'raw:signsign' 'raw:sign\n' 'raw:sign\0' marker-sign \
              'raw: cancel' 'raw:cancel\0' 'raw:spam\n'; do
    export FAKE_DIALOG_DECISION=$answer
    gate_case --status-fd=2 -bsau TEST
    [[ "$pin_status" -eq 70 && -z "$pin_output" && -z $(touch_at_start) ]] && grep -qxF "$GATE_REFUSED" "$TMP/pin.stderr" ||
        fail "touch off, answer '$answer': $pin_status, GPG $(touch_at_start)"
    [[ $(sed -n 's/.*decision=\([^ ]*\).*/\1/p' "$TMP/audit.log") == sign-not-clicked ]] ||
        fail "touch off, answer '$answer': audited as $(sed -n 's/.*decision=\([^ ]*\).*/\1/p' "$TMP/audit.log")"
done
[[ ! -e "$XDG_CONFIG_HOME/git-gpg-preview/spam-subjects" ]] || fail "touch off, answer 'spam\\n': the subject was saved"
export FAKE_DIALOG_DECISION=raw:sign
gate_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 0 && $(touch_at_start) == before ]] || fail "touch off, an exact sign: $pin_status, GPG $(touch_at_start)"
# Mark as Spam is no Sign either: the subject is saved, and GPG never runs.
awk '{ print } $0 == "" { exit }' "$TMP/initial.payload" > "$TMP/gate-spam.payload"
printf 'Touch off spam subject\n' >> "$TMP/gate-spam.payload"
export FAKE_DIALOG_DECISION=spam
GATE_PAYLOAD="$TMP/gate-spam.payload" gate_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 1 && -z "$pin_output" && -z $(touch_at_start) ]] && grep -qxF "$GATE_REFUSED" "$TMP/pin.stderr" ||
    fail "touch off, Mark as Spam: $pin_status, GPG $(touch_at_start)"
grep -qxF 'touch off spam subject' "$XDG_CONFIG_HOME/git-gpg-preview/spam-subjects" || fail 'touch off, Mark as Spam: the subject was not saved'
grep -qF 'decision=spam-mark' "$TMP/audit.log" || fail 'touch off, Mark as Spam: not audited'
rm -f "$XDG_CONFIG_HOME/git-gpg-preview/spam-subjects"
export FAKE_DIALOG_DECISION=sign
unset FAKE_PIN_RETRIES FAKE_GPG_PIN FAKE_PIN_ENTRIES
pass 'touch off: each PIN attempt needs its own Sign, only an exact "sign" counts, and Mark as Spam saves the subject without GPG'

# A Sign inside SIGN_CLICK_SECONDS counts, and one after it does not. After
# Sign the preview is closed, so a key that never confirms is stopped after
# SIGN_GPG_SECONDS: nothing is signed, and the request ends.
sed 's/^SIGN_CLICK_SECONDS=.*/SIGN_CLICK_SECONDS=2/; s/^SIGN_GPG_SECONDS=.*/SIGN_GPG_SECONDS=1/' "$ROOT/git-gpg-preview" > "$TMP/short-wrapper"
chmod 700 "$TMP/short-wrapper"
[[ $(grep -c '^SIGN_\(CLICK\|GPG\)_SECONDS=[12]$' "$TMP/short-wrapper") -eq 2 ]] || fail 'could not shorten the Sign deadlines'
export FAKE_CARD_UIF=%00+ FAKE_DIALOG_DECISION=sign
for case in 1.4:0 2.8:70; do
    export FAKE_DIALOG_DELAY=${case%:*}
    GATE_WRAPPER="$TMP/short-wrapper" gate_case --status-fd=2 -bsau TEST
    [[ "$pin_status" -eq "${case#*:}" ]] || fail "touch off, Sign after ${FAKE_DIALOG_DELAY}s of 2: $pin_status"
done
export FAKE_DIALOG_DECISION=sign-no-touch FAKE_DIALOG_DELAY=0
gate_started=$SECONDS
GATE_WRAPPER="$TMP/short-wrapper" gate_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 70 && -z "$pin_output" && -n $(touch_at_start) && $((SECONDS - gate_started)) -lt 6 ]] ||
    fail "touch off, no touch after Sign: $pin_status after $((SECONDS - gate_started))s"
grep -qxF 'git-gpg-preview: not signed: no touch or PIN before the deadline' "$TMP/pin.stderr" || fail "no touch after Sign: $(cat "$TMP/pin.stderr")"
grep -qF 'decision=gpg-timeout' "$TMP/audit.log" || fail 'no touch after Sign: not audited'
# The card operation the stopped GPG left behind ends with it, before the next
# request: that request's touch signs that request, not the stale one.
export FAKE_CARD_QUEUE="$TMP/card-queue"
: > "$FAKE_CARD_QUEUE"
GATE_WRAPPER="$TMP/short-wrapper" gate_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 70 ]] || fail "a stopped signature: $pin_status"
grep -qxF 'SCD KILLSCD /bye' "$FAKE_GPG_CALL_DIR/connect-agent-calls" || fail 'the stopped signature was left pending at the card'
export FAKE_DIALOG_DECISION=sign
GATE_PAYLOAD="$TMP/initial.payload" gate_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 0 && "$pin_output" == "signed:$(shasum -a 256 "$TMP/initial.payload" | awk '{print $1}')" ]] ||
    fail "the next touch went to the stopped signature: $pin_status, $pin_output"
# So does a Cancel, Mark as Spam or preview closed without an answer while GPG
# waits at the card (touch on, so GPG starts with the preview). Spam comes
# last, since it blocks the subject that the others sign.
export FAKE_CARD_UIF=%01+
for answer in cancel:1 garbage:70 spam:1; do
    : > "$FAKE_CARD_QUEUE"
    : > "$FAKE_GPG_CALL_DIR/connect-agent-calls"
    export FAKE_DIALOG_DECISION=${answer%:*} FAKE_DIALOG_DELAY=0.5
    gate_case --status-fd=2 -bsau TEST
    [[ "$pin_status" -eq "${answer#*:}" && -z "$pin_output" ]] || fail "touch on, ${answer%:*} while the card waits: $pin_status"
    grep -qxF 'SCD KILLSCD /bye' "$FAKE_GPG_CALL_DIR/connect-agent-calls" ||
        fail "touch on, ${answer%:*}: the stopped signature was left pending at the card"
    export FAKE_DIALOG_DECISION=sign FAKE_DIALOG_DELAY=0
    GATE_PAYLOAD="$TMP/initial.payload" gate_case --status-fd=2 -bsau TEST
    [[ "$pin_status" -eq 0 && "$pin_output" == "signed:$(shasum -a 256 "$TMP/initial.payload" | awk '{print $1}')" ]] ||
        fail "touch on, ${answer%:*}: the next touch went to the stopped signature: $pin_status, $pin_output"
done
rm -f "$XDG_CONFIG_HOME/git-gpg-preview/spam-subjects"
# So does a Cancel in the PIN window, and a question it cannot answer.
export FAKE_DIALOG_DECISION=sign-no-touch FAKE_PIN_RETRIES=3 FAKE_GPG_PIN=123456
for pin_case in pin-cancel:1 pin-close:70 ask:70; do
    : > "$FAKE_CARD_QUEUE"
    : > "$FAKE_GPG_CALL_DIR/connect-agent-calls"
    case "${pin_case%:*}" in
        ask) export FAKE_GPG_ASK='GET_BOOL cardctrl.insert_card.okay' ;;
        pin-close) export FAKE_PIN_ENTRIES=CLOSE ;;
        *) export FAKE_PIN_ENTRIES=CANCEL ;;
    esac
    gate_case --status-fd=2 -bsau TEST
    unset FAKE_GPG_ASK FAKE_PIN_ENTRIES
    [[ "$pin_status" -eq "${pin_case#*:}" && -z "$pin_output" && -n $(touch_at_start) ]] ||
        fail "${pin_case%:*} after Sign: $pin_status, GPG $(touch_at_start)"
    grep -qxF 'SCD KILLSCD /bye' "$FAKE_GPG_CALL_DIR/connect-agent-calls" ||
        fail "${pin_case%:*} after Sign: the stopped signature was left pending at the card"
    [[ "${pin_case%:*}" != pin-close ]] || grep -qxF 'git-gpg-preview: PIN window closed without an answer; refusing to sign' "$TMP/pin.stderr" ||
        fail "the PIN window closed without an answer: $(cat "$TMP/pin.stderr")"
done
unset FAKE_PIN_RETRIES FAKE_GPG_PIN
export FAKE_CARD_UIF=%00+
unset FAKE_CARD_QUEUE
# A request with its own GnuPG home has its card operation cancelled there,
# not in the default home's agent, by GPG's rule: the last --homedir wins, under
# any name GPG takes for it. An --options file cannot change the home (GPG
# ignores homedir there), so its line naming another one does not count.
export FAKE_DIALOG_DECISION=sign-no-touch
printf 'homedir %s\n' "$TMP/not-this-one" > "$TMP/homedir-options"
for homedir_case in plain equals home hom last options options-only; do
    case "$homedir_case" in
        plain) homedir_args=(--homedir "$TMP/elsewhere") ;;
        equals) homedir_args=(--homedir="$TMP/elsewhere") ;;
        home) homedir_args=(--home="$TMP/elsewhere") ;;
        hom) homedir_args=(--hom="$TMP/elsewhere") ;;
        last) homedir_args=(--homedir "$TMP/not-this-one" --homedir="$TMP/elsewhere") ;;
        options) homedir_args=(--homedir "$TMP/elsewhere" --options "$TMP/homedir-options") ;;
        options-only) homedir_args=(--options "$TMP/homedir-options") ;;
    esac
    homedir_cancel="--homedir $TMP/elsewhere SCD KILLSCD /bye"
    [[ "$homedir_case" != options-only ]] || homedir_cancel='SCD KILLSCD /bye'
    : > "$FAKE_GPG_CALL_DIR/connect-agent-calls"
    GATE_WRAPPER="$TMP/short-wrapper" gate_case --status-fd=2 -bsau TEST "${homedir_args[@]}"
    [[ "$pin_status" -eq 70 && -n $(touch_at_start) ]] || fail "a stopped signature, $homedir_case home: $pin_status"
    [[ $(cat "$FAKE_GPG_CALL_DIR/connect-agent-calls") == "$homedir_cancel" ]] ||
        fail "a stopped signature, $homedir_case home, was cancelled elsewhere: $(cat "$FAKE_GPG_CALL_DIR/connect-agent-calls")"
done
# The wrapper looks up no key of its own for such a request: --home= names its
# own home as --homedir does, so the policy goes unread and Sign is needed.
grep -qxF 'git-gpg-preview: not signed: no touch or PIN before the deadline' "$TMP/pin.stderr" ||
    fail "a stopped signature with its own home: $(cat "$TMP/pin.stderr")"
# A certificate with no signing key on a card leaves nothing there: stopping
# its GPG cancels nothing, which would drop the PIN scdaemon holds and disturb
# its other users. One with a card signing key gets the cancel even when its
# newer software key is the pick, since GnuPG 2.3 and later may sign on the card.
cp "$FAKE_SECRET_KEYS" "$TMP/secret-keys.card"
for certificate in software-only:0 card-and-software:1; do
    if [[ "${certificate%:*}" == software-only ]]; then
        secret_keys "$PRIMARY" cSC '' "$SOFT_SUB" u 300 '' > "$FAKE_SECRET_KEYS"
    else
        secret_keys "$PRIMARY" cSC + "$CARD_SUB" u 200 "$CARD" "$SOFT_SUB" u 300 + > "$FAKE_SECRET_KEYS"
    fi
    : > "$FAKE_GPG_CALL_DIR/connect-agent-calls"
    GATE_WRAPPER="$TMP/short-wrapper" gate_case --status-fd=2 -bsau TEST
    [[ "$pin_status" -eq 70 && -n $(touch_at_start) ]] || fail "a stopped signature, ${certificate%:*} certificate: $pin_status"
    [[ $(grep -c '^SCD KILLSCD /bye$' "$FAKE_GPG_CALL_DIR/connect-agent-calls") -eq "${certificate#*:}" ]] ||
        fail "a stopped signature, ${certificate%:*} certificate: $(cat "$FAKE_GPG_CALL_DIR/connect-agent-calls")"
done
cp "$TMP/secret-keys.card" "$FAKE_SECRET_KEYS"
# Nor does a GPG that finished after Cancel was read but before it was stopped:
# here GPG takes 0.4s, and this copy of the wrapper takes a second over the
# Cancel. It signed, so nothing waits at the card.
/usr/bin/awk '{ print } /^handle_operator_rejection\(\) \{$/ { print "    /bin/sleep 1" }' "$ROOT/git-gpg-preview" > "$TMP/slow-cancel-wrapper"
chmod 700 "$TMP/slow-cancel-wrapper"
[[ $(grep -c '^    /bin/sleep 1$' "$TMP/slow-cancel-wrapper") -eq 1 ]] || fail 'could not slow the Cancel down'
export FAKE_CARD_UIF=%01+ FAKE_DIALOG_DECISION=raw:cancel FAKE_GPG_SLOW=0.4
: > "$FAKE_GPG_CALL_DIR/connect-agent-calls"
finished_before=$(wc -l < "$FAKE_GPG_CALL_DIR/calls")
GATE_WRAPPER="$TMP/slow-cancel-wrapper" gate_case --status-fd=2 -bsau TEST
unset FAKE_GPG_SLOW
[[ "$pin_status" -eq 1 && -z "$pin_output" && $(wc -l < "$FAKE_GPG_CALL_DIR/calls") -gt "$finished_before" ]] ||
    fail "Cancel read before GPG finished: $pin_status, GPG finished: $(($(wc -l < "$FAKE_GPG_CALL_DIR/calls") > finished_before))"
! grep -q KILLSCD "$FAKE_GPG_CALL_DIR/connect-agent-calls" || fail 'a GPG that had finished before it was stopped stopped scdaemon'
export FAKE_CARD_UIF=%00+
# A GPG_PID or PIN_CHANNEL the caller exports is not the wrapper's: an early
# exit (here Cancel, before GPG starts) stops no such process and sends no
# KILLSCD, and the PIN path deletes no such file.
sleep 30 &
inherited_pid=$!
: > "$TMP/inherited-pin-channel"
: > "$FAKE_GPG_CALL_DIR/connect-agent-calls"
export FAKE_DIALOG_DECISION=cancel
GPG_PID=$inherited_pid PIN_CHANNEL="$TMP/inherited-pin-channel" gate_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 1 && -z $(touch_at_start) ]] || fail "Cancel with an inherited GPG_PID: $pin_status, GPG $(touch_at_start)"
kill -0 "$inherited_pid" 2>/dev/null || fail 'an inherited GPG_PID was stopped'
! grep -q KILLSCD "$FAKE_GPG_CALL_DIR/connect-agent-calls" || fail 'an inherited GPG_PID stopped scdaemon'
[[ -e "$TMP/inherited-pin-channel" ]] || fail 'an inherited PIN_CHANNEL was deleted'
kill "$inherited_pid"
wait "$inherited_pid" 2>/dev/null || true
# The policy is read only from a status word of 90 00 (done): a reply with a
# valid policy byte but another one, such as 6A 82, reads as unknown and asks
# for Sign. So does an abbreviation GPG takes for --homedir or --keyring: the
# request names its own files, whose card the wrapper does not read.
export FAKE_CARD_UIF=%01+
for unread in apdu-sw homed keyr no-default-k opt; do
    unread_arg=""
    case "$unread" in
        apdu-sw) export FAKE_CARD_APDU_SW='6A 82' ;;
        homed) unread_arg=--homed="$TMP/elsewhere" ;;
        keyr) unread_arg=--keyr="$TMP/elsewhere/pubring.kbx" ;;
        no-default-k) unread_arg=--no-default-k ;;
        opt) unread_arg=--opt="$TMP/homedir-options" ;;
    esac
    if [[ -z "$unread_arg" ]]; then
        gate_case --status-fd=2 -bsau TEST
    else
        gate_case --status-fd=2 -bsau TEST "$unread_arg"
    fi
    unset FAKE_CARD_APDU_SW
    unread_gate=$(latest_capture)
    unread_gate=$(cat "${unread_gate%.summary}.gate")
    [[ "$pin_status" -eq 1 && "$unread_gate" == "require-sign"$'\n'"$TOUCH_UNKNOWN" ]] ||
        fail "touch on, $unread: the policy was read ($pin_status, preview asked: $unread_gate)"
done
export FAKE_CARD_UIF=%00+
# A preview still open at the deadline is stopped, and a Sign it wrote before
# then does not count: GPG never starts.
export FAKE_DIALOG_DECISION=early-sign
gate_started=$SECONDS
GATE_WRAPPER="$TMP/short-wrapper" gate_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 70 && -z "$pin_output" && -z $(touch_at_start) && $((SECONDS - gate_started)) -lt 6 ]] ||
    fail "touch off, a Sign from a preview still open at the deadline: $pin_status, GPG $(touch_at_start)"
grep -qxF "$GATE_REFUSED" "$TMP/pin.stderr" && grep -qF 'decision=sign-not-clicked' "$TMP/audit.log" ||
    fail "touch off, a preview still open at the deadline: $(cat "$TMP/pin.stderr")"
# After Sign the preview has closed, so a window says the key still waits, with
# Cancel, while GPG runs: a touch signs and closes it; Cancel stops GPG and
# cancels what it left at the card. A preview the touch gates needs none.
export FAKE_DIALOG_DECISION=sign-no-touch FAKE_WAITING_DELAY=0.3
for answer in touch:0 cancel:1; do
    : > "$FAKE_GPG_CALL_DIR/connect-agent-calls"
    export FAKE_WAITING_DECISION=${answer%:*}
    gate_case --status-fd=2 -bsau TEST
    [[ "$pin_status" -eq "${answer#*:}" && $(touch_at_start) == after ]] ||
        fail "touch off, ${answer%:*} in the window after Sign: $pin_status, GPG $(touch_at_start)"
    waiting_pid=$(sed -n 's/^waiting //p' "$FAKE_DIALOG_LOG")
    [[ $(grep -c '^waiting ' "$FAKE_DIALOG_LOG") -eq 1 ]] && ! kill -0 "$waiting_pid" 2>/dev/null ||
        fail "touch off, ${answer%:*}: no window after Sign, or it outlived the request"
    [[ "${answer%:*}" == cancel || -n "$pin_output" ]] || fail 'touch off, a touch in the window after Sign: no signature'
done
[[ -z "$pin_output" ]] && grep -qxF 'git-gpg-preview: signing cancelled by user' "$TMP/pin.stderr" ||
    fail "touch off, Cancel after Sign: $(cat "$TMP/pin.stderr")"
grep -qxF 'SCD KILLSCD /bye' "$FAKE_GPG_CALL_DIR/connect-agent-calls" || fail 'Cancel after Sign left the signature pending at the card'
grep -qF 'decision=cancel' "$TMP/audit.log" || fail 'Cancel after Sign: not audited'
export FAKE_CARD_UIF=%01+ FAKE_DIALOG_DECISION=sign
gate_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 0 ]] && ! grep -q '^waiting ' "$FAKE_DIALOG_LOG" || fail "touch on: a window after Sign opened ($pin_status)"
unset FAKE_WAITING_DECISION FAKE_WAITING_DELAY
# A signal while GPG waits after Sign ends the request at once, though GPG
# ignores it: GPG is killed a second after TERM, and what it left at the card
# is cancelled, waiting at most about 3s for a wedged scdaemon. Background jobs
# start with INT ignored, so perl restores it.
export FAKE_CARD_UIF=%00+ FAKE_DIALOG_DECISION=sign-no-touch FAKE_GPG_IGNORE_SIGNALS=1
for signal in INT:130:5 TERM:143:5 TERM:143:8:wedged; do
    if [[ "$signal" == *:wedged ]]; then
        export FAKE_KILLSCD_SLEEP=30
        signal=${signal%:wedged}
    fi
    signal_limit=${signal##*:}
    signal=${signal%:*}
    reset_pin_state
    rm -f "$FAKE_GPG_CALL_DIR/touch-at-start"
    : > "$FAKE_GPG_CALL_DIR/connect-agent-calls"
    /usr/bin/perl -e '$SIG{INT} = "DEFAULT"; exec @ARGV or die' "$ROOT/git-gpg-preview" --status-fd=2 -bsau TEST \
        < "$TMP/commit.payload" > "$TMP/signal.stdout" 2> "$TMP/signal.stderr" &
    signal_pid=$!
    waited=0
    while [[ ! -s "$FAKE_GPG_CALL_DIR/touch-at-start" && "$waited" -lt 100 ]]; do
        sleep 0.1
        waited=$((waited + 1))
    done
    [[ -s "$FAKE_GPG_CALL_DIR/touch-at-start" ]] || fail "SIG${signal%:*} after Sign: GPG never started"
    # The signing GPG, named by its payload file, until it records its call.
    signal_gpg=$(ls -t "$FAKE_GPG_CALL_DIR"/*.stdin | head -n 1)
    signal_gpg=${signal_gpg##*/}
    signal_sent=$SECONDS
    kill -s "${signal%:*}" "$signal_pid"
    signal_status=0
    wait "$signal_pid" || signal_status=$?
    [[ "$signal_status" -eq "${signal#*:}" && $((SECONDS - signal_sent)) -lt "$signal_limit" && ! -s "$TMP/signal.stdout" ]] ||
        fail "SIG${signal%:*} after Sign: status $signal_status after $((SECONDS - signal_sent))s"
    ! kill -0 "${signal_gpg%%.*}" 2>/dev/null || fail "SIG${signal%:*} after Sign: GPG still runs"
    grep -qxF 'SCD KILLSCD /bye' "$FAKE_GPG_CALL_DIR/connect-agent-calls" ||
        fail "SIG${signal%:*} after Sign: the stopped signature was left pending at the card"
done
unset FAKE_GPG_IGNORE_SIGNALS FAKE_KILLSCD_SLEEP
# A signal after GPG has finished and been reaped, while the request still runs
# (here waiting for an answer the preview began), signals neither GPG's old
# number, which may belong to another process by now, nor scdaemon: GPG had
# finished, so nothing waits at the card. /bin/kill is logged to see that.
printf '#!/bin/bash\nprintf "%%s\\n" "$*" >> "%s"\nexec /bin/kill "$@"\n' "$TMP/kill.log" > "$TMP/logged-kill"
chmod 700 "$TMP/logged-kill"
sed "s#/bin/kill#$TMP/logged-kill#g" "$ROOT/git-gpg-preview" > "$TMP/kill-logged-wrapper"
chmod 700 "$TMP/kill-logged-wrapper"
export FAKE_CARD_UIF=%01+ FAKE_DIALOG_DECISION=touch-then-stall-spam FAKE_DIALOG_DELAY=0
reset_pin_state
rm -f "$TMP/kill.log"
: > "$FAKE_GPG_CALL_DIR/connect-agent-calls"
reaped_before=$(wc -l < "$FAKE_GPG_CALL_DIR/calls")
"$TMP/kill-logged-wrapper" --status-fd=2 -bsau TEST < "$TMP/commit.payload" > "$TMP/signal.stdout" 2> "$TMP/signal.stderr" &
signal_pid=$!
waited=0
while [[ $(wc -l < "$FAKE_GPG_CALL_DIR/calls") -eq "$reaped_before" && "$waited" -lt 100 ]]; do
    sleep 0.1
    waited=$((waited + 1))
done
reaped_gpg=$(latest_call)
reaped_gpg=${reaped_gpg%%.*}
sleep 0.5
kill -s TERM "$signal_pid"
signal_status=0
wait "$signal_pid" || signal_status=$?
[[ "$signal_status" -eq 143 && ! -s "$TMP/signal.stdout" && "$waited" -lt 100 ]] ||
    fail "SIGTERM after GPG finished: status $signal_status, GPG finished: $((waited < 100))"
! grep -qE "^-s [A-Z]+ $reaped_gpg\$" "$TMP/kill.log" || fail "SIGTERM after GPG finished signalled its old number $reaped_gpg"
! grep -q KILLSCD "$FAKE_GPG_CALL_DIR/connect-agent-calls" || fail 'SIGTERM after GPG finished stopped scdaemon'
# Where ps cannot answer (a sandbox may deny it), a child kill -0 reaches still
# counts as the wrapper's: Cancel and SIGTERM while GPG waits for the touch stop
# it promptly and cancel what it left at the card.
printf '#!/bin/bash\necho "ps: Operation not permitted" >&2\nexit 1\n' > "$TMP/denied-ps"
chmod 700 "$TMP/denied-ps"
sed "s#/bin/ps#$TMP/denied-ps#g" "$ROOT/git-gpg-preview" > "$TMP/no-ps-wrapper"
chmod 700 "$TMP/no-ps-wrapper"
! grep -q '/bin/ps' "$TMP/no-ps-wrapper" || fail 'could not deny ps'
export FAKE_CARD_UIF=%01+ FAKE_DIALOG_DECISION=cancel FAKE_DIALOG_DELAY=0.5
# A ps that fails, and one that answers nothing.
for ps_answer in 'echo "ps: Operation not permitted" >&2; exit 1' 'exit 0'; do
    printf '#!/bin/bash\n%s\n' "$ps_answer" > "$TMP/denied-ps"
    : > "$FAKE_GPG_CALL_DIR/connect-agent-calls"
    no_ps_started=$SECONDS
    GATE_WRAPPER="$TMP/no-ps-wrapper" gate_case --status-fd=2 -bsau TEST
    [[ "$pin_status" -eq 1 && -n $(touch_at_start) && $((SECONDS - no_ps_started)) -lt 6 ]] ||
        fail "Cancel with ps ($ps_answer): $pin_status after $((SECONDS - no_ps_started))s"
    grep -qxF 'SCD KILLSCD /bye' "$FAKE_GPG_CALL_DIR/connect-agent-calls" ||
        fail "Cancel with ps ($ps_answer) left the signature pending at the card"
done
printf '#!/bin/bash\necho "ps: Operation not permitted" >&2\nexit 1\n' > "$TMP/denied-ps"
export FAKE_DIALOG_DECISION=hang FAKE_DIALOG_DELAY=0
for no_ps_case in denied-ps inherited-pid; do
    reset_pin_state
    rm -f "$FAKE_GPG_CALL_DIR/touch-at-start"
    : > "$FAKE_GPG_CALL_DIR/connect-agent-calls"
    if [[ "$no_ps_case" == denied-ps ]]; then
        "$TMP/no-ps-wrapper" --status-fd=2 -bsau TEST < "$TMP/commit.payload" > "$TMP/signal.stdout" 2> "$TMP/signal.stderr" &
    else
        # A signal with a GPG_PID the caller exported, before GPG starts (touch
        # off: the preview waits for Sign), stops no such process.
        export FAKE_CARD_UIF=%00+
        sleep 30 &
        inherited_pid=$!
        GPG_PID=$inherited_pid "$ROOT/git-gpg-preview" --status-fd=2 -bsau TEST < "$TMP/commit.payload" > "$TMP/signal.stdout" 2> "$TMP/signal.stderr" &
    fi
    signal_pid=$!
    waited=0
    if [[ "$no_ps_case" == denied-ps ]]; then
        while [[ ! -s "$FAKE_GPG_CALL_DIR/touch-at-start" && "$waited" -lt 100 ]]; do sleep 0.1; waited=$((waited + 1)); done
        signal_gpg=$(ls -t "$FAKE_GPG_CALL_DIR"/*.stdin | head -n 1)
        signal_gpg=${signal_gpg##*/}
    else
        while ! grep -q '^start ' "$FAKE_DIALOG_LOG" && [[ "$waited" -lt 100 ]]; do sleep 0.1; waited=$((waited + 1)); done
    fi
    sleep 0.3
    signal_sent=$SECONDS
    kill -s TERM "$signal_pid"
    signal_status=0
    wait "$signal_pid" || signal_status=$?
    [[ "$signal_status" -eq 143 && $((SECONDS - signal_sent)) -lt 5 && "$waited" -lt 100 ]] ||
        fail "SIGTERM, $no_ps_case: status $signal_status after $((SECONDS - signal_sent))s"
    if [[ "$no_ps_case" == denied-ps ]]; then
        ! kill -0 "${signal_gpg%%.*}" 2>/dev/null || fail 'SIGTERM with ps denied: GPG still runs'
        grep -qxF 'SCD KILLSCD /bye' "$FAKE_GPG_CALL_DIR/connect-agent-calls" || fail 'SIGTERM with ps denied left the signature pending at the card'
    else
        kill -0 "$inherited_pid" 2>/dev/null || fail 'SIGTERM stopped an inherited GPG_PID'
        ! grep -q KILLSCD "$FAKE_GPG_CALL_DIR/connect-agent-calls" || fail 'SIGTERM with an inherited GPG_PID stopped scdaemon'
        kill "$inherited_pid"
        wait "$inherited_pid" 2>/dev/null || true
    fi
done
export FAKE_CARD_UIF=%00+ FAKE_DIALOG_DECISION=sign-no-touch
# scdaemon answers GETATTR UIF-1 from the card data it read first (here
# FAKE_SCD_CACHE), so a policy changed since would read as the old one. The
# wrapper asks the card itself: a key turned from on to off asks for Sign on
# the next request.
export FAKE_SCD_CACHE="$TMP/scd-cache" FAKE_DIALOG_DECISION=sign FAKE_DIALOG_DELAY=1 FAKE_CARD_UIF=%01+
rm -f "$FAKE_SCD_CACHE"
gate_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 0 && $(touch_at_start) == after ]] || fail "touch on, before it changes: $pin_status, GPG $(touch_at_start)"
export FAKE_CARD_UIF=%00+
gate_case --status-fd=2 -bsau TEST
stale_gate=$(latest_capture)
stale_gate=$(head -n 1 "${stale_gate%.summary}.gate")
[[ "$pin_status" -eq 0 && $(touch_at_start) == before && "$stale_gate" == require-sign ]] ||
    fail "touch turned off since scdaemon read the card: $pin_status, GPG $(touch_at_start), preview asked: $stale_gate"
unset FAKE_SCD_CACHE
export FAKE_DIALOG_DELAY=0
# A slow PIN and touch within SIGN_GPG_SECONDS sign, and the real allowance
# leaves a person time to type a PIN, find the key and touch it.
[[ $(sed -n 's/^SIGN_GPG_SECONDS=//p' "$ROOT/git-gpg-preview") -eq 90 ]] || fail 'SIGN_GPG_SECONDS is not the 90s decided for a PIN and a touch'
sed 's/^SIGN_GPG_SECONDS=.*/SIGN_GPG_SECONDS=3/' "$ROOT/git-gpg-preview" > "$TMP/slow-pin-wrapper"
chmod 700 "$TMP/slow-pin-wrapper"
export FAKE_DIALOG_DECISION=sign FAKE_GPG_SLOW=1.5
GATE_WRAPPER="$TMP/slow-pin-wrapper" gate_case --status-fd=2 -bsau TEST
unset FAKE_GPG_SLOW
[[ "$pin_status" -eq 0 && "$pin_output" == 'signature-touch-policy' ]] || fail "touch off, a slow PIN within SIGN_GPG_SECONDS: $pin_status"
# The gate follows the policy, never the notice text: an empty one still gates.
sed 's/^UNKNOWN_TOUCH_NOTICE=.*/UNKNOWN_TOUCH_NOTICE=""/' "$ROOT/git-gpg-preview" > "$TMP/no-notice-wrapper"
chmod 700 "$TMP/no-notice-wrapper"
! cmp -s "$ROOT/git-gpg-preview" "$TMP/no-notice-wrapper" || fail 'could not empty the unknown notice'
export FAKE_CARD_UIF=%05+ FAKE_DIALOG_DELAY=1
GATE_WRAPPER="$TMP/no-notice-wrapper" gate_case --status-fd=2 -bsau TEST
empty_gate=$(latest_capture)
empty_gate=$(cat "${empty_gate%.summary}.gate")
[[ "$pin_status" -eq 0 && $(touch_at_start) == before && "$empty_gate" == require-sign ]] ||
    fail "touch unknown, an empty notice: $pin_status, GPG $(touch_at_start), preview asked: $empty_gate"
export FAKE_CARD_UIF=%00+ FAKE_DIALOG_DELAY=0
pass 'touch off: a Sign inside the deadline counts and a later one does not; a key that never confirms after Sign is stopped, a slow one signs; the gate needs no notice'


# A wrong PIN repeats the preview: the notice stays, and the policy is read once.
use_real_gpg "$TMP/gnupg-bin/gpg"
reset_pin_state
rm -f "$FAKE_GPG_CALL_DIR/connect-agent-calls"
export FAKE_CARD_UIF=%00+ FAKE_PIN_RETRIES=3 FAKE_GPG_PIN=123456
export FAKE_PIN_ENTRIES=654321,123456 FAKE_PIN_ERROR_DECISION=retry
run_pin_case --status-fd=2 -bsau TEST
[[ "$pin_status" -eq 0 && "$pin_output" == 'signature-touch-policy' ]] || fail "touch notice with a PIN retry ($pin_status)"
retry_summary=$(grep -l '^PIN attempt 2: ' "$TMP/captures"/*.summary) || fail 'the retry preview was not shown'
[[ $(sed -n 3,4p "$retry_summary") == "$TOUCH_OFF" ]] || fail 'the retry preview lost the touch notice'
facts_lines=$(awk '/^Message:$/ { print NR - 2; exit }' "$retry_summary")
max_facts=$(sed -n 's/^const FACTS_MAX_LINES = \([0-9][0-9]*\);$/\1/p' "$ROOT/dialog.jxa")
[[ "$facts_lines" -eq 10 && "$facts_lines" -le "$max_facts" ]] ||
    fail "the retry preview has $facts_lines fact lines, and the facts pane shows $max_facts"
[[ $(connect_agent_calls) -eq 1 ]] || fail 'touch policy was read again for the retry'
unset FAKE_PIN_RETRIES FAKE_GPG_PIN FAKE_PIN_ENTRIES FAKE_PIN_ERROR_DECISION FAKE_SECRET_KEYS
default_card
cp "$TMP/config.saved" "$XDG_CONFIG_HOME/git-gpg-preview/config"
pass 'a PIN retry keeps the touch notice without reading the policy again'

# dialog.jxa splits the preview at the first Message: line, so no fact may hold
# a line break, and the message itself gets a long allowance.
export FAKE_GPG_STDOUT='signature-message'
reset_pin_state
git -C "$FIXTURE" commit -q --allow-empty -m $'Message split subject\n\nMessage:\nFORGED fact in the body' >/dev/null
git -C "$FIXTURE" cat-file commit HEAD > "$TMP/forged-message.payload"
"$ROOT/git-gpg-preview" --status-fd=2 -bsau $'TEST\n\nMessage:\nFORGED selector' < "$TMP/forged-message.payload" > /dev/null 2>&1 \
    || fail 'signing with a forged selector and message'
summary=$(latest_capture)
facts=$(awk '/^$/ { exit } { print }' "$summary")
[[ $(printf '%s\n' "$facts" | sed -n 1p) == 'Request type: commit' && $(printf '%s\n' "$facts" | grep -c '') -eq 5 ]] \
    || fail "facts are not their single lines: $facts"
grep -qxF 'Signing key: TEST  Message: FORGED selector' <<< "$facts" || fail 'a selector broke out of its line'
[[ $(sed -n 7p "$summary") == 'Message:' && $(sed -n 8p "$summary") == 'Message split subject' ]] || fail 'facts do not end at the first Message: line'
! grep -qF 'FORGED fact' <<< "$facts" || fail 'the message reached the facts'
grep -qF 'FORGED fact in the body' "$summary" || fail 'the message lost its own text'
# Nor a character at which the facts pane would start a new line or reorder the
# text, though none of their bytes is a control: U+0085, U+2028, U+2029 and the
# bidirectional controls in a branch name each become '?'. Other text stays.
unsafe_branch=$(printf 'facts\302\205a\342\200\250b\342\200\251c\330\234d\342\200\216e\342\200\217f\342\200\252g')
unsafe_branch=$unsafe_branch$(printf '\342\200\253h\342\200\254i\342\200\255j\342\200\256k\342\201\246l\342\201\247m\342\201\250n\342\201\251o\303\251')
git -C "$FIXTURE" checkout -q -b "$unsafe_branch"
reset_pin_state
"$ROOT/git-gpg-preview" --status-fd=2 -bsau TEST < "$TMP/forged-message.payload" > /dev/null 2>&1 || fail 'signing on a branch with line separators'
git -C "$FIXTURE" checkout -q -
git -C "$FIXTURE" branch -q -D "$unsafe_branch"
grep -qxF "Branch: facts?a?b?c?d?e?f?g?h?i?j?k?l?m?n?o$(printf '\303\251')" "$(latest_capture)" ||
    fail "a branch name drew past its fact line: $(grep '^Branch: ' "$(latest_capture)" | od -c | head -3)"
git -C "$FIXTURE" commit -q --allow-empty -F - >/dev/null <<< "$(printf 'A long message\n\n'; printf 'body line of a long commit message\n%.0s' {1..100})"
git -C "$FIXTURE" cat-file commit HEAD > "$TMP/long-message.payload"
"$ROOT/git-gpg-preview" --status-fd=2 -bsau TEST < "$TMP/long-message.payload" > /dev/null 2>&1 || fail 'signing a long message'
[[ $(grep -c '^body line of a long commit message$' "$(latest_capture)") -eq 100 ]] || fail 'a long message was cut from the preview'
! grep -qF 'truncated in summary' "$(latest_capture)" || fail 'a long message was reported as truncated'
git -C "$FIXTURE" commit -q --allow-empty -F - >/dev/null <<< "$(printf 'A very long message\n\n'; printf 'body line of a long commit message\n%.0s' {1..200})"
git -C "$FIXTURE" cat-file commit HEAD > "$TMP/very-long-message.payload"
"$ROOT/git-gpg-preview" --status-fd=2 -bsau TEST < "$TMP/very-long-message.payload" > /dev/null 2>&1 || fail 'signing a very long message'
grep -qxF '[truncated in summary; View Details shows the complete report]' "$(latest_capture)" || fail 'a very long message was not reported as truncated'
pass 'the preview splits at the first Message: line, whatever the message or selector says, and keeps long messages'

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

# Use real payload headers with independent subjects so earlier checks remain
# unaffected. No production Git settings or signing keys enter these tests.
spam_payload() {
    awk '{ print } $0 == "" { exit }' "$TMP/initial.payload" > "$2"
    printf '%s\n' "$1" >> "$2"
}
SPAM_LIST="$XDG_CONFIG_HOME/git-gpg-preview/spam-subjects"
spam_payload 'Noisy subject $(touch bad) [a-z].*' "$TMP/spam.payload"
export FAKE_DIALOG_DECISION=spam
rm -f "$FAKE_TOUCH_FILE".*
set +e
"$ROOT/git-gpg-preview" -bsau TEST < "$TMP/spam.payload" > "$TMP/spam.stdout" 2> "$TMP/spam.stderr"
spam_status=$?
set -e
[[ "$spam_status" -eq 1 && ! -s "$TMP/spam.stdout" ]] || fail 'mark as spam did not cancel'
[[ $(stat -f '%Lp' "$SPAM_LIST") == 600 ]] || fail 'spam list is not private'
grep -Fx 'noisy subject $(touch bad) [a-z].*' "$SPAM_LIST" >/dev/null || fail 'spam rule was not stored literally'
grep -F 'decision=spam-mark' "$TMP/audit.log" >/dev/null || fail 'spam mark was not audited'
[[ ! -e "$FIXTURE/bad" ]] || fail 'spam subject executed as code'
before_dialogs=$(wc -l < "$FAKE_DIALOG_LOG")
before=$(wc -l < "$FAKE_GPG_CALL_DIR/calls")
spam_payload $'\n  NOISY SUBJECT $(touch bad) [a-z].*\t\r\nnew body' "$TMP/spam-retry.payload"
set +e
GIT_GPG_PREVIEW_ALLOW_FIXTURE=1 "$ROOT/git-gpg-preview" -bsau TEST < "$TMP/spam-retry.payload" > "$TMP/spam.stdout" 2> "$TMP/spam.stderr"
spam_status=$?
set -e
[[ "$spam_status" -eq 65 && ! -s "$TMP/spam.stdout" ]] || fail 'remembered spam was not rejected'
[[ $(wc -l < "$FAKE_DIALOG_LOG") -eq "$before_dialogs" ]] || fail 'remembered spam opened a preview'
[[ $(wc -l < "$FAKE_GPG_CALL_DIR/calls") -eq "$before" ]] || fail 'remembered spam signed'
grep -F 'decision=spam-reject' "$TMP/audit.log" >/dev/null || fail 'spam rejection was not audited'
export FAKE_DIALOG_DECISION=sign
spam_payload 'Noisy subject $(touch bad) [a-z].* follow-up' "$TMP/spam-near.payload"
run_preview 'spam near-match' "$TMP/spam-near.payload" commit
rm "$SPAM_LIST"
run_preview 'spam rule removed' "$TMP/spam.payload" commit
pass 'mark as spam persists a private literal rule, rejects retries, and can be undone'

export FAKE_DIALOG_DECISION=touch-then-spam
rm -f "$FAKE_TOUCH_FILE".*
set +e
"$ROOT/git-gpg-preview" -bsau TEST < "$TMP/spam.payload" > "$TMP/spam.stdout" 2> "$TMP/spam.stderr"
spam_status=$?
set -e
[[ "$spam_status" -eq 1 && ! -s "$TMP/spam.stdout" ]] || fail 'simultaneous touch and spam released a signature'
[[ -s "$SPAM_LIST" ]] || fail 'simultaneous touch and spam lost the rule'
rm "$SPAM_LIST"
pass 'mark as spam wins over a simultaneous hardware touch'

export FAKE_DIALOG_DECISION=touch-then-stall-spam
rm -f "$FAKE_TOUCH_FILE".*
before=$(wc -l < "$FAKE_GPG_CALL_DIR/calls")
set +e
"$ROOT/git-gpg-preview" -bsau TEST < "$TMP/spam.payload" > "$TMP/stall.stdout" 2> "$TMP/stall.stderr"
stall_status=$?
set -e
[[ $(wc -l < "$FAKE_GPG_CALL_DIR/calls") -gt "$before" ]] || fail 'lost decision test never reached GPG'
[[ "$stall_status" -eq 70 ]] || fail "a lost decision did not fail closed (status $stall_status)"
[[ ! -s "$TMP/stall.stdout" ]] || fail 'a lost decision released a signature'
grep -F 'began a decision that never completed' "$TMP/stall.stderr" >/dev/null || fail 'a lost decision was not reported'
grep -F 'decision=pending-decision-lost' "$TMP/audit.log" >/dev/null || fail 'a lost decision was not audited'
[[ ! -e "$SPAM_LIST" ]] || fail 'a lost decision saved a spam rule'
export FAKE_DIALOG_DECISION=sign
pass 'a rejection cut off before it lands refuses the signature instead of releasing it'

export FAKE_DIALOG_DECISION=spam
export FAKE_DIALOG_DELAY=1
rm -f "$FAKE_TOUCH_FILE".*
before_dialogs=$(wc -l < "$FAKE_DIALOG_LOG")
"$ROOT/git-gpg-preview" -bsau TEST < "$TMP/spam.payload" > "$TMP/spam.1" 2> "$TMP/spam.1.err" &
p1=$!
"$ROOT/git-gpg-preview" -bsau TEST < "$TMP/spam.payload" > "$TMP/spam.2" 2> "$TMP/spam.2.err" &
p2=$!
set +e
wait "$p1"; s1=$?
wait "$p2"; s2=$?
set -e
[[ ( "$s1" -eq 1 && "$s2" -eq 65 ) || ( "$s1" -eq 65 && "$s2" -eq 1 ) ]] || fail 'queued spam was not rechecked'
[[ ! -s "$TMP/spam.1" && ! -s "$TMP/spam.2" ]] || fail 'queued spam released a signature'
[[ $(wc -l < "$FAKE_DIALOG_LOG") -eq $((before_dialogs + 2)) ]] || fail 'queued spam opened a second preview'
rm "$SPAM_LIST"
pass 'queued requests recheck the saved spam list under the dialog lock'

before_dialogs=$(wc -l < "$FAKE_DIALOG_LOG")
"$ROOT/git-gpg-preview" -bsau TEST < "$TMP/spam.payload" > "$TMP/spam.stdout" 2> "$TMP/spam.stderr" &
spam_pid=$!
for attempt in {1..100}; do
    [[ $(wc -l < "$FAKE_DIALOG_LOG") -gt "$before_dialogs" ]] && break
    sleep 0.05
done
[[ $(wc -l < "$FAKE_DIALOG_LOG") -gt "$before_dialogs" ]] || fail 'spam failure test did not reach preview'
mkdir "$SPAM_LIST"
set +e
wait "$spam_pid"; spam_status=$?
set -e
[[ "$spam_status" -eq 70 && ! -s "$TMP/spam.stdout" ]] || fail 'save failure did not cancel'
grep -F 'could not save spam subject' "$TMP/spam.stderr" >/dev/null || fail 'save failure was not reported'
rmdir "$SPAM_LIST"
export FAKE_DIALOG_DELAY=0
export FAKE_DIALOG_DECISION=sign
pass 'spam persistence failure cancels signing and reports that the rule was not saved'

/usr/bin/osascript -l JavaScript "$ROOT/tests/dialog.jxa" "$ROOT/dialog.jxa" "$TMP"
pass 'AppKit main and detail dialogs dispatch spam/cancel, wrong-PIN retry, and preserve legacy callers'

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
    ! grep -q '^pin_prompt=' "$XDG_CONFIG_HOME/git-gpg-preview/config" || exit 1
    printf 'pin_prompt=pinentry\n' >> "$XDG_CONFIG_HOME/git-gpg-preview/config"
    "$ROOT/install.sh" --real-gpg "$ROOT/tests/helpers/fake-gpg" >/dev/null
    [[ $(<"$HOME/.local/state/git-gpg-preview/previous-program-state") == absent ]]
    grep -qx 'pin_prompt=pinentry' "$XDG_CONFIG_HOME/git-gpg-preview/config" || exit 1
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
    printf 'remember this subject\n' > "$XDG_CONFIG_HOME/git-gpg-preview/spam-subjects"
    printf 'AAAA 2 1\n' > "$XDG_CONFIG_HOME/git-gpg-preview/touch-offers"
    "$ROOT/scripts/git-gpg-preview-setup" upgrade >/dev/null
    [[ $(cat "$XDG_CONFIG_HOME/git-gpg-preview/spam-subjects") == 'remember this subject' ]]
    [[ $(cat "$XDG_CONFIG_HOME/git-gpg-preview/touch-offers") == 'AAAA 2 1' ]]
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
