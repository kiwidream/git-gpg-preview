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
pass 'wrong PINs stop when the key reports its PIN blocked'
unset FAKE_GPG_PIN FAKE_PIN_ENTRIES

# Without --status-fd=2 GPG's own pinentry is used; retries still work, and
# with no readable counter a request allows three attempts in total.
reset_pin_state
unset FAKE_PIN_RETRIES
export FAKE_GPG_BAD_PINS=99
run_pin_case -bsau TEST
[[ "$pin_status" -eq 2 ]] || fail "pinentry-path PIN status ($pin_status)"
[[ $(wc -l < "$FAKE_GPG_CALL_DIR/bad-pin-calls") -eq 3 ]] || fail 'unknown-counter attempt limit'
[[ $(pin_dialogs) == $'pin-error unknown retry counted\npin-error unknown retry counted\npin-error unknown final counted' ]] \
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
    "$ROOT/scripts/git-gpg-preview-setup" upgrade >/dev/null
    [[ $(cat "$XDG_CONFIG_HOME/git-gpg-preview/spam-subjects") == 'remember this subject' ]]
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
