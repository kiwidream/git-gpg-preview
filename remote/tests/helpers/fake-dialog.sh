#!/bin/bash
# Stand-in for dialog.jxa: captures what the operator would see, reports
# readiness, then decides per the control file (sign | cancel | hang).
set -u
summary=$1 details=$2 decision=$3 ready=${4:-} spam_action=${5:-}
capture=${FAKE_DIALOG_CAPTURE_DIR:?}
mkdir -p "$capture"
cp "$summary" "$capture/$$.summary"
cp "$details" "$capture/$$.details"
printf '%s' "$spam_action" > "$capture/$$.spam-action"
[[ -n "$ready" ]] && : > "$ready"
choice=$(cat "${FAKE_DIALOG_DECISION_FILE:?}" 2>/dev/null || echo sign)
if [[ "$choice" == delayed-spam ]]; then
    sleep 0.5
    choice=spam
fi
case "$choice" in
    sign)
        sha=$(sed -n 's/^SHA-256: //p' "$summary" | head -n 1)
        : > "${FAKE_TOUCH_FILE:?}.$sha"   # the "touch" completes the signature
        printf 'sign' > "$decision"
        ;;
    approve-no-touch) printf 'sign' > "$decision" ;;   # approved, but the key never confirms
    touch-then-cancel)                                  # the key confirms, the operator cancels in the same instant
        sha=$(sed -n 's/^SHA-256: //p' "$summary" | head -n 1)
        : > "${FAKE_TOUCH_FILE:?}.$sha"
        : > "$decision.deciding"
        printf 'cancel' > "$decision"
        ;;
    cancel) : > "$decision.deciding"; printf 'cancel' > "$decision" ;;
    spam) : > "$decision.deciding"; printf 'spam' > "$decision" ;;
    touch-then-spam)
        sha=$(sed -n 's/^SHA-256: //p' "$summary" | head -n 1)
        : > "${FAKE_TOUCH_FILE:?}.$sha"
        : > "$decision.deciding"
        printf 'spam' > "$decision"
        ;;
    touch-then-stall-spam)                              # answered, then cut off before the decision lands
        sha=$(sed -n 's/^SHA-256: //p' "$summary" | head -n 1)
        : > "${FAKE_TOUCH_FILE:?}.$sha"
        : > "$decision.deciding"
        sleep 30
        ;;
    hang) sleep 30 ;;
    *) printf 'garbage' > "$decision" ;;
esac
exit 0
