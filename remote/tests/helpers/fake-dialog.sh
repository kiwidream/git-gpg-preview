#!/bin/bash
# Stand-in for dialog.jxa: captures what the operator would see, reports
# readiness, then decides per the control file (sign | cancel | hang).
set -u
summary=$1 details=$2 decision=$3 ready=${4:-}
capture=${FAKE_DIALOG_CAPTURE_DIR:?}
mkdir -p "$capture"
cp "$summary" "$capture/$$.summary"
cp "$details" "$capture/$$.details"
[[ -n "$ready" ]] && : > "$ready"
choice=$(cat "${FAKE_DIALOG_DECISION_FILE:?}" 2>/dev/null || echo sign)
case "$choice" in
    sign)
        sha=$(sed -n 's/^SHA-256: //p' "$summary" | head -n 1)
        : > "${FAKE_TOUCH_FILE:?}.$sha"   # the "touch" completes the signature
        printf 'sign' > "$decision"
        ;;
    approve-no-touch) printf 'sign' > "$decision" ;;   # approved, but the key never confirms
    cancel) printf 'cancel' > "$decision" ;;
    hang) sleep 30 ;;
    *) printf 'garbage' > "$decision" ;;
esac
exit 0
