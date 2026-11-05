#!/bin/bash
# Stand-in for dialog.jxa: captures what the operator would see, reports
# readiness, then decides per the control file (sign | cancel | hang). The touch
# policy windows append to touch-dialogs in the capture directory, and the offer
# answers per its own control file (apply | dismiss | hang; default dismiss).
set -u
capture=${FAKE_DIALOG_CAPTURE_DIR:?}
mkdir -p "$capture"
if [[ "${1-}" == --touch-offer ]]; then
    printf 'touch-offer %s %s\n' "$3" "$4" >> "$capture/touch-dialogs"
    answer=$(cat "${FAKE_TOUCH_OFFER_FILE:-}" 2>/dev/null || echo dismiss)
    [[ "$answer" == hang ]] && exec sleep 30
    printf '%s' "$answer" > "$2"
    exit 0
fi
if [[ "${1-}" == --touch-unchanged ]]; then
    printf 'touch-unchanged %s\n' "${2-}" >> "$capture/touch-dialogs"
    exit 0
fi
summary=$1 details=$2 decision=$3 ready=${4:-} spam_action=${5:-}
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
