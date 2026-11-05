#!/bin/bash
# Stand-in for dialog.jxa: captures what the operator would see, reports
# readiness, then decides per the control file (sign | cancel | hang). The
# preview is the only window the service may open, so any other request is
# recorded in other-windows in the capture directory and refused.
set -u
capture=${FAKE_DIALOG_CAPTURE_DIR:?}
mkdir -p "$capture"
if [[ "${1-}" == --* ]]; then
    printf '%s\n' "$*" >> "$capture/other-windows"
    exit 64
fi
summary=$1 details=$2 decision=$3 ready=${4:-} spam_action=${5:-}
cp "$summary" "$capture/$$.summary"
cp "$details" "$capture/$$.details"
printf '%s' "$spam_action" > "$capture/$$.spam-action"
# require-sign and the touch policy notice, when the service asks for Sign.
printf '%s\n%s' "${6-}" "${7-}" > "$capture/$$.gate"
choice=$(cat "${FAKE_DIALOG_DECISION_FILE:?}" 2>/dev/null || echo sign)
[[ "$choice" == never-ready ]] && exec sleep 30            # never shows, never answers
[[ -n "$ready" ]] && : > "$ready"
if [[ "$choice" == delayed-spam || "$choice" == delayed-sign ]]; then
    sleep 0.5
    choice=${choice#delayed-}
elif [[ "$choice" == late-sign:* ]]; then                 # Sign after that many seconds
    sleep "${choice#late-sign:}"
    choice=sign
fi
touched() {
    local sha
    sha=$(sed -n 's/^SHA-256: //p' "$summary" | head -n 1)
    : > "${FAKE_TOUCH_FILE:?}.$sha"
}
case "$choice" in
    raw:*) touched; printf '%b' "${choice#raw:}" > "$decision" ;;   # exactly these bytes, no marker
    marker-sign) touched; : > "$decision.deciding"; printf 'sign' > "$decision" ;;
    early-sign) touched; printf 'sign' > "$decision"; sleep 30 ;;   # answers, but the window stays open
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
