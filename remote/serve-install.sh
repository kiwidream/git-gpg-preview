#!/bin/bash
# Install, inspect or remove the remote signing service on the machine that
# holds the key (macOS launchd). Requires the wrapper to be installed first:
# the service reuses its real_gpg, dialog, lock and audit settings.

set -euo pipefail
umask 077

SCRIPT_DIR=$(cd -P -- "$(dirname -- "$0")" && pwd)
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/git-gpg-preview"
WRAPPER_CONFIG="$CONFIG_DIR/config"
SERVE_CONFIG="$CONFIG_DIR/serve"
LABEL="dev.git-gpg-preview.serve"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG_DIR="$HOME/Library/Logs/git-gpg-preview"
INSTALL_LIB_DIR="$HOME/.local/libexec/git-gpg-preview"
INSTALL_MODULE="$INSTALL_LIB_DIR/git_gpg_preview_remote.py"

usage() {
    cat >&2 <<USAGE
Usage: $(basename -- "$0") install [--port N] [--allow-node NAME]... [--allow-prefix PREFIX]... [--signing-key FPR]
       $(basename -- "$0") status
       $(basename -- "$0") uninstall

install   copies the service next to the wrapper's helpers, writes $SERVE_CONFIG
          (kept if it exists; flags update it), and loads a launchd agent that
          listens on this machine's Tailscale address. Nodes named minidev* and
          your own tailnet devices may request signatures; every one still needs
          your touch. Idempotent.
USAGE
}

config_value() {
    [[ -f "$1" ]] || return 1
    sed -n "s/^$2=//p" "$1" | tail -n 1
}

# XML-escape a value for a <string> element, so any home path yields a
# well-formed plist that launchctl will load.
xml() {
    # sed, not ${var//pat/rep}: bash 5.2's patsub_replacement expands & in
    # the replacement to the match, which is exactly the character escaped here.
    printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

# Union of a comma-separated list and extra entries, order kept, duplicates
# and blanks dropped: merge_csv "a,b" b c -> a,b,c
merge_csv() {
    local existing=$1; shift
    local out="" item seen=","
    for item in ${existing//,/ } "$@"; do
        item=${item// /}
        [[ -z "$item" ]] && continue
        case "$seen" in *",$item,"*) continue ;; esac
        seen="$seen$item,"
        out="${out:+$out,}$item"
    done
    printf '%s' "$out"
}

python_for_launchd() {
    local candidate
    for candidate in /usr/bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3; do
        if [[ -x "$candidate" ]] && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

install_service() {
    local port="" key="" nodes=() prefixes=() python
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --port) port=$2; shift 2 ;;
            --allow-node) nodes+=("$2"); shift 2 ;;
            --allow-prefix) prefixes+=("$2"); shift 2 ;;
            --signing-key) key=$2; shift 2 ;;
            *) usage; exit 64 ;;
        esac
    done
    [[ "$(uname -s)" == "Darwin" ]] || { printf 'the signing service runs where the key is: macOS only\n' >&2; exit 64; }
    if [[ ! -f "$WRAPPER_CONFIG" ]] || [[ -z "$(config_value "$WRAPPER_CONFIG" real_gpg)" ]]; then
        printf 'git-gpg-preview is not installed here; run its install first\n' >&2
        exit 1
    fi
    python=$(python_for_launchd) || { printf 'no python3 >= 3.9 found for launchd\n' >&2; exit 1; }

    mkdir -p "$INSTALL_LIB_DIR" "$LOG_DIR" "$HOME/Library/LaunchAgents"
    chmod 700 "$INSTALL_LIB_DIR" "$LOG_DIR"
    /usr/bin/install -m 600 "$SCRIPT_DIR/git_gpg_preview_remote.py" "$INSTALL_MODULE"

    # Merge flags into the existing serve config; unknown keys are preserved,
    # and allow lists are unioned so adding one node never drops another.
    local existing_port existing_nodes existing_prefixes existing_key
    existing_port=$(config_value "$SERVE_CONFIG" port || true)
    existing_nodes=$(config_value "$SERVE_CONFIG" allow_nodes || true)
    existing_prefixes=$(config_value "$SERVE_CONFIG" allow_node_prefixes || true)
    existing_key=$(config_value "$SERVE_CONFIG" signing_key || true)
    local node_list prefix_list
    node_list=$(merge_csv "$existing_nodes" "${nodes[@]:-}")
    prefix_list=$(merge_csv "${existing_prefixes:-minidev}" "${prefixes[@]:-}")
    local tmp
    tmp=$(mktemp "$CONFIG_DIR/serve.XXXXXX")
    {
        grep -Ev '^(port|allow_nodes|allow_node_prefixes|signing_key)=' "$SERVE_CONFIG" 2>/dev/null || true
        printf 'port=%s\n' "${port:-${existing_port:-24824}}"
        printf 'allow_nodes=%s\n' "$node_list"
        printf 'allow_node_prefixes=%s\n' "$prefix_list"
        printf 'signing_key=%s\n' "${key:-$existing_key}"
    } > "$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$SERVE_CONFIG"

    cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$(xml "$python")</string>
        <string>$(xml "$INSTALL_MODULE")</string>
        <string>serve</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>HOME</key><string>$(xml "$HOME")</string>
        <key>XDG_CONFIG_HOME</key><string>$(xml "${XDG_CONFIG_HOME:-$HOME/.config}")</string>
        <key>PATH</key><string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin</string>
    </dict>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>ThrottleInterval</key><integer>10</integer>
    <key>StandardOutPath</key><string>$(xml "$LOG_DIR/serve.log")</string>
    <key>StandardErrorPath</key><string>$(xml "$LOG_DIR/serve.log")</string>
</dict>
</plist>
PLIST
    chmod 600 "$PLIST"
    launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || true
    launchctl bootstrap "gui/$(id -u)" "$PLIST"
    printf 'Installed %s (launchd %s)\n' "$INSTALL_MODULE" "$LABEL"
    printf 'Config: %s\n' "$SERVE_CONFIG"
    printf 'Log:    %s/serve.log\n' "$LOG_DIR"
}

status_service() {
    printf 'service module: %s\n' "$([[ -f "$INSTALL_MODULE" ]] && printf '%s' "$INSTALL_MODULE" || printf 'not installed')"
    printf 'serve config:   %s\n' "$([[ -f "$SERVE_CONFIG" ]] && printf '%s' "$SERVE_CONFIG" || printf 'not installed')"
    if [[ -f "$SERVE_CONFIG" ]]; then
        printf '  port=%s allow_nodes=%s allow_node_prefixes=%s\n' \
            "$(config_value "$SERVE_CONFIG" port)" "$(config_value "$SERVE_CONFIG" allow_nodes)" \
            "$(config_value "$SERVE_CONFIG" allow_node_prefixes)"
    fi
    if launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1; then
        printf 'launchd:        loaded (%s)\n' "$LABEL"
    else
        printf 'launchd:        not loaded\n'
        return 1
    fi
    [[ -f "$LOG_DIR/serve.log" ]] && tail -n 1 "$LOG_DIR/serve.log"
    return 0
}

uninstall_service() {
    launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || true
    rm -f "$PLIST" "$INSTALL_MODULE"
    printf 'Removed the service; %s was left in place.\n' "$SERVE_CONFIG"
}

case "${1:-}" in
    install) shift; install_service "$@" ;;
    status) status_service ;;
    uninstall) uninstall_service ;;
    *) usage; exit 64 ;;
esac
