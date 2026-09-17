#!/bin/bash

set -euo pipefail
umask 077

SCRIPT_DIR=$(cd -P -- "$(dirname -- "$0")" && pwd)
INSTALL_BIN="$HOME/.local/bin/git-gpg-preview"
INSTALL_LIB="$HOME/.local/libexec/git-gpg-preview/dialog.jxa"
INSTALL_TOUCH="$HOME/.local/libexec/git-gpg-preview/touch-prompt.jxa"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/git-gpg-preview"
CONFIG_FILE="$CONFIG_DIR/config"
STATE_DIR="$HOME/.local/state/git-gpg-preview"
STATE_MARKER="$STATE_DIR/previous-program-state"
STATE_VALUES="$STATE_DIR/previous-program-values"
LOCK_ROOT="$HOME/Library/Caches/git-gpg-preview"
REAL_GPG_ARG=""
AUDIT_LOG=""

usage() {
    printf 'Usage: %s [--real-gpg /absolute/path/to/gpg] [--audit-log /absolute/path]\n' "$0" >&2
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --real-gpg)
            [[ "$#" -ge 2 ]] || { usage; exit 64; }
            REAL_GPG_ARG=$2
            shift 2
            ;;
        --audit-log)
            [[ "$#" -ge 2 ]] || { usage; exit 64; }
            AUDIT_LOG=$2
            shift 2
            ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 64 ;;
    esac
done

resolve_program() {
    local candidate="$1"
    if [[ "$candidate" == /* ]]; then
        printf '%s\n' "$candidate"
    else
        command -v -- "$candidate"
    fi
}

if [[ -n "$REAL_GPG_ARG" ]]; then
    REAL_GPG=$(resolve_program "$REAL_GPG_ARG") || {
        printf 'install.sh: cannot resolve GPG executable: %s\n' "$REAL_GPG_ARG" >&2
        exit 1
    }
else
    CONFIGURED_GPG=$(git config --global --get gpg.openpgp.program 2>/dev/null || true)
    if [[ -n "$CONFIGURED_GPG" && "$CONFIGURED_GPG" != "$INSTALL_BIN" ]]; then
        REAL_GPG=$(resolve_program "$CONFIGURED_GPG") || {
            printf 'install.sh: cannot resolve configured GPG executable: %s\n' "$CONFIGURED_GPG" >&2
            exit 1
        }
    else
        REAL_GPG=$(command -v gpg) || {
            printf 'install.sh: gpg was not found on PATH\n' >&2
            exit 1
        }
    fi
fi

if [[ "$REAL_GPG" != /* || ! -x "$REAL_GPG" ]]; then
    printf 'install.sh: real GPG must be an executable absolute path\n' >&2
    exit 1
fi
if [[ "$REAL_GPG" == "$INSTALL_BIN" || "$REAL_GPG" -ef "$SCRIPT_DIR/git-gpg-preview" ]]; then
    printf 'install.sh: refusing to configure the wrapper as real GPG\n' >&2
    exit 1
fi
if [[ -n "$AUDIT_LOG" && "$AUDIT_LOG" != /* ]]; then
    printf 'install.sh: audit log path must be absolute\n' >&2
    exit 1
fi

mkdir -p "$HOME/.local/bin" "$(dirname -- "$INSTALL_LIB")" "$CONFIG_DIR" "$STATE_DIR" "$LOCK_ROOT"
chmod 700 "$HOME/.local/bin" "$(dirname -- "$INSTALL_LIB")" "$CONFIG_DIR" "$STATE_DIR" "$LOCK_ROOT"

if [[ ! -f "$STATE_MARKER" ]]; then
    if git config --global --get-all gpg.openpgp.program >/dev/null 2>&1; then
        printf 'present\n' > "$STATE_MARKER"
        git config --global --null --get-all gpg.openpgp.program > "$STATE_VALUES"
    else
        printf 'absent\n' > "$STATE_MARKER"
        : > "$STATE_VALUES"
    fi
    chmod 600 "$STATE_MARKER" "$STATE_VALUES"
fi

/usr/bin/install -m 700 "$SCRIPT_DIR/git-gpg-preview" "$INSTALL_BIN"
/usr/bin/install -m 600 "$SCRIPT_DIR/dialog.jxa" "$INSTALL_LIB"
/usr/bin/install -m 600 "$SCRIPT_DIR/touch-prompt.jxa" "$INSTALL_TOUCH"

CONFIG_TEMP=$(mktemp "$CONFIG_DIR/config.XXXXXX")
trap 'rm -f "$CONFIG_TEMP"' EXIT
{
    printf 'real_gpg=%s\n' "$REAL_GPG"
    printf 'ui_helper=%s\n' "$INSTALL_LIB"
    printf 'touch_helper=%s\n' "$INSTALL_TOUCH"
    printf 'lock_root=%s\n' "$LOCK_ROOT"
    printf 'audit_log=%s\n' "$AUDIT_LOG"
} > "$CONFIG_TEMP"
chmod 600 "$CONFIG_TEMP"
mv -f "$CONFIG_TEMP" "$CONFIG_FILE"
trap - EXIT

git config --global --unset-all gpg.openpgp.program >/dev/null 2>&1 || true
git config --global --add gpg.openpgp.program "$INSTALL_BIN"

printf 'Installed %s\n' "$INSTALL_BIN"
printf 'Touch prompt: %s\n' "$INSTALL_TOUCH"
printf 'Real GPG: %s\n' "$REAL_GPG"
printf 'Global gpg.openpgp.program: %s\n' "$(git config --global --get gpg.openpgp.program)"
if [[ -n "$AUDIT_LOG" ]]; then
    printf 'Audit log: %s\n' "$AUDIT_LOG"
else
    printf 'Audit log: disabled\n'
fi
