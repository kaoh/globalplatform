#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GPSHELL3_BIN="${GPSHELL3_BIN:-gpshell3}"
CAP_FILE="${CAP_FILE:-${SCRIPT_DIR}/helloworld.cap}"
LOAD_FILE_AID="${LOAD_FILE_AID:-D0D1D2D3D4D501}"
APPLET_AID="${APPLET_AID:-D0D1D2D3D4D50101}"

if [[ ! -f "$CAP_FILE" ]]; then
    echo "Missing CAP file: $CAP_FILE"
    exit 1
fi

echo "Running install/get-status/delete flow with ${GPSHELL3_BIN}"

# test_install
"$GPSHELL3_BIN" install "$CAP_FILE"

# test_get_status
"$GPSHELL3_BIN" list-apps

# test_delete
"$GPSHELL3_BIN" delete "$APPLET_AID"
"$GPSHELL3_BIN" delete "$LOAD_FILE_AID"

echo "Install/get-status/delete flow completed."
