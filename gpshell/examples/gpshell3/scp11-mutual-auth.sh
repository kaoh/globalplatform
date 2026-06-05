#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GPSHELL3_BIN="${GPSHELL3_BIN:-gpshell3}"
KEY_DIR="${KEY_DIR:-${SCRIPT_DIR}/scp11-oce-ca}"

SCP11_KVN="${SCP11_KVN:-0x01}"
SCP11_KID="${SCP11_KID:-0x13}"
SCP11_IMPL="${SCP11_IMPL:-00}"
SCP11_IMPL="${SCP11_IMPL#0x}"
SCP11_IMPL="${SCP11_IMPL#0X}"
if [[ ! "$SCP11_IMPL" =~ ^[0-9A-Fa-f]{2}$ ]]; then
    echo "SCP11_IMPL must be one byte of hex, for example 00 or 3C" >&2
    exit 1
fi

OCE_CERT_CHAIN_FILE="${OCE_CERT_CHAIN_FILE:-${KEY_DIR}/CERT.OCE.ECKA.CHAIN.der}"
SK_OCE_ECKA_PEM="${SK_OCE_ECKA_PEM:-${KEY_DIR}/SK.OCE.ECKA.pem}"
SK_OCE_ECKA_HEX="${SK_OCE_ECKA_HEX:-}"

TEST_COMMAND="${TEST_COMMAND:-list-apps}"

if [[ ! -f "$OCE_CERT_CHAIN_FILE" ]]; then
    echo "Missing OCE certificate chain file: $OCE_CERT_CHAIN_FILE" >&2
    exit 1
fi

if [[ -z "$SK_OCE_ECKA_HEX" ]]; then
    if [[ ! -f "$SK_OCE_ECKA_PEM" ]]; then
        echo "Missing SK.OCE.ECKA PEM file: $SK_OCE_ECKA_PEM" >&2
        echo "Provide SK_OCE_ECKA_HEX directly or provide SK_OCE_ECKA_PEM." >&2
        exit 1
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        echo "openssl not found in PATH" >&2
        exit 1
    fi
    SK_OCE_ECKA_HEX="$(
        openssl ec -in "$SK_OCE_ECKA_PEM" -noout -text 2>/dev/null \
            | awk '
                /^priv:/ {capture=1; next}
                /^pub:/ {capture=0}
                capture {
                    gsub(/[^0-9A-Fa-f]/, "", $0);
                    if (length($0) > 0) {
                        printf "%s", toupper($0);
                    }
                }
                END { printf "\n" }
            '
    )"
fi

SK_OCE_ECKA_HEX="$(printf '%s' "$SK_OCE_ECKA_HEX" | tr -d '[:space:]:')"
if [[ ! "$SK_OCE_ECKA_HEX" =~ ^[0-9A-Fa-f]+$ ]]; then
    echo "SK_OCE_ECKA_HEX is not valid hex" >&2
    exit 1
fi

CMD=(
    "$GPSHELL3_BIN"
    -t
    --scp 0x11
    --kv "$SCP11_KVN"
    --idx "$SCP11_KID"
    --key "$SK_OCE_ECKA_HEX"
    --scp-impl "$SCP11_IMPL"
    --scp11-cert "$OCE_CERT_CHAIN_FILE"
)

if [[ $# -gt 0 ]]; then
    CMD+=("$@")
    echo "Running SCP11 mutual authentication demo command: $*"
else
    CMD+=("$TEST_COMMAND")
    echo "Running SCP11 mutual authentication demo command: $TEST_COMMAND"
fi
"${CMD[@]}"
