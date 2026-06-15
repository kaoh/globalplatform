#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GPSHELL3_BIN="${GPSHELL3_BIN:-gpshell3}"
KEY_DIR="${KEY_DIR:-${SCRIPT_DIR}/scp11-oce-ca}"

SCP11_KVN="${SCP11_KVN:-0x03}"
SCP11_KID="${SCP11_KID:-0x11}"
SCP11_IMPL="${SCP11_IMPL:-00}"
SCP11_IMPL="${SCP11_IMPL#0x}"
SCP11_IMPL="${SCP11_IMPL#0X}"
if [[ ! "$SCP11_IMPL" =~ ^[0-9A-Fa-f]{2}$ ]]; then
    echo "SCP11_IMPL must be one byte of hex, for example 00 or 3C" >&2
    exit 1
fi

OCE_CERT_CHAIN_FILE="${OCE_CERT_CHAIN_FILE:-}"
KA_KLOC_CERT_DER="${KA_KLOC_CERT_DER:-${KEY_DIR}/CERT.KA-KLOC.ECDSA.der}"
OCE_CERT_DER="${OCE_CERT_DER:-${KEY_DIR}/CERT.OCE.ECKA.der}"
SK_OCE_ECKA_PEM="${SK_OCE_ECKA_PEM:-${KEY_DIR}/SK.OCE.ECKA.pem}"
SK_OCE_ECKA_HEX="${SK_OCE_ECKA_HEX:-}"
SCP11_SD_PUBLIC_KEY="${SCP11_SD_PUBLIC_KEY:-${SCP11_SD_PUBLIC_KEY_HEX:-}}"

TEST_COMMAND="${TEST_COMMAND:-list-apps}"
TEMP_OCE_CERT_CHAIN_FILE=""

if [[ -z "$OCE_CERT_CHAIN_FILE" ]]; then
    if [[ -f "$KA_KLOC_CERT_DER" && -f "$OCE_CERT_DER" ]]; then
        TEMP_OCE_CERT_CHAIN_FILE="$(mktemp)"
        OCE_CERT_CHAIN_FILE="$TEMP_OCE_CERT_CHAIN_FILE"
        trap 'rm -f "$TEMP_OCE_CERT_CHAIN_FILE"' EXIT
        cat "$KA_KLOC_CERT_DER" "$OCE_CERT_DER" > "$OCE_CERT_CHAIN_FILE"
    else
        OCE_CERT_CHAIN_FILE="${KEY_DIR}/CERT.OCE.ECKA.CHAIN.der"
    fi
fi

if [[ ! -f "$OCE_CERT_CHAIN_FILE" ]]; then
    echo "Missing OCE certificate chain file: $OCE_CERT_CHAIN_FILE" >&2
    echo "Expected either that file, or both:" >&2
    echo "  $KA_KLOC_CERT_DER" >&2
    echo "  $OCE_CERT_DER" >&2
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

if [[ -n "$SCP11_SD_PUBLIC_KEY" && ! -f "$SCP11_SD_PUBLIC_KEY" ]]; then
    SCP11_SD_PUBLIC_KEY="$(printf '%s' "$SCP11_SD_PUBLIC_KEY" | tr -d '[:space:]:')"
    if [[ ! "$SCP11_SD_PUBLIC_KEY" =~ ^[0-9A-Fa-f]+$ ]]; then
        echo "SCP11_SD_PUBLIC_KEY is neither an existing PEM file nor valid hex" >&2
        exit 1
    fi
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

if [[ -n "$SCP11_SD_PUBLIC_KEY" ]]; then
    CMD+=(--scp11-sd-public-key "$SCP11_SD_PUBLIC_KEY")
    echo "Using provided SCP11 SD public key instead of retrieving CERT.SD.ECKA from the card"
fi

if [[ -n "$TEMP_OCE_CERT_CHAIN_FILE" ]]; then
    echo "Using generated SCP11 OCE certificate chain: CERT.KA-KLOC.ECDSA + CERT.OCE.ECKA"
else
    echo "Using SCP11 OCE certificate chain file: $OCE_CERT_CHAIN_FILE"
fi

if [[ $# -gt 0 ]]; then
    CMD+=("$@")
    echo "Running SCP11 mutual authentication demo command: $*"
else
    CMD+=("$TEST_COMMAND")
    echo "Running SCP11 mutual authentication demo command: $TEST_COMMAND"
fi
"${CMD[@]}"
