#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<'EOF'
Provision SCP11 example material to a card.

Usage:
  scp11-provision.sh [options]

Options:
  --store-cert-chain       Also store CERT.SD.ECKA certificate chain with scp11-store-cert.
  --no-store-cert-chain    Do not store CERT.SD.ECKA certificate chain (default).
  -h, --help              Show this help.

Environment:
  STORE_SD_CERT_CHAIN=1    Same as --store-cert-chain.
EOF
}

GPSHELL3_BIN="${GPSHELL3_BIN:-gpshell3}"
KEY_DIR="${KEY_DIR:-${SCRIPT_DIR}/scp11-oce-ca}"

# Secure-channel options used for provisioning commands.
AUTH_SCP="${AUTH_SCP:-3}"
# YubiKey reports its SCP03 static AES key set at KVN 0xFF. Keep P2/IDX at
# 0x00 for INITIALIZE UPDATE; the listed AES entries 1/2/3 are key components.
AUTH_KV="${AUTH_KV:-0xFF}"
AUTH_IDX="${AUTH_IDX:-0x00}"
AUTH_KEY="${AUTH_KEY:-404142434445464748494A4B4C4D4E4F}"

# CA-KLOC key reference on card.
CA_KLOC_KID="${CA_KLOC_KID:-0x10}"
CA_KLOC_KVN="${CA_KLOC_KVN:-0x01}"
# PUT KEY P1=0x00 means "add a new key". To replace an existing CA-KLOC key,
# set this to that key's current KVN, for example CA_KLOC_PREV_KV=0x01.
CA_KLOC_PREV_KV="${CA_KLOC_PREV_KV:-0x00}"

CA_PUB_PEM="${CA_PUB_PEM:-${KEY_DIR}/PK.CA-KLOC.ECDSA.pem}"
CA_ID_FILE="${CA_ID_FILE:-${KEY_DIR}/CA-KLOC.ID.hex}"

SD_ECKA_KID="${SD_ECKA_KID:-0x11}"
SD_ECKA_KVN="${SD_ECKA_KVN:-0x03}"
# PUT KEY P1=0x00 means "add a new key". To replace an existing SD ECKA key,
# set this to that key's current KVN, for example SD_ECKA_PREV_KV=0x03.
SD_ECKA_PREV_KV="${SD_ECKA_PREV_KV:-0x00}"
SD_ECKA_PRIVATE_PEM="${SD_ECKA_PRIVATE_PEM:-${KEY_DIR}/SK.SD.ECKA.pem}"
SD_ECKA_PRIVATE_HEX="${SD_ECKA_PRIVATE_HEX:-}"
SD_CERT_CHAIN_FILE="${SD_CERT_CHAIN_FILE:-${KEY_DIR}/CERT.SD.ECKA.CHAIN.pem}"
STORE_SD_CERT_CHAIN="${STORE_SD_CERT_CHAIN:-0}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --store-cert-chain)
            STORE_SD_CERT_CHAIN=1
            shift
            ;;
        --no-store-cert-chain)
            STORE_SD_CERT_CHAIN=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ ! -f "$CA_PUB_PEM" ]]; then
    echo "Missing CA public key PEM: $CA_PUB_PEM" >&2
    exit 1
fi
if [[ ! -f "$CA_ID_FILE" ]]; then
    echo "Missing CA Identifier file: $CA_ID_FILE" >&2
    exit 1
fi

CA_ID_HEX="$(tr -d '[:space:]' < "$CA_ID_FILE" | tr '[:lower:]' '[:upper:]')"
if [[ -z "$CA_ID_HEX" ]]; then
    echo "CA Identifier file is empty: $CA_ID_FILE" >&2
    exit 1
fi

if [[ -z "$SD_ECKA_PRIVATE_HEX" ]]; then
    if [[ ! -f "$SD_ECKA_PRIVATE_PEM" ]]; then
        echo "Missing SK.SD.ECKA PEM file: $SD_ECKA_PRIVATE_PEM" >&2
        echo "Provide SD_ECKA_PRIVATE_HEX directly or provide SD_ECKA_PRIVATE_PEM." >&2
        exit 1
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        echo "openssl not found in PATH" >&2
        exit 1
    fi
    SD_ECKA_PRIVATE_HEX="$(
        openssl ec -in "$SD_ECKA_PRIVATE_PEM" -noout -text 2>/dev/null \
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
SD_ECKA_PRIVATE_HEX="$(printf '%s' "$SD_ECKA_PRIVATE_HEX" | tr -d '[:space:]:')"
if [[ ! "$SD_ECKA_PRIVATE_HEX" =~ ^[0-9A-Fa-f]{64}$ ]]; then
    echo "SD_ECKA_PRIVATE_HEX is not a 32-byte hex private key" >&2
    exit 1
fi
if [[ "$STORE_SD_CERT_CHAIN" != "0" && "$STORE_SD_CERT_CHAIN" != "1" ]]; then
    echo "STORE_SD_CERT_CHAIN must be 0 or 1" >&2
    exit 2
fi
if [[ "$STORE_SD_CERT_CHAIN" == "1" && ! -f "$SD_CERT_CHAIN_FILE" ]]; then
    echo "Missing SD ECKA certificate chain file: $SD_CERT_CHAIN_FILE" >&2
    exit 1
fi

# All provisioning steps are chained in a single gpshell3 session using "then".
# This is critical: the PUT KEY for PK.CA-KLOC.ECDSA at KVN=0x01 may remove
# the SCP03 key set (KVN=0xFF) on some cards (e.g. YubiKey 5 NFC). By chaining
# commands, all operations share the same authenticated session established
# before any key modifications.

# Build the command array: put CA-KLOC public key, store the CA identifier, then
# put the SD ECKA private key used by SCP11a MUTUAL AUTHENTICATE.
CMD=(
    "$GPSHELL3_BIN"
    -t --scp "$AUTH_SCP" --kv "$AUTH_KV" --idx "$AUTH_IDX" --key "$AUTH_KEY"
    put-key --type ecc
        --ecc-curve reference
        --kv "$CA_KLOC_PREV_KV"
        --idx "$CA_KLOC_KID"
        --new-kv "$CA_KLOC_KVN"
        --pem "$CA_PUB_PEM"
    then scp11-store-ca-id
        --ca-id "$CA_ID_HEX"
        --kv "$CA_KLOC_KVN"
        --idx "$CA_KLOC_KID"
    then put-key --type ecc-private
        --kv "$SD_ECKA_PREV_KV"
        --idx "$SD_ECKA_KID"
        --new-kv "$SD_ECKA_KVN"
        --key "$SD_ECKA_PRIVATE_HEX"
)

if [[ "$STORE_SD_CERT_CHAIN" == "1" ]]; then
    CMD+=(
        then scp11-store-cert
            --kv "$SD_ECKA_KVN"
            --idx "$SD_ECKA_KID"
            "$SD_CERT_CHAIN_FILE"
    )
fi

echo "Provisioning PK.CA-KLOC.ECDSA (KID=${CA_KLOC_KID}, KVN=${CA_KLOC_KVN})"
echo "  + CA-KLOC Identifier mapping (${CA_ID_HEX})"
echo "  + SK.SD.ECKA private key (KID=${SD_ECKA_KID}, KVN=${SD_ECKA_KVN})"
if [[ "$STORE_SD_CERT_CHAIN" == "1" ]]; then
    echo "  + CERT.SD.ECKA certificate store (${SD_CERT_CHAIN_FILE})"
fi

"${CMD[@]}"

echo "Done. Inspect with: $GPSHELL3_BIN scp11-cert-data"
