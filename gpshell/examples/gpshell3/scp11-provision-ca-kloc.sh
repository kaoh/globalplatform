#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GPSHELL3_BIN="${GPSHELL3_BIN:-gpshell3}"
KEY_DIR="${KEY_DIR:-${SCRIPT_DIR}/scp11-oce-ca}"

# Secure-channel options used for provisioning commands.
AUTH_SCP="${AUTH_SCP:-3}"
AUTH_KV="${AUTH_KV:-0x00}"
AUTH_IDX="${AUTH_IDX:-0x00}"
AUTH_KEY="${AUTH_KEY:-404142434445464748494A4B4C4D4E4F}"

# CA-KLOC key reference on card.
CA_KLOC_KID="${CA_KLOC_KID:-0x10}"
CA_KLOC_KVN="${CA_KLOC_KVN:-0x01}"
CA_KLOC_PREV_KV="${CA_KLOC_PREV_KV:-0x00}"

CA_PUB_PEM="${CA_PUB_PEM:-${KEY_DIR}/PK.CA-KLOC.ECDSA.pem}"
CA_ID_FILE="${CA_ID_FILE:-${KEY_DIR}/CA-KLOC.ID.hex}"

# Optional: also store/replace CERT.SD.ECKA certificate store (section 7.8).
SD_CERT_STORE_FILE="${SD_CERT_STORE_FILE:-}"
SD_ECKA_KID="${SD_ECKA_KID:-0x13}"
SD_ECKA_KVN="${SD_ECKA_KVN:-0x01}"

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

echo "Provisioning PK.CA-KLOC.ECDSA (KID=${CA_KLOC_KID}, KVN=${CA_KLOC_KVN})"
"$GPSHELL3_BIN" \
    --scp "$AUTH_SCP" --kv "$AUTH_KV" --idx "$AUTH_IDX" --key "$AUTH_KEY" \
    put-key --type ecc \
        --kv "$CA_KLOC_PREV_KV" \
        --idx "$CA_KLOC_KID" \
        --new-kv "$CA_KLOC_KVN" \
        --pem "$CA_PUB_PEM"

echo "Provisioning CA-KLOC Identifier mapping (${CA_ID_HEX})"
"$GPSHELL3_BIN" \
    --scp "$AUTH_SCP" --kv "$AUTH_KV" --idx "$AUTH_IDX" --key "$AUTH_KEY" \
    scp11-store-ca-id \
        --ca-id "$CA_ID_HEX" \
        --kv "$CA_KLOC_KVN" \
        --idx "$CA_KLOC_KID"

if [[ -n "$SD_CERT_STORE_FILE" ]]; then
    if [[ ! -f "$SD_CERT_STORE_FILE" ]]; then
        echo "Missing SD certificate store file: $SD_CERT_STORE_FILE" >&2
        exit 1
    fi
    echo "Provisioning CERT.SD.ECKA certificate store (KID=${SD_ECKA_KID}, KVN=${SD_ECKA_KVN})"
    "$GPSHELL3_BIN" \
        --scp "$AUTH_SCP" --kv "$AUTH_KV" --idx "$AUTH_IDX" --key "$AUTH_KEY" \
        scp11-store-cert \
            --kv "$SD_ECKA_KVN" \
            --idx "$SD_ECKA_KID" \
            "$SD_CERT_STORE_FILE"
fi

echo "Done. Inspect with: $GPSHELL3_BIN scp11-cert-data"
