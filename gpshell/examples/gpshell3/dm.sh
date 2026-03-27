#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GPSHELL3_BIN="${GPSHELL3_BIN:-gpshell3}"
CAP_FILE="${CAP_FILE:-${SCRIPT_DIR}/helloworld.cap}"
ECC_PUBLIC_KEY="${ECC_PUBLIC_KEY:-${SCRIPT_DIR}/../../globalplatform/src/ecc_public_key_test.pem}"
ECC_PRIVATE_KEY="${ECC_PRIVATE_KEY:-${SCRIPT_DIR}/../../globalplatform/src/ecc_private_key_test.pem}"

SD_AID="D4D4D4D4D4010101"
SD_PKG_AID="A0000001515350"
SD_MODULE_AID="A000000151535041"
LOAD_FILE_AID="D0D1D2D3D4D501"
APPLET_AID="D0D1D2D3D4D50101"
SD_KEY="404142434445464748494A4B4C4D4E40"
RECEIPT_KEY="101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F"
NV_CODE_LIMIT="${NV_CODE_LIMIT:-343}"

for required_file in "$CAP_FILE" "$ECC_PUBLIC_KEY" "$ECC_PRIVATE_KEY"; do
    if [[ ! -f "$required_file" ]]; then
        echo "Missing required file: $required_file"
        exit 1
    fi
done

echo "Running delegated-management ECC flow with ${GPSHELL3_BIN}"

# test_dm_put_token_key_ecc
"$GPSHELL3_BIN" del-key --kv 0x70 || true
"$GPSHELL3_BIN" put-dm-token --kv 0 --new-kv 0x70 --token-type ecc "$ECC_PUBLIC_KEY"

# test_dm_put_receipt_key_aes256
"$GPSHELL3_BIN" del-key --kv 0x71 || true
"$GPSHELL3_BIN" put-dm-receipt --kv 0 --new-kv 0x71 --receipt-type aes "$RECEIPT_KEY"

# test_dm_install_sd_with_delegated_management
"$GPSHELL3_BIN" delete "$SD_AID" || true
"$GPSHELL3_BIN" install-sd \
    --load-file "$SD_PKG_AID" \
    --module "$SD_MODULE_AID" \
    --priv delegated-mgmt \
    --extradition-here isd \
    --delete-here isd \
    --extradition-away isd \
    "$SD_AID"

# test_personalize_sd
"$GPSHELL3_BIN" --sd "$SD_AID" --scp 3 --sec mac \
    put-auth --kv 0 --new-kv 1 --type aes --key "$SD_KEY"

# test_dm_calculate_load_token_ecc
HASH="$("$GPSHELL3_BIN" hash --sha256 "$CAP_FILE" | tr -d '\n')"
LOAD_TOKEN="$("$GPSHELL3_BIN" sign-load-token \
    --nv-code-limit "$NV_CODE_LIMIT" \
    "$LOAD_FILE_AID" "$SD_AID" "$HASH" "$ECC_PRIVATE_KEY" | tr -d '\n')"

# test_dm_calculate_install_token_ecc
INSTALL_TOKEN="$("$GPSHELL3_BIN" sign-install-token \
    "$LOAD_FILE_AID" "$APPLET_AID" "$APPLET_AID" "$ECC_PRIVATE_KEY" | tr -d '\n')"

# test_dm_install_helloworld_with_tokens_ecc
"$GPSHELL3_BIN" --sd "$SD_AID" --kv 1 --key "$SD_KEY" install \
    --hash "$HASH" \
    --load-token "$LOAD_TOKEN" \
    --install-token "$INSTALL_TOKEN" \
    "$CAP_FILE"

# test_dm_delete_helloworld
"$GPSHELL3_BIN" delete "$APPLET_AID"
"$GPSHELL3_BIN" delete "$LOAD_FILE_AID"

# test_dm_delete_keys
"$GPSHELL3_BIN" del-key --kv 0x70
"$GPSHELL3_BIN" del-key --kv 0x71

# test_dm_delete_sd
"$GPSHELL3_BIN" delete "$SD_AID"

echo "Delegated-management ECC flow completed."
