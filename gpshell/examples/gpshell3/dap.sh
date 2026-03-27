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

for required_file in "$CAP_FILE" "$ECC_PUBLIC_KEY" "$ECC_PRIVATE_KEY"; do
    if [[ ! -f "$required_file" ]]; then
        echo "Missing required file: $required_file"
        exit 1
    fi
done

echo "Running DAP ECC flow with ${GPSHELL3_BIN}"

# test_dap_install_sd_with_mandated_dap
"$GPSHELL3_BIN" delete "$SD_AID" || true
"$GPSHELL3_BIN" install-sd \
    --load-file "$SD_PKG_AID" \
    --module "$SD_MODULE_AID" \
    --priv dap-verif,mandated-dap \
    --extradition-here isd \
    --delete-here isd \
    --extradition-away isd \
    "$SD_AID"

# test_dap_personalize_sd
"$GPSHELL3_BIN" --sd "$SD_AID" --scp 3 --sec mac \
    put-auth --kv 0 --new-kv 1 --type aes --key "$SD_KEY"
"$GPSHELL3_BIN" --sd "$SD_AID" --kv 1 --key "$SD_KEY" del-key --kv 0x73 || true
"$GPSHELL3_BIN" --sd "$SD_AID" --kv 1 --key "$SD_KEY" \
    put-dap-key --kv 0 --new-kv 0x73 --key-type ecc "$ECC_PUBLIC_KEY"

# test_dap_calculate_helloworld_ecc_dap
HASH="$("$GPSHELL3_BIN" hash --sha256 "$CAP_FILE" | tr -d '\n')"
DAP_SIG="$("$GPSHELL3_BIN" sign-dap ecc "$HASH" "$SD_AID" "$ECC_PRIVATE_KEY" | tr -d '\n')"

# test_dm_install_helloworld_with_dap
"$GPSHELL3_BIN" delete "$APPLET_AID" || true
"$GPSHELL3_BIN" delete "$LOAD_FILE_AID" || true
"$GPSHELL3_BIN" --sd "$SD_AID" --kv 1 --key "$SD_KEY" install \
    --hash "$HASH" \
    --dap "$DAP_SIG" \
    "$CAP_FILE"

# test_dap_delete_key
"$GPSHELL3_BIN" --sd "$SD_AID" --kv 1 --key "$SD_KEY" del-key --kv 0x73

# test_dap_delete_helloworld
"$GPSHELL3_BIN" delete "$APPLET_AID"
"$GPSHELL3_BIN" delete "$LOAD_FILE_AID"

# test_dap_delete_sd
"$GPSHELL3_BIN" delete "$SD_AID"

echo "DAP ECC flow completed."
