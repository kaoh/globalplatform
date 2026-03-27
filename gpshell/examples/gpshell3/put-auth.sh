#!/usr/bin/env bash
set -euo pipefail

GPSHELL3_BIN="${GPSHELL3_BIN:-gpshell3}"
TEST_AES_KEY="${TEST_AES_KEY:-00010203040506070809000102030405}"

echo "Running put-key/delete-key flow with ${GPSHELL3_BIN}"

# test_put_aes_key
"$GPSHELL3_BIN" del-key --kv 5 || true
"$GPSHELL3_BIN" put-key --type aes --kv 0 --idx 1 --new-kv 5 --key "$TEST_AES_KEY"

# test_delete_key
"$GPSHELL3_BIN" del-key --kv 5

echo "put-key/delete-key flow completed."
