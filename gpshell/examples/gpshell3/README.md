# GPShell3 Example Scripts

This directory contains small shell scripts that exercise `gpshell3` card-management flows. Most scripts send commands to a real GlobalPlatform card and can install applets, delete applications, add or remove keys, or provision SCP11 trust data.

Do not run these scripts against a production card or an unknown card. Confirm the target card, reader, keys, secure-channel protocol, and expected AIDs first. Failed authentication attempts or key-management commands can lock or permanently change a card.

## Directory Contents

- `helloworld.cap`: test CAP file used by the install, DAP, and delegated-management flows.
- `install.sh`: installs `helloworld.cap`, lists applications, then deletes the applet and load file.
- `put-auth.sh`: exercises AES key creation and deletion with `put-key` and `del-key`.
- `dap.sh`: installs `helloworld.cap` through a Security Domain that mandates DAP verification.
- `dm.sh`: installs `helloworld.cap` using delegated-management load and install tokens.
- `scp11-cert-creation.sh`: generates SCP11 OCE and CA-KLOC key/certificate material with OpenSSL.
- `scp11-provision.sh`: provisions the generated CA-KLOC trust data and SD ECKA private key to a card.
- `scp11-mutual-auth.sh`: opens an SCP11 secure channel with the generated OCE material and runs a test command.

## Common Prerequisites

- Bash.
- A built or installed `gpshell3` binary. If it is not in `PATH`, set `GPSHELL3_BIN`, for example:

  ```sh
  GPSHELL3_BIN=/path/to/gpshell3 bash ./install.sh
  ```

- PC/SC configured for the target environment. For a static build, for example `cmake -DSTATIC=ON`, the in-tree PC/SC connection plugin is linked into `gpshell3`, so `OPGP_PLUGIN_PATH` is not needed. For a non-static build, set `OPGP_PLUGIN_PATH` only if `gpshell3` cannot otherwise find the shared `gppcscconnectionplugin`, for example when running from an uninstalled out-of-source build tree:

  ```sh
  export OPGP_PLUGIN_PATH="$(pwd)/out/build/dev/gppcscconnectionplugin/src"
  ```

  This variable points to the GlobalPlatform connection plugin. It does not replace the operating-system PC/SC service/library and a working reader setup.

- A GlobalPlatform card or test card accepted by `gpshell3`.
- Valid secure-channel credentials for any command that authenticates. Several scripts rely on `gpshell3` defaults unless they pass explicit `--scp`, `--kv`, `--idx`, or `--key` options.

The checked-in scripts are examples, not a universal provisioning recipe. Adapt AIDs, key versions, key indexes, keys, and certificate material for the card profile you are testing.

## Running From This Directory

Run the scripts from `gpshell/examples/gpshell3` unless you set all paths explicitly. This is especially important for the SCP11 flow: `scp11-cert-creation.sh` writes its default output directory relative to the current working directory, while the SCP11 provision and authentication scripts look for `scp11-oce-ca` next to the scripts.

## Script Details

### `install.sh`

Purpose:

- Runs a simple load/install/status/delete lifecycle for `helloworld.cap`.
- Calls `gpshell3 install "$CAP_FILE"`.
- Calls `gpshell3 list-apps`.
- Deletes the applet AID and load-file AID.

Inputs and defaults:

- `GPSHELL3_BIN`: `gpshell3`
- `CAP_FILE`: `helloworld.cap` in this directory
- `LOAD_FILE_AID`: `D0D1D2D3D4D501`
- `APPLET_AID`: `D0D1D2D3D4D50101`

Prerequisites and assumptions:

- The CAP file exists and matches the configured AIDs.
- The card accepts the default `gpshell3` security settings for install and delete.
- Existing applications with the same AIDs may be overwritten or deleted by the flow.

Outcome:

- On success, the applet is installed, the registry is listed, and both the applet and load file are deleted again. The card should not retain the test applet after the script completes.

### `put-auth.sh`

Purpose:

- Exercises AES key insertion and deletion on the selected Security Domain.
- Deletes key version `5` if it exists.
- Adds a new AES key version `5` with key index `1`, based on current key version `0`.
- Deletes key version `5` again.

Inputs and defaults:

- `GPSHELL3_BIN`: `gpshell3`
- `TEST_AES_KEY`: `00010203040506070809000102030405`

Prerequisites and assumptions:

- The selected Security Domain permits key management.
- Key version `0`, key index `1`, and the default secure-channel credentials are valid for the target card.
- The card supports AES key management for this operation.

Outcome:

- On success, a temporary AES key version `5` is created and then removed. The script intentionally changes key state during the run.

### `dap.sh`

Purpose:

- Demonstrates Data Authentication Pattern (DAP) verification with ECC keys.
- Creates a Security Domain with DAP verification and mandated DAP privileges.
- Personalizes that Security Domain with an AES key.
- Stores a DAP verification public key.
- Hashes `helloworld.cap`, signs the hash with the matching ECC private key, installs the CAP with the DAP signature, and then removes the applet, load file, DAP key, and Security Domain.

Inputs and defaults:

- `GPSHELL3_BIN`: `gpshell3`
- `CAP_FILE`: `helloworld.cap` in this directory
- `ECC_PUBLIC_KEY`: `../../globalplatform/src/ecc_public_key_test.pem` relative to this directory
- `ECC_PRIVATE_KEY`: `../../globalplatform/src/ecc_private_key_test.pem` relative to this directory
- Security Domain AID: `D4D4D4D4D4010101`
- Security Domain package AID: `A0000001515350`
- Security Domain module AID: `A000000151535041`
- Test applet load-file AID: `D0D1D2D3D4D501`
- Test applet AID: `D0D1D2D3D4D50101`
- Security Domain AES key: `404142434445464748494A4B4C4D4E40`

Prerequisites and assumptions:

- The card supports installing Security Domains with DAP-related privileges.
- The card accepts the configured Security Domain package and module AIDs.
- The CAP file and ECC key pair are available.
- In this source tree, the checked-in ECC fixture keys are under `globalplatform/src/`. If the script default paths do not exist in your checkout layout, set them explicitly, for example from the repository root:

  ```sh
  ECC_PUBLIC_KEY="$PWD/globalplatform/src/ecc_public_key_test.pem" \
  ECC_PRIVATE_KEY="$PWD/globalplatform/src/ecc_private_key_test.pem" \
  bash gpshell/examples/gpshell3/dap.sh
  ```

Outcome:

- On success, the script validates an ECC DAP-protected load/install flow. It then deletes the temporary applet, load file, DAP key, and Security Domain.

### `dm.sh`

Purpose:

- Demonstrates delegated management with ECC tokens and an AES receipt key.
- Provisions a delegated-management token verification key.
- Provisions a delegated-management receipt key.
- Creates and personalizes a delegated-management Security Domain.
- Calculates a CAP hash, signs a load token, signs an install token, installs `helloworld.cap` with those tokens, and then removes the applet, load file, token key, receipt key, and Security Domain.

Inputs and defaults:

- `GPSHELL3_BIN`: `gpshell3`
- `CAP_FILE`: `helloworld.cap` in this directory
- `ECC_PUBLIC_KEY`: `../../globalplatform/src/ecc_public_key_test.pem` relative to this directory
- `ECC_PRIVATE_KEY`: `../../globalplatform/src/ecc_private_key_test.pem` relative to this directory
- Security Domain AID: `D4D4D4D4D4010101`
- Security Domain package AID: `A0000001515350`
- Security Domain module AID: `A000000151535041`
- Test applet load-file AID: `D0D1D2D3D4D501`
- Test applet AID: `D0D1D2D3D4D50101`
- Security Domain AES key: `404142434445464748494A4B4C4D4E40`
- Receipt key: `101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F`

Prerequisites and assumptions:

- The card supports delegated management, ECC token verification keys, and AES receipt keys.
- The issuer Security Domain accepts `put-dm-token`, `put-dm-receipt`, Security Domain installation, and cleanup deletes.
- The CAP file and ECC key pair are available. As with `dap.sh`, set `ECC_PUBLIC_KEY` and `ECC_PRIVATE_KEY` explicitly if the default relative paths do not exist in your checkout.

Outcome:

- On success, the script validates an ECC delegated-management load/install flow. It then deletes the temporary applet, load file, delegated-management keys, and Security Domain.

### `scp11-cert-creation.sh`

Purpose:

- Generates local SCP11 key and certificate material using OpenSSL.
- Creates a CA-KLOC ECDSA key pair and self-signed CA certificate.
- Creates an intermediate KA-KLOC ECDSA key pair and certificate signed by the CA-KLOC key.
- Creates an OCE ECKA key pair and an OCE certificate signed by the KA-KLOC key.
- Creates CA-KLCC, KA-KLCC, and SD ECKA material for provisioning a card-side SCP11a `SK.SD.ECKA`.
- Exports PEM and DER certificates.
- Builds OCE certificate chains in PEM and concatenated DER form (`CERT.KA-KLOC.ECDSA` followed by `CERT.OCE.ECKA`).
- Builds SD ECKA certificate chains in PEM and concatenated DER form (`CERT.CA-KLCC.ECDSA`, `CERT.KA-KLCC.ECDSA`, then `CERT.SD.ECKA`).
- Computes `CA-KLOC.ID.hex` from the CA certificate Subject Key Identifier, matching the KA-KLOC certificate Authority Key Identifier.
- Adds the standard SCP11 certificate-policy OIDs plus additional Yubico-compatible policy OIDs observed as required for YubiKey 5 NFC SCP11a certificate validation.

Inputs and defaults:

- Output directory: `./scp11-oce-ca`
- Validity: `3650` days
- Curve: `prime256v1`
- CA subject: `/CN=GP CA/OU=GP Trust Network/O=GP/C=UK`
- OCE subject: `/CN=GP OCE/OU=GP Trust Network/O=GP/C=UK`

Useful options:

```sh
bash ./scp11-cert-creation.sh --help
bash ./scp11-cert-creation.sh -o ./scp11-oce-ca
bash ./scp11-cert-creation.sh -o ./scp11-oce-ca --cn "My GP CA" --oce-cn "My OCE"
bash ./scp11-cert-creation.sh -f
```

Prerequisites and assumptions:

- OpenSSL is available in `PATH`.
- The output directory does not already exist, unless `--force` is used.
- Generated private keys are test material and must be protected. The script sets `umask 077` before writing outputs.
- The target SCP11 flow accepts X.509 material generated on the selected curve.

Outcome:

- The output directory contains:

  ```text
  SK.CA-KLOC.ECDSA.pem
  PK.CA-KLOC.ECDSA.pem
  CERT.CA-KLOC.ECDSA.pem
  CERT.CA-KLOC.ECDSA.der
  CERT.CA-KLOC.ECDSA.srl
  CA-KLOC.ID.hex
  SK.CA-KLCC.ECDSA.pem
  PK.CA-KLCC.ECDSA.pem
  CERT.CA-KLCC.ECDSA.pem
  CERT.CA-KLCC.ECDSA.der
  CERT.CA-KLCC.ECDSA.srl
  CA-KLCC.ID.hex
  SK.KA-KLOC.ECDSA.pem
  PK.KA-KLOC.ECDSA.pem
  CERT.KA-KLOC.ECDSA.pem
  CERT.KA-KLOC.ECDSA.der
  CERT.KA-KLOC.ECDSA.srl
  KA-KLOC.ID.hex
  SK.KA-KLCC.ECDSA.pem
  PK.KA-KLCC.ECDSA.pem
  CERT.KA-KLCC.ECDSA.pem
  CERT.KA-KLCC.ECDSA.der
  CERT.KA-KLCC.ECDSA.srl
  KA-KLCC.ID.hex
  SK.OCE.ECKA.pem
  PK.OCE.ECKA.pem
  CERT.OCE.ECKA.pem
  CERT.OCE.ECKA.der
  CERT.OCE.ECKA.CHAIN.pem
  CERT.OCE.ECKA.CHAIN.der
  SK.SD.ECKA.pem
  PK.SD.ECKA.pem
  CERT.SD.ECKA.pem
  CERT.SD.ECKA.der
  CERT.SD.ECKA.CHAIN.pem
  CERT.SD.ECKA.CHAIN.der
  ```

### `scp11-provision.sh`

Purpose:

- Provisions the generated CA-KLOC public key and CA identifier mapping to a card.
- Provisions the generated SD ECKA private key used by SCP11a mutual authentication.
- Uses an existing secure channel, by default SCP03 with sample test credentials.
- Stores `PK.CA-KLOC.ECDSA.pem` as an ECC public key.
- Stores the `CA-KLOC.ID.hex` to KID/KVN mapping with `scp11-store-ca-id`.
- Stores `SK.SD.ECKA.pem` as an ECC private key at the configured SD ECKA KID/KVN.
- Optionally stores `CERT.SD.ECKA.CHAIN.pem` as the `CERT.SD.ECKA` certificate store with `scp11-store-cert`.

Inputs and defaults:

- `GPSHELL3_BIN`: `gpshell3`
- `KEY_DIR`: `scp11-oce-ca` in this directory
- `AUTH_SCP`: `3`
- `AUTH_KV`: `0xFF`
- `AUTH_IDX`: `0x00`
- `AUTH_KEY`: `404142434445464748494A4B4C4D4E4F`
- `CA_KLOC_KID`: `0x10`
- `CA_KLOC_KVN`: `0x01`
- `CA_KLOC_PREV_KV`: `0x00`
- `CA_PUB_PEM`: `$KEY_DIR/PK.CA-KLOC.ECDSA.pem`
- `CA_ID_FILE`: `$KEY_DIR/CA-KLOC.ID.hex`
- `SD_ECKA_KID`: `0x11`
- `SD_ECKA_KVN`: `0x03`
- `SD_ECKA_PREV_KV`: `0x00`
- `SD_ECKA_PRIVATE_PEM`: `$KEY_DIR/SK.SD.ECKA.pem`
- `SD_ECKA_PRIVATE_HEX`: unset by default
- `SD_CERT_CHAIN_FILE`: `$KEY_DIR/CERT.SD.ECKA.CHAIN.pem`
- `STORE_SD_CERT_CHAIN`: `0` by default; set to `1` or pass `--store-cert-chain` to exercise STORE DATA Certificate Store provisioning

Useful options:

```sh
bash ./scp11-provision.sh --help
bash ./scp11-provision.sh
bash ./scp11-provision.sh --store-cert-chain
STORE_SD_CERT_CHAIN=1 bash ./scp11-provision.sh
```

Prerequisites and assumptions:

- Run `scp11-cert-creation.sh` first, or provide equivalent CA-KLOC and SD ECKA material.
- The target card supports ECC public-key provisioning for CA-KLOC, ECC private-key provisioning for SD ECKA, and the SCP11 CA identifier STORE DATA operation.
- `--store-cert-chain` additionally requires the card to accept the SCP11 Certificate Store STORE DATA command for the configured SD ECKA KID/KVN.
- The authentication key, key version, key index, and SCP protocol are correct for the target card.
- The chosen CA-KLOC and SD ECKA KID/KVN values match the card profile and do not collide with data that must be preserved.

Outcome:

- On success, the card contains the CA-KLOC public key, the CA identifier to KID/KVN mapping, and the SD ECKA private key referenced by SCP11 mutual authentication. With `--store-cert-chain`, it also contains the SD ECKA certificate store.

### `scp11-mutual-auth.sh`

Purpose:

- Demonstrates SCP11 mutual authentication using the generated OCE certificate chain and OCE private key.
- Extracts the raw OCE private-key bytes from `SK.OCE.ECKA.pem` with OpenSSL unless `SK_OCE_ECKA_HEX` is provided directly.
- Runs `gpshell3 --scp 0x11 --scp-impl <impl>` with the configured SD ECKA KVN/KID, private key, and OCE certificate chain.
- Executes either the command-line arguments passed to the script or the default `list-apps` command.

Inputs and defaults:

- `GPSHELL3_BIN`: `gpshell3`
- `KEY_DIR`: `scp11-oce-ca` in this directory
- `SCP11_KVN`: `0x03`
- `SCP11_KID`: `0x11`
- `SCP11_IMPL`: `00` by default, one byte of hex accepted with or without `0x`
- `OCE_CERT_CHAIN_FILE`: `$KEY_DIR/CERT.OCE.ECKA.CHAIN.der`
- `SK_OCE_ECKA_PEM`: `$KEY_DIR/SK.OCE.ECKA.pem`
- `SK_OCE_ECKA_HEX`: unset by default
- `SCP11_SD_PUBLIC_KEY`: `$KEY_DIR/PK.SD.ECKA.pem` by default; PEM file path, raw `PK.SD.ECKA` public key hex, or the `B04104...` TLV returned by compatible SD key generation. Set it to an empty value to force retrieval of `CERT.SD.ECKA` from the card.
- `SCP11_SD_PUBLIC_KEY_HEX`: backward-compatible alias for `SCP11_SD_PUBLIC_KEY`
- `SCP11_USE_SD_PUBLIC_KEY`: `1` by default; set to `0` or pass `--no-sd-public-key` to retrieve `CERT.SD.ECKA` from the card instead
- `TEST_COMMAND`: `list-apps`

Examples:

```sh
bash ./scp11-mutual-auth.sh
bash ./scp11-mutual-auth.sh list-apps
bash ./scp11-mutual-auth.sh card-info
SCP11_USE_SD_PUBLIC_KEY=0 bash ./scp11-mutual-auth.sh list-apps
SCP11_IMPL=3C bash ./scp11-mutual-auth.sh list-apps
bash ./scp11-mutual-auth.sh --no-sd-public-key list-apps
```

Prerequisites and assumptions:

- The OCE certificate chain and private key exist, usually from `scp11-cert-creation.sh`.
- The card has been provisioned with the matching CA-KLOC trust data and SD ECKA private key, and supports the configured SCP11 mode.
- `SCP11_KID` and `SCP11_KVN` identify the card's SD ECKA key material. The default KVN `0x03` matches the YubiKey-compatible generated SD ECKA key flow used by these examples. The PSO CA-KLOC reference is resolved from the certificate CA identifier when the card provides that mapping; otherwise the library falls back to the standard CA-KLOC KID `0x10` with the same KVN.
- If explicit SD public-key use is enabled, the public key is passed to mutual authentication directly and `gpshell3` does not retrieve `CERT.SD.ECKA` with `GET DATA BF21`.
- If `--no-sd-public-key` or `SCP11_USE_SD_PUBLIC_KEY=0` is used, `gpshell3` retrieves `CERT.SD.ECKA` from the card. This requires the certificate store to have been provisioned successfully.
- OpenSSL is available if `SK_OCE_ECKA_HEX` is not supplied directly.

Outcome:

- On success, `gpshell3` opens an SCP11 secure channel and runs the requested command. With defaults, it lists applications under SCP11.

## Typical SCP11 Demo Order

From this directory:

```sh
bash ./scp11-cert-creation.sh -o ./scp11-oce-ca
bash ./scp11-provision.sh
bash ./scp11-mutual-auth.sh list-apps
```

Use card-specific authentication and SCP11 parameters instead of the sample defaults:

```sh
AUTH_SCP=3 AUTH_KV=0x01 AUTH_IDX=0x00 AUTH_KEY=<hex> \
bash ./scp11-provision.sh

SCP11_KVN=0x03 SCP11_KID=0x11 SCP11_SD_PUBLIC_KEY=<pem-or-hex> \
bash ./scp11-mutual-auth.sh list-apps
```

Keep generated SCP11 private keys and card logs out of source control.
