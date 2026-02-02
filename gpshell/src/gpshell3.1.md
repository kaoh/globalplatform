% GPSHELL3(1) 3.0.0 | GPShell3 Documentation

# NAME

**gpshell3** - simplified command line tool for managing GlobalPlatform compliant smart cards

# SYNOPSIS

| **gpshell3** [global-options] <command> [command-args]

# DESCRIPTION

gpshell3 is a modern, simplified CLI for GlobalPlatform card management. It provides a concise set of commands for listing, installing and deleting applications, managing keys, opening secure channels, sending raw APDUs, and performing personalization steps, while following the GlobalPlatform Card specification.

Unlike the legacy `gpshell` (script-driven), `gpshell3` is argument-driven and aims to be easy to use interactively, in shell scripts, or on CI systems. All commands work against PC/SC readers and use the in-tree GlobalPlatform library.

Unless otherwise specified, `gpshell3` will:

- connect to the first available PC/SC reader;
- select a suitable Issuer Security Domain (ISD) AID automatically (`A000000151000000`, `A0000001510000`, or `A000000003000000`);
- open a Secure Channel using defaults listed below when a command requires security (e.g., install, delete, key management).

See also the example scripts in `gpshell/examples/` in the repository.

# GLOBAL OPTIONS

-r, --reader <name|num>
:  PC/SC reader name or 1-based number. Default: first present reader.

--protocol <auto|t0|t1>
:  Transport protocol. Default: `auto`.

--sd <aidhex>
:  ISD AID to select explicitly (hex). By default `gpshell3` will try, in order:

   - `A000000151000000` (GP 2.3.1 ISD)
   - `A0000001510000`   (GP 2.1.1 CM)
   - `A000000003000000` (OP 2.0.1 CM)

--sec <mac|mac+enc|mac+enc+rmac>
:  Secure Channel security level. Default: `mac+enc`.

--scp <protocol>
:  Secure Channel Protocol number, e.g. `1`, `2`, `3`. Normally auto-detected.

--scp-impl <impl>
:  SCP implementation as a hex value (e.g., `15`, `55`). Normally auto-detected.

--kv <n>
:  Key set version to use for mutual authentication. Default: `0`.

--idx <n>
:  Key index within the key set for mutual authentication. Default: `0`.

--derive <none|visa2|emv>
:  Key derivation method when authenticating with a single base key.

   - `none` (default): use keys as provided.
   - `visa2`: VISA2 derivation (a.k.a. VISA key derivation).
   - `emv`: EMV CPS 1.1 derivation.

--key <hex>
:  Base key (hex) used to derive ENC/MAC/DEK when `--derive` is not `none`. If `--enc/--mac/--dek` are not provided and no derivation is provided, this base key is also used directly for SCP02. Default: bytes `40..4F` (16 bytes).

--enc <hex>, --mac <hex>, --dek <hex>
:  Explicit S-ENC, S-MAC and DEK keys (hex) for mutual authentication. If provided together, `--key` is ignored.

-v, --verbose
:  Verbose output.

-t, --trace
:  Print APDU trace (hex APDUs and status words).

-h, --help
:  Show usage.

# COMMANDS

## list-apps

List Issuer Security Domains, Security Domains, Applications, Load Files and Executable Modules. Output includes:

- AIDs and life cycle states;
- associated Security Domain AIDs;
- privileges in short-name form like `priv=[sd,cm-lock,...]`.

Example:
```
gpshell3 list-apps
```

## list-keys

List key information grouped by key set version (`kv`), including key types and size.

Example:
```
gpshell3 list-keys
```

## list-readers

List available PC/SC readers.

## install

Load a CAP file and install/make selectable applet instances.

Synopsis:
```
gpshell3 install [--load-only|--install-only]
                 [--dap <hex>|@<file>] [--load-token <hex>] [--install-token <hex>]
                 [--hash <hex>] [--load-file <AIDhex>] [--applet <AIDhex>] [--module <AIDhex>]
                 [--params <hex>] [--v-data-limit <size>] [--nv-data-limit <size>]
                 [--priv <p1,p2,...>] <cap-file>
```

Options:

- `--applet <AIDhex>`: Applet AID to install (optional). If omitted together with `--module`, installs all applets from the CAP.
- `--module <AIDhex>`: Module AID (often same as applet) to install (optional).
- `--params <hex>`: Installation parameters (hex) passed to the applet `install()` method (optional).
- `--priv <list>`: Comma-separated privileges by short names. See “Privileges” below (optional).
- `--v-data-limit <size>`: Volatile data storage limit in bytes (optional).
- `--nv-data-limit <size>`: Non-volatile data storage limit in bytes (optional).
- `--load-only`: Perform INSTALL [for load] + LOAD only, skip installation/make-selectable.
- `--install-only`: Perform only INSTALL [for install] and make-selectable. Requires `--load-file`, `--module`, and `--applet`.
- `--load-file <AID>`: AID of the load file (required for `--install-only`).
- `--dap <hex>|@file`: DAP signature as hex or binary file (security domain AID is taken from `--sd`). If used, `--hash` must provide the precomputed load-file data block hash.
- `--hash <hex>`: Precomputed load-file data block hash (hex) required when `--dap` is supplied.
- `--load-token <hex>` / `--install-token <hex>`: Tokens for delegated management (optional).

Examples:
```
# Load and install with default security settings
gpshell3 install ./helloworld.cap

# Load only (stage package without creating instances)
gpshell3 install --load-only ./helloworld.cap

# Install only from an already loaded package
gpshell3 install --install-only \
    --load-file A00000000101 \
    --module   A00000000101 \
    --applet   A0000000010101 \
    --params 80
```

## delete <AIDhex>

Delete an application instance or load file by AID.

Example:
```
gpshell3 delete A0000000010101
```

## status

Set the lifecycle state of a card element.

Synopsis:
```
gpshell3 status <isd|sd|app|sd-app> --lc <state> <AIDhex>
```

Element types and allowed states:

- `isd`: `locked`, `terminated`  (WARNING: `terminated` is permanent.)
- `sd`:  `personalized`, `locked`
- `app`: `locked`, `selectable`
- `sd-app`: `locked`

## put-auth

Set secure channel keys (S-ENC, S-MAC, DEK) for a key set.

Synopsis:
```
gpshell3 put-auth [--type <aes|3des>] [--derive <none|emv|visa2>] --kv <ver> [--new-kv <ver>] [--key <hex> | --enc <hex> --mac <hex> --dek <hex>]
```

Options:

- Use either a single `--key` (with optional `--derive`) OR all of `--enc/--mac/--dek`.
- `--kv <ver>`: Key set version, defaults to 1, 0 means that a new key set is created (optional).
- `--new-kv <ver>`: New key set version when replacing keys, defaults to 1 (optional).
- `--type` defaults to `aes`.

## put-key

Put (add or replace) a key in a key set.

Synopsis:
```
gpshell3 put-key [--type <3des|aes|rsa>] --kv <ver> --idx <idx> --new-kv <ver> (--key <hex>|--pem <file>[:pass])
```

Options:

- `--kv <ver>`: Key set version (mandatory).
- `--idx <idx>`: Key index within the set (mandatory).
- `--new-kv <ver>`: New key set version when replacing keys (mandatory).
- For `--type aes|3des`: provide the key via `--key <hex>`.
- For `--type rsa`: provide an RSA public key in PEM via `--pem <file>[:pass]`.

## put-dm

Put delegated management keys.

Synopsis:
```
gpshell3 put-dm --kv <ver> [--new-kv <ver>] [--token-type <rsa>] [--receipt-type <aes|des>] <pem-file>[:pass] <receipt-key-hex>
```

Options:

- `--kv <ver>`: Key set version, defaults to 0, 0 means that a new key set is created (optional).
- `--new-kv <ver>`: New key set version when replacing or creating a new key set (mandatory).
- `<pem-file>[:pass]`: Token signing key in PEM, optional passphrase after colon.
- `<receipt-key-hex>`: Receipt key material (last positional parameter).
- `--token-type`: Token key type, default `rsa`.
- `--receipt-type`: Receipt key type, `aes` or `des` (default `aes`).

## del-key

Delete a key or an entire key set.

Synopsis:
```
gpshell3 del-key --kv <ver> [--idx <idx>]
```

Options:

- `--kv <ver>`: Key set version (mandatory).
- `--idx <idx>`: Key index within the set If `--idx` is omitted, the entire key set `kv` is deleted.

## apdu

Send raw APDUs. Multiple APDUs can be supplied as separate arguments or separated by `;` or `,` in a single argument. APDUs can be continuous hex (`00A40400`) or space-separated (`00 A4 04 00`).

Synopsis:
```
gpshell3 apdu [--auth] [--nostop|--ignore-errors] <APDU> [<APDU> ...]
```

Options:

- `--auth`: Perform default ISD selection and mutual authentication before sending APDUs.
- `--nostop` / `--ignore-errors`: Continue even if an APDU returns an error status (non-`9000`).

## hash

Compute the load-file data block hash of a CAP file.

Synopsis:
```
gpshell3 hash <cap-file> [--sha1|--sha256|--sha384|--sha512|--sm3]
```

Default hash algorithm: `sha256`.

## sign-dap

Generate a DAP signature from a precomputed hash.

Synopsis:
```
gpshell3 sign-dap aes [--output <file>] <hash-hex> <sd-aidhex> <hexkey>
gpshell3 sign-dap rsa [--output <file>] <hash-hex> <sd-aidhex> <pem>[:pass]
```

Writes the signature bytes to stdout unless `--output` is provided.

## store

Personalize an application by combining INSTALL [for personalization] and STORE DATA.

Synopsis:
```
gpshell3 store [--encryption <noinfo|app|enc>] [--format <noinfo|dgi|ber>] [--response <true|false>] <AIDhex> <datahex>
```

## cplc

Read and decode the Card Production Life Cycle (CPLC) data. This command does not require authentication.

Example:
```
gpshell3 cplc
```

## card-data

Read and decode GlobalPlatform Card Recognition Data (Card Data tag `0x66`). This command does not require authentication.

Example:
```
gpshell3 card-data
```

## card-capability

Read and decode GlobalPlatform Card Capability Information (Card Capability Information tag `0x67`). This command does not require authentication.

Example:
```
gpshell3 card-capability
```

## card-resources

Read extended card resource information (number of installed applications and free memory). This command does not require authentication.

Example:
```
gpshell3 card-resources
```

## diversification

Read diversification data (tag `0xCF`). This command does not require authentication.

Example:
```
gpshell3 diversification
```

## seq-counter

Read the Sequence Counter of the default Secure Channel key set (tag `0xC1`). This command does not require authentication.

Example:
```
gpshell3 seq-counter
```

## confirm-counter

Read the Confirmation Counter (tag `0xC2`). This command does not require authentication.

Example:
```
gpshell3 confirm-counter
```

Options:

- `--encryption` (default `noinfo`):
  - `noinfo`: no encryption information;
  - `app`: application-dependent encryption;
  - `enc`: encrypted with data encryption key.
- `--format` (default `noinfo`):
  - `noinfo`: raw data, no structural information;
  - `dgi`: DGI structures;
  - `ber`: BER-TLV structures.
- `--response <true|false>`: expect response data (default `false`).

# PRIVILEGES

Privileges are reported by `list-apps` as `priv=[...]`. A subset can be supplied to `install --priv` as a comma-separated list of short names.

Accepted by `install --priv`:

- `sd` — Security Domain
- `dap-verif` — DAP Verification
- `delegated-mgmt` — Delegated Management
- `cm-lock` — Card Manager Lock privilege
- `cm-terminate` — Card Manager Terminate privilege
- `default-selected` — Default Selected (does not imply on-reset default)
- `pin-change` — PIN Change
- `mandated-dap` — Mandated DAP Verification

Additional privilege names that may appear in `list-apps` output:

- `authorized-mgmt` — Authorized Management
- `token-mgmt` — Token Verification
- `global-delete` — Global Delete
- `global-lock` — Global Lock
- `global-registry` — Global Registry
- `final-application` — Final Application
- `global-service` — Global Service
- `receipt-generation` — Receipt Generation
- `ciphered-load-file-data-block` — Ciphered Load File Data Block
- `contactless-activation` — Contactless Activation
- `contactless-self-activation` — Contactless Self Activation

Note: Not all privileges are applicable to all element types. Refer to the GlobalPlatform Card Specification for details.

# EXAMPLES

Install an applet with parameters and explicit privileges:
```
gpshell3 install --priv default-selected --params 80 ./helloworld.cap
```

List applets and related:
```
gpshell3 list-apps
```

Open APDU session with mutual auth and send GET DATA:
```
gpshell3 apdu --auth "80CA006600"
```

Put authentication keys:
```
put-auth --enc 404142434445464748494a4b4c4d4e4f --mac 404142434445464748494a4b4c4d4e4f --dek 404142434445464748494a4b4c4d4e4f
```

Compute CAP hash and sign DAP (AES):
```
HASH=$(gpshell3 hash ./helloworld.cap | tr -d '\n')
gpshell3 sign-dap aes --output dap.sig "$HASH" A000000151000000 00112233445566778899AABBCCDDEEFF
```

# EXIT CODES

- `0` on success
- non-zero on error (APDU errors produce non-zero unless `apdu --nostop` is used)

# REQUIREMENTS

- PC/SC stack and a compatible card reader
- GlobalPlatform-compliant card

# SEE ALSO

`gpshell`(1), GlobalPlatform Card Specification
