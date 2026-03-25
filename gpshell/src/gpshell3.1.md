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
:  Verbose output. Sets `GLOBALPLATFORM_DEBUG=1` and `GLOBALPLATFORM_LOGFILE=stderr`.

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

- `--applet <AIDhex>`: Sets the applet instance AID (usually same as module) (optional).
- `--module <AIDhex>`: Module AID to install (optional). If omitted, installs all applets from the CAP.
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
- Delegated management note: the selected Security Domain (`--sd`, the one used for SCP/authentication) is also used as the target Security Domain AID in INSTALL [for load]. In typical DM flows this means the delegated management SD is also the receiving/associated SD for the loaded package and installed applets.

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

### Delegated Management Token Workflow

For delegated management, token verification must match both the key material on card and the exact APDU payload:

1. Select/authenticate the delegated management Security Domain using global `--sd <AIDhex>` and valid SCP keys.
2. Provision the matching **public** token verification key with `put-dm-token`.
3. Generate tokens with the corresponding **private** key using `sign-*-token` commands.
4. Pass the generated token bytes into the operation (`install --load-token`, `install --install-token`, `delete --token`, `move --token`, `update-registry --token`).

Important parameter matching rules:

- `sign-load-token <load-file-aid> <sd-aid> ...`:
  - `<sd-aid>` must be the same SD AID used as `--sd` during `install`.
  - It must also be the target SD AID used in INSTALL [for load].
- `sign-install-token <load-file-aid> <module-aid> <app-aid> ...`:
  - All AIDs, privileges, limits, and parameters must match the INSTALL [for install and make selectable] command.
- `sign-extradition-token` / `sign-update-registry-token`:
  - `<sd-aid>` must match the Security Domain AID used by the corresponding command.

If these fields differ, cards typically reject the command with status words such as `6982`/`6985`.

## install-sd

Install an Issuer Security Domain instance.

Synopsis:
```
gpshell3 install-sd [--load-file <AIDhex>] [--module <AIDhex>] [--expl-personalized]
                   [--priv <list>] [--extradition-here <list>] [--delete-here <list>]
                   [--extradition-away <list>] <instance-aid>
```

Options:

- `--load-file <AIDhex>`: Load file / package AID to use (optional). Defaults to `A0000000035350` or `A0000001515350` if found on card.
- `--module <AIDhex>`: Module AID to use (optional). Defaults to `A000000003535041` or `A000000151535041` if found on card.
- `--expl-personalized`: Include explicit personalized state tag in SD parameters (optional).
- `--priv <list>`: Comma-separated privileges by short names. See “Privileges” below (optional). Note: `GP211_SECURITY_DOMAIN` is automatically added.
- `--extradition-here <list>`: Accept extradition to this SD (optional, default `isd`).
- `--delete-here <list>`: Accept deletion (optional, default `isd`).
- `--extradition-away <list>`: Accept extradition away from this SD (optional, default `isd`).

The `<list>` value is a comma-separated list; tokens can be ORed:

- `none`: SD does not accept the operation (default policy if the tag is not present).
- `an-am`: accept from an ancestor SD with AM privilege.
- `am`: accept from any SD in its hierarchy with AM privilege.
- `isd`: accept from Issuer Security Domain.
- `an-am-dm`: accept from any SD with DM privilege under an ancestor SD with AM.
- `all-am`: accept from every SD with AM privilege on the card.

Example:
```
gpshell3 install-sd --extradition-here isd --delete-here isd --extradition-away isd A0000001510000
```

## delete

Delete an application instance or load file by AID.

Synopsis:
```
gpshell3 delete [--token <hex>] <AIDhex>
```

Options:

- `--token <hex>`: Optional delegated-management delete token (encoded with tag `9F`).
- `<AIDhex>`: AID of the application instance or load file to delete.

Example:
```
gpshell3 delete A0000000010101
```

## update-registry

Update the registry for an application (e.g. change privileges).

Synopsis:
```
gpshell3 update-registry [--sd <AIDhex>] [--priv <p1,p2,...>] [--token <hex>] <AIDhex>
```

Options:

- `<AIDhex>`: AID of the application instance to be updated (mandatory, last positional parameter).
- `--sd <AIDhex>`: AID of the target Security Domain (optional).
- `--priv <list>`: Comma-separated privileges by short names. See “Privileges” below (optional).
- `--token <hex>`: Optional delegated-management registry update token.

Example:
```
gpshell3 update-registry --sd A000000151000000 --priv default-selected A0000000010101
```

## move

Move an application to a different Security Domain (extradition).

Synopsis:
```
gpshell3 move [--token <hex>] <applicationAID> <securityDomainAID>
```

Options:

- `<applicationAID>`: AID of the application instance to be moved.
- `<securityDomainAID>`: AID of the target Security Domain.
- `--token <hex>`: Optional delegated-management extradition token.

Example:
```
gpshell3 move A0000000010101 A00000015100000002
```

## status

Set the lifecycle state of a card element.

Synopsis:
```
gpshell3 status <isd|sd|app|sd-app> --lc <state> <AIDhex>
```

Options:

- `<isd|sd|app|sd-app>`: Target element type.
- `--lc <state>`: Target lifecycle state (mandatory).
- `<AIDhex>`: AID of the target element.

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

## put-dm-token

Put delegated management token verification key.

Synopsis:
```
gpshell3 put-dm-token --kv <ver> [--new-kv <ver>] [--token-type <rsa|ecc>] <pem-file>[:pass]
```

Options:

- `--kv <ver>`: Key set version, defaults to 0, 0 means that a new key set is created (optional).
- `--new-kv <ver>`: New key set version when replacing or creating a new key set, default 0x70 (optional).
- `<pem-file>[:pass]`: Token verification public key in PEM, optional passphrase after colon.
- `--token-type`: Token key type, `rsa` or `ecc` (default `rsa`).

`put-dm-token` stores the token **verification** public key on card.  
`sign-load-token`, `sign-install-token`, `sign-extradition-token`, `sign-update-registry-token`, and `sign-delete-token` must use the matching **private** key to create tokens accepted by that verification key.

## put-dm-receipt

Put delegated management receipt key.

Synopsis:
```
gpshell3 put-dm-receipt --kv <ver> [--new-kv <ver>] [--receipt-type <aes|des>] <receipt-key-hex>
```

Options:

- `--kv <ver>`: Key set version, defaults to 0, 0 means that a new key set is created (optional).
- `--new-kv <ver>`: New key set version when replacing or creating a new key set, default 0x701 (optional).
- `<receipt-key-hex>`: Receipt key material (last positional parameter).
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
gpshell3 sign-dap ecc [--output <file>] <hash-hex> <sd-aidhex> <pem>[:pass]
```

Writes the signature bytes to stdout unless `--output` is provided.
For `ecc`, the signature is encoded in plain format according to BSI TR-03111 (`r||s`).

## sign-load-token

Calculate a Load Token using a private RSA or ECC key.

Synopsis:
```
gpshell3 sign-load-token [--output <file>] [--nv-code-limit <n>] [--v-data-limit <n>] [--nv-data-limit <n>] <load-file-aidhex> <sd-aidhex> <hash-hex> <pem>[:pass]
```

## sign-install-token

Calculate an Install Token using a private RSA or ECC key.

Synopsis:
```
gpshell3 sign-install-token [--output <file>] [--p1 <n>] [--priv <n>] [--v-data-limit <n>] [--nv-data-limit <n>] [--params <hex>] [--sd-params <hex>] [--uicc-params <hex>] [--sim-params <hex>] <load-file-aidhex> <module-aidhex> <app-aidhex> <pem>[:pass]
```

## sign-extradition-token

Calculate an Extradition Token using a private RSA or ECC key.

Synopsis:
```
gpshell3 sign-extradition-token [--output <file>] <sd-aidhex> <app-aidhex> <pem>[:pass]
```

## sign-update-registry-token

Calculate a Registry Update Token using a private RSA or ECC key.

Synopsis:
```
gpshell3 sign-update-registry-token [--output <file>] [--priv <n>] [--registry-params <hex>] <sd-aidhex> <app-aidhex> <pem>[:pass]
```

## sign-delete-token

Calculate a Delete Token using a private RSA or ECC key.

Synopsis:
```
gpshell3 sign-delete-token [--output <file>] <aidhex> <pem>[:pass]
```

## store

Personalize an application by combining INSTALL [for personalization] and STORE DATA.

Synopsis:
```
gpshell3 store [--encryption <noinfo|app|enc>] [--format <noinfo|dgi|ber>] [--response <true|false>] <AIDhex> <datahex>
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

## store-iin

Store the Issuer Identification Number (tag `0x42`) using BCD encoding.

Synopsis:
```
gpshell3 store-iin <IIN>
```

Options:

- `<IIN>`: Issuer Identification Number as a decimal string.

Example:
```
gpshell3 store-iin 123456
```

## store-cin

Store the Card Image Number (tag `0x45`) using BCD encoding.

Synopsis:
```
gpshell3 store-cin <CIN>
```

Options:

- `<CIN>`: Card Image Number as a decimal string.

Example:
```
gpshell3 store-cin 123456
```

## card-data

Read a bundle of card data objects, in this order:

- iin (Issuer Identification Number / SD Provider Identification Number, tag `0x42`)
- cin (Card Image Number / SD Image Number, tag `0x45`)
- CPLC
- card-info (Card Recognition Data, tag `0x66`)
- card-cap (Card Capability Information, tag `0x67`)
- confirm-counter (tag `0xC2`)
- seq-counter (tag `0xC1`)
- div-data (Diversification Data, tag `0xCF`)

This command does not require authentication.

Example:
```
gpshell3 card-data
```

## cplc

Read and decode the Card Production Life Cycle (CPLC) data. This command does not require authentication.

Example:
```
gpshell3 cplc
```

## iin

Read Issuer Identification Number / SD Provider Identification Number (tag `0x42`). This command does not require authentication.

Example:
```
gpshell3 iin
```

## cin

Read Card Image Number / SD Image Number (tag `0x45`). This command does not require authentication.

Example:
```
gpshell3 cin
```

## card-info

Read and decode GlobalPlatform Card Recognition Data (Card Data tag `0x66`). This command does not require authentication.

Example:
```
gpshell3 card-info
```

## card-cap

Read and decode GlobalPlatform Card Capability Information (Card Capability Information tag `0x67`). This command does not require authentication.

Example:
```
gpshell3 card-cap
```

## card-resources

Read extended card resource information (number of installed applications and free memory). This command does not require authentication.

Example:
```
gpshell3 card-resources
```

## div-data

Read diversification data (tag `0xCF`). This command does not require authentication.

Example:
```
gpshell3 div-data
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

# PRIVILEGES

Privileges are reported by `list-apps` as `priv=[...]` and can be supplied to `install --priv` as a comma-separated list of short names. Multiple privileges can be combined, e.g., `--priv sd,cm-lock,trusted-path`.

- `sd`, `security-domain` — Application is a Security Domain
- `dap-verif`, `dap` — Application can require DAP verification for loading and installing applications
- `delegated-mgmt` — Security Domain has delegated management right
- `cm-lock` — Application can lock the Card Manager
- `cm-terminate` — Application can terminate the card
- `default-selected`, `card-reset` — Application is default selected (In GP 2.3.1 redefined as Card Reset privilege)
- `pin-change`, `pin` — Application can change global PIN
- `mandated-dap`, `mandated-dap-verif` — Security Domain requires DAP verification for loading and installing applications
- `trusted-path` — Application is a Trusted Path for inter-application communication
- `authorized-mgmt` — Application is capable of Card Content Management (Security Domain privilege shall also be set)
- `token-verif`, `token` — Application is capable of verifying a token for Delegated Card Content Management
- `global-delete` — Application may delete any Card Content
- `global-lock` — Application may lock or unlock any Application
- `global-registry` — Application may access any entry in the GlobalPlatform Registry
- `final-application`, `final-app` — The only Application selectable in card Life Cycle State CARD_LOCKED and TERMINATED
- `global-service` — Application provides services to other Applications on the card
- `receipt-generation`, `receipt` — Application is capable of generating a receipt for Delegated Card Content Management
- `ciphered-load-file-data-block`, `ciphered-load` — The Security Domain requires that the Load File being associated with it is to be loaded ciphered
- `contactless-activation` — Application is capable of activating and deactivating any Application on the contactless interface
- `contactless-self-activation` — Application is capable of activating itself on the contactless interface without a prior request to the Application with the Contactless Activation privilege

**Note**: Not all privileges are applicable to all element types. Refer to the GlobalPlatform Card Specification v2.3.1 for details.

# EXAMPLES

Install an applet with parameters and explicit privileges:
```
gpshell3 install --priv default-selected --params 80 ./helloworld.cap
```

List applets and related:
```
gpshell3 list-apps
```

Store Issuer Identification Number:
```
gpshell3 store-iin 123456
```

Store Card Image Number:
```
gpshell3 store-cin 1234567890
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

`gpshell3`(1), GlobalPlatform Card Specification
