/*
 *  Copyright (c) 2026, Karsten Ohme
 *  This file is part of GlobalPlatform.
 *
 *  GPShell is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GPShell is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GPShell.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _WIN32
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/stat.h>

#include <globalplatform/globalplatform.h>

#ifndef _WIN32
#include <sys/types.h>
#endif

#define MAX_READERS_BUF 4096

static int status_ok(OPGP_ERROR_STATUS s) {
    if (s.errorStatus != OPGP_ERROR_STATUS_SUCCESS) {
        fprintf(stderr, "Error 0x%08X: %s\n", (unsigned int)s.errorCode, s.errorMessage);
        return 0;
    }
    return 1;
}

// Remember the ISD AID that was actually selected during connection/authentication
// so subsequent operations (e.g., install) can reuse it without probing via GET DATA.
static unsigned char g_selected_isd[16];
static DWORD g_selected_isd_len = 0;

// Cleanup state tracking
static OPGP_CARD_CONTEXT *g_cleanup_ctx = NULL;
static OPGP_CARD_INFO *g_cleanup_info = NULL;
static int g_cleanup_card_connected = 0;

static void cleanup_and_exit(int exit_code) {
    if (g_cleanup_card_connected && g_cleanup_ctx && g_cleanup_info) {
        OPGP_card_disconnect(*g_cleanup_ctx, g_cleanup_info);
        g_cleanup_card_connected = 0;
    }
    if (g_cleanup_ctx) {
        OPGP_release_context(g_cleanup_ctx);
        g_cleanup_ctx = NULL;
    }
    exit(exit_code);
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [global-options] <command> [command-args]\n\n", prog);

    fputs(
        "Global options:\n"
        "  -r, --reader <name|num>    PC/SC reader name or number (1-based) (default: auto first present)\n"
        "  --protocol <auto|t0|t1>    Transport protocol (default: auto)\n"
        "  --sd <aidhex>             ISD AID hex; default tries A000000151000000 then A0000001510000 then A000000003000000\n"
        "  --sec <mac|mac+enc|mac+enc+rmac>\n"
        "                            Secure channel security level (default: mac+enc)\n"
        "  --scp <protocol>           SCP protocol as digit (e.g., 1, 2, 3)\n"
        "  --scp-impl <impl>          SCP implementation as hex (e.g., 15, 55)\n"
        "  --kv <n>                   Key set version for mutual auth (default: 0)\n"
        "  --idx <n>                  Key index within key set for mutual auth (default: 0)\n"
        "  --derive <none|visa2|emv>  Key derivation (default: none)\n"
        "  --key <hex>                Base key for mutual auth (default: 40..4F)\n"
        "  --enc <hex>                ENC key for mutual auth (default: 40..4F)\n"
        "  --mac <hex>                MAC key for mutual auth (default: 40..4F)\n"
        "  --dek <hex>                DEK key for mutual auth (default: 40..4F)\n"
        "  -v, --verbose              Verbose output\n"
        "  -t, --trace                Enable APDU trace\n"
        "  -h, --help                 Show this help\n\n"
        "Commands:\n"
        "  list-apps\n"
        "      List security domains, applications, load files and load-file modules.\n"
        "      Privileges are printed in short-name form like: priv=[sd,cm-lock,...]\n"
        "  list-keys\n"
        "      List key information grouped by key set version (kv).\n"
        "  list-readers\n"
        "      List available PC/SC readers.\n\n",
        stderr);

    fputs(
        "  install [--load-only|--install-only] [--dap <hex>|@<file>] [--load-token <hex>] [--install-token <hex>] \\\n"
        "          [--hash <hex>] [--load-file <AIDhex>] [--applet <AIDhex>] [--module <AIDhex>] [--params <hex>] \\\n"
        "          [--v-data-limit <size>] [--nv-data-limit <size>] [--priv <p1,p2,...>] <cap-file>\n"
        "      Load a CAP file, and optionally install/make selectable applet instance(s).\n"
        "      --applet <AIDhex>: Select which applet AID to install (optional).\n"
        "      --module <AIDhex>: Select which module AID to install (usually same as applet) (optional).\n"
        "                         If both --applet and --module are omitted, installs all applets in the CAP.\n"
        "      --params: installation parameters (hex) (optional).\n"
        "      --priv: comma-separated privilege short names (see 'Privileges' below)  (optional).\n"
        "      --v-data-limit <size>: Volatile data storage limit in bytes for applet instance (optional).\n"
        "      --nv-data-limit <size>: Non-volatile data storage limit in bytes for applet instance (optional).\n"
        "      --load-only: only perform INSTALL [for load] + LOAD, skip install/make-selectable (optional).\n"
        "      --install-only: only perform INSTALL [for install and make selectable], skip load phase (optional).\n"
        "                      Requires --load-file, --module, and --applet.\n"
        "      --load-file: AID of the load file (required for --install-only) (optional).\n"
        "      --dap: DAP signature as hex or @file for binary signature (SD AID taken from --sd) (optional).\n"
        "      --hash: precomputed load-file data block hash (hex) (required for --dap) (optional).\n"
        "      --load-token <hex>: Load token for delegated management (optional).\n"
        "      --install-token <hex>: Install token for delegated management (optional).\n\n"
        "  delete <AIDhex>\n"
        "      Delete an application instance or load file by AID.\n\n"
        "  put-key [--type <3des|aes|rsa>] --kv <ver> --idx <idx> [--new-kv <ver>] \\\n"
        "          (--key <hex>|--pem <file>[:pass])\n"
        "      Put (add/replace) a key in a key set.\n"
        "      --kv <ver>: Key set version number to put key into (mandatory).\n"
        "      --idx <idx>: Key index within key set (mandatory).\n"
        "      --new-kv <ver>: New key set version when replacing keys (optional).\n"
        "      --type aes|3des uses --key (hex). --type rsa uses --pem (optionally :pass).\n\n"
        "  put-auth [--type <aes|3des>] [--derive <none|emv|visa2>] --kv <ver> [--new-kv <ver>] \\\n"
        "           [--key <hex> | --enc <hex> --mac <hex> --dek <hex>]\n"
        "      Put secure channel keys (S-ENC/S-MAC/DEK) for a key set.\n"
        "      --kv <ver>: Key set version number to put keys into (default: 1) (optional).\n"
        "      --new-kv <ver>: New key set version when replacing keys (default: 1) (optional).\n"
        "      Use either --key (single base key) OR all of --enc/--mac/--dek.\n"
        "      --type: Key type (default: aes).\n"
        "      --derive: Key derivation method for single base key (default: none).\n\n"
        "  put-dm --kv <ver> [--new-kv <ver>] [--token-type <rsa>] [--receipt-type <aes|des>] \\\n"
        "         <pem-file>[:pass] <receipt-key-hex>\n"
        "      Put delegated management keys.\n"
        "      --kv <ver>: Key set version number to put delegated management keys into (mandatory).\n"
        "      --new-kv <ver>: New key set version when replacing keys (optional).\n"
        "      <pem-file>[:pass]: PEM file path with optional passphrase after colon.\n"
        "      <receipt-key-hex>: Receipt key as hex (mandatory, last positional parameter).\n"
        "      --token-type: Token key type, 'rsa' (default: rsa).\n"
        "      --receipt-type: Receipt key type, 'aes' or 'des' (default: aes).\n\n"
        "  del-key --kv <ver> [--idx <idx>]\n"
        "      Delete a key. If --idx is omitted, deletes all keys in the given key set.\n"
        "      --kv <ver>: Key set version number (mandatory).\n"
        "      --idx <idx>: Key index within key set (optional; if omitted, deletes entire key set).\n\n",
        stderr);

    fputs(
        "  status <isd|sd|app|sd-app> [--lc <state>] <AIDhex>\n"
        "      Set the lifecycle state of a card element.\n"
        "      Element types:\n"
        "        isd:    Issuer Security Domain; --lc: locked, terminated\n"
        "        sd:     Security Domain; --lc: personalized, locked\n"
        "        app:    Application; --lc: locked, selectable\n"
        "        sd-app: Security Domain and Application; --lc: locked\n"
        "      WARNING: 'terminated' for ISD cannot be undone - the card will be permanently terminated!\n\n"
        "  apdu [--auth] [--nostop|--ignore-errors] <APDU> [<APDU> ...]\n"
        "      Send raw APDUs.\n"
        "      --nostop|--ignore-errors: Continue execution even if APDU returns error status.\n"
        "      APDU format: hex bytes either concatenated (e.g. 00A40400) or space-separated (e.g. 00 A4 04 00).\n"
        "      Multiple APDUs can be provided as separate args or separated by ';' or ',' in one arg.\n"
        "      By default, apdu does NOT select ISD or perform mutual authentication; use --auth to enable it.\n\n"
        "  hash <cap-file> [--sha1|--sha256|--sha384|--sha512|--sm3]\n"
        "      Compute the load-file data block hash of a CAP file. Default is sha256.\n\n"
        "  sign-dap aes [--output <file>] <hash-hex> <sd-aidhex> <hexkey>\n"
        "  sign-dap rsa [--output <file>] <hash-hex> <sd-aidhex> <pem>[:pass]\n"
        "      Generate a DAP signature from a precomputed hash.\n"
        "      Output is signature only (for use with 'install --dap <hex>' or '--dap @file').\n"
        "      --output: write signature to a binary file.\n\n"
        "  store [--encryption <noinfo|app|enc>] [--format <noinfo|dgi|ber>] \\\n"
        "        [--response <true|false>] <AIDhex> <datahex>\n"
        "      Personalize an application by combining INSTALL [for personalization] and STORE DATA.\n"
        "      --encryption: data encryption mode (default: noinfo)\n"
        "        noinfo: no encryption information\n"
        "        app:    application-dependent encryption\n"
        "        enc:    encrypted with data encryption key\n"
        "      --format: data structure format (default: noinfo)\n"
        "        noinfo: no structure information\n"
        "        dgi:    DGI format\n"
        "        ber:    BER-TLV format\n"
        "      --response: expect response data (default: false)\n"
        "      Data supports flexible hex format (spaces/tabs ignored).\n\n"
        "Privileges (used by install --priv and shown by list-apps as priv=[...]):\n"
        "  sd,dap-verif,delegated-mgmt,cm-lock,cm-terminate,default-selected,pin-change,mandated-dap",
        stderr);
}

static int hex_to_bytes(const char *hex, unsigned char *out, size_t *outlen) {
    size_t len = strlen(hex), i = 0, j = 0;
    if (len % 2 != 0) return -1;
    if (*outlen < len/2) return -2;
    for (; i < len; i += 2) {
        int v1, v2;
        char c1 = tolower((unsigned char)hex[i]);
        char c2 = tolower((unsigned char)hex[i+1]);
        v1 = (c1 >= '0' && c1 <= '9') ? c1 - '0' : (c1 >= 'a' && c1 <= 'f') ? c1 - 'a' + 10 : -1;
        v2 = (c2 >= '0' && c2 <= '9') ? c2 - '0' : (c2 >= 'a' && c2 <= 'f') ? c2 - 'a' + 10 : -1;
        if (v1 < 0 || v2 < 0) return -3;
        out[j++] = (unsigned char)((v1 << 4) | v2);
    }
    *outlen = j; return 0;
}

static void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i=0;i<len;i++) printf("%02X", buf[i]);
}

static void print_aid(const OPGP_AID *aid) { print_hex(aid->AID, aid->AIDLength); }

static BYTE sec_level_from_option(BYTE proto, const char *opt) {
    if (!opt || strcmp(opt, "mac+enc") == 0) {
        return (proto == GP211_SCP03) ? GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC : GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC;
    }
    if (strcmp(opt, "mac") == 0) {
        return (proto == GP211_SCP03) ? GP211_SCP03_SECURITY_LEVEL_C_MAC : GP211_SCP02_SECURITY_LEVEL_C_MAC;
    }
    if (strcmp(opt, "mac+enc+rmac") == 0) {
        return (proto == GP211_SCP03) ? GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC : GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC;
    }
    return (proto == GP211_SCP03) ? GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC : GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC;
}

static int parse_privs_byte(const char *list, BYTE *out)
{
    if (!list) { *out = 0; return 0; }
    BYTE p = 0;
    char buf[256]; strncpy(buf, list, sizeof(buf)-1); buf[sizeof(buf)-1] = '\0';
    char *save=NULL; char *tok = strtok_r(buf, ",", &save);
    while (tok) {
        // normalize
        for (char *c=tok; *c; ++c) *c = (char)tolower((unsigned char)*c);
        if (!strcmp(tok, "sd") || !strcmp(tok, "security-domain")) p |= 0x80; // SECURITY_DOMAIN
        else if (!strcmp(tok, "dap-verif") || !strcmp(tok, "dap")) p |= 0xC0; // DAP_VERIFICATION
        else if (!strcmp(tok, "delegated-mgmt")) p |= 0xA0; // DELEGATED_MANAGEMENT
        else if (!strcmp(tok, "cm-lock")) p |= 0x10; // CARD_MANAGER_LOCK
        else if (!strcmp(tok, "cm-terminate")) p |= 0x08; // CARD_MANAGER_TERMINATE
        else if (!strcmp(tok, "default-selected") || !strcmp(tok, "default")) p |= 0x04; // DEFAULT_SELECTED (do not refer to card reset)
        else if (!strcmp(tok, "pin-change") || !strcmp(tok, "pin")) p |= 0x02; // PIN_CHANGE
        else if (!strcmp(tok, "mandated-dap") || !strcmp(tok, "mandated-dap-verif")) p |= 0xD0; // MANDATED_DAP_VERIFICATION
        else { fprintf(stderr, "Unknown privilege '%s'\n", tok); return -1; }
        tok = strtok_r(NULL, ",", &save);
    }
    *out = p; return 0;
}

static int select_isd(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, const char *isd_hex_opt) {
    OPGP_ERROR_STATUS s;
    if (isd_hex_opt) {
        unsigned char aidbuf[16]; size_t aidlen = sizeof(aidbuf);
        if (hex_to_bytes(isd_hex_opt, aidbuf, &aidlen) != 0) return -1;
        s = OPGP_select_application(ctx, info, aidbuf, (DWORD)aidlen);
        if (status_ok(s)) {
            if (aidlen <= sizeof(g_selected_isd)) { memcpy(g_selected_isd, aidbuf, aidlen); g_selected_isd_len = (DWORD)aidlen; }
            return 0;
        }
    }
    s = OPGP_select_application(ctx, info, (PBYTE)GP231_ISD_AID, 8);
    if (status_ok(s)) {
        memcpy(g_selected_isd, GP231_ISD_AID, 8); g_selected_isd_len = 8; return 0;
    }
    // has on 00 less but would still work on GP2.3.1 cards
    s = OPGP_select_application(ctx, info, (PBYTE)GP211_CARD_MANAGER_AID, 7);
    if (status_ok(s)) {
        memcpy(g_selected_isd, GP211_CARD_MANAGER_AID, 7); g_selected_isd_len = 7; return 0;
    }
    s = OPGP_select_application(ctx, info, (PBYTE)GP211_CARD_MANAGER_AID_ALT1, 8);
    if (status_ok(s)) {
        memcpy(g_selected_isd, GP211_CARD_MANAGER_AID_ALT1, 8); g_selected_isd_len = 8; return 0;
    }
    return -1;
}

static int connect_pcsc(OPGP_CARD_CONTEXT *pctx, OPGP_CARD_INFO *pinfo, const char *reader, const char *protocol, int trace, int verbose) {
    OPGP_ERROR_STATUS s;
    s = OPGP_establish_context(pctx);
    if (!status_ok(s)) { fprintf(stderr, "Failed to establish PC/SC context\n"); return -1; }
    if (trace) { OPGP_enable_trace_mode(OPGP_TRACE_MODE_ENABLE, stderr); }
    char readers[MAX_READERS_BUF]; DWORD rlen = sizeof(readers);
    if (!reader) {
        s = OPGP_list_readers(*pctx, readers, &rlen, 1);
        if (!status_ok(s) || rlen <= 1 || readers[0] == '\0') {
            fprintf(stderr, "No PC/SC readers with a smart card inserted found\n");
            // release context on error path to avoid leaks
            OPGP_release_context(pctx);
            return -1;
        }
        reader = readers; // first reader
    } else {
        // Check if reader is a numeric index (1-based)
        char *endptr;
        long reader_num = strtol(reader, &endptr, 10);
        if (*endptr == '\0' && reader_num > 0) {
            // It's a number - list all readers and select by index
            s = OPGP_list_readers(*pctx, readers, &rlen, 0);
            if (!status_ok(s) || rlen <= 1) {
                fprintf(stderr, "No PC/SC readers found\n");
                OPGP_release_context(pctx);
                return -1;
            }
            // Parse reader list (null-separated strings)
            const char *current = readers;
            int count = 0;
            while (*current && current < readers + rlen) {
                count++;
                if (count == reader_num) {
                    reader = current;
                    break;
                }
                current += strlen(current) + 1;
            }
            if (count < reader_num) {
                fprintf(stderr, "Reader number %ld not found (only %d readers available)\n", reader_num, count);
                OPGP_release_context(pctx);
                return -1;
            }
        }
    }
    if (verbose) { fprintf(stderr, "Selected reader: %s\n", reader); }
    DWORD proto = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
    if (protocol) {
        if (strcmp(protocol, "t0") == 0) proto = SCARD_PROTOCOL_T0;
        else if (strcmp(protocol, "t1") == 0) proto = SCARD_PROTOCOL_T1;
    }
    s = OPGP_card_connect(*pctx, reader, pinfo, proto);
    if (!status_ok(s)) {
        fprintf(stderr, "Failed to connect to reader '%s'\n", reader);
        // release context on error path to avoid leaks
        OPGP_release_context(pctx);
        return -1;
    }
    return 0;
}

static int mutual_auth(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec,
                       BYTE keyset_ver, BYTE key_index, int derivation, const char *sec_level_opt, int verbose,
                       const BYTE *baseKey_in, const BYTE *enc_in, const BYTE *mac_in, const BYTE *dek_in, BYTE keyLength_in,
                       const char *scp_protocol, const char *scp_impl) {
    BYTE scp = 0, scpImpl = 0;

    // Parse SCP protocol if provided
    if (scp_protocol) {
        scp = (BYTE)atoi(scp_protocol);
        if (scp == 1) scp = GP211_SCP01;
        else if (scp == 2) scp = GP211_SCP02;
        else if (scp == 3) scp = GP211_SCP03;
    }

    // Parse SCP implementation if provided
    if (scp_impl) {
        size_t impl_len = sizeof(scpImpl);
        if (hex_to_bytes(scp_impl, &scpImpl, &impl_len) != 0 || impl_len != 1) {
            fprintf(stderr, "Invalid --scp-impl hex (must be 1 byte)\n");
            return -1;
        }
    }

    // Only fetch from card if both are not provided
    if (!scp_protocol || !scp_impl) {
        OPGP_ERROR_STATUS s = GP211_get_secure_channel_protocol_details(ctx, info, &scp, &scpImpl);
        if (!status_ok(s)) {
            if (verbose) fprintf(stderr, "Failed to get SCP details, defaulting to SCP02 i15\n");
            scp = GP211_SCP02; scpImpl = GP211_SCP02_IMPL_i15;
        }
    }
    BYTE secLevel = sec_level_from_option(scp, sec_level_opt);
    BYTE S_ENC[32]={0}, S_MAC[32]={0}, DEK[32]={0}, baseKey[32]={0};
    BYTE keyLength = keyLength_in > 0 ? keyLength_in : 16;

    // Use provided keys or default to VISA default key
    if (baseKey_in) {
        memcpy(baseKey, baseKey_in, keyLength);
    } else {
        memcpy(baseKey, OPGP_VISA_DEFAULT_KEY, 16);
    }

    if (enc_in) {
        memcpy(S_ENC, enc_in, keyLength);
    } else {
        memcpy(S_ENC, OPGP_VISA_DEFAULT_KEY, 16);
    }

    if (mac_in) {
        memcpy(S_MAC, mac_in, keyLength);
    } else {
        memcpy(S_MAC, OPGP_VISA_DEFAULT_KEY, 16);
    }

    if (dek_in) {
        memcpy(DEK, dek_in, keyLength);
    } else {
        memcpy(DEK, OPGP_VISA_DEFAULT_KEY, 16);
    }

    BYTE deriv = OPGP_DERIVATION_METHOD_NONE;
    if (derivation == 1) deriv = OPGP_DERIVATION_METHOD_VISA2;
    else if (derivation == 2) deriv = OPGP_DERIVATION_METHOD_EMV_CPS11;
    OPGP_ERROR_STATUS s2 = GP211_mutual_authentication(ctx, info, baseKey, S_ENC, S_MAC, DEK, keyLength,
                                                       keyset_ver, key_index, scp, scpImpl, secLevel, deriv, sec);
    return status_ok(s2) ? 0 : -1;
}

static const char* lc_to_string(BYTE lifeCycle, BYTE element) {
    const char *lcLoaded = "loaded";
    const char *lcInstalled = "installed";
    const char *lcSelectable = "selectable";
    const char *lcLocked = "locked";
    const char *lcPersonalized = "personalized";
    const char *lcOpReady = "op-ready";
    const char *lcInitialized = "initialized";
    const char *lcSecured = "secured";
    const char *lcCardLocked = "card-locked";
    const char *lcTerminated = "terminated";

    const char *lifeCycleState = "unknown";

    switch (element) {
        case GP211_STATUS_LOAD_FILES:
        case GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES:
            if ((lifeCycle & GP211_LIFE_CYCLE_LOAD_FILE_LOADED) == GP211_LIFE_CYCLE_LOAD_FILE_LOADED) {
                lifeCycleState = lcLoaded;
            }
            break;
        case GP211_STATUS_APPLICATIONS:
            if ((lifeCycle & GP211_LIFE_CYCLE_APPLICATION_INSTALLED) == GP211_LIFE_CYCLE_APPLICATION_INSTALLED) {
                lifeCycleState = lcInstalled;
            }
            if ((lifeCycle & GP211_LIFE_CYCLE_APPLICATION_SELECTABLE) == GP211_LIFE_CYCLE_APPLICATION_SELECTABLE) {
                lifeCycleState = lcSelectable;
            }
            if ((lifeCycle & GP211_LIFE_CYCLE_SECURITY_DOMAIN_PERSONALIZED)  == GP211_LIFE_CYCLE_SECURITY_DOMAIN_PERSONALIZED) {
                lifeCycleState = lcPersonalized;
            }
            if ((lifeCycle & GP211_LIFE_CYCLE_APPLICATION_LOCKED) == GP211_LIFE_CYCLE_APPLICATION_LOCKED) {
                lifeCycleState = lcLocked;
            }
            break;
        case GP211_STATUS_ISSUER_SECURITY_DOMAIN:
            if ((lifeCycle & GP211_LIFE_CYCLE_CARD_OP_READY) == GP211_LIFE_CYCLE_CARD_OP_READY) {
                lifeCycleState = lcOpReady;
            }
            if ((lifeCycle & GP211_LIFE_CYCLE_CARD_INITIALIZED) == GP211_LIFE_CYCLE_CARD_INITIALIZED) {
                lifeCycleState = lcInitialized;
            }
            if ((lifeCycle & GP211_LIFE_CYCLE_CARD_SECURED)  == GP211_LIFE_CYCLE_CARD_SECURED) {
                lifeCycleState = lcSecured;
            }
            if ((lifeCycle & GP211_LIFE_CYCLE_CARD_LOCKED) == GP211_LIFE_CYCLE_CARD_LOCKED) {
                lifeCycleState = lcCardLocked;
            }
            if ((lifeCycle & GP211_LIFE_CYCLE_CARD_TERMINATED) == GP211_LIFE_CYCLE_CARD_TERMINATED) {
                lifeCycleState = lcTerminated;
            }
            break;
        default:
            break;
    }

    return lifeCycleState;
}

// Stringify privilege bitfield similar to gpshell.c:privilegesToString
static void privileges_to_string(DWORD privileges, char *out, size_t outlen) {
    struct { DWORD bit; const char *name; } map[] = {
        { GP211_SECURITY_DOMAIN, "sd" },
        { GP211_DAP_VERIFICATION, "dap-verif" },
        { GP211_DELEGATED_MANAGEMENT, "delegated-mgmt" },
        { GP211_CARD_MANAGER_LOCK_PRIVILEGE, "cm-lock" },
        { GP211_CARD_MANAGER_TERMINATE_PRIVILEGE, "cm-terminate" },
        { GP211_DEFAULT_SELECTED_CARD_RESET_PRIVILEGE, "default-selected" },
        { GP211_PIN_CHANGE_PRIVILEGE, "pin-change" },
        { GP211_MANDATED_DAP_VERIFICATION, "mandated-dap" },
        { GP211_TRUSTED_PATH, "trusted-path" },
        { GP211_AUTHORIZED_MANAGEMENT, "authorized-mgmt" },
        { GP211_TOKEN_VERIFICATION, "token-mgmt" },
        { GP211_GLOBAL_DELETE, "global-delete" },
        { GP211_GLOBAL_LOCK, "global-lock" },
        { GP211_GLOBAL_REGISTRY, "global-registry" },
        { GP211_FINAL_APPLICATION, "final-application" },
        { GP211_GLOBAL_SERVICE, "global-service" },
        { GP211_RECEIPT_GENERATION, "receipt-generation" },
        { GP211_CIPHERED_LOAD_FILE_DATA_BLOCK, "ciphered-load-file-data-block" },
        { GP211_CONTACTLESS_ACTIVATION, "contactless-activation" },
        { GP211_CONTACTLESS_SELF_ACTIVATION, "contactless-self-activation" },
    };

    if (!out || outlen == 0) return;
    out[0] = '\0';
    size_t used = 0;
    int first = 1;
    for (size_t i = 0; i < sizeof(map)/sizeof(map[0]); ++i) {
        if ((privileges & map[i].bit) == map[i].bit) {
            const char *name = map[i].name;
            size_t nlen = strlen(name);
            // add separator if not first
            if (!first) {
                if (used + 1 < outlen) { out[used++] = ','; }
            }
            first = 0;
            // copy name
            for (size_t j = 0; j < nlen && used + 1 < outlen; ++j) {
                out[used++] = name[j];
            }
            if (used < outlen) out[used] = '\0';
        }
    }
    if (first) {
        // no bits matched
        snprintf(out, outlen, "none");
    }
}

static int aid_equal(const OPGP_AID *a, const OPGP_AID *b) {
    if (a->AIDLength != b->AIDLength) return 0;
    return memcmp(a->AID, b->AID, a->AIDLength) == 0;
}

static void aid_to_hex_str(const OPGP_AID *a, char *out, size_t outlen) {
    if (!out || outlen == 0) return;
    size_t need = (size_t)a->AIDLength * 2 + 1;
    if (outlen < need) { out[0] = '\0'; return; }
    size_t pos = 0;
    for (size_t i = 0; i < (size_t)a->AIDLength; ++i) {
        snprintf(out + pos, outlen - pos, "%02X", a->AID[i]);
        pos += 2;
    }
    out[pos] = '\0';
}

static int cmd_list_apps(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    GP211_APPLICATION_DATA apps[256];
    GP211_APPLICATION_DATA isds[64];
    GP211_APPLICATION_DATA lfs[256];
    GP211_EXECUTABLE_MODULES_DATA mods[128];

    DWORD apps_len = sizeof(apps)/sizeof(apps[0]);
    DWORD isds_len = sizeof(isds)/sizeof(isds[0]);
    DWORD lfs_len  = sizeof(lfs)/sizeof(lfs[0]);
    DWORD mods_len = sizeof(mods)/sizeof(mods[0]);

    OPGP_ERROR_STATUS s;

    s = GP211_get_status(ctx, info, sec, GP211_STATUS_APPLICATIONS, GP211_STATUS_FORMAT_NEW, apps, NULL, &apps_len);
    if (!status_ok(s)) { fprintf(stderr, "GET STATUS (applications) failed\n"); return -1; }

    s = GP211_get_status(ctx, info, sec, GP211_STATUS_ISSUER_SECURITY_DOMAIN, GP211_STATUS_FORMAT_NEW, isds, NULL, &isds_len);
    if (!status_ok(s)) { fprintf(stderr, "GET STATUS (issuer security domain) failed\n"); return -1; }

    s = GP211_get_status(ctx, info, sec, GP211_STATUS_LOAD_FILES, GP211_STATUS_FORMAT_NEW, lfs, NULL, &lfs_len);
    if (!status_ok(s)) { fprintf(stderr, "GET STATUS (load files) failed\n"); return -1; }

    s = GP211_get_status(ctx, info, sec, GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES, GP211_STATUS_FORMAT_NEW, NULL, mods, &mods_len);
    if (!status_ok(s)) { fprintf(stderr, "GET STATUS (load files and executable modules) failed\n"); return -1; }

    // Collect distinct Security Domains (by associatedSecurityDomainAID) from all results.
    OPGP_AID sds[256];
    DWORD sd_count = 0;

    #define ADD_SD_IF_PRESENT(_aid) do { \
        if ((_aid).AIDLength) { \
            int found = 0; \
            for (DWORD _k = 0; _k < sd_count; ++_k) { \
                if (aid_equal(&sds[_k], &(_aid))) { found = 1; break; } \
            } \
            if (!found && sd_count < (DWORD)(sizeof(sds)/sizeof(sds[0]))) { \
                sds[sd_count++] = (_aid); \
            } \
        } \
    } while(0)

    for (DWORD i = 0; i < apps_len; ++i) ADD_SD_IF_PRESENT(apps[i].associatedSecurityDomainAID);
    for (DWORD i = 0; i < isds_len; ++i) ADD_SD_IF_PRESENT(isds[i].associatedSecurityDomainAID);
    for (DWORD i = 0; i < lfs_len;  ++i) ADD_SD_IF_PRESENT(lfs[i].associatedSecurityDomainAID);
    for (DWORD i = 0; i < mods_len; ++i) ADD_SD_IF_PRESENT(mods[i].associatedSecurityDomainAID);

    #undef ADD_SD_IF_PRESENT

    printf("== security domains ==\n");
    if (sd_count == 0) {
        printf("(none)\n");
        return 0;
    }

    for (DWORD sd_i = 0; sd_i < sd_count; ++sd_i) {
        char sd_hex[64];
        aid_to_hex_str(&sds[sd_i], sd_hex, sizeof(sd_hex));

        // Print SD header line; prefer info from ISD listing when matching.
        const GP211_APPLICATION_DATA *sd_info = NULL;
        for (DWORD i = 0; i < isds_len; ++i) {
            if (aid_equal(&isds[i].aid, &sds[sd_i]) || aid_equal(&isds[i].associatedSecurityDomainAID, &sds[sd_i])) {
                sd_info = &isds[i];
                break;
            }
        }

        if (sd_info) {
            printf("SD %s lc=%s", sd_hex, lc_to_string(sd_info->lifeCycleState, GP211_STATUS_ISSUER_SECURITY_DOMAIN));
            if (sd_info->privileges) {
                char pbuf[512];
                privileges_to_string(sd_info->privileges, pbuf, sizeof(pbuf));
                printf(" priv=[%s]", pbuf);
            }
            printf("\n");
        } else {
            printf("SD %s\n", sd_hex);
        }

        // Applications under this SD
        int any_apps = 0;
        for (DWORD i = 0; i < apps_len; ++i) {
            if (!aid_equal(&apps[i].associatedSecurityDomainAID, &sds[sd_i])) continue;
            if (!any_apps) { printf("  Applications:\n"); any_apps = 1; }
            printf("    ");
            print_aid(&apps[i].aid);
            printf(" lc=%s", lc_to_string(apps[i].lifeCycleState, GP211_STATUS_APPLICATIONS));
            if (apps[i].privileges) {
                char pbuf[512];
                privileges_to_string(apps[i].privileges, pbuf, sizeof(pbuf));
                printf(" priv=[%s]", pbuf);
            }
            if (apps[i].versionNumber[0] || apps[i].versionNumber[1]) {
                printf(" ver=%u.%u", apps[i].versionNumber[0], apps[i].versionNumber[1]);
            }
            printf("\n");
        }

        // Load files under this SD (with modules)
        int any_lf = 0;
        for (DWORD i = 0; i < lfs_len; ++i) {
            if (!aid_equal(&lfs[i].associatedSecurityDomainAID, &sds[sd_i])) continue;
            if (!any_lf) { printf("  Load files:\n"); any_lf = 1; }

            printf("    ");
            print_aid(&lfs[i].aid);
            printf(" lc=%s", lc_to_string(lfs[i].lifeCycleState, GP211_STATUS_LOAD_FILES));
            if (lfs[i].versionNumber[0] || lfs[i].versionNumber[1]) {
                printf(" ver=%u.%u", lfs[i].versionNumber[0], lfs[i].versionNumber[1]);
            }
            printf("\n");

            // modules for this load file (from GET STATUS 0x10)
            for (DWORD m = 0; m < mods_len; ++m) {
                if (!aid_equal(&mods[m].aid, &lfs[i].aid)) continue;
                if (mods[m].numExecutableModules > 0) {
                    printf("      Modules:\n");
                    for (DWORD j = 0;
                         j < mods[m].numExecutableModules &&
                         j < (DWORD)(sizeof(mods[m].executableModules)/sizeof(mods[m].executableModules[0]));
                         ++j) {
                        printf("        ");
                        print_aid(&mods[m].executableModules[j]);
                        printf("\n");
                    }
                }
                break;
            }
        }

        if (!any_apps && !any_lf) {
            printf("  (no applications or load files)\n");
        }
    }

    return 0;
}

static const char* key_type_to_string(BYTE type) {
    switch (type) {
        case 0x80: return "DES";
        case 0x85: return "Pre-Shared Key TLS";
        case 0x88: return "AES";
        case 0x89: return "SM4";
        case 0xA0: return "RSA Public Key - e";
        case 0xA1: return "RSA Public Key - N";
        case 0xA2: return "RSA Private Key - N";
        case 0xA3: return "RSA Private Key - d";
        case 0xA4: return "RSA Private Key - CR P";
        case 0xA5: return "RSA Private Key - CR Q";
        case 0xA6: return "RSA Private Key - CR PQ";
        case 0xA7: return "RSA Private Key - CR DP1";
        case 0xA8: return "RSA Private Key - CR DQ1";
        default: return NULL;
    }
}

static const char* key_access_to_string(BYTE access) {
    switch (access) {
        case 0x00: return "Security Domain and Application";
        case 0x01: return "Security Domain";
        case 0x02: return "Application";
        default: return NULL;
    }
}

static void key_usage_to_string(unsigned short usage, char *out, size_t outlen) {
    if (!out || outlen == 0) return;
    out[0] = '\0';
    size_t used = 0;
    int found = 0;

    BYTE firstByte = (BYTE)((usage >> 8) & 0xFF);
    BYTE secondByte = (BYTE)(usage & 0xFF);

    // Map first byte (leftmost)
    const char *firstByteStr = NULL;
    switch (firstByte) {
        case 0x14: firstByteStr = "C-MAC"; break;
        case 0x24: firstByteStr = "R-MAC"; break;
        case 0x34: firstByteStr = "C-MAC + R-MAC"; break;
        case 0x18: firstByteStr = "C-ENC"; break;
        case 0x28: firstByteStr = "R-ENC"; break;
        case 0x38: firstByteStr = "C-ENC + R-ENC"; break;
        case 0x48: firstByteStr = "C-DEK"; break;
        case 0x88: firstByteStr = "R-DEK"; break;
        case 0xC8: firstByteStr = "C-DEK + R-DEK"; break;
        case 0x82: firstByteStr = "PK.SD.AUT"; break;
        case 0x42: firstByteStr = "SK.SD.AUT"; break;
        case 0x81: firstByteStr = "Token"; break;
        case 0x44: firstByteStr = "Receipt"; break;
        case 0x84: firstByteStr = "DAP"; break;
    }

    if (firstByteStr) {
        size_t len = strlen(firstByteStr);
        if (used + len < outlen) {
            strcpy(out + used, firstByteStr);
            used += len;
            found = 1;
        }
    }

    // Map second byte (rightmost) - only 0x80 is defined
    if (secondByte == 0x80) {
        const char *secondByteStr = "Key Agreement (KAT)";
        size_t len = strlen(secondByteStr);
        if (found && used + 2 < outlen) {
            strcpy(out + used, ", ");
            used += 2;
        }
        if (used + len < outlen) {
            strcpy(out + used, secondByteStr);
            used += len;
            found = 1;
        }
    }

    if (!found) {
        snprintf(out, outlen, "0x%04X", usage);
    }
}

// Sort by (kv, idx)
static int key_info_cmp(const void *pa, const void *pb) {
    const GP211_KEY_INFORMATION *a = pa;
    const GP211_KEY_INFORMATION *b = pb;
    if (a->keySetVersion != b->keySetVersion) return (int)a->keySetVersion - (int)b->keySetVersion;
    return (int)a->keyIndex - (int)b->keyIndex;
}

static int cmd_list_keys(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    GP211_KEY_INFORMATION infos[64]; DWORD ilen;
    BYTE keyIndex = 0;
    OPGP_ERROR_STATUS s;

    // Collect all keys first so we can sort & group nicely
    GP211_KEY_INFORMATION all[512];
    DWORD all_len = 0;

    // Loop until OPGP_ISO7816_ERROR_DATA_NOT_FOUND is returned
    while (1) {
        ilen = sizeof(infos)/sizeof(infos[0]);
        memset(infos, 0, sizeof(infos));
        s = GP211_get_key_information_templates(ctx, info, sec, keyIndex, infos, &ilen);

        // Check specifically for DATA_NOT_FOUND - this ends the loop normally
        if (s.errorCode == OPGP_ISO7816_ERROR_DATA_NOT_FOUND) {
            break;
        }

        // All other errors should be checked with status_ok
        if (!status_ok(s)) {
            return -1;
        }

        // Append key information
        for (DWORD i = 0; i < ilen; i++) {
            if (all_len < (DWORD)(sizeof(all) / sizeof(all[0]))) {
                all[all_len++] = infos[i];
            }
        }

        // Move to next key index for the next iteration
        keyIndex++;
    }

    printf("== keys ==\n");
    if (all_len == 0) {
        printf("(none)\n");
        return 0;
    }


    qsort(all, all_len, sizeof(all[0]), key_info_cmp);

    // Print grouped by KV
    int current_kv = -1;
    for (DWORD i = 0; i < all_len; i++) {
        if (current_kv != (int)all[i].keySetVersion) {
            current_kv = (int)all[i].keySetVersion;
            printf("kv=%d:\n", current_kv);
        }

        printf("  idx=%u ", all[i].keyIndex);

        const char *typeStr = key_type_to_string(all[i].keyType);
        if (typeStr) {
            printf("type=%s ", typeStr);
        } else {
            printf("type=0x%02X ", all[i].keyType);
        }

        printf("len=%u", all[i].keyLength);

        if (all[i].extended) {
            char usageBuf[256];
            key_usage_to_string(all[i].keyUsage, usageBuf, sizeof(usageBuf));
            printf(" usage=%s", usageBuf);

            const char *accessStr = key_access_to_string(all[i].keyAccess);
            if (accessStr) {
                printf(" access=%s", accessStr);
            } else {
                printf(" access=0x%02X", all[i].keyAccess);
            }
        }

        printf("\n");
    }

    return 0;
}

static int cmd_install(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec,
                       int argc, char **argv) {
    int load_only = 0;
    int install_only = 0;
    DWORD v_data_limit = 0, nv_data_limit = 0;
    const char *dap_hex = NULL; const char *applet_aid_hex=NULL; const char *module_aid_hex=NULL; const char *priv_list=NULL; const char *params_hex=NULL;
    const char *load_token_hex = NULL; const char *install_token_hex = NULL; const char *load_file_hash_hex = NULL;
    const char *load_file_aid_hex = NULL;
    int ai = 0;
    for (; ai < argc; ++ai) {
        if (strcmp(argv[ai], "--load-only") == 0) load_only = 1;
        else if (strcmp(argv[ai], "--install-only") == 0) install_only = 1;
        else if (strcmp(argv[ai], "--dap") == 0 && ai+1 < argc) { dap_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--load-token") == 0 && ai+1 < argc) { load_token_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--install-token") == 0 && ai+1 < argc) { install_token_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--hash") == 0 && ai+1 < argc) { load_file_hash_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--load-file") == 0 && ai+1 < argc) { load_file_aid_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--applet") == 0 && ai+1 < argc) { applet_aid_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--module") == 0 && ai+1 < argc) { module_aid_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--priv") == 0 && ai+1 < argc) { priv_list = argv[++ai]; }
        else if (strcmp(argv[ai], "--v-data-limit") == 0 && ai+1 < argc) { v_data_limit = (DWORD)atoi(argv[++ai]); }
        else if (strcmp(argv[ai], "--nv-data-limit") == 0 && ai+1 < argc) { nv_data_limit = (DWORD)atoi(argv[++ai]); }
        else if (strcmp(argv[ai], "--params") == 0 && ai+1 < argc) { params_hex = argv[++ai]; }
        else break;
    }
    if (ai >= argc) { fprintf(stderr, "install: missing <cap-file>\n"); return -1; }
    const char *capfile = argv[ai++];

    // Validate mutually exclusive flags
    if (load_only && install_only) {
        fprintf(stderr, "install: --load-only and --install-only are mutually exclusive\n");
        return -1;
    }

    // Validate --install-only requirements
    if (install_only) {
        if (!load_file_aid_hex) {
            fprintf(stderr, "install: --install-only requires --load-file <AIDhex>\n");
            return -1;
        }
        if (!module_aid_hex) {
            fprintf(stderr, "install: --install-only requires --module <AIDhex>\n");
            return -1;
        }
        if (!applet_aid_hex) {
            fprintf(stderr, "install: --install-only requires --applet <AIDhex>\n");
            return -1;
        }
    }

    GP211_DAP_BLOCK dapBlocks[1]; DWORD dapCount = 0;
    // Use the ISD AID that was selected during connection/authentication, without probing via GET DATA.
    unsigned char sdAid[16]; DWORD sdAidLen = 0;
    if (g_selected_isd_len > 0 && g_selected_isd_len <= sizeof(sdAid)) {
        memcpy(sdAid, g_selected_isd, g_selected_isd_len);
        sdAidLen = g_selected_isd_len;
    } else {
        memcpy(sdAid, GP231_ISD_AID, 7);
        sdAidLen = 7;
    }

    // Parse generic DAP signature if provided
    if (dap_hex) {
        unsigned char sig_buf[256]; size_t sig_len = sizeof(sig_buf);

        // Check if it's a file path (starts with '@')
        if (dap_hex[0] == '@') {
            const char *filepath = dap_hex + 1;
            FILE *f = fopen(filepath, "rb");
            if (!f) { fprintf(stderr, "Failed to open DAP signature file: %s\n", filepath); return -1; }
            sig_len = fread(sig_buf, 1, sizeof(sig_buf), f);
            fclose(f);
            if (sig_len == 0) { fprintf(stderr, "Empty DAP signature file\n"); return -1; }
        } else {
            // Parse as hex string
            if (hex_to_bytes(dap_hex, sig_buf, &sig_len) != 0) { fprintf(stderr, "Invalid DAP signature hex\n"); return -1; }
        }

        // Fill in DAP block with signature and SD AID
        memcpy(dapBlocks[0].securityDomainAID, sdAid, sdAidLen);
        dapBlocks[0].securityDomainAIDLength = (BYTE)sdAidLen;
        memcpy(dapBlocks[0].signature, sig_buf, sig_len);
        dapBlocks[0].signatureLength = (BYTE)sig_len;
        dapCount = 1;
    }

    // Read CAP load file parameters to obtain the package AID (unless --install-only)
    OPGP_LOAD_FILE_PARAMETERS lfp; memset(&lfp,0,sizeof(lfp));
    unsigned char load_file_aid[16]; size_t load_file_aid_len = 0;

    if (install_only) {
        // Parse load file AID from command line for --install-only mode
        load_file_aid_len = sizeof(load_file_aid);
        if (hex_to_bytes(load_file_aid_hex, load_file_aid, &load_file_aid_len) != 0) {
            fprintf(stderr, "Invalid --load-file AID\n");
            return -1;
        }
    } else {
        // Read CAP file parameters for normal or --load-only mode
        if (!status_ok(OPGP_read_executable_load_file_parameters((char*)capfile, &lfp))) {
            fprintf(stderr, "Failed to read CAP load file parameters\n");
            return -1;
        }

        // Parse optional load file hash
        BYTE loadFileHash[64]; memset(loadFileHash, 0, sizeof(loadFileHash));
        BYTE *loadFileHashPtr = NULL;
        if (load_file_hash_hex) {
            size_t hash_len = sizeof(loadFileHash);
            if (hex_to_bytes(load_file_hash_hex, loadFileHash, &hash_len) != 0) {
                fprintf(stderr, "Invalid load file hash hex\n");
                return -1;
            }
            // Only first 20 bytes are used by GP211_install_for_load
            loadFileHashPtr = loadFileHash;
        }

        // Parse optional load token
        BYTE loadToken[128]; memset(loadToken, 0, sizeof(loadToken));
        BYTE *loadTokenPtr = NULL;
        if (load_token_hex) {
            size_t token_len = sizeof(loadToken);
            if (hex_to_bytes(load_token_hex, loadToken, &token_len) != 0 || token_len != 128) {
                fprintf(stderr, "Invalid load token hex (must be 128 bytes)\n");
                return -1;
            }
            loadTokenPtr = loadToken;
        }

        if (!status_ok(GP211_install_for_load(ctx, info, sec,
                lfp.loadFileAID.AID, lfp.loadFileAID.AIDLength,
                sdAid, sdAidLen,
                loadFileHashPtr, loadTokenPtr,
                lfp.loadFileSize, v_data_limit, nv_data_limit))) {
            return -1;
        }

        GP211_RECEIPT_DATA receipt; DWORD receiptAvail=0; memset(&receipt, 0, sizeof(receipt));
        if (!status_ok(GP211_load(ctx, info, sec, dapCount?dapBlocks:NULL, dapCount, (char*)capfile, &receipt, &receiptAvail, NULL))) {
            return -1;
        }
        if (load_only) { return 0; }
    }

    unsigned char applet_aid[16]; size_t applet_len=0;
    if (applet_aid_hex) {
        applet_len = sizeof(applet_aid);
        if (hex_to_bytes(applet_aid_hex, applet_aid, &applet_len)!=0) {
            fprintf(stderr, "Invalid --applet AID\n");
            return -1;
        }
    }
    unsigned char module_aid[16]; size_t module_len=0;
    if (module_aid_hex) {
        module_len = sizeof(module_aid);
        if (hex_to_bytes(module_aid_hex, module_aid, &module_len)!=0) {
            fprintf(stderr, "Invalid --module AID\n");
            return -1;
        }
    }

    unsigned char inst_param[256]; size_t inst_param_len=0;
    if (params_hex) {
        inst_param_len = sizeof(inst_param);
        if (hex_to_bytes(params_hex, inst_param, &inst_param_len)!=0) {
            fprintf(stderr, "Invalid --params hex\n");
            return -1;
        }
    }

    // Parse optional install token
    BYTE installToken[128]; memset(installToken,0,sizeof(installToken));
    BYTE *installTokenPtr = NULL;
    if (install_token_hex) {
        size_t token_len = sizeof(installToken);
        if (hex_to_bytes(install_token_hex, installToken, &token_len) != 0 || token_len != 128) {
            fprintf(stderr, "Invalid install token hex (must be 128 bytes)\n");
            return -1;
        }
        installTokenPtr = installToken;
    }

    GP211_RECEIPT_DATA rec2; DWORD rec2Avail=0; memset(&rec2,0,sizeof(rec2));
    BYTE privileges = 0x00; // first 8 bits only as per requirement
    if (priv_list) {
        if (parse_privs_byte(priv_list, &privileges) != 0) {
            return -1;
        }
    }

    // Determine which load file AID to use
    PBYTE effectiveLoadFileAID;
    DWORD effectiveLoadFileAIDLength;
    if (install_only) {
        effectiveLoadFileAID = load_file_aid;
        effectiveLoadFileAIDLength = (DWORD)load_file_aid_len;
    } else {
        effectiveLoadFileAID = lfp.loadFileAID.AID;
        effectiveLoadFileAIDLength = lfp.loadFileAID.AIDLength;
    }

    if (applet_len || module_len) {
        if (applet_len == 0 && module_len > 0) {
            // Use module AID also as applet instance AID
            memcpy(applet_aid, module_aid, module_len);
            applet_len = module_len;
        } else if (module_len == 0 && applet_len > 0) {
            // Use applet AID also as module/class AID
            memcpy(module_aid, applet_aid, applet_len);
            module_len = applet_len;
        }

        if (!status_ok(GP211_install_for_install_and_make_selectable(ctx, info, sec,
                effectiveLoadFileAID, effectiveLoadFileAIDLength,
                module_aid, (DWORD)module_len,
                applet_aid, (DWORD)applet_len,
                privileges, v_data_limit, nv_data_limit,
                inst_param_len ? inst_param : NULL, (DWORD)inst_param_len,
                installTokenPtr, &rec2, &rec2Avail))) {
            return -1;
        }
    } else {
        // Neither provided: iterate over all applets from CAP
        if (install_only) {
            fprintf(stderr, "INSTALL: --install-only requires explicit --applet and --module\n");
            return -1;
        }
        int i = 0; int did_any = 0;
        while (lfp.appletAIDs[i].AIDLength) {
            did_any = 1;
            PBYTE aid = (PBYTE)lfp.appletAIDs[i].AID;
            DWORD aidLen = lfp.appletAIDs[i].AIDLength;
            if (!status_ok(GP211_install_for_install_and_make_selectable(ctx, info, sec,
                    effectiveLoadFileAID, effectiveLoadFileAIDLength,
                    aid, aidLen,
                    aid, aidLen,
                    privileges, v_data_limit, nv_data_limit,
                    inst_param_len ? inst_param : NULL, (DWORD)inst_param_len,
                    installTokenPtr, &rec2, &rec2Avail))) {
                fprintf(stderr, "Failed for applet index %d\n", i);
                return -1;
            }
            i++;
        }
        if (!did_any) {
            fprintf(stderr, "INSTALL: No applets found in CAP to install\n");
            return -1;
        }
    }
    return 0;
}

static int cmd_delete(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, const char *aid_hex) {
    if (!aid_hex) { fprintf(stderr, "delete: missing <AIDhex>\n"); return -1; }
    unsigned char aidb[16]; size_t alen=sizeof(aidb);
    if (hex_to_bytes(aid_hex, aidb, &alen)!=0) { fprintf(stderr, "Invalid AID hex\n"); return -1; }
    OPGP_AID a; memset(&a,0,sizeof(a)); a.AIDLength=(BYTE)alen; memcpy(a.AID, aidb, alen);
    GP211_RECEIPT_DATA rec; DWORD recLen=0; memset(&rec,0,sizeof(rec));
    if (!status_ok(GP211_delete_application(ctx, info, sec, &a, 1, &rec, &recLen))) {
        return -1;
    }
    return 0;
}

static int cmd_put_key(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    BYTE setVer=0, idx=0, newSetVer=0; const char *type="aes"; const char *hexkey=NULL; const char *pem=NULL; char *pass=NULL;
    for (int i=0;i<argc;i++) {
        if (strcmp(argv[i], "--kv")==0 && i+1<argc) setVer=(BYTE)atoi(argv[++i]);
        else if (strcmp(argv[i], "--idx")==0 && i+1<argc) idx=(BYTE)atoi(argv[++i]);
        else if (strcmp(argv[i], "--new-kv")==0 && i+1<argc) newSetVer=(BYTE)atoi(argv[++i]);
        else if (strcmp(argv[i], "--type")==0 && i+1<argc) type=argv[++i];
        else if (strcmp(argv[i], "--key")==0 && i+1<argc) hexkey=argv[++i];
        else if (strcmp(argv[i], "--pem")==0 && i+1<argc) { pem=argv[++i]; char *c=strchr((char*)pem, ':'); if (c){ *c='\0'; pass=c+1; } }
    }
    if (strcmp(type, "rsa")==0) {
        if (!pem) { fprintf(stderr, "put-key rsa: --pem <file>[:pass] required\n"); return -1; }
        if (!status_ok(GP211_put_rsa_key(ctx, info, sec, setVer, idx, newSetVer, (char*)pem, pass))) {
            return -1;
        }
        return 0;
    }
    if (strcmp(type, "aes")==0) {
        if (!hexkey) { fprintf(stderr, "put-key aes: --key <hex> required\n"); return -1; }
        unsigned char k[32]; size_t klen=sizeof(k);
        if (hex_to_bytes(hexkey, k, &klen)!=0 || (klen!=16 && klen!=24 && klen!=32)) {
            fprintf(stderr, "Invalid AES key len\n");
            return -1;
        }
        if (!status_ok(GP211_put_aes_key(ctx, info, sec, setVer, idx, newSetVer, k, (DWORD)klen))) {
            return -1;
        }
        return 0;
    }
    if (strcmp(type, "3des")==0) {
        if (!hexkey) { fprintf(stderr, "put-key 3des: --key <hex> required\n"); return -1; }
        unsigned char k[16]; size_t klen=sizeof(k);
        if (hex_to_bytes(hexkey, k, &klen)!=0 || klen!=16) {
            fprintf(stderr, "3DES key must be 16 hex bytes\n");
            return -1;
        }
        if (!status_ok(GP211_put_3des_key(ctx, info, sec, setVer, idx, newSetVer, k))) {
            return -1;
        }
        return 0;
    }
    fprintf(stderr, "put-key: unsupported --type '%s' (use 3des|aes|rsa). For Secure Channel keys use put-sc-keys.\n", type);
    return -1;
}

static int cmd_put_auth(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    BYTE setVer=1, newSetVer=1; const char *base=NULL, *enc=NULL, *mac=NULL, *dek=NULL;
    const char *type="aes", *derive="none";
    for (int i=0;i<argc;i++) {
        if (strcmp(argv[i], "--kv")==0 && i+1<argc) setVer=(BYTE)atoi(argv[++i]);
        else if (strcmp(argv[i], "--new-kv")==0 && i+1<argc) newSetVer=(BYTE)atoi(argv[++i]);
        else if (strcmp(argv[i], "--base")==0 && i+1<argc) base=argv[++i];
        else if (strcmp(argv[i], "--key")==0 && i+1<argc) base=argv[++i];
        else if (strcmp(argv[i], "--enc")==0 && i+1<argc) enc=argv[++i];
        else if (strcmp(argv[i], "--mac")==0 && i+1<argc) mac=argv[++i];
        else if (strcmp(argv[i], "--dek")==0 && i+1<argc) dek=argv[++i];
        else if (strcmp(argv[i], "--type")==0 && i+1<argc) type=argv[++i];
        else if (strcmp(argv[i], "--derive")==0 && i+1<argc) derive=argv[++i];
    }
    if (base && (enc || mac || dek)) {
        fprintf(stderr, "put-auth: use either --base/--key OR all of --enc/--mac/--dek\n");
        return -1;
    }
    if (!base && !(enc && mac && dek)) {
        fprintf(stderr, "put-auth: specify either --base/--key <hex> or --enc/--mac/--dek <hex>\n");
        return -1;
    }

    // Determine key type
    BYTE keyType = GP211_KEY_TYPE_AES;
    if (strcmp(type, "3des")==0) {
        keyType = GP211_KEY_TYPE_DES;
    } else if (strcmp(type, "aes")==0) {
        keyType = GP211_KEY_TYPE_AES;
    } else {
        fprintf(stderr, "put-auth: unsupported --type '%s' (use aes|3des)\n", type);
        return -1;
    }

    // Determine derivation method
    BYTE derivation = OPGP_DERIVATION_METHOD_NONE;
    if (strcmp(derive, "emv")==0) {
        derivation = OPGP_DERIVATION_METHOD_EMV_CPS11;
    } else if (strcmp(derive, "visa2")==0) {
        derivation = OPGP_DERIVATION_METHOD_VISA2;
    } else if (strcmp(derive, "none")!=0) {
        fprintf(stderr, "put-auth: unsupported --derive '%s' (use none|emv|visa2)\n", derive);
        return -1;
    }

    // Validate derivation usage
    if ((enc || mac || dek) && derivation != OPGP_DERIVATION_METHOD_NONE) {
        fprintf(stderr, "put-auth: --derive cannot be used when --enc/--mac/--dek are provided\n");
        return -1;
    }

    if (base) {
        unsigned char b[32]; size_t blen=sizeof(b);
        if (hex_to_bytes(base, b, &blen)!=0 || (blen!=16 && blen!=24 && blen!=32)) {
            fprintf(stderr, "Invalid base key length\n");
            return -1;
        }

        // Apply key derivation if requested
        if (derivation == OPGP_DERIVATION_METHOD_EMV_CPS11) {
            OPGP_ERROR_STATUS s = GP211_EMV_CPS11_derive_keys(ctx, info, sec, b, b, b, b);
            if (!status_ok(s)) {
                fprintf(stderr, "EMV CPS11 key derivation failed\n");
                return -1;
            }
        } else if (derivation == OPGP_DERIVATION_METHOD_VISA2) {
            if (g_selected_isd_len == 0) {
                fprintf(stderr, "VISA2 derivation requires a selected ISD AID\n");
                return -1;
            }
            OPGP_ERROR_STATUS s = GP211_VISA2_derive_keys(ctx, info, sec, g_selected_isd, g_selected_isd_len, b, b, b, b);
            if (!status_ok(s)) {
                fprintf(stderr, "VISA2 key derivation failed\n");
                return -1;
            }
        }

        OPGP_ERROR_STATUS s = GP211_put_secure_channel_keys(ctx, info, sec, setVer, newSetVer, b, NULL, NULL, NULL, (DWORD)blen, keyType);
        if (!status_ok(s)) {
            return -1;
        }
        return 0;
    }
    unsigned char se[32], sm[32], dk[32]; size_t el=sizeof(se), ml=sizeof(sm), dl=sizeof(dk);
    if (hex_to_bytes(enc, se, &el)!=0 || hex_to_bytes(mac, sm, &ml)!=0 || hex_to_bytes(dek, dk, &dl)!=0) {
        fprintf(stderr, "Invalid hex for ENC/MAC/DEK\n");
        return -1;
    }
    if (!((el==ml && ml==dl) && (el==16 || el==24 || el==32))) {
        fprintf(stderr, "Keys must have equal length of 16/24/32 bytes\n");
        return -1;
    }

    OPGP_ERROR_STATUS s = GP211_put_secure_channel_keys(ctx, info, sec, setVer, newSetVer, NULL, se, sm, dk, (DWORD)el, keyType);
    if (!status_ok(s)) {
        return -1;
    }
    return 0;
}

static int cmd_put_dm(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    BYTE setVer=0, newSetVer=0;
    const char *tokenType="rsa";
    const char *receiptType="aes";
    const char *pem=NULL;
    char *pass=NULL;
    const char *receiptKeyHex=NULL;
    BYTE receiptKey[32];
    DWORD keyLength=0;

    // Parse arguments
    for (int i=0; i<argc; i++) {
        if (strcmp(argv[i], "--kv")==0 && i+1<argc) {
            setVer = (BYTE)atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--new-kv")==0 && i+1<argc) {
            newSetVer = (BYTE)atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--token-type")==0 && i+1<argc) {
            tokenType = argv[++i];
        }
        else if (strcmp(argv[i], "--receipt-type")==0 && i+1<argc) {
            receiptType = argv[++i];
        }
        else if (!pem) {
            // First positional argument is PEM file with optional :pass
            pem = argv[i];
            char *c = strchr((char*)pem, ':');
            if (c) {
                *c = '\0';
                pass = c + 1;
            }
        }
        else if (!receiptKeyHex) {
            // Second positional argument is receipt key hex
            receiptKeyHex = argv[i];
        }
    }

    if (!pem) {
        fprintf(stderr, "put-dm: missing PEM file path (use <pem-file>[:pass] <receipt-key-hex>)\n");
        return -1;
    }

    if (!receiptKeyHex) {
        fprintf(stderr, "put-dm: missing receipt key hex (last positional parameter)\n");
        return -1;
    }

    // Parse receipt key
    size_t len = sizeof(receiptKey);
    if (hex_to_bytes(receiptKeyHex, receiptKey, &len) != 0) {
        fprintf(stderr, "put-dm: invalid receipt key hex\n");
        return -1;
    }
    keyLength = (DWORD)len;

    // Map token type string to byte value
    BYTE tokenKeyType;
    if (strcmp(tokenType, "rsa")==0) {
        tokenKeyType = 0xA0; // GP211_KEY_TYPE_RSA_PUB
    } else {
        fprintf(stderr, "put-dm: unsupported --token-type '%s' (use rsa)\n", tokenType);
        return -1;
    }

    // Map receipt type string to byte value
    BYTE receiptKeyType;
    if (strcmp(receiptType, "aes")==0) {
        receiptKeyType = 0x88; // GP211_KEY_TYPE_AES
    } else if (strcmp(receiptType, "des")==0) {
        receiptKeyType = 0x80; // GP211_KEY_TYPE_DES
    } else {
        fprintf(stderr, "put-dm: unsupported --receipt-type '%s' (use aes|des)\n", receiptType);
        return -1;
    }

    // Call GP211_put_delegated_management_keys
    if (!status_ok(GP211_put_delegated_management_keys(ctx, info, sec,
                                                        setVer, newSetVer,
                                                        (char*)pem, pass,
                                                        tokenKeyType, receiptKey, keyLength, receiptKeyType))) {
        return -1;
    }
    return 0;
}

static int cmd_del_key(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    BYTE setVer=0; BYTE idx=0xFF; // 0xFF => delete all keys in set
    for (int i=0;i<argc;i++) {
        if (strcmp(argv[i], "--kv")==0 && i+1<argc) setVer=(BYTE)atoi(argv[++i]);
        else if (strcmp(argv[i], "--idx")==0 && i+1<argc) idx=(BYTE)atoi(argv[++i]);
    }
    if (!status_ok(GP211_delete_key(ctx, info, sec, setVer, idx))) {
        return -1;
    }
    return 0;
}

static int compact_hex(const char *in, char *out, size_t outsz) {
    // Copy only hex digits, ignore spaces and tabs; fail on other chars
    size_t j=0;
    for (const char *p=in; *p; ++p) {
        unsigned char c = (unsigned char)*p;
        if (c==' ' || c=='\t') continue;
        if (!isxdigit(c)) {
            if (c==';' || c==',') break; // caller should split before calling
            return -1;
        }
        if (j+1 >= outsz) return -2;
        out[j++] = (char)toupper(c);
    }
    out[j] = '\0';
    if (j % 2 != 0) return -3;
    return 0;
}

static int is_hex_byte_token(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n > 2) return 0;
    for (size_t i=0;i<n;i++) if (!isxdigit((unsigned char)s[i])) return 0;
    return 1;
}

static int cmd_apdu(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "apdu: missing arguments\n"); return -1; }
    int nostop = 0;
    const int MAX_APDUS = 256;
    char *apdus[MAX_APDUS]; int napdus=0;
    for (int i=0;i<argc;i++) {
        const char *a = argv[i];
        if (strcmp(a, "--nostop")==0 || strcmp(a, "--ignore-errors")==0) { nostop=1; continue; }
        if (strcmp(a, "--auth")==0 || strcmp(a, "--secure")==0) { /* handled in main; skip here */ continue; }
        // Case 1: sequence of hex byte tokens across argv -> one APDU
        if (is_hex_byte_token(a)) {
            char buf[4096]; buf[0]='\0'; size_t bl=0;
            while (i<argc && is_hex_byte_token(argv[i])) {
                const char *b = argv[i];
                size_t bn = strlen(b);
                if (bl + bn >= sizeof(buf)-1) { fprintf(stderr, "APDU too long\n"); return -1; }
                for (size_t t=0;t<bn;t++) buf[bl++] = (char)toupper((unsigned char)b[t]);
                i++;
            }
            i--; // compensate last increment in while
            buf[bl]='\0';
            if (napdus < MAX_APDUS) apdus[napdus++] = strdup(buf);
            continue;
        }
        // Case 2: split by ';' or ',' within the same argument
        char *dup = strdup(a);
        if (!dup) { fprintf(stderr, "oom\n"); return -1; }
        char *save=NULL; char *tok = strtok_r(dup, ";,", &save);
        while (tok) {
            if (napdus < MAX_APDUS) {
                apdus[napdus++] = strdup(tok);
            }
            tok = strtok_r(NULL, ";,", &save);
        }
        free(dup);
        if (napdus >= MAX_APDUS) break;
    }
    if (napdus == 0) { fprintf(stderr, "apdu: no APDUs provided\n"); return -1; }

    int rc = 0;
    for (int k=0;k<napdus;k++) {
        char hexbuf[4096];
        if (compact_hex(apdus[k], hexbuf, sizeof(hexbuf)) != 0) {
            fprintf(stderr, "Invalid hex in APDU %d\n", k+1);
            rc = -1; if (!nostop) { break; } else { continue; }
        }
        unsigned char capdu[APDU_COMMAND_LEN]; size_t clen=sizeof(capdu);
        if (hex_to_bytes(hexbuf, capdu, &clen)!=0) {
            fprintf(stderr, "Invalid hex length in APDU %d\n", k+1);
            rc = -1; if (!nostop) { break; } else { continue; }
        }
        unsigned char rapdu[APDU_RESPONSE_LEN]; DWORD rlen=sizeof(rapdu);
        OPGP_ERROR_STATUS s = GP211_send_APDU(ctx, info, sec, capdu, (DWORD)clen, rapdu, &rlen);
        if (!status_ok(s)) {
            fprintf(stderr, "APDU %d send failed: 0x%08X (%s)\n", k+1, (unsigned int)s.errorCode, s.errorMessage);
            rc = -1; if (!nostop) { break; } else { continue; }
        }
        print_hex(rapdu, rlen); printf("\n");
    }
    for (int k=0;k<napdus;k++) free(apdus[k]);
    return rc;
}

static int cmd_hash(int argc, char **argv) {
    const char *hash_alg = "sha256"; // default
    int ai = 0;
    for (; ai < argc; ++ai) {
        if (strcmp(argv[ai], "--sha1") == 0) { hash_alg = "sha1"; }
        else if (strcmp(argv[ai], "--sha256") == 0 || strcmp(argv[ai], "--sha2-256") == 0) { hash_alg = "sha256"; }
        else if (strcmp(argv[ai], "--sha384") == 0 || strcmp(argv[ai], "--sha2-384") == 0) { hash_alg = "sha384"; }
        else if (strcmp(argv[ai], "--sha512") == 0 || strcmp(argv[ai], "--sha2-512") == 0) { hash_alg = "sha512"; }
        else if (strcmp(argv[ai], "--sm3") == 0) { hash_alg = "sm3"; }
        else break;
    }
    if (ai >= argc) { fprintf(stderr, "hash: missing <cap-file>\n"); return -1; }
    const char *cap = argv[ai++];

    BYTE hashType = GP211_HASH_SHA256;
    DWORD hash_len = 32;
    if (strcmp(hash_alg, "sha1") == 0) { hashType = GP211_HASH_SHA1; hash_len = 20; }
    else if (strcmp(hash_alg, "sha256") == 0) { hashType = GP211_HASH_SHA256; hash_len = 32; }
    else if (strcmp(hash_alg, "sha384") == 0) { hashType = GP211_HASH_SHA384; hash_len = 48; }
    else if (strcmp(hash_alg, "sha512") == 0) { hashType = GP211_HASH_SHA512; hash_len = 64; }
    else if (strcmp(hash_alg, "sm3") == 0) { hashType = GP211_HASH_SM3; hash_len = 32; }

    BYTE hash[64]; memset(hash, 0, sizeof(hash));
    if (!status_ok(GP211_calculate_load_file_data_block_hash((char*)cap, hash, hash_len, hashType))) {
        fprintf(stderr, "hash failed\n"); return -1;
    }
    print_hex(hash, hash_len); printf("\n");
    return 0;
}

static int cmd_dap(int is_rsa, OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    // Parse optional flags
    const char *output_file = NULL;
    int ai = 0;
    while (ai < argc && argv[ai][0] == '-') {
        if (strcmp(argv[ai], "--output") == 0 && ai+1 < argc) { output_file = argv[++ai]; ai++; }
        else break;
    }

    if (is_rsa) {
        if (argc - ai < 3) { fprintf(stderr, "sign-dap rsa [--output <file>] <hash-hex> <sd-aidhex> <pem>[:pass]\n"); return -1; }
        const char *hash_hex = argv[ai++]; const char *sd_hex = argv[ai++]; const char *pem = argv[ai++];
        unsigned char hash[64]; size_t hashlen=sizeof(hash);
        if (hex_to_bytes(hash_hex, hash, &hashlen)!=0) { fprintf(stderr, "Invalid hash hex\n"); return -1; }
        unsigned char sd[16]; size_t sdlen=sizeof(sd); if (hex_to_bytes(sd_hex, sd, &sdlen)!=0) { fprintf(stderr, "Invalid sd-aid\n"); return -1; }
        char pemcopy[512]; strncpy(pemcopy, pem, sizeof(pemcopy)-1); pemcopy[sizeof(pemcopy)-1]='\0'; char *pass=NULL; char *c=strchr(pemcopy,':'); if (c){*c='\0'; pass=c+1;}
        GP211_DAP_BLOCK dap; if (!status_ok(GP211_calculate_rsa_schemeX_DAP(hash, (DWORD)hashlen, sd, (DWORD)sdlen, pemcopy, pass, &dap))) { fprintf(stderr, "calc rsa DAP failed\n"); return -1; }

        if (output_file) {
            FILE *f = fopen(output_file, "wb");
            if (!f) { fprintf(stderr, "Failed to open output file: %s\n", output_file); return -1; }
            fwrite(dap.signature, 1, dap.signatureLength, f);
            fclose(f);
        } else {
            print_hex(dap.signature, dap.signatureLength); printf("\n");
        }
        return 0;
    } else {
        if (argc - ai < 3) { fprintf(stderr, "sign-dap aes [--output <file>] <hash-hex> <sd-aidhex> <hexkey>\n"); return -1; }
        const char *hash_hex = argv[ai++]; const char *sd_hex = argv[ai++]; const char *hexkey = argv[ai++];
        unsigned char hash[64]; size_t hashlen=sizeof(hash);
        if (hex_to_bytes(hash_hex, hash, &hashlen)!=0) { fprintf(stderr, "Invalid hash hex\n"); return -1; }
        unsigned char sd[16]; size_t sdlen=sizeof(sd); if (hex_to_bytes(sd_hex, sd, &sdlen)!=0) { fprintf(stderr, "Invalid sd-aid\n"); return -1; }
        unsigned char key[32]; size_t klen=sizeof(key); if (hex_to_bytes(hexkey, key, &klen)!=0) { fprintf(stderr, "Invalid hexkey\n"); return -1; }
        // Determine SCP based on hash length
        BYTE scp = (hashlen > 20) ? GP211_SCP03 : GP211_SCP02;
        GP211_DAP_BLOCK dap; if (!status_ok(GP211_calculate_DAP(hash, (BYTE)hashlen, sd, (DWORD)sdlen, key, (DWORD)klen, &dap, scp))) { fprintf(stderr, "calc aes DAP failed\n"); return -1; }

        if (output_file) {
            FILE *f = fopen(output_file, "wb");
            if (!f) { fprintf(stderr, "Failed to open output file: %s\n", output_file); return -1; }
            fwrite(dap.signature, 1, dap.signatureLength, f);
            fclose(f);
        } else {
            print_hex(dap.signature, dap.signatureLength); printf("\n");
        }
        return 0;
    }
}

static int cmd_status(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "status: missing element type (isd|sd|app|sd-app)\n"); return -1; }

    const char *element_type = argv[0];
    const char *lc_state = NULL;
    const char *aid_hex = NULL;

    int ai = 1;
    for (; ai < argc; ++ai) {
        if (strcmp(argv[ai], "--lc") == 0 && ai+1 < argc) {
            lc_state = argv[++ai];
        } else {
            aid_hex = argv[ai];
            break;
        }
    }

    if (!aid_hex) { fprintf(stderr, "status: missing <AIDhex>\n"); return -1; }

    // Parse AID
    unsigned char aid[16]; size_t aidlen = sizeof(aid);
    if (hex_to_bytes(aid_hex, aid, &aidlen) != 0) {
        fprintf(stderr, "Invalid AID hex\n");
        return -1;
    }

    // Determine status type and lifecycle state
    BYTE statusType = 0;
    BYTE lifeCycleState = 0;

    if (strcmp(element_type, "isd") == 0) {
        statusType = GP211_STATUS_TYPE_ISSUER_SECURITY_DOMAIN;

        if (!lc_state) {
            fprintf(stderr, "status isd: --lc <state> required (locked|terminated)\n");
            return -1;
        }

        if (strcmp(lc_state, "locked") == 0) {
            lifeCycleState = GP211_LIFE_CYCLE_CARD_LOCKED;
        } else if (strcmp(lc_state, "terminated") == 0) {
            lifeCycleState = GP211_LIFE_CYCLE_CARD_TERMINATED;

            // Display prominent warning for terminated state
            fprintf(stderr, "\n");
            fprintf(stderr, "================================================================================\n");
            fprintf(stderr, "                              *** WARNING ***\n");
            fprintf(stderr, "================================================================================\n");
            fprintf(stderr, "You are about to TERMINATE the Issuer Security Domain!\n");
            fprintf(stderr, "\n");
            fprintf(stderr, "THIS ACTION CANNOT BE UNDONE!\n");
            fprintf(stderr, "The card will be PERMANENTLY TERMINATED and UNUSABLE after this operation.\n");
            fprintf(stderr, "\n");
            fprintf(stderr, "To confirm, please enter the AID again: ");
            fprintf(stderr, "\n> ");

            char confirm[64];
            if (fgets(confirm, sizeof(confirm), stdin)) {
                // Remove trailing newline
                size_t len = strlen(confirm);
                if (len > 0 && confirm[len-1] == '\n') confirm[len-1] = '\0';

                if (strcmp(confirm, aid_hex) != 0) {
                    fprintf(stderr, "AID does not match. Operation cancelled.\n");
                    return 0;
                }
            } else {
                fprintf(stderr, "Failed to read confirmation. Operation cancelled.\n");
                return 0;
            }
            fprintf(stderr, "================================================================================\n");
            fprintf(stderr, "\n");
        } else {
            fprintf(stderr, "status isd: invalid lifecycle state '%s' (use: locked|terminated)\n", lc_state);
            return -1;
        }
    } else if (strcmp(element_type, "sd") == 0) {
        statusType = GP211_STATUS_TYPE_APPLICATIONS;

        if (!lc_state) {
            fprintf(stderr, "status sd: --lc <state> required (personalized|locked)\n");
            return -1;
        }

        if (strcmp(lc_state, "personalized") == 0) {
            lifeCycleState = GP211_LIFE_CYCLE_SECURITY_DOMAIN_PERSONALIZED;
        } else if (strcmp(lc_state, "locked") == 0) {
            lifeCycleState = GP211_LIFE_CYCLE_SECURITY_DOMAIN_LOCKED;
        } else {
            fprintf(stderr, "status sd: invalid lifecycle state '%s' (use: personalized|locked)\n", lc_state);
            return -1;
        }
    } else if (strcmp(element_type, "app") == 0) {
        statusType = GP211_STATUS_TYPE_APPLICATIONS;

        if (!lc_state) {
            fprintf(stderr, "status app: --lc <state> required (locked|selectable)\n");
            return -1;
        }

        if (strcmp(lc_state, "locked") == 0) {
            lifeCycleState = GP211_LIFE_CYCLE_APPLICATION_LOCKED;
        } else if (strcmp(lc_state, "selectable") == 0) {
            lifeCycleState = GP211_LIFE_CYCLE_APPLICATION_SELECTABLE;
        } else {
            fprintf(stderr, "status app: invalid lifecycle state '%s' (use: locked|selectable)\n", lc_state);
            return -1;
        }
    } else if (strcmp(element_type, "sd-app") == 0) {
        statusType = GP211_STATUS_TYPE_SECURITY_DOMAIN_AND_APPLICATIONS;

        if (!lc_state) {
            fprintf(stderr, "status sd-app: --lc <state> required (locked|unlocked)\n");
            return -1;
        }

        if (strcmp(lc_state, "locked") == 0) {
            lifeCycleState = GP211_LIFE_CYCLE_SECURITY_DOMAIN_LOCKED;
        } else if (strcmp(lc_state, "unlocked") == 0) {
            lifeCycleState = 0;
        } else {
            fprintf(stderr, "status app: invalid lifecycle state '%s' (use: locked|unlocked)\n", lc_state);
            return -1;
        }
    } else {
        fprintf(stderr, "status: invalid element type '%s' (use: isd|sd|app|sd-app)\n", element_type);
        return -1;
    }

    // Call GP211_set_status
    if (!status_ok(GP211_set_status(ctx, info, sec, statusType, aid, (DWORD)aidlen, lifeCycleState))) {
        return -1;
    }

    return 0;
}

static int cmd_store(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "store: requires <aid> <data> arguments\n");
        return -1;
    }

    // Parse options
    BYTE encryptionFlags = STORE_DATA_ENCRYPTION_NO_INFORMATION;
    BYTE formatFlags = STORE_DATA_FORMAT_NO_INFORMATION;
    BOOL responseDataExpected = false;

    int i = 0;
    while (i < argc - 2) {  // Leave at least 2 args for aid and data
        const char *arg = argv[i];
        if (strcmp(arg, "--encryption") == 0 || strcmp(arg, "-e") == 0) {
            if (i + 1 >= argc - 2) {
                fprintf(stderr, "store: --encryption requires argument\n");
                return -1;
            }
            i++;
            const char *val = argv[i];
            if (strcmp(val, "noinfo") == 0) {
                encryptionFlags = STORE_DATA_ENCRYPTION_NO_INFORMATION;
            } else if (strcmp(val, "app") == 0) {
                encryptionFlags = STORE_DATA_ENCRYPTION_APPLICATION_DEPENDENT;
            } else if (strcmp(val, "enc") == 0) {
                encryptionFlags = STORE_DATA_ENCRYPTION_ENCRYPTED;
            } else {
                fprintf(stderr, "store: unknown encryption value '%s' (use: noinfo, app, enc)\n", val);
                return -1;
            }
        } else if (strcmp(arg, "--format") == 0 || strcmp(arg, "-f") == 0) {
            if (i + 1 >= argc - 2) {
                fprintf(stderr, "store: --format requires argument\n");
                return -1;
            }
            i++;
            const char *val = argv[i];
            if (strcmp(val, "noinfo") == 0) {
                formatFlags = STORE_DATA_FORMAT_NO_INFORMATION;
            } else if (strcmp(val, "dgi") == 0) {
                formatFlags = STORE_DATA_FORMAT_DGI;
            } else if (strcmp(val, "ber") == 0) {
                formatFlags = STORE_DATA_FORMAT_BER_TLV;
            } else {
                fprintf(stderr, "store: unknown format value '%s' (use: noinfo, dgi, ber)\n", val);
                return -1;
            }
        } else if (strcmp(arg, "--response") == 0 || strcmp(arg, "-r") == 0) {
            if (i + 1 >= argc - 2) {
                fprintf(stderr, "store: --response requires argument\n");
                return -1;
            }
            i++;
            const char *val = argv[i];
            if (strcmp(val, "true") == 0 || strcmp(val, "1") == 0) {
                responseDataExpected = true;
            } else if (strcmp(val, "false") == 0 || strcmp(val, "0") == 0) {
                responseDataExpected = false;
            } else {
                fprintf(stderr, "store: --response expects true/false or 1/0\n");
                return -1;
            }
        } else {
            break;  // Not an option, must be aid
        }
        i++;
    }

    if (argc - i < 2) {
        fprintf(stderr, "store: requires <aid> <data> positional arguments\n");
        return -1;
    }

    const char *aid_hex = argv[i];
    const char *data_str = argv[i + 1];

    // Parse AID
    unsigned char aid[16];
    size_t aidlen = sizeof(aid);
    if (hex_to_bytes(aid_hex, aid, &aidlen) != 0) {
        fprintf(stderr, "store: invalid AID hex string\n");
        return -1;
    }

    // Parse data using compact_hex to support flexible format
    char compacted[8192];
    if (compact_hex(data_str, compacted, sizeof(compacted)) != 0) {
        fprintf(stderr, "store: invalid data hex string\n");
        return -1;
    }

    unsigned char data[4096];
    size_t datalen = sizeof(data);
    if (hex_to_bytes(compacted, data, &datalen) != 0) {
        fprintf(stderr, "store: failed to parse data hex\n");
        return -1;
    }

    // Step 1: Install for personalization
    if (!status_ok(GP211_install_for_personalization(ctx, info, sec, aid, (DWORD)aidlen))) {
        fprintf(stderr, "store: GP211_install_for_personalization failed\n");
        return -1;
    }

    // Step 2: Store data
    if (!status_ok(GP211_store_data(ctx, info, sec, encryptionFlags, formatFlags,
                                     responseDataExpected, data, (DWORD)datalen))) {
        fprintf(stderr, "store: GP211_store_data failed\n");
        return -1;
    }

    printf("Store data successful\n");
    return 0;
}

static int cmd_list_readers(void) {
    // Establish a temporary PC/SC context and enumerate all readers (like gpshell.c:list_readers)
    OPGP_CARD_CONTEXT ctx; memset(&ctx, 0, sizeof(ctx));
    _tcsncpy(ctx.libraryName, _T("gppcscconnectionplugin"), _tcslen(_T("gppcscconnectionplugin"))+1);
    _tcsncpy(ctx.libraryVersion, _T("1"), _tcslen(_T("1"))+1);
    OPGP_ERROR_STATUS s = OPGP_establish_context(&ctx);
    if (!status_ok(s)) { fprintf(stderr, "list-readers: failed to establish PC/SC context\n"); return -1; }

    char buf[MAX_READERS_BUF]; DWORD len = sizeof(buf);
    s = OPGP_list_readers(ctx, buf, &len, 0);
    if (!status_ok(s)) {
        fprintf(stderr, "list-readers failed with error 0x%08X (%s)\n", (unsigned int)s.errorCode, s.errorMessage);
        OPGP_release_context(&ctx);
        return -1;
    }
    for (DWORD j = 0; j < len; ) {
        if (buf[j] == '\0') break; // end of multi-string
        printf("* reader name %s\n", &buf[j]);
        j += (DWORD)strlen(&buf[j]) + 1;
    }
    OPGP_release_context(&ctx);
    return 0;
}

int main(int argc, char **argv) {
    const char *prog = argv[0];
    const char *reader=NULL, *protocol="auto", *sd_hex=NULL, *sec_level_opt="mac+enc";
    const char *key_hex=NULL, *enc_hex=NULL, *mac_hex=NULL, *dek_hex=NULL;
    int verbose=0, trace=0; BYTE keyset_ver=0, key_index=0; int derivation=0;
    BYTE baseKey[32]={0}, enc_key[32]={0}, mac_key[32]={0}, dek_key[32]={0};
    BYTE keyLength=0;
    const char *scp_protocol=NULL, *scp_impl=NULL;
    int i=1; for (; i<argc; ++i) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { print_usage(prog); return 0; }

        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) { verbose=1; }
        else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--trace")) { trace=1; }
        else if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--reader")) { if(i+1<argc) reader=argv[++i]; }
        else if (!strcmp(argv[i], "--protocol") && i+1<argc) { protocol=argv[++i]; }
        else if (!strcmp(argv[i], "--scp") && i+1<argc) { scp_protocol=argv[++i]; }
        else if (!strcmp(argv[i], "--scp-impl") && i+1<argc) { scp_impl=argv[++i]; }
        else if (!strcmp(argv[i], "--kv") && i+1<argc) { keyset_ver=(BYTE)atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--idx") && i+1<argc) { key_index=(BYTE)atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--derive") && i+1<argc) { const char *d=argv[++i]; if (!strcmp(d,"visa2")) derivation=1; else if (!strcmp(d,"emv")) derivation=2; else derivation=0; }
        else if (!strcmp(argv[i], "--sec") && i+1<argc) { sec_level_opt=argv[++i]; }
        else if (!strcmp(argv[i], "--sd") && i+1<argc) { sd_hex=argv[++i]; }
        else if (!strcmp(argv[i], "--key") && i+1<argc) { key_hex=argv[++i]; }
        else if (!strcmp(argv[i], "--enc") && i+1<argc) { enc_hex=argv[++i]; }
        else if (!strcmp(argv[i], "--mac") && i+1<argc) { mac_hex=argv[++i]; }
        else if (!strcmp(argv[i], "--dek") && i+1<argc) { dek_hex=argv[++i]; }
        else break;
    }
    if (i>=argc) { print_usage(prog); return 1; }
    const char *cmd = argv[i++];

    // Commands that do not require a card connection
    if (!strcmp(cmd, "list-readers")) {
        int rc = cmd_list_readers();
        return rc==0 ? 0 : 10;
    }
    if (!strcmp(cmd, "hash")) {
        int rc = cmd_hash(argc - i, &argv[i]);
        return rc==0 ? 0 : 10;
    }

    OPGP_CARD_CONTEXT ctx; OPGP_CARD_INFO info; GP211_SECURITY_INFO sec; memset(&ctx,0,sizeof(ctx)); memset(&info,0,sizeof(info)); memset(&sec,0,sizeof(sec));
    _tcsncpy(ctx.libraryName, _T("gppcscconnectionplugin"),
         _tcslen(_T("gppcscconnectionplugin"))+1);
    _tcsncpy(ctx.libraryVersion, _T("1"),
             _tcslen(_T("1"))+1);

    // Set up cleanup handlers
    g_cleanup_ctx = &ctx;
    g_cleanup_info = &info;

    if (connect_pcsc(&ctx, &info, reader, protocol, trace, verbose) != 0) {
        cleanup_and_exit(3);
    }
    g_cleanup_card_connected = 1;

    int need_auth = 1; // default for non-apdu commands
    if (!strcmp(cmd, "apdu")) {
        need_auth = 0;
        for (int j=i; j<argc; ++j) {
            if (!strcmp(argv[j], "--auth") || !strcmp(argv[j], "--secure")) { need_auth = 1; break; }
        }
    }
    if (!strcmp(cmd, "sign-dap") || !strcmp(cmd, "hash")) {
        need_auth = 0;
    }
    // Parse key options if provided
    BYTE *baseKeyPtr = NULL, *encKeyPtr = NULL, *macKeyPtr = NULL, *dekKeyPtr = NULL;
    if (key_hex || enc_hex || mac_hex || dek_hex) {
        if (key_hex && (enc_hex || mac_hex || dek_hex)) {
            fprintf(stderr, "Cannot specify both --key and individual keys (--enc/--mac/--dek)\n");
            cleanup_and_exit(2);
        }
        if (key_hex) {
            size_t klen = sizeof(baseKey);
            if (hex_to_bytes(key_hex, baseKey, &klen) != 0 || (klen != 16 && klen != 24 && klen != 32)) {
                fprintf(stderr, "Invalid --key (must be 16, 24, or 32 bytes hex)\n");
                cleanup_and_exit(2);
            }
            keyLength = (BYTE)klen;
            baseKeyPtr = baseKey;
        } else if (enc_hex && mac_hex && dek_hex) {
            size_t el = sizeof(enc_key), ml = sizeof(mac_key), dl = sizeof(dek_key);
            if (hex_to_bytes(enc_hex, enc_key, &el) != 0 || hex_to_bytes(mac_hex, mac_key, &ml) != 0 || hex_to_bytes(dek_hex, dek_key, &dl) != 0) {
                fprintf(stderr, "Invalid hex for --enc/--mac/--dek\n");
                cleanup_and_exit(2);
            }
            if (!((el == ml && ml == dl) && (el == 16 || el == 24 || el == 32))) {
                fprintf(stderr, "Keys --enc/--mac/--dek must have equal length of 16/24/32 bytes\n");
                cleanup_and_exit(2);
            }
            keyLength = (BYTE)el;
            encKeyPtr = enc_key;
            macKeyPtr = mac_key;
            dekKeyPtr = dek_key;
        } else {
            fprintf(stderr, "Must specify either --key OR all of --enc/--mac/--dek\n");
            cleanup_and_exit(2);
        }
    }

    GP211_SECURITY_INFO *sec_ptr = &sec;
    if (need_auth) {
        if (select_isd(ctx, info, sd_hex) != 0) {
            fprintf(stderr, "Failed to select ISD\n");
            cleanup_and_exit(4);
        }
        if (mutual_auth(ctx, info, &sec, keyset_ver, key_index, derivation, sec_level_opt, verbose,
                        baseKeyPtr, encKeyPtr, macKeyPtr, dekKeyPtr, keyLength,
                        scp_protocol, scp_impl) != 0) {
            fprintf(stderr, "Mutual authentication failed\n");
            cleanup_and_exit(5);
        }
    } else {
        sec_ptr = NULL; // no secure channel for raw APDU by default
    }

    int rc = 0;
    if (!strcmp(cmd, "list-apps")) rc = cmd_list_apps(ctx, info, &sec);
    else if (!strcmp(cmd, "list-keys")) rc = cmd_list_keys(ctx, info, &sec);
    else if (!strcmp(cmd, "install")) rc = cmd_install(ctx, info, &sec, argc - i, &argv[i]);
    else if (!strcmp(cmd, "delete")) rc = cmd_delete(ctx, info, &sec, (i<argc)?argv[i]:NULL);
    else if (!strcmp(cmd, "put-key")) rc = cmd_put_key(ctx, info, &sec, argc - i, &argv[i]);
    else if (!strcmp(cmd, "put-auth")) rc = cmd_put_auth(ctx, info, &sec, argc - i, &argv[i]);
    else if (!strcmp(cmd, "put-dm")) rc = cmd_put_dm(ctx, info, &sec, argc - i, &argv[i]);
    else if (!strcmp(cmd, "del-key")) rc = cmd_del_key(ctx, info, &sec, argc - i, &argv[i]);
    else if (!strcmp(cmd, "apdu")) rc = cmd_apdu(ctx, info, sec_ptr, argc - i, &argv[i]);
    else if (!strcmp(cmd, "status")) rc = cmd_status(ctx, info, &sec, argc - i, &argv[i]);
    else if (!strcmp(cmd, "store")) rc = cmd_store(ctx, info, &sec, argc - i, &argv[i]);
    else if (!strcmp(cmd, "sign-dap")) {
        if (i>=argc) { fprintf(stderr, "sign-dap: missing type aes|rsa\n"); rc=-1; }
        else if (!strcmp(argv[i], "rsa")) rc = cmd_dap(1, ctx, info, &sec, argc - (i+1), &argv[i+1]);
        else if (!strcmp(argv[i], "aes")) rc = cmd_dap(0, ctx, info, &sec, argc - (i+1), &argv[i+1]);
        else { fprintf(stderr, "sign-dap: unknown type\n"); rc=-1; }
    } else { fprintf(stderr, "Unknown command: %s\n", cmd); rc=-1; }

    if (rc != 0) {
        cleanup_and_exit(10);
    }

    OPGP_card_disconnect(ctx, &info);
    OPGP_release_context(&ctx);
    return 0;
}
