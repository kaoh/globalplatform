/*
 * gpshell3: Simplified CLI for GlobalPlatform 2.1.1+
 *
 * Separate binary that provides a subcommand UX while keeping the legacy
 * gpshell intact. If invoked without a subcommand or with a script filename,
 * this executable falls back to exec the legacy gpshell.
 *
 * Scope:
 * - PC/SC only, protocol auto (T=0/T=1) by default
 * - GP 2.1.1+ only, SCP02/SCP03 autodetected
 * - Default key set version 0, default derivation none
 * - Default security level MAC+ENC
 * - Commands: list-apps, list-keys, install, delete, put-auth, key-del, apdu, sign-dap (aes|rsa)
 * - No URL download support (local CAP file only)
 */

#ifndef _WIN32
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
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
    fprintf(stderr,
        "Usage: %s [global-options] <command> [command-args]\n\n"
        "Global options:\n"
        "  -r, --reader <name>       PC/SC reader name (default: auto first present)\n"
        "  --protocol <auto|t0|t1>   Transport protocol (default: auto)\n"
        "  --kv <n>                  Key set version for mutual auth (default: 0)\n"
        "  --idx <n>                 Key index within key set (default: 0)\n"
        "  --derive <none|visa2|emv>  Key derivation (default: none)\n"
        "  --sec <mac|mac+enc|mac+enc+rmac> Channel security level (default: mac+enc)\n"
        "  --isd <aidhex>            ISD AID hex; default tries A000000151000000 then A0000001510000 then A000000003000000\n"
        "  --key <hex>               Base key for mutual auth (default: A0..AF)\n"
        "  --enc <hex>               ENC key for mutual auth (default: A0..AF)\n"
        "  --mac <hex>               MAC key for mutual auth (default: A0..AF)\n"
        "  --dek <hex>               DEK key for mutual auth (default: A0..AF)\n"
        "  -v, --verbose             Verbose output\n"
        "  -t, --trace               Enable APDU trace\n"
        "  -h, --help                Show this help\n\n"
        "Commands:\n"
        "  list-apps\n"
        "  list-readers\n"
        "  list-keys\n"
        "  install [--load-only] [--dap <hex>|@<file>] [--load-token <hex>] [--install-token <hex>] \\\n"
        "          [--hash <hex>] [--applet <AIDhex>] [--v-data-limit <size>] \\\n"
        "          [--nv-data-limit <size>] [--params <hex>] [--module <AIDhex>] \\\n"
        "          [--priv <p1,p2,...>] <cap-file>\n"
        "      --dap: DAP signature as hex or @file for binary signature (SD AID taken from --isd)\n"
        "  delete <AIDhex>\n"
        "  key-put [--type <3des|aes|rsa>] --kv <ver> --idx <idx> [--new-kv <ver>] \\\n"
        "          (--key <hex>|--pem <file>[:pass])\n"
        "  put-auth --kv <ver> [--new-kv <ver>] [--key <hex> | --enc <hex> --mac <hex> --dek <hex>]\n"
        "  key-del --kv <ver> [--idx <idx>]\n"
        "  apdu [--auth] [--nostop|--ignore-errors] <APDU> [<APDU> ...]\n"
        "      APDU format: hex bytes either concatenated (e.g. 00A40400) or space-separated (e.g. 00 A4 04 00).\n"
        "      Multiple APDUs can be provided as separate args or separated by ';' or ',' in one arg.\n"
        "      By default, apdu does NOT select ISD or perform mutual authentication; use --auth to enable it.\n"
        "  hash <cap-file> [--sha1|--sha256|--sha384|--sha512]\n"
        "      Compute the load file data block hash of a CAP file. Default is SHA-1.\n"
        "  sign-dap aes [--output <file>] <hash-hex> <sd-aidhex> <hexkey>\n"
        "  sign-dap rsa [--output <file>] <hash-hex> <sd-aidhex> <pem>[:pass]\n"
        "      Generate DAP signature from precomputed hash. Use 'hash' command to compute hash first.\n"
        "      Output is signature only (for use with 'install --dap <hex>' or '--dap @file').\n"
        "      --output: Write signature to binary file\n\n"
        "Privilege short names for --priv: sd,dap-verif,delegated-mgmt,cm-lock,cm-terminate,default-selected,pin-change,mandated-dap\n\n"
        "Fallback: If invoked without command or with a script filename, legacy gpshell is executed.\n",
        prog);
}

static int is_file_exists(const char *path) {
    struct stat st; return stat(path, &st) == 0 && S_ISREG(st.st_mode);
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
                       const BYTE *baseKey_in, const BYTE *enc_in, const BYTE *mac_in, const BYTE *dek_in, BYTE keyLength_in) {
    BYTE scp = 0, scpImpl = 0;
    {
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
                if (used + 2 < outlen) { out[used++] = ','; out[used++] = ' '; }
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

// Helper to reduce repetition in cmd_list: lists app-like elements for a given GET STATUS element
static void list_app_like_elements(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec,
                                   BYTE element, const char *label)
{
    GP211_APPLICATION_DATA apps[256];
    DWORD len = sizeof(apps)/sizeof(apps[0]);
    OPGP_ERROR_STATUS s = GP211_get_status(ctx, info, sec, element, GP211_STATUS_FORMAT_NEW, apps, NULL, &len);
    if (status_ok(s)) {
        printf("== %s ==\n", label);
        for (DWORD i=0; i<len; i++) {
            printf("AID="); print_aid(&apps[i].aid);
            printf(" lc=%s", lc_to_string(apps[i].lifeCycleState, element));
            if (apps[i].privileges) {
                char pbuf[512];
                privileges_to_string(apps[i].privileges, pbuf, sizeof(pbuf));
                printf(" priv=%08X [%s]", (unsigned)apps[i].privileges, pbuf);
            }
            if (apps[i].versionNumber[0] || apps[i].versionNumber[1]) printf(" ver=%u.%u", apps[i].versionNumber[0], apps[i].versionNumber[1]);
            if (apps[i].associatedSecurityDomainAID.AIDLength) { printf(" sd="); print_aid(&apps[i].associatedSecurityDomainAID); }
            printf("\n");
        }
    } else {
        fprintf(stderr, "GET STATUS (%s) failed\n", label);
    }
}

static int cmd_list(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    GP211_EXECUTABLE_MODULES_DATA mods[128];
    // Applications
    list_app_like_elements(ctx, info, sec, GP211_STATUS_APPLICATIONS, "applications");
    // Issuer Security Domain(s)
    list_app_like_elements(ctx, info, sec, GP211_STATUS_ISSUER_SECURITY_DOMAIN, "issuer security domain");
    // Load Files (without module details)
    list_app_like_elements(ctx, info, sec, GP211_STATUS_LOAD_FILES, "load files");

    DWORD mlen = sizeof(mods)/sizeof(mods[0]);
    {
        OPGP_ERROR_STATUS s = GP211_get_status(ctx, info, sec, GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES, GP211_STATUS_FORMAT_NEW, NULL, mods, &mlen);
        if (status_ok(s)) {
            printf("== load files and executable modules ==\n");
            for (DWORD i=0;i<mlen;i++) {
                printf("LOADFILE="); print_aid(&mods[i].aid);
                printf(" lc=%s ver=%u.%u modules=%u\n", lc_to_string(mods[i].lifeCycleState, GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES), mods[i].versionNumber[0], mods[i].versionNumber[1], mods[i].numExecutableModules);
                for (DWORD j=0; j<mods[i].numExecutableModules && j < (DWORD)(sizeof(mods[i].executableModules)/sizeof(mods[i].executableModules[0])); j++) {
                    printf("  MODULE=");
                    print_aid(&mods[i].executableModules[j]);
                    printf("\n");
                }
            }
        }
    }
    return 0;
}

static int cmd_keys(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    GP211_KEY_INFORMATION infos[64]; DWORD ilen = sizeof(infos)/sizeof(infos[0]);
    OPGP_ERROR_STATUS s = GP211_get_key_information_templates(ctx, info, sec, 0xE0, infos, &ilen);
    if (!status_ok(s)) {
        cleanup_and_exit(10);
    }
    for (DWORD i=0;i<ilen;i++) {
        printf("set=%u index=%u type=0x%02X len=%u usage=0x%02X access=0x%02X\n",
               infos[i].keySetVersion, infos[i].keyIndex, infos[i].keyType, infos[i].keyLength, infos[i].keyUsage, infos[i].keyAccess);
    }
    return 0;
}

static int cmd_install(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec,
                       int argc, char **argv) {
    int load_only = 0;
    DWORD v_data_limit = 0, nv_data_limit = 0;
    const char *dap_hex = NULL; const char *applet_aid_hex=NULL; const char *module_aid_hex=NULL; const char *priv_list=NULL; const char *params_hex=NULL;
    const char *load_token_hex = NULL; const char *install_token_hex = NULL; const char *load_file_hash_hex = NULL;
    int ai = 0;
    for (; ai < argc; ++ai) {
        if (strcmp(argv[ai], "--load-only") == 0) load_only = 1;
        else if (strcmp(argv[ai], "--dap") == 0 && ai+1 < argc) { dap_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--load-token") == 0 && ai+1 < argc) { load_token_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--install-token") == 0 && ai+1 < argc) { install_token_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--hash") == 0 && ai+1 < argc) { load_file_hash_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--applet") == 0 && ai+1 < argc) { applet_aid_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--module") == 0 && ai+1 < argc) { module_aid_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--priv") == 0 && ai+1 < argc) { priv_list = argv[++ai]; }
        else if (strcmp(argv[ai], "--v-data-limit") == 0 && ai+1 < argc) { v_data_limit = (DWORD)atoi(argv[++ai]); }
        else if (strcmp(argv[ai], "--nv-data-limit") == 0 && ai+1 < argc) { nv_data_limit = (DWORD)atoi(argv[++ai]); }
        else if (strcmp(argv[ai], "--params") == 0 && ai+1 < argc) { params_hex = argv[++ai]; }
        else break;
    }
    if (ai >= argc) { fprintf(stderr, "install: missing <cap-file>\n"); cleanup_and_exit(10); }
    const char *capfile = argv[ai++];

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
            if (!f) { fprintf(stderr, "Failed to open DAP signature file: %s\n", filepath); cleanup_and_exit(10); }
            sig_len = fread(sig_buf, 1, sizeof(sig_buf), f);
            fclose(f);
            if (sig_len == 0) { fprintf(stderr, "Empty DAP signature file\n"); cleanup_and_exit(10); }
        } else {
            // Parse as hex string
            if (hex_to_bytes(dap_hex, sig_buf, &sig_len) != 0) { fprintf(stderr, "Invalid DAP signature hex\n"); cleanup_and_exit(10); }
        }

        // Fill in DAP block with signature and SD AID
        memcpy(dapBlocks[0].securityDomainAID, sdAid, sdAidLen);
        dapBlocks[0].securityDomainAIDLength = (BYTE)sdAidLen;
        memcpy(dapBlocks[0].signature, sig_buf, sig_len);
        dapBlocks[0].signatureLength = (BYTE)sig_len;
        dapCount = 1;
    }

    // Read CAP load file parameters to obtain the package AID
    OPGP_LOAD_FILE_PARAMETERS lfp; memset(&lfp,0,sizeof(lfp));
    if (!status_ok(OPGP_read_executable_load_file_parameters((char*)capfile, &lfp))) {
        fprintf(stderr, "Failed to read CAP load file parameters\n");
        cleanup_and_exit(10);
    }

    // Parse optional load file hash
    BYTE loadFileHash[64]; memset(loadFileHash, 0, sizeof(loadFileHash));
    BYTE *loadFileHashPtr = NULL;
    if (load_file_hash_hex) {
        size_t hash_len = sizeof(loadFileHash);
        if (hex_to_bytes(load_file_hash_hex, loadFileHash, &hash_len) != 0) {
            fprintf(stderr, "Invalid load file hash hex\n");
            cleanup_and_exit(10);
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
            cleanup_and_exit(10);
        }
        loadTokenPtr = loadToken;
    }

    {
        OPGP_ERROR_STATUS s = GP211_install_for_load(ctx, info, sec,
            lfp.loadFileAID.AID, lfp.loadFileAID.AIDLength,
            sdAid, sdAidLen,
            loadFileHashPtr, loadTokenPtr,
            lfp.loadFileSize, v_data_limit, nv_data_limit);
        if (!status_ok(s)) {
            cleanup_and_exit(10);
        }
    }

    GP211_RECEIPT_DATA receipt; DWORD receiptAvail=0; memset(&receipt, 0, sizeof(receipt));
    if (!status_ok(GP211_load(ctx, info, sec, dapCount?dapBlocks:NULL, dapCount, (char*)capfile, &receipt, &receiptAvail, NULL))) {
        cleanup_and_exit(10);
    }
    if (load_only) { return 0; }

    unsigned char applet_aid[16]; size_t applet_len=0;
    if (applet_aid_hex) {
        applet_len = sizeof(applet_aid);
        if (hex_to_bytes(applet_aid_hex, applet_aid, &applet_len)!=0) {
            fprintf(stderr, "Invalid --applet AID\n");
            cleanup_and_exit(10);
        }
    }
    unsigned char module_aid[16]; size_t module_len=0;
    if (module_aid_hex) {
        module_len = sizeof(module_aid);
        if (hex_to_bytes(module_aid_hex, module_aid, &module_len)!=0) {
            fprintf(stderr, "Invalid --module AID\n");
            cleanup_and_exit(10);
        }
    }

    unsigned char inst_param[256]; size_t inst_param_len=0;
    if (params_hex) {
        inst_param_len = sizeof(inst_param);
        if (hex_to_bytes(params_hex, inst_param, &inst_param_len)!=0) {
            fprintf(stderr, "Invalid --params hex\n");
            cleanup_and_exit(10);
        }
    }

    // Parse optional install token
    BYTE installToken[128]; memset(installToken,0,sizeof(installToken));
    BYTE *installTokenPtr = NULL;
    if (install_token_hex) {
        size_t token_len = sizeof(installToken);
        if (hex_to_bytes(install_token_hex, installToken, &token_len) != 0 || token_len != 128) {
            fprintf(stderr, "Invalid install token hex (must be 128 bytes)\n");
            cleanup_and_exit(10);
        }
        installTokenPtr = installToken;
    }

    GP211_RECEIPT_DATA rec2; DWORD rec2Avail=0; memset(&rec2,0,sizeof(rec2));
    BYTE privileges = 0x00; // first 8 bits only as per requirement
    if (priv_list) {
        if (parse_privs_byte(priv_list, &privileges) != 0) {
            cleanup_and_exit(10);
        }
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
                lfp.loadFileAID.AID, lfp.loadFileAID.AIDLength,
                module_aid, (DWORD)module_len,
                applet_aid, (DWORD)applet_len,
                privileges, v_data_limit, nv_data_limit,
                inst_param_len ? inst_param : NULL, (DWORD)inst_param_len,
                installTokenPtr, &rec2, &rec2Avail))) {
            cleanup_and_exit(10);
        }
    } else {
        // Neither provided: iterate over all applets from CAP
        int i = 0; int did_any = 0;
        while (lfp.appletAIDs[i].AIDLength) {
            did_any = 1;
            PBYTE aid = (PBYTE)lfp.appletAIDs[i].AID;
            DWORD aidLen = lfp.appletAIDs[i].AIDLength;
            if (!status_ok(GP211_install_for_install_and_make_selectable(ctx, info, sec,
                    lfp.loadFileAID.AID, lfp.loadFileAID.AIDLength,
                    aid, aidLen,
                    aid, aidLen,
                    privileges, v_data_limit, nv_data_limit,
                    inst_param_len ? inst_param : NULL, (DWORD)inst_param_len,
                    installTokenPtr, &rec2, &rec2Avail))) {
                fprintf(stderr, "Failed for applet index %d\n", i);
                cleanup_and_exit(10);
            }
            i++;
        }
        if (!did_any) {
            fprintf(stderr, "INSTALL: No applets found in CAP to install\n");
            cleanup_and_exit(10);
        }
    }
    return 0;
}

static int cmd_delete(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, const char *aid_hex) {
    if (!aid_hex) { fprintf(stderr, "delete: missing <AIDhex>\n"); cleanup_and_exit(10); }
    unsigned char aidb[16]; size_t alen=sizeof(aidb);
    if (hex_to_bytes(aid_hex, aidb, &alen)!=0) { fprintf(stderr, "Invalid AID hex\n"); cleanup_and_exit(10); }
    OPGP_AID a; memset(&a,0,sizeof(a)); a.AIDLength=(BYTE)alen; memcpy(a.AID, aidb, alen);
    GP211_RECEIPT_DATA rec; DWORD recLen=0; memset(&rec,0,sizeof(rec));
    if (!status_ok(GP211_delete_application(ctx, info, sec, &a, 1, &rec, &recLen))) {
        cleanup_and_exit(10);
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
        if (!pem) { fprintf(stderr, "put-key rsa: --pem <file>[:pass] required\n"); cleanup_and_exit(10); }
        if (!status_ok(GP211_put_rsa_key(ctx, info, sec, setVer, idx, newSetVer, (char*)pem, pass))) {
            cleanup_and_exit(10);
        }
        return 0;
    } else if (strcmp(type, "aes")==0) {
        if (!hexkey) { fprintf(stderr, "put-key aes: --key <hex> required\n"); cleanup_and_exit(10); }
        unsigned char k[32]; size_t klen=sizeof(k);
        if (hex_to_bytes(hexkey, k, &klen)!=0 || (klen!=16 && klen!=24 && klen!=32)) {
            fprintf(stderr, "Invalid AES key len\n");
            cleanup_and_exit(10);
        }
        if (!status_ok(GP211_put_aes_key(ctx, info, sec, setVer, idx, newSetVer, k, (DWORD)klen))) {
            cleanup_and_exit(10);
        }
        return 0;
    } else if (strcmp(type, "3des")==0) {
        if (!hexkey) { fprintf(stderr, "put-key 3des: --key <hex> required\n"); cleanup_and_exit(10); }
        unsigned char k[16]; size_t klen=sizeof(k);
        if (hex_to_bytes(hexkey, k, &klen)!=0 || klen!=16) {
            fprintf(stderr, "3DES key must be 16 hex bytes\n");
            cleanup_and_exit(10);
        }
        if (!status_ok(GP211_put_3des_key(ctx, info, sec, setVer, idx, newSetVer, k))) {
            cleanup_and_exit(10);
        }
        return 0;
    } else {
        fprintf(stderr, "put-key: unsupported --type '%s' (use 3des|aes|rsa). For Secure Channel keys use put-sc-keys.\n", type);
        cleanup_and_exit(10);
    }
}

static int cmd_put_sc_key(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    BYTE setVer=0, newSetVer=0; const char *base=NULL, *enc=NULL, *mac=NULL, *dek=NULL;
    for (int i=0;i<argc;i++) {
        if (strcmp(argv[i], "--kv")==0 && i+1<argc) setVer=(BYTE)atoi(argv[++i]);
        else if (strcmp(argv[i], "--new-kv")==0 && i+1<argc) newSetVer=(BYTE)atoi(argv[++i]);
        else if (strcmp(argv[i], "--base")==0 && i+1<argc) base=argv[++i];
        else if (strcmp(argv[i], "--key")==0 && i+1<argc) base=argv[++i];
        else if (strcmp(argv[i], "--enc")==0 && i+1<argc) enc=argv[++i];
        else if (strcmp(argv[i], "--mac")==0 && i+1<argc) mac=argv[++i];
        else if (strcmp(argv[i], "--dek")==0 && i+1<argc) dek=argv[++i];
    }
    if (!setVer && !newSetVer) {
        // allow zero, but typically setVer is 0 for default
    }
    if (base && (enc || mac || dek)) {
        fprintf(stderr, "put-auth: use either --base/--key OR all of --enc/--mac/--dek\n");
        cleanup_and_exit(10);
    }
    if (!base && !(enc && mac && dek)) {
        fprintf(stderr, "put-auth: specify either --base/--key <hex> or --enc/--mac/--dek <hex>\n");
        cleanup_and_exit(10);
    }
    if (base) {
        unsigned char b[32]; size_t blen=sizeof(b);
        if (hex_to_bytes(base, b, &blen)!=0 || (blen!=16 && blen!=24 && blen!=32)) {
            fprintf(stderr, "Invalid base key length\n");
            cleanup_and_exit(10);
        }
        OPGP_ERROR_STATUS s = GP211_put_secure_channel_keys(ctx, info, sec, setVer, newSetVer, b, NULL, NULL, NULL, (DWORD)blen);
        if (!status_ok(s)) {
            cleanup_and_exit(10);
        }
        return 0;
    } else {
        unsigned char se[32], sm[32], dk[32]; size_t el=sizeof(se), ml=sizeof(sm), dl=sizeof(dk);
        if (hex_to_bytes(enc, se, &el)!=0 || hex_to_bytes(mac, sm, &ml)!=0 || hex_to_bytes(dek, dk, &dl)!=0) {
            fprintf(stderr, "Invalid hex for ENC/MAC/DEK\n");
            cleanup_and_exit(10);
        }
        if (!((el==ml && ml==dl) && (el==16 || el==24 || el==32))) {
            fprintf(stderr, "Keys must have equal length of 16/24/32 bytes\n");
            cleanup_and_exit(10);
        }
        OPGP_ERROR_STATUS s = GP211_put_secure_channel_keys(ctx, info, sec, setVer, newSetVer, NULL, se, sm, dk, (DWORD)el);
        if (!status_ok(s)) {
            cleanup_and_exit(10);
        }
        return 0;
    }
}

static int cmd_del_key(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    BYTE setVer=0; BYTE idx=0xFF; // 0xFF => delete all keys in set
    for (int i=0;i<argc;i++) {
        if (strcmp(argv[i], "--kv")==0 && i+1<argc) setVer=(BYTE)atoi(argv[++i]);
        else if (strcmp(argv[i], "--idx")==0 && i+1<argc) idx=(BYTE)atoi(argv[++i]);
    }
    if (!status_ok(GP211_delete_key(ctx, info, sec, setVer, idx))) {
        cleanup_and_exit(10);
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
    if (argc < 1) { fprintf(stderr, "hash: missing <cap-file>\n"); return -1; }
    const char *cap = argv[0];
    const char *hash_alg = "sha256"; // default
    int ai = 1;
    for (; ai < argc; ++ai) {
        if (strcmp(argv[ai], "--sha1") == 0) { hash_alg = "sha1"; }
        else if (strcmp(argv[ai], "--sha256") == 0 || strcmp(argv[ai], "--sha2-256") == 0) { hash_alg = "sha256"; }
        else if (strcmp(argv[ai], "--sha384") == 0 || strcmp(argv[ai], "--sha2-384") == 0) { hash_alg = "sha384"; }
        else if (strcmp(argv[ai], "--sha512") == 0 || strcmp(argv[ai], "--sha2-512") == 0) { hash_alg = "sha512"; }
        else { fprintf(stderr, "hash: unknown option '%s'\n", argv[ai]); return -1; }
    }
    BYTE scp = GP211_SCP03;
    DWORD hash_len = 32;
    if (strcmp(hash_alg, "sha1") == 0) { scp = GP211_SCP02; hash_len = 20; }
    else if (strcmp(hash_alg, "sha256") == 0) { scp = GP211_SCP03; hash_len = 32; }
    else if (strcmp(hash_alg, "sha384") == 0) { scp = GP211_SCP03; hash_len = 48; }
    else if (strcmp(hash_alg, "sha512") == 0) { scp = GP211_SCP03; hash_len = 64; }

    BYTE hash[64]; memset(hash, 0, sizeof(hash));
    if (!status_ok(GP211_calculate_load_file_data_block_hash((char*)cap, hash, hash_len, scp))) {
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
    if (argc < 2 || (argc >= 2 && argv[1][0] != '-' && is_file_exists(argv[1]))) {
#ifndef _WIN32
        argv[0] = (char*)"gpshell";
        execvp("gpshell", argv);
        perror("execvp gpshell");
        return 127;
#else
        fprintf(stderr, "Legacy fallback not supported on Windows in gpshell3. Use gpshell.\n");
        return 2;
#endif
    }

    const char *reader=NULL, *protocol="auto", *isd_hex=NULL, *sec_level_opt="mac+enc";
    const char *key_hex=NULL, *enc_hex=NULL, *mac_hex=NULL, *dek_hex=NULL;
    int verbose=0, trace=0; BYTE keyset_ver=0, key_index=0; int derivation=0;
    BYTE baseKey[32]={0}, enc_key[32]={0}, mac_key[32]={0}, dek_key[32]={0};
    BYTE keyLength=0;
    int i=1; for (; i<argc; ++i) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { print_usage(prog); return 0; }
        else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) { verbose=1; }
        else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--trace")) { trace=1; }
        else if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--reader")) { if(i+1<argc) reader=argv[++i]; }
        else if (!strcmp(argv[i], "--protocol") && i+1<argc) { protocol=argv[++i]; }
        else if (!strcmp(argv[i], "--kv") && i+1<argc) { keyset_ver=(BYTE)atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--idx") && i+1<argc) { key_index=(BYTE)atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--derive") && i+1<argc) { const char *d=argv[++i]; if (!strcmp(d,"visa2")) derivation=1; else if (!strcmp(d,"emv")) derivation=2; else derivation=0; }
        else if (!strcmp(argv[i], "--sec") && i+1<argc) { sec_level_opt=argv[++i]; }
        else if (!strcmp(argv[i], "--isd") && i+1<argc) { isd_hex=argv[++i]; }
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

    // Determine authentication need: for 'apdu' command default is no auth unless --auth/--secure is present
    int need_auth = 1; // default for non-apdu commands
    if (!strcmp(cmd, "apdu")) {
        need_auth = 0;
        for (int j=i; j<argc; ++j) {
            if (!strcmp(argv[j], "--auth") || !strcmp(argv[j], "--secure")) { need_auth = 1; break; }
        }
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
        if (select_isd(ctx, info, isd_hex) != 0) {
            fprintf(stderr, "Failed to select ISD\n");
            cleanup_and_exit(4);
        }
        if (mutual_auth(ctx, info, &sec, keyset_ver, key_index, derivation, sec_level_opt, verbose,
                        baseKeyPtr, encKeyPtr, macKeyPtr, dekKeyPtr, keyLength) != 0) {
            fprintf(stderr, "Mutual authentication failed\n");
            cleanup_and_exit(5);
        }
    } else {
        sec_ptr = NULL; // no secure channel for raw APDU by default
    }

    int rc = 0;
    if (!strcmp(cmd, "list-apps")) rc = cmd_list(ctx, info, &sec);
    else if (!strcmp(cmd, "list-keys")) rc = cmd_keys(ctx, info, &sec);
    else if (!strcmp(cmd, "install")) rc = cmd_install(ctx, info, &sec, argc - i, &argv[i]);
    else if (!strcmp(cmd, "delete")) rc = cmd_delete(ctx, info, &sec, (i<argc)?argv[i]:NULL);
    else if (!strcmp(cmd, "key-put")) rc = cmd_put_key(ctx, info, &sec, argc - i, &argv[i]);
    else if (!strcmp(cmd, "put-auth")) rc = cmd_put_sc_key(ctx, info, &sec, argc - i, &argv[i]);
    else if (!strcmp(cmd, "key-del")) rc = cmd_del_key(ctx, info, &sec, argc - i, &argv[i]);
    else if (!strcmp(cmd, "apdu")) rc = cmd_apdu(ctx, info, sec_ptr, argc - i, &argv[i]);
    else if (!strcmp(cmd, "sign-dap")) {
        if (i>=argc) { fprintf(stderr, "sign-dap: missing type aes|rsa\n"); rc=-1; }
        else if (!strcmp(argv[i], "rsa")) rc = cmd_dap(1, ctx, info, &sec, argc - (i+1), &argv[i+1]);
        else if (!strcmp(argv[i], "aes")) rc = cmd_dap(0, ctx, info, &sec, argc - (i+1), &argv[i+1]);
        else { fprintf(stderr, "sign-dap: unknown type\n"); rc=-1; }
    } else { fprintf(stderr, "Unknown command: %s\n", cmd); rc=-1; }

    OPGP_card_disconnect(ctx, &info);
    OPGP_release_context(&ctx);
    return rc==0?0:10;
}
