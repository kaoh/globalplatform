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
 * - Commands: list, keys, install, delete, put-key, del-key, apdu, dap (aes|rsa)
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

static int status_ok(OPGP_ERROR_STATUS s) { return s.errorStatus == OPGP_ERROR_STATUS_SUCCESS; }

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [global-options] <command> [command-args]\n\n"
        "Global options:\n"
        "  --reader <name>           PC/SC reader name (default: auto first present)\n"
        "  --protocol <auto|t0|t1>   Transport protocol (default: auto)\n"
        "  --keyset-version <n>      Key set version for mutual auth (default: 0)\n"
        "  --key-index <n>           Key index within key set (default: 0)\n"
        "  --derive <none|visa2|emv|visa1>  Key derivation (default: none)\n"
        "  --sec-level <mac|mac+enc|mac+enc+rmac> Channel security level (default: mac+enc)\n"
        "  --isd <aidhex>            ISD AID hex; default tries A0000001510000 then A000000151000000 then A000000003000000\n"
        "  -v, --verbose             Verbose output\n"
        "  -t, --trace               Enable APDU trace\n"
        "  -h, --help                Show this help\n\n"
        "Commands:\n"
        "  list\n"
        "  keys\n"
        "  install [--load-only] [--dap-aes <hexkey>|--dap-rsa <pem>[:pass]] \\\n"
        "          [--applet <AIDhex>] [--module <AIDhex>] [--priv <p1,p2,...>] <cap-file>\n"
        "  delete <AIDhex>\n"
        "  put-key [--type <3des|aes|rsa>] --set <ver> --index <idx> [--new-set <ver>] \\\n"
        "          (--key <hex>|--pem <file>[:pass])\n"
        "  put-sc-key --set <ver> [--new-set <ver>] [--base <hex> | --senc <hex> --smac <hex> --dek <hex>]\n"
        "  del-key --set <ver> [--index <idx>]\n"
        "  apdu <hex>\n"
        "  dap aes <cap-file> <sd-aidhex> <hexkey>\n"
        "  dap rsa <cap-file> <sd-aidhex> <pem>[:pass]\n\n"
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
        else if (!strcmp(tok, "dap-verif") || !strcmp(tok, "dap") || !strcmp(tok, "dapverification")) p |= 0xC0; // DAP_VERIFICATION
        else if (!strcmp(tok, "delegated-mgmt") || !strcmp(tok, "delegated-management")) p |= 0xA0; // DELEGATED_MANAGEMENT
        else if (!strcmp(tok, "cm-lock") || !strcmp(tok, "card-manager-lock")) p |= 0x10; // CARD_MANAGER_LOCK
        else if (!strcmp(tok, "cm-terminate") || !strcmp(tok, "card-manager-terminate")) p |= 0x08; // CARD_MANAGER_TERMINATE
        else if (!strcmp(tok, "default-selected") || !strcmp(tok, "default")) p |= 0x04; // DEFAULT_SELECTED (do not refer to card reset)
        else if (!strcmp(tok, "pin-change") || !strcmp(tok, "pin")) p |= 0x02; // PIN_CHANGE
        else if (!strcmp(tok, "mandated-dap") || !strcmp(tok, "mandated-dap-verif") || !strcmp(tok, "mandated")) p |= 0xD0; // MANDATED_DAP_VERIFICATION
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
        if (status_ok(s)) return 0;
    }
    s = OPGP_select_application(ctx, info, (PBYTE)GP211_CARD_MANAGER_AID, 7);
    if (status_ok(s)) return 0;
    s = OPGP_select_application(ctx, info, (PBYTE)GP231_ISD_AID, 8);
    if (status_ok(s)) return 0;
    s = OPGP_select_application(ctx, info, (PBYTE)GP211_CARD_MANAGER_AID_ALT1, 8);
    if (status_ok(s)) return 0;
    return -1;
}

static int connect_pcsc(OPGP_CARD_CONTEXT *pctx, OPGP_CARD_INFO *pinfo, const char *reader, const char *protocol, int trace) {
    OPGP_ERROR_STATUS s;
    s = OPGP_establish_context(pctx);
    if (!status_ok(s)) { fprintf(stderr, "Failed to establish PC/SC context\n"); return -1; }
    if (trace) { OPGP_enable_trace_mode(OPGP_TRACE_MODE_ENABLE, stderr); }
    char readers[MAX_READERS_BUF]; DWORD rlen = sizeof(readers);
    if (!reader) {
        s = OPGP_list_readers(*pctx, readers, &rlen);
        if (!status_ok(s) || rlen == 0) { fprintf(stderr, "No PC/SC readers found\n"); return -1; }
        reader = readers; // first reader
    }
    DWORD proto = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
    if (protocol) {
        if (strcmp(protocol, "t0") == 0) proto = SCARD_PROTOCOL_T0;
        else if (strcmp(protocol, "t1") == 0) proto = SCARD_PROTOCOL_T1;
    }
    s = OPGP_card_connect(*pctx, reader, pinfo, proto);
    if (!status_ok(s)) { fprintf(stderr, "Failed to connect to reader '%s'\n", reader); return -1; }
    return 0;
}

static int mutual_auth(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec,
                       BYTE keyset_ver, BYTE key_index, int derivation, const char *sec_level_opt, int verbose) {
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
    memcpy(S_ENC, OPGP_VISA_DEFAULT_KEY, 16);
    memcpy(S_MAC, OPGP_VISA_DEFAULT_KEY, 16);
    memcpy(DEK,  OPGP_VISA_DEFAULT_KEY, 16);
    memcpy(baseKey, OPGP_VISA_DEFAULT_KEY, 16);
    BYTE keyLength = 16;
    BYTE deriv = OPGP_DERIVATION_METHOD_NONE;
    if (derivation == 1) deriv = OPGP_DERIVATION_METHOD_VISA2;
    else if (derivation == 2) deriv = OPGP_DERIVATION_METHOD_EMV_CPS11;
    else if (derivation == 3) deriv = OPGP_DERIVATION_METHOD_VISA1;
    OPGP_ERROR_STATUS s2 = GP211_mutual_authentication(ctx, info, baseKey, S_ENC, S_MAC, DEK, keyLength,
                                                       keyset_ver, key_index, scp, scpImpl, secLevel, deriv, sec);
    return status_ok(s2) ? 0 : -1;
}

static int cmd_list(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    GP211_APPLICATION_DATA apps[256]; GP211_EXECUTABLE_MODULES_DATA mods[128]; DWORD len;
    len = sizeof(apps)/sizeof(apps[0]);
    {
        OPGP_ERROR_STATUS s = GP211_get_status(ctx, info, sec, GP211_STATUS_APPLICATIONS|GP211_STATUS_ISSUER_SECURITY_DOMAIN, GP211_STATUS_FORMAT_NEW, apps, NULL, &len);
        if (status_ok(s)) {
            for (DWORD i=0;i<len;i++) {
                printf("AID="); print_aid(&apps[i].aid);
                printf(" lc=%02X", apps[i].lifeCycleState);
                if (apps[i].privileges) printf(" priv=%08X", (unsigned)apps[i].privileges);
                if (apps[i].versionNumber[0] || apps[i].versionNumber[1]) printf(" ver=%u.%u", apps[i].versionNumber[0], apps[i].versionNumber[1]);
                if (apps[i].associatedSecurityDomainAID.AIDLength) { printf(" sd="); print_aid(&apps[i].associatedSecurityDomainAID); }
                printf("\n");
            }
        } else {
            fprintf(stderr, "GET STATUS (applications) failed\n");
        }
    }
    DWORD mlen = sizeof(mods)/sizeof(mods[0]);
    {
        OPGP_ERROR_STATUS s = GP211_get_status(ctx, info, sec, GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES, GP211_STATUS_FORMAT_NEW, NULL, mods, &mlen);
        if (status_ok(s)) {
            for (DWORD i=0;i<mlen;i++) {
                printf("LOADFILE="); print_aid(&mods[i].aid);
                printf(" lc=%02X ver=%u.%u modules=%u\n", mods[i].lifeCycleState, mods[i].versionNumber[0], mods[i].versionNumber[1], mods[i].numExecutableModules);
            }
        }
    }
    return 0;
}

static int cmd_keys(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    GP211_KEY_INFORMATION infos[64]; DWORD ilen = sizeof(infos)/sizeof(infos[0]);
    OPGP_ERROR_STATUS s = GP211_get_key_information_templates(ctx, info, sec, 0xE0, infos, &ilen);
    if (!status_ok(s)) { fprintf(stderr, "Failed to get key information templates\n"); return -1; }
    for (DWORD i=0;i<ilen;i++) {
        printf("set=%u index=%u type=0x%02X len=%u usage=0x%02X access=0x%02X\n",
               infos[i].keySetVersion, infos[i].keyIndex, infos[i].keyType, infos[i].keyLength, infos[i].keyUsage, infos[i].keyAccess);
    }
    return 0;
}

static int cmd_install(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec,
                       int argc, char **argv) {
    int load_only = 0;
    const char *dap_aes = NULL; const char *dap_rsa = NULL; const char *applet_aid_hex=NULL; const char *module_aid_hex=NULL; const char *priv_list=NULL;
    int ai = 0;
    for (; ai < argc; ++ai) {
        if (strcmp(argv[ai], "--load-only") == 0) load_only = 1;
        else if (strcmp(argv[ai], "--dap-aes") == 0 && ai+1 < argc) { dap_aes = argv[++ai]; }
        else if (strcmp(argv[ai], "--dap-rsa") == 0 && ai+1 < argc) { dap_rsa = argv[++ai]; }
        else if (strcmp(argv[ai], "--applet") == 0 && ai+1 < argc) { applet_aid_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--module") == 0 && ai+1 < argc) { module_aid_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--priv") == 0 && ai+1 < argc) { priv_list = argv[++ai]; }
        else break;
    }
    if (ai >= argc) { fprintf(stderr, "install: missing <cap-file>\n"); return -1; }
    const char *capfile = argv[ai++];

    GP211_DAP_BLOCK dapBlocks[1]; DWORD dapCount = 0;
    if (dap_aes) {
        unsigned char key[32]; size_t klen = sizeof(key); if (hex_to_bytes(dap_aes, key, &klen) != 0) { fprintf(stderr, "Invalid AES key hex\n"); return -1; }
        unsigned char sdAid[16]; DWORD sdAidLen = sizeof(sdAid);
        {
            BYTE recv[32]; DWORD rlen = sizeof(recv);
            OPGP_ERROR_STATUS s = GP211_get_data(ctx, info, sec, (BYTE*)GP211_GET_DATA_SECURITY_DOMAIN_AID, recv, &rlen);
            if (status_ok(s) && rlen>0 && rlen<=16) { memcpy(sdAid, recv, rlen); sdAidLen = rlen; }
            else { memcpy(sdAid, GP211_CARD_MANAGER_AID, 7); sdAidLen = 7; }
        }
        BYTE hash[64]; DWORD hlen;
        hlen = (sec->secureChannelProtocol == GP211_SCP03) ? 64 : 20;
        if (!status_ok(GP211_calculate_load_file_data_block_hash((char*)capfile, hash, hlen, sec->secureChannelProtocol))) {
            fprintf(stderr, "Failed to calculate load file hash\n"); return -1;
        }
        if (!status_ok(GP211_calculate_DAP(hash, (BYTE)hlen, sdAid, sdAidLen, key, (DWORD)klen, &dapBlocks[0], sec->secureChannelProtocol))) {
            fprintf(stderr, "Failed to calculate AES DAP\n"); return -1;
        }
        dapCount = 1;
    } else if (dap_rsa) {
        char pemcopy[512]; strncpy(pemcopy, dap_rsa, sizeof(pemcopy)-1); pemcopy[sizeof(pemcopy)-1]='\0';
        char *pass = NULL; char *colon = strchr(pemcopy, ':'); if (colon) { *colon='\0'; pass = colon+1; }
        BYTE hash20[20]; if (!status_ok(GP211_calculate_load_file_data_block_hash((char*)capfile, hash20, 20, sec->secureChannelProtocol))) { fprintf(stderr, "Failed to calculate load file hash\n"); return -1; }
        if (!status_ok(GP211_calculate_rsa_DAP(hash20, NULL, 0, pemcopy, pass, &dapBlocks[0]))) { fprintf(stderr, "Failed to calculate RSA DAP\n"); return -1; }
        dapCount = 1;
    }

    GP211_RECEIPT_DATA receipt; DWORD receiptAvail=0; memset(&receipt, 0, sizeof(receipt));
    if (!status_ok(GP211_load(ctx, info, sec, dapCount?dapBlocks:NULL, dapCount, (char*)capfile, &receipt, &receiptAvail, NULL))) {
        fprintf(stderr, "LOAD failed\n"); return -1;
    }
    if (load_only) { return 0; }

    unsigned char applet_aid[16]; size_t applet_len=0;
    if (applet_aid_hex) { applet_len = sizeof(applet_aid); if (hex_to_bytes(applet_aid_hex, applet_aid, &applet_len)!=0) { fprintf(stderr, "Invalid --applet AID\n"); return -1; } }
    unsigned char module_aid[16]; size_t module_len=0;
    if (module_aid_hex) { module_len = sizeof(module_aid); if (hex_to_bytes(module_aid_hex, module_aid, &module_len)!=0) { fprintf(stderr, "Invalid --module AID\n"); return -1; } }

    OPGP_LOAD_FILE_PARAMETERS lfp; memset(&lfp,0,sizeof(lfp));
    if (status_ok(OPGP_read_executable_load_file_parameters((char*)capfile, &lfp))) {
        if (module_len==0 && lfp.numAppletAIDs>0) { module_len = lfp.appletAIDs[0].AIDLength; memcpy(module_aid, lfp.appletAIDs[0].AID, module_len); }
        if (applet_len==0 && lfp.numAppletAIDs>0) { applet_len = lfp.appletAIDs[0].AIDLength; memcpy(applet_aid, lfp.appletAIDs[0].AID, applet_len); }
    }

    BYTE installToken[128]; memset(installToken,0,sizeof(installToken));
    GP211_RECEIPT_DATA rec2; DWORD rec2Avail=0; memset(&rec2,0,sizeof(rec2));
    BYTE privileges = 0x00; // first 8 bits only as per requirement
    if (priv_list) {
        if (parse_privs_byte(priv_list, &privileges) != 0) { return -1; }
    }
    if (!status_ok(GP211_install_for_install_and_make_selectable(ctx, info, sec,
            lfp.loadFileAID.AID, lfp.loadFileAID.AIDLength,
            (module_len?module_aid:NULL), (DWORD)module_len,
            applet_aid, (DWORD)applet_len,
            privileges, 0, 0, NULL, 0, installToken, &rec2, &rec2Avail))) {
        fprintf(stderr, "INSTALL [install+make_selectable] failed\n"); return -1;
    }
    return 0;
}

static int cmd_delete(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, const char *aid_hex) {
    if (!aid_hex) { fprintf(stderr, "delete: missing <AIDhex>\n"); return -1; }
    unsigned char aidb[16]; size_t alen=sizeof(aidb); if (hex_to_bytes(aid_hex, aidb, &alen)!=0) { fprintf(stderr, "Invalid AID hex\n"); return -1; }
    OPGP_AID a; memset(&a,0,sizeof(a)); a.AIDLength=(BYTE)alen; memcpy(a.AID, aidb, alen);
    GP211_RECEIPT_DATA rec; DWORD recLen=0; memset(&rec,0,sizeof(rec));
    if (!status_ok(GP211_delete_application(ctx, info, sec, &a, 1, &rec, &recLen))) { fprintf(stderr, "DELETE failed\n"); return -1; }
    return 0;
}

static int cmd_put_key(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    BYTE setVer=0, idx=0, newSetVer=0; const char *type="aes"; const char *hexkey=NULL; const char *pem=NULL; char *pass=NULL;
    for (int i=0;i<argc;i++) {
        if (strcmp(argv[i], "--set")==0 && i+1<argc) setVer=(BYTE)atoi(argv[++i]);
        else if (strcmp(argv[i], "--index")==0 && i+1<argc) idx=(BYTE)atoi(argv[++i]);
        else if (strcmp(argv[i], "--new-set")==0 && i+1<argc) newSetVer=(BYTE)atoi(argv[++i]);
        else if (strcmp(argv[i], "--type")==0 && i+1<argc) type=argv[++i];
        else if (strcmp(argv[i], "--key")==0 && i+1<argc) hexkey=argv[++i];
        else if (strcmp(argv[i], "--pem")==0 && i+1<argc) { pem=argv[++i]; char *c=strchr((char*)pem, ':'); if (c){ *c='\0'; pass=c+1; } }
    }
    if (strcmp(type, "rsa")==0) {
        if (!pem) { fprintf(stderr, "put-key rsa: --pem <file>[:pass] required\n"); return -1; }
        if (!status_ok(GP211_put_rsa_key(ctx, info, sec, setVer, idx, newSetVer, (char*)pem, pass))) { fprintf(stderr, "put rsa key failed\n"); return -1; }
        return 0;
    } else if (strcmp(type, "aes")==0) {
        if (!hexkey) { fprintf(stderr, "put-key aes: --key <hex> required\n"); return -1; }
        unsigned char k[32]; size_t klen=sizeof(k); if (hex_to_bytes(hexkey, k, &klen)!=0 || (klen!=16 && klen!=24 && klen!=32)) { fprintf(stderr, "Invalid AES key len\n"); return -1; }
        if (!status_ok(GP211_put_aes_key(ctx, info, sec, setVer, idx, newSetVer, k, (DWORD)klen))) { fprintf(stderr, "put aes key failed\n"); return -1; }
        return 0;
    } else if (strcmp(type, "3des")==0) {
        if (!hexkey) { fprintf(stderr, "put-key 3des: --key <hex> required\n"); return -1; }
        unsigned char k[16]; size_t klen=sizeof(k); if (hex_to_bytes(hexkey, k, &klen)!=0 || klen!=16) { fprintf(stderr, "3DES key must be 16 hex bytes\n"); return -1; }
        if (!status_ok(GP211_put_3des_key(ctx, info, sec, setVer, idx, newSetVer, k))) { fprintf(stderr, "put 3des key failed\n"); return -1; }
        return 0;
    } else {
        fprintf(stderr, "put-key: unsupported --type '%s' (use 3des|aes|rsa). For Secure Channel keys use put-sc-key.\n", type);
        return -1;
    }
}

static int cmd_put_sc_key(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    BYTE setVer=0, newSetVer=0; const char *base=NULL, *senc=NULL, *smac=NULL, *dek=NULL;
    for (int i=0;i<argc;i++) {
        if (strcmp(argv[i], "--set")==0 && i+1<argc) setVer=(BYTE)atoi(argv[++i]);
        else if (strcmp(argv[i], "--new-set")==0 && i+1<argc) newSetVer=(BYTE)atoi(argv[++i]);
        else if (strcmp(argv[i], "--base")==0 && i+1<argc) base=argv[++i];
        else if (strcmp(argv[i], "--senc")==0 && i+1<argc) senc=argv[++i];
        else if (strcmp(argv[i], "--smac")==0 && i+1<argc) smac=argv[++i];
        else if (strcmp(argv[i], "--dek")==0 && i+1<argc) dek=argv[++i];
    }
    if (!setVer && !newSetVer) {
        // allow zero, but typically setVer is 0 for default
    }
    if (base && (senc || smac || dek)) {
        fprintf(stderr, "put-sc-key: use either --base OR all of --senc/--smac/--dek\n"); return -1;
    }
    if (!base && !(senc && smac && dek)) {
        fprintf(stderr, "put-sc-key: specify either --base <hex> or --senc/--smac/--dek <hex>\n"); return -1;
    }
    if (base) {
        unsigned char b[32]; size_t blen=sizeof(b); if (hex_to_bytes(base, b, &blen)!=0 || (blen!=16 && blen!=24 && blen!=32)) { fprintf(stderr, "Invalid base key length\n"); return -1; }
        OPGP_ERROR_STATUS s = GP211_put_secure_channel_keys(ctx, info, sec, setVer, newSetVer, b, NULL, NULL, NULL, (DWORD)blen);
        if (!status_ok(s)) { fprintf(stderr, "put-sc-key (base) failed\n"); return -1; }
        return 0;
    } else {
        unsigned char se[32], sm[32], dk[32]; size_t el=sizeof(se), ml=sizeof(sm), dl=sizeof(dk);
        if (hex_to_bytes(senc, se, &el)!=0 || hex_to_bytes(smac, sm, &ml)!=0 || hex_to_bytes(dek, dk, &dl)!=0) { fprintf(stderr, "Invalid hex for S-ENC/S-MAC/DEK\n"); return -1; }
        if (!((el==ml && ml==dl) && (el==16 || el==24 || el==32))) { fprintf(stderr, "Keys must have equal length of 16/24/32 bytes\n"); return -1; }
        OPGP_ERROR_STATUS s = GP211_put_secure_channel_keys(ctx, info, sec, setVer, newSetVer, NULL, se, sm, dk, (DWORD)el);
        if (!status_ok(s)) { fprintf(stderr, "put-sc-key (triple) failed\n"); return -1; }
        return 0;
    }
}

static int cmd_del_key(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    BYTE setVer=0; BYTE idx=0xFF; // 0xFF => delete all keys in set
    for (int i=0;i<argc;i++) {
        if (strcmp(argv[i], "--set")==0 && i+1<argc) setVer=(BYTE)atoi(argv[++i]);
        else if (strcmp(argv[i], "--index")==0 && i+1<argc) idx=(BYTE)atoi(argv[++i]);
    }
    if (!status_ok(GP211_delete_key(ctx, info, sec, setVer, idx))) { fprintf(stderr, "delete key failed\n"); return -1; }
    return 0;
}

static int cmd_apdu(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, const char *hex) {
    if (!hex) { fprintf(stderr, "apdu: missing <hex>\n"); return -1; }
    unsigned char capdu[APDU_COMMAND_LEN]; size_t clen=sizeof(capdu); if (hex_to_bytes(hex, capdu, &clen)!=0) { fprintf(stderr, "Invalid hex\n"); return -1; }
    unsigned char rapdu[APDU_RESPONSE_LEN]; DWORD rlen=sizeof(rapdu);
    if (!status_ok(GP211_send_APDU(ctx, info, sec, capdu, (DWORD)clen, rapdu, &rlen))) { fprintf(stderr, "APDU send failed\n"); return -1; }
    print_hex(rapdu, rlen); printf("\n"); return 0;
}

static int cmd_dap(int is_rsa, OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    if (is_rsa) {
        if (argc < 3) { fprintf(stderr, "dap rsa <cap-file> <sd-aidhex> <pem>[:pass]\n"); return -1; }
        const char *cap = argv[0]; const char *sd_hex = argv[1]; const char *pem = argv[2];
        unsigned char sd[16]; size_t sdlen=sizeof(sd); if (hex_to_bytes(sd_hex, sd, &sdlen)!=0) { fprintf(stderr, "Invalid sd-aid\n"); return -1; }
        BYTE hash20[20]; if (!status_ok(GP211_calculate_load_file_data_block_hash((char*)cap, hash20, 20, sec->secureChannelProtocol))) { fprintf(stderr, "hash failed\n"); return -1; }
        char pemcopy[512]; strncpy(pemcopy, pem, sizeof(pemcopy)-1); pemcopy[sizeof(pemcopy)-1]='\0'; char *pass=NULL; char *c=strchr(pemcopy,':'); if (c){*c='\0'; pass=c+1;}
        GP211_DAP_BLOCK dap; if (!status_ok(GP211_calculate_rsa_DAP(hash20, sd, (DWORD)sdlen, pemcopy, pass, &dap))) { fprintf(stderr, "calc rsa DAP failed\n"); return -1; }
        printf("E2%02X4F%02X", (unsigned)(dap.securityDomainAIDLength + dap.signatureLength + 4), dap.securityDomainAIDLength);
        print_hex(dap.securityDomainAID, dap.securityDomainAIDLength);
        printf("C8%02X", dap.signatureLength); print_hex(dap.signature, dap.signatureLength); printf("\n");
        return 0;
    } else {
        if (argc < 3) { fprintf(stderr, "dap aes <cap-file> <sd-aidhex> <hexkey>\n"); return -1; }
        const char *cap = argv[0]; const char *sd_hex = argv[1]; const char *hexkey = argv[2];
        unsigned char sd[16]; size_t sdlen=sizeof(sd); if (hex_to_bytes(sd_hex, sd, &sdlen)!=0) { fprintf(stderr, "Invalid sd-aid\n"); return -1; }
        unsigned char key[32]; size_t klen=sizeof(key); if (hex_to_bytes(hexkey, key, &klen)!=0) { fprintf(stderr, "Invalid hexkey\n"); return -1; }
        BYTE hash[64]; DWORD hlen = (sec->secureChannelProtocol == GP211_SCP03) ? 64 : 20;
        if (!status_ok(GP211_calculate_load_file_data_block_hash((char*)cap, hash, hlen, sec->secureChannelProtocol))) { fprintf(stderr, "hash failed\n"); return -1; }
        GP211_DAP_BLOCK dap; if (!status_ok(GP211_calculate_DAP(hash, (BYTE)hlen, sd, (DWORD)sdlen, key, (DWORD)klen, &dap, sec->secureChannelProtocol))) { fprintf(stderr, "calc aes DAP failed\n"); return -1; }
        printf("E2%02X4F%02X", (unsigned)(dap.securityDomainAIDLength + dap.signatureLength + 4), dap.securityDomainAIDLength);
        print_hex(dap.securityDomainAID, dap.securityDomainAIDLength);
        printf("C8%02X", dap.signatureLength); print_hex(dap.signature, dap.signatureLength); printf("\n");
        return 0;
    }
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
    int verbose=0, trace=0; BYTE keyset_ver=0, key_index=0; int derivation=0;
    int i=1; for (; i<argc; ++i) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { print_usage(prog); return 0; }
        else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) { verbose=1; }
        else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--trace")) { trace=1; }
        else if (!strcmp(argv[i], "--reader") && i+1<argc) { reader=argv[++i]; }
        else if (!strcmp(argv[i], "--protocol") && i+1<argc) { protocol=argv[++i]; }
        else if (!strcmp(argv[i], "--keyset-version") && i+1<argc) { keyset_ver=(BYTE)atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--key-index") && i+1<argc) { key_index=(BYTE)atoi(argv[++i]); }
        else if (!strcmp(argv[i], "--derive") && i+1<argc) { const char *d=argv[++i]; if (!strcmp(d,"visa2")) derivation=1; else if (!strcmp(d,"emv")) derivation=2; else if (!strcmp(d,"visa1")) derivation=3; else derivation=0; }
        else if (!strcmp(argv[i], "--sec-level") && i+1<argc) { sec_level_opt=argv[++i]; }
        else if (!strcmp(argv[i], "--isd") && i+1<argc) { isd_hex=argv[++i]; }
        else break;
    }
    if (i>=argc) { print_usage(prog); return 1; }
    const char *cmd = argv[i++];

    OPGP_CARD_CONTEXT ctx; OPGP_CARD_INFO info; GP211_SECURITY_INFO sec; memset(&ctx,0,sizeof(ctx)); memset(&info,0,sizeof(info)); memset(&sec,0,sizeof(sec));
    if (connect_pcsc(&ctx, &info, reader, protocol, trace) != 0) return 3;
    if (select_isd(ctx, info, isd_hex) != 0) { fprintf(stderr, "Failed to select ISD\n"); OPGP_card_disconnect(ctx, &info); OPGP_release_context(&ctx); return 4; }
    if (mutual_auth(ctx, info, &sec, keyset_ver, key_index, derivation, sec_level_opt, verbose) != 0) { fprintf(stderr, "Mutual authentication failed\n"); OPGP_card_disconnect(ctx, &info); OPGP_release_context(&ctx); return 5; }

    int rc = 0;
    if (!strcmp(cmd, "list")) rc = cmd_list(ctx, info, &sec);
    else if (!strcmp(cmd, "keys")) rc = cmd_keys(ctx, info, &sec);
    else if (!strcmp(cmd, "install")) rc = cmd_install(ctx, info, &sec, argc - i, &argv[i]);
    else if (!strcmp(cmd, "delete")) rc = cmd_delete(ctx, info, &sec, (i<argc)?argv[i]:NULL);
    else if (!strcmp(cmd, "put-key")) rc = cmd_put_key(ctx, info, &sec, argc - i, &argv[i]);
    else if (!strcmp(cmd, "put-sc-key")) rc = cmd_put_sc_key(ctx, info, &sec, argc - i, &argv[i]);
    else if (!strcmp(cmd, "del-key")) rc = cmd_del_key(ctx, info, &sec, argc - i, &argv[i]);
    else if (!strcmp(cmd, "apdu")) rc = cmd_apdu(ctx, info, &sec, (i<argc)?argv[i]:NULL);
    else if (!strcmp(cmd, "dap")) {
        if (i>=argc) { fprintf(stderr, "dap: missing type aes|rsa\n"); rc=-1; }
        else if (!strcmp(argv[i], "rsa")) rc = cmd_dap(1, ctx, info, &sec, argc - (i+1), &argv[i+1]);
        else if (!strcmp(argv[i], "aes")) rc = cmd_dap(0, ctx, info, &sec, argc - (i+1), &argv[i+1]);
        else { fprintf(stderr, "dap: unknown type\n"); rc=-1; }
    } else { fprintf(stderr, "Unknown command: %s\n", cmd); rc=-1; }

    OPGP_card_disconnect(ctx, &info);
    OPGP_release_context(&ctx);
    return rc==0?0:10;
}
