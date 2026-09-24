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
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.
 */

#ifndef _WIN32
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#include <globalplatform/globalplatform.h>
#include "util.h"
#include "gpshell3_output.h"
#include "gpshell3_session.h"
#include "gpshell3_registry.h"
#include "gpshell3_commands.h"
#include "gpshell3_mcp.h"

#ifdef _WIN32
static int setenv(const char *name, const char *value, int overwrite) {
    if (!overwrite && getenv(name) != NULL) {
        return 0;
    }
    return _putenv_s(name, value ? value : "") == 0 ? 0 : -1;
}
#endif

static int parse_int(const char *s) {
    if (s == NULL) return 0;
    return (int)strtol(s, NULL, 0);
}

static int hex_to_bytes(const char *hex, unsigned char *out, size_t *outlen) {
    size_t len = strlen(hex), i = 0, j = 0;
    if (len % 2 != 0) return -1;
    if (*outlen < len/2) return -2;
    for (; i < len; i += 2) {
        int v1, v2;
        char c1 = (char)tolower((unsigned char)hex[i]);
        char c2 = (char)tolower((unsigned char)hex[i+1]);
        v1 = (c1 >= '0' && c1 <= '9') ? c1 - '0' : (c1 >= 'a' && c1 <= 'f') ? c1 - 'a' + 10 : -1;
        v2 = (c2 >= '0' && c2 <= '9') ? c2 - '0' : (c2 >= 'a' && c2 <= 'f') ? c2 - 'a' + 10 : -1;
        if (v1 < 0 || v2 < 0) return -3;
        out[j++] = (unsigned char)((v1 << 4) | v2);
    }
    *outlen = j;
    return 0;
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [global-options] <command> [command-args] [then <command> [command-args] ...]\n\n", prog);

    fputs(
        "Global options:\n"
        "  -r, --reader <name|num>    PC/SC reader name or number (1-based) (default: auto first present)\n"
        "  --protocol <auto|t0|t1>    Transport protocol (default: auto)\n"
        "  --sd <aidhex>             ISD AID hex; default tries A000000151000000 then A0000001510000 then A000000003000000 then A0000000030000\n"
        "  --sec <auto|mac|mac+enc|mac+enc+rmac>\n"
        "                            Secure channel security level (default: auto)\n"
        "  --scp <protocol>           SCP protocol as digit (e.g., 1, 2, 3, 11; 0x11 also accepted)\n"
        "  --scp-impl <impl>          SCP implementation as hex (e.g., 15, 55)\n"
        "  --scp11-cert <file>        SCP11 OCE certificate chain file for PERFORM SECURITY OPERATION (DER TLV chain/BF21)\n"
        "  --scp11-sd-public-key <hex|pem>\n"
        "                            SCP11 SD ECKA public key as PEM file, raw uncompressed EC point, or B0 TLV\n"
        "  --scp11-session-key-length <n>\n"
        "                            SCP11 AES session key length: 16, 24 or 32 bytes (default: 16 / 0x10)\n"
        "  --kv <n>                   Key set version for mutual auth (default: 0)\n"
        "  --idx <n>                  Key index within key set for mutual auth (default: 0)\n"
        "  --derive <none|visa2|emv>  Key derivation (default: none)\n"
        "  --key <hex>                Base key for mutual auth; for SCP11, raw SK.OCE.ECKA private key (default: 40..4F)\n"
        "  --enc <hex>                ENC key for mutual auth (default: 40..4F)\n"
        "  --mac <hex>                MAC key for mutual auth (default: 40..4F)\n"
        "  --dek <hex>                DEK key for mutual auth (default: 40..4F)\n"
        "  --output <text|json>       Output format (default: text)\n"
        "  --mcp                      Start MCP JSON-RPC 2.0 server over STDIO\n"
        "  -v, --verbose              Verbose output\n"
        "  -t, --trace                Enable APDU trace\n"
        "  -h, --help                 Show this help\n\n"
        "Commands:\n"
        "  list-apps, list-keys, list-readers, hash, sign-dap, sign-load-token, sign-install-token,\n"
        "  sign-extradition-token, sign-update-registry-token, sign-delete-token, verify-delete-receipt,\n"
        "  verify-load-receipt, verify-install-receipt, verify-registry-update-receipt, verify-move-receipt,\n"
        "  cplc, card-data, iin, cin, card-info, card-cap, card-resources, div-data, seq-counter,\n"
        "  confirm-counter, scp11-cert-data, scp11-store-cert, scp11-store-ca-id, store-iin, store-cin,\n"
        "  install, install-sd, delete, update-registry, move, put-key, put-auth, put-dm-token,\n"
        "  put-dm-receipt, put-dap-key, del-key, apdu, status, store\n",
        stderr);
}

int main(int argc, char **argv) {
    const char *prog = argv[0];
    const char *reader = NULL, *protocol = "auto", *sd_hex = NULL, *sec_level_opt = "auto";
    const char *key_hex = NULL, *enc_hex = NULL, *mac_hex = NULL, *dek_hex = NULL;
    int verbose = 0, trace = 0; BYTE keyset_ver = 0, key_index = 0; int derivation = 0;
    BYTE baseKey[32] = {0}, enc_key[32] = {0}, mac_key[32] = {0}, dek_key[32] = {0};
    BYTE keyLength = 0;
    BYTE scp11SessionKeyLength = 16;
    const char *scp_protocol = NULL, *scp_impl = NULL;
    const char *scp11_cert_file = NULL;
    const char *scp11_sd_public_key = NULL;
    gpshell3_output_mode_t output_mode = OUTPUT_FORMAT_TEXT;

    gpshell3_registry_init();

    int i = 1;
    for (; i < argc; ++i) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_usage(prog);
            return 0;
        }
        if (!strcmp(argv[i], "--mcp")) {
            gpshell3_mcp_server_t server;
            gpshell3_mcp_server_init(&server, stdin, stdout, stderr);
            int mcp_rc = gpshell3_mcp_run_stdio_loop(&server);
            return mcp_rc;
        }
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) {
            verbose = 1;
            setenv("GLOBALPLATFORM_DEBUG", "1", 1);
            setenv("GLOBALPLATFORM_LOGFILE", "stderr", 1);
        }
        else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--trace")) { trace = 1; }
        else if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--reader")) { if (i + 1 < argc) reader = argv[++i]; }
        else if (!strcmp(argv[i], "--protocol") && i + 1 < argc) { protocol = argv[++i]; }
        else if (!strcmp(argv[i], "--scp") && i + 1 < argc) { scp_protocol = argv[++i]; }
        else if (!strcmp(argv[i], "--scp-impl") && i + 1 < argc) { scp_impl = argv[++i]; }
        else if (!strcmp(argv[i], "--scp11-cert") && i + 1 < argc) { scp11_cert_file = argv[++i]; }
        else if (!strcmp(argv[i], "--scp11-sd-public-key") && i + 1 < argc) { scp11_sd_public_key = argv[++i]; }
        else if (!strcmp(argv[i], "--scp11-session-key-length") && i + 1 < argc) {
            int parsedLength = parse_int(argv[++i]);
            if (parsedLength != 16 && parsedLength != 24 && parsedLength != 32) {
                fprintf(stderr, "--scp11-session-key-length must be 16, 24 or 32 bytes\n");
                return 2;
            }
            scp11SessionKeyLength = (BYTE)parsedLength;
        }
        else if (!strcmp(argv[i], "--kv") && i + 1 < argc) { keyset_ver = (BYTE)parse_int(argv[++i]); }
        else if (!strcmp(argv[i], "--idx") && i + 1 < argc) { key_index = (BYTE)parse_int(argv[++i]); }
        else if (!strcmp(argv[i], "--derive") && i + 1 < argc) {
            const char *d = argv[++i];
            if (!strcmp(d, "visa2")) derivation = 1;
            else if (!strcmp(d, "emv")) derivation = 2;
            else derivation = 0;
        }
        else if (!strcmp(argv[i], "--sec") && i + 1 < argc) { sec_level_opt = argv[++i]; }
        else if (!strcmp(argv[i], "--sd") && i + 1 < argc) { sd_hex = argv[++i]; }
        else if (!strcmp(argv[i], "--key") && i + 1 < argc) { key_hex = argv[++i]; }
        else if (!strcmp(argv[i], "--enc") && i + 1 < argc) { enc_hex = argv[++i]; }
        else if (!strcmp(argv[i], "--mac") && i + 1 < argc) { mac_hex = argv[++i]; }
        else if (!strcmp(argv[i], "--dek") && i + 1 < argc) { dek_hex = argv[++i]; }
        else if (!strcmp(argv[i], "--output") && i + 1 < argc) {
            const char *out_opt = argv[++i];
            if (!strcmp(out_opt, "json")) output_mode = OUTPUT_FORMAT_JSON;
            else if (!strcmp(out_opt, "text")) output_mode = OUTPUT_FORMAT_TEXT;
        }
        else if (!strcmp(argv[i], "--json")) { output_mode = OUTPUT_FORMAT_JSON; }
        else break;
    }

    if (i >= argc) {
        print_usage(prog);
        return 1;
    }

    gpshell3_output_ctx_t out;
    gpshell3_output_init(&out, output_mode);

    gpshell3_session_t session;
    gpshell3_session_init(&session);

    const char *cmd = argv[i++];

    const gpshell3_cmd_def_t *first_cmd_def = gpshell3_registry_find_by_name(cmd);
    if (!first_cmd_def) {
        gpshell3_report_error(&out, "UNKNOWN_COMMAND", "Unknown command: %s", cmd);
        gpshell3_output_flush(&out);
        gpshell3_output_cleanup(&out);
        return 1;
    }

    /* Offline commands that do not require a card connection */
    if (!first_cmd_def->requires_session) {
        int rc = first_cmd_def->execute_cli(&session, argc - i, &argv[i], &out);
        gpshell3_output_flush(&out);
        gpshell3_output_cleanup(&out);
        return (rc == 0) ? 0 : 10;
    }

    /* Establish PC/SC connection */
    if (gpshell3_connect_pcsc(&session, reader, protocol, trace, verbose) != 0) {
        gpshell3_report_error(&out, "CONNECTION_FAILED", "Failed to connect to card reader");
        gpshell3_output_flush(&out);
        gpshell3_output_cleanup(&out);
        return 3;
    }

    int need_auth = 1;
    int need_select = 1;
    if (!strcmp(cmd, "apdu")) {
        need_auth = 0;
        need_select = 0;
        for (int j = i; j < argc; ++j) {
            if (!strcmp(argv[j], "--auth") || !strcmp(argv[j], "--secure")) {
                need_auth = 1;
                need_select = 1;
                break;
            }
        }
    }
    if (!strcmp(cmd, "card-data") || !strcmp(cmd, "iin") || !strcmp(cmd, "cin")
        || !strcmp(cmd, "card-info") || !strcmp(cmd, "card-cap") || !strcmp(cmd, "card-resources")
        || !strcmp(cmd, "div-data") || !strcmp(cmd, "seq-counter") || !strcmp(cmd, "confirm-counter")
        || !strcmp(cmd, "scp11-cert-data")) {
        need_auth = 0;
    }

    /* Parse key options if provided */
    BYTE *baseKeyPtr = NULL, *encKeyPtr = NULL, *macKeyPtr = NULL, *dekKeyPtr = NULL;
    if (key_hex || enc_hex || mac_hex || dek_hex) {
        if (key_hex && (enc_hex || mac_hex || dek_hex)) {
            gpshell3_report_error(&out, "INVALID_OPTIONS", "Cannot specify both --key and individual keys (--enc/--mac/--dek)");
            gpshell3_output_flush(&out);
            gpshell3_session_close(&session);
            gpshell3_output_cleanup(&out);
            return 2;
        }
        if (key_hex) {
            size_t klen = sizeof(baseKey);
            if (hex_to_bytes(key_hex, baseKey, &klen) != 0 || (klen != 16 && klen != 24 && klen != 32)) {
                gpshell3_report_error(&out, "INVALID_KEY", "Invalid --key (must be 16, 24, or 32 bytes hex)");
                gpshell3_output_flush(&out);
                gpshell3_session_close(&session);
                gpshell3_output_cleanup(&out);
                return 2;
            }
            keyLength = (BYTE)klen;
            baseKeyPtr = baseKey;
        } else if (enc_hex && mac_hex && dek_hex) {
            size_t el = sizeof(enc_key), ml = sizeof(mac_key), dl = sizeof(dek_key);
            if (hex_to_bytes(enc_hex, enc_key, &el) != 0 || hex_to_bytes(mac_hex, mac_key, &ml) != 0 || hex_to_bytes(dek_hex, dek_key, &dl) != 0) {
                gpshell3_report_error(&out, "INVALID_KEY", "Invalid hex for --enc/--mac/--dek");
                gpshell3_output_flush(&out);
                gpshell3_session_close(&session);
                gpshell3_output_cleanup(&out);
                return 2;
            }
            if (!((el == ml && ml == dl) && (el == 16 || el == 24 || el == 32))) {
                gpshell3_report_error(&out, "INVALID_KEY", "Keys --enc/--mac/--dek must have equal length of 16/24/32 bytes");
                gpshell3_output_flush(&out);
                gpshell3_session_close(&session);
                gpshell3_output_cleanup(&out);
                return 2;
            }
            keyLength = (BYTE)el;
            encKeyPtr = enc_key;
            macKeyPtr = mac_key;
            dekKeyPtr = dek_key;
        } else {
            gpshell3_report_error(&out, "INVALID_OPTIONS", "Must specify either --key OR all of --enc/--mac/--dek");
            gpshell3_output_flush(&out);
            gpshell3_session_close(&session);
            gpshell3_output_cleanup(&out);
            return 2;
        }
    }

    if (need_select) {
        if (gpshell3_select_isd(&session, sd_hex) != 0) {
            gpshell3_report_error(&out, "SELECT_ISD_FAILED", "Failed to select ISD");
            gpshell3_output_flush(&out);
            gpshell3_session_close(&session);
            gpshell3_output_cleanup(&out);
            return 4;
        }
    }
    if (need_auth) {
        if (gpshell3_mutual_auth(&session, keyset_ver, key_index, derivation, sec_level_opt, verbose,
                                 baseKeyPtr, encKeyPtr, macKeyPtr, dekKeyPtr, keyLength,
                                 scp_protocol, scp_impl, scp11_cert_file, scp11_sd_public_key,
                                 scp11SessionKeyLength) != 0) {
            gpshell3_report_error(&out, "AUTH_FAILED", "Mutual authentication failed");
            gpshell3_output_flush(&out);
            gpshell3_session_close(&session);
            gpshell3_output_cleanup(&out);
            return 5;
        }
    }

    /* Command chaining loop */
    int rc = 0;
    while (1) {
        int cmd_end = argc;
        for (int j = i; j < argc; j++) {
            if (!strcmp(argv[j], "then")) {
                cmd_end = j;
                break;
            }
        }
        int cmd_argc = cmd_end - i;

        const gpshell3_cmd_def_t *cmd_def = gpshell3_registry_find_by_name(cmd);
        if (!cmd_def) {
            gpshell3_report_error(&out, "UNKNOWN_COMMAND", "Unknown command: %s", cmd);
            rc = -1;
        } else {
            rc = cmd_def->execute_cli(&session, cmd_argc, &argv[i], &out);
        }

        gpshell3_output_flush(&out);
        gpshell3_output_reset(&out);

        if (rc != 0) {
            gpshell3_session_close(&session);
            gpshell3_output_cleanup(&out);
            return 10;
        }

        if (cmd_end >= argc) break;
        i = cmd_end + 1;
        if (i >= argc) {
            gpshell3_report_error(&out, "INVALID_CHAIN", "Error: 'then' at end of command line without a following command");
            gpshell3_output_flush(&out);
            gpshell3_session_close(&session);
            gpshell3_output_cleanup(&out);
            return 2;
        }
        cmd = argv[i++];
    }

    gpshell3_session_close(&session);
    gpshell3_output_cleanup(&out);
    return 0;
}
