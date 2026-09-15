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
#include <sys/types.h>
#include <fcntl.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <time.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <globalplatform/globalplatform.h>
#include "util.h"
#include "gpshell3_session.h"
#include "gpshell3_registry.h"
#include "gpshell3_output.h"

#define MAX_READERS_BUF 4096
#define MAX_PATH_BUF 4096
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))


static int hex_to_bytes_session(const char *hex, unsigned char *out, size_t *outlen) {
    if (!hex || !out || !outlen) return -1;
    size_t len = strlen(hex), i = 0, j = 0;
    if (len % 2 != 0) return -1;
    if (*outlen < len / 2) return -2;
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

static void generate_session_id(char *out, size_t out_len) {
    if (!out || out_len <= GPSHELL3_SESSION_ID_LEN) return;
    unsigned char random_bytes[32];
    int success = 0;

    if (RAND_bytes(random_bytes, sizeof(random_bytes)) == 1) {
        success = 1;
    }

#ifndef _WIN32
    if (!success) {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            if (read(fd, random_bytes, sizeof(random_bytes)) == sizeof(random_bytes)) {
                success = 1;
            }
            close(fd);
        }
    }
#endif

    if (!success) {
        /* Pseudo-random fallback */
        static unsigned int counter = 0;
        srand((unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)&counter ^ counter++);
        for (size_t i = 0; i < sizeof(random_bytes); i++) {
            random_bytes[i] = (unsigned char)(rand() & 0xFF);
        }
    }

    for (size_t i = 0; i < sizeof(random_bytes); i++) {
        snprintf(out + (i * 2), out_len - (i * 2), "%02x", random_bytes[i]);
    }
    out[GPSHELL3_SESSION_ID_LEN] = '\0';
    OPENSSL_cleanse(random_bytes, sizeof(random_bytes));
}

void gpshell3_session_init(gpshell3_session_t *session) {
    if (!session) return;
    memset(session, 0, sizeof(*session));
    _tcsncpy(session->ctx.libraryName, _T("gppcscconnectionplugin"),
             _tcslen(_T("gppcscconnectionplugin")) + 1);
    _tcsncpy(session->ctx.libraryVersion, _T("1"),
             _tcslen(_T("1")) + 1);
}

void gpshell3_session_zeroize_params(gpshell3_session_params_t *params) {
    if (!params) return;
    OPENSSL_cleanse(params->key, sizeof(params->key));
    OPENSSL_cleanse(params->enc, sizeof(params->enc));
    OPENSSL_cleanse(params->mac, sizeof(params->mac));
    OPENSSL_cleanse(params->dek, sizeof(params->dek));
    OPENSSL_cleanse(params->scp11_sd_public_key, sizeof(params->scp11_sd_public_key));
    memset(params, 0, sizeof(*params));
}

void gpshell3_session_zeroize_session(gpshell3_session_t *session) {
    if (!session) return;
    OPENSSL_cleanse(session->sec.C_MACSessionKey, sizeof(session->sec.C_MACSessionKey));
    OPENSSL_cleanse(session->sec.R_MACSessionKey, sizeof(session->sec.R_MACSessionKey));
    OPENSSL_cleanse(session->sec.encryptionSessionKey, sizeof(session->sec.encryptionSessionKey));
    OPENSSL_cleanse(session->sec.dataEncryptionSessionKey, sizeof(session->sec.dataEncryptionSessionKey));
    OPENSSL_cleanse(session->sec.lastC_MAC, sizeof(session->sec.lastC_MAC));
    OPENSSL_cleanse(session->sec.lastR_MAC, sizeof(session->sec.lastR_MAC));
    OPENSSL_cleanse(session->session_id, sizeof(session->session_id));
}

void gpshell3_session_close(gpshell3_session_t *session) {
    if (!session) return;
    if (session->is_connected) {
        OPGP_card_disconnect(session->ctx, &session->info);
        session->is_connected = false;
    }
    if (session->ctx.libraryHandle != NULL || session->ctx.libraryName[0] != _T('\0')) {
        OPGP_release_context(&session->ctx);
    }
    gpshell3_session_zeroize_session(session);
    session->is_authenticated = false;
    session->connected_reader[0] = '\0';
    session->selected_isd_len = 0;
    session->current_scp = 0;
    session->current_scp_impl = 0;
    session->current_scp_set = 0;
}

bool gpshell3_session_is_valid(const gpshell3_session_t *session, const char *session_id) {
    if (!session || !session->is_connected || session->session_id[0] == '\0') {
        return false;
    }
    if (session_id && *session_id) {
        return strcmp(session->session_id, session_id) == 0;
    }
    return true;
}

int gpshell3_session_open(gpshell3_session_t *session, const gpshell3_session_params_t *params, gpshell3_output_ctx_t *out) {
    if (!session) {
        if (out) gpshell3_report_error(out, "INVALID_ARGUMENT", "Null session pointer");
        return -1;
    }

    /* Reset existing session if already connected */
    if (session->is_connected) {
        gpshell3_session_close(session);
    }
    gpshell3_session_init(session);

    const char *reader_opt = (params && params->reader[0] != '\0') ? params->reader : NULL;
    const char *proto_opt = (params && params->protocol[0] != '\0') ? params->protocol : NULL;

    int rc = gpshell3_connect_pcsc(session, reader_opt, proto_opt, params ? params->trace : 0, params ? params->verbose : 0);
    if (rc != 0) {
        if (out) gpshell3_report_error(out, "NO_READERS", "Failed to connect to card reader");
        return -1;
    }

    /* Select ISD */
    const char *sd_opt = (params && params->sd[0] != '\0') ? params->sd : NULL;
    rc = gpshell3_select_isd(session, sd_opt);
    if (rc != 0) {
        if (out) gpshell3_report_error(out, "SELECT_ISD_FAILED", "Failed to select Issuer Security Domain");
        gpshell3_session_close(session);
        return -1;
    }

    /* Mutual authentication if requested */
    if (params && params->auth_mode == GPSHELL3_AUTH_MODE_SECURE_CHANNEL) {
        BYTE baseKey[32] = {0}, encKey[32] = {0}, macKey[32] = {0}, dekKey[32] = {0};
        size_t baseLen = sizeof(baseKey), encLen = sizeof(encKey), macLen = sizeof(macKey), dekLen = sizeof(dekKey);
        BYTE *pBase = NULL, *pEnc = NULL, *pMac = NULL, *pDek = NULL;
        BYTE keyLen = 16;

        if (params->key[0] != '\0') {
            if (hex_to_bytes_session(params->key, baseKey, &baseLen) != 0 || (baseLen != 16 && baseLen != 24 && baseLen != 32)) {
                if (out) gpshell3_report_error(out, "INVALID_KEY", "Invalid base key hex (must be 16, 24, or 32 bytes)");
                OPENSSL_cleanse(baseKey, sizeof(baseKey));
                gpshell3_session_close(session);
                return -1;
            }
            pBase = baseKey;
            keyLen = (BYTE)baseLen;
        } else if (params->enc[0] != '\0' && params->mac[0] != '\0' && params->dek[0] != '\0') {
            if (hex_to_bytes_session(params->enc, encKey, &encLen) != 0 ||
                hex_to_bytes_session(params->mac, macKey, &macLen) != 0 ||
                hex_to_bytes_session(params->dek, dekKey, &dekLen) != 0 ||
                encLen != macLen || macLen != dekLen || (encLen != 16 && encLen != 24 && encLen != 32)) {
                if (out) gpshell3_report_error(out, "INVALID_KEY", "Invalid enc/mac/dek keys (lengths must match 16, 24, or 32 bytes)");
                OPENSSL_cleanse(encKey, sizeof(encKey));
                OPENSSL_cleanse(macKey, sizeof(macKey));
                OPENSSL_cleanse(dekKey, sizeof(dekKey));
                gpshell3_session_close(session);
                return -1;
            }
            pEnc = encKey; pMac = macKey; pDek = dekKey;
            keyLen = (BYTE)encLen;
        } else {
            if (out) gpshell3_report_error(out, "AUTHENTICATION_ERROR", "Explicit keys required for secure_channel mode");
            gpshell3_session_close(session);
            return -1;
        }

        const char *scp_opt = (params->scp[0] != '\0') ? params->scp : NULL;
        const char *scp_impl_opt = (params->scp_impl[0] != '\0') ? params->scp_impl : NULL;
        const char *sec_level_opt = (params->sec_level[0] != '\0') ? params->sec_level : "mac";
        const char *scp11_cert = (params->scp11_cert_file[0] != '\0') ? params->scp11_cert_file : NULL;
        const char *scp11_sd_pub = (params->scp11_sd_public_key[0] != '\0') ? params->scp11_sd_public_key : NULL;

        rc = gpshell3_mutual_auth(session, params->keyset_version, params->key_index, params->derivation,
                                  sec_level_opt, params->verbose,
                                  pBase, pEnc, pMac, pDek, keyLen,
                                  scp_opt, scp_impl_opt, scp11_cert, scp11_sd_pub, params->scp11_session_key_len);

        /* Cleanse raw memory */
        OPENSSL_cleanse(baseKey, sizeof(baseKey));
        OPENSSL_cleanse(encKey, sizeof(encKey));
        OPENSSL_cleanse(macKey, sizeof(macKey));
        OPENSSL_cleanse(dekKey, sizeof(dekKey));

        if (rc != 0) {
            if (out) gpshell3_report_error(out, "MUTUAL_AUTH_FAILED", "Mutual authentication failed");
            gpshell3_session_close(session);
            return -1;
        }
    }

    generate_session_id(session->session_id, sizeof(session->session_id));

    if (out) {
        if (out->mode == OUTPUT_FORMAT_JSON) {
            gpshell3_output_add_string(out, "sessionId", session->session_id);
            gpshell3_output_add_string(out, "reader", session->connected_reader);
            gpshell3_output_add_hex(out, "selectedIsd", session->selected_isd, session->selected_isd_len);
            gpshell3_output_add_bool(out, "authenticated", session->is_authenticated);
            if (session->is_authenticated) {
                char scp_str[32];
                snprintf(scp_str, sizeof(scp_str), "SCP%02d_i%02X", session->current_scp, session->current_scp_impl);
                gpshell3_output_add_string(out, "protocol", scp_str);
            }
        } else {
            FILE *f = out->out_stream ? out->out_stream : stdout;
            fprintf(f, "Connected to reader: %s\n", session->connected_reader);
            fprintf(f, "Session ID: %s\n", session->session_id);
            if (session->is_authenticated) {
                fprintf(f, "Authenticated via SCP%02d (impl=0x%02X)\n", session->current_scp, session->current_scp_impl);
            }
        }
    }
    return 0;
}

int gpshell3_session_open_json(gpshell3_session_t *session, const cJSON *args, gpshell3_output_ctx_t *out) {
    gpshell3_session_params_t params;
    memset(&params, 0, sizeof(params));
    params.keyset_version = 1;
    params.key_index = 0;
    params.auth_mode = GPSHELL3_AUTH_MODE_NONE;

    if (args) {
        const char *r = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(args, "reader"));
        if (r) strncpy(params.reader, r, sizeof(params.reader) - 1);

        const char *proto = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(args, "protocol"));
        if (proto) strncpy(params.protocol, proto, sizeof(params.protocol) - 1);

        const char *sd = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(args, "sd"));
        if (sd) strncpy(params.sd, sd, sizeof(params.sd) - 1);

        const cJSON *auth = cJSON_GetObjectItemCaseSensitive(args, "authentication");
        if (auth && cJSON_IsObject(auth)) {
            const char *mode = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(auth, "mode"));
            if (mode && !strcmp(mode, "secure_channel")) {
                params.auth_mode = GPSHELL3_AUTH_MODE_SECURE_CHANNEL;
            }

            cJSON *kv = cJSON_GetObjectItemCaseSensitive(auth, "keySetVersion");
            if (kv && cJSON_IsNumber(kv)) params.keyset_version = (BYTE)kv->valuedouble;

            cJSON *ki = cJSON_GetObjectItemCaseSensitive(auth, "keyIndex");
            if (ki && cJSON_IsNumber(ki)) params.key_index = (BYTE)ki->valuedouble;

            const char *kt = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(auth, "keyType"));
            if (kt) strncpy(params.key_type, kt, sizeof(params.key_type) - 1);

            const char *k = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(auth, "key"));
            if (k) strncpy(params.key, k, sizeof(params.key) - 1);

            const char *e = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(auth, "enc"));
            if (e) strncpy(params.enc, e, sizeof(params.enc) - 1);

            const char *m = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(auth, "mac"));
            if (m) strncpy(params.mac, m, sizeof(params.mac) - 1);

            const char *d = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(auth, "dek"));
            if (d) strncpy(params.dek, d, sizeof(params.dek) - 1);

            const char *deriv = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(auth, "derivation"));
            if (deriv) {
                if (!strcmp(deriv, "emv")) params.derivation = OPGP_DERIVATION_METHOD_EMV_CPS11;
                else if (!strcmp(deriv, "visa2")) params.derivation = OPGP_DERIVATION_METHOD_VISA2;
            }

            const char *sec = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(auth, "securityLevel"));
            if (sec) strncpy(params.sec_level, sec, sizeof(params.sec_level) - 1);

            const char *scp = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(auth, "scp"));
            if (scp) strncpy(params.scp, scp, sizeof(params.scp) - 1);

            cJSON *impl = cJSON_GetObjectItemCaseSensitive(auth, "scpImpl");
            if (impl && cJSON_IsNumber(impl)) snprintf(params.scp_impl, sizeof(params.scp_impl), "%d", (int)impl->valuedouble);
        }
    }

    int rc = gpshell3_session_open(session, &params, out);
    gpshell3_session_zeroize_params(&params);
    return rc;
}

/* --- MCP Tool Schemas & Handlers --- */

cJSON *gpshell3_cmd_open_session_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "reader", "Smart card reader name or index (e.g. 'ACS ACR122U 0' or '1')", false);
    const char *protocols[] = {"auto", "t0", "t1"};
    gpshell3_schema_add_prop_enum(s, "protocol", "Card communication protocol", protocols, 3, false);
    gpshell3_schema_add_prop_string(s, "sd", "Target Issuer Security Domain AID in hex", false);

    cJSON *auth_schema = gpshell3_schema_object();
    const char *modes[] = {"none", "secure_channel"};
    gpshell3_schema_add_prop_enum(auth_schema, "mode", "Authentication mode ('none' or 'secure_channel')", modes, 2, false);
    gpshell3_schema_add_prop_int(auth_schema, "keySetVersion", "Key Set Version (e.g. 1)", false);
    gpshell3_schema_add_prop_int(auth_schema, "keyIndex", "Key Index (e.g. 0)", false);
    const char *key_types[] = {"aes", "3des"};
    gpshell3_schema_add_prop_enum(auth_schema, "keyType", "Key algorithm type", key_types, 2, false);
    gpshell3_schema_add_prop_string(auth_schema, "key", "Base key hex string for mutual authentication", false);
    gpshell3_schema_add_prop_string(auth_schema, "enc", "Static S-ENC key hex string", false);
    gpshell3_schema_add_prop_string(auth_schema, "mac", "Static S-MAC key hex string", false);
    gpshell3_schema_add_prop_string(auth_schema, "dek", "Static DEK key hex string", false);
    const char *derivs[] = {"none", "emv", "visa2"};
    gpshell3_schema_add_prop_enum(auth_schema, "derivation", "Key derivation algorithm", derivs, 3, false);
    const char *sec_levels[] = {"none", "mac", "mac+enc", "mac+rmac", "mac+enc+rmac"};
    gpshell3_schema_add_prop_enum(auth_schema, "securityLevel", "Secure channel communication level", sec_levels, 5, false);
    const char *scps[] = {"scp01", "scp02", "scp03", "scp11"};
    gpshell3_schema_add_prop_enum(auth_schema, "scp", "Secure Channel Protocol version", scps, 4, false);
    gpshell3_schema_add_prop_int(auth_schema, "scpImpl", "SCP implementation mode option bits", false);

    cJSON *props = cJSON_GetObjectItemCaseSensitive(s, "properties");
    if (props) {
        cJSON_AddItemToObject(props, "authentication", auth_schema);
    }
    return s;
}

cJSON *gpshell3_cmd_open_session_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "sessionId", "Opaque 64-character session identifier token", true);
    gpshell3_schema_add_prop_string(s, "reader", "Connected PC/SC reader name", true);
    gpshell3_schema_add_prop_string(s, "selectedIsd", "Selected ISD AID in hex", true);
    gpshell3_schema_add_prop_bool(s, "authenticated", "Whether mutual authentication was established", true);
    gpshell3_schema_add_prop_string(s, "protocol", "Negotiated SCP secure channel protocol", false);
    return s;
}

int gpshell3_cmd_open_session_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_open_session");
    return gpshell3_session_open_json(session, args, out);
}

cJSON *gpshell3_cmd_close_session_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "sessionId", "Opaque session identifier token to close", false);
    return s;
}

cJSON *gpshell3_cmd_close_session_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "closed", "True when session is successfully disconnected and wiped", true);
    return s;
}

int gpshell3_cmd_close_session_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_close_session");
    const char *sid = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(args, "sessionId"));
    if (session && session->is_connected) {
        if (sid && session->session_id[0] != '\0' && strcmp(session->session_id, sid) != 0) {
            gpshell3_report_error(out, "INVALID_SESSION_ID", "Provided session ID does not match active session");
            return -1;
        }
        gpshell3_session_close(session);
    }
    if (out->mode == OUTPUT_FORMAT_JSON) {
        gpshell3_output_add_bool(out, "closed", true);
    } else {
        FILE *f = out->out_stream ? out->out_stream : stdout;
        fprintf(f, "Session closed successfully.\n");
    }
    return 0;
}
