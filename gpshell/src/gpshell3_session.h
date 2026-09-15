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

#ifndef GPSHELL3_SESSION_H
#define GPSHELL3_SESSION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <globalplatform/globalplatform.h>
#include "cJSON.h"
#include "gpshell3_output.h"

#define GPSHELL3_SESSION_ID_LEN 64

/**
 * Authentication mode for smart card sessions.
 */
typedef enum {
    GPSHELL3_AUTH_MODE_NONE = 0,
    GPSHELL3_AUTH_MODE_SECURE_CHANNEL
} gpshell3_auth_mode_t;

/**
 * Parameters used to open and authenticate a card session.
 */
typedef struct gpshell3_session_params {
    char reader[256];
    char protocol[32];          /* "auto", "t0", "t1" */
    char sd[64];                /* Target ISD AID hex */
    gpshell3_auth_mode_t auth_mode;
    BYTE keyset_version;
    BYTE key_index;
    char key_type[32];          /* "aes", "3des", "scp11" */
    char key[128];              /* Base key hex */
    char enc[128];              /* S-ENC key hex */
    char mac[128];              /* S-MAC key hex */
    char dek[128];              /* DEK key hex */
    BYTE derivation;            /* OPGP_DERIVATION_METHOD_* */
    char sec_level[32];         /* "none", "mac", "mac+enc", "mac+rmac", "mac+enc+rmac" */
    char scp[32];               /* "scp01", "scp02", "scp03", "scp11" */
    char scp_impl[32];
    char scp11_cert_file[512];
    char scp11_sd_public_key[128];
    BYTE scp11_session_key_len;
    int trace;
    int verbose;
} gpshell3_session_params_t;

/**
 * Smart card session context holding PC/SC handles, security info,
 * selected ISD AID, session token, and active SCP protocol parameters.
 */
typedef struct gpshell3_session {
    char session_id[GPSHELL3_SESSION_ID_LEN + 1];
    OPGP_CARD_CONTEXT ctx;
    OPGP_CARD_INFO info;
    GP211_SECURITY_INFO sec;
    bool is_connected;
    bool is_authenticated;
    char connected_reader[256];
    BYTE selected_isd[16];
    DWORD selected_isd_len;
    BYTE current_scp;
    BYTE current_scp_impl;
    int current_scp_set;
} gpshell3_session_t;

/**
 * Initialize a session structure to zero/defaults.
 */
void gpshell3_session_init(gpshell3_session_t *session);

/**
 * Open a card session using the provided parameters.
 * Connects to PC/SC reader, selects ISD, and performs mutual authentication if configured.
 * Generates an opaque session_id token upon success.
 *
 * @param session Session handle to initialize and populate.
 * @param params Session configuration parameters.
 * @param out Output context for structured results and error reporting.
 * @return 0 on success, non-zero on failure.
 */
int gpshell3_session_open(gpshell3_session_t *session, const gpshell3_session_params_t *params, gpshell3_output_ctx_t *out);

/**
 * Open a card session from structured JSON arguments.
 *
 * @param session Session handle.
 * @param args cJSON object containing connection and authentication properties.
 * @param out Output context.
 * @return 0 on success, non-zero on failure.
 */
int gpshell3_session_open_json(gpshell3_session_t *session, const cJSON *args, gpshell3_output_ctx_t *out);

/**
 * Connect to PC/SC reader.
 */
int gpshell3_connect_pcsc(gpshell3_session_t *session, const char *reader, const char *protocol, int trace, int verbose);

/**
 * Select Issuer Security Domain.
 */
int gpshell3_select_isd(gpshell3_session_t *session, const char *sd_hex);

/**
 * Perform mutual authentication.
 */
int gpshell3_mutual_auth(gpshell3_session_t *session, BYTE keyset_ver, BYTE key_index, int derivation,
                         const char *sec_level_opt, int verbose,
                         const BYTE *baseKey, const BYTE *enc_key, const BYTE *mac_key, const BYTE *dek_key,
                         BYTE keyLength, const char *scp_protocol, const char *scp_impl,
                         const char *scp11_cert_file, const char *scp11_sd_public_key,
                         BYTE scp11SessionKeyLength);

/**
 * Disconnect card, zeroize sensitive credentials, and release OPGP context.
 */
void gpshell3_session_close(gpshell3_session_t *session);

/**
 * Validate that the session is active, connected, and matches the given session_id token.
 */
bool gpshell3_session_is_valid(const gpshell3_session_t *session, const char *session_id);

/**
 * Safely wipe sensitive key material from session parameter structures.
 */
void gpshell3_session_zeroize_params(gpshell3_session_params_t *params);

/**
 * Safely wipe sensitive key material and security context from session.
 */
void gpshell3_session_zeroize_session(gpshell3_session_t *session);

/**
 * MCP Tool input/output schemas and handlers for session management.
 */
cJSON *gpshell3_cmd_open_session_input_schema(void);
cJSON *gpshell3_cmd_open_session_output_schema(void);
int gpshell3_cmd_open_session_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out);

cJSON *gpshell3_cmd_close_session_input_schema(void);
cJSON *gpshell3_cmd_close_session_output_schema(void);
int gpshell3_cmd_close_session_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out);

#ifdef __cplusplus
}
#endif

#endif /* GPSHELL3_SESSION_H */
