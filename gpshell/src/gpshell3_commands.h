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

#ifndef GPSHELL3_COMMANDS_H
#define GPSHELL3_COMMANDS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <globalplatform/globalplatform.h>
#include "cJSON.h"
#include "gpshell3_output.h"
#include "gpshell3_session.h"

/* Connection & Authentication helpers */
int gpshell3_connect_pcsc(gpshell3_session_t *session, const char *reader, const char *protocol, int trace, int verbose);
int gpshell3_select_isd(gpshell3_session_t *session, const char *sd_hex);
int gpshell3_mutual_auth(gpshell3_session_t *session, BYTE keyset_ver, BYTE key_index, int derivation,
                         const char *sec_level_opt, int verbose,
                         const BYTE *baseKey, const BYTE *enc_key, const BYTE *mac_key, const BYTE *dek_key,
                         BYTE keyLength, const char *scp_protocol, const char *scp_impl,
                         const char *scp11_cert_file, const char *scp11_sd_public_key,
                         BYTE scp11SessionKeyLength);

#define DECLARE_GPSHELL3_CMD(name) \
    int gpshell3_cmd_##name##_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out); \
    int gpshell3_cmd_##name##_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out); \
    cJSON *gpshell3_cmd_##name##_input_schema(void); \
    cJSON *gpshell3_cmd_##name##_output_schema(void);

/* Offline commands (13) */
DECLARE_GPSHELL3_CMD(list_readers)
DECLARE_GPSHELL3_CMD(hash)
DECLARE_GPSHELL3_CMD(sign_dap)
DECLARE_GPSHELL3_CMD(sign_load_token)
DECLARE_GPSHELL3_CMD(sign_install_token)
DECLARE_GPSHELL3_CMD(sign_extradition_token)
DECLARE_GPSHELL3_CMD(sign_update_registry_token)
DECLARE_GPSHELL3_CMD(sign_delete_token)
DECLARE_GPSHELL3_CMD(verify_delete_receipt)
DECLARE_GPSHELL3_CMD(verify_load_receipt)
DECLARE_GPSHELL3_CMD(verify_install_receipt)
DECLARE_GPSHELL3_CMD(verify_registry_update_receipt)
DECLARE_GPSHELL3_CMD(verify_move_receipt)

/* Card query commands (13) */
DECLARE_GPSHELL3_CMD(list_apps)
DECLARE_GPSHELL3_CMD(list_keys)
DECLARE_GPSHELL3_CMD(cplc)
DECLARE_GPSHELL3_CMD(card_data)
DECLARE_GPSHELL3_CMD(iin)
DECLARE_GPSHELL3_CMD(cin)
DECLARE_GPSHELL3_CMD(card_info)
DECLARE_GPSHELL3_CMD(card_cap)
DECLARE_GPSHELL3_CMD(card_resources)
DECLARE_GPSHELL3_CMD(div_data)
DECLARE_GPSHELL3_CMD(seq_counter)
DECLARE_GPSHELL3_CMD(confirm_counter)
DECLARE_GPSHELL3_CMD(scp11_cert_data)

/* Card mutation & management commands (18) */
DECLARE_GPSHELL3_CMD(store_iin)
DECLARE_GPSHELL3_CMD(store_cin)
DECLARE_GPSHELL3_CMD(scp11_store_cert)
DECLARE_GPSHELL3_CMD(scp11_store_ca_id)
DECLARE_GPSHELL3_CMD(install)
DECLARE_GPSHELL3_CMD(install_sd)
DECLARE_GPSHELL3_CMD(delete)
DECLARE_GPSHELL3_CMD(update_registry)
DECLARE_GPSHELL3_CMD(move)
DECLARE_GPSHELL3_CMD(put_key)
DECLARE_GPSHELL3_CMD(put_auth)
DECLARE_GPSHELL3_CMD(put_dm_token)
DECLARE_GPSHELL3_CMD(put_dm_receipt)
DECLARE_GPSHELL3_CMD(put_dap_key)
DECLARE_GPSHELL3_CMD(del_key)
DECLARE_GPSHELL3_CMD(apdu)
DECLARE_GPSHELL3_CMD(status)
DECLARE_GPSHELL3_CMD(store)

#undef DECLARE_GPSHELL3_CMD

#ifdef __cplusplus
}
#endif

#endif /* GPSHELL3_COMMANDS_H */
