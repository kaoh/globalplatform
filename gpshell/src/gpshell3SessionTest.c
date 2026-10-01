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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <string.h>
#include <stdlib.h>

#include "cJSON.h"
#include "gpshell3_output.h"
#include "gpshell3_session.h"
#include "gpshell3_registry.h"

static void test_session_init_and_defaults(void **state) {
    (void)state;
    gpshell3_session_t session;
    gpshell3_session_init(&session);

    assert_false(session.is_connected);
    assert_false(session.is_authenticated);
    assert_int_equal(session.selected_isd_len, 0);
    assert_int_equal(session.current_scp, 0);
    assert_int_equal(session.current_scp_impl, 0);
    assert_int_equal(session.session_id[0], '\0');

    /* Unestablished session is not valid */
    assert_false(gpshell3_session_is_valid(&session, NULL));
    assert_false(gpshell3_session_is_valid(&session, "some_token"));

    /* Close on unestablished session is safe */
    gpshell3_session_close(&session);
    assert_false(session.is_connected);
}

static void test_session_id_validation(void **state) {
    (void)state;
    gpshell3_session_t session;
    gpshell3_session_init(&session);

    session.is_connected = true;
    snprintf(session.session_id, sizeof(session.session_id), "%s", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    /* Valid with exact match or NULL */
    assert_true(gpshell3_session_is_valid(&session, NULL));
    assert_true(gpshell3_session_is_valid(&session, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));

    /* Invalid with mismatched ID */
    assert_false(gpshell3_session_is_valid(&session, "wrong_token_1234567890"));
    assert_false(gpshell3_session_is_valid(NULL, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));

    session.is_connected = false;
    assert_false(gpshell3_session_is_valid(&session, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
}

static void test_session_credential_zeroization(void **state) {
    (void)state;
    gpshell3_session_params_t params;
    memset(&params, 0, sizeof(params));
    strncpy(params.key, "404142434445464748494A4B4C4D4E4F", sizeof(params.key) - 1);
    strncpy(params.enc, "404142434445464748494A4B4C4D4E4F", sizeof(params.enc) - 1);
    strncpy(params.mac, "404142434445464748494A4B4C4D4E4F", sizeof(params.mac) - 1);
    strncpy(params.dek, "404142434445464748494A4B4C4D4E4F", sizeof(params.dek) - 1);

    gpshell3_session_zeroize_params(&params);

    for (size_t i = 0; i < sizeof(params.key); i++) assert_int_equal((unsigned char)params.key[i], 0);
    for (size_t i = 0; i < sizeof(params.enc); i++) assert_int_equal((unsigned char)params.enc[i], 0);
    for (size_t i = 0; i < sizeof(params.mac); i++) assert_int_equal((unsigned char)params.mac[i], 0);
    for (size_t i = 0; i < sizeof(params.dek); i++) assert_int_equal((unsigned char)params.dek[i], 0);

    gpshell3_session_t session;
    gpshell3_session_init(&session);
    memset(session.sec.C_MACSessionKey, 0xAA, sizeof(session.sec.C_MACSessionKey));
    memset(session.sec.R_MACSessionKey, 0xBB, sizeof(session.sec.R_MACSessionKey));
    memset(session.sec.encryptionSessionKey, 0xCC, sizeof(session.sec.encryptionSessionKey));
    memset(session.sec.dataEncryptionSessionKey, 0xDD, sizeof(session.sec.dataEncryptionSessionKey));
    strncpy(session.session_id, "secret_session_token_12345", sizeof(session.session_id) - 1);

    gpshell3_session_zeroize_session(&session);

    for (size_t i = 0; i < sizeof(session.sec.C_MACSessionKey); i++) assert_int_equal((unsigned char)session.sec.C_MACSessionKey[i], 0);
    for (size_t i = 0; i < sizeof(session.sec.R_MACSessionKey); i++) assert_int_equal((unsigned char)session.sec.R_MACSessionKey[i], 0);
    for (size_t i = 0; i < sizeof(session.sec.encryptionSessionKey); i++) assert_int_equal((unsigned char)session.sec.encryptionSessionKey[i], 0);
    for (size_t i = 0; i < sizeof(session.sec.dataEncryptionSessionKey); i++) assert_int_equal((unsigned char)session.sec.dataEncryptionSessionKey[i], 0);
    for (size_t i = 0; i < sizeof(session.session_id); i++) assert_int_equal((unsigned char)session.session_id[i], 0);
}

static void test_session_open_missing_auth_keys(void **state) {
    (void)state;
    gpshell3_session_t session;
    gpshell3_session_init(&session);

    gpshell3_output_ctx_t out;
    FILE *out_stream = tmpfile();
    FILE *err_stream = tmpfile();
    gpshell3_output_init_stream(&out, OUTPUT_FORMAT_JSON, out_stream, err_stream);

    /* Open session with secure_channel but without key material -> should fail with error */
    cJSON *args = cJSON_CreateObject();
    cJSON *auth = cJSON_CreateObject();
    cJSON_AddStringToObject(auth, "mode", "secure_channel");
    cJSON_AddItemToObject(args, "authentication", auth);

    int rc = gpshell3_session_open_json(&session, args, &out);
    cJSON_Delete(args);

    assert_int_equal(rc, -1);
    assert_true(out.has_error);
    assert_non_null(out.json_error);

    cJSON *err_code = cJSON_GetObjectItemCaseSensitive(out.json_error, "code");
    assert_non_null(err_code);
    /* Either NO_READERS or AUTHENTICATION_ERROR (no silent default key fallback) */
    assert_true(strcmp(err_code->valuestring, "NO_READERS") == 0 ||
                strcmp(err_code->valuestring, "AUTHENTICATION_ERROR") == 0 ||
                strcmp(err_code->valuestring, "CONTEXT_FAILED") == 0);

    gpshell3_output_cleanup(&out);
    fclose(out_stream);
    fclose(err_stream);
}

static void test_session_open_auth_key_auto_mode(void **state) {
    (void)state;
    gpshell3_session_t session;
    gpshell3_session_init(&session);

    gpshell3_output_ctx_t out;
    FILE *out_stream = tmpfile();
    FILE *err_stream = tmpfile();
    gpshell3_output_init_stream(&out, OUTPUT_FORMAT_JSON, out_stream, err_stream);

    /* Open session with authentication.key without explicit mode -> should auto-enable secure_channel */
    cJSON *args = cJSON_CreateObject();
    cJSON *auth = cJSON_CreateObject();
    cJSON_AddStringToObject(auth, "key", "404142434445464748494A4B4C4D4E4F");
    cJSON_AddItemToObject(args, "authentication", auth);

    int rc = gpshell3_session_open_json(&session, args, &out);
    cJSON_Delete(args);

    assert_int_equal(rc, -1);
    assert_true(out.has_error);
    assert_non_null(out.json_error);

    cJSON *err_code = cJSON_GetObjectItemCaseSensitive(out.json_error, "code");
    assert_non_null(err_code);
    /* Expect connection attempt failure when no card/reader is connected, not AUTHENTICATION_ERROR */
    assert_true(strcmp(err_code->valuestring, "NO_READERS") == 0 ||
                strcmp(err_code->valuestring, "CONTEXT_FAILED") == 0);

    gpshell3_output_cleanup(&out);
    fclose(out_stream);
    fclose(err_stream);
}

static void test_session_mcp_tool_schemas(void **state) {
    (void)state;
    /* Open session schemas */
    cJSON *in_open = gpshell3_cmd_open_session_input_schema();
    assert_non_null(in_open);
    cJSON *in_type = cJSON_GetObjectItemCaseSensitive(in_open, "type");
    assert_non_null(in_type);
    assert_string_equal(in_type->valuestring, "object");

    cJSON *props = cJSON_GetObjectItemCaseSensitive(in_open, "properties");
    assert_non_null(props);
    assert_non_null(cJSON_GetObjectItemCaseSensitive(props, "reader"));
    assert_non_null(cJSON_GetObjectItemCaseSensitive(props, "protocol"));
    assert_non_null(cJSON_GetObjectItemCaseSensitive(props, "sd"));
    cJSON *auth = cJSON_GetObjectItemCaseSensitive(props, "authentication");
    assert_non_null(auth);
    cJSON *auth_props = cJSON_GetObjectItemCaseSensitive(auth, "properties");
    assert_non_null(auth_props);
    cJSON *sec_level = cJSON_GetObjectItemCaseSensitive(auth_props, "securityLevel");
    assert_non_null(sec_level);
    cJSON *sec_enum = cJSON_GetObjectItemCaseSensitive(sec_level, "enum");
    assert_non_null(sec_enum);
    assert_int_equal(cJSON_GetArraySize(sec_enum), 6);
    cJSON_Delete(in_open);

    cJSON *out_open = gpshell3_cmd_open_session_output_schema();
    assert_non_null(out_open);
    cJSON *out_props = cJSON_GetObjectItemCaseSensitive(out_open, "properties");
    assert_non_null(out_props);
    assert_non_null(cJSON_GetObjectItemCaseSensitive(out_props, "sessionId"));
    assert_non_null(cJSON_GetObjectItemCaseSensitive(out_props, "reader"));
    assert_non_null(cJSON_GetObjectItemCaseSensitive(out_props, "atr"));
    assert_non_null(cJSON_GetObjectItemCaseSensitive(out_props, "selectedIsd"));
    assert_non_null(cJSON_GetObjectItemCaseSensitive(out_props, "authenticated"));
    cJSON_Delete(out_open);

    /* Close session schemas */
    cJSON *in_close = gpshell3_cmd_close_session_input_schema();
    assert_non_null(in_close);
    cJSON *close_props = cJSON_GetObjectItemCaseSensitive(in_close, "properties");
    assert_non_null(close_props);
    assert_non_null(cJSON_GetObjectItemCaseSensitive(close_props, "sessionId"));
    cJSON_Delete(in_close);

    cJSON *out_close = gpshell3_cmd_close_session_output_schema();
    assert_non_null(out_close);
    cJSON *out_close_props = cJSON_GetObjectItemCaseSensitive(out_close, "properties");
    assert_non_null(out_close_props);
    assert_non_null(cJSON_GetObjectItemCaseSensitive(out_close_props, "closed"));
    cJSON_Delete(out_close);
}

static void test_session_close_cmd_execution(void **state) {
    (void)state;
    gpshell3_session_t session;
    gpshell3_session_init(&session);

    gpshell3_output_ctx_t out;
    FILE *out_stream = tmpfile();
    FILE *err_stream = tmpfile();
    gpshell3_output_init_stream(&out, OUTPUT_FORMAT_JSON, out_stream, err_stream);

    int rc = gpshell3_cmd_close_session_cmd(&session, NULL, &out);
    assert_int_equal(rc, 0);
    assert_false(out.has_error);
    assert_non_null(out.json_result);

    cJSON *closed = cJSON_GetObjectItemCaseSensitive(out.json_result, "closed");
    assert_non_null(closed);
    assert_true(cJSON_IsTrue(closed));

    gpshell3_output_cleanup(&out);
    fclose(out_stream);
    fclose(err_stream);
}

static void test_session_reader_name_preservation(void **state) {
    (void)state;
    gpshell3_session_t session;
    gpshell3_session_init(&session);
    strncpy(session.connected_reader, "Identiv uTrust 3700 F CL Reader 0", sizeof(session.connected_reader) - 1);
    session.is_connected = true;
    snprintf(session.session_id, sizeof(session.session_id), "test_session_12345");

    gpshell3_output_ctx_t out;
    gpshell3_output_init(&out, OUTPUT_FORMAT_JSON);
    gpshell3_output_set_command(&out, "gpshell3_open_session");
    gpshell3_output_add_string(&out, "sessionId", session.session_id);
    gpshell3_output_add_string(&out, "reader", session.connected_reader);
    gpshell3_output_add_hex(&out, "selectedIsd", session.selected_isd, session.selected_isd_len);
    gpshell3_output_add_bool(&out, "authenticated", session.is_authenticated);

    char *json_str = gpshell3_output_render_string(&out, false);
    assert_non_null(json_str);
    cJSON *parsed = cJSON_Parse(json_str);
    assert_non_null(parsed);

    cJSON *res = cJSON_GetObjectItemCaseSensitive(parsed, "result");
    assert_non_null(res);
    cJSON *r = cJSON_GetObjectItemCaseSensitive(res, "reader");
    assert_non_null(r);
    assert_string_equal(r->valuestring, "Identiv uTrust 3700 F CL Reader 0");

    free(json_str);
    cJSON_Delete(parsed);
    gpshell3_output_cleanup(&out);
}

static void test_session_auto_detected_reader_name(void **state) {
    (void)state;
    gpshell3_session_t session;
    gpshell3_session_init(&session);
    strncpy(session.connected_reader, "Broadcom Corp 58200 [Contacted SmartCard] (0123456789ABCD) 00 00", sizeof(session.connected_reader) - 1);
    session.is_connected = true;
    snprintf(session.session_id, sizeof(session.session_id), "d64e25f0d1a1953333b75eb1a6d14c6eacf1774ee36682dfb7814573f5ed0b25");

    gpshell3_output_ctx_t out;
    gpshell3_output_init(&out, OUTPUT_FORMAT_JSON);
    gpshell3_output_set_command(&out, "gpshell3_open_session");
    gpshell3_output_add_string(&out, "sessionId", session.session_id);
    gpshell3_output_add_string(&out, "reader", session.connected_reader);
    gpshell3_output_add_hex(&out, "selectedIsd", session.selected_isd, session.selected_isd_len);
    gpshell3_output_add_bool(&out, "authenticated", session.is_authenticated);

    char *json_str = gpshell3_output_render_string(&out, false);
    assert_non_null(json_str);
    cJSON *parsed = cJSON_Parse(json_str);
    assert_non_null(parsed);

    cJSON *res = cJSON_GetObjectItemCaseSensitive(parsed, "result");
    assert_non_null(res);
    cJSON *r = cJSON_GetObjectItemCaseSensitive(res, "reader");
    assert_non_null(r);
    assert_string_equal(r->valuestring, "Broadcom Corp 58200 [Contacted SmartCard] (0123456789ABCD) 00 00");

    free(json_str);
    cJSON_Delete(parsed);
    gpshell3_output_cleanup(&out);
}

static void test_session_open_atr_formatting(void **state) {
    (void)state;
    gpshell3_session_t session;
    gpshell3_session_init(&session);
    strncpy(session.connected_reader, "Test Reader", sizeof(session.connected_reader) - 1);
    session.is_connected = true;
    snprintf(session.session_id, sizeof(session.session_id), "test_session_atr_123");

    /* Populate ATR with sample bytes */
    BYTE sample_atr[] = { 0x3B, 0x80, 0x80, 0x01, 0x01 };
    memcpy(session.info.ATR, sample_atr, sizeof(sample_atr));
    session.info.ATRLength = sizeof(sample_atr);

    gpshell3_output_ctx_t out;
    gpshell3_output_init(&out, OUTPUT_FORMAT_JSON);
    gpshell3_output_set_command(&out, "gpshell3_open_session");
    gpshell3_output_add_string(&out, "sessionId", session.session_id);
    gpshell3_output_add_string(&out, "reader", session.connected_reader);
    if (session.info.ATRLength > 0) {
        gpshell3_output_add_hex(&out, "atr", session.info.ATR, session.info.ATRLength);
    }
    gpshell3_output_add_hex(&out, "selectedIsd", session.selected_isd, session.selected_isd_len);
    gpshell3_output_add_bool(&out, "authenticated", session.is_authenticated);

    char *json_str = gpshell3_output_render_string(&out, false);
    assert_non_null(json_str);
    cJSON *parsed = cJSON_Parse(json_str);
    assert_non_null(parsed);

    cJSON *res = cJSON_GetObjectItemCaseSensitive(parsed, "result");
    assert_non_null(res);
    cJSON *atr_item = cJSON_GetObjectItemCaseSensitive(res, "atr");
    assert_non_null(atr_item);
    assert_string_equal(atr_item->valuestring, "3B80800101");

    free(json_str);
    cJSON_Delete(parsed);
    gpshell3_output_cleanup(&out);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_session_init_and_defaults),
        cmocka_unit_test(test_session_id_validation),
        cmocka_unit_test(test_session_credential_zeroization),
        cmocka_unit_test(test_session_open_missing_auth_keys),
        cmocka_unit_test(test_session_open_auth_key_auto_mode),
        cmocka_unit_test(test_session_mcp_tool_schemas),
        cmocka_unit_test(test_session_close_cmd_execution),
        cmocka_unit_test(test_session_reader_name_preservation),
        cmocka_unit_test(test_session_auto_detected_reader_name),
        cmocka_unit_test(test_session_open_atr_formatting),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
