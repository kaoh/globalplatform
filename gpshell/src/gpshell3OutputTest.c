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

#include <stdlib.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>

#include "cJSON.h"
#include "gpshell3_output.h"

static void test_cjson_basic(void **state) {
    (void)state;
    const char *raw_json = "{\"name\":\"gpshell3\",\"version\":3,\"active\":true,\"tags\":[\"smartcard\",\"gp\"]}";
    cJSON *root = cJSON_Parse(raw_json);
    assert_non_null(root);

    cJSON *name = cJSON_GetObjectItem(root, "name");
    assert_non_null(name);
    assert_true(cJSON_IsString(name));
    assert_string_equal(name->valuestring, "gpshell3");

    cJSON *version = cJSON_GetObjectItem(root, "version");
    assert_non_null(version);
    assert_true(cJSON_IsNumber(version));
    assert_int_equal((int)version->valuedouble, 3);

    cJSON *active = cJSON_GetObjectItem(root, "active");
    assert_non_null(active);
    assert_true(cJSON_IsTrue(active));

    cJSON *tags = cJSON_GetObjectItem(root, "tags");
    assert_non_null(tags);
    assert_true(cJSON_IsArray(tags));
    assert_int_equal(cJSON_GetArraySize(tags), 2);

    char *rendered = cJSON_PrintUnformatted(root);
    assert_non_null(rendered);
    assert_string_equal(rendered, raw_json);

    free(rendered);
    cJSON_Delete(root);
}

static void test_output_text_mode_messages(void **state) {
    (void)state;
    char out_buf[1024] = {0};
    char err_buf[1024] = {0};
#if defined(_WIN32)
    FILE *out_stream = tmpfile();
    FILE *err_stream = tmpfile();
#else
    FILE *out_stream = fmemopen(out_buf, sizeof(out_buf), "w");
    FILE *err_stream = fmemopen(err_buf, sizeof(err_buf), "w");
#endif
    assert_non_null(out_stream);
    assert_non_null(err_stream);

    gpshell3_output_ctx_t ctx;
    gpshell3_output_init_stream(&ctx, OUTPUT_FORMAT_TEXT, out_stream, err_stream);
    gpshell3_output_set_command(&ctx, "list-readers");

    assert_int_equal(ctx.mode, OUTPUT_FORMAT_TEXT);
    assert_string_equal(gpshell3_output_get_command(&ctx), "list-readers");
    assert_false(gpshell3_output_has_error(&ctx));

    gpshell3_output_message(&ctx, "Found reader: %s\n", "OMNIKEY 3121");
    gpshell3_output_warning(&ctx, "Reader firmware is outdated: %d", 102);
    gpshell3_output_flush(&ctx);

#if defined(_WIN32)
    fflush(out_stream);
    fflush(err_stream);
    fseek(out_stream, 0, SEEK_SET);
    fseek(err_stream, 0, SEEK_SET);
    fread(out_buf, 1, sizeof(out_buf) - 1, out_stream);
    fread(err_buf, 1, sizeof(err_buf) - 1, err_stream);
#endif

    assert_non_null(strstr(out_buf, "Found reader: OMNIKEY 3121\n"));
    assert_non_null(strstr(err_buf, "Warning: Reader firmware is outdated: 102\n"));

    gpshell3_output_cleanup(&ctx);
    fclose(out_stream);
    fclose(err_stream);
}

static void test_output_text_mode_errors(void **state) {
    (void)state;
    char err_buf[1024] = {0};
#if defined(_WIN32)
    FILE *err_stream = tmpfile();
#else
    FILE *err_stream = fmemopen(err_buf, sizeof(err_buf), "w");
#endif
    assert_non_null(err_stream);

    gpshell3_output_ctx_t ctx;
    gpshell3_output_init_stream(&ctx, OUTPUT_FORMAT_TEXT, stdout, err_stream);
    gpshell3_output_set_command(&ctx, "gpshell3_install");

    gpshell3_report_error(&ctx, "INVALID_PARAM", "Parameter %s is missing", "--aid");
    assert_true(gpshell3_output_has_error(&ctx));

#if defined(_WIN32)
    fflush(err_stream);
    fseek(err_stream, 0, SEEK_SET);
    fread(err_buf, 1, sizeof(err_buf) - 1, err_stream);
#endif

    assert_non_null(strstr(err_buf, "gpshell3_install: Parameter --aid is missing\n"));

    /* Test OPGP error reporting in text mode */
    gpshell3_output_reset(&ctx);
    assert_false(gpshell3_output_has_error(&ctx));

    OPGP_ERROR_STATUS status;
    OPGP_ERROR_CREATE_ERROR(status, 0x8010006E, _T("Card not present in selected reader."));
    gpshell3_report_opgp_error(&ctx, "CARD_NOT_PRESENT", status, "Connection check");
    assert_true(gpshell3_output_has_error(&ctx));

    gpshell3_output_cleanup(&ctx);
    fclose(err_stream);
}

static void test_output_json_mode_success_envelope(void **state) {
    (void)state;
    gpshell3_output_ctx_t ctx;
    gpshell3_output_init(&ctx, OUTPUT_FORMAT_JSON);
    gpshell3_output_set_command(&ctx, "gpshell3_list_apps");

    gpshell3_output_add_string(&ctx, "cardManagerAid", "A000000151000000");
    gpshell3_output_add_int(&ctx, "appCount", 2);
    gpshell3_output_add_bool(&ctx, "isLocked", false);
    gpshell3_output_add_double(&ctx, "executionTimeSec", 0.045);

    const unsigned char aid_bytes[] = {0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00};
    gpshell3_output_add_hex(&ctx, "rawAid", aid_bytes, sizeof(aid_bytes));
    gpshell3_output_add_status_word(&ctx, 0x9000);

    const char *privs[] = {"security_domain", "card_lock"};
    cJSON *privs_array = gpshell3_json_create_string_array(privs, 2);
    gpshell3_output_add_array(&ctx, "privileges", privs_array);

    cJSON *sub_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(sub_obj, "lifeCycle", "SECURED");
    cJSON_AddNumberToObject(sub_obj, "keyVersion", 1);
    gpshell3_output_add_object(&ctx, "details", sub_obj);

    char *json_str = gpshell3_output_render_string(&ctx, false);
    assert_non_null(json_str);

    cJSON *parsed = cJSON_Parse(json_str);
    assert_non_null(parsed);

    cJSON *ok_item = cJSON_GetObjectItem(parsed, "ok");
    assert_non_null(ok_item);
    assert_true(cJSON_IsTrue(ok_item));

    cJSON *cmd_item = cJSON_GetObjectItem(parsed, "command");
    assert_non_null(cmd_item);
    assert_string_equal(cmd_item->valuestring, "gpshell3_list_apps");

    cJSON *result = cJSON_GetObjectItem(parsed, "result");
    assert_non_null(result);
    assert_true(cJSON_IsObject(result));

    assert_string_equal(cJSON_GetObjectItem(result, "cardManagerAid")->valuestring, "A000000151000000");
    assert_int_equal((int)cJSON_GetObjectItem(result, "appCount")->valuedouble, 2);
    assert_true(cJSON_IsFalse(cJSON_GetObjectItem(result, "isLocked")));
    assert_string_equal(cJSON_GetObjectItem(result, "rawAid")->valuestring, "A000000151000000");
    assert_string_equal(cJSON_GetObjectItem(result, "sw")->valuestring, "9000");

    cJSON *parsed_privs = cJSON_GetObjectItem(result, "privileges");
    assert_non_null(parsed_privs);
    assert_int_equal(cJSON_GetArraySize(parsed_privs), 2);
    assert_string_equal(cJSON_GetArrayItem(parsed_privs, 0)->valuestring, "security_domain");

    cJSON *parsed_details = cJSON_GetObjectItem(result, "details");
    assert_non_null(parsed_details);
    assert_string_equal(cJSON_GetObjectItem(parsed_details, "lifeCycle")->valuestring, "SECURED");

    free(json_str);
    cJSON_Delete(parsed);
    gpshell3_output_cleanup(&ctx);
}

static void test_output_json_mode_generic_error(void **state) {
    (void)state;
    gpshell3_output_ctx_t ctx;
    gpshell3_output_init(&ctx, OUTPUT_FORMAT_JSON);
    gpshell3_output_set_command(&ctx, "gpshell3_delete");

    /* Add some intermediate result before failure */
    gpshell3_output_add_string(&ctx, "targetAid", "A000000001");

    gpshell3_report_error(&ctx, "AID_NOT_FOUND", "Application %s not found on card", "A000000001");
    assert_true(gpshell3_output_has_error(&ctx));

    char *json_str = gpshell3_output_render_string(&ctx, false);
    assert_non_null(json_str);

    cJSON *parsed = cJSON_Parse(json_str);
    assert_non_null(parsed);

    cJSON *ok_item = cJSON_GetObjectItem(parsed, "ok");
    assert_non_null(ok_item);
    assert_true(cJSON_IsFalse(ok_item));

    /* Result must be nullified/removed on error */
    assert_null(cJSON_GetObjectItem(parsed, "result"));

    cJSON *err_item = cJSON_GetObjectItem(parsed, "error");
    assert_non_null(err_item);
    assert_true(cJSON_IsObject(err_item));

    assert_string_equal(cJSON_GetObjectItem(err_item, "code")->valuestring, "AID_NOT_FOUND");
    assert_string_equal(cJSON_GetObjectItem(err_item, "message")->valuestring, "Application A000000001 not found on card");
    assert_string_equal(cJSON_GetObjectItem(err_item, "command")->valuestring, "gpshell3_delete");

    free(json_str);
    cJSON_Delete(parsed);
    gpshell3_output_cleanup(&ctx);
}

static void test_output_json_mode_opgp_error(void **state) {
    (void)state;
    gpshell3_output_ctx_t ctx;
    gpshell3_output_init(&ctx, OUTPUT_FORMAT_JSON);
    gpshell3_output_set_command(&ctx, "gpshell3_list_keys");

    OPGP_ERROR_STATUS status;
    OPGP_ERROR_CREATE_ERROR(status, 0x8010006E, _T("Card not present in selected reader."));
    gpshell3_report_opgp_error(&ctx, "CARD_COMMUNICATION_ERROR", status, "Failed to connect to reader");
    assert_true(gpshell3_output_has_error(&ctx));

    char *json_str = gpshell3_output_render_string(&ctx, true);
    assert_non_null(json_str);

    cJSON *parsed = cJSON_Parse(json_str);
    assert_non_null(parsed);

    cJSON *ok_item = cJSON_GetObjectItem(parsed, "ok");
    assert_non_null(ok_item);
    assert_true(cJSON_IsFalse(ok_item));

    cJSON *err_item = cJSON_GetObjectItem(parsed, "error");
    assert_non_null(err_item);
    assert_string_equal(cJSON_GetObjectItem(err_item, "code")->valuestring, "CARD_COMMUNICATION_ERROR");
    assert_string_equal(cJSON_GetObjectItem(err_item, "opgpErrorCode")->valuestring, "0x8010006E");
    assert_string_equal(cJSON_GetObjectItem(err_item, "command")->valuestring, "gpshell3_list_keys");
    assert_non_null(strstr(cJSON_GetObjectItem(err_item, "message")->valuestring, "Failed to connect to reader"));
    assert_non_null(strstr(cJSON_GetObjectItem(err_item, "message")->valuestring, "Card not present in selected reader."));

    free(json_str);
    cJSON_Delete(parsed);
    gpshell3_output_cleanup(&ctx);
}

static void test_output_helpers_and_edge_cases(void **state) {
    (void)state;
    /* Hex conversion */
    const unsigned char sample_bytes[] = {0xDE, 0xAD, 0xBE, 0xEF};
    char *hex = gpshell3_bytes_to_hex(sample_bytes, sizeof(sample_bytes));
    assert_non_null(hex);
    assert_string_equal(hex, "DEADBEEF");
    free(hex);

    char *empty_hex = gpshell3_bytes_to_hex(NULL, 0);
    assert_non_null(empty_hex);
    assert_string_equal(empty_hex, "");
    free(empty_hex);

    /* Null context resilience */
    gpshell3_report_error(NULL, "TEST", "Message");
    assert_int_equal(gpshell3_output_add_string(NULL, "key", "val"), -1);
    assert_int_equal(gpshell3_output_add_int(NULL, "key", 10), -1);
    assert_int_equal(gpshell3_output_flush(NULL), -1);
    assert_false(gpshell3_output_has_error(NULL));
    assert_string_equal(gpshell3_output_get_command(NULL), "");

    /* Custom result replacement */
    gpshell3_output_ctx_t ctx;
    gpshell3_output_init(&ctx, OUTPUT_FORMAT_JSON);
    gpshell3_output_set_command(&ctx, "gpshell3_custom");

    cJSON *custom_array = cJSON_CreateArray();
    cJSON_AddItemToArray(custom_array, cJSON_CreateString("reader1"));
    cJSON_AddItemToArray(custom_array, cJSON_CreateString("reader2"));
    assert_int_equal(gpshell3_output_set_result(&ctx, custom_array), 0);

    cJSON *root = gpshell3_output_get_root(&ctx);
    assert_non_null(root);
    cJSON *res = cJSON_GetObjectItem(root, "result");
    assert_non_null(res);
    assert_true(cJSON_IsArray(res));
    assert_int_equal(cJSON_GetArraySize(res), 2);

    gpshell3_output_cleanup(&ctx);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_cjson_basic),
        cmocka_unit_test(test_output_text_mode_messages),
        cmocka_unit_test(test_output_text_mode_errors),
        cmocka_unit_test(test_output_json_mode_success_envelope),
        cmocka_unit_test(test_output_json_mode_generic_error),
        cmocka_unit_test(test_output_json_mode_opgp_error),
        cmocka_unit_test(test_output_helpers_and_edge_cases),
    };
    return cmocka_run_group_tests_name("gpshell3_output", tests, NULL, NULL);
}
