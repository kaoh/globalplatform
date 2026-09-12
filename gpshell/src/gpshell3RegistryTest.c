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
#include "gpshell3_commands.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static void test_registry_count_and_enumeration(void **state) {
    (void)state;
    gpshell3_registry_init();
    size_t count = gpshell3_registry_count();
    assert_int_equal(count, 44);

    for (size_t i = 0; i < count; i++) {
        const gpshell3_cmd_def_t *def = gpshell3_registry_get(i);
        assert_non_null(def);
        assert_non_null(def->name);
        assert_true(strlen(def->name) > 0);
        assert_non_null(def->tool_name);
        assert_true(strncmp(def->tool_name, "gpshell3_", 9) == 0);
        assert_non_null(def->description);
        assert_true(strlen(def->description) > 0);
        assert_non_null(def->execute_cmd);
        assert_non_null(def->execute_cli);
        assert_non_null(def->get_input_schema);
        assert_non_null(def->get_output_schema);
    }

    assert_null(gpshell3_registry_get(count));
    assert_null(gpshell3_registry_get(count + 100));
}

static void test_registry_lookup_by_name(void **state) {
    (void)state;
    const gpshell3_cmd_def_t *def = gpshell3_registry_find_by_name("list-apps");
    assert_non_null(def);
    assert_string_equal(def->name, "list-apps");
    assert_string_equal(def->tool_name, "gpshell3_list_apps");
    assert_true(def->requires_session);
    assert_false(def->is_destructive);

    def = gpshell3_registry_find_by_name("install");
    assert_non_null(def);
    assert_string_equal(def->name, "install");
    assert_string_equal(def->tool_name, "gpshell3_install");
    assert_true(def->requires_session);
    assert_true(def->is_destructive);

    def = gpshell3_registry_find_by_name("hash");
    assert_non_null(def);
    assert_string_equal(def->name, "hash");
    assert_string_equal(def->tool_name, "gpshell3_hash");
    assert_false(def->requires_session);
    assert_false(def->is_destructive);

    assert_null(gpshell3_registry_find_by_name("non-existent-cmd"));
    assert_null(gpshell3_registry_find_by_name(NULL));
}

static void test_registry_lookup_by_tool_name(void **state) {
    (void)state;
    const gpshell3_cmd_def_t *def = gpshell3_registry_find_by_tool_name("gpshell3_list_keys");
    assert_non_null(def);
    assert_string_equal(def->name, "list-keys");
    assert_string_equal(def->tool_name, "gpshell3_list_keys");

    def = gpshell3_registry_find_by_tool_name("gpshell3_delete");
    assert_non_null(def);
    assert_string_equal(def->name, "delete");
    assert_true(def->is_destructive);

    assert_null(gpshell3_registry_find_by_tool_name("gpshell3_unknown_tool"));
    assert_null(gpshell3_registry_find_by_tool_name(NULL));
}

static void test_registry_all_schemas_valid_json(void **state) {
    (void)state;
    size_t count = gpshell3_registry_count();

    for (size_t i = 0; i < count; i++) {
        const gpshell3_cmd_def_t *def = gpshell3_registry_get(i);
        assert_non_null(def);

        cJSON *in_schema = def->get_input_schema();
        assert_non_null(in_schema);
        cJSON *in_type = cJSON_GetObjectItemCaseSensitive(in_schema, "type");
        assert_non_null(in_type);
        assert_string_equal(in_type->valuestring, "object");
        cJSON_Delete(in_schema);

        cJSON *out_schema = def->get_output_schema();
        assert_non_null(out_schema);
        cJSON *out_type = cJSON_GetObjectItemCaseSensitive(out_schema, "type");
        assert_non_null(out_type);
        assert_string_equal(out_type->valuestring, "object");
        cJSON_Delete(out_schema);
    }
}

static void test_destructive_flags_accurate(void **state) {
    (void)state;
    /* Destructive tools must have is_destructive == true */
    const char *destructive_tools[] = {
        "install", "install-sd", "delete", "update-registry", "move",
        "put-key", "put-auth", "put-dm-token", "put-dm-receipt", "put-dap-key",
        "del-key", "apdu", "status", "store", "store-iin", "store-cin",
        "scp11-store-cert", "scp11-store-ca-id"
    };
    for (size_t i = 0; i < ARRAY_SIZE(destructive_tools); i++) {
        const gpshell3_cmd_def_t *def = gpshell3_registry_find_by_name(destructive_tools[i]);
        assert_non_null(def);
        assert_true(def->is_destructive);
    }

    /* Read-only / queries must have is_destructive == false */
    const char *read_only_tools[] = {
        "list-apps", "list-keys", "cplc", "card-data", "iin", "cin",
        "card-info", "card-cap", "card-resources", "div-data",
        "seq-counter", "confirm-counter", "scp11-cert-data", "list-readers",
        "hash", "sign-dap", "sign-load-token", "verify-delete-receipt"
    };
    for (size_t i = 0; i < ARRAY_SIZE(read_only_tools); i++) {
        const gpshell3_cmd_def_t *def = gpshell3_registry_find_by_name(read_only_tools[i]);
        assert_non_null(def);
        assert_false(def->is_destructive);
    }
}

static void test_session_lifecycle_helpers(void **state) {
    (void)state;
    gpshell3_session_t session;
    gpshell3_session_init(&session);
    assert_false(session.is_connected);
    assert_false(session.is_authenticated);
    assert_int_equal(session.selected_isd_len, 0);

    /* Closing an unestablished session is safe */
    gpshell3_session_close(&session);
    assert_false(session.is_connected);
    assert_false(session.is_authenticated);
}

static void test_command_execution_json_error(void **state) {
    (void)state;
    gpshell3_output_ctx_t out;
    FILE *out_stream = tmpfile();
    FILE *err_stream = tmpfile();
    gpshell3_output_init_stream(&out, OUTPUT_FORMAT_JSON, out_stream, err_stream);

    const gpshell3_cmd_def_t *def = gpshell3_registry_find_by_name("hash");
    assert_non_null(def);

    /* Execute hash with missing args */
    int rc = def->execute_cmd(NULL, NULL, &out);
    assert_int_equal(rc, -1);
    assert_true(out.has_error);
    assert_non_null(out.json_error);

    char *json_str = gpshell3_output_render_string(&out, true);
    assert_non_null(json_str);
    cJSON *parsed = cJSON_Parse(json_str);
    assert_non_null(parsed);

    cJSON *ok = cJSON_GetObjectItemCaseSensitive(parsed, "ok");
    assert_non_null(ok);
    assert_false(cJSON_IsTrue(ok));

    cJSON *err = cJSON_GetObjectItemCaseSensitive(parsed, "error");
    assert_non_null(err);
    cJSON *code = cJSON_GetObjectItemCaseSensitive(err, "code");
    assert_non_null(code);
    assert_string_equal(code->valuestring, "MISSING_ARGUMENT");

    cJSON_Delete(parsed);
    free(json_str);
    gpshell3_output_cleanup(&out);
    fclose(out_stream);
    fclose(err_stream);
}

static void test_command_execution_hash_success(void **state) {
    (void)state;
    gpshell3_output_ctx_t out;
    FILE *out_stream = tmpfile();
    FILE *err_stream = tmpfile();
    gpshell3_output_init_stream(&out, OUTPUT_FORMAT_JSON, out_stream, err_stream);

    const gpshell3_cmd_def_t *def = gpshell3_registry_find_by_name("hash");
    assert_non_null(def);

    const char *cap_path = "globalplatform/src/helloworld.cap";
    FILE *f = fopen(cap_path, "rb");
    if (!f) {
        cap_path = "../../../globalplatform/src/helloworld.cap";
        f = fopen(cap_path, "rb");
    }
    if (!f) {
        cap_path = "../../globalplatform/src/helloworld.cap";
        f = fopen(cap_path, "rb");
    }
    if (f) fclose(f);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "capFile", cap_path);
    cJSON_AddStringToObject(args, "algorithm", "sha256");

    int rc = def->execute_cmd(NULL, args, &out);
    cJSON_Delete(args);

    assert_int_equal(rc, 0);
    assert_false(out.has_error);
    assert_non_null(out.json_result);

    char *json_str = gpshell3_output_render_string(&out, true);
    assert_non_null(json_str);
    cJSON *parsed = cJSON_Parse(json_str);
    assert_non_null(parsed);

    cJSON *ok = cJSON_GetObjectItemCaseSensitive(parsed, "ok");
    assert_non_null(ok);
    assert_true(cJSON_IsTrue(ok));

    cJSON *res = cJSON_GetObjectItemCaseSensitive(parsed, "result");
    assert_non_null(res);
    cJSON *hash_item = cJSON_GetObjectItemCaseSensitive(res, "hash");
    assert_non_null(hash_item);
    assert_true(strlen(hash_item->valuestring) == 64);

    cJSON_Delete(parsed);
    free(json_str);
    gpshell3_output_cleanup(&out);
    fclose(out_stream);
    fclose(err_stream);
}

static void test_card_commands_require_session(void **state) {
    (void)state;
    const char *session_cmds[] = {"list-apps", "list-keys", "cplc", "install", "delete", "status", "apdu", "put-key"};

    for (size_t i = 0; i < ARRAY_SIZE(session_cmds); i++) {
        const gpshell3_cmd_def_t *def = gpshell3_registry_find_by_name(session_cmds[i]);
        assert_non_null(def);
        assert_true(def->requires_session);

        gpshell3_output_ctx_t out;
        FILE *out_stream = tmpfile();
        FILE *err_stream = tmpfile();
        gpshell3_output_init_stream(&out, OUTPUT_FORMAT_JSON, out_stream, err_stream);

        /* Call without active session */
        int rc = def->execute_cmd(NULL, NULL, &out);
        assert_int_equal(rc, -1);
        assert_true(out.has_error);
        assert_non_null(out.json_error);

        cJSON *code = cJSON_GetObjectItemCaseSensitive(out.json_error, "code");
        assert_non_null(code);
        assert_string_equal(code->valuestring, "SESSION_REQUIRED");

        gpshell3_output_cleanup(&out);
        fclose(out_stream);
        fclose(err_stream);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_registry_count_and_enumeration),
        cmocka_unit_test(test_registry_lookup_by_name),
        cmocka_unit_test(test_registry_lookup_by_tool_name),
        cmocka_unit_test(test_registry_all_schemas_valid_json),
        cmocka_unit_test(test_destructive_flags_accurate),
        cmocka_unit_test(test_session_lifecycle_helpers),
        cmocka_unit_test(test_command_execution_json_error),
        cmocka_unit_test(test_command_execution_hash_success),
        cmocka_unit_test(test_card_commands_require_session),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
