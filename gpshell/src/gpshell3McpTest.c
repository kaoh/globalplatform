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
#include "gpshell3_mcp.h"

static cJSON *process_and_parse_response(gpshell3_mcp_server_t *server, FILE *out_stream, const char *input_json) {
    rewind(out_stream);
    int rc = gpshell3_mcp_process_message(server, input_json);
    assert_int_equal(rc, 0);

    rewind(out_stream);
    char buf[65536];
    if (!fgets(buf, sizeof(buf), out_stream)) return NULL;

    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n')) buf[--len] = '\0';

    return cJSON_Parse(buf);
}

static void test_mcp_initialize(void **state) {
    (void)state;
    gpshell3_mcp_server_t server;
    FILE *in_s = tmpfile();
    FILE *out_s = tmpfile();
    FILE *err_s = tmpfile();
    gpshell3_mcp_server_init(&server, in_s, out_s, err_s);

    const char *init_req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{\"elicitation\":{}}}}";
    cJSON *resp = process_and_parse_response(&server, out_s, init_req);
    assert_non_null(resp);

    cJSON *id = cJSON_GetObjectItemCaseSensitive(resp, "id");
    assert_non_null(id);
    assert_int_equal((int)id->valuedouble, 1);

    cJSON *result = cJSON_GetObjectItemCaseSensitive(resp, "result");
    assert_non_null(result);

    cJSON *proto = cJSON_GetObjectItemCaseSensitive(result, "protocolVersion");
    assert_non_null(proto);
    assert_string_equal(proto->valuestring, "2025-11-25");

    cJSON *srv_info = cJSON_GetObjectItemCaseSensitive(result, "serverInfo");
    assert_non_null(srv_info);
    cJSON *srv_name = cJSON_GetObjectItemCaseSensitive(srv_info, "name");
    assert_non_null(srv_name);
    assert_string_equal(srv_name->valuestring, "gpshell3");

    cJSON_Delete(resp);
    gpshell3_mcp_server_cleanup(&server);
    fclose(in_s);
    fclose(out_s);
    fclose(err_s);
}

static void test_mcp_initialized_notification_and_ping(void **state) {
    (void)state;
    gpshell3_mcp_server_t server;
    FILE *in_s = tmpfile();
    FILE *out_s = tmpfile();
    FILE *err_s = tmpfile();
    gpshell3_mcp_server_init(&server, in_s, out_s, err_s);

    const char *notif = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}";
    int rc = gpshell3_mcp_process_message(&server, notif);
    assert_int_equal(rc, 0);
    assert_true(server.is_initialized);

    const char *ping = "{\"jsonrpc\":\"2.0\",\"id\":\"ping-123\",\"method\":\"ping\"}";
    cJSON *resp = process_and_parse_response(&server, out_s, ping);
    assert_non_null(resp);

    cJSON *id = cJSON_GetObjectItemCaseSensitive(resp, "id");
    assert_non_null(id);
    assert_string_equal(id->valuestring, "ping-123");

    cJSON *result = cJSON_GetObjectItemCaseSensitive(resp, "result");
    assert_non_null(result);
    assert_true(cJSON_IsObject(result));

    cJSON_Delete(resp);
    gpshell3_mcp_server_cleanup(&server);
    fclose(in_s);
    fclose(out_s);
    fclose(err_s);
}

static void test_mcp_tools_list(void **state) {
    (void)state;
    gpshell3_mcp_server_t server;
    FILE *in_s = tmpfile();
    FILE *out_s = tmpfile();
    FILE *err_s = tmpfile();
    gpshell3_mcp_server_init(&server, in_s, out_s, err_s);

    const char *req = "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"tools/list\"}";
    cJSON *resp = process_and_parse_response(&server, out_s, req);
    assert_non_null(resp);

    cJSON *result = cJSON_GetObjectItemCaseSensitive(resp, "result");
    assert_non_null(result);

    cJSON *tools = cJSON_GetObjectItemCaseSensitive(result, "tools");
    assert_non_null(tools);
    assert_true(cJSON_IsArray(tools));

    int count = cJSON_GetArraySize(tools);
    /* 44 registry commands + open_session + close_session = 46 tools */
    assert_int_equal(count, 46);

    for (int i = 0; i < count; i++) {
        cJSON *tool = cJSON_GetArrayItem(tools, i);
        assert_non_null(tool);

        cJSON *name = cJSON_GetObjectItemCaseSensitive(tool, "name");
        assert_non_null(name);
        assert_true(name->valuestring && strlen(name->valuestring) > 0);

        cJSON *desc = cJSON_GetObjectItemCaseSensitive(tool, "description");
        assert_non_null(desc);
        assert_true(desc->valuestring && strlen(desc->valuestring) > 0);

        cJSON *schema = cJSON_GetObjectItemCaseSensitive(tool, "inputSchema");
        assert_non_null(schema);
        assert_true(cJSON_IsObject(schema));

        cJSON *ann = cJSON_GetObjectItemCaseSensitive(tool, "annotations");
        assert_non_null(ann);
        assert_true(cJSON_IsObject(ann));
    }

    cJSON_Delete(resp);
    gpshell3_mcp_server_cleanup(&server);
    fclose(in_s);
    fclose(out_s);
    fclose(err_s);
}

static void test_mcp_tools_call_hash_offline(void **state) {
    (void)state;
    gpshell3_mcp_server_t server;
    FILE *in_s = tmpfile();
    FILE *out_s = tmpfile();
    FILE *err_s = tmpfile();
    gpshell3_mcp_server_init(&server, in_s, out_s, err_s);

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

    char call_req[1024];
    snprintf(call_req, sizeof(call_req),
             "{\"jsonrpc\":\"2.0\",\"id\":20,\"method\":\"tools/call\",\"params\":{\"name\":\"gpshell3_hash\",\"arguments\":{\"capFile\":\"%s\",\"algorithm\":\"sha256\"}}}",
             cap_path);

    cJSON *resp = process_and_parse_response(&server, out_s, call_req);
    assert_non_null(resp);

    cJSON *result = cJSON_GetObjectItemCaseSensitive(resp, "result");
    assert_non_null(result);

    cJSON *is_err = cJSON_GetObjectItemCaseSensitive(result, "isError");
    assert_non_null(is_err);
    assert_false(cJSON_IsTrue(is_err));

    cJSON *struct_res = cJSON_GetObjectItemCaseSensitive(result, "structuredContent");
    assert_non_null(struct_res);
    cJSON *hash = cJSON_GetObjectItemCaseSensitive(struct_res, "hash");
    assert_non_null(hash);
    assert_int_equal(strlen(hash->valuestring), 64);

    cJSON_Delete(resp);
    gpshell3_mcp_server_cleanup(&server);
    fclose(in_s);
    fclose(out_s);
    fclose(err_s);
}

static void test_mcp_tools_call_session_required_rejection(void **state) {
    (void)state;
    gpshell3_mcp_server_t server;
    FILE *in_s = tmpfile();
    FILE *out_s = tmpfile();
    FILE *err_s = tmpfile();
    gpshell3_mcp_server_init(&server, in_s, out_s, err_s);

    const char *call_req = "{\"jsonrpc\":\"2.0\",\"id\":30,\"method\":\"tools/call\",\"params\":{\"name\":\"gpshell3_list_apps\",\"arguments\":{}}}";
    cJSON *resp = process_and_parse_response(&server, out_s, call_req);
    assert_non_null(resp);

    cJSON *result = cJSON_GetObjectItemCaseSensitive(resp, "result");
    assert_non_null(result);

    cJSON *is_err = cJSON_GetObjectItemCaseSensitive(result, "isError");
    assert_non_null(is_err);
    assert_true(cJSON_IsTrue(is_err));

    cJSON *content = cJSON_GetObjectItemCaseSensitive(result, "content");
    assert_non_null(content);
    assert_true(cJSON_IsArray(content) && cJSON_GetArraySize(content) > 0);

    cJSON_Delete(resp);
    gpshell3_mcp_server_cleanup(&server);
    fclose(in_s);
    fclose(out_s);
    fclose(err_s);
}

static void test_mcp_tools_call_close_session(void **state) {
    (void)state;
    gpshell3_mcp_server_t server;
    FILE *in_s = tmpfile();
    FILE *out_s = tmpfile();
    FILE *err_s = tmpfile();
    gpshell3_mcp_server_init(&server, in_s, out_s, err_s);

    const char *call_req = "{\"jsonrpc\":\"2.0\",\"id\":40,\"method\":\"tools/call\",\"params\":{\"name\":\"gpshell3_close_session\",\"arguments\":{}}}";
    cJSON *resp = process_and_parse_response(&server, out_s, call_req);
    assert_non_null(resp);

    cJSON *result = cJSON_GetObjectItemCaseSensitive(resp, "result");
    assert_non_null(result);

    cJSON *is_err = cJSON_GetObjectItemCaseSensitive(result, "isError");
    assert_non_null(is_err);
    assert_false(cJSON_IsTrue(is_err));

    cJSON *struct_res = cJSON_GetObjectItemCaseSensitive(result, "structuredContent");
    assert_non_null(struct_res);
    cJSON *closed = cJSON_GetObjectItemCaseSensitive(struct_res, "closed");
    assert_non_null(closed);
    assert_true(cJSON_IsTrue(closed));

    cJSON_Delete(resp);
    gpshell3_mcp_server_cleanup(&server);
    fclose(in_s);
    fclose(out_s);
    fclose(err_s);
}

static void test_mcp_error_handling(void **state) {
    (void)state;
    gpshell3_mcp_server_t server;
    FILE *in_s = tmpfile();
    FILE *out_s = tmpfile();
    FILE *err_s = tmpfile();
    gpshell3_mcp_server_init(&server, in_s, out_s, err_s);

    /* Invalid JSON */
    cJSON *resp1 = process_and_parse_response(&server, out_s, "{invalid_json");
    assert_non_null(resp1);
    cJSON *err1 = cJSON_GetObjectItemCaseSensitive(resp1, "error");
    assert_non_null(err1);
    cJSON *code1 = cJSON_GetObjectItemCaseSensitive(err1, "code");
    assert_non_null(code1);
    assert_int_equal((int)code1->valuedouble, -32700);
    cJSON_Delete(resp1);

    /* Unknown method */
    cJSON *resp2 = process_and_parse_response(&server, out_s, "{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"unknown_method\"}");
    assert_non_null(resp2);
    cJSON *err2 = cJSON_GetObjectItemCaseSensitive(resp2, "error");
    assert_non_null(err2);
    cJSON *code2 = cJSON_GetObjectItemCaseSensitive(err2, "code");
    assert_non_null(code2);
    assert_int_equal((int)code2->valuedouble, -32601);
    cJSON_Delete(resp2);

    gpshell3_mcp_server_cleanup(&server);
    fclose(in_s);
    fclose(out_s);
    fclose(err_s);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_mcp_initialize),
        cmocka_unit_test(test_mcp_initialized_notification_and_ping),
        cmocka_unit_test(test_mcp_tools_list),
        cmocka_unit_test(test_mcp_tools_call_hash_offline),
        cmocka_unit_test(test_mcp_tools_call_session_required_rejection),
        cmocka_unit_test(test_mcp_tools_call_close_session),
        cmocka_unit_test(test_mcp_error_handling),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
