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
#include <globalplatform/globalplatform.h>
#include "gpshell3_output.h"
#include "gpshell3_session.h"
#include "gpshell3_registry.h"
#include "gpshell3_commands.h"
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
    /* 45 registry commands + open_session + close_session = 47 tools */
    assert_int_equal(count, 47);

    for (int i = 0; i < count; i++) {
        cJSON *tool = cJSON_GetArrayItem(tools, i);
        assert_non_null(tool);

        cJSON *name = cJSON_GetObjectItemCaseSensitive(tool, "name");
        assert_non_null(name);
        assert_true(name->valuestring && strlen(name->valuestring) > 0);

        cJSON *desc = cJSON_GetObjectItemCaseSensitive(tool, "description");
        assert_non_null(desc);
        assert_true(desc->valuestring && strlen(desc->valuestring) > 0);
        assert_true(strncmp(desc->valuestring, "Use this when the user asks to ", 31) == 0);
        assert_non_null(strstr(desc->valuestring, "Returns "));
        assert_non_null(strstr(desc->valuestring, "gpshell"));
        assert_non_null(strstr(desc->valuestring, "gpshell3"));

        cJSON *schema = cJSON_GetObjectItemCaseSensitive(tool, "inputSchema");
        assert_non_null(schema);
        assert_true(cJSON_IsObject(schema));

        cJSON *ann = cJSON_GetObjectItemCaseSensitive(tool, "annotations");
        assert_non_null(ann);
        assert_true(cJSON_IsObject(ann));

        if (strcmp(name->valuestring, "gpshell3_open_session") == 0) {
            assert_non_null(strstr(desc->valuestring, "re-authenticate"));
            assert_non_null(strstr(desc->valuestring, "persists across multiple commands"));
            assert_non_null(strstr(desc->valuestring, "prerequisite tool"));
        } else if (strcmp(name->valuestring, "gpshell3_delete") == 0) {
            assert_non_null(strstr(desc->valuestring, "AUTHENTICATION_REQUIRED"));
            assert_non_null(strstr(desc->valuestring, "gpshell3_open_session"));
        } else if (strcmp(name->valuestring, "gpshell3_list_apps") == 0) {
            assert_non_null(strstr(desc->valuestring, "6982"));
            assert_non_null(strstr(desc->valuestring, "gpshell3_open_session"));
        }
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

static void test_mcp_tools_call_inspect_card_no_card(void **state) {
    (void)state;
    gpshell3_mcp_server_t server;
    FILE *in_s = tmpfile();
    FILE *out_s = tmpfile();
    FILE *err_s = tmpfile();
    gpshell3_mcp_server_init(&server, in_s, out_s, err_s);

    const char *call_req = "{\"jsonrpc\":\"2.0\",\"id\":25,\"method\":\"tools/call\",\"params\":{\"name\":\"gpshell3_inspect_card\",\"arguments\":{}}}";
    cJSON *resp = process_and_parse_response(&server, out_s, call_req);
    assert_non_null(resp);

    cJSON *result = cJSON_GetObjectItemCaseSensitive(resp, "result");
    assert_non_null(result);

    cJSON *is_err = cJSON_GetObjectItemCaseSensitive(result, "isError");
    assert_non_null(is_err);
    assert_false(cJSON_IsTrue(is_err));

    cJSON *struct_res = cJSON_GetObjectItemCaseSensitive(result, "structuredContent");
    assert_non_null(struct_res);

    cJSON *card_present = cJSON_GetObjectItemCaseSensitive(struct_res, "cardPresent");
    assert_non_null(card_present);
    assert_false(cJSON_IsTrue(card_present));

    cJSON *readers = cJSON_GetObjectItemCaseSensitive(struct_res, "readers");
    assert_non_null(readers);
    assert_true(cJSON_IsArray(readers));

    cJSON *msg = cJSON_GetObjectItemCaseSensitive(struct_res, "message");
    assert_non_null(msg);
    assert_true(msg->valuestring && strlen(msg->valuestring) > 0);

    /* Verify output schema contains applicationsStatus and atr */
    cJSON *out_schema = gpshell3_cmd_inspect_card_output_schema();
    assert_non_null(out_schema);
    cJSON *schema_props = cJSON_GetObjectItemCaseSensitive(out_schema, "properties");
    assert_non_null(schema_props);
    assert_non_null(cJSON_GetObjectItemCaseSensitive(schema_props, "applicationsStatus"));
    assert_non_null(cJSON_GetObjectItemCaseSensitive(schema_props, "atr"));
    cJSON_Delete(out_schema);

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
    cJSON *first_text = cJSON_GetArrayItem(content, 0);
    assert_non_null(first_text);
    cJSON *t_str = cJSON_GetObjectItemCaseSensitive(first_text, "text");
    assert_non_null(t_str);
    assert_non_null(strstr(t_str->valuestring, "Active session required"));

    /* Verify content[0].text is valid parseable JSON containing ok: false and code: SESSION_REQUIRED */
    cJSON *parsed_t = cJSON_Parse(t_str->valuestring);
    assert_non_null(parsed_t);
    assert_false(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(parsed_t, "ok")));
    cJSON *parsed_err = cJSON_GetObjectItemCaseSensitive(parsed_t, "error");
    assert_non_null(parsed_err);
    assert_string_equal(cJSON_GetObjectItemCaseSensitive(parsed_err, "code")->valuestring, "SESSION_REQUIRED");
    cJSON_Delete(parsed_t);

    cJSON *err_obj = cJSON_GetObjectItemCaseSensitive(result, "error");
    assert_non_null(err_obj);
    assert_true(cJSON_IsObject(err_obj));
    cJSON *code = cJSON_GetObjectItemCaseSensitive(err_obj, "code");
    assert_non_null(code);
    assert_string_equal(code->valuestring, "SESSION_REQUIRED");
    cJSON *op = cJSON_GetObjectItemCaseSensitive(err_obj, "operation");
    assert_non_null(op);
    assert_string_equal(op->valuestring, "gpshell3_list_apps");

    cJSON *structured_error = cJSON_GetObjectItemCaseSensitive(result, "structuredContent");
    assert_non_null(structured_error);
    assert_true(cJSON_IsObject(structured_error));
    assert_false(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(structured_error, "ok")));
    cJSON *structured_error_obj = cJSON_GetObjectItemCaseSensitive(structured_error, "error");
    assert_non_null(structured_error_obj);
    assert_string_equal(cJSON_GetObjectItemCaseSensitive(structured_error_obj, "code")->valuestring,
                        "SESSION_REQUIRED");
    assert_string_equal(cJSON_GetObjectItemCaseSensitive(structured_error_obj, "operation")->valuestring,
                        "gpshell3_list_apps");

    cJSON_Delete(resp);
    gpshell3_mcp_server_cleanup(&server);
    fclose(in_s);
    fclose(out_s);
    fclose(err_s);
}

static void test_mcp_tools_call_open_session_error_envelope(void **state) {
    (void)state;
    gpshell3_mcp_server_t server;
    FILE *in_s = tmpfile();
    FILE *out_s = tmpfile();
    FILE *err_s = tmpfile();
    gpshell3_mcp_server_init(&server, in_s, out_s, err_s);

    const char *call_req = "{\"jsonrpc\":\"2.0\",\"id\":35,\"method\":\"tools/call\",\"params\":{\"name\":\"gpshell3_open_session\",\"arguments\":{\"reader\":\"non_existent_reader_xyz_123\"}}}";
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
    cJSON *first_text = cJSON_GetArrayItem(content, 0);
    assert_non_null(first_text);
    cJSON *t_str = cJSON_GetObjectItemCaseSensitive(first_text, "text");
    assert_non_null(t_str);

    /* Verify content[0].text is valid parseable JSON containing ok: false */
    cJSON *parsed_t = cJSON_Parse(t_str->valuestring);
    assert_non_null(parsed_t);
    assert_false(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(parsed_t, "ok")));
    cJSON *parsed_err = cJSON_GetObjectItemCaseSensitive(parsed_t, "error");
    assert_non_null(parsed_err);
    assert_non_null(cJSON_GetObjectItemCaseSensitive(parsed_err, "code"));
    cJSON_Delete(parsed_t);

    cJSON *err_obj = cJSON_GetObjectItemCaseSensitive(result, "error");
    assert_non_null(err_obj);
    assert_true(cJSON_IsObject(err_obj));
    cJSON *code = cJSON_GetObjectItemCaseSensitive(err_obj, "code");
    assert_non_null(code);
    assert_non_null(code->valuestring);
    cJSON *op = cJSON_GetObjectItemCaseSensitive(err_obj, "operation");
    assert_non_null(op);
    assert_string_equal(op->valuestring, "gpshell3_open_session");

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

static void test_mcp_sequential_errors_no_stale_opgp_error(void **state) {
    (void)state;
    gpshell3_mcp_server_t server;
    FILE *in_s = tmpfile();
    FILE *out_s = tmpfile();
    FILE *err_s = tmpfile();
    gpshell3_mcp_server_init(&server, in_s, out_s, err_s);

    /* 1. Simulate a prior command failing with an ISO/GP Status Word 0x6982 */
    OPGP_ERROR_STATUS status;
    OPGP_ERROR_CREATE_ERROR(status, 0x80206982, _T("Security status not satisfied"));
    gpshell3_set_last_opgp_error(status);

    /* Verify that gpshell3_propagate_last_opgp_error would pick it up when present */
    gpshell3_output_ctx_t out_ctx1;
    gpshell3_output_init(&out_ctx1, OUTPUT_FORMAT_JSON);
    gpshell3_output_set_command(&out_ctx1, "gpshell3_list_apps");
    gpshell3_propagate_last_opgp_error(&out_ctx1, "COMMAND_FAILED", NULL);
    assert_true(out_ctx1.has_error);
    assert_non_null(out_ctx1.json_error);
    cJSON *code1 = cJSON_GetObjectItemCaseSensitive(out_ctx1.json_error, "code");
    assert_non_null(code1);
    assert_string_equal(code1->valuestring, "AUTHENTICATION_REQUIRED");
    cJSON *sw1 = cJSON_GetObjectItemCaseSensitive(out_ctx1.json_error, "statusWord");
    assert_non_null(sw1);
    assert_string_equal(sw1->valuestring, "6982");
    gpshell3_output_cleanup(&out_ctx1);

    /* 2. Re-inject an error status into g_last_opgp_error before an MCP tools/call */
    gpshell3_set_last_opgp_error(status);

    /* 3. Call a tool via MCP that fails via non-card path (e.g. session required) */
    const char *call_req = "{\"jsonrpc\":\"2.0\",\"id\":50,\"method\":\"tools/call\",\"params\":{\"name\":\"gpshell3_list_apps\",\"arguments\":{}}}";
    cJSON *resp = process_and_parse_response(&server, out_s, call_req);
    assert_non_null(resp);

    cJSON *result = cJSON_GetObjectItemCaseSensitive(resp, "result");
    assert_non_null(result);

    cJSON *is_err = cJSON_GetObjectItemCaseSensitive(result, "isError");
    assert_non_null(is_err);
    assert_true(cJSON_IsTrue(is_err));

    cJSON *err_obj = cJSON_GetObjectItemCaseSensitive(result, "error");
    assert_non_null(err_obj);
    assert_true(cJSON_IsObject(err_obj));

    /* Ensure error code is SESSION_REQUIRED and NOT AUTHENTICATION_REQUIRED */
    cJSON *code2 = cJSON_GetObjectItemCaseSensitive(err_obj, "code");
    assert_non_null(code2);
    assert_string_equal(code2->valuestring, "SESSION_REQUIRED");

    /* Ensure no stale statusWord or opgpErrorCode from the prior 0x6982 error */
    cJSON *sw2 = cJSON_GetObjectItemCaseSensitive(err_obj, "statusWord");
    assert_null(sw2);

    cJSON *opgp_code2 = cJSON_GetObjectItemCaseSensitive(err_obj, "opgpErrorCode");
    assert_null(opgp_code2);

    /* Ensure message is about session, not card security status */
    cJSON *msg2 = cJSON_GetObjectItemCaseSensitive(err_obj, "message");
    assert_non_null(msg2);
    assert_non_null(strstr(msg2->valuestring, "Active session required"));
    assert_null(strstr(msg2->valuestring, "Security status not satisfied"));
    assert_null(strstr(msg2->valuestring, "authenticated session"));

    cJSON_Delete(resp);

    /* 4. Also test calling a tool where command execution handler fails on arguments without setting OPGP error */
    gpshell3_set_last_opgp_error(status);

    /* Call gpshell3_hash with missing argument (fails with MISSING_ARGUMENT) */
    const char *hash_req = "{\"jsonrpc\":\"2.0\",\"id\":51,\"method\":\"tools/call\",\"params\":{\"name\":\"gpshell3_hash\",\"arguments\":{}}}";
    resp = process_and_parse_response(&server, out_s, hash_req);
    assert_non_null(resp);

    result = cJSON_GetObjectItemCaseSensitive(resp, "result");
    assert_non_null(result);
    err_obj = cJSON_GetObjectItemCaseSensitive(result, "error");
    assert_non_null(err_obj);

    cJSON *code3 = cJSON_GetObjectItemCaseSensitive(err_obj, "code");
    assert_non_null(code3);
    assert_string_equal(code3->valuestring, "MISSING_ARGUMENT");
    assert_null(cJSON_GetObjectItemCaseSensitive(err_obj, "statusWord"));
    assert_null(cJSON_GetObjectItemCaseSensitive(err_obj, "opgpErrorCode"));

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

static void test_mcp_open_session_description_clarity(void **state) {
    (void)state;
    gpshell3_mcp_server_t server;
    FILE *in_s = tmpfile();
    FILE *out_s = tmpfile();
    FILE *err_s = tmpfile();
    gpshell3_mcp_server_init(&server, in_s, out_s, err_s);

    const char *list_req = "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"tools/list\"}";
    cJSON *resp = process_and_parse_response(&server, out_s, list_req);
    assert_non_null(resp);

    cJSON *result = cJSON_GetObjectItemCaseSensitive(resp, "result");
    assert_non_null(result);
    cJSON *tools = cJSON_GetObjectItemCaseSensitive(result, "tools");
    assert_non_null(tools);

    cJSON *open_tool = NULL;
    int count = cJSON_GetArraySize(tools);
    for (int i = 0; i < count; i++) {
        cJSON *t = cJSON_GetArrayItem(tools, i);
        cJSON *name = cJSON_GetObjectItemCaseSensitive(t, "name");
        if (name && strcmp(name->valuestring, "gpshell3_open_session") == 0) {
            open_tool = t;
            break;
        }
    }
    assert_non_null(open_tool);
    cJSON *desc = cJSON_GetObjectItemCaseSensitive(open_tool, "description");
    assert_non_null(desc);
    assert_non_null(strstr(desc->valuestring, "gpshell"));
    assert_non_null(strstr(desc->valuestring, "gpshell3"));
    assert_non_null(strstr(desc->valuestring, "prerequisite tool"));
    assert_non_null(strstr(desc->valuestring, "unauthenticated session"));
    assert_non_null(strstr(desc->valuestring, "authentication"));

    cJSON_Delete(resp);
    gpshell3_mcp_server_cleanup(&server);
    fclose(in_s);
    fclose(out_s);
    fclose(err_s);
}

static void test_mcp_apdu_invalid_argument_error(void **state) {
    (void)state;
    gpshell3_mcp_server_t server;
    FILE *in_s = tmpfile();
    FILE *out_s = tmpfile();
    FILE *err_s = tmpfile();
    gpshell3_mcp_server_init(&server, in_s, out_s, err_s);

    /* Setup active mock session on server */
    server.session.is_connected = true;
    snprintf(server.session.session_id, sizeof(server.session.session_id), "mock-session-123");
    snprintf(server.session.connected_reader, sizeof(server.session.connected_reader), "Mock Reader");

    /* Call gpshell3_apdu with invalid hex in arguments */
    char call_req[1024];
    snprintf(call_req, sizeof(call_req),
             "{\"jsonrpc\":\"2.0\",\"id\":60,\"method\":\"tools/call\",\"params\":{\"name\":\"gpshell3_apdu\",\"arguments\":{\"sessionId\":\"%s\",\"apdu\":\"not-hex\"}}}",
             server.session.session_id);

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
    cJSON *first_text = cJSON_GetArrayItem(content, 0);
    assert_non_null(first_text);
    cJSON *t_str = cJSON_GetObjectItemCaseSensitive(first_text, "text");
    assert_non_null(t_str);
    assert_non_null(strstr(t_str->valuestring, "Invalid hex in APDU"));

    /* Verify content[0].text is valid parseable JSON containing ok: false and code: INVALID_ARGUMENT */
    cJSON *parsed_t = cJSON_Parse(t_str->valuestring);
    assert_non_null(parsed_t);
    assert_false(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(parsed_t, "ok")));
    cJSON *parsed_err = cJSON_GetObjectItemCaseSensitive(parsed_t, "error");
    assert_non_null(parsed_err);
    assert_string_equal(cJSON_GetObjectItemCaseSensitive(parsed_err, "code")->valuestring, "INVALID_ARGUMENT");
    cJSON_Delete(parsed_t);

    cJSON *err_obj = cJSON_GetObjectItemCaseSensitive(result, "error");
    assert_non_null(err_obj);

    cJSON *code = cJSON_GetObjectItemCaseSensitive(err_obj, "code");
    assert_non_null(code);
    assert_string_equal(code->valuestring, "INVALID_ARGUMENT");

    cJSON *msg = cJSON_GetObjectItemCaseSensitive(err_obj, "message");
    assert_non_null(msg);
    assert_non_null(strstr(msg->valuestring, "Invalid hex in APDU"));

    cJSON_Delete(resp);
    server.session.is_connected = false;
    gpshell3_mcp_server_cleanup(&server);
    fclose(in_s);
    fclose(out_s);
    fclose(err_s);
}

static void test_status_ok_records_opgp_error(void **state) {
    (void)state;
    gpshell3_clear_last_opgp_error();

    /* Simulate a GP failure with ISO 7816-4 SW 0x6A80 (Incorrect parameters in data field) */
    OPGP_ERROR_STATUS status;
    OPGP_ERROR_CREATE_ERROR(status, 0x80206A80, _T("Incorrect parameters in data field"));
    gpshell3_set_last_opgp_error(status);

    gpshell3_output_ctx_t out;
    gpshell3_output_init(&out, OUTPUT_FORMAT_JSON);
    gpshell3_output_set_command(&out, "gpshell3_install");

    gpshell3_propagate_last_opgp_error(&out, "COMMAND_FAILED", "Installation failed");
    assert_true(out.has_error);
    assert_non_null(out.json_error);

    cJSON *code = cJSON_GetObjectItemCaseSensitive(out.json_error, "code");
    assert_non_null(code);
    assert_string_equal(code->valuestring, "WRONG_DATA");

    cJSON *sw = cJSON_GetObjectItemCaseSensitive(out.json_error, "statusWord");
    assert_non_null(sw);
    assert_string_equal(sw->valuestring, "6A80");

    cJSON *opgp_err = cJSON_GetObjectItemCaseSensitive(out.json_error, "opgpErrorCode");
    assert_non_null(opgp_err);
    assert_string_equal(opgp_err->valuestring, "0x80206A80");

    gpshell3_output_cleanup(&out);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_mcp_initialize),
        cmocka_unit_test(test_mcp_initialized_notification_and_ping),
        cmocka_unit_test(test_mcp_tools_list),
        cmocka_unit_test(test_mcp_tools_call_hash_offline),
        cmocka_unit_test(test_mcp_tools_call_inspect_card_no_card),
        cmocka_unit_test(test_mcp_tools_call_session_required_rejection),
        cmocka_unit_test(test_mcp_tools_call_open_session_error_envelope),
        cmocka_unit_test(test_mcp_sequential_errors_no_stale_opgp_error),
        cmocka_unit_test(test_mcp_tools_call_close_session),
        cmocka_unit_test(test_mcp_error_handling),
        cmocka_unit_test(test_mcp_open_session_description_clarity),
        cmocka_unit_test(test_mcp_apdu_invalid_argument_error),
        cmocka_unit_test(test_status_ok_records_opgp_error),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
