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

#include "gpshell3_mcp.h"
#include "gpshell3_registry.h"
#include "gpshell3_session.h"
#include "gpshell3_output.h"
#include "gpshell3_commands.h"

#define JSONRPC_PARSE_ERROR -32700
#define JSONRPC_INVALID_REQUEST -32600
#define JSONRPC_METHOD_NOT_FOUND -32601
#define JSONRPC_INVALID_PARAMS -32602
#define JSONRPC_INTERNAL_ERROR -32603

static void send_jsonrpc_response(gpshell3_mcp_server_t *server, cJSON *response) {
    if (!server || !server->out_stream || !response) return;
    char *rendered = cJSON_PrintUnformatted(response);
    if (rendered) {
        fputs(rendered, server->out_stream);
        fputc('\n', server->out_stream);
        fflush(server->out_stream);
        free(rendered);
    }
}

static void send_jsonrpc_error(gpshell3_mcp_server_t *server, const cJSON *id, int code, const char *message) {
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "jsonrpc", "2.0");
    if (id && !cJSON_IsNull(id)) {
        if (cJSON_IsNumber(id)) cJSON_AddNumberToObject(resp, "id", id->valuedouble);
        else if (cJSON_IsString(id)) cJSON_AddStringToObject(resp, "id", id->valuestring);
        else cJSON_AddNullToObject(resp, "id");
    } else {
        cJSON_AddNullToObject(resp, "id");
    }
    cJSON *err = cJSON_CreateObject();
    cJSON_AddNumberToObject(err, "code", code);
    cJSON_AddStringToObject(err, "message", message ? message : "Error");
    cJSON_AddItemToObject(resp, "error", err);

    send_jsonrpc_response(server, resp);
    cJSON_Delete(resp);
}

void gpshell3_mcp_server_init(gpshell3_mcp_server_t *server, FILE *in, FILE *out, FILE *err) {
    if (!server) return;
    memset(server, 0, sizeof(*server));
    server->in_stream = in ? in : stdin;
    server->out_stream = out ? out : stdout;
    server->err_stream = err ? err : stderr;
    server->is_initialized = false;
    server->should_exit = false;
    server->next_request_id = 1;
    strncpy(server->client_protocol_version, GPSHELL3_MCP_PROTOCOL_VERSION, sizeof(server->client_protocol_version) - 1);
    gpshell3_session_init(&server->session);
    gpshell3_registry_init();
}

void gpshell3_mcp_server_cleanup(gpshell3_mcp_server_t *server) {
    if (!server) return;
    gpshell3_session_close(&server->session);
    server->is_initialized = false;
}

static void handle_initialize(gpshell3_mcp_server_t *server, const cJSON *id, const cJSON *params) {
    if (params && cJSON_IsObject(params)) {
        const char *proto = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(params, "protocolVersion"));
        if (proto && *proto) {
            strncpy(server->client_protocol_version, proto, sizeof(server->client_protocol_version) - 1);
        }
        const cJSON *caps = cJSON_GetObjectItemCaseSensitive(params, "capabilities");
        if (caps && cJSON_IsObject(caps)) {
            if (cJSON_GetObjectItemCaseSensitive(caps, "elicitation") != NULL) {
                server->client_supports_elicitation = true;
            }
        }
    }

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "jsonrpc", "2.0");
    if (id) {
        if (cJSON_IsNumber(id)) cJSON_AddNumberToObject(resp, "id", id->valuedouble);
        else if (cJSON_IsString(id)) cJSON_AddStringToObject(resp, "id", id->valuestring);
        else cJSON_AddNullToObject(resp, "id");
    }

    cJSON *result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "protocolVersion", GPSHELL3_MCP_PROTOCOL_VERSION);

    cJSON *caps = cJSON_CreateObject();
    cJSON *tools = cJSON_CreateObject();
    cJSON_AddBoolToObject(tools, "listChanged", false);
    cJSON_AddItemToObject(caps, "tools", tools);
    cJSON_AddItemToObject(result, "capabilities", caps);

    cJSON *srv_info = cJSON_CreateObject();
    cJSON_AddStringToObject(srv_info, "name", GPSHELL3_MCP_SERVER_NAME);
    cJSON_AddStringToObject(srv_info, "version", GPSHELL3_MCP_SERVER_VERSION);
    cJSON_AddStringToObject(srv_info, "description", "GlobalPlatform smart card shell & management tool for Java Card / GlobalPlatform applet lifecycle, security domains, keys, card queries, and APDU communication.");
    cJSON_AddItemToObject(result, "serverInfo", srv_info);

    cJSON_AddItemToObject(resp, "result", result);
    send_jsonrpc_response(server, resp);
    cJSON_Delete(resp);
}

static void handle_ping(gpshell3_mcp_server_t *server, const cJSON *id) {
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "jsonrpc", "2.0");
    if (id) {
        if (cJSON_IsNumber(id)) cJSON_AddNumberToObject(resp, "id", id->valuedouble);
        else if (cJSON_IsString(id)) cJSON_AddStringToObject(resp, "id", id->valuestring);
        else cJSON_AddNullToObject(resp, "id");
    }
    cJSON_AddItemToObject(resp, "result", cJSON_CreateObject());
    send_jsonrpc_response(server, resp);
    cJSON_Delete(resp);
}

static void handle_tools_list(gpshell3_mcp_server_t *server, const cJSON *id) {
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "jsonrpc", "2.0");
    if (id) {
        if (cJSON_IsNumber(id)) cJSON_AddNumberToObject(resp, "id", id->valuedouble);
        else if (cJSON_IsString(id)) cJSON_AddStringToObject(resp, "id", id->valuestring);
        else cJSON_AddNullToObject(resp, "id");
    }

    cJSON *result = cJSON_CreateObject();
    cJSON *tools_arr = cJSON_CreateArray();

    /* 1. gpshell3_open_session */
    cJSON *tool_open = cJSON_CreateObject();
    cJSON_AddStringToObject(tool_open, "name", "gpshell3_open_session");
    cJSON_AddStringToObject(tool_open, "description", "Use this when the user asks to connect to a smart card reader and optionally authenticate a session. When called with empty arguments ({}), establishes an unauthenticated session (protocol and SCP parameters are auto-detected). To authenticate, keys must be explicitly provided in the 'authentication' argument. Returns session ID, connected reader name, and selected ISD AID.");
    cJSON_AddItemToObject(tool_open, "inputSchema", gpshell3_cmd_open_session_input_schema());
    cJSON *ann_open = cJSON_CreateObject();
    cJSON_AddBoolToObject(ann_open, "destructive", false);
    cJSON_AddBoolToObject(ann_open, "readOnly", false);
    cJSON_AddItemToObject(tool_open, "annotations", ann_open);
    cJSON_AddItemToArray(tools_arr, tool_open);

    /* 2. gpshell3_close_session */
    cJSON *tool_close = cJSON_CreateObject();
    cJSON_AddStringToObject(tool_close, "name", "gpshell3_close_session");
    cJSON_AddStringToObject(tool_close, "description", "Use this when the user asks to close, disconnect, or terminate an active smart card session. Releases PC/SC reader resources and securely zeroizes all cryptographic keys and session state from memory. Returns session closure status.");
    cJSON_AddItemToObject(tool_close, "inputSchema", gpshell3_cmd_close_session_input_schema());
    cJSON *ann_close = cJSON_CreateObject();
    cJSON_AddBoolToObject(ann_close, "destructive", false);
    cJSON_AddBoolToObject(ann_close, "readOnly", true);
    cJSON_AddItemToObject(tool_close, "annotations", ann_close);
    cJSON_AddItemToArray(tools_arr, tool_close);

    /* 3. All registry commands */
    size_t count = gpshell3_registry_count();
    for (size_t i = 0; i < count; i++) {
        const gpshell3_cmd_def_t *def = gpshell3_registry_get(i);
        if (!def) continue;

        cJSON *tool = cJSON_CreateObject();
        cJSON_AddStringToObject(tool, "name", def->tool_name);
        cJSON_AddStringToObject(tool, "description", def->description);

        if (def->get_input_schema) {
            cJSON_AddItemToObject(tool, "inputSchema", def->get_input_schema());
        } else {
            cJSON_AddItemToObject(tool, "inputSchema", gpshell3_schema_object());
        }

        cJSON *ann = cJSON_CreateObject();
        cJSON_AddBoolToObject(ann, "destructive", def->is_destructive);
        cJSON_AddBoolToObject(ann, "readOnly", !def->is_destructive);
        cJSON_AddItemToObject(tool, "annotations", ann);

        cJSON_AddItemToArray(tools_arr, tool);
    }

    cJSON_AddItemToObject(result, "tools", tools_arr);
    cJSON_AddItemToObject(resp, "result", result);
    send_jsonrpc_response(server, resp);
    cJSON_Delete(resp);
}

static void handle_tools_call(gpshell3_mcp_server_t *server, const cJSON *id, const cJSON *params) {
    gpshell3_clear_last_opgp_error();
    if (!params || !cJSON_IsObject(params)) {
        send_jsonrpc_error(server, id, JSONRPC_INVALID_PARAMS, "Missing params for tools/call");
        return;
    }

    const char *tool_name = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(params, "name"));
    if (!tool_name) {
        send_jsonrpc_error(server, id, JSONRPC_INVALID_PARAMS, "Missing tool name in tools/call");
        return;
    }

    cJSON *args = cJSON_GetObjectItemCaseSensitive(params, "arguments");

    gpshell3_output_ctx_t out_ctx;
    FILE *stream_out = tmpfile();
    FILE *stream_err = tmpfile();
    gpshell3_output_init_stream(&out_ctx, OUTPUT_FORMAT_JSON, stream_out, stream_err);
    gpshell3_output_set_command(&out_ctx, tool_name);

    int exec_rc = 0;

    if (!strcmp(tool_name, "gpshell3_open_session")) {
        exec_rc = gpshell3_cmd_open_session_cmd(&server->session, args, &out_ctx);
    } else if (!strcmp(tool_name, "gpshell3_close_session")) {
        exec_rc = gpshell3_cmd_close_session_cmd(&server->session, args, &out_ctx);
    } else {
        const gpshell3_cmd_def_t *def = gpshell3_registry_find_by_tool_name(tool_name);
        if (!def) {
            gpshell3_output_cleanup(&out_ctx);
            if (stream_out) fclose(stream_out);
            if (stream_err) fclose(stream_err);
            send_jsonrpc_error(server, id, JSONRPC_METHOD_NOT_FOUND, "Tool not found");
            return;
        }

        if (def->requires_session) {
            const char *sid = args ? cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(args, "sessionId")) : NULL;
            if (!gpshell3_session_is_valid(&server->session, sid)) {
                gpshell3_report_error(&out_ctx, "SESSION_REQUIRED", "Active session required. Call gpshell3_open_session first.");
                exec_rc = -1;
            }
        }

        if (exec_rc == 0) {
            if (def->execute_cmd) {
                exec_rc = def->execute_cmd(&server->session, args, &out_ctx);
            } else {
                gpshell3_report_error(&out_ctx, "NOT_IMPLEMENTED", "Command execution handler not implemented");
                exec_rc = -1;
            }
        }
    }

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "jsonrpc", "2.0");
    if (id) {
        if (cJSON_IsNumber(id)) cJSON_AddNumberToObject(resp, "id", id->valuedouble);
        else if (cJSON_IsString(id)) cJSON_AddStringToObject(resp, "id", id->valuestring);
        else cJSON_AddNullToObject(resp, "id");
    }

    cJSON *result = cJSON_CreateObject();
    cJSON *content_arr = cJSON_CreateArray();

    if (exec_rc != 0 || out_ctx.has_error) {
        if (!out_ctx.has_error) {
            gpshell3_propagate_last_opgp_error(&out_ctx, "COMMAND_FAILED", NULL);
        }
        cJSON_AddBoolToObject(result, "isError", true);
        char *err_str = gpshell3_output_render_string(&out_ctx, false);
        cJSON *text_node = cJSON_CreateObject();
        cJSON_AddStringToObject(text_node, "type", "text");
        cJSON_AddStringToObject(text_node, "text", err_str ? err_str : "{\"ok\":false,\"error\":{\"code\":\"COMMAND_FAILED\",\"message\":\"Command failed\"}}");
        cJSON_AddItemToArray(content_arr, text_node);
        if (err_str) free(err_str);

        if (out_ctx.json_error) {
            cJSON_AddItemToObject(result, "error", cJSON_Duplicate(out_ctx.json_error, true));
            cJSON *structured_error = gpshell3_output_get_root(&out_ctx);
            if (structured_error) {
                cJSON_AddItemToObject(result, "structuredContent", cJSON_Duplicate(structured_error, true));
            }
        }
    } else {
        cJSON_AddBoolToObject(result, "isError", false);

        char *res_str = gpshell3_output_render_string(&out_ctx, false);
        cJSON *text_node = cJSON_CreateObject();
        cJSON_AddStringToObject(text_node, "type", "text");
        cJSON_AddStringToObject(text_node, "text", res_str ? res_str : "Success");
        cJSON_AddItemToArray(content_arr, text_node);
        if (res_str) free(res_str);

        if (out_ctx.json_result) {
            cJSON_AddItemToObject(result, "structuredContent", cJSON_Duplicate(out_ctx.json_result, true));
        }
    }

    cJSON_AddItemToObject(result, "content", content_arr);
    cJSON_AddItemToObject(resp, "result", result);

    send_jsonrpc_response(server, resp);

    cJSON_Delete(resp);
    gpshell3_output_cleanup(&out_ctx);
    if (stream_out) fclose(stream_out);
    if (stream_err) fclose(stream_err);
}

int gpshell3_mcp_process_message(gpshell3_mcp_server_t *server, const char *json_msg) {
    if (!server || !json_msg || *json_msg == '\0') return 0;

    cJSON *req = cJSON_Parse(json_msg);
    if (!req) {
        send_jsonrpc_error(server, NULL, JSONRPC_PARSE_ERROR, "Parse error: invalid JSON");
        return 0;
    }

    if (!cJSON_IsObject(req)) {
        send_jsonrpc_error(server, NULL, JSONRPC_INVALID_REQUEST, "Invalid request: expected JSON object");
        cJSON_Delete(req);
        return 0;
    }

    const cJSON *id = cJSON_GetObjectItemCaseSensitive(req, "id");
    const char *method = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(req, "method"));
    const cJSON *params = cJSON_GetObjectItemCaseSensitive(req, "params");

    if (!method) {
        send_jsonrpc_error(server, id, JSONRPC_INVALID_REQUEST, "Missing method");
        cJSON_Delete(req);
        return 0;
    }

    if (!strcmp(method, "initialize")) {
        handle_initialize(server, id, params);
    } else if (!strcmp(method, "notifications/initialized") || !strcmp(method, "initialized")) {
        server->is_initialized = true;
    } else if (!strcmp(method, "ping")) {
        handle_ping(server, id);
    } else if (!strcmp(method, "tools/list")) {
        handle_tools_list(server, id);
    } else if (!strcmp(method, "tools/call")) {
        handle_tools_call(server, id, params);
    } else {
        if (id && !cJSON_IsNull(id)) {
            send_jsonrpc_error(server, id, JSONRPC_METHOD_NOT_FOUND, "Method not supported");
        }
    }

    cJSON_Delete(req);
    return 0;
}

int gpshell3_mcp_run_stdio_loop(gpshell3_mcp_server_t *server) {
    if (!server) return -1;
    char buffer[16384];

    while (!server->should_exit && fgets(buffer, sizeof(buffer), server->in_stream)) {
        size_t len = strlen(buffer);
        while (len > 0 && (buffer[len - 1] == '\r' || buffer[len - 1] == '\n')) {
            buffer[--len] = '\0';
        }
        if (len == 0) continue;

        gpshell3_mcp_process_message(server, buffer);
    }

    gpshell3_mcp_server_cleanup(server);
    return 0;
}
