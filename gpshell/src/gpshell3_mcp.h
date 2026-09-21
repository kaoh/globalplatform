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

#ifndef GPSHELL3_MCP_H
#define GPSHELL3_MCP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdbool.h>
#include "cJSON.h"
#include "gpshell3_session.h"
#include "gpshell3_output.h"

#define GPSHELL3_MCP_PROTOCOL_VERSION "2025-11-25"
#define GPSHELL3_MCP_SERVER_NAME "gpshell3"
#define GPSHELL3_MCP_SERVER_VERSION "1.0.0"

/**
 * MCP Server state context.
 */
typedef struct gpshell3_mcp_server {
    bool is_initialized;
    char client_protocol_version[32];
    bool client_supports_elicitation;
    gpshell3_session_t session;
    FILE *in_stream;
    FILE *out_stream;
    FILE *err_stream;
    bool should_exit;
    int next_request_id;
} gpshell3_mcp_server_t;

/**
 * Initialize an MCP server instance with custom I/O streams.
 */
void gpshell3_mcp_server_init(gpshell3_mcp_server_t *server, FILE *in, FILE *out, FILE *err);

/**
 * Clean up and close all server resources and active sessions.
 */
void gpshell3_mcp_server_cleanup(gpshell3_mcp_server_t *server);

/**
 * Process a single raw JSON-RPC string message and write the response (if any) to out_stream.
 *
 * @param server Server context.
 * @param json_msg Raw input line.
 * @return 0 on success, non-zero on error or fatal EOF.
 */
int gpshell3_mcp_process_message(gpshell3_mcp_server_t *server, const char *json_msg);

/**
 * Run the standard newline-delimited STDIO message loop until EOF or shutdown.
 *
 * @param server Server context.
 * @return 0 on normal exit, non-zero on error.
 */
int gpshell3_mcp_run_stdio_loop(gpshell3_mcp_server_t *server);

#ifdef __cplusplus
}
#endif

#endif /* GPSHELL3_MCP_H */
