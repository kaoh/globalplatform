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

#ifndef GPSHELL3_REGISTRY_H
#define GPSHELL3_REGISTRY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include "cJSON.h"
#include "gpshell3_output.h"
#include "gpshell3_session.h"

/**
 * Command and MCP tool descriptor.
 */
typedef struct gpshell3_cmd_def {
    const char *name;              /* CLI command name, e.g. "list-apps" */
    const char *tool_name;         /* MCP tool name, e.g. "gpshell3_list_apps" */
    const char *description;       /* Detailed LLM-friendly description */
    bool requires_session;         /* Requires active PC/SC smart card session */
    bool is_destructive;           /* State-changing operation (requires MCP Elicitation) */
    cJSON *(*get_input_schema)(void);
    cJSON *(*get_output_schema)(void);
    int (*execute_cmd)(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out);
    int (*execute_cli)(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out);
} gpshell3_cmd_def_t;

/**
 * Initialize the command registry.
 */
void gpshell3_registry_init(void);

/**
 * Look up command by CLI name (e.g. "list-apps").
 * \param name CLI command name.
 * \return Pointer to descriptor or NULL if not found.
 */
const gpshell3_cmd_def_t *gpshell3_registry_find_by_name(const char *name);

/**
 * Look up command by MCP tool name (e.g. "gpshell3_list_apps").
 * \param tool_name MCP tool name.
 * \return Pointer to descriptor or NULL if not found.
 */
const gpshell3_cmd_def_t *gpshell3_registry_find_by_tool_name(const char *tool_name);

/**
 * Get total number of registered commands.
 * \return Count of commands.
 */
size_t gpshell3_registry_count(void);

/**
 * Get command descriptor by index.
 * \param index 0-based index.
 * \return Pointer to descriptor or NULL if out of bounds.
 */
const gpshell3_cmd_def_t *gpshell3_registry_get(size_t index);

/**
 * Schema builder helpers.
 */
cJSON *gpshell3_schema_object(void);
void gpshell3_schema_add_prop_string(cJSON *schema, const char *name, const char *desc, bool required);
void gpshell3_schema_add_prop_int(cJSON *schema, const char *name, const char *desc, bool required);
void gpshell3_schema_add_prop_bool(cJSON *schema, const char *name, const char *desc, bool required);
void gpshell3_schema_add_prop_enum(cJSON *schema, const char *name, const char *desc, const char **enum_values, size_t count, bool required);
void gpshell3_schema_add_prop_array(cJSON *schema, const char *name, const char *desc, const char *item_type, bool required);
void gpshell3_schema_add_prop_object(cJSON *schema, const char *name, const char *desc, bool required);

#ifdef __cplusplus
}
#endif

#endif /* GPSHELL3_REGISTRY_H */
