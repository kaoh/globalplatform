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

#ifndef GPSHELL3_OUTPUT_H
#define GPSHELL3_OUTPUT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stddef.h>

#include <globalplatform/globalplatform.h>
#include "cJSON.h"

/**
 * Output format modes for gpshell3.
 */
typedef enum {
    OUTPUT_FORMAT_TEXT = 0,
    OUTPUT_FORMAT_JSON = 1
} gpshell3_output_mode_t;

/**
 * Generic output context holding output mode, target streams,
 * command identifier, and structured JSON AST.
 */
typedef struct gpshell3_output_ctx {
    gpshell3_output_mode_t mode;
    FILE *out_stream;
    FILE *err_stream;
    char command[128];
    bool has_error;
    cJSON *json_root;
    cJSON *json_result;
    cJSON *json_error;
} gpshell3_output_ctx_t;

/**
 * Initialize output context with standard stdout/stderr streams.
 * \param ctx Output context.
 * \param mode Output mode (OUTPUT_FORMAT_TEXT or OUTPUT_FORMAT_JSON).
 */
void gpshell3_output_init(gpshell3_output_ctx_t *ctx, gpshell3_output_mode_t mode);

/**
 * Initialize output context with custom output and error streams.
 * \param ctx Output context.
 * \param mode Output mode.
 * \param out_stream Standard output stream (defaults to stdout if NULL).
 * \param err_stream Error output stream (defaults to stderr if NULL).
 */
void gpshell3_output_init_stream(gpshell3_output_ctx_t *ctx, gpshell3_output_mode_t mode, FILE *out_stream, FILE *err_stream);

/**
 * Set the current command name in the output context.
 * \param ctx Output context.
 * \param command Command name (e.g., "list-apps" or "gpshell3_list_apps").
 */
void gpshell3_output_set_command(gpshell3_output_ctx_t *ctx, const char *command);

/**
 * Get the current command name from the output context.
 * \param ctx Output context.
 * \return Command name or empty string.
 */
const char *gpshell3_output_get_command(const gpshell3_output_ctx_t *ctx);

/**
 * Reset output context state for a new command invocation without destroying streams.
 * \param ctx Output context.
 */
void gpshell3_output_reset(gpshell3_output_ctx_t *ctx);

/**
 * Clean up all resources held by output context.
 * \param ctx Output context.
 */
void gpshell3_output_cleanup(gpshell3_output_ctx_t *ctx);

/**
 * Check whether an error has been reported in this context.
 * \param ctx Output context.
 * \return true if an error has occurred, false otherwise.
 */
bool gpshell3_output_has_error(const gpshell3_output_ctx_t *ctx);

/**
 * Report a generic error with an error code and formatted message.
 * In text mode, outputs formatted error to err_stream.
 * In JSON mode, constructs standardized error envelope.
 * \param ctx Output context.
 * \param code Error code identifier (e.g. "INVALID_ARGUMENT", "SESSION_REQUIRED").
 * \param fmt Format string.
 */
void gpshell3_report_error(gpshell3_output_ctx_t *ctx, const char *code, const char *fmt, ...);
void gpshell3_report_error_va(gpshell3_output_ctx_t *ctx, const char *code, const char *fmt, va_list args);

/**
 * Report a GlobalPlatform library error with status and optional context message.
 * In text mode, formats error message and hex code to err_stream.
 * In JSON mode, constructs error object with code, opgpErrorCode, and message.
 * \param ctx Output context.
 * \param code High-level error code (or NULL for default "CARD_COMMUNICATION_ERROR").
 * \param status OPGP_ERROR_STATUS structure returned from libglobalplatform.
 * \param fmt Optional additional context format string (or NULL).
 */
void gpshell3_report_opgp_error(gpshell3_output_ctx_t *ctx, const char *code, OPGP_ERROR_STATUS status, const char *fmt, ...);
void gpshell3_report_opgp_error_va(gpshell3_output_ctx_t *ctx, const char *code, OPGP_ERROR_STATUS status, const char *fmt, va_list args);

/**
 * Emit an informational message (only in text mode).
 * In JSON mode, informational text is suppressed so stdout remains valid JSON.
 * \param ctx Output context.
 * \param fmt Format string.
 */
void gpshell3_output_message(gpshell3_output_ctx_t *ctx, const char *fmt, ...);
void gpshell3_output_message_va(gpshell3_output_ctx_t *ctx, const char *fmt, va_list args);

/**
 * Emit a warning message to err_stream in both text and JSON modes.
 * \param ctx Output context.
 * \param fmt Format string.
 */
void gpshell3_output_warning(gpshell3_output_ctx_t *ctx, const char *fmt, ...);

/**
 * Retrieve the current "result" JSON object or array.
 * Creates an empty object if one does not already exist.
 * \param ctx Output context.
 * \return Pointer to cJSON result object.
 */
cJSON *gpshell3_output_get_result(gpshell3_output_ctx_t *ctx);

/**
 * Replace the entire "result" field with a custom cJSON item (object or array).
 * Takes ownership of the provided cJSON item.
 * \param ctx Output context.
 * \param result cJSON item to set as result.
 * \return 0 on success, negative error code on failure.
 */
int gpshell3_output_set_result(gpshell3_output_ctx_t *ctx, cJSON *result);

/**
 * Add a string key/value pair to the result object.
 * \param ctx Output context.
 * \param key Property key.
 * \param value String value.
 * \return 0 on success, negative on error.
 */
int gpshell3_output_add_string(gpshell3_output_ctx_t *ctx, const char *key, const char *value);

/**
 * Add an integer key/value pair to the result object.
 * \param ctx Output context.
 * \param key Property key.
 * \param value Integer value.
 * \return 0 on success, negative on error.
 */
int gpshell3_output_add_int(gpshell3_output_ctx_t *ctx, const char *key, long long value);

/**
 * Add a boolean key/value pair to the result object.
 * \param ctx Output context.
 * \param key Property key.
 * \param value Boolean value.
 * \return 0 on success, negative on error.
 */
int gpshell3_output_add_bool(gpshell3_output_ctx_t *ctx, const char *key, bool value);

/**
 * Add a floating-point key/value pair to the result object.
 * \param ctx Output context.
 * \param key Property key.
 * \param value Floating-point value.
 * \return 0 on success, negative on error.
 */
int gpshell3_output_add_double(gpshell3_output_ctx_t *ctx, const char *key, double value);

/**
 * Add a binary buffer encoded as uppercase hex string to the result object.
 * \param ctx Output context.
 * \param key Property key.
 * \param bytes Raw byte buffer.
 * \param len Buffer length in bytes.
 * \return 0 on success, negative on error.
 */
int gpshell3_output_add_hex(gpshell3_output_ctx_t *ctx, const char *key, const unsigned char *bytes, size_t len);

/**
 * Add smart card status word (SW) to the result object.
 * \param ctx Output context.
 * \param sw 16-bit status word (e.g. 0x9000).
 * \return 0 on success, negative on error.
 */
int gpshell3_output_add_status_word(gpshell3_output_ctx_t *ctx, unsigned short sw);

/**
 * Add smart card status word components (SW1, SW2) to the result object.
 * \param ctx Output context.
 * \param sw1 Status word byte 1.
 * \param sw2 Status word byte 2.
 * \return 0 on success, negative on error.
 */
int gpshell3_output_add_sw(gpshell3_output_ctx_t *ctx, unsigned char sw1, unsigned char sw2);

/**
 * Add an array item to the result object. Takes ownership of array_item.
 * \param ctx Output context.
 * \param key Property key.
 * \param array_item cJSON array to attach.
 * \return 0 on success, negative on error.
 */
int gpshell3_output_add_array(gpshell3_output_ctx_t *ctx, const char *key, cJSON *array_item);

/**
 * Add a nested object item to the result object. Takes ownership of obj_item.
 * \param ctx Output context.
 * \param key Property key.
 * \param obj_item cJSON object to attach.
 * \return 0 on success, negative on error.
 */
int gpshell3_output_add_object(gpshell3_output_ctx_t *ctx, const char *key, cJSON *obj_item);

/**
 * Get or construct the top-level root JSON response object.
 * \param ctx Output context.
 * \return cJSON root object.
 */
cJSON *gpshell3_output_get_root(gpshell3_output_ctx_t *ctx);

/**
 * Render the JSON response into a freshly-allocated string.
 * Caller is responsible for freeing the returned string using free().
 * \param ctx Output context.
 * \param formatted If true, formats with whitespace/indentation; if false, compact.
 * \return Allocated JSON string or NULL on failure.
 */
char *gpshell3_output_render_string(gpshell3_output_ctx_t *ctx, bool formatted);

/**
 * Flush the output. In JSON mode, serializes and prints the final JSON payload
 * to out_stream followed by newline and flushes. In text mode, flushes streams.
 * \param ctx Output context.
 * \return 0 on success, negative on error.
 */
int gpshell3_output_flush(gpshell3_output_ctx_t *ctx);

/**
 * Convert byte buffer to an allocated uppercase hex string.
 * Caller must free the result using free().
 * \param bytes Raw byte buffer.
 * \param len Length in bytes.
 * \return Allocated string or NULL.
 */
char *gpshell3_bytes_to_hex(const unsigned char *bytes, size_t len);

/**
 * Create a cJSON string node containing uppercase hex encoding of bytes.
 * \param bytes Raw byte buffer.
 * \param len Length in bytes.
 * \return cJSON string node or NULL.
 */
cJSON *gpshell3_json_create_hex_string(const unsigned char *bytes, size_t len);

/**
 * Create a cJSON array of string nodes.
 * \param strings Array of C strings.
 * \param count Number of strings in array.
 * \return cJSON array node or NULL.
 */
cJSON *gpshell3_json_create_string_array(const char *const *strings, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* GPSHELL3_OUTPUT_H */
