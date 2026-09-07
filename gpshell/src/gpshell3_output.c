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

#include "gpshell3_output.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

static void opgp_tchar_to_utf8(const TCHAR *src, char *dst, size_t dst_len) {
    if (!dst || dst_len == 0) {
        return;
    }
    dst[0] = '\0';
    if (!src) {
        return;
    }
#if defined(_WIN32) && defined(UNICODE)
    WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, (int)dst_len, NULL, NULL);
    dst[dst_len - 1] = '\0';
#else
    strncpy(dst, src, dst_len - 1);
    dst[dst_len - 1] = '\0';
#endif
}

void gpshell3_output_init(gpshell3_output_ctx_t *ctx, gpshell3_output_mode_t mode) {
    gpshell3_output_init_stream(ctx, mode, stdout, stderr);
}

void gpshell3_output_init_stream(gpshell3_output_ctx_t *ctx, gpshell3_output_mode_t mode, FILE *out_stream, FILE *err_stream) {
    if (!ctx) {
        return;
    }
    ctx->mode = mode;
    ctx->out_stream = out_stream ? out_stream : stdout;
    ctx->err_stream = err_stream ? err_stream : stderr;
    ctx->command[0] = '\0';
    ctx->has_error = false;
    ctx->json_root = NULL;
    ctx->json_result = NULL;
    ctx->json_error = NULL;

    if (mode == OUTPUT_FORMAT_JSON) {
        ctx->json_root = cJSON_CreateObject();
        cJSON_AddBoolToObject(ctx->json_root, "ok", true);
        ctx->json_result = cJSON_CreateObject();
        cJSON_AddItemToObject(ctx->json_root, "result", ctx->json_result);
    }
}

void gpshell3_output_set_command(gpshell3_output_ctx_t *ctx, const char *command) {
    if (!ctx) {
        return;
    }
    if (command && command[0] != '\0') {
        strncpy(ctx->command, command, sizeof(ctx->command) - 1);
        ctx->command[sizeof(ctx->command) - 1] = '\0';
    } else {
        ctx->command[0] = '\0';
    }

    if (ctx->json_root && !ctx->has_error) {
        if (ctx->command[0] != '\0') {
            if (cJSON_HasObjectItem(ctx->json_root, "command")) {
                cJSON_ReplaceItemInObject(ctx->json_root, "command", cJSON_CreateString(ctx->command));
            } else {
                cJSON_AddStringToObject(ctx->json_root, "command", ctx->command);
            }
        } else if (cJSON_HasObjectItem(ctx->json_root, "command")) {
            cJSON_DeleteItemFromObject(ctx->json_root, "command");
        }
    }

    if (ctx->json_error && ctx->command[0] != '\0') {
        if (cJSON_HasObjectItem(ctx->json_error, "command")) {
            cJSON_ReplaceItemInObject(ctx->json_error, "command", cJSON_CreateString(ctx->command));
        } else {
            cJSON_AddStringToObject(ctx->json_error, "command", ctx->command);
        }
    }
}

const char *gpshell3_output_get_command(const gpshell3_output_ctx_t *ctx) {
    return ctx ? ctx->command : "";
}

void gpshell3_output_reset(gpshell3_output_ctx_t *ctx) {
    if (!ctx) {
        return;
    }
    FILE *out = ctx->out_stream;
    FILE *err = ctx->err_stream;
    gpshell3_output_mode_t mode = ctx->mode;
    gpshell3_output_cleanup(ctx);
    gpshell3_output_init_stream(ctx, mode, out, err);
}

void gpshell3_output_cleanup(gpshell3_output_ctx_t *ctx) {
    if (!ctx) {
        return;
    }
    if (ctx->json_root) {
        cJSON_Delete(ctx->json_root);
        ctx->json_root = NULL;
    }
    ctx->json_result = NULL;
    ctx->json_error = NULL;
    ctx->has_error = false;
    ctx->command[0] = '\0';
}

bool gpshell3_output_has_error(const gpshell3_output_ctx_t *ctx) {
    return ctx ? ctx->has_error : false;
}

void gpshell3_report_error(gpshell3_output_ctx_t *ctx, const char *code, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    gpshell3_report_error_va(ctx, code, fmt, args);
    va_end(args);
}

void gpshell3_report_error_va(gpshell3_output_ctx_t *ctx, const char *code, const char *fmt, va_list args) {
    char msg[1024] = {0};
    if (fmt) {
        vsnprintf(msg, sizeof(msg), fmt, args);
    }

    if (!ctx) {
        fprintf(stderr, "Error: %s\n", msg);
        return;
    }

    ctx->has_error = true;

    if (ctx->mode == OUTPUT_FORMAT_TEXT) {
        if (ctx->command[0] != '\0') {
            fprintf(ctx->err_stream, "%s: %s\n", ctx->command, msg);
        } else {
            fprintf(ctx->err_stream, "Error: %s\n", msg);
        }
        fflush(ctx->err_stream);
    } else {
        if (!ctx->json_root) {
            ctx->json_root = cJSON_CreateObject();
        }

        if (cJSON_HasObjectItem(ctx->json_root, "ok")) {
            cJSON_ReplaceItemInObject(ctx->json_root, "ok", cJSON_CreateFalse());
        } else {
            cJSON_AddBoolToObject(ctx->json_root, "ok", false);
        }

        if (cJSON_HasObjectItem(ctx->json_root, "command")) {
            cJSON_DeleteItemFromObject(ctx->json_root, "command");
        }

        if (cJSON_HasObjectItem(ctx->json_root, "result")) {
            cJSON_DeleteItemFromObject(ctx->json_root, "result");
            ctx->json_result = NULL;
        }

        cJSON *err_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(err_obj, "code", (code && *code) ? code : "ERROR");
        cJSON_AddStringToObject(err_obj, "message", msg);
        if (ctx->command[0] != '\0') {
            cJSON_AddStringToObject(err_obj, "command", ctx->command);
        }

        if (cJSON_HasObjectItem(ctx->json_root, "error")) {
            cJSON_ReplaceItemInObject(ctx->json_root, "error", err_obj);
        } else {
            cJSON_AddItemToObject(ctx->json_root, "error", err_obj);
        }
        ctx->json_error = err_obj;
    }
}

void gpshell3_report_opgp_error(gpshell3_output_ctx_t *ctx, const char *code, OPGP_ERROR_STATUS status, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    gpshell3_report_opgp_error_va(ctx, code, status, fmt, args);
    va_end(args);
}

void gpshell3_report_opgp_error_va(gpshell3_output_ctx_t *ctx, const char *code, OPGP_ERROR_STATUS status, const char *fmt, va_list args) {
    char hex_code[32];
    snprintf(hex_code, sizeof(hex_code), "0x%08X", (unsigned int)status.errorCode);

    char opgp_msg[ERROR_MESSAGE_LENGTH * 2 + 1];
    opgp_tchar_to_utf8(status.errorMessage, opgp_msg, sizeof(opgp_msg));

    char custom_msg[512] = {0};
    if (fmt) {
        vsnprintf(custom_msg, sizeof(custom_msg), fmt, args);
    }

    char full_msg[2048];
    if (custom_msg[0] != '\0' && opgp_msg[0] != '\0') {
        snprintf(full_msg, sizeof(full_msg), "%s: %s", custom_msg, opgp_msg);
    } else if (custom_msg[0] != '\0') {
        snprintf(full_msg, sizeof(full_msg), "%s", custom_msg);
    } else if (opgp_msg[0] != '\0') {
        snprintf(full_msg, sizeof(full_msg), "%s", opgp_msg);
    } else {
        snprintf(full_msg, sizeof(full_msg), "Error %s", hex_code);
    }

    if (!ctx) {
        _ftprintf(stderr, _T("Error 0x%08X: %s\n"), (unsigned int)status.errorCode, status.errorMessage);
        return;
    }

    ctx->has_error = true;

    if (ctx->mode == OUTPUT_FORMAT_TEXT) {
        if (custom_msg[0] != '\0') {
            fprintf(ctx->err_stream, "%s: Error 0x%08X: %s\n", custom_msg, (unsigned int)status.errorCode, opgp_msg);
        } else {
            _ftprintf(ctx->err_stream, _T("Error 0x%08X: %s\n"), (unsigned int)status.errorCode, status.errorMessage);
        }
        fflush(ctx->err_stream);
    } else {
        if (!ctx->json_root) {
            ctx->json_root = cJSON_CreateObject();
        }

        if (cJSON_HasObjectItem(ctx->json_root, "ok")) {
            cJSON_ReplaceItemInObject(ctx->json_root, "ok", cJSON_CreateFalse());
        } else {
            cJSON_AddBoolToObject(ctx->json_root, "ok", false);
        }

        if (cJSON_HasObjectItem(ctx->json_root, "command")) {
            cJSON_DeleteItemFromObject(ctx->json_root, "command");
        }

        if (cJSON_HasObjectItem(ctx->json_root, "result")) {
            cJSON_DeleteItemFromObject(ctx->json_root, "result");
            ctx->json_result = NULL;
        }

        cJSON *err_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(err_obj, "code", (code && *code) ? code : "CARD_COMMUNICATION_ERROR");
        cJSON_AddStringToObject(err_obj, "opgpErrorCode", hex_code);
        cJSON_AddStringToObject(err_obj, "message", full_msg);
        if (ctx->command[0] != '\0') {
            cJSON_AddStringToObject(err_obj, "command", ctx->command);
        }

        if (cJSON_HasObjectItem(ctx->json_root, "error")) {
            cJSON_ReplaceItemInObject(ctx->json_root, "error", err_obj);
        } else {
            cJSON_AddItemToObject(ctx->json_root, "error", err_obj);
        }
        ctx->json_error = err_obj;
    }
}

void gpshell3_output_message(gpshell3_output_ctx_t *ctx, const char *fmt, ...) {
    if (!ctx || !fmt) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    gpshell3_output_message_va(ctx, fmt, args);
    va_end(args);
}

void gpshell3_output_message_va(gpshell3_output_ctx_t *ctx, const char *fmt, va_list args) {
    if (!ctx || !fmt) {
        return;
    }
    if (ctx->mode == OUTPUT_FORMAT_TEXT) {
        vfprintf(ctx->out_stream, fmt, args);
    }
}

void gpshell3_output_warning(gpshell3_output_ctx_t *ctx, const char *fmt, ...) {
    if (!fmt) {
        return;
    }
    FILE *err = (ctx && ctx->err_stream) ? ctx->err_stream : stderr;
    fprintf(err, "Warning: ");
    va_list args;
    va_start(args, fmt);
    vfprintf(err, fmt, args);
    va_end(args);
    fprintf(err, "\n");
    fflush(err);
}

cJSON *gpshell3_output_get_result(gpshell3_output_ctx_t *ctx) {
    if (!ctx) {
        return NULL;
    }
    if (ctx->json_result) {
        return ctx->json_result;
    }
    if (ctx->mode == OUTPUT_FORMAT_JSON) {
        if (!ctx->json_root) {
            ctx->json_root = cJSON_CreateObject();
            cJSON_AddBoolToObject(ctx->json_root, "ok", !ctx->has_error);
        }
        ctx->json_result = cJSON_CreateObject();
        cJSON_AddItemToObject(ctx->json_root, "result", ctx->json_result);
        return ctx->json_result;
    }
    return NULL;
}

int gpshell3_output_set_result(gpshell3_output_ctx_t *ctx, cJSON *result) {
    if (!ctx || !result) {
        if (result) {
            cJSON_Delete(result);
        }
        return -1;
    }
    if (ctx->mode != OUTPUT_FORMAT_JSON) {
        cJSON_Delete(result);
        return 0;
    }
    if (!ctx->json_root) {
        ctx->json_root = cJSON_CreateObject();
        cJSON_AddBoolToObject(ctx->json_root, "ok", !ctx->has_error);
    }
    if (cJSON_HasObjectItem(ctx->json_root, "result")) {
        cJSON_DeleteItemFromObject(ctx->json_root, "result");
    }
    cJSON_AddItemToObject(ctx->json_root, "result", result);
    ctx->json_result = result;
    return 0;
}

int gpshell3_output_add_string(gpshell3_output_ctx_t *ctx, const char *key, const char *value) {
    if (!ctx || !key) {
        return -1;
    }
    if (ctx->mode == OUTPUT_FORMAT_JSON) {
        cJSON *res = gpshell3_output_get_result(ctx);
        if (!res || !cJSON_IsObject(res)) {
            return -1;
        }
        if (value) {
            cJSON_AddStringToObject(res, key, value);
        } else {
            cJSON_AddNullToObject(res, key);
        }
    }
    return 0;
}

int gpshell3_output_add_int(gpshell3_output_ctx_t *ctx, const char *key, long long value) {
    if (!ctx || !key) {
        return -1;
    }
    if (ctx->mode == OUTPUT_FORMAT_JSON) {
        cJSON *res = gpshell3_output_get_result(ctx);
        if (!res || !cJSON_IsObject(res)) {
            return -1;
        }
        cJSON_AddNumberToObject(res, key, (double)value);
    }
    return 0;
}

int gpshell3_output_add_bool(gpshell3_output_ctx_t *ctx, const char *key, bool value) {
    if (!ctx || !key) {
        return -1;
    }
    if (ctx->mode == OUTPUT_FORMAT_JSON) {
        cJSON *res = gpshell3_output_get_result(ctx);
        if (!res || !cJSON_IsObject(res)) {
            return -1;
        }
        cJSON_AddBoolToObject(res, key, value);
    }
    return 0;
}

int gpshell3_output_add_double(gpshell3_output_ctx_t *ctx, const char *key, double value) {
    if (!ctx || !key) {
        return -1;
    }
    if (ctx->mode == OUTPUT_FORMAT_JSON) {
        cJSON *res = gpshell3_output_get_result(ctx);
        if (!res || !cJSON_IsObject(res)) {
            return -1;
        }
        cJSON_AddNumberToObject(res, key, value);
    }
    return 0;
}

int gpshell3_output_add_hex(gpshell3_output_ctx_t *ctx, const char *key, const unsigned char *bytes, size_t len) {
    if (!ctx || !key) {
        return -1;
    }
    if (ctx->mode == OUTPUT_FORMAT_JSON) {
        cJSON *res = gpshell3_output_get_result(ctx);
        if (!res || !cJSON_IsObject(res)) {
            return -1;
        }
        char *hex = gpshell3_bytes_to_hex(bytes, len);
        if (!hex) {
            return -1;
        }
        cJSON_AddStringToObject(res, key, hex);
        free(hex);
    }
    return 0;
}

int gpshell3_output_add_status_word(gpshell3_output_ctx_t *ctx, unsigned short sw) {
    if (!ctx) {
        return -1;
    }
    if (ctx->mode == OUTPUT_FORMAT_JSON) {
        cJSON *res = gpshell3_output_get_result(ctx);
        if (!res || !cJSON_IsObject(res)) {
            return -1;
        }
        char sw_hex[8];
        snprintf(sw_hex, sizeof(sw_hex), "%04X", (unsigned int)sw);
        cJSON_AddStringToObject(res, "sw", sw_hex);
    }
    return 0;
}

int gpshell3_output_add_sw(gpshell3_output_ctx_t *ctx, unsigned char sw1, unsigned char sw2) {
    return gpshell3_output_add_status_word(ctx, (unsigned short)(((unsigned short)sw1 << 8) | (unsigned short)sw2));
}

int gpshell3_output_add_array(gpshell3_output_ctx_t *ctx, const char *key, cJSON *array_item) {
    if (!ctx || !key || !array_item) {
        if (array_item) {
            cJSON_Delete(array_item);
        }
        return -1;
    }
    if (ctx->mode == OUTPUT_FORMAT_JSON) {
        cJSON *res = gpshell3_output_get_result(ctx);
        if (!res || !cJSON_IsObject(res)) {
            cJSON_Delete(array_item);
            return -1;
        }
        if (cJSON_HasObjectItem(res, key)) {
            cJSON_DeleteItemFromObject(res, key);
        }
        cJSON_AddItemToObject(res, key, array_item);
    } else {
        cJSON_Delete(array_item);
    }
    return 0;
}

int gpshell3_output_add_object(gpshell3_output_ctx_t *ctx, const char *key, cJSON *obj_item) {
    if (!ctx || !key || !obj_item) {
        if (obj_item) {
            cJSON_Delete(obj_item);
        }
        return -1;
    }
    if (ctx->mode == OUTPUT_FORMAT_JSON) {
        cJSON *res = gpshell3_output_get_result(ctx);
        if (!res || !cJSON_IsObject(res)) {
            cJSON_Delete(obj_item);
            return -1;
        }
        if (cJSON_HasObjectItem(res, key)) {
            cJSON_DeleteItemFromObject(res, key);
        }
        cJSON_AddItemToObject(res, key, obj_item);
    } else {
        cJSON_Delete(obj_item);
    }
    return 0;
}

cJSON *gpshell3_output_get_root(gpshell3_output_ctx_t *ctx) {
    if (!ctx) {
        return NULL;
    }
    if (ctx->mode == OUTPUT_FORMAT_JSON) {
        if (!ctx->json_root) {
            ctx->json_root = cJSON_CreateObject();
            cJSON_AddBoolToObject(ctx->json_root, "ok", !ctx->has_error);
        }
        if (!ctx->has_error && ctx->command[0] != '\0' && !cJSON_HasObjectItem(ctx->json_root, "command")) {
            cJSON_AddStringToObject(ctx->json_root, "command", ctx->command);
        }
        return ctx->json_root;
    }
    return NULL;
}

char *gpshell3_output_render_string(gpshell3_output_ctx_t *ctx, bool formatted) {
    if (!ctx) {
        return NULL;
    }
    cJSON *root = gpshell3_output_get_root(ctx);
    if (!root) {
        return NULL;
    }
    return formatted ? cJSON_Print(root) : cJSON_PrintUnformatted(root);
}

int gpshell3_output_flush(gpshell3_output_ctx_t *ctx) {
    if (!ctx) {
        return -1;
    }
    if (ctx->mode == OUTPUT_FORMAT_JSON) {
        char *str = gpshell3_output_render_string(ctx, true);
        if (str) {
            fprintf(ctx->out_stream, "%s\n", str);
            free(str);
        }
        fflush(ctx->out_stream);
    } else {
        fflush(ctx->out_stream);
        fflush(ctx->err_stream);
    }
    return 0;
}

char *gpshell3_bytes_to_hex(const unsigned char *bytes, size_t len) {
    if (len > 0 && !bytes) {
        return NULL;
    }
    char *out = (char *)malloc(len * 2 + 1);
    if (!out) {
        return NULL;
    }
    for (size_t i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02X", bytes[i]);
    }
    out[len * 2] = '\0';
    return out;
}

cJSON *gpshell3_json_create_hex_string(const unsigned char *bytes, size_t len) {
    char *hex = gpshell3_bytes_to_hex(bytes, len);
    if (!hex) {
        return NULL;
    }
    cJSON *item = cJSON_CreateString(hex);
    free(hex);
    return item;
}

cJSON *gpshell3_json_create_string_array(const char *const *strings, size_t count) {
    cJSON *arr = cJSON_CreateArray();
    if (!arr) {
        return NULL;
    }
    for (size_t i = 0; i < count; i++) {
        if (strings && strings[i]) {
            cJSON_AddItemToArray(arr, cJSON_CreateString(strings[i]));
        }
    }
    return arr;
}
