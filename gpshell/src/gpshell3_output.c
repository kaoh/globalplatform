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
        if (cJSON_HasObjectItem(ctx->json_error, "operation")) {
            cJSON_ReplaceItemInObject(ctx->json_error, "operation", cJSON_CreateString(ctx->command));
        } else {
            cJSON_AddStringToObject(ctx->json_error, "operation", ctx->command);
        }
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

bool gpshell3_extract_status_word(DWORD errorCode, unsigned short *sw_out) {
    if ((errorCode & 0xFFF00000L) == 0x80200000L) {
        if (sw_out) {
            *sw_out = (unsigned short)(errorCode & 0xFFFF);
        }
        return true;
    }
    if ((errorCode >= 0x6000 && errorCode <= 0x6FFF) ||
        (errorCode >= 0x9000 && errorCode <= 0x9FFF)) {
        if (sw_out) {
            *sw_out = (unsigned short)(errorCode & 0xFFFF);
        }
        return true;
    }
    return false;
}

const char *gpshell3_sw_to_error_code(unsigned short sw) {
    switch (sw) {
        case 0x6982: return "AUTHENTICATION_REQUIRED";
        case 0x6A81: return "APPLET_NOT_SELECTABLE";
        case 0x6A82: return "NOT_FOUND";
        case 0x6A88: return "DATA_NOT_FOUND";
        case 0x6985: return "CONDITIONS_NOT_SATISFIED";
        case 0x6A80: return "WRONG_DATA";
        case 0x6A84: return "NOT_ENOUGH_MEMORY";
        case 0x6A86: return "INCORRECT_P1P2";
        case 0x6B00: return "WRONG_P1P2";
        case 0x6700: return "WRONG_LENGTH";
        case 0x6D00: return "INVALID_INS";
        case 0x6E00: return "WRONG_CLA";
        case 0x6881: return "CHANNEL_NOT_SUPPORTED";
        case 0x6882: return "SECURE_MESSAGING_NOT_SUPPORTED";
        case 0x6283: return "CARD_LOCKED";
        case 0x6300: return "AUTHENTICATION_FAILED";
        case 0x6581: return "MEMORY_FAILURE";
        case 0x6F74: return "ILLEGAL_PARAMETER";
        case 0x9484: return "ALGORITHM_NOT_SUPPORTED";
        case 0x9485: return "INVALID_KEY_CHECK_VALUE";
        default: return NULL;
    }
}

const char *gpshell3_sw_to_message(unsigned short sw) {
    switch (sw) {
        case 0x6982: return "The card requires an authenticated session.";
        case 0x6A81: return "Card is locked or selected application was not in a selectable state.";
        case 0x6A82: return "File or application not found.";
        case 0x6A88: return "Referenced data not found.";
        case 0x6985: return "Conditions of use not satisfied.";
        case 0x6A80: return "Incorrect parameters in command data.";
        case 0x6A84: return "Not enough memory space.";
        case 0x6A86: return "Incorrect parameters (P1, P2).";
        case 0x6B00: return "Wrong parameters (P1, P2).";
        case 0x6700: return "Wrong length.";
        case 0x6D00: return "Instruction code not supported or invalid.";
        case 0x6E00: return "Class not supported.";
        case 0x6881: return "Logical channel not supported or open.";
        case 0x6882: return "Secure messaging not supported.";
        case 0x6283: return "Selected file invalidated / Card life cycle is locked.";
        case 0x6300: return "Authentication of host cryptogram failed.";
        case 0x6581: return "Memory failure or EDC check failed.";
        case 0x6F74: return "Illegal parameter.";
        case 0x9484: return "Algorithm not supported.";
        case 0x9485: return "Invalid key check value.";
        default: return NULL;
    }
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
        if (ctx->command[0] != '\0') {
            cJSON_AddStringToObject(err_obj, "operation", ctx->command);
            cJSON_AddStringToObject(err_obj, "command", ctx->command);
        }
        cJSON_AddStringToObject(err_obj, "message", msg);

        if (cJSON_HasObjectItem(ctx->json_root, "error")) {
            cJSON_ReplaceItemInObject(ctx->json_root, "error", err_obj);
        } else {
            cJSON_AddItemToObject(ctx->json_root, "error", err_obj);
        }
        ctx->json_error = err_obj;
    }
}

void gpshell3_report_error_with_sw(gpshell3_output_ctx_t *ctx, const char *code, unsigned short sw, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    gpshell3_report_error_with_sw_va(ctx, code, sw, fmt, args);
    va_end(args);
}

void gpshell3_report_error_with_sw_va(gpshell3_output_ctx_t *ctx, const char *code, unsigned short sw, const char *fmt, va_list args) {
    OPGP_ERROR_STATUS status;
    const char *sw_msg = gpshell3_sw_to_message(sw);
    TCHAR tmsg[ERROR_MESSAGE_LENGTH];
#if defined(_WIN32) && defined(UNICODE)
    MultiByteToWideChar(CP_UTF8, 0, sw_msg ? sw_msg : "Card error", -1, tmsg, ERROR_MESSAGE_LENGTH);
#else
    strncpy(tmsg, sw_msg ? sw_msg : "Card error", ERROR_MESSAGE_LENGTH - 1);
    tmsg[ERROR_MESSAGE_LENGTH - 1] = '\0';
#endif
    OPGP_ERROR_CREATE_ERROR(status, (DWORD)(0x80200000L | (DWORD)sw), tmsg);
    gpshell3_report_opgp_error_va(ctx, code, status, fmt, args);
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

    unsigned short sw = 0;
    bool has_sw = gpshell3_extract_status_word(status.errorCode, &sw);
    char sw_str[8] = {0};
    if (has_sw) {
        snprintf(sw_str, sizeof(sw_str), "%04X", sw);
    }

    const char *effective_code = code;
    if (!effective_code || !*effective_code ||
        strcmp(effective_code, "CARD_COMMUNICATION_ERROR") == 0 ||
        strcmp(effective_code, "ERROR") == 0 ||
        strcmp(effective_code, "COMMAND_FAILED") == 0 ||
        strcmp(effective_code, "FAILED") == 0) {
        if (has_sw) {
            const char *mapped = gpshell3_sw_to_error_code(sw);
            if (mapped) {
                effective_code = mapped;
            } else {
                effective_code = "CARD_COMMUNICATION_ERROR";
            }
        } else {
            effective_code = (code && *code) ? code : "CARD_COMMUNICATION_ERROR";
        }
    }

    char opgp_msg[ERROR_MESSAGE_LENGTH * 2 + 1];
    opgp_tchar_to_utf8(status.errorMessage, opgp_msg, sizeof(opgp_msg));

    char custom_msg[512] = {0};
    if (fmt) {
        vsnprintf(custom_msg, sizeof(custom_msg), fmt, args);
    }

    char full_msg[2048];
    if (sw == 0x6982 && custom_msg[0] == '\0') {
        if (opgp_msg[0] == '\0' || strcmp(opgp_msg, "Security status not satisfied") == 0) {
            snprintf(full_msg, sizeof(full_msg), "The card requires an authenticated session.");
        } else {
            snprintf(full_msg, sizeof(full_msg), "%s. The card requires an authenticated session.", opgp_msg);
        }
    } else if (custom_msg[0] != '\0' && opgp_msg[0] != '\0') {
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
        cJSON_AddStringToObject(err_obj, "code", effective_code);
        if (ctx->command[0] != '\0') {
            cJSON_AddStringToObject(err_obj, "operation", ctx->command);
            cJSON_AddStringToObject(err_obj, "command", ctx->command);
        }
        if (has_sw) {
            cJSON_AddStringToObject(err_obj, "statusWord", sw_str);
        }
        cJSON_AddStringToObject(err_obj, "opgpErrorCode", hex_code);
        cJSON_AddStringToObject(err_obj, "message", full_msg);

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

void gpshell3_cplc_to_wire_bytes(const OPGP_CPLC *cplc, unsigned char out_bytes[42]) {
    if (!cplc || !out_bytes) return;
    out_bytes[0]  = (unsigned char)((cplc->icFabricator >> 8) & 0xFF);
    out_bytes[1]  = (unsigned char)(cplc->icFabricator & 0xFF);
    out_bytes[2]  = (unsigned char)((cplc->icType >> 8) & 0xFF);
    out_bytes[3]  = (unsigned char)(cplc->icType & 0xFF);
    out_bytes[4]  = (unsigned char)((cplc->operatingSystemId >> 8) & 0xFF);
    out_bytes[5]  = (unsigned char)(cplc->operatingSystemId & 0xFF);
    out_bytes[6]  = (unsigned char)((cplc->operatingSystemReleaseDate >> 8) & 0xFF);
    out_bytes[7]  = (unsigned char)(cplc->operatingSystemReleaseDate & 0xFF);
    out_bytes[8]  = (unsigned char)((cplc->operatingSystemReleaseLevel >> 8) & 0xFF);
    out_bytes[9]  = (unsigned char)(cplc->operatingSystemReleaseLevel & 0xFF);
    out_bytes[10] = (unsigned char)((cplc->icFabricationDate >> 8) & 0xFF);
    out_bytes[11] = (unsigned char)(cplc->icFabricationDate & 0xFF);
    out_bytes[12] = (unsigned char)((cplc->icSerialNumberHigh >> 8) & 0xFF);
    out_bytes[13] = (unsigned char)(cplc->icSerialNumberHigh & 0xFF);
    out_bytes[14] = (unsigned char)((cplc->icSerialNumberLow >> 8) & 0xFF);
    out_bytes[15] = (unsigned char)(cplc->icSerialNumberLow & 0xFF);
    out_bytes[16] = (unsigned char)((cplc->icBatchIdentifier >> 8) & 0xFF);
    out_bytes[17] = (unsigned char)(cplc->icBatchIdentifier & 0xFF);
    out_bytes[18] = (unsigned char)((cplc->icModuleFabricator >> 8) & 0xFF);
    out_bytes[19] = (unsigned char)(cplc->icModuleFabricator & 0xFF);
    out_bytes[20] = (unsigned char)((cplc->icModulePackagingDate >> 8) & 0xFF);
    out_bytes[21] = (unsigned char)(cplc->icModulePackagingDate & 0xFF);
    out_bytes[22] = (unsigned char)((cplc->iccManufacturer >> 8) & 0xFF);
    out_bytes[23] = (unsigned char)(cplc->iccManufacturer & 0xFF);
    out_bytes[24] = (unsigned char)((cplc->icEmbeddingDate >> 8) & 0xFF);
    out_bytes[25] = (unsigned char)(cplc->icEmbeddingDate & 0xFF);
    out_bytes[26] = (unsigned char)((cplc->icPrePersonalizer >> 8) & 0xFF);
    out_bytes[27] = (unsigned char)(cplc->icPrePersonalizer & 0xFF);
    out_bytes[28] = (unsigned char)((cplc->icPrePersonalizationEquipmentDate >> 8) & 0xFF);
    out_bytes[29] = (unsigned char)(cplc->icPrePersonalizationEquipmentDate & 0xFF);
    out_bytes[30] = (unsigned char)((cplc->icPrePersonalizationEquipmentId >> 24) & 0xFF);
    out_bytes[31] = (unsigned char)((cplc->icPrePersonalizationEquipmentId >> 16) & 0xFF);
    out_bytes[32] = (unsigned char)((cplc->icPrePersonalizationEquipmentId >> 8) & 0xFF);
    out_bytes[33] = (unsigned char)(cplc->icPrePersonalizationEquipmentId & 0xFF);
    out_bytes[34] = (unsigned char)((cplc->icPersonalizer >> 8) & 0xFF);
    out_bytes[35] = (unsigned char)(cplc->icPersonalizer & 0xFF);
    out_bytes[36] = (unsigned char)((cplc->icPersonalizationDate >> 8) & 0xFF);
    out_bytes[37] = (unsigned char)(cplc->icPersonalizationDate & 0xFF);
    out_bytes[38] = (unsigned char)((cplc->icPersonalizationEquipmentId >> 24) & 0xFF);
    out_bytes[39] = (unsigned char)((cplc->icPersonalizationEquipmentId >> 16) & 0xFF);
    out_bytes[40] = (unsigned char)((cplc->icPersonalizationEquipmentId >> 8) & 0xFF);
    out_bytes[41] = (unsigned char)(cplc->icPersonalizationEquipmentId & 0xFF);
}
