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
#include <sys/types.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/stat.h>

#include <globalplatform/globalplatform.h>
#include "util.h"
#include "gpshell3_commands.h"
#include "gpshell3_registry.h"
#include "gpshell3_output.h"

#ifdef _WIN32
#define strtok_r strtok_s
#define strdup _strdup
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define MAX_READERS_BUF 4096
#define MAX_PATH_BUF 4096

#ifdef _WIN32
static int setenv(const char *name, const char *value, int overwrite) {
    if (!overwrite && getenv(name) != NULL) {
        return 0;
    }
    return _putenv_s(name, value ? value : "") == 0 ? 0 : -1;
}
#endif

static int to_opgp_string(const char *src, TCHAR *dst, size_t dst_len) {
    if (!src || !dst || dst_len == 0) {
        return -1;
    }
#ifdef _WIN32
#ifdef UNICODE
    int needed = MultiByteToWideChar(CP_ACP, 0, src, -1, NULL, 0);
    if (needed <= 0 || (size_t)needed > dst_len) {
        return -1;
    }
    if (!MultiByteToWideChar(CP_ACP, 0, src, -1, dst, (int)dst_len)) {
        return -1;
    }
    return 0;
#else
    strncpy(dst, src, dst_len - 1);
    dst[dst_len - 1] = '\0';
    return 0;
#endif
#else
#ifdef UNICODE
    mbstowcs(dst, src, dst_len - 1);
    dst[dst_len - 1] = L'\0';
    return 0;
#else
    strncpy(dst, src, dst_len - 1);
    dst[dst_len - 1] = '\0';
    return 0;
#endif
#endif
}

static int status_ok(OPGP_ERROR_STATUS s, bool print_error) {
    if (s.errorStatus != OPGP_ERROR_STATUS_SUCCESS) {
        if (print_error) {
            _ftprintf(stderr, _T("Error 0x%08X: %s\n"), (unsigned int)s.errorCode, s.errorMessage);
        }
        return 0;
    }
    return 1;
}

// Remember the ISD AID that was actually selected during connection/authentication
// so subsequent operations (e.g., install) can reuse it without probing via GET DATA.
static unsigned char g_selected_isd[16];
static DWORD g_selected_isd_len = 0;
static BYTE g_current_scp = 0;
static BYTE g_current_scp_impl = 0;
static int g_current_scp_set = 0;

// Cleanup state tracking
static OPGP_CARD_CONTEXT *g_cleanup_ctx = NULL;
static OPGP_CARD_INFO *g_cleanup_info = NULL;
static int g_cleanup_card_connected = 0;

static void cleanup_and_exit(int exit_code) {
    if (g_cleanup_card_connected && g_cleanup_ctx && g_cleanup_info) {
        OPGP_card_disconnect(*g_cleanup_ctx, g_cleanup_info);
        g_cleanup_card_connected = 0;
    }
    if (g_cleanup_ctx) {
        OPGP_release_context(g_cleanup_ctx);
        g_cleanup_ctx = NULL;
    }
    exit(exit_code);
}

static int parse_int(const char *s) {
    if (s == NULL) return 0;
    return (int)strtol(s, NULL, 0);
}

static int hex_to_bytes(const char *hex, unsigned char *out, size_t *outlen) {
    size_t len = strlen(hex), i = 0, j = 0;
    if (len % 2 != 0) return -1;
    if (*outlen < len/2) return -2;
    for (; i < len; i += 2) {
        int v1, v2;
        char c1 = tolower((unsigned char)hex[i]);
        char c2 = tolower((unsigned char)hex[i+1]);
        v1 = (c1 >= '0' && c1 <= '9') ? c1 - '0' : (c1 >= 'a' && c1 <= 'f') ? c1 - 'a' + 10 : -1;
        v2 = (c2 >= '0' && c2 <= '9') ? c2 - '0' : (c2 >= 'a' && c2 <= 'f') ? c2 - 'a' + 10 : -1;
        if (v1 < 0 || v2 < 0) return -3;
        out[j++] = (unsigned char)((v1 << 4) | v2);
    }
    *outlen = j; return 0;
}

static int read_binary_file_into_buffer(const char *path, BYTE *out, size_t *outLen) {
    FILE *f;
    size_t readLen;
    int extra;

    if (!path || !out || !outLen || *outLen == 0) {
        return -1;
    }
    f = fopen(path, "rb");
    if (!f) {
        return -1;
    }
    readLen = fread(out, 1, *outLen, f);
    if (ferror(f)) {
        fclose(f);
        return -1;
    }
    extra = fgetc(f);
    if (extra != EOF) {
        fclose(f);
        return -2;
    }
    fclose(f);
    *outLen = readLen;
    return 0;
}

static int path_is_readable_file(const char *path) {
    FILE *f;

    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    f = fopen(path, "rb");
    if (f == NULL) {
        return 0;
    }
    fclose(f);
    return 1;
}

static void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i=0;i<len;i++) printf("%02X", buf[i]);
}

static void print_scp11_certificate_hex_field(const char *label, const BYTE *value, DWORD valueLength) {
    printf("%s : ", label);
    if (valueLength == 0 || value == NULL) {
        printf("(none)");
    } else {
        print_hex(value, valueLength);
    }
    printf("\n");
}

static void print_scp11_certificate(const GP211_SCP11_CERTIFICATE *certificate, size_t certificateIndex) {
    printf("CERT[%lu] : GP legacy (7F21)\n", (unsigned long)certificateIndex);
    print_scp11_certificate_hex_field("  serial-number", certificate->certificateSerialNumber,
                                      certificate->certificateSerialNumberLength);
    print_scp11_certificate_hex_field("  authority-identifier", certificate->authorityIdentifier,
                                      certificate->authorityIdentifierLength);
    print_scp11_certificate_hex_field("  subject-identifier", certificate->subjectIdentifier,
                                      certificate->subjectIdentifierLength);
    print_scp11_certificate_hex_field("  key-usage", certificate->keyUsage, certificate->keyUsageLength);
    if (certificate->effectiveDatePresent) {
        print_scp11_certificate_hex_field("  effective-date", certificate->effectiveDate,
                                          GP211_SCP11_CERTIFICATE_MAX_DATE_LENGTH);
    } else {
        print_scp11_certificate_hex_field("  effective-date", NULL, 0);
    }
    print_scp11_certificate_hex_field("  expiration-date", certificate->expirationDate,
                                      certificate->expirationDateLength);
    print_scp11_certificate_hex_field("  key-parameter-reference", certificate->keyParameterReference,
                                      certificate->keyParameterReferenceLength);
    print_scp11_certificate_hex_field("  public-key", certificate->publicKey,
                                      certificate->publicKeyLength);
    if (certificate->discretionaryDataTag != 0) {
        char label[48];
        snprintf(label, sizeof(label), "  discretionary-data-%04X", certificate->discretionaryDataTag);
        print_scp11_certificate_hex_field(label, certificate->discretionaryData,
                                          certificate->discretionaryDataLength);
    }
    if (certificate->authorizationsPresent) {
        print_scp11_certificate_hex_field("  authorizations", certificate->authorizations,
                                          certificate->authorizationsLength);
    }
    print_scp11_certificate_hex_field("  signature", certificate->signature,
                                      certificate->signatureLength);
}

typedef struct {
    unsigned short tag;
    const unsigned char *value;
    size_t length;
    size_t tlv_length;
} simple_tlv_view_t;

static int parse_simple_tlv_view(const unsigned char *buffer, size_t length, simple_tlv_view_t *tlv) {
    size_t offset = 0;
    unsigned char firstTagOctet;
    unsigned char firstLengthOctet;
    size_t numLengthOctets;
    size_t valueLength = 0;

    if (buffer == NULL || tlv == NULL || length < 2) {
        return -1;
    }

    firstTagOctet = buffer[offset++];
    if ((firstTagOctet & 0x1F) == 0x1F) {
        unsigned char secondTagOctet;
        if (length < offset + 1) {
            return -1;
        }
        secondTagOctet = buffer[offset++];
        if ((secondTagOctet & 0x80) != 0) {
            return -1;
        }
        tlv->tag = (unsigned short)((firstTagOctet << 8) | secondTagOctet);
    } else {
        tlv->tag = firstTagOctet;
    }

    if (length < offset + 1) {
        return -1;
    }
    firstLengthOctet = buffer[offset++];
    if ((firstLengthOctet & 0x80) != 0) {
        numLengthOctets = (size_t)(firstLengthOctet & 0x7F);
        if (numLengthOctets == 0 || numLengthOctets > 2 || length < offset + numLengthOctets) {
            return -1;
        }
        for (size_t i = 0; i < numLengthOctets; i++) {
            valueLength = (valueLength << 8) | buffer[offset++];
        }
    } else {
        valueLength = firstLengthOctet;
    }

    if (length < offset + valueLength) {
        return -1;
    }

    tlv->value = buffer + offset;
    tlv->length = valueLength;
    tlv->tlv_length = offset + valueLength;
    return 0;
}

static void scp_impl_to_hex(const GP211_CARD_RECOGNITION_DATA *data, DWORD index, char *out, size_t outlen) {
    size_t pos = 0;
    BYTE implLength = 0;

    if (out == NULL || outlen == 0 || data == NULL) return;
    out[0] = '\0';

    implLength = data->scpImplOidBytesLength[index];
    if (implLength > 0) {
        for (BYTE j = 0; j < implLength && pos + 2 < outlen; j++) {
            int written = snprintf(out + pos, outlen - pos, "%02X", data->scpImplOidBytes[index][j]);
            if (written < 0) {
                out[pos] = '\0';
                return;
            }
            if ((size_t)written >= outlen - pos) {
                pos = outlen - 1;
                out[pos] = '\0';
                return;
            }
            pos += (size_t)written;
        }
        return;
    }

    snprintf(out, outlen, "%02X", data->scpImpl[index]);
}

static void append_csv_token(char *out, size_t outlen, const char *token) {
    size_t used = 0;
    if (!out || outlen == 0 || !token || token[0] == '\0') return;
    used = strlen(out);
    if (used + 1 >= outlen) return;

    if (used > 0) {
        if (used + 2 >= outlen) return;
        out[used++] = ',';
        out[used++] = ' ';
    }

    for (const char *p = token; *p && used + 1 < outlen; ++p) {
        out[used++] = *p;
    }
    out[used] = '\0';
}

static void append_scpi_unknown_bits(char *out, size_t outlen, BYTE bits) {
    char buf[16];
    if (bits == 0) return;
    snprintf(buf, sizeof(buf), "rfu=0x%02X", bits);
    append_csv_token(out, outlen, buf);
}

static size_t scp_impl_to_bytes(const GP211_CARD_RECOGNITION_DATA *data, DWORD index, BYTE *out, size_t outlen) {
    size_t copyLen = 0;
    BYTE implLength = 0;
    if (!data || !out || outlen == 0) return 0;

    implLength = data->scpImplOidBytesLength[index];
    if (implLength == 0) {
        out[0] = data->scpImpl[index];
        return 1;
    }

    copyLen = (size_t)implLength;
    if (copyLen > outlen) copyLen = outlen;
    memcpy(out, data->scpImplOidBytes[index], copyLen);
    return copyLen;
}

static void scpi_scp02_to_string(const BYTE *impl, size_t implLen, char *out, size_t outlen) {
    BYTE i = 0;
    BYTE mode = 0;
    BYTE knownMask = 0;
    if (!out || outlen == 0) return;
    out[0] = '\0';

    if (!impl || implLen != 1) {
        snprintf(out, outlen, "unexpected-length=%u", (unsigned int)implLen);
        return;
    }

    i = impl[0];
    mode = (BYTE)(i & GP211_SCP02_SCPI_MODE_MASK);

    switch (mode) {
        case GP211_SCP02_SCPI_MODE_EXPLICIT:
            append_csv_token(out, outlen, "explicit-init");
            append_csv_token(out, outlen, "cmac=modified-apdu");
            append_csv_token(out, outlen, "icv=zero");
            break;
        case GP211_SCP02_SCPI_MODE_IMPLICIT:
            append_csv_token(out, outlen, "implicit-init");
            append_csv_token(out, outlen, "cmac=unmodified-apdu");
            append_csv_token(out, outlen, "icv=mac(aid)");
            break;
        default: {
            char modeBuf[16];
            snprintf(modeBuf, sizeof(modeBuf), "mode=0x%02X", mode);
            append_csv_token(out, outlen, modeBuf);
            break;
        }
    }

    append_csv_token(out, outlen,
        (i & GP211_SCP02_SCPI_CMAC_ICV_ENCRYPTION) ? "cmac-icv-encrypted" : "cmac-icv-plain");
    append_csv_token(out, outlen,
        (i & GP211_SCP02_SCPI_PSEUDO_RANDOM_CARD_CHALLENGE) ? "challenge=pseudo-random" : "challenge=unspecified");
    append_csv_token(out, outlen,
        (i & GP211_SCP02_SCPI_THREE_KEYS) ? "keys=3-static" : "keys=1-base");

    knownMask = (BYTE)(GP211_SCP02_SCPI_THREE_KEYS | GP211_SCP02_SCPI_MODE_MASK
        | GP211_SCP02_SCPI_CMAC_ICV_ENCRYPTION | GP211_SCP02_SCPI_PSEUDO_RANDOM_CARD_CHALLENGE);
    append_scpi_unknown_bits(out, outlen, (BYTE)(i & (BYTE)~knownMask));
}

static void scpi_scp03_to_string(const BYTE *impl, size_t implLen, char *out, size_t outlen) {
    BYTE i = 0;
    BYTE response = 0;
    BYTE knownMask = 0;
    if (!out || outlen == 0) return;
    out[0] = '\0';

    if (!impl || implLen != 1) {
        snprintf(out, outlen, "unexpected-length=%u", (unsigned int)implLen);
        return;
    }

    i = impl[0];
    response = (BYTE)(i & GP211_SCP03_SCPI_RESPONSE_MASK);

    append_csv_token(out, outlen,
        (i & GP211_SCP03_SCPI_PSEUDO_RANDOM_CARD_CHALLENGE) ? "challenge=pseudo-random" : "challenge=random");

    switch (response) {
        case GP211_SCP03_SCPI_RESPONSE_NONE:
            append_csv_token(out, outlen, "response=no-rmac/no-renc");
            break;
        case GP211_SCP03_SCPI_RESPONSE_R_MAC:
            append_csv_token(out, outlen, "response=rmac");
            break;
        case GP211_SCP03_SCPI_RESPONSE_R_ENC_R_MAC:
            append_csv_token(out, outlen, "response=rmac+renc");
            break;
        default: {
            char modeBuf[24];
            snprintf(modeBuf, sizeof(modeBuf), "response=0x%02X", response);
            append_csv_token(out, outlen, modeBuf);
            break;
        }
    }

    knownMask = (BYTE)(GP211_SCP03_SCPI_PSEUDO_RANDOM_CARD_CHALLENGE | GP211_SCP03_SCPI_RESPONSE_MASK);
    append_scpi_unknown_bits(out, outlen, (BYTE)(i & (BYTE)~knownMask));
}

static void scpi_scp11_to_string(const BYTE *impl, size_t implLen, char *out, size_t outlen) {
    BYTE b1 = 0;
    if (!out || outlen == 0) return;
    out[0] = '\0';

    if (!impl || implLen == 0) {
        snprintf(out, outlen, "unexpected-length=0");
        return;
    }

    b1 = impl[0];

    if ((b1 & GP211_SCP11_SCPI_B1_SCP11A_SUPPORTED) != 0) append_csv_token(out, outlen, "scp11a");
    if ((b1 & GP211_SCP11_SCPI_B1_SCP11B_SUPPORTED) != 0) append_csv_token(out, outlen, "scp11b");
    if ((b1 & GP211_SCP11_SCPI_B1_SCP11C_SUPPORTED) != 0) append_csv_token(out, outlen, "scp11c");

    append_csv_token(out, outlen,
        (b1 & GP211_SCP11_SCPI_B1_S16_MODE) ? "sm=s16" : "sm=s8");

    if ((b1 & GP211_SCP11_SCPI_B1_SCP11C_AUTH_BF20) != 0) append_csv_token(out, outlen, "scp11c-bf20-auth");
    if ((b1 & GP211_SCP11_SCPI_B1_CERT_CHAIN_SUPPORTED) != 0) append_csv_token(out, outlen, "cert-chain");
    if ((b1 & GP211_SCP11_SCPI_B1_SD_PERSISTENT_PK_OCE_ECKA) != 0) append_csv_token(out, outlen, "sd-stores-pk.oce.ecka");

    if ((b1 & GP211_SCP11_SCPI_B1_SECOND_BYTE_PRESENT) != 0) {
        if (implLen >= 2) {
            BYTE b2 = impl[1];
            BYTE knownMask = (BYTE)(GP211_SCP11_SCPI_B2_GP_LEGACY_CERT_NOT_SUPPORTED
                | GP211_SCP11_SCPI_B2_X509_CERT_SUPPORTED | GP211_SCP11_SCPI_B2_SCP11A_AUTH_BF20);
            if ((b2 & GP211_SCP11_SCPI_B2_SCP11A_AUTH_BF20) != 0) append_csv_token(out, outlen, "scp11a-bf20-auth");
            if ((b2 & GP211_SCP11_SCPI_B2_X509_CERT_SUPPORTED) != 0) append_csv_token(out, outlen, "x509-cert");
            if ((b2 & GP211_SCP11_SCPI_B2_GP_LEGACY_CERT_NOT_SUPPORTED) != 0) append_csv_token(out, outlen, "no-gp-legacy-cert");
            append_scpi_unknown_bits(out, outlen, (BYTE)(b2 & (BYTE)~knownMask));

            if (implLen > 2) {
                char extraBuf[24];
                snprintf(extraBuf, sizeof(extraBuf), "extra-bytes=%u", (unsigned int)(implLen - 2));
                append_csv_token(out, outlen, extraBuf);
            }
        } else {
            append_csv_token(out, outlen, "byte2-missing");
        }
    } else if (implLen >= 2) {
        append_csv_token(out, outlen, "byte2-present-without-flag");
    }
}

static void scpi_to_string(BYTE scp, const BYTE *impl, size_t implLen, char *out, size_t outlen) {
    if (!out || outlen == 0) return;
    out[0] = '\0';

    switch (scp) {
        case GP211_SCP02:
            scpi_scp02_to_string(impl, implLen, out, outlen);
            break;
        case GP211_SCP03:
            scpi_scp03_to_string(impl, implLen, out, outlen);
            break;
        case GP211_SCP11:
            scpi_scp11_to_string(impl, implLen, out, outlen);
            break;
        default:
            break;
    }
}

static void print_aid(const OPGP_AID *aid) { print_hex(aid->AID, aid->AIDLength); }

static int cplc_date_to_dmy(const BYTE *data, int *day, int *month, int *year) {
    int y = (data[0] >> 4) & 0x0F;
    int d1 = data[0] & 0x0F;
    int d2 = (data[1] >> 4) & 0x0F;
    int d3 = data[1] & 0x0F;
    if (data[0] == 0x00 && data[1] == 0x00) return 0;
    if (y > 9 || d1 > 9 || d2 > 9 || d3 > 9) return 0;
    {
        int day_of_year = d1 * 100 + d2 * 10 + d3;
        int y_full = 2020 + y;
        int leap = (y_full % 4 == 0 && (y_full % 100 != 0 || y_full % 400 == 0));
        int days_in_month[12] = {31, 28 + leap, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        int max_days = leap ? 366 : 365;
        int m = 0;
        if (day_of_year <= 0 || day_of_year > max_days) return 0;
        while (m < 12 && day_of_year > days_in_month[m]) {
            day_of_year -= days_in_month[m];
            m++;
        }
        if (m >= 12) return 0;
        *day = day_of_year;
        *month = m + 1;
        *year = y_full;
        return 1;
    }
}

static void print_cplc_date_field_ushort(const char *label, USHORT data) {
    int day = 0, month = 0, year = 0;
    BYTE date_bytes[2] = { (BYTE)((data >> 8) & 0xFF), (BYTE)(data & 0xFF) };
    printf("%s : ", label);
    if (cplc_date_to_dmy(date_bytes, &day, &month, &year)) {
        printf("%d.%d.%d", day, month, year);
    } else {
        printf("unknown");
    }
    printf("\n");
}

static void print_card_data_hex_field(const char *label, const BYTE *data, size_t len) {
    printf("%s : ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    if (len == 0) {
        printf("(none)");
    }
    printf("\n");
}

static void print_card_data_oid_field(const char *label, const char *oid, DWORD oid_len) {
    printf("%s OID : ", label);
    if (oid_len > 0 && oid != NULL && oid[0] != '\0') {
        printf("%s", oid);
    } else {
        printf("(none)");
    }
    printf("\n");
}

static void print_capability_hex_field(const char *label, const BYTE *data, size_t len) {
    if (len == 0 || data == NULL) {
        return;
    }
    printf("%s : ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

static void print_capability_scpi_csv(const char *label, const BYTE *data, size_t len) {
    if (len == 0 || data == NULL) return;
    printf("%s : ", label);
    for (size_t i = 0; i < len; i++) {
        if (i) printf(", ");
        printf("i=%02X", data[i]);
    }
    printf("\n");
}

static void print_capability_hex_bytes_csv(const char *label, const BYTE *data, size_t len) {
    if (len == 0 || data == NULL) return;
    printf("%s : ", label);
    for (size_t i = 0; i < len; i++) {
        if (i) printf(", ");
        printf("0x%02X", data[i]);
    }
    printf("\n");
}

static DWORD gp211_privileges_3bytes_to_dword(const BYTE b[3]) {
    return ((DWORD)b[0] << 16) | ((DWORD)b[1] << 8) | (DWORD)b[2];
}

static const char *gp211_hash_to_string(BYTE hashId) {
    switch (hashId) {
        case GP211_HASH_SHA1: return "sha1";
        case GP211_HASH_SHA256: return "sha256";
        case GP211_HASH_SHA384: return "sha384";
        case GP211_HASH_SHA512: return "sha512";
        case GP211_HASH_SM3: return "sm3";
        default: return NULL;
    }
}

static void gp211_lfdbh_algorithms_to_string(const BYTE *algs, DWORD algsLen, char *out, size_t outlen) {
    if (!out || outlen == 0) return;
    out[0] = '\0';
    size_t used = 0;
    int first = 1;

    for (DWORD i = 0; i < algsLen; i++) {
        const char *name = gp211_hash_to_string(algs[i]);
        char unknown[16];

        if (!name) {
            snprintf(unknown, sizeof(unknown), "0x%02X", algs[i]);
            name = unknown;
        }

        if (!first) {
            const char *sep = ", ";
            for (const char *p = sep; *p && used + 1 < outlen; ++p) out[used++] = *p;
        }
        first = 0;

        for (const char *p = name; *p && used + 1 < outlen; ++p) out[used++] = *p;
        out[used] = '\0';
    }

    if (first) snprintf(out, outlen, "none");
}

static void gp211_lfdb_encryption_to_string(BYTE suites, char *out, size_t outlen) {
    if (!out || outlen == 0) return;
    out[0] = '\0';
    size_t used = 0;
    int first = 1;

    struct { BYTE bit; const char *name; } map[] = {
        { GP211_LFDB_ENCRYPTION_3DES_16B_KEY, "3des" },
        { GP211_LFDB_ENCRYPTION_AES_128, "aes128" },
        { GP211_LFDB_ENCRYPTION_AES_192, "aes192" },
        { GP211_LFDB_ENCRYPTION_AES_256, "aes256" },
        { GP211_LFDB_ENCRYPTION_SM4, "sm4" },
        { GP211_LFDB_ENCRYPTION_ICV_SUPPORTED, "icv" },
    };

    for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
        if ((suites & map[i].bit) == 0) continue;

        if (!first) {
            const char *sep = ", ";
            for (const char *p = sep; *p && used + 1 < outlen; ++p) out[used++] = *p;
        }
        first = 0;

        for (const char *p = map[i].name; *p && used + 1 < outlen; ++p) out[used++] = *p;
        out[used] = '\0';
    }

    if (first) snprintf(out, outlen, "none");
}

static const char *gp211_elf_upgrade_to_string(BYTE v) {
    switch (v) {
        case GP211_ELF_UPGRADE_SINGLE: return "single";
        case GP211_ELF_UPGRADE_MULTI: return "multi";
        default: return NULL;
    }
}

static void gp211_scp_supported_key_sizes_to_string(BYTE sizes, char *out, size_t outlen) {
    if (!out || outlen == 0) return;
    out[0] = '\0';
    size_t used = 0;
    int first = 1;

    struct { BYTE bit; const char *name; } map[] = {
        { GP211_SCP_SUPPORTED_KEY_SIZE_128, "128" },
        { GP211_SCP_SUPPORTED_KEY_SIZE_192, "192" },
        { GP211_SCP_SUPPORTED_KEY_SIZE_256, "256" },
    };

    for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
        if ((sizes & map[i].bit) == 0) continue;

        if (!first) {
            const char *sep = ", ";
            for (const char *p = sep; *p && used + 1 < outlen; ++p) out[used++] = *p;
        }
        first = 0;

        for (const char *p = map[i].name; *p && used + 1 < outlen; ++p) out[used++] = *p;
        out[used] = '\0';
    }

    if (first) snprintf(out, outlen, "none");
}

static void gp211_signature_cs_to_string(USHORT suites, char *out, size_t outlen) {
    if (!out || outlen == 0) return;
    out[0] = '\0';
    size_t used = 0;
    int first = 1;

    struct { USHORT bit; const char *name; } map[] = {
        { GP211_SIGNATURE_CS_RSA_1024_SHA1, "rsa1024-sha1" },
        { GP211_SIGNATURE_CS_RSA_PSS_SHA256, "rsa-pss-sha256" },
        { GP211_SIGNATURE_CS_DES_MAC_16B, "des-mac-16b" },
        { GP211_SIGNATURE_CS_CMAC_AES_128, "cmac-aes128" },
        { GP211_SIGNATURE_CS_CMAC_AES_192, "cmac-aes192" },
        { GP211_SIGNATURE_CS_CMAC_AES_256, "cmac-aes256" },
        { GP211_SIGNATURE_CS_ECDSA_256_SHA256, "ecdsa256-sha256" },
        { GP211_SIGNATURE_CS_ECDSA_384_SHA384, "ecdsa384-sha384" },

        { GP211_SIGNATURE_CS_ECDSA_512_SHA512, "ecdsa512-sha512" },
        { GP211_SIGNATURE_CS_ECDSA_521_SHA512, "ecdsa521-sha512" },
        { GP211_SIGNATURE_CS_SM2, "sm2" },
    };

    USHORT remaining = suites;

    for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
        if ((suites & map[i].bit) == 0) continue;

        remaining = (USHORT)(remaining & (USHORT)~map[i].bit);

        if (!first) {
            const char *sep = ", ";
            for (const char *p = sep; *p && used + 1 < outlen; ++p) out[used++] = *p;
        }
        first = 0;

        for (const char *p = map[i].name; *p && used + 1 < outlen; ++p) out[used++] = *p;
        out[used] = '\0';
    }

    if (first) {
        snprintf(out, outlen, "none");
        return;
    }

    if (remaining) {
        char unk[32];
        snprintf(unk, sizeof(unk), "0x%04X", (unsigned int)remaining);

        const char *sep = ", ";
        for (const char *p = sep; *p && used + 1 < outlen; ++p) out[used++] = *p;
        for (const char *p = unk; *p && used + 1 < outlen; ++p) out[used++] = *p;
        out[used] = '\0';
    }
}

static BYTE sec_level_auto(BYTE proto, BYTE scpImpl) {
    if (proto == GP211_SCP03) {
        BYTE responseMode = (BYTE)(scpImpl & GP211_SCP03_SCPI_RESPONSE_MASK);
        if (responseMode == GP211_SCP03_SCPI_RESPONSE_R_ENC_R_MAC) {
            return GP211_SCP03_SECURITY_LEVEL_C_DEC_R_ENC_C_MAC_R_MAC;
        }
        if (responseMode == GP211_SCP03_SCPI_RESPONSE_R_MAC) {
            return GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC;
        }
        return GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC;
    }
    return GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC;
}

static BYTE sec_level_from_option(BYTE proto, BYTE scpImpl, const char *opt) {
    if (!opt || strcmp(opt, "auto") == 0) {
        return sec_level_auto(proto, scpImpl);
    }
    if (strcmp(opt, "mac+enc") == 0) {
        return (proto == GP211_SCP03) ? GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC : GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC;
    }
    if (strcmp(opt, "mac") == 0) {
        return (proto == GP211_SCP03) ? GP211_SCP03_SECURITY_LEVEL_C_MAC : GP211_SCP02_SECURITY_LEVEL_C_MAC;
    }
    if (strcmp(opt, "mac+enc+rmac") == 0) {
        if (proto == GP211_SCP03) {
            BYTE responseMode = (BYTE)(scpImpl & GP211_SCP03_SCPI_RESPONSE_MASK);
            if (responseMode == GP211_SCP03_SCPI_RESPONSE_R_MAC) {
                return GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC;
            }
            return GP211_SCP03_SECURITY_LEVEL_C_DEC_R_ENC_C_MAC_R_MAC;
        }
        return GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC;
    }
    return sec_level_auto(proto, scpImpl);
}

// Parse comma-separated privilege names into a DWORD privilege bitfield
// Supports all GP211_APPLICATION_PRIVILEGES enum values (3 bytes)
static int parse_privileges(const char *list, DWORD *out)
{
    if (!list) { *out = 0; return 0; }

    // Map of privilege names to GP211_APPLICATION_PRIVILEGES enum values
    struct { const char *name; DWORD value; } priv_map[] = {
        { "sd", GP211_SECURITY_DOMAIN },
        { "security-domain", GP211_SECURITY_DOMAIN },
        { "dap-verif", GP211_DAP_VERIFICATION },
        { "dap", GP211_DAP_VERIFICATION },
        { "delegated-mgmt", GP211_DELEGATED_MANAGEMENT },
        { "dm", GP211_DELEGATED_MANAGEMENT },
        { "cm-lock", GP211_CARD_MANAGER_LOCK_PRIVILEGE },
        { "cm-terminate", GP211_CARD_MANAGER_TERMINATE_PRIVILEGE },
        { "default-selected", GP211_DEFAULT_SELECTED_CARD_RESET_PRIVILEGE },
        { "default", GP211_DEFAULT_SELECTED_CARD_RESET_PRIVILEGE },
        { "card-reset", GP211_DEFAULT_SELECTED_CARD_RESET_PRIVILEGE },
        { "pin-change", GP211_PIN_CHANGE_PRIVILEGE },
        { "pin", GP211_PIN_CHANGE_PRIVILEGE },
        { "mandated-dap", GP211_MANDATED_DAP_VERIFICATION },
        { "mandated-dap-verif", GP211_MANDATED_DAP_VERIFICATION },

        { "trusted-path", GP211_TRUSTED_PATH },
        { "authorized-mgmt", GP211_AUTHORIZED_MANAGEMENT },
        { "token-verif", GP211_TOKEN_VERIFICATION },
        { "token", GP211_TOKEN_VERIFICATION },
        { "global-delete", GP211_GLOBAL_DELETE },
        { "global-lock", GP211_GLOBAL_LOCK },
        { "global-registry", GP211_GLOBAL_REGISTRY },
        { "final-application", GP211_FINAL_APPLICATION },
        { "final-app", GP211_FINAL_APPLICATION },
        { "global-service", GP211_GLOBAL_SERVICE },

        { "receipt-generation", GP211_RECEIPT_GENERATION },
        { "receipt", GP211_RECEIPT_GENERATION },
        { "ciphered-load-file-data-block", GP211_CIPHERED_LOAD_FILE_DATA_BLOCK },
        { "ciphered-load", GP211_CIPHERED_LOAD_FILE_DATA_BLOCK },
        { "contactless-activation", GP211_CONTACTLESS_ACTIVATION },
        { "contactless-self-activation", GP211_CONTACTLESS_SELF_ACTIVATION },
    };

    DWORD p = 0;
    char buf[512];
    strncpy(buf, list, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';

    char *save = NULL;
    char *tok = strtok_r(buf, ",", &save);
    while (tok) {
        // Trim whitespace
        while (*tok == ' ' || *tok == '\t') tok++;
        char *end = tok + strlen(tok) - 1;
        while (end > tok && (*end == ' ' || *end == '\t')) *end-- = '\0';

        // Normalize to lowercase
        for (char *c = tok; *c; ++c) {
            *c = (char)tolower((unsigned char)*c);
        }

        // Look up privilege
        int found = 0;
        for (size_t i = 0; i < sizeof(priv_map)/sizeof(priv_map[0]); ++i) {
            if (!strcmp(tok, priv_map[i].name)) {
                p |= priv_map[i].value;
                found = 1;
                break;
            }
        }

        if (!found) {
            fprintf(stderr, "Unknown privilege '%s'\n", tok);
            fprintf(stderr, "Valid privileges: sd, dap-verif, delegated-mgmt, cm-lock, cm-terminate,\n");
            fprintf(stderr, "  default-selected, pin-change, mandated-dap, trusted-path, authorized-mgmt,\n");
            fprintf(stderr, "  token-verif, global-delete, global-lock, global-registry, final-application,\n");
            fprintf(stderr, "  global-service, receipt-generation, ciphered-load-file-data-block,\n");
            fprintf(stderr, "  contactless-activation, contactless-self-activation\n");
            return -1;
        }

        tok = strtok_r(NULL, ",", &save);
    }

    *out = p;
    return 0;
}

static int parse_sd_accept_list(const char *list, BYTE *out) {
    if (!list || !out) return -1;
    char buf[128];
    strncpy(buf, list, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    BYTE val = 0;
    int have = 0;
    char *save = NULL;
    char *tok = strtok_r(buf, ",", &save);
    while (tok) {
        while (isspace((unsigned char)*tok)) tok++;
        char *end = tok + strlen(tok);
        while (end > tok && isspace((unsigned char)end[-1])) { end--; }
        *end = '\0';
        for (char *c = tok; *c; ++c) *c = (char)tolower((unsigned char)*c);

        if (!strcmp(tok, "none")) {
            // no bits set
            have = 1;
        } else if (!strcmp(tok, "an-am")) {
            val |= GP211_SD_ACCEPT_ANCESTOR_AM;
            have = 1;
        } else if (!strcmp(tok, "am")) {
            val |= GP211_SD_ACCEPT_HIERARCHY_AM;
            have = 1;
        } else if (!strcmp(tok, "isd")) {
            val |= GP211_SD_ACCEPT_ISD;
            have = 1;
        } else if (!strcmp(tok, "an-am-dm")) {
            val |= GP211_SD_ACCEPT_DM_UNDER_ANCESTOR_AM;
            have = 1;
        } else if (!strcmp(tok, "all-am")) {
            val |= GP211_SD_ACCEPT_ALL_AM;
            have = 1;
        } else if (*tok != '\0') {
            fprintf(stderr, "install-sd: unknown accept token '%s'\n", tok);
            return -1;
        }
        tok = strtok_r(NULL, ",", &save);
    }
    if (!have) {
        fprintf(stderr, "install-sd: accept list is empty\n");
        return -1;
    }
    *out = val;
    return 0;
}

static int aid_matches_hex(const OPGP_AID *aid, const char *hex) {
    if (!aid || !hex) return 0;
    BYTE buf[16]; size_t len = sizeof(buf);
    if (hex_to_bytes(hex, buf, &len) != 0) return 0;
    if (aid->AIDLength != len) return 0;
    return memcmp(aid->AID, buf, len) == 0;
}

static int find_default_load_file(const GP211_APPLICATION_DATA *lfs, DWORD lfs_len, BYTE *out, size_t *out_len) {
    const char *candidates[] = { "A0000000035350", "A0000001515350" };
    for (size_t c = 0; c < ARRAY_SIZE(candidates); ++c) {
        for (DWORD i = 0; i < lfs_len; ++i) {
            if (aid_matches_hex(&lfs[i].aid, candidates[c])) {
                size_t len = lfs[i].aid.AIDLength;
                if (len > *out_len) return 0;
                memcpy(out, lfs[i].aid.AID, len);
                *out_len = len;
                return 1;
            }
        }
    }
    return 0;
}

static int find_default_module(const GP211_EXECUTABLE_MODULES_DATA *mods, DWORD mods_len, BYTE *out, size_t *out_len) {
    const char *candidates[] = { "A000000003535041", "A000000151535041" };
    for (size_t c = 0; c < ARRAY_SIZE(candidates); ++c) {
        for (DWORD i = 0; i < mods_len; ++i) {
            for (DWORD j = 0; j < mods[i].numExecutableModules &&
                 j < (DWORD)(sizeof(mods[i].executableModules)/sizeof(mods[i].executableModules[0])); ++j) {
                if (aid_matches_hex(&mods[i].executableModules[j], candidates[c])) {
                    size_t len = mods[i].executableModules[j].AIDLength;
                    if (len > *out_len) return 0;
                    memcpy(out, mods[i].executableModules[j].AID, len);
                    *out_len = len;
                    return 1;
                }
            }
        }
    }
    return 0;
}

typedef struct {
    BYTE receiptKeyType;
    BYTE receiptKey[32];
    DWORD receiptKeyLength;
    PBYTE receiptKeyPtr;
    TCHAR pemFileName[MAX_PATH_BUF];
    OPGP_STRING pemKeyFileName;
    char passPhrase[256];
    char *passPhrasePtr;
} RECEIPT_VERIFY_KEY_INPUT;

static int parse_receipt_length_ber_cli(const BYTE *buf, size_t bufLength, size_t *receiptLength, size_t *lengthFieldSize) {
    if (!buf || !receiptLength || !lengthFieldSize || bufLength < 1) {
        return -1;
    }
    if (buf[0] <= 0x7F) {
        *receiptLength = buf[0];
        *lengthFieldSize = 1;
        return 0;
    }
    if (buf[0] == 0x81) {
        if (bufLength < 2 || buf[1] < 0x80) {
            return -1;
        }
        *receiptLength = buf[1];
        *lengthFieldSize = 2;
        return 0;
    }
    return -1;
}

static int parse_receipt_from_rapdu_hex(const char *cmd, const char *rapduHex, GP211_RECEIPT_DATA *receiptData) {
    BYTE rapdu[1024];
    size_t rapduLen = sizeof(rapdu);
    size_t payloadLen;
    size_t offset = 0;
    size_t receiptLen = 0;
    size_t lengthFieldSize = 0;

    if (!rapduHex || !receiptData) {
        return -1;
    }
    if (hex_to_bytes(rapduHex, rapdu, &rapduLen) != 0) {
        fprintf(stderr, "%s: invalid response APDU hex\n", cmd);
        return -1;
    }
    if (rapduLen < 2) {
        fprintf(stderr, "%s: response APDU too short\n", cmd);
        return -1;
    }
    payloadLen = rapduLen;
    if (rapduLen >= 2 && rapdu[rapduLen - 2] == 0x90 && rapdu[rapduLen - 1] == 0x00) {
        payloadLen = rapduLen - 2;
    }
    if (payloadLen == 0) {
        fprintf(stderr, "%s: response APDU has no receipt payload\n", cmd);
        return -1;
    }

    memset(receiptData, 0, sizeof(*receiptData));
    if (parse_receipt_length_ber_cli(rapdu, payloadLen, &receiptLen, &lengthFieldSize) != 0) {
        fprintf(stderr, "%s: invalid receipt length BER field\n", cmd);
        return -1;
    }
    if (receiptLen > sizeof(receiptData->receipt)) {
        fprintf(stderr, "%s: receipt length too large\n", cmd);
        return -1;
    }

    offset += lengthFieldSize;
    if (payloadLen - offset < receiptLen) {
        fprintf(stderr, "%s: truncated receipt data\n", cmd);
        return -1;
    }
    receiptData->receiptLength = (BYTE)receiptLen;
    if (receiptLen > 0) {
        memcpy(receiptData->receipt, rapdu + offset, receiptLen);
    }
    offset += receiptLen;

    if (payloadLen - offset < 1) {
        fprintf(stderr, "%s: missing confirmation counter length\n", cmd);
        return -1;
    }
    receiptData->confirmationCounterLength = rapdu[offset++];
    if (receiptData->confirmationCounterLength == 0 ||
        receiptData->confirmationCounterLength > sizeof(receiptData->confirmationCounter) ||
        payloadLen - offset < receiptData->confirmationCounterLength) {
        fprintf(stderr, "%s: invalid confirmation counter field\n", cmd);
        return -1;
    }
    memcpy(receiptData->confirmationCounter, rapdu + offset, receiptData->confirmationCounterLength);
    offset += receiptData->confirmationCounterLength;

    if (payloadLen - offset < 1) {
        fprintf(stderr, "%s: missing SD unique data length\n", cmd);
        return -1;
    }
    receiptData->cardUniqueDataLength = rapdu[offset++];
    if (receiptData->cardUniqueDataLength > sizeof(receiptData->cardUniqueData) ||
        payloadLen - offset < receiptData->cardUniqueDataLength) {
        fprintf(stderr, "%s: invalid SD unique data field\n", cmd);
        return -1;
    }
    if (receiptData->cardUniqueDataLength > 0) {
        memcpy(receiptData->cardUniqueData, rapdu + offset, receiptData->cardUniqueDataLength);
    }
    offset += receiptData->cardUniqueDataLength;

    if (payloadLen > offset) {
        receiptData->tokenIdentifierPresent = 1;
        receiptData->tokenIdentifierLength = rapdu[offset++];
        if (receiptData->tokenIdentifierLength > sizeof(receiptData->tokenIdentifier) ||
            payloadLen - offset < receiptData->tokenIdentifierLength) {
            fprintf(stderr, "%s: invalid token identifier field\n", cmd);
            return -1;
        }
        if (receiptData->tokenIdentifierLength > 0) {
            memcpy(receiptData->tokenIdentifier, rapdu + offset, receiptData->tokenIdentifierLength);
        }
        offset += receiptData->tokenIdentifierLength;
    }

    if (payloadLen > offset) {
        receiptData->tokenDataDigestPresent = 1;
        receiptData->tokenDataDigestLength = rapdu[offset++];
        if (receiptData->tokenDataDigestLength > sizeof(receiptData->tokenDataDigest) ||
            payloadLen - offset < receiptData->tokenDataDigestLength) {
            fprintf(stderr, "%s: invalid token data digest field\n", cmd);
            return -1;
        }
        if (receiptData->tokenDataDigestLength > 0) {
            memcpy(receiptData->tokenDataDigest, rapdu + offset, receiptData->tokenDataDigestLength);
        }
        offset += receiptData->tokenDataDigestLength;
    }

    if (offset != payloadLen) {
        fprintf(stderr, "%s: trailing bytes in receipt payload\n", cmd);
        return -1;
    }
    return 0;
}

static int build_receipt_response_apdu_payload(const GP211_RECEIPT_DATA *receiptData, BYTE *out, size_t *outLen) {
    size_t i = 0;
    size_t cap;

    if (!receiptData || !out || !outLen) {
        return -1;
    }
    cap = *outLen;

    if (receiptData->receiptLength <= 0x7F) {
        if (i + 1 > cap) return -1;
        out[i++] = receiptData->receiptLength;
    } else {
        if (i + 2 > cap) return -1;
        out[i++] = 0x81;
        out[i++] = receiptData->receiptLength;
    }

    if (i + receiptData->receiptLength > cap) return -1;
    if (receiptData->receiptLength > 0) {
        memcpy(out + i, receiptData->receipt, receiptData->receiptLength);
        i += receiptData->receiptLength;
    }

    if (i + 1 + receiptData->confirmationCounterLength > cap) return -1;
    out[i++] = receiptData->confirmationCounterLength;
    if (receiptData->confirmationCounterLength > 0) {
        memcpy(out + i, receiptData->confirmationCounter, receiptData->confirmationCounterLength);
        i += receiptData->confirmationCounterLength;
    }

    if (i + 1 + receiptData->cardUniqueDataLength > cap) return -1;
    out[i++] = receiptData->cardUniqueDataLength;
    if (receiptData->cardUniqueDataLength > 0) {
        memcpy(out + i, receiptData->cardUniqueData, receiptData->cardUniqueDataLength);
        i += receiptData->cardUniqueDataLength;
    }

    if (receiptData->tokenIdentifierPresent) {
        if (i + 1 + receiptData->tokenIdentifierLength > cap) return -1;
        out[i++] = receiptData->tokenIdentifierLength;
        if (receiptData->tokenIdentifierLength > 0) {
            memcpy(out + i, receiptData->tokenIdentifier, receiptData->tokenIdentifierLength);
            i += receiptData->tokenIdentifierLength;
        }
    }

    if (receiptData->tokenDataDigestPresent) {
        if (i + 1 + receiptData->tokenDataDigestLength > cap) return -1;
        out[i++] = receiptData->tokenDataDigestLength;
        if (receiptData->tokenDataDigestLength > 0) {
            memcpy(out + i, receiptData->tokenDataDigest, receiptData->tokenDataDigestLength);
            i += receiptData->tokenDataDigestLength;
        }
    }

    *outLen = i;
    return 0;
}

static void print_receipt_confirmation_data(const GP211_RECEIPT_DATA *receiptData) {
    if (!receiptData) {
        return;
    }
    printf("Confirmation Counter: ");
    print_hex(receiptData->confirmationCounter, receiptData->confirmationCounterLength);
    printf("\n");
    printf("SD Unique Data: ");
    print_hex(receiptData->cardUniqueData, receiptData->cardUniqueDataLength);
    printf("\n");
    if (receiptData->tokenIdentifierPresent) {
        printf("Token Identifier: ");
        print_hex(receiptData->tokenIdentifier, receiptData->tokenIdentifierLength);
        printf("\n");
    }
    if (receiptData->tokenDataDigestPresent) {
        printf("Token Data Digest: ");
        print_hex(receiptData->tokenDataDigest, receiptData->tokenDataDigestLength);
        printf("\n");
    }
}

static void print_received_receipt(const char *operation, const GP211_RECEIPT_DATA *receiptData) {
    BYTE apduPayload[1024];
    size_t apduPayloadLen = sizeof(apduPayload);

    if (!operation || !receiptData) {
        return;
    }
    printf("%s receipt received.\n", operation);
    printf("Receipt: ");
    print_hex(receiptData->receipt, receiptData->receiptLength);
    printf("\n");
    if (build_receipt_response_apdu_payload(receiptData, apduPayload, &apduPayloadLen) == 0) {
        printf("Response APDU (without 9000): ");
        print_hex(apduPayload, (DWORD)apduPayloadLen);
        printf("\n");
    }
    print_receipt_confirmation_data(receiptData);
}

static int parse_receipt_verify_key(const char *cmd, const char *typeOpt, const char *keyHex, const char *pemSpec,
                                    RECEIPT_VERIFY_KEY_INPUT *out) {
    const char *type = typeOpt ? typeOpt : "aes";
    size_t len;

    if (!cmd || !out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));

    if (strcmp(type, "des") == 0 || strcmp(type, "3des") == 0) {
        if (!keyHex) {
            fprintf(stderr, "%s: --key <hex> is required for type des\n", cmd);
            return -1;
        }
        out->receiptKeyType = GP211_KEY_TYPE_DES;
        len = sizeof(out->receiptKey);
        if (hex_to_bytes(keyHex, out->receiptKey, &len) != 0 || !(len == 16 || len == 24)) {
            fprintf(stderr, "%s: invalid DES receipt key (must be 16 or 24 bytes)\n", cmd);
            return -1;
        }
        out->receiptKeyLength = (DWORD)len;
        out->receiptKeyPtr = out->receiptKey;
        return 0;
    }

    if (strcmp(type, "aes") == 0) {
        if (!keyHex) {
            fprintf(stderr, "%s: --key <hex> is required for type aes\n", cmd);
            return -1;
        }
        out->receiptKeyType = GP211_KEY_TYPE_AES;
        len = sizeof(out->receiptKey);
        if (hex_to_bytes(keyHex, out->receiptKey, &len) != 0 || !(len == 16 || len == 24 || len == 32)) {
            fprintf(stderr, "%s: invalid AES receipt key (must be 16, 24, or 32 bytes)\n", cmd);
            return -1;
        }
        out->receiptKeyLength = (DWORD)len;
        out->receiptKeyPtr = out->receiptKey;
        return 0;
    }

    if (strcmp(type, "rsa") == 0 || strcmp(type, "ecc") == 0) {
        char pemCopy[MAX_PATH_BUF];
        char *sep;
        const char *pemPath;

        if (!pemSpec) {
            fprintf(stderr, "%s: --pem <file>[:pass] is required for type %s\n", cmd, type);
            return -1;
        }
        out->receiptKeyType = (strcmp(type, "rsa") == 0) ? GP211_KEY_TYPE_RSA : GP211_KEY_TYPE_ECC;
        strncpy(pemCopy, pemSpec, sizeof(pemCopy) - 1);
        pemCopy[sizeof(pemCopy) - 1] = '\0';
        sep = strchr(pemCopy, ':');
        if (sep) {
            *sep = '\0';
            strncpy(out->passPhrase, sep + 1, sizeof(out->passPhrase) - 1);
            out->passPhrase[sizeof(out->passPhrase) - 1] = '\0';
            out->passPhrasePtr = out->passPhrase;
        } else {
            out->passPhrasePtr = NULL;
        }
        pemPath = pemCopy;
        if (to_opgp_string(pemPath, out->pemFileName, ARRAY_SIZE(out->pemFileName)) != 0) {
            fprintf(stderr, "%s: PEM file path too long\n", cmd);
            return -1;
        }
        out->pemKeyFileName = out->pemFileName;
        return 0;
    }

    fprintf(stderr, "%s: unsupported --type '%s' (use des|aes|rsa|ecc)\n", cmd, type);
    return -1;
}

static int parse_required_hex_field(const char *cmd, const char *fieldName, const char *hex,
                                    BYTE *out, size_t *outLen) {
    if (!hex) {
        fprintf(stderr, "%s: missing %s\n", cmd, fieldName);
        return -1;
    }
    if (hex_to_bytes(hex, out, outLen) != 0) {
        fprintf(stderr, "%s: invalid %s\n", cmd, fieldName);
        return -1;
    }
    return 0;
}

static int select_isd(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, const char *isd_hex_opt) {
    OPGP_ERROR_STATUS s;
    if (isd_hex_opt) {
        unsigned char aidbuf[16]; size_t aidlen = sizeof(aidbuf);
        if (hex_to_bytes(isd_hex_opt, aidbuf, &aidlen) != 0) return -1;
        s = OPGP_select_application(ctx, info, sec, aidbuf, (DWORD)aidlen);
        if (status_ok(s, true)) {
            if (aidlen <= sizeof(g_selected_isd)) { memcpy(g_selected_isd, aidbuf, aidlen); g_selected_isd_len = (DWORD)aidlen; }
            return 0;
        }
    }
    s = OPGP_select_application(ctx, info, sec, (PBYTE)GP231_ISD_AID, 8);
    if (status_ok(s, true)) {
        memcpy(g_selected_isd, GP231_ISD_AID, 8); g_selected_isd_len = 8; return 0;
    }
    // has on 00 less but would still work on GP2.3.1 cards
    s = OPGP_select_application(ctx, info, sec, (PBYTE)GP211_CARD_MANAGER_AID, 7);
    if (status_ok(s, true)) {
        memcpy(g_selected_isd, GP211_CARD_MANAGER_AID, 7); g_selected_isd_len = 7; return 0;
    }
    s = OPGP_select_application(ctx, info, sec, (PBYTE)GP211_CARD_MANAGER_AID_ALT1, 8);
    if (status_ok(s, true)) {
        memcpy(g_selected_isd, GP211_CARD_MANAGER_AID_ALT1, 8); g_selected_isd_len = 8; return 0;
    }
    s = OPGP_select_application(ctx, info, sec, (PBYTE)GP211_CARD_MANAGER_AID_ALT2, 7);
    if (status_ok(s, true)) {
        memcpy(g_selected_isd, GP211_CARD_MANAGER_AID_ALT2, 7); g_selected_isd_len = 7; return 0;
    }
    s = OPGP_select_application(ctx, info, sec, (PBYTE)GP211_CARD_MANAGER_AID_GEMPLUS, 8);
    if (status_ok(s, true)) {
        memcpy(g_selected_isd, GP211_CARD_MANAGER_AID_GEMPLUS, 8); g_selected_isd_len = 8; return 0;
    }
    return -1;
}

static int connect_pcsc(OPGP_CARD_CONTEXT *pctx, OPGP_CARD_INFO *pinfo, const char *reader, const char *protocol, int trace, int verbose) {
    OPGP_ERROR_STATUS s;
    s = OPGP_establish_context(pctx);
    if (!status_ok(s, true)) { fprintf(stderr, "Failed to establish PC/SC context\n"); return -1; }
    if (trace) { OPGP_enable_trace_mode(OPGP_TRACE_MODE_ENABLE, stderr); }
    TCHAR readers[MAX_READERS_BUF];
    DWORD rlen = (DWORD)ARRAY_SIZE(readers);
    TCHAR reader_buf[MAX_READERS_BUF];
    OPGP_CSTRING reader_t = NULL;
    if (!reader) {
        s = OPGP_list_readers(*pctx, readers, &rlen, 1);
        if (!status_ok(s, true) || rlen <= 1 || readers[0] == _T('\0')) {
            fprintf(stderr, "No PC/SC readers with a smart card inserted found\n");
            // release context on error path to avoid leaks
            OPGP_release_context(pctx);
            return -1;
        }
        reader_t = readers; // first reader
    } else {
        // Check if reader is a numeric index (1-based)
        char *endptr;
        long reader_num = strtol(reader, &endptr, 10);
        if (*endptr == '\0' && reader_num > 0) {
            // It's a number - list all readers and select by index
            s = OPGP_list_readers(*pctx, readers, &rlen, 0);
            if (!status_ok(s, true) || rlen <= 1) {
                fprintf(stderr, "No PC/SC readers found\n");
                OPGP_release_context(pctx);
                return -1;
            }
            // Parse reader list (null-separated strings)
            const TCHAR *current = readers;
            int count = 0;
            while (*current && current < readers + rlen) {
                count++;
                if (count == reader_num) {
                    reader_t = current;
                    break;
                }
                current += _tcslen(current) + 1;
            }
            if (count < reader_num) {
                fprintf(stderr, "Reader number %ld not found (only %d readers available)\n", reader_num, count);
                OPGP_release_context(pctx);
                return -1;
            }
        }
        if (!reader_t) {
            if (to_opgp_string(reader, reader_buf, ARRAY_SIZE(reader_buf)) != 0) {
                fprintf(stderr, "Reader name too long\n");
                OPGP_release_context(pctx);
                return -1;
            }
            reader_t = reader_buf;
        }
    }
    if (verbose) { _ftprintf(stderr, _T("Selected reader: %s\n"), reader_t); }
    DWORD proto = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
    if (protocol) {
        if (strcmp(protocol, "t0") == 0) proto = SCARD_PROTOCOL_T0;
        else if (strcmp(protocol, "t1") == 0) proto = SCARD_PROTOCOL_T1;
    }
    s = OPGP_card_connect(*pctx, reader_t, pinfo, proto);
    if (!status_ok(s, true)) {
        _ftprintf(stderr, _T("Failed to connect to reader '%s'\n"), reader_t);
        // release context on error path to avoid leaks
        OPGP_release_context(pctx);
        return -1;
    }
    return 0;
}

static int mutual_auth(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec,
                       BYTE keyset_ver, BYTE key_index, int derivation, const char *sec_level_opt, int verbose,
                       const BYTE *baseKey_in, const BYTE *enc_in, const BYTE *mac_in, const BYTE *dek_in, BYTE keyLength_in,
                       const char *scp_protocol, const char *scp_impl, const char *scp11_cert_file,
                       const char *scp11_sd_public_key, BYTE scp11SessionKeyLength) {
    BYTE scp = 0, scpImpl = 0;
    BYTE scp11CertificateData[16384];
    size_t scp11CertificateDataLength = sizeof(scp11CertificateData);
    BYTE scp11SdPublicKey[128];
    size_t scp11SdPublicKeyLength = sizeof(scp11SdPublicKey);
    PBYTE certOceEcka = NULL;
    DWORD certOceEckaLength = 0;
    PBYTE sdPublicKey = NULL;
    DWORD sdPublicKeyLength = 0;
    TCHAR sdPublicKeyFileName[MAX_PATH_BUF];
    OPGP_STRING sdPublicKeyFileNamePtr = NULL;

    // Parse SCP protocol if provided
    if (scp_protocol) {
        scp = (BYTE)parse_int(scp_protocol);
        if (scp == 1) {
            scp = GP211_SCP01;
            scpImpl = GP211_SCP01_IMPL_i05;
        }
        else if (scp == 2) scp = GP211_SCP02;
        else if (scp == 3) scp = GP211_SCP03;
        else if (scp == 11) scp = GP211_SCP11;
    }

    // Parse SCP implementation if provided
    if (scp_impl) {
        size_t impl_len = sizeof(scpImpl);
        if (hex_to_bytes(scp_impl, &scpImpl, &impl_len) != 0 || impl_len != 1) {
            fprintf(stderr, "Invalid --scp-impl hex (must be 1 byte)\n");
            return -1;
        }
    }

    // Only fetch from card if both are not provided
    if ((!scp_protocol || !scp_impl) && (scp != GP211_SCP01)) {
        OPGP_ERROR_STATUS s = GP211_get_secure_channel_protocol_details(ctx, info, sec, &scp, &scpImpl);
        if (!status_ok(s, false)) {
            if (verbose) fprintf(stderr, "Failed to get SCP details, trying to auto-detect\n");
        }
    }
    BYTE secLevel = sec_level_from_option(scp, scpImpl, sec_level_opt);

    if (scp11_cert_file && scp11_cert_file[0] != '\0') {
        if (scp != GP211_SCP11) {
            fprintf(stderr, "--scp11-cert requires SCP11 (use --scp 11 or card SCP11 auto-detection)\n");
            return -1;
        }
        if (read_binary_file_into_buffer(scp11_cert_file, scp11CertificateData, &scp11CertificateDataLength) != 0
            || scp11CertificateDataLength == 0) {
            fprintf(stderr, "Failed to read --scp11-cert file: %s\n", scp11_cert_file);
            return -1;
        }
        certOceEcka = scp11CertificateData;
        certOceEckaLength = (DWORD)scp11CertificateDataLength;
    }

    if (scp11_sd_public_key && scp11_sd_public_key[0] != '\0') {
        if (scp != GP211_SCP11) {
            fprintf(stderr, "--scp11-sd-public-key requires SCP11 (use --scp 11 or card SCP11 auto-detection)\n");
            return -1;
        }
        if (path_is_readable_file(scp11_sd_public_key)) {
            if (to_opgp_string(scp11_sd_public_key, sdPublicKeyFileName, MAX_PATH_BUF) != 0) {
                fprintf(stderr, "Invalid --scp11-sd-public-key path\n");
                return -1;
            }
            sdPublicKeyFileNamePtr = sdPublicKeyFileName;
        } else {
            if (hex_to_bytes(scp11_sd_public_key, scp11SdPublicKey, &scp11SdPublicKeyLength) != 0) {
                fprintf(stderr, "Invalid --scp11-sd-public-key (expected PEM file path or hex-encoded raw/B0-wrapped public key)\n");
                return -1;
            }
            sdPublicKey = scp11SdPublicKey;
            sdPublicKeyLength = (DWORD)scp11SdPublicKeyLength;
        }
    }

    if (scp == GP211_SCP11 && baseKey_in == NULL) {
        fprintf(stderr, "SCP11 requires --key with SK.OCE.ECKA as raw private key hex\n");
        return -1;
    }

    BYTE S_ENC[32]={0}, S_MAC[32]={0}, DEK[32]={0}, baseKey[32]={0};
    BYTE keyLength = (scp == GP211_SCP11)
            ? (scp11SessionKeyLength > 0 ? scp11SessionKeyLength : 16)
            : (keyLength_in > 0 ? keyLength_in : 16);
    int hasBaseOnly = (baseKey_in != NULL && enc_in == NULL && mac_in == NULL && dek_in == NULL);

    // Use provided keys or default to VISA default key
    if (baseKey_in) {
        BYTE baseKeyLength = (scp == GP211_SCP11) ? keyLength_in : keyLength;
        if (baseKeyLength == 0 || baseKeyLength > sizeof(baseKey)) {
            fprintf(stderr, "Invalid --key length\n");
            return -1;
        }
        memcpy(baseKey, baseKey_in, baseKeyLength);
    } else {
        memcpy(baseKey, OPGP_VISA_DEFAULT_KEY, 16);
    }

    if (enc_in) {
        memcpy(S_ENC, enc_in, keyLength);
    } else if (hasBaseOnly) {
        memcpy(S_ENC, baseKey, keyLength);
    } else {
        memcpy(S_ENC, OPGP_VISA_DEFAULT_KEY, 16);
    }

    if (mac_in) {
        memcpy(S_MAC, mac_in, keyLength);
    } else if (hasBaseOnly) {
        memcpy(S_MAC, baseKey, keyLength);
    } else {
        memcpy(S_MAC, OPGP_VISA_DEFAULT_KEY, 16);
    }

    if (dek_in) {
        memcpy(DEK, dek_in, keyLength);
    } else if (hasBaseOnly) {
        memcpy(DEK, baseKey, keyLength);
    } else {
        memcpy(DEK, OPGP_VISA_DEFAULT_KEY, 16);
    }
    if (g_selected_isd_len > 0) {
        memcpy(sec->invokingAid, g_selected_isd, g_selected_isd_len);
        sec->invokingAidLength = g_selected_isd_len;
    }

    BYTE deriv = OPGP_DERIVATION_METHOD_NONE;
    if (derivation == 1) deriv = OPGP_DERIVATION_METHOD_VISA2;
    else if (derivation == 2) deriv = OPGP_DERIVATION_METHOD_EMV_CPS11;
    OPGP_ERROR_STATUS s2;
    s2 = GP211_mutual_authentication(ctx, info, baseKey, S_ENC, S_MAC, DEK, keyLength,
                                     keyset_ver, key_index, scp, scpImpl, secLevel, deriv,
                                     certOceEcka, certOceEckaLength,
                                     sdPublicKey, sdPublicKeyLength, sdPublicKeyFileNamePtr,
                                     sec);
    if (!status_ok(s2, true)) {
        return -1;
    }
    g_current_scp = scp;
    g_current_scp_impl = scpImpl;
    g_current_scp_set = 1;
    return 0;
}

static const char* lc_to_string(BYTE lifeCycle, BYTE element) {
    const char *lcLoaded = "loaded";
    const char *lcInstalled = "installed";
    const char *lcSelectable = "selectable";
    const char *lcLocked = "locked";
    const char *lcPersonalized = "personalized";
    const char *lcOpReady = "op-ready";
    const char *lcInitialized = "initialized";
    const char *lcSecured = "secured";
    const char *lcCardLocked = "card-locked";
    const char *lcTerminated = "terminated";

    const char *lifeCycleState = "unknown";

    switch (element) {
        case GP211_STATUS_LOAD_FILES:
        case GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES:
            if ((lifeCycle & GP211_LIFE_CYCLE_LOAD_FILE_LOADED) == GP211_LIFE_CYCLE_LOAD_FILE_LOADED) {
                lifeCycleState = lcLoaded;
            }
            break;
        case GP211_STATUS_APPLICATIONS:
            if ((lifeCycle & GP211_LIFE_CYCLE_APPLICATION_INSTALLED) == GP211_LIFE_CYCLE_APPLICATION_INSTALLED) {
                lifeCycleState = lcInstalled;
            }
            if ((lifeCycle & GP211_LIFE_CYCLE_APPLICATION_SELECTABLE) == GP211_LIFE_CYCLE_APPLICATION_SELECTABLE) {
                lifeCycleState = lcSelectable;
            }
            if ((lifeCycle & GP211_LIFE_CYCLE_SECURITY_DOMAIN_PERSONALIZED)  == GP211_LIFE_CYCLE_SECURITY_DOMAIN_PERSONALIZED) {
                lifeCycleState = lcPersonalized;
            }
            if ((lifeCycle & GP211_LIFE_CYCLE_APPLICATION_LOCKED) == GP211_LIFE_CYCLE_APPLICATION_LOCKED) {
                lifeCycleState = lcLocked;
            }
            break;
        case GP211_STATUS_ISSUER_SECURITY_DOMAIN:
            if ((lifeCycle & GP211_LIFE_CYCLE_CARD_OP_READY) == GP211_LIFE_CYCLE_CARD_OP_READY) {
                lifeCycleState = lcOpReady;
            }
            if ((lifeCycle & GP211_LIFE_CYCLE_CARD_INITIALIZED) == GP211_LIFE_CYCLE_CARD_INITIALIZED) {
                lifeCycleState = lcInitialized;
            }
            if ((lifeCycle & GP211_LIFE_CYCLE_CARD_SECURED)  == GP211_LIFE_CYCLE_CARD_SECURED) {
                lifeCycleState = lcSecured;
            }
            if ((lifeCycle & GP211_LIFE_CYCLE_CARD_LOCKED) == GP211_LIFE_CYCLE_CARD_LOCKED) {
                lifeCycleState = lcCardLocked;
            }
            if ((lifeCycle & GP211_LIFE_CYCLE_CARD_TERMINATED) == GP211_LIFE_CYCLE_CARD_TERMINATED) {
                lifeCycleState = lcTerminated;
            }
            break;
        default:
            break;
    }

    return lifeCycleState;
}

// Stringify privilege bitfield similar to gpshell.c:privilegesToString
static void privileges_to_string(DWORD privileges, char *out, size_t outlen) {
    struct { DWORD bit; const char *name; } map[] = {
        { GP211_SECURITY_DOMAIN, "sd" },
        { GP211_DAP_VERIFICATION, "dap-verif" },
        { GP211_DELEGATED_MANAGEMENT, "delegated-mgmt" },
        { GP211_CARD_MANAGER_LOCK_PRIVILEGE, "cm-lock" },
        { GP211_CARD_MANAGER_TERMINATE_PRIVILEGE, "cm-terminate" },
        { GP211_DEFAULT_SELECTED_CARD_RESET_PRIVILEGE, "default-selected" },
        { GP211_PIN_CHANGE_PRIVILEGE, "pin-change" },
        { GP211_MANDATED_DAP_VERIFICATION, "mandated-dap" },
        { GP211_TRUSTED_PATH, "trusted-path" },
        { GP211_AUTHORIZED_MANAGEMENT, "authorized-mgmt" },
        { GP211_TOKEN_VERIFICATION, "token-verif" },
        { GP211_GLOBAL_DELETE, "global-delete" },
        { GP211_GLOBAL_LOCK, "global-lock" },
        { GP211_GLOBAL_REGISTRY, "global-registry" },
        { GP211_FINAL_APPLICATION, "final-application" },
        { GP211_GLOBAL_SERVICE, "global-service" },
        { GP211_RECEIPT_GENERATION, "receipt-generation" },
        { GP211_CIPHERED_LOAD_FILE_DATA_BLOCK, "ciphered-load-file-data-block" },
        { GP211_CONTACTLESS_ACTIVATION, "contactless-activation" },
        { GP211_CONTACTLESS_SELF_ACTIVATION, "contactless-self-activation" },
    };

    if (!out || outlen == 0) return;
    out[0] = '\0';
    size_t used = 0;
    int first = 1;
    for (size_t i = 0; i < sizeof(map)/sizeof(map[0]); ++i) {
        if ((privileges & map[i].bit) == map[i].bit) {
            const char *name = map[i].name;
            size_t nlen = strlen(name);
            // add separator if not first
            if (!first) {
                if (used + 1 < outlen) { out[used++] = ','; }
            }
            first = 0;
            // copy name
            for (size_t j = 0; j < nlen && used + 1 < outlen; ++j) {
                out[used++] = name[j];
            }
            if (used < outlen) out[used] = '\0';
        }
    }
    if (first) {
        // no bits matched
        snprintf(out, outlen, "none");
    }
}

static int aid_equal(const OPGP_AID *a, const OPGP_AID *b) {
    if (a->AIDLength != b->AIDLength) return 0;
    return memcmp(a->AID, b->AID, a->AIDLength) == 0;
}

static int aid_is_present(const OPGP_AID *a) {
    return a && a->AIDLength > 0;
}

static void append_unique_aid(OPGP_AID *aids, DWORD *aid_count, DWORD aid_capacity, const OPGP_AID *aid) {
    if (!aid_is_present(aid) || !aids || !aid_count) return;
    for (DWORD i = 0; i < *aid_count; ++i) {
        if (aid_equal(&aids[i], aid)) return;
    }
    if (*aid_count < aid_capacity) {
        aids[(*aid_count)++] = *aid;
    }
}

static void aid_to_hex_str(const OPGP_AID *a, char *out, size_t outlen) {
    if (!out || outlen == 0) return;
    size_t need = (size_t)a->AIDLength * 2 + 1;
    if (outlen < need) { out[0] = '\0'; return; }
    size_t pos = 0;
    for (size_t i = 0; i < (size_t)a->AIDLength; ++i) {
        snprintf(out + pos, outlen - pos, "%02X", a->AID[i]);
        pos += 2;
    }
    out[pos] = '\0';
}

static int status_is_get_status_unsupported(OPGP_ERROR_STATUS s) {
    return s.errorCode == OPGP_ISO7816_ERROR_INVALID_INS
        || s.errorCode == OPGP_ISO7816_ERROR_WRONG_CLA
        || s.errorCode == OPGP_ISO7816_ERROR_FUNC_NOT_SUPPORTED;
}

static int list_apps_probe_common_aids(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info) {
    static const BYTE YK_AID_OTP[] = { 0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01 };
    static const BYTE YK_AID_MANAGEMENT[] = { 0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17 };
    static const BYTE YK_AID_OPENPGP[] = { 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01 };
    static const BYTE YK_AID_OATH[] = { 0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01 };
    static const BYTE YK_AID_PIV[] = { 0xA0, 0x00, 0x00, 0x03, 0x08 };
    static const BYTE YK_AID_FIDO[] = { 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01 };
    static const BYTE YK_AID_HSMAUTH[] = { 0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01 };

    struct aid_probe {
        const BYTE *aid;
        BYTE aid_len;
        const char *label;
    };

    struct aid_probe probes[] = {
        { GP231_ISD_AID, (BYTE)sizeof(GP231_ISD_AID), "ISD (GP231)" },
        { GP211_CARD_MANAGER_AID, (BYTE)sizeof(GP211_CARD_MANAGER_AID), "Card Manager" },
        { GP211_CARD_MANAGER_AID_ALT1, (BYTE)sizeof(GP211_CARD_MANAGER_AID_ALT1), "Card Manager (Alt1)" },
        { GP211_CARD_MANAGER_AID_ALT2, (BYTE)sizeof(GP211_CARD_MANAGER_AID_ALT2), "Card Manager (Alt2)" },
        { GP211_CARD_MANAGER_AID_GEMPLUS, (BYTE)sizeof(GP211_CARD_MANAGER_AID_GEMPLUS), "Card Manager (Gemplus)" },
        { YK_AID_OTP, (BYTE)sizeof(YK_AID_OTP), "YubiKey OTP" },
        { YK_AID_MANAGEMENT, (BYTE)sizeof(YK_AID_MANAGEMENT), "YubiKey Management" },
        { YK_AID_OPENPGP, (BYTE)sizeof(YK_AID_OPENPGP), "YubiKey OpenPGP" },
        { YK_AID_OATH, (BYTE)sizeof(YK_AID_OATH), "YubiKey OATH" },
        { YK_AID_PIV, (BYTE)sizeof(YK_AID_PIV), "YubiKey PIV" },
        { YK_AID_FIDO, (BYTE)sizeof(YK_AID_FIDO), "YubiKey FIDO" },
        { YK_AID_HSMAUTH, (BYTE)sizeof(YK_AID_HSMAUTH), "YubiKey HSMAuth" },
    };

    OPGP_AID tried[64];
    DWORD tried_count = 0;
    int found = 0;

    printf("== applications (select probe) ==\n");

    // If we know what was selected for SCP, probe it first.
    if (g_selected_isd_len > 0 && g_selected_isd_len <= sizeof(tried[0].AID)) {
        OPGP_AID selected = { 0 };
        OPGP_ERROR_STATUS s;
        selected.AIDLength = (BYTE)g_selected_isd_len;
        memcpy(selected.AID, g_selected_isd, g_selected_isd_len);
        append_unique_aid(tried, &tried_count, ARRAY_SIZE(tried), &selected);
        s = OPGP_select_application(ctx, info, NULL, selected.AID, selected.AIDLength);
        if (status_ok(s, false)) {
            char aid_hex[64];
            aid_to_hex_str(&selected, aid_hex, sizeof(aid_hex));
            printf("  %s  [%s]\n", aid_hex, "Selected ISD");
            found = 1;
        }
    }

    for (size_t i = 0; i < ARRAY_SIZE(probes); ++i) {
        OPGP_AID a = { 0 };
        DWORD before;
        OPGP_ERROR_STATUS s;
        if (probes[i].aid_len > sizeof(a.AID)) continue;
        a.AIDLength = probes[i].aid_len;
        memcpy(a.AID, probes[i].aid, probes[i].aid_len);

        before = tried_count;
        append_unique_aid(tried, &tried_count, ARRAY_SIZE(tried), &a);
        if (tried_count == before) {
            continue;
        }

        s = OPGP_select_application(ctx, info, NULL, a.AID, a.AIDLength);
        if (status_ok(s, false)) {
            char aid_hex[64];
            aid_to_hex_str(&a, aid_hex, sizeof(aid_hex));
            printf("  %s  [%s]\n", aid_hex, probes[i].label);
            found = 1;
        }
    }

    if (!found) {
        printf("  (no known applet AIDs responded to SELECT)\n");
    }
    return 0;
}


/* --- Session Connection & Authentication Implementation --- */


int gpshell3_connect_pcsc(gpshell3_session_t *session, const char *reader, const char *protocol, int trace, int verbose) {
    if (!session) return -1;
    if (session->ctx.libraryName[0] == 0) {
        gpshell3_session_init(session);
    }
    int rc = connect_pcsc(&session->ctx, &session->info, reader, protocol, trace, verbose);
    if (rc == 0) {
        session->is_connected = true;
    }
    return rc;
}

int gpshell3_select_isd(gpshell3_session_t *session, const char *sd_hex) {
    if (!session || !session->is_connected) return -1;
    int rc = select_isd(session->ctx, session->info, &session->sec, sd_hex);
    if (rc == 0) {
        memcpy(session->selected_isd, g_selected_isd, g_selected_isd_len);
        session->selected_isd_len = g_selected_isd_len;
    }
    return rc;
}

int gpshell3_mutual_auth(gpshell3_session_t *session, BYTE keyset_ver, BYTE key_index, int derivation,
                         const char *sec_level_opt, int verbose,
                         const BYTE *baseKey, const BYTE *enc_key, const BYTE *mac_key, const BYTE *dek_key,
                         BYTE keyLength, const char *scp_protocol, const char *scp_impl,
                         const char *scp11_cert_file, const char *scp11_sd_public_key,
                         BYTE scp11SessionKeyLength) {
    if (!session || !session->is_connected) return -1;
    int rc = mutual_auth(session->ctx, session->info, &session->sec, keyset_ver, key_index, derivation,
                         sec_level_opt, verbose, baseKey, enc_key, mac_key, dek_key, keyLength,
                         scp_protocol, scp_impl, scp11_cert_file, scp11_sd_public_key, scp11SessionKeyLength);
    if (rc == 0) {
        session->is_authenticated = true;
        session->current_scp = g_current_scp;
        session->current_scp_impl = g_current_scp_impl;
    }
    return rc;
}
static int cmd_list_apps(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    GP211_APPLICATION_DATA apps[256];
    GP211_APPLICATION_DATA isds[64];
    GP211_APPLICATION_DATA lfs[256];
    GP211_EXECUTABLE_MODULES_DATA mods[128];

    DWORD apps_len = sizeof(apps)/sizeof(apps[0]);
    DWORD isds_len = sizeof(isds)/sizeof(isds[0]);
    DWORD lfs_len  = sizeof(lfs)/sizeof(lfs[0]);
    DWORD mods_len = sizeof(mods)/sizeof(mods[0]);
    BYTE status_format = GP211_STATUS_FORMAT_NEW;

    OPGP_ERROR_STATUS s;

    s = GP211_get_status(ctx, info, sec, GP211_STATUS_APPLICATIONS, status_format, apps, NULL, &apps_len);
    if (!status_ok(s, false)) {
        DWORD apps_len_legacy = sizeof(apps)/sizeof(apps[0]);
        OPGP_ERROR_STATUS s_legacy = GP211_get_status(ctx, info, sec, GP211_STATUS_APPLICATIONS,
                                                      GP211_STATUS_FORMAT_DEPRECATED, apps, NULL, &apps_len_legacy);
        if (status_ok(s_legacy, false)) {
            status_format = GP211_STATUS_FORMAT_DEPRECATED;
            apps_len = apps_len_legacy;
        } else if (status_is_get_status_unsupported(s) || status_is_get_status_unsupported(s_legacy)) {
            fprintf(stderr, "GET STATUS is not supported by the selected Security Domain (SW=0x%04X). Falling back to SELECT probing.\n",
                    (unsigned int)((s_legacy.errorCode != 0 ? s_legacy.errorCode : s.errorCode) & 0xFFFF));
            return list_apps_probe_common_aids(ctx, info);
        } else {
            status_ok(s, true);
            fprintf(stderr, "GET STATUS (applications) failed\n");
            return -1;
        }
    }

    s = GP211_get_status(ctx, info, sec, GP211_STATUS_ISSUER_SECURITY_DOMAIN, status_format, isds, NULL, &isds_len);
    if (!status_ok(s, true)) { fprintf(stderr, "GET STATUS (issuer security domain) failed\n"); return -1; }

    s = GP211_get_status(ctx, info, sec, GP211_STATUS_LOAD_FILES, status_format, lfs, NULL, &lfs_len);
    if (!status_ok(s, true)) { fprintf(stderr, "GET STATUS (load files) failed\n"); return -1; }

    s = GP211_get_status(ctx, info, sec, GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES, status_format, NULL, mods, &mods_len);
    if (!status_ok(s, true)) { fprintf(stderr, "GET STATUS (load files and executable modules) failed\n"); return -1; }

    // Collect distinct Security Domains from issuer SD entries and linked content.
    OPGP_AID sds[256];
    DWORD sd_count = 0;
    bool has_unassigned = false;

    for (DWORD i = 0; i < apps_len; ++i) {
        append_unique_aid(sds, &sd_count, ARRAY_SIZE(sds), &apps[i].associatedSecurityDomainAID);
        if (!aid_is_present(&apps[i].associatedSecurityDomainAID)) has_unassigned = true;
    }
    for (DWORD i = 0; i < isds_len; ++i) {
        append_unique_aid(sds, &sd_count, ARRAY_SIZE(sds), &isds[i].aid);
    }
    for (DWORD i = 0; i < lfs_len; ++i) {
        append_unique_aid(sds, &sd_count, ARRAY_SIZE(sds), &lfs[i].associatedSecurityDomainAID);
        if (!aid_is_present(&lfs[i].associatedSecurityDomainAID)) has_unassigned = true;
    }
    for (DWORD i = 0; i < mods_len; ++i) {
        append_unique_aid(sds, &sd_count, ARRAY_SIZE(sds), &mods[i].associatedSecurityDomainAID);
        if (!aid_is_present(&mods[i].associatedSecurityDomainAID)) has_unassigned = true;
    }

    printf("== security domains ==\n");
    if (sd_count == 0 && !has_unassigned) {
        printf("(none)\n");
        return 0;
    }

    for (DWORD sd_i = 0; sd_i < sd_count + (has_unassigned ? 1U : 0U); ++sd_i) {
        const bool is_unassigned_group = (sd_i == sd_count);
        const OPGP_AID *group_sd = is_unassigned_group ? NULL : &sds[sd_i];

        // Print SD header line; prefer info from ISD listing when matching.
        const GP211_APPLICATION_DATA *sd_info = NULL;
        if (!is_unassigned_group) {
            char sd_hex[64];
            aid_to_hex_str(group_sd, sd_hex, sizeof(sd_hex));

            for (DWORD i = 0; i < isds_len; ++i) {
                if (aid_equal(&isds[i].aid, group_sd) ||
                    aid_equal(&isds[i].associatedSecurityDomainAID, group_sd)) {
                    sd_info = &isds[i];
                    break;
                }
            }

            if (sd_info) {
                printf("SD %s lc=%s", sd_hex, lc_to_string(sd_info->lifeCycleState, GP211_STATUS_ISSUER_SECURITY_DOMAIN));
                if (sd_info->privileges) {
                    char pbuf[512];
                    privileges_to_string(sd_info->privileges, pbuf, sizeof(pbuf));
                    printf(" priv=[%s]", pbuf);
                }
                printf("\n");
            } else {
                printf("SD %s\n", sd_hex);
            }
        } else {
            printf("SD Unassigned\n");
        }

        // Applications under this SD
        int any_apps = 0;
        for (DWORD i = 0; i < apps_len; ++i) {
            if (is_unassigned_group) {
                if (aid_is_present(&apps[i].associatedSecurityDomainAID)) continue;
            } else if (!aid_equal(&apps[i].associatedSecurityDomainAID, group_sd)) {
                continue;
            }
            if (!any_apps) { printf("  Applications:\n"); any_apps = 1; }
            printf("    ");
            print_aid(&apps[i].aid);
            printf(" lc=%s", lc_to_string(apps[i].lifeCycleState, GP211_STATUS_APPLICATIONS));
            if (apps[i].privileges) {
                char pbuf[512];
                privileges_to_string(apps[i].privileges, pbuf, sizeof(pbuf));
                printf(" priv=[%s]", pbuf);
            }
            if (apps[i].versionNumber[0] || apps[i].versionNumber[1]) {
                printf(" ver=%u.%u", apps[i].versionNumber[0], apps[i].versionNumber[1]);
            }
            printf("\n");
        }

        // Load files under this SD (with modules)
        int any_lf = 0;
        for (DWORD i = 0; i < lfs_len; ++i) {
            if (is_unassigned_group) {
                if (aid_is_present(&lfs[i].associatedSecurityDomainAID)) continue;
            } else if (!aid_equal(&lfs[i].associatedSecurityDomainAID, group_sd)) {
                continue;
            }
            if (!any_lf) { printf("  Load files:\n"); any_lf = 1; }

            printf("    ");
            print_aid(&lfs[i].aid);
            printf(" lc=%s", lc_to_string(lfs[i].lifeCycleState, GP211_STATUS_LOAD_FILES));
            if (lfs[i].versionNumber[0] || lfs[i].versionNumber[1]) {
                printf(" ver=%u.%u", lfs[i].versionNumber[0], lfs[i].versionNumber[1]);
            }
            printf("\n");

            // modules for this load file (from GET STATUS 0x10)
            for (DWORD m = 0; m < mods_len; ++m) {
                if (!aid_equal(&mods[m].aid, &lfs[i].aid)) continue;
                if (mods[m].numExecutableModules > 0) {
                    printf("      Modules:\n");
                    for (DWORD j = 0;
                         j < mods[m].numExecutableModules &&
                         j < (DWORD)(sizeof(mods[m].executableModules)/sizeof(mods[m].executableModules[0]));
                         ++j) {
                        printf("        ");
                        print_aid(&mods[m].executableModules[j]);
                        printf("\n");
                    }
                }
                break;
            }
        }

        if (!any_apps && !any_lf) {
            printf("  (no applications or load files)\n");
        }
    }

    return 0;
}

static const char* key_type_to_string(BYTE type) {
    switch (type) {
        case GP211_KEY_TYPE_DES: return "DES";
        case GP211_KEY_TYPE_3DES: return "3DES";
        case GP211_KEY_TYPE_3DES_CBC: return "3DES-CBC";
        case GP211_KEY_TYPE_DES_ECB: return "DES-ECB";
        case GP211_KEY_TYPE_DES_CBC: return "DES-CBC";
        case GP211_KEY_TYPE_PSK_TLS: return "Pre-Shared Key TLS";
        case GP211_KEY_TYPE_AES: return "AES";
        case GP211_KEY_TYPE_SM4: return "SM4";
        case GP211_KEY_TYPE_RSA_PUB_E: return "RSA Public Key - e";
        case GP211_KEY_TYPE_RSA_PUB_N: return "RSA Public Key - N";
        case GP211_KEY_TYPE_RSA_PRIV_ENC_N: return "RSA Private Key - N";
        case GP211_KEY_TYPE_RSA_PRIV_D: return "RSA Private Key - d";
        case GP211_KEY_TYPE_RSA_PRIV_P: return "RSA Private Key - CR P";
        case GP211_KEY_TYPE_RSA_PRIV_Q: return "RSA Private Key - CR Q";
        case GP211_KEY_TYPE_RSA_PRIV_PQ: return "RSA Private Key - CR PQ";
        case GP211_KEY_TYPE_RSA_PRIV_DP1: return "RSA Private Key - CR DP1";
        case GP211_KEY_TYPE_RSA_PRIV_DQ1: return "RSA Private Key - CR DQ1";
        case GP211_KEY_TYPE_ECC_PUBLIC_OR_PRIVATE: return "ECC Public Key";
        case GP211_KEY_TYPE_ECC_PRIVATE: return "ECC Private Key";
        case GP211_KEY_TYPE_ECC_FIELD_PARAMETER_P: return "ECC Field Parameter P";
        case GP211_KEY_TYPE_ECC_FIELD_PARAMETER_A: return "ECC Field Parameter A";
        case GP211_KEY_TYPE_ECC_FIELD_PARAMETER_B: return "ECC Field Parameter B";
        case GP211_KEY_TYPE_ECC_FIELD_PARAMETER_G: return "ECC Field Parameter G";
        case GP211_KEY_TYPE_ECC_FIELD_PARAMETER_N: return "ECC Field Parameter N";
        case GP211_KEY_TYPE_ECC_SM2_PUBLIC_OR_PRIVATE: return "SM2 Public/Private Key";
        case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE: return "ECC Key Parameter Reference";
        case GP211_KEY_TYPE_ECC: return "ECC";
        default: return NULL;
    }
}

static const char* key_access_to_string(BYTE access) {
    switch (access) {
        case 0x00: return "Security Domain and Application";
        case 0x01: return "Security Domain";
        case 0x02: return "Application";
        default: return NULL;
    }
}

static void key_usage_to_string(unsigned short usage, char *out, size_t outlen) {
    if (!out || outlen == 0) return;
    out[0] = '\0';
    size_t used = 0;
    int found = 0;

    BYTE firstByte = (BYTE)((usage >> 8) & 0xFF);
    BYTE secondByte = (BYTE)(usage & 0xFF);

    // Map first byte (leftmost)
    const char *firstByteStr = NULL;
    switch (firstByte) {
        case 0x14: firstByteStr = "C-MAC"; break;
        case 0x24: firstByteStr = "R-MAC"; break;
        case 0x34: firstByteStr = "C-MAC + R-MAC"; break;
        case 0x18: firstByteStr = "C-ENC"; break;
        case 0x28: firstByteStr = "R-ENC"; break;
        case 0x38: firstByteStr = "C-ENC + R-ENC"; break;
        case 0x48: firstByteStr = "C-DEK"; break;
        case 0x88: firstByteStr = "R-DEK"; break;
        case 0xC8: firstByteStr = "C-DEK + R-DEK"; break;
        case 0x82: firstByteStr = "PK.SD.AUT"; break;
        case 0x42: firstByteStr = "SK.SD.AUT"; break;
        case 0x81: firstByteStr = "Token"; break;
        case 0x44: firstByteStr = "Receipt"; break;
        case 0x84: firstByteStr = "DAP"; break;
    }

    if (firstByteStr) {
        size_t len = strlen(firstByteStr);
        if (used + len < outlen) {
            strcpy(out + used, firstByteStr);
            used += len;
            found = 1;
        }
    }

    // Map second byte (rightmost) - only 0x80 is defined
    if (secondByte == 0x80) {
        const char *secondByteStr = "Key Agreement (KAT)";
        size_t len = strlen(secondByteStr);
        if (found && used + 2 < outlen) {
            strcpy(out + used, ", ");
            used += 2;
        }
        if (used + len < outlen) {
            strcpy(out + used, secondByteStr);
            used += len;
            found = 1;
        }
    }

    if (!found) {
        snprintf(out, outlen, "0x%04X", usage);
    }
}

// Sort by (kv, idx)
static int key_info_cmp(const void *pa, const void *pb) {
    const GP211_KEY_INFORMATION *a = pa;
    const GP211_KEY_INFORMATION *b = pb;
    if (a->keySetVersion != b->keySetVersion) return (int)a->keySetVersion - (int)b->keySetVersion;
    return (int)a->keyIndex - (int)b->keyIndex;
}

static int cmd_list_keys(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    GP211_KEY_INFORMATION infos[64]; DWORD ilen;
    BYTE keyIndex = 0;
    OPGP_ERROR_STATUS s;

    // Collect all keys first so we can sort & group nicely
    GP211_KEY_INFORMATION all[512];
    DWORD all_len = 0;

    // Loop until OPGP_ISO7816_ERROR_DATA_NOT_FOUND is returned
    while (1) {
        ilen = sizeof(infos)/sizeof(infos[0]);
        memset(infos, 0, sizeof(infos));
        s = GP211_get_key_information_templates(ctx, info, sec, keyIndex, infos, &ilen);

        // Check specifically for DATA_NOT_FOUND - this ends the loop normally
        if (s.errorCode == OPGP_ISO7816_ERROR_DATA_NOT_FOUND) {
            break;
        }

        // All other errors should be checked with status_ok
        if (!status_ok(s, true)) {
            return -1;
        }

        // Append key information
        for (DWORD i = 0; i < ilen; i++) {
            if (all_len < (DWORD)(sizeof(all) / sizeof(all[0]))) {
                all[all_len++] = infos[i];
            }
        }

        // Move to next key index for the next iteration
        keyIndex++;
    }

    printf("== keys ==\n");
    if (all_len == 0) {
        printf("(none)\n");
        return 0;
    }


    qsort(all, all_len, sizeof(all[0]), key_info_cmp);

    // Print grouped by KV
    int current_kv = -1;
    for (DWORD i = 0; i < all_len; i++) {
        if (current_kv != (int)all[i].keySetVersion) {
            current_kv = (int)all[i].keySetVersion;
            printf("kv=0x%02x:\n", current_kv);
        }

        printf("  idx=%u (0x%02X) ", all[i].keyIndex, all[i].keyIndex);
        for (BYTE k = 0; k < all[i].numKeyComponents; k++) {
            if (k > 0) printf("         ");
            const char *typeStr = key_type_to_string(all[i].keyComponents[k].keyType);
            if (typeStr) {
                printf("type=%s ", typeStr);
            } else {
                printf("type=0x%02X ", all[i].keyComponents[k].keyType);
            }

            printf("len=%u", all[i].keyComponents[k].keyLength);

            if (all[i].keyComponents[k].extended) {
                char usageBuf[256];
                key_usage_to_string(all[i].keyComponents[k].keyUsage, usageBuf, sizeof(usageBuf));
                printf(" usage=%s", usageBuf);

                const char *accessStr = key_access_to_string(all[i].keyComponents[k].keyAccess);
                if (accessStr) {
                    printf(" access=%s", accessStr);
                } else {
                    printf(" access=0x%02X", all[i].keyComponents[k].keyAccess);
                }
            }
            printf("\n");
        }
    }

    return 0;
}

static int cmd_install(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec,
                       int argc, char **argv) {
    int load_only = 0;
    int install_only = 0;
    DWORD v_data_limit = 0, nv_data_limit = 0;
    const char *dap_hex = NULL; const char *dap_sd_hex = NULL; const char *applet_aid_hex=NULL; const char *module_aid_hex=NULL; const char *priv_list=NULL; const char *params_hex=NULL;
    const char *load_token_hex = NULL; const char *install_token_hex = NULL; const char *load_file_hash_hex = NULL;
    const char *load_file_aid_hex = NULL;
    int ai = 0;
    for (; ai < argc; ++ai) {
        if (strcmp(argv[ai], "--load-only") == 0) load_only = 1;
        else if (strcmp(argv[ai], "--install-only") == 0) install_only = 1;
        else if (strcmp(argv[ai], "--dap") == 0 && ai+1 < argc) { dap_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--dap-sd") == 0 && ai+1 < argc) { dap_sd_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--load-token") == 0 && ai+1 < argc) { load_token_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--install-token") == 0 && ai+1 < argc) { install_token_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--hash") == 0 && ai+1 < argc) { load_file_hash_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--load-file") == 0 && ai+1 < argc) { load_file_aid_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--applet") == 0 && ai+1 < argc) { applet_aid_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--module") == 0 && ai+1 < argc) { module_aid_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--priv") == 0 && ai+1 < argc) { priv_list = argv[++ai]; }
        else if (strcmp(argv[ai], "--v-data-limit") == 0 && ai+1 < argc) { v_data_limit = (DWORD)parse_int(argv[++ai]); }
        else if (strcmp(argv[ai], "--nv-data-limit") == 0 && ai+1 < argc) { nv_data_limit = (DWORD)parse_int(argv[++ai]); }
        else if (strcmp(argv[ai], "--params") == 0 && ai+1 < argc) { params_hex = argv[++ai]; }
        else break;
    }
    if (ai >= argc) { fprintf(stderr, "install: missing <cap-file>\n"); return -1; }
    const char *capfile = argv[ai++];
    TCHAR capfile_t[MAX_PATH_BUF];
    OPGP_STRING capfile_opgp = NULL;
    if (to_opgp_string(capfile, capfile_t, ARRAY_SIZE(capfile_t)) != 0) {
        fprintf(stderr, "install: cap file path too long\n");
        return -1;
    }
    capfile_opgp = capfile_t;

    // Validate mutually exclusive flags
    if (load_only && install_only) {
        fprintf(stderr, "install: --load-only and --install-only are mutually exclusive\n");
        return -1;
    }

    // Validate --install-only requirements
    if (install_only) {
        if (!load_file_aid_hex) {
            fprintf(stderr, "install: --install-only requires --load-file <AIDhex>\n");
            return -1;
        }
        if (!module_aid_hex) {
            fprintf(stderr, "install: --install-only requires --module <AIDhex>\n");
            return -1;
        }
        if (!applet_aid_hex) {
            fprintf(stderr, "install: --install-only requires --applet <AIDhex>\n");
            return -1;
        }
    }
    if (dap_sd_hex != NULL && dap_hex == NULL) {
        fprintf(stderr, "install: --dap-sd requires --dap\n");
        return -1;
    }

    GP211_DAP_BLOCK dapBlocks[1]; DWORD dapCount = 0;
    // Use the ISD AID that was selected during connection/authentication, without probing via GET DATA.
    unsigned char sdAid[16]; DWORD sdAidLen = 0;
    if (g_selected_isd_len > 0 && g_selected_isd_len <= sizeof(sdAid)) {
        memcpy(sdAid, g_selected_isd, g_selected_isd_len);
        sdAidLen = g_selected_isd_len;
    } else {
        memcpy(sdAid, GP231_ISD_AID, 7);
        sdAidLen = 7;
    }
    unsigned char dapSdAid[16]; DWORD dapSdAidLen = sdAidLen;
    memcpy(dapSdAid, sdAid, sdAidLen);
    if (dap_sd_hex != NULL) {
        size_t dap_sd_len = sizeof(dapSdAid);
        if (hex_to_bytes(dap_sd_hex, dapSdAid, &dap_sd_len) != 0) {
            fprintf(stderr, "install: invalid --dap-sd AID\n");
            return -1;
        }
        dapSdAidLen = (DWORD)dap_sd_len;
    }

    // Parse generic DAP signature if provided
    if (dap_hex) {
        unsigned char sig_buf[256]; size_t sig_len = sizeof(sig_buf);

        // Check if it's a file path (starts with '@')
        if (dap_hex[0] == '@') {
            const char *filepath = dap_hex + 1;
            FILE *f = fopen(filepath, "rb");
            if (!f) { fprintf(stderr, "Failed to open DAP signature file: %s\n", filepath); return -1; }
            sig_len = fread(sig_buf, 1, sizeof(sig_buf), f);
            fclose(f);
            if (sig_len == 0) { fprintf(stderr, "Empty DAP signature file\n"); return -1; }
        } else {
            // Parse as hex string
            if (hex_to_bytes(dap_hex, sig_buf, &sig_len) != 0) { fprintf(stderr, "Invalid DAP signature hex\n"); return -1; }
        }

        // Fill in DAP block with signature and SD AID
        memcpy(dapBlocks[0].securityDomainAID, dapSdAid, dapSdAidLen);
        dapBlocks[0].securityDomainAIDLength = (BYTE)dapSdAidLen;
        memcpy(dapBlocks[0].signature, sig_buf, sig_len);
        dapBlocks[0].signatureLength = (BYTE)sig_len;
        dapCount = 1;
    }

    // Read CAP load file parameters to obtain the package AID (unless --install-only)
    OPGP_LOAD_FILE_PARAMETERS lfp; memset(&lfp,0,sizeof(lfp));
    unsigned char load_file_aid[16]; size_t load_file_aid_len = 0;

    if (install_only) {
        // Parse load file AID from command line for --install-only mode
        load_file_aid_len = sizeof(load_file_aid);
        if (hex_to_bytes(load_file_aid_hex, load_file_aid, &load_file_aid_len) != 0) {
            fprintf(stderr, "Invalid --load-file AID\n");
            return -1;
        }
    } else {
        // Read CAP file parameters for normal or --load-only mode
        if (!status_ok(OPGP_read_executable_load_file_parameters(capfile_opgp, &lfp), false)) {
            fprintf(stderr, "Failed to read CAP load file parameters\n");
            return -1;
        }

        // Parse optional load file hash
        BYTE loadFileHash[64]; memset(loadFileHash, 0, sizeof(loadFileHash));
        BYTE *loadFileHashPtr = NULL;
        DWORD loadFileHashLen = 0;
        if (load_file_hash_hex) {
            size_t hash_len = sizeof(loadFileHash);
            if (hex_to_bytes(load_file_hash_hex, loadFileHash, &hash_len) != 0) {
                fprintf(stderr, "Invalid load file hash hex\n");
                return -1;
            }
            loadFileHashPtr = loadFileHash;
            loadFileHashLen = (DWORD)hash_len;
        }

        // Parse optional load token
        BYTE loadToken[512]; memset(loadToken, 0, sizeof(loadToken));
        BYTE *loadTokenPtr = NULL;
        DWORD loadTokenLen = 0;
        if (load_token_hex) {
            size_t token_len = sizeof(loadToken);
            if (hex_to_bytes(load_token_hex, loadToken, &token_len) != 0 || token_len == 0) {
                fprintf(stderr, "Invalid load token hex\n");
                return -1;
            }
            loadTokenPtr = loadToken;
            loadTokenLen = (DWORD)token_len;
        }

        if (!status_ok(GP211_install_for_load(ctx, info, sec,
                lfp.loadFileAID.AID, lfp.loadFileAID.AIDLength,
                sdAid, sdAidLen,
                loadFileHashPtr, loadFileHashLen,
                loadTokenPtr, loadTokenLen,
                lfp.loadFileSize, v_data_limit, nv_data_limit), true)) {
            return -1;
        }

        GP211_RECEIPT_DATA receipt; DWORD receiptAvail=0; memset(&receipt, 0, sizeof(receipt));
        if (!status_ok(GP211_load(ctx, info, sec, dapCount?dapBlocks:NULL, dapCount, capfile_opgp, &receipt, &receiptAvail, NULL), true)) {
            return -1;
        }
        if (receiptAvail) {
            print_received_receipt("Load", &receipt);
        }
        if (load_only) { return 0; }
    }

    unsigned char applet_aid[16]; size_t applet_len=0;
    if (applet_aid_hex) {
        applet_len = sizeof(applet_aid);
        if (hex_to_bytes(applet_aid_hex, applet_aid, &applet_len)!=0) {
            fprintf(stderr, "Invalid --applet AID\n");
            return -1;
        }
    }
    unsigned char module_aid[16]; size_t module_len=0;
    if (module_aid_hex) {
        module_len = sizeof(module_aid);
        if (hex_to_bytes(module_aid_hex, module_aid, &module_len)!=0) {
            fprintf(stderr, "Invalid --module AID\n");
            return -1;
        }
    }

    unsigned char inst_param[256]; size_t inst_param_len=0;
    if (params_hex) {
        inst_param_len = sizeof(inst_param);
        if (hex_to_bytes(params_hex, inst_param, &inst_param_len)!=0) {
            fprintf(stderr, "Invalid --params hex\n");
            return -1;
        }
    }
    // Parse optional install token
    BYTE installToken[512]; memset(installToken,0,sizeof(installToken));
    BYTE *installTokenPtr = NULL;
    DWORD installTokenLen = 0;
    if (install_token_hex) {
        size_t token_len = sizeof(installToken);
        if (hex_to_bytes(install_token_hex, installToken, &token_len) != 0 || token_len == 0) {
            fprintf(stderr, "Invalid install token hex\n");
            return -1;
        }
        installTokenPtr = installToken;
        installTokenLen = (DWORD)token_len;
    }

    GP211_RECEIPT_DATA rec2; DWORD rec2Avail=0; memset(&rec2,0,sizeof(rec2));
    DWORD privileges = 0x00;
    if (priv_list) {
        if (parse_privileges(priv_list, &privileges) != 0) {
            return -1;
        }
    }

    // Determine which load file AID to use
    PBYTE effectiveLoadFileAID;
    DWORD effectiveLoadFileAIDLength;
    if (install_only) {
        effectiveLoadFileAID = load_file_aid;
        effectiveLoadFileAIDLength = (DWORD)load_file_aid_len;
    } else {
        effectiveLoadFileAID = lfp.loadFileAID.AID;
        effectiveLoadFileAIDLength = lfp.loadFileAID.AIDLength;
    }

    if (applet_len || module_len) {
        if (applet_len == 0 && module_len > 0) {
            // Use module AID also as applet instance AID
            memcpy(applet_aid, module_aid, module_len);
            applet_len = module_len;
        } else if (module_len == 0 && applet_len > 0) {
            // Use applet AID also as module/class AID
            memcpy(module_aid, applet_aid, applet_len);
            module_len = applet_len;
        }

        if (!status_ok(GP211_install_for_install_and_make_selectable(ctx, info, sec,
                effectiveLoadFileAID, effectiveLoadFileAIDLength,
                module_aid, (DWORD)module_len,
                applet_aid, (DWORD)applet_len,
                privileges, v_data_limit, nv_data_limit,
                inst_param_len ? inst_param : NULL, (DWORD)inst_param_len,
                NULL, 0,
                NULL, 0,
                NULL, 0,
                installTokenPtr, installTokenLen, &rec2, &rec2Avail), true)) {
            return -1;
        }
        if (rec2Avail) {
            print_received_receipt("Install", &rec2);
        }
    } else {
        // Neither provided: iterate over all applets from CAP
        if (install_only) {
            fprintf(stderr, "INSTALL: --install-only requires explicit --applet and --module\n");
            return -1;
        }
        int i = 0; int did_any = 0;
        while (lfp.appletAIDs[i].AIDLength) {
            did_any = 1;
            PBYTE aid = (PBYTE)lfp.appletAIDs[i].AID;
            DWORD aidLen = lfp.appletAIDs[i].AIDLength;
            if (!status_ok(GP211_install_for_install_and_make_selectable(ctx, info, sec,
                    effectiveLoadFileAID, effectiveLoadFileAIDLength,
                    aid, aidLen,
                    aid, aidLen,
                    privileges, v_data_limit, nv_data_limit,
                    inst_param_len ? inst_param : NULL, (DWORD)inst_param_len,
                    NULL, 0,
                    NULL, 0,
                    NULL, 0,
                    installTokenPtr, installTokenLen, &rec2, &rec2Avail), false)) {
                fprintf(stderr, "Failed for applet index %d\n", i);
                return -1;
            }
            if (rec2Avail) {
                print_received_receipt("Install", &rec2);
            }
            i++;
        }
        if (!did_any) {
            fprintf(stderr, "INSTALL: No applets found in CAP to install\n");
            return -1;
        }
    }
    return 0;
}

static int cmd_install_sd(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec,
                          int argc, char **argv,
                          BYTE keyset_ver, BYTE key_index, int derivation, const char *sec_level_opt, int verbose,
                          BYTE *baseKeyPtr, BYTE *encKeyPtr, BYTE *macKeyPtr, BYTE *dekKeyPtr, BYTE keyLength,
                          const char *scp_protocol, const char *scp_impl) {
    const char *load_file_hex = NULL;
    const char *module_hex = NULL;
    const char *extradition_here_opt = NULL;
    const char *delete_here_opt = NULL;
    const char *extradition_away_opt = NULL;
    const char *priv_list = NULL;
    int expl_personalized = 0;
    int ai = 0;
    for (; ai < argc; ++ai) {
        if (strcmp(argv[ai], "--load-file") == 0 && ai + 1 < argc) { load_file_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--module") == 0 && ai + 1 < argc) { module_hex = argv[++ai]; }
        else if (strcmp(argv[ai], "--expl-personalized") == 0) { expl_personalized = 1; }
        else if (strcmp(argv[ai], "--priv") == 0 && ai + 1 < argc) { priv_list = argv[++ai]; }
        else if (strcmp(argv[ai], "--extradition-here") == 0 && ai + 1 < argc) { extradition_here_opt = argv[++ai]; }
        else if (strcmp(argv[ai], "--delete-here") == 0 && ai + 1 < argc) { delete_here_opt = argv[++ai]; }
        else if (strcmp(argv[ai], "--extradition-away") == 0 && ai + 1 < argc) { extradition_away_opt = argv[++ai]; }
        else break;
    }
    if (ai >= argc) { fprintf(stderr, "install-sd: missing <instance-aid>\n"); return -1; }
    const char *instance_hex = argv[ai++];
    if (ai < argc) { fprintf(stderr, "install-sd: unexpected argument: %s\n", argv[ai]); return -1; }

    BYTE instance_aid[16]; size_t instance_len = sizeof(instance_aid);
    if (hex_to_bytes(instance_hex, instance_aid, &instance_len) != 0) {
        fprintf(stderr, "install-sd: invalid <instance-aid>\n");
        return -1;
    }

    // List existing issuer security domains to avoid duplicates
    GP211_APPLICATION_DATA isds[64];
    DWORD isds_len = (DWORD)ARRAY_SIZE(isds);
    if (!status_ok(GP211_get_status(ctx, info, sec, GP211_STATUS_ISSUER_SECURITY_DOMAIN,
                                    GP211_STATUS_FORMAT_NEW, isds, NULL, &isds_len), false)) {
        fprintf(stderr, "GET STATUS (issuer security domain) failed\n");
        return -1;
    }
    for (DWORD i = 0; i < isds_len; ++i) {
        if (isds[i].aid.AIDLength == instance_len &&
            memcmp(isds[i].aid.AID, instance_aid, instance_len) == 0) {
            fprintf(stderr, "install-sd: instance AID already exists\n");
            return -1;
        }
    }

    BYTE load_file_aid[16]; size_t load_file_len = sizeof(load_file_aid);
    if (load_file_hex) {
        if (hex_to_bytes(load_file_hex, load_file_aid, &load_file_len) != 0) {
            fprintf(stderr, "install-sd: invalid --load-file AID\n");
            return -1;
        }
    } else {
        GP211_APPLICATION_DATA lfs[256];
        DWORD lfs_len = (DWORD)ARRAY_SIZE(lfs);
        if (!status_ok(GP211_get_status(ctx, info, sec, GP211_STATUS_LOAD_FILES,
                                        GP211_STATUS_FORMAT_NEW, lfs, NULL, &lfs_len), false)) {
            fprintf(stderr, "GET STATUS (load files) failed\n");
            return -1;
        }
        if (!find_default_load_file(lfs, lfs_len, load_file_aid, &load_file_len)) {
            fprintf(stderr, "install-sd: --load-file required (default load file not found)\n");
            return -1;
        }
    }

    BYTE module_aid[16]; size_t module_len = sizeof(module_aid);
    if (module_hex) {
        if (hex_to_bytes(module_hex, module_aid, &module_len) != 0) {
            fprintf(stderr, "install-sd: invalid --module AID\n");
            return -1;
        }
    } else {
        GP211_EXECUTABLE_MODULES_DATA mods[128];
        DWORD mods_len = (DWORD)ARRAY_SIZE(mods);
        if (!status_ok(GP211_get_status(ctx, info, sec, GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES,
                                        GP211_STATUS_FORMAT_NEW, NULL, mods, &mods_len), false)) {
            fprintf(stderr, "GET STATUS (load files and modules) failed\n");
            return -1;
        }
        if (!find_default_module(mods, mods_len, module_aid, &module_len)) {
            fprintf(stderr, "install-sd: --module required (default module not found)\n");
            return -1;
        }
    }

    BYTE accept_here = GP211_SD_ACCEPT_ISD;
    BYTE accept_delete = GP211_SD_ACCEPT_ISD;
    BYTE accept_away = GP211_SD_ACCEPT_ISD;
    if (extradition_here_opt && parse_sd_accept_list(extradition_here_opt, &accept_here) != 0) return -1;
    if (delete_here_opt && parse_sd_accept_list(delete_here_opt, &accept_delete) != 0) return -1;
    if (extradition_away_opt && parse_sd_accept_list(extradition_away_opt, &accept_away) != 0) return -1;

    if (!g_current_scp_set) {
        fprintf(stderr, "install-sd: secure channel not established\n");
        return -1;
    }

    GP211_SD_INSTALL_PARAMS params;
    memset(&params, 0, sizeof(params));
    params.scpEntriesLength = 1;
    params.scpEntries[0].scpIdentifier = g_current_scp;
    params.scpEntries[0].scpImpl = g_current_scp_impl;
    params.personalizedStatePresent = expl_personalized ? 1 : 0;
    params.acceptExtraditionHere[0] = accept_here;
    params.acceptExtraditionHere[1] = accept_here;
    params.acceptExtraditionHereLength = 2;
    params.acceptDeletion = accept_delete;
    params.acceptDeletionLength = 1;
    params.acceptExtraditionAway[0] = accept_away;
    params.acceptExtraditionAway[1] = accept_away;
    params.acceptExtraditionAwayLength = 2;

    BYTE sd_params[256];
    DWORD sd_params_len = (DWORD)sizeof(sd_params);
    if (!status_ok(GP211_build_sd_parameters(&params, sd_params, &sd_params_len), false)) {
        fprintf(stderr, "install-sd: failed to build SD parameters\n");
        return -1;
    }

    GP211_RECEIPT_DATA rec; DWORD recAvail = 0; memset(&rec, 0, sizeof(rec));
    DWORD privileges = GP211_SECURITY_DOMAIN;
    if (priv_list) {
        if (parse_privileges(priv_list, &privileges) != 0) {
            return -1;
        }
        privileges |= GP211_SECURITY_DOMAIN;
    }
    GP211_CARD_RECOGNITION_DATA crd;
    if (!status_ok(GP211_get_card_recognition_data(ctx, info, sec, &crd), false)) {
        fprintf(stderr, "install-sd: GP211_get_card_recognition_data failed\n");
        return -1;
    }

    if (!status_ok(GP211_install_for_install_and_make_selectable(ctx, info, sec,
            load_file_aid, (DWORD)load_file_len,
            module_aid, (DWORD)module_len,
            instance_aid, (DWORD)instance_len,
            privileges, 0, 0,
            NULL, 0,
            sd_params, sd_params_len,
            NULL, 0,
            NULL, 0,
            NULL, 0,
            &rec, &recAvail), true)) {
        return -1;
    }
    if (recAvail) {
        print_received_receipt("Install SD", &rec);
    }

    // TODO: add card data
    // // Select the new security domain
    // if (!status_ok(OPGP_select_application(ctx, info, sec, instance_aid, (DWORD)instance_len))) {
    //     fprintf(stderr, "install-sd: OPGP_select_application failed for the new SD\n");
    //     return -1;
    // }
    //
    // // Re-establish secure channel with the newly selected SD (using issuer SD keys)
    // if (mutual_auth(ctx, info, sec, keyset_ver, key_index, derivation, sec_level_opt, verbose,
    //                 baseKeyPtr, encKeyPtr, macKeyPtr, dekKeyPtr, keyLength,
    //                 scp_protocol, scp_impl) != 0) {
    //     fprintf(stderr, "install-sd: mutual authentication failed\n");
    //     return -1;
    // }
    //
    // crd.scp[0] = g_current_scp;
    // crd.scpImpl[0] = g_current_scp_impl;
    // crd.scpLength = 1;
    //
    // crd.cardConfigurationDetailsOid[0] = '\0';
    // crd.cardChipDetailsOid[0] = '\0';
    // crd.issuerSecurityDomainsTrustPointCertificateInformationOid[0] = '\0';
    // crd.issuerSecurityDomainCertificateInformationOid[0] = '\0';
    //
    // BYTE crd_buf[1024];
    // DWORD crd_buf_len = (DWORD)sizeof(crd_buf);
    // if (!status_ok(GP211_build_card_recognition_data(&crd, crd_buf, &crd_buf_len))) {
    //     fprintf(stderr, "install-sd: GP211_build_card_recognition_data failed\n");
    //     return -1;
    // }
    //
    // if (!status_ok(GP211_store_data(ctx, info, sec, STORE_DATA_ENCRYPTION_NO_INFORMATION,
    //                                STORE_DATA_FORMAT_BER_TLV, false, crd_buf, crd_buf_len))) {
    //     fprintf(stderr, "install-sd: GP211_store_data failed\n");
    //     return -1;
    // }

    return 0;
}

static int cmd_delete(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    const char *aid_hex = NULL;
    const char *token_hex = NULL;
    BYTE delete_token[255];
    BYTE *delete_token_ptr = NULL;
    DWORD delete_token_len = 0;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--token") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "delete: --token requires <hex>\n");
                return -1;
            }
            token_hex = argv[++i];
        }
        else if (argv[i][0] == '-') {
            fprintf(stderr, "delete: unknown option %s\n", argv[i]);
            return -1;
        }
        else if (aid_hex == NULL) {
            aid_hex = argv[i];
        }
        else {
            fprintf(stderr, "delete: unexpected argument %s\n", argv[i]);
            return -1;
        }
    }

    if (!aid_hex) { fprintf(stderr, "delete: missing <AIDhex>\n"); return -1; }
    unsigned char aidb[16]; size_t alen=sizeof(aidb);
    if (hex_to_bytes(aid_hex, aidb, &alen)!=0) { fprintf(stderr, "Invalid AID hex\n"); return -1; }

    if (token_hex != NULL) {
        size_t token_len = sizeof(delete_token);
        if (hex_to_bytes(token_hex, delete_token, &token_len) != 0 || token_len == 0) {
            fprintf(stderr, "delete: invalid --token hex\n");
            return -1;
        }
        delete_token_ptr = delete_token;
        delete_token_len = (DWORD)token_len;
    }

    OPGP_AID a; memset(&a,0,sizeof(a)); a.AIDLength=(BYTE)alen; memcpy(a.AID, aidb, alen);
    GP211_RECEIPT_DATA rec; DWORD recAvail = 0; memset(&rec,0,sizeof(rec));
    if (!status_ok(GP211_delete_application(ctx, info, sec, &a, 1, &rec, &recAvail, delete_token_ptr, delete_token_len), true)) {
        return -1;
    }
    if (recAvail) {
        print_received_receipt("Delete", &rec);
    }
    return 0;
}

static int cmd_move(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    const char *token_hex = NULL;
    const char *app_aid_hex = NULL;
    const char *sd_aid_hex = NULL;
    BYTE token[512];
    BYTE *token_ptr = NULL;
    DWORD token_len = 0;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--token") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "move: --token requires <hex>\n");
                return -1;
            }
            token_hex = argv[++i];
        }
        else if (argv[i][0] == '-') {
            fprintf(stderr, "move: unknown option %s\n", argv[i]);
            return -1;
        }
        else if (app_aid_hex == NULL) {
            app_aid_hex = argv[i];
        }
        else if (sd_aid_hex == NULL) {
            sd_aid_hex = argv[i];
        }
        else {
            fprintf(stderr, "move: unexpected argument %s\n", argv[i]);
            return -1;
        }
    }

    if (app_aid_hex == NULL || sd_aid_hex == NULL) {
        fprintf(stderr, "move: missing parameters <applicationAID> <securityDomainAID>\n");
        return -1;
    }

    unsigned char app_aid_bytes[16];
    size_t app_aid_len = sizeof(app_aid_bytes);
    if (hex_to_bytes(app_aid_hex, app_aid_bytes, &app_aid_len) != 0) {
        fprintf(stderr, "move: invalid applicationAID hex\n");
        return -1;
    }

    unsigned char sd_aid_bytes[16];
    size_t sd_aid_len = sizeof(sd_aid_bytes);
    if (hex_to_bytes(sd_aid_hex, sd_aid_bytes, &sd_aid_len) != 0) {
        fprintf(stderr, "move: invalid securityDomainAID hex\n");
        return -1;
    }

    if (token_hex != NULL) {
        size_t token_size = sizeof(token);
        if (hex_to_bytes(token_hex, token, &token_size) != 0 || token_size == 0) {
            fprintf(stderr, "move: invalid --token hex\n");
            return -1;
        }
        token_ptr = token;
        token_len = (DWORD)token_size;
    }

    GP211_RECEIPT_DATA rec;
    DWORD recAvail = 0;
    memset(&rec, 0, sizeof(rec));

    if (!status_ok(GP211_install_for_extradition(ctx, info, sec,
                                               sd_aid_bytes, (DWORD)sd_aid_len,
                                               app_aid_bytes, (DWORD)app_aid_len,
                                               token_ptr, token_len, &rec, &recAvail), true)) {
        return -1;
    }
    if (recAvail) {
        print_received_receipt("Move", &rec);
    }
    return 0;
}

static int cmd_verify_delete_receipt(int argc, char **argv) {
    const char *cmd = "verify-delete-receipt";
    const char *type_opt = "aes";
    const char *key_hex = NULL;
    const char *pem_spec = NULL;
    const char *aid_hex = NULL;
    const char *rapdu_hex = NULL;
    BYTE aid[16];
    size_t aid_len = sizeof(aid);
    GP211_RECEIPT_DATA receiptData;
    RECEIPT_VERIFY_KEY_INPUT keyInput;
    OPGP_ERROR_STATUS s;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) type_opt = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key_hex = argv[++i];
        else if (strcmp(argv[i], "--pem") == 0 && i + 1 < argc) pem_spec = argv[++i];
        else if (strcmp(argv[i], "--aid") == 0 && i + 1 < argc) aid_hex = argv[++i];
        else if (argv[i][0] == '-') {
            fprintf(stderr, "%s: unknown option %s\n", cmd, argv[i]);
            return -1;
        } else {
            if (i != argc - 1 || rapdu_hex != NULL) {
                fprintf(stderr, "%s: response APDU must be the last positional parameter\n", cmd);
                return -1;
            }
            rapdu_hex = argv[i];
        }
    }
    if (!rapdu_hex) {
        fprintf(stderr, "%s: missing <response-apdu-hex>\n", cmd);
        return -1;
    }
    if (parse_required_hex_field(cmd, "--aid <AIDhex>", aid_hex, aid, &aid_len) != 0) return -1;
    if (parse_receipt_verify_key(cmd, type_opt, key_hex, pem_spec, &keyInput) != 0) return -1;
    if (parse_receipt_from_rapdu_hex(cmd, rapdu_hex, &receiptData) != 0) return -1;
    print_receipt_confirmation_data(&receiptData);

    s = GP211_validate_delete_receipt(keyInput.receiptKeyPtr, keyInput.receiptKeyLength, receiptData,
                                      aid, (DWORD)aid_len,
                                      keyInput.receiptKeyType, keyInput.pemKeyFileName, keyInput.passPhrasePtr);
    if (!status_ok(s, true)) return -1;
    printf("%s: receipt verification successful\n", cmd);
    return 0;
}

static int cmd_verify_load_receipt(int argc, char **argv) {
    const char *cmd = "verify-load-receipt";
    const char *type_opt = "aes";
    const char *key_hex = NULL;
    const char *pem_spec = NULL;
    const char *load_file_hex = NULL;
    const char *sd_hex = NULL;
    const char *rapdu_hex = NULL;
    BYTE load_file_aid[16];
    size_t load_file_aid_len = sizeof(load_file_aid);
    BYTE sd_aid[16];
    size_t sd_aid_len = sizeof(sd_aid);
    GP211_RECEIPT_DATA receiptData;
    RECEIPT_VERIFY_KEY_INPUT keyInput;
    OPGP_ERROR_STATUS s;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) type_opt = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key_hex = argv[++i];
        else if (strcmp(argv[i], "--pem") == 0 && i + 1 < argc) pem_spec = argv[++i];
        else if (strcmp(argv[i], "--load-file") == 0 && i + 1 < argc) load_file_hex = argv[++i];
        else if (strcmp(argv[i], "--sd") == 0 && i + 1 < argc) sd_hex = argv[++i];
        else if (argv[i][0] == '-') {
            fprintf(stderr, "%s: unknown option %s\n", cmd, argv[i]);
            return -1;
        } else {
            if (i != argc - 1 || rapdu_hex != NULL) {
                fprintf(stderr, "%s: response APDU must be the last positional parameter\n", cmd);
                return -1;
            }
            rapdu_hex = argv[i];
        }
    }
    if (!rapdu_hex) {
        fprintf(stderr, "%s: missing <response-apdu-hex>\n", cmd);
        return -1;
    }
    if (parse_required_hex_field(cmd, "--load-file <AIDhex>", load_file_hex, load_file_aid, &load_file_aid_len) != 0) return -1;
    if (parse_required_hex_field(cmd, "--sd <AIDhex>", sd_hex, sd_aid, &sd_aid_len) != 0) return -1;
    if (parse_receipt_verify_key(cmd, type_opt, key_hex, pem_spec, &keyInput) != 0) return -1;
    if (parse_receipt_from_rapdu_hex(cmd, rapdu_hex, &receiptData) != 0) return -1;
    print_receipt_confirmation_data(&receiptData);

    s = GP211_validate_load_receipt(keyInput.receiptKeyPtr, keyInput.receiptKeyLength, receiptData,
                                    load_file_aid, (DWORD)load_file_aid_len,
                                    sd_aid, (DWORD)sd_aid_len,
                                    keyInput.receiptKeyType, keyInput.pemKeyFileName, keyInput.passPhrasePtr);
    if (!status_ok(s, true)) return -1;
    printf("%s: receipt verification successful\n", cmd);
    return 0;
}

static int cmd_verify_install_receipt(int argc, char **argv) {
    const char *cmd = "verify-install-receipt";
    const char *type_opt = "aes";
    const char *key_hex = NULL;
    const char *pem_spec = NULL;
    const char *load_file_hex = NULL;
    const char *aid_hex = NULL;
    const char *rapdu_hex = NULL;
    BYTE load_file_aid[16];
    size_t load_file_aid_len = sizeof(load_file_aid);
    BYTE aid[16];
    size_t aid_len = sizeof(aid);
    GP211_RECEIPT_DATA receiptData;
    RECEIPT_VERIFY_KEY_INPUT keyInput;
    OPGP_ERROR_STATUS s;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) type_opt = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key_hex = argv[++i];
        else if (strcmp(argv[i], "--pem") == 0 && i + 1 < argc) pem_spec = argv[++i];
        else if (strcmp(argv[i], "--load-file") == 0 && i + 1 < argc) load_file_hex = argv[++i];
        else if (strcmp(argv[i], "--aid") == 0 && i + 1 < argc) aid_hex = argv[++i];
        else if (argv[i][0] == '-') {
            fprintf(stderr, "%s: unknown option %s\n", cmd, argv[i]);
            return -1;
        } else {
            if (i != argc - 1 || rapdu_hex != NULL) {
                fprintf(stderr, "%s: response APDU must be the last positional parameter\n", cmd);
                return -1;
            }
            rapdu_hex = argv[i];
        }
    }
    if (!rapdu_hex) {
        fprintf(stderr, "%s: missing <response-apdu-hex>\n", cmd);
        return -1;
    }
    if (parse_required_hex_field(cmd, "--load-file <AIDhex>", load_file_hex, load_file_aid, &load_file_aid_len) != 0) return -1;
    if (parse_required_hex_field(cmd, "--aid <AIDhex>", aid_hex, aid, &aid_len) != 0) return -1;
    if (parse_receipt_verify_key(cmd, type_opt, key_hex, pem_spec, &keyInput) != 0) return -1;
    if (parse_receipt_from_rapdu_hex(cmd, rapdu_hex, &receiptData) != 0) return -1;
    print_receipt_confirmation_data(&receiptData);

    s = GP211_validate_install_receipt(keyInput.receiptKeyPtr, keyInput.receiptKeyLength, receiptData,
                                       load_file_aid, (DWORD)load_file_aid_len,
                                       aid, (DWORD)aid_len,
                                       keyInput.receiptKeyType, keyInput.pemKeyFileName, keyInput.passPhrasePtr);
    if (!status_ok(s, true)) return -1;
    printf("%s: receipt verification successful\n", cmd);
    return 0;
}

static int cmd_verify_move_receipt(int argc, char **argv) {
    const char *cmd = "verify-move-receipt";
    const char *type_opt = "aes";
    const char *key_hex = NULL;
    const char *pem_spec = NULL;
    const char *aid_hex = NULL;
    const char *oldsd_hex = NULL;
    const char *newsd_hex = NULL;
    const char *rapdu_hex = NULL;
    BYTE aid[16];
    size_t aid_len = sizeof(aid);
    BYTE oldsd[16];
    size_t oldsd_len = sizeof(oldsd);
    BYTE newsd[16];
    size_t newsd_len = sizeof(newsd);
    GP211_RECEIPT_DATA receiptData;
    RECEIPT_VERIFY_KEY_INPUT keyInput;
    OPGP_ERROR_STATUS s;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) type_opt = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key_hex = argv[++i];
        else if (strcmp(argv[i], "--pem") == 0 && i + 1 < argc) pem_spec = argv[++i];
        else if (strcmp(argv[i], "--aid") == 0 && i + 1 < argc) aid_hex = argv[++i];
        else if (strcmp(argv[i], "--oldsd") == 0 && i + 1 < argc) oldsd_hex = argv[++i];
        else if (strcmp(argv[i], "--newsd") == 0 && i + 1 < argc) newsd_hex = argv[++i];
        else if (argv[i][0] == '-') {
            fprintf(stderr, "%s: unknown option %s\n", cmd, argv[i]);
            return -1;
        } else {
            if (i != argc - 1 || rapdu_hex != NULL) {
                fprintf(stderr, "%s: response APDU must be the last positional parameter\n", cmd);
                return -1;
            }
            rapdu_hex = argv[i];
        }
    }
    if (!rapdu_hex) {
        fprintf(stderr, "%s: missing <response-apdu-hex>\n", cmd);
        return -1;
    }
    if (parse_required_hex_field(cmd, "--aid <AIDhex>", aid_hex, aid, &aid_len) != 0) return -1;
    if (parse_required_hex_field(cmd, "--oldsd <AIDhex>", oldsd_hex, oldsd, &oldsd_len) != 0) return -1;
    if (parse_required_hex_field(cmd, "--newsd <AIDhex>", newsd_hex, newsd, &newsd_len) != 0) return -1;
    if (parse_receipt_verify_key(cmd, type_opt, key_hex, pem_spec, &keyInput) != 0) return -1;
    if (parse_receipt_from_rapdu_hex(cmd, rapdu_hex, &receiptData) != 0) return -1;
    print_receipt_confirmation_data(&receiptData);

    s = GP211_validate_extradition_receipt(keyInput.receiptKeyPtr, keyInput.receiptKeyLength, receiptData,
                                           oldsd, (DWORD)oldsd_len,
                                           newsd, (DWORD)newsd_len,
                                           aid, (DWORD)aid_len,
                                           keyInput.receiptKeyType, keyInput.pemKeyFileName, keyInput.passPhrasePtr);
    if (!status_ok(s, true)) return -1;
    printf("%s: receipt verification successful\n", cmd);
    return 0;
}

static int cmd_verify_registry_update_receipt(int argc, char **argv) {
    const char *cmd = "verify-registry-update-receipt";
    const char *type_opt = "aes";
    const char *key_hex = NULL;
    const char *pem_spec = NULL;
    const char *aid_hex = NULL;
    const char *oldsd_hex = NULL;
    const char *newsd_hex = NULL;
    const char *priv_list = NULL;
    const char *rapdu_hex = NULL;
    BYTE aid[16];
    size_t aid_len = sizeof(aid);
    BYTE oldsd[16];
    size_t oldsd_len = sizeof(oldsd);
    BYTE newsd[16];
    size_t newsd_len = sizeof(newsd);
    DWORD privileges = 0;
    GP211_RECEIPT_DATA receiptData;
    RECEIPT_VERIFY_KEY_INPUT keyInput;
    OPGP_ERROR_STATUS s;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) type_opt = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key_hex = argv[++i];
        else if (strcmp(argv[i], "--pem") == 0 && i + 1 < argc) pem_spec = argv[++i];
        else if (strcmp(argv[i], "--aid") == 0 && i + 1 < argc) aid_hex = argv[++i];
        else if (strcmp(argv[i], "--oldsd") == 0 && i + 1 < argc) oldsd_hex = argv[++i];
        else if (strcmp(argv[i], "--newsd") == 0 && i + 1 < argc) newsd_hex = argv[++i];
        else if (strcmp(argv[i], "--priv") == 0 && i + 1 < argc) priv_list = argv[++i];
        else if (argv[i][0] == '-') {
            fprintf(stderr, "%s: unknown option %s\n", cmd, argv[i]);
            return -1;
        } else {
            if (i != argc - 1 || rapdu_hex != NULL) {
                fprintf(stderr, "%s: response APDU must be the last positional parameter\n", cmd);
                return -1;
            }
            rapdu_hex = argv[i];
        }
    }
    if (!rapdu_hex) {
        fprintf(stderr, "%s: missing <response-apdu-hex>\n", cmd);
        return -1;
    }
    if (!priv_list) {
        fprintf(stderr, "%s: missing --priv <list>\n", cmd);
        return -1;
    }
    if (parse_required_hex_field(cmd, "--aid <AIDhex>", aid_hex, aid, &aid_len) != 0) return -1;
    if (parse_required_hex_field(cmd, "--oldsd <AIDhex>", oldsd_hex, oldsd, &oldsd_len) != 0) return -1;
    if (parse_required_hex_field(cmd, "--newsd <AIDhex>", newsd_hex, newsd, &newsd_len) != 0) return -1;
    if (parse_privileges(priv_list, &privileges) != 0) return -1;
    if (parse_receipt_verify_key(cmd, type_opt, key_hex, pem_spec, &keyInput) != 0) return -1;
    if (parse_receipt_from_rapdu_hex(cmd, rapdu_hex, &receiptData) != 0) return -1;
    print_receipt_confirmation_data(&receiptData);

    s = GP211_validate_registry_update_receipt(keyInput.receiptKeyPtr, keyInput.receiptKeyLength, receiptData,
                                               oldsd, (DWORD)oldsd_len,
                                               aid, (DWORD)aid_len,
                                               newsd, (DWORD)newsd_len,
                                               privileges,
                                               NULL, 0,
                                               keyInput.receiptKeyType, keyInput.pemKeyFileName, keyInput.passPhrasePtr);
    if (!status_ok(s, true)) return -1;
    printf("%s: receipt verification successful\n", cmd);
    return 0;
}

static int cmd_put_key(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    BYTE setVer=0, idx=0, newSetVer=0;
    int kvSet=0, newKvSet=0;
    const char *type="aes"; const char *hexkey=NULL; const char *pem=NULL; char *pass=NULL; const char *eccCurve="explicit";
    for (int i=0;i<argc;i++) {
        if (strcmp(argv[i], "--kv")==0 && i+1<argc) { setVer=(BYTE)parse_int(argv[++i]); kvSet=1; }
        else if (strcmp(argv[i], "--idx")==0 && i+1<argc) idx=(BYTE)parse_int(argv[++i]);
        else if (strcmp(argv[i], "--new-kv")==0 && i+1<argc) { newSetVer=(BYTE)parse_int(argv[++i]); newKvSet=1; }
        else if (strcmp(argv[i], "--type")==0 && i+1<argc) type=argv[++i];
        else if (strcmp(argv[i], "--key")==0 && i+1<argc) hexkey=argv[++i];
        else if (strcmp(argv[i], "--pem")==0 && i+1<argc) { pem=argv[++i]; char *c=strchr((char*)pem, ':'); if (c){ *c='\0'; pass=c+1; } }
        else if ((strcmp(argv[i], "--ecc-curve")==0 || strcmp(argv[i], "--ecc-params")==0) && i+1<argc) eccCurve=argv[++i];
    }
    if (!kvSet) { fprintf(stderr, "put-key: missing --kv <ver>\n"); return -1; }
    if (!newKvSet) { fprintf(stderr, "put-key: missing --new-kv <ver>\n"); return -1; }
    if (strcmp(type, "rsa")==0) {
        if (!pem) { fprintf(stderr, "put-key rsa: --pem <file>[:pass] required\n"); return -1; }
        TCHAR pem_t[MAX_PATH_BUF];
        OPGP_STRING pem_opgp = NULL;
        if (to_opgp_string(pem, pem_t, ARRAY_SIZE(pem_t)) != 0) {
            fprintf(stderr, "put-key: pem path too long\n");
            return -1;
        }
        pem_opgp = pem_t;
        if (!status_ok(GP211_put_rsa_key(ctx, info, sec, setVer, idx, newSetVer, pem_opgp, pass), true)) {
            return -1;
        }
        return 0;
    }
    if (strcmp(type, "ecc")==0) {
        if (!pem) { fprintf(stderr, "put-key ecc: --pem <file>[:pass] required\n"); return -1; }
        TCHAR pem_t[MAX_PATH_BUF];
        OPGP_STRING pem_opgp = NULL;
        if (to_opgp_string(pem, pem_t, ARRAY_SIZE(pem_t)) != 0) {
            fprintf(stderr, "put-key: pem path too long\n");
            return -1;
        }
        pem_opgp = pem_t;
        if (strcmp(eccCurve, "reference") == 0 || strcmp(eccCurve, "ref") == 0 || strcmp(eccCurve, "referenced") == 0) {
            if (!status_ok(GP211_put_ecc_key_with_curve_parameter_reference(ctx, info, sec, setVer, idx, newSetVer, pem_opgp, pass), true)) {
                return -1;
            }
        } else if (strcmp(eccCurve, "explicit") == 0 || strcmp(eccCurve, "full") == 0 || strcmp(eccCurve, "params") == 0) {
            if (!status_ok(GP211_put_ecc_key(ctx, info, sec, setVer, idx, newSetVer, pem_opgp, pass), true)) {
                return -1;
            }
        } else {
            fprintf(stderr, "put-key ecc: unsupported --ecc-curve '%s' (use reference|explicit)\n", eccCurve);
            return -1;
        }
        return 0;
    }
    if (strcmp(type, "ecc-private")==0 || strcmp(type, "ecc-priv")==0) {
        if (!hexkey) { fprintf(stderr, "put-key ecc-private: --key <hex> required\n"); return -1; }
        unsigned char k[32]; size_t klen=sizeof(k);
        if (hex_to_bytes(hexkey, k, &klen)!=0 || klen!=32) {
            fprintf(stderr, "put-key ecc-private: key must be 32 bytes hex for P-256\n");
            return -1;
        }
        if (!status_ok(GP211_put_ecc_private_key_with_curve_parameter_reference(ctx, info, sec, setVer, idx, newSetVer, k, (DWORD)klen), true)) {
            return -1;
        }
        return 0;
    }
    if (strcmp(type, "aes")==0) {
        if (!hexkey) { fprintf(stderr, "put-key aes: --key <hex> required\n"); return -1; }
        unsigned char k[32]; size_t klen=sizeof(k);
        if (hex_to_bytes(hexkey, k, &klen)!=0 || (klen!=16 && klen!=24 && klen!=32)) {
            fprintf(stderr, "Invalid AES key len\n");
            return -1;
        }
        if (!status_ok(GP211_put_aes_key(ctx, info, sec, setVer, idx, newSetVer, k, (DWORD)klen), true)) {
            return -1;
        }
        return 0;
    }
    if (strcmp(type, "3des")==0) {
        if (!hexkey) { fprintf(stderr, "put-key 3des: --key <hex> required\n"); return -1; }
        unsigned char k[16]; size_t klen=sizeof(k);
        if (hex_to_bytes(hexkey, k, &klen)!=0 || klen!=16) {
            fprintf(stderr, "3DES key must be 16 hex bytes\n");
            return -1;
        }
        if (!status_ok(GP211_put_3des_key(ctx, info, sec, setVer, idx, newSetVer, k), true)) {
            return -1;
        }
        return 0;
    }
    fprintf(stderr, "put-key: unsupported --type '%s' (use 3des|aes|rsa|ecc|ecc-private). For Secure Channel keys use put-sc-keys.\n", type);
    return -1;
}

static int cmd_put_auth(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    BYTE setVer=1, newSetVer=1; const char *base=NULL, *enc=NULL, *mac=NULL, *dek=NULL;
    const char *type="aes", *derive="none";
    for (int i=0;i<argc;i++) {
        if (strcmp(argv[i], "--kv")==0 && i+1<argc) setVer=(BYTE)parse_int(argv[++i]);
        else if (strcmp(argv[i], "--new-kv")==0 && i+1<argc) newSetVer=(BYTE)parse_int(argv[++i]);
        else if (strcmp(argv[i], "--base")==0 && i+1<argc) base=argv[++i];
        else if (strcmp(argv[i], "--key")==0 && i+1<argc) base=argv[++i];
        else if (strcmp(argv[i], "--enc")==0 && i+1<argc) enc=argv[++i];
        else if (strcmp(argv[i], "--mac")==0 && i+1<argc) mac=argv[++i];
        else if (strcmp(argv[i], "--dek")==0 && i+1<argc) dek=argv[++i];
        else if (strcmp(argv[i], "--type")==0 && i+1<argc) type=argv[++i];
        else if (strcmp(argv[i], "--derive")==0 && i+1<argc) derive=argv[++i];
    }
    if (base && (enc || mac || dek)) {
        fprintf(stderr, "put-auth: use either --base/--key OR all of --enc/--mac/--dek\n");
        return -1;
    }
    if (!base && !(enc && mac && dek)) {
        fprintf(stderr, "put-auth: specify either --base/--key <hex> or --enc/--mac/--dek <hex>\n");
        return -1;
    }

    // Determine key type
    BYTE keyType = GP211_KEY_TYPE_AES;
    if (strcmp(type, "3des")==0) {
        keyType = GP211_KEY_TYPE_DES;
    } else if (strcmp(type, "aes")==0) {
        keyType = GP211_KEY_TYPE_AES;
    } else {
        fprintf(stderr, "put-auth: unsupported --type '%s' (use aes|3des)\n", type);
        return -1;
    }

    // Determine derivation method
    BYTE derivation = OPGP_DERIVATION_METHOD_NONE;
    if (strcmp(derive, "emv")==0) {
        derivation = OPGP_DERIVATION_METHOD_EMV_CPS11;
    } else if (strcmp(derive, "visa2")==0) {
        derivation = OPGP_DERIVATION_METHOD_VISA2;
    } else if (strcmp(derive, "none")!=0) {
        fprintf(stderr, "put-auth: unsupported --derive '%s' (use none|emv|visa2)\n", derive);
        return -1;
    }

    // Validate derivation usage
    if ((enc || mac || dek) && derivation != OPGP_DERIVATION_METHOD_NONE) {
        fprintf(stderr, "put-auth: --derive cannot be used when --enc/--mac/--dek are provided\n");
        return -1;
    }

    if (base) {
        unsigned char b[32]; size_t blen=sizeof(b);
        unsigned char master[32] = {0};
        unsigned char s_enc_key[32] = {0};
        unsigned char s_mac_key[32] = {0};
        unsigned char dek_key[32] = {0};
        BYTE *putBaseKey = NULL;
        BYTE *putSEnc = NULL;
        BYTE *putSMac = NULL;
        BYTE *putDek = NULL;
        bool requiresThreeKeys = !(sec->secureChannelProtocol == GP211_SCP02 &&
                                   (sec->secureChannelProtocolImpl & 0x01) == 0);
        if (hex_to_bytes(base, b, &blen)!=0 || (blen!=16 && blen!=24 && blen!=32)) {
            fprintf(stderr, "Invalid base key length\n");
            return -1;
        }

        // Apply key derivation if requested
        if (derivation == OPGP_DERIVATION_METHOD_EMV_CPS11) {
            memcpy(master, b, blen);
            OPGP_ERROR_STATUS s = GP211_EMV_CPS11_derive_keys(ctx, info, sec, master, s_enc_key, s_mac_key, dek_key);
            if (!status_ok(s, true)) {
                fprintf(stderr, "EMV CPS11 key derivation failed\n");
                return -1;
            }
            putSEnc = s_enc_key;
            putSMac = s_mac_key;
            putDek = dek_key;
        } else if (derivation == OPGP_DERIVATION_METHOD_VISA2) {
            if (g_selected_isd_len == 0) {
                fprintf(stderr, "VISA2 derivation requires a selected ISD AID\n");
                return -1;
            }
            memcpy(master, b, blen);
            OPGP_ERROR_STATUS s = GP211_VISA2_derive_keys(ctx, info, sec, g_selected_isd, g_selected_isd_len, master,
                                                          s_enc_key, s_mac_key, dek_key);
            if (!status_ok(s, true)) {
                fprintf(stderr, "VISA2 key derivation failed\n");
                return -1;
            }
            putSEnc = s_enc_key;
            putSMac = s_mac_key;
            putDek = dek_key;
        } else if (requiresThreeKeys) {
            // SCPs that require explicit S-ENC/S-MAC/DEK: reuse the provided single key for all three.
            memcpy(s_enc_key, b, blen);
            memcpy(s_mac_key, b, blen);
            memcpy(dek_key, b, blen);
            putSEnc = s_enc_key;
            putSMac = s_mac_key;
            putDek = dek_key;
        } else {
            // SCP02 variants that use a single base key.
            putBaseKey = b;
        }

        OPGP_ERROR_STATUS s = GP211_put_secure_channel_keys(ctx, info, sec, setVer, newSetVer,
                                                            putBaseKey, putSEnc, putSMac, putDek,
                                                            (DWORD)blen, keyType);
        if (!status_ok(s, true)) {
            return -1;
        }
        return 0;
    }
    unsigned char se[32], sm[32], dk[32]; size_t el=sizeof(se), ml=sizeof(sm), dl=sizeof(dk);
    if (hex_to_bytes(enc, se, &el)!=0 || hex_to_bytes(mac, sm, &ml)!=0 || hex_to_bytes(dek, dk, &dl)!=0) {
        fprintf(stderr, "Invalid hex for ENC/MAC/DEK\n");
        return -1;
    }
    if (!((el==ml && ml==dl) && (el==16 || el==24 || el==32))) {
        fprintf(stderr, "Keys must have equal length of 16/24/32 bytes\n");
        return -1;
    }

    OPGP_ERROR_STATUS s = GP211_put_secure_channel_keys(ctx, info, sec, setVer, newSetVer, NULL, se, sm, dk, (DWORD)el, keyType);
    if (!status_ok(s, true)) {
        return -1;
    }
    return 0;
}

static int cmd_put_dm_token(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    BYTE setVer=0, newSetVer=GP211_KEY_VERSION_TOKEN_VERIFICATION;
    const char *tokenType="rsa";
    const char *pem=NULL;
    char *pass=NULL;

    for (int i=0; i<argc; i++) {
        if (strcmp(argv[i], "--kv")==0 && i+1<argc) {
            setVer = (BYTE)parse_int(argv[++i]);
        }
        else if (strcmp(argv[i], "--new-kv")==0 && i+1<argc) {
            newSetVer = (BYTE)parse_int(argv[++i]);
        }
        else if (strcmp(argv[i], "--token-type")==0 && i+1<argc) {
            tokenType = argv[++i];
        }
        else if (!pem) {
            pem = argv[i];
            char *c = strchr((char*)pem, ':');
            if (c) {
                *c = '\0';
                pass = c + 1;
            }
        }
    }

    if (!pem) {
        fprintf(stderr, "put-dm-token: missing PEM file path\n");
        return -1;
    }

    BYTE tokenKeyType;
    if (strcmp(tokenType, "rsa")==0) {
        tokenKeyType = GP211_KEY_TYPE_RSA;
    } else if (strcmp(tokenType, "ecc")==0) {
        tokenKeyType = GP211_KEY_TYPE_ECC;
    } else {
        fprintf(stderr, "put-dm-token: unsupported --token-type '%s' (use rsa|ecc)\n", tokenType);
        return -1;
    }

    TCHAR pem_t[MAX_PATH_BUF];
    if (to_opgp_string(pem, pem_t, ARRAY_SIZE(pem_t)) != 0) {
        fprintf(stderr, "put-dm-token: pem path too long\n");
        return -1;
    }

    if (!status_ok(GP211_put_delegated_management_token_keys(ctx, info, sec,
                                                              setVer, newSetVer,
                                                              pem_t, pass,
                                                              tokenKeyType), true)) {
        return -1;
    }
    return 0;
}

static int cmd_put_dm_receipt(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    BYTE setVer=0, newSetVer=(BYTE)GP211_KEY_VERSION_RECEIPT_GENERATION;
    const char *receiptType="aes";
    const char *receiptKeyHex=NULL;
    BYTE receiptKey[32];
    DWORD keyLength=0;

    for (int i=0; i<argc; i++) {
        if (strcmp(argv[i], "--kv")==0 && i+1<argc) {
            setVer = (BYTE)parse_int(argv[++i]);
        }
        else if (strcmp(argv[i], "--new-kv")==0 && i+1<argc) {
            newSetVer = (BYTE)parse_int(argv[++i]);
        }
        else if (strcmp(argv[i], "--receipt-type")==0 && i+1<argc) {
            receiptType = argv[++i];
        }
        else if (!receiptKeyHex) {
            receiptKeyHex = argv[i];
        }
    }

    if (!receiptKeyHex) {
        fprintf(stderr, "put-dm-receipt: missing receipt key hex\n");
        return -1;
    }

    size_t len = sizeof(receiptKey);
    if (hex_to_bytes(receiptKeyHex, receiptKey, &len) != 0) {
        fprintf(stderr, "put-dm-receipt: invalid receipt key hex\n");
        return -1;
    }
    keyLength = (DWORD)len;

    BYTE receiptKeyType = 0;
    if (strcmp(receiptType, "aes")==0) {
        receiptKeyType = 0x88; // GP211_KEY_TYPE_AES
    } else if (strcmp(receiptType, "des")==0) {
        receiptKeyType = 0x80; // GP211_KEY_TYPE_DES
    } else {
        fprintf(stderr, "put-dm-receipt: unsupported --receipt-type '%s' (use aes|des)\n", receiptType);
        return -1;
    }

    if (!status_ok(GP211_put_delegated_management_receipt_keys(ctx, info, sec,
                                                                setVer, newSetVer,
                                                                receiptKey, keyLength, receiptKeyType), true)) {
        return -1;
    }
    return 0;
}

static int cmd_put_dap_key(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    BYTE setVer = 0;
    BYTE newSetVer = (BYTE)GP211_KEY_VERSION_DAP_VERIFICATION;
    const char *keyTypeStr = "ecc";
    const char *keyValue = NULL;
    BYTE keyType = 0;
    BYTE symmetricKey[32];
    DWORD keyLength = 0;
    TCHAR pem_t[MAX_PATH_BUF];
    OPGP_STRING pem_opgp = NULL;
    char *pass = NULL;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--kv") == 0 && i + 1 < argc) {
            setVer = (BYTE)parse_int(argv[++i]);
        } else if (strcmp(argv[i], "--new-kv") == 0 && i + 1 < argc) {
            newSetVer = (BYTE)parse_int(argv[++i]);
        } else if (strcmp(argv[i], "--key-type") == 0 && i + 1 < argc) {
            keyTypeStr = argv[++i];
        } else if (!keyValue) {
            keyValue = argv[i];
        }
    }

    if (!keyValue) {
        fprintf(stderr, "put-dap-key: missing key value (<pem-file>[:pass] or <key-hex>)\n");
        return -1;
    }

    if (strcmp(keyTypeStr, "ecc") == 0) {
        keyType = GP211_KEY_TYPE_ECC;
    } else if (strcmp(keyTypeStr, "rsa") == 0) {
        keyType = GP211_KEY_TYPE_RSA;
    } else if (strcmp(keyTypeStr, "aes") == 0) {
        keyType = GP211_KEY_TYPE_AES;
    } else if (strcmp(keyTypeStr, "3des") == 0) {
        keyType = GP211_KEY_TYPE_3DES;
    } else {
        fprintf(stderr, "put-dap-key: unsupported --key-type '%s' (use ecc|rsa|aes|3des)\n", keyTypeStr);
        return -1;
    }

    if (keyType == GP211_KEY_TYPE_ECC || keyType == GP211_KEY_TYPE_RSA) {
        const char *pem = keyValue;
        char *c = strchr((char *)pem, ':');
        if (c) {
            *c = '\0';
            pass = c + 1;
        }

        if (to_opgp_string(pem, pem_t, ARRAY_SIZE(pem_t)) != 0) {
            fprintf(stderr, "put-dap-key: pem path too long\n");
            return -1;
        }
        pem_opgp = pem_t;
    } else {
        size_t len = sizeof(symmetricKey);
        if (hex_to_bytes(keyValue, symmetricKey, &len) != 0) {
            fprintf(stderr, "put-dap-key: invalid symmetric key hex\n");
            return -1;
        }
        if (keyType == GP211_KEY_TYPE_AES && (len != 16 && len != 24 && len != 32)) {
            fprintf(stderr, "put-dap-key: AES key must be 16, 24, or 32 bytes\n");
            return -1;
        }
        if (keyType == GP211_KEY_TYPE_3DES && len != 16) {
            fprintf(stderr, "put-dap-key: 3DES key must be 16 bytes\n");
            return -1;
        }
        keyLength = (DWORD)len;
    }

    if (!status_ok(GP211_put_dap_keys(ctx, info, sec,
                                      setVer, newSetVer,
                                      pem_opgp, pass,
                                      keyType,
                                      keyLength ? symmetricKey : NULL, keyLength), true)) {
        return -1;
    }
    return 0;
}

static int cmd_del_key(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    BYTE setVer=0; BYTE idx=0xFF; // 0xFF => delete all keys in set
    for (int i=0;i<argc;i++) {
        if (strcmp(argv[i], "--kv")==0 && i+1<argc) setVer=(BYTE)parse_int(argv[++i]);
        else if (strcmp(argv[i], "--idx")==0 && i+1<argc) idx=(BYTE)parse_int(argv[++i]);
    }
    if (!status_ok(GP211_delete_key(ctx, info, sec, setVer, idx), true)) {
        return -1;
    }
    return 0;
}

static int cmd_update_registry(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    const char *aid_hex = NULL;
    const char *sd_aid_hex = NULL;
    const char *priv_list = NULL;
    const char *token_hex = NULL;
    BYTE token[512];
    BYTE *token_ptr = NULL;
    DWORD token_len = 0;
    DWORD privileges = 0;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--priv") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "update-registry: --priv requires <p1,p2,...>\n");
                return -1;
            }
            priv_list = argv[++i];
        }
        else if (strcmp(argv[i], "--sd") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "update-registry: --sd requires <AIDhex>\n");
                return -1;
            }
            sd_aid_hex = argv[++i];
        }
        else if (strcmp(argv[i], "--token") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "update-registry: --token requires <hex>\n");
                return -1;
            }
            token_hex = argv[++i];
        }
        else if (argv[i][0] == '-') {
            fprintf(stderr, "update-registry: unknown option %s\n", argv[i]);
            return -1;
        }
        else if (aid_hex == NULL) {
            aid_hex = argv[i];
        }
        else {
            fprintf(stderr, "update-registry: unexpected argument %s\n", argv[i]);
            return -1;
        }
    }

    if (!aid_hex) {
        fprintf(stderr, "update-registry: missing mandatory <AIDhex>\n");
        return -1;
    }

    if (!sec) {
        fprintf(stderr, "update-registry: secure channel required\n");
        return -1;
    }

    unsigned char aid[16];
    size_t aid_len = sizeof(aid);
    if (hex_to_bytes(aid_hex, aid, &aid_len) != 0) {
        fprintf(stderr, "update-registry: invalid <AIDhex> hex\n");
        return -1;
    }

    unsigned char sd_aid[16];
    size_t sd_aid_len = 0;
    if (sd_aid_hex) {
        sd_aid_len = sizeof(sd_aid);
        if (hex_to_bytes(sd_aid_hex, sd_aid, &sd_aid_len) != 0) {
            fprintf(stderr, "update-registry: invalid --sd <AIDhex> hex\n");
            return -1;
        }
    }

    if (priv_list) {
        if (parse_privileges(priv_list, &privileges) != 0) {
            fprintf(stderr, "update-registry: invalid privileges: %s\n", priv_list);
            return -1;
        }
    }

    if (token_hex) {
        size_t len = sizeof(token);
        if (hex_to_bytes(token_hex, token, &len) != 0 || len == 0) {
            fprintf(stderr, "update-registry: invalid --token hex\n");
            return -1;
        }
        token_ptr = token;
        token_len = (DWORD)len;
    }

    GP211_RECEIPT_DATA receipt;
    DWORD receiptAvailable = 0;
    OPGP_ERROR_STATUS s = GP211_install_for_registry_update(ctx, info, sec,
                                                            sd_aid_hex ? sd_aid : NULL, (DWORD)sd_aid_len,
                                                            aid, (DWORD)aid_len,
                                                            privileges,
                                                            NULL, 0, // Registry Update Parameters not supported
                                                            token_ptr, token_len,
                                                            &receipt, &receiptAvailable);

    if (!status_ok(s, true)) {
        return -1;
    }

    if (receiptAvailable) {
        print_received_receipt("Registry update", &receipt);
    }

    return 0;
}

static int compact_hex(const char *in, char *out, size_t outsz) {
    // Copy only hex digits, ignore spaces and tabs; fail on other chars
    size_t j=0;
    for (const char *p=in; *p; ++p) {
        unsigned char c = (unsigned char)*p;
        if (c==' ' || c=='\t') continue;
        if (!isxdigit(c)) {
            if (c==';' || c==',') break; // caller should split before calling
            return -1;
        }
        if (j+1 >= outsz) return -2;
        out[j++] = (char)toupper(c);
    }
    out[j] = '\0';
    if (j % 2 != 0) return -3;
    return 0;
}

static int is_hex_byte_token(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n > 2) return 0;
    for (size_t i=0;i<n;i++) if (!isxdigit((unsigned char)s[i])) return 0;
    return 1;
}

static int cmd_apdu(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "apdu: missing arguments\n"); return -1; }
    int nostop = 0;
    enum { MAX_APDUS = 256 };
    char *apdus[MAX_APDUS]; int napdus=0;
    for (int i=0;i<argc;i++) {
        const char *a = argv[i];
        if (strcmp(a, "--nostop")==0 || strcmp(a, "--ignore-errors")==0) { nostop=1; continue; }
        if (strcmp(a, "--auth")==0 || strcmp(a, "--secure")==0) { /* handled in main; skip here */ continue; }
        // Case 1: sequence of hex byte tokens across argv -> one APDU
        if (is_hex_byte_token(a)) {
            char buf[4096]; buf[0]='\0'; size_t bl=0;
            while (i<argc && is_hex_byte_token(argv[i])) {
                const char *b = argv[i];
                size_t bn = strlen(b);
                if (bl + bn >= sizeof(buf)-1) { fprintf(stderr, "APDU too long\n"); return -1; }
                for (size_t t=0;t<bn;t++) buf[bl++] = (char)toupper((unsigned char)b[t]);
                i++;
            }
            i--; // compensate last increment in while
            buf[bl]='\0';
            if (napdus < MAX_APDUS) apdus[napdus++] = strdup(buf);
            continue;
        }
        // Case 2: split by ';' or ',' within the same argument
        char *dup = strdup(a);
        if (!dup) { fprintf(stderr, "oom\n"); return -1; }
        char *save=NULL; char *tok = strtok_r(dup, ";,", &save);
        while (tok) {
            if (napdus < MAX_APDUS) {
                apdus[napdus++] = strdup(tok);
            }
            tok = strtok_r(NULL, ";,", &save);
        }
        free(dup);
        if (napdus >= MAX_APDUS) break;
    }
    if (napdus == 0) { fprintf(stderr, "apdu: no APDUs provided\n"); return -1; }

    int rc = 0;
    for (int k=0;k<napdus;k++) {
        char hexbuf[4096];
        if (compact_hex(apdus[k], hexbuf, sizeof(hexbuf)) != 0) {
            fprintf(stderr, "Invalid hex in APDU %d\n", k+1);
            rc = -1; if (!nostop) { break; } else { continue; }
        }
        unsigned char capdu[APDU_COMMAND_LEN]; size_t clen=sizeof(capdu);
        if (hex_to_bytes(hexbuf, capdu, &clen)!=0) {
            fprintf(stderr, "Invalid hex length in APDU %d\n", k+1);
            rc = -1; if (!nostop) { break; } else { continue; }
        }
        unsigned char rapdu[APDU_RESPONSE_LEN]; DWORD rlen=sizeof(rapdu);
        OPGP_ERROR_STATUS s = GP211_send_APDU(ctx, info, sec, capdu, (DWORD)clen, rapdu, &rlen);
        if (!status_ok(s, true)) {
            _ftprintf(stderr, _T("APDU %d send failed: 0x%08X (%s)\n"), k+1, (unsigned int)s.errorCode, s.errorMessage);
            rc = -1; if (!nostop) { break; } else { continue; }
        }
        print_hex(rapdu, rlen); printf("\n");
    }
    for (int k=0;k<napdus;k++) free(apdus[k]);
    return rc;
}

static int cmd_hash(int argc, char **argv) {
    const char *hash_alg = "sha256"; // default
    int ai = 0;
    for (; ai < argc; ++ai) {
        if (strcmp(argv[ai], "--sha1") == 0) { hash_alg = "sha1"; }
        else if (strcmp(argv[ai], "--sha256") == 0 || strcmp(argv[ai], "--sha2-256") == 0) { hash_alg = "sha256"; }
        else if (strcmp(argv[ai], "--sha384") == 0 || strcmp(argv[ai], "--sha2-384") == 0) { hash_alg = "sha384"; }
        else if (strcmp(argv[ai], "--sha512") == 0 || strcmp(argv[ai], "--sha2-512") == 0) { hash_alg = "sha512"; }
        else if (strcmp(argv[ai], "--sm3") == 0) { hash_alg = "sm3"; }
        else break;
    }
    if (ai >= argc) { fprintf(stderr, "hash: missing <cap-file>\n"); return -1; }
    const char *cap = argv[ai++];
    TCHAR cap_t[MAX_PATH_BUF];
    OPGP_STRING cap_opgp = NULL;
    if (to_opgp_string(cap, cap_t, ARRAY_SIZE(cap_t)) != 0) {
        fprintf(stderr, "hash: cap file path too long\n");
        return -1;
    }
    cap_opgp = cap_t;

    BYTE hashType = GP211_HASH_SHA256;
    DWORD hash_len = 32;
    if (strcmp(hash_alg, "sha1") == 0) { hashType = GP211_HASH_SHA1; hash_len = 20; }
    else if (strcmp(hash_alg, "sha256") == 0) { hashType = GP211_HASH_SHA256; hash_len = 32; }
    else if (strcmp(hash_alg, "sha384") == 0) { hashType = GP211_HASH_SHA384; hash_len = 48; }
    else if (strcmp(hash_alg, "sha512") == 0) { hashType = GP211_HASH_SHA512; hash_len = 64; }
    else if (strcmp(hash_alg, "sm3") == 0) { hashType = GP211_HASH_SM3; hash_len = 32; }

    BYTE hash[64]; memset(hash, 0, sizeof(hash));
    if (!status_ok(GP211_calculate_load_file_data_block_hash(cap_opgp, hash, hash_len, hashType), false)) {
        fprintf(stderr, "hash failed\n"); return -1;
    }
    print_hex(hash, hash_len); printf("\n");
    return 0;
}

static int cmd_sign_dap(const char *dap_type, int argc, char **argv) {
    // Parse optional flags
    const char *output_file = NULL;
    int ai = 0;
    while (ai < argc && argv[ai][0] == '-') {
        if (strcmp(argv[ai], "--output") == 0 && ai+1 < argc) { output_file = argv[++ai]; ai++; }
        else break;
    }

    if (strcmp(dap_type, "rsa") == 0) {
        if (argc - ai < 2) { fprintf(stderr, "sign-dap rsa [--output <file>] <hash-hex> <pem>[:pass]\n"); return -1; }
        const char *hash_hex = argv[ai++]; const char *pem = argv[ai++];
        unsigned char hash[64]; size_t hashlen=sizeof(hash);
        unsigned char signature[512]; DWORD signatureLen = sizeof(signature);
        if (hex_to_bytes(hash_hex, hash, &hashlen)!=0) { fprintf(stderr, "Invalid hash hex\n"); return -1; }
        char pemcopy[512]; strncpy(pemcopy, pem, sizeof(pemcopy)-1); pemcopy[sizeof(pemcopy)-1]='\0'; char *pass=""; char *c=strchr(pemcopy,':'); if (c){*c='\0'; pass=c+1;}
        TCHAR pem_t[MAX_PATH_BUF];
        OPGP_STRING pem_opgp = NULL;
        if (to_opgp_string(pemcopy, pem_t, ARRAY_SIZE(pem_t)) != 0) {
            fprintf(stderr, "sign-dap: pem path too long\n");
            return -1;
        }
        pem_opgp = pem_t;
        if (!status_ok(GP211_calculate_rsa_schemeX_DAP(hash, (DWORD)hashlen, pem_opgp, pass, signature, &signatureLen), false)) { fprintf(stderr, "calc rsa DAP failed\n"); return -1; }

        if (output_file) {
            FILE *f = fopen(output_file, "wb");
            if (!f) { fprintf(stderr, "Failed to open output file: %s\n", output_file); return -1; }
            fwrite(signature, 1, signatureLen, f);
            fclose(f);
        } else {
            print_hex(signature, signatureLen); printf("\n");
        }
        return 0;
    } else if (strcmp(dap_type, "ecc") == 0) {
        if (argc - ai < 2) { fprintf(stderr, "sign-dap ecc [--output <file>] <hash-hex> <pem>[:pass]\n"); return -1; }
        const char *hash_hex = argv[ai++]; const char *pem = argv[ai++];
        unsigned char hash[64]; size_t hashlen=sizeof(hash);
        unsigned char signature[512]; DWORD signatureLen = sizeof(signature);
        if (hex_to_bytes(hash_hex, hash, &hashlen)!=0) { fprintf(stderr, "Invalid hash hex\n"); return -1; }
        char pemcopy[512]; strncpy(pemcopy, pem, sizeof(pemcopy)-1); pemcopy[sizeof(pemcopy)-1]='\0'; char *pass=""; char *c=strchr(pemcopy,':'); if (c){*c='\0'; pass=c+1;}
        TCHAR pem_t[MAX_PATH_BUF];
        OPGP_STRING pem_opgp = NULL;
        if (to_opgp_string(pemcopy, pem_t, ARRAY_SIZE(pem_t)) != 0) {
            fprintf(stderr, "sign-dap: pem path too long\n");
            return -1;
        }
        pem_opgp = pem_t;
        if (!status_ok(GP211_calculate_ecc_DAP(hash, (DWORD)hashlen, pem_opgp, pass, signature, &signatureLen), false)) { fprintf(stderr, "calc ecc DAP failed\n"); return -1; }

        if (output_file) {
            FILE *f = fopen(output_file, "wb");
            if (!f) { fprintf(stderr, "Failed to open output file: %s\n", output_file); return -1; }
            fwrite(signature, 1, signatureLen, f);
            fclose(f);
        } else {
            print_hex(signature, signatureLen); printf("\n");
        }
        return 0;
    } else {
        if (argc - ai < 2) { fprintf(stderr, "sign-dap aes [--output <file>] <hash-hex> <hexkey>\n"); return -1; }
        const char *hash_hex = argv[ai++]; const char *hexkey = argv[ai++];
        unsigned char hash[64]; size_t hashlen=sizeof(hash);
        unsigned char signature[64]; DWORD signatureLen = sizeof(signature);
        if (hex_to_bytes(hash_hex, hash, &hashlen)!=0) { fprintf(stderr, "Invalid hash hex\n"); return -1; }
        unsigned char key[32]; size_t klen=sizeof(key); if (hex_to_bytes(hexkey, key, &klen)!=0) { fprintf(stderr, "Invalid hexkey\n"); return -1; }
        // Determine SCP based on hash length
        BYTE scp = (hashlen > 20) ? GP211_SCP03 : GP211_SCP02;
        if (!status_ok(GP211_calculate_DAP(hash, (BYTE)hashlen, key, (DWORD)klen, signature, &signatureLen, scp), false)) { fprintf(stderr, "calc aes DAP failed\n"); return -1; }

        if (output_file) {
            FILE *f = fopen(output_file, "wb");
            if (!f) { fprintf(stderr, "Failed to open output file: %s\n", output_file); return -1; }
            fwrite(signature, 1, signatureLen, f);
            fclose(f);
        } else {
            print_hex(signature, signatureLen); printf("\n");
        }
        return 0;
    }
}

static int write_hex_or_binary_output(const BYTE *data, DWORD dataLength, const char *outputFile) {
    if (outputFile != NULL) {
        FILE *f = fopen(outputFile, "wb");
        if (f == NULL) {
            fprintf(stderr, "Failed to open output file: %s\n", outputFile);
            return -1;
        }
        if (fwrite(data, 1, dataLength, f) != dataLength) {
            fprintf(stderr, "Failed to write output file: %s\n", outputFile);
            fclose(f);
            return -1;
        }
        fclose(f);
        return 0;
    }
    print_hex(data, dataLength);
    printf("\n");
    return 0;
}

static int cmd_sign_load_token(int argc, char **argv) {
    const char *output_file = NULL;
    DWORD v_data_limit = 0;
    DWORD nv_data_limit = 0;
    int ai = 0;

    while (ai < argc && argv[ai][0] == '-') {
        if (strcmp(argv[ai], "--output") == 0 && ai + 1 < argc) {
            output_file = argv[++ai];
        } else if (strcmp(argv[ai], "--v-data-limit") == 0 && ai + 1 < argc) {
            v_data_limit = (DWORD)parse_int(argv[++ai]);
        } else if (strcmp(argv[ai], "--nv-data-limit") == 0 && ai + 1 < argc) {
            nv_data_limit = (DWORD)parse_int(argv[++ai]);
        } else {
            break;
        }
        ai++;
    }

    if (argc - ai < 4) {
        fprintf(stderr, "sign-load-token [--output <file>] [--v-data-limit <n>] [--nv-data-limit <n>] <cap-file> <sd-aidhex> <hash-hex> <pem>[:pass]\n");
        return -1;
    }

    const char *cap_file = argv[ai++];
    const char *sd_hex = argv[ai++];
    const char *hash_hex = argv[ai++];
    const char *pem_arg = argv[ai++];

    if (ai != argc) {
        fprintf(stderr, "sign-load-token: unexpected argument %s\n", argv[ai]);
        return -1;
    }

    TCHAR capfile_t[MAX_PATH_BUF];
    OPGP_STRING capfile_opgp = NULL;
    OPGP_LOAD_FILE_PARAMETERS lfp;
    memset(&lfp, 0, sizeof(lfp));
    if (to_opgp_string(cap_file, capfile_t, ARRAY_SIZE(capfile_t)) != 0) {
        fprintf(stderr, "sign-load-token: cap file path too long\n");
        return -1;
    }
    capfile_opgp = capfile_t;
    if (!status_ok(OPGP_read_executable_load_file_parameters(capfile_opgp, &lfp), false)) {
        fprintf(stderr, "sign-load-token: failed to read CAP load file parameters\n");
        return -1;
    }

    BYTE sd_aid[16];
    size_t sd_aid_len = sizeof(sd_aid);
    if (hex_to_bytes(sd_hex, sd_aid, &sd_aid_len) != 0) {
        fprintf(stderr, "sign-load-token: invalid <sd-aidhex>\n");
        return -1;
    }

    BYTE hash[64];
    size_t hash_len = sizeof(hash);
    if (hex_to_bytes(hash_hex, hash, &hash_len) != 0 || hash_len == 0) {
        fprintf(stderr, "sign-load-token: invalid <hash-hex>\n");
        return -1;
    }

    char pemcopy[MAX_PATH_BUF];
    char *pass = "";
    char *sep;
    TCHAR pem_t[MAX_PATH_BUF];
    OPGP_STRING pem_opgp = NULL;
    strncpy(pemcopy, pem_arg, sizeof(pemcopy) - 1);
    pemcopy[sizeof(pemcopy) - 1] = '\0';
    sep = strchr(pemcopy, ':');
    if (sep != NULL) {
        *sep = '\0';
        pass = sep + 1;
    }
    if (to_opgp_string(pemcopy, pem_t, ARRAY_SIZE(pem_t)) != 0) {
        fprintf(stderr, "sign-load-token: pem path too long\n");
        return -1;
    }
    pem_opgp = pem_t;

    BYTE token[512];
    DWORD token_len = sizeof(token);
    if (!status_ok(GP211_calculate_load_token(lfp.loadFileAID.AID, lfp.loadFileAID.AIDLength,
                                              sd_aid, (DWORD)sd_aid_len,
                                              hash, (DWORD)hash_len,
                                              lfp.loadFileSize, v_data_limit, nv_data_limit,
                                              token, &token_len,
                                              pem_opgp, pass), false)) {
        fprintf(stderr, "sign-load-token failed\n");
        return -1;
    }

    return write_hex_or_binary_output(token, token_len, output_file);
}

static int cmd_gp211_calculate_install_token(int argc, char **argv) {
    const char *output_file = NULL;
    BYTE p1 = 0x0C;
    DWORD privileges = 0;
    DWORD v_data_limit = 0;
    DWORD nv_data_limit = 0;
    const char *params_hex = NULL;
    const char *sd_params_hex = NULL;
    const char *uicc_params_hex = NULL;
    const char *sim_params_hex = NULL;
    int ai = 0;

    while (ai < argc && argv[ai][0] == '-') {
        if (strcmp(argv[ai], "--output") == 0 && ai + 1 < argc) {
            output_file = argv[++ai];
        } else if (strcmp(argv[ai], "--p1") == 0 && ai + 1 < argc) {
            p1 = (BYTE)parse_int(argv[++ai]);
        } else if (strcmp(argv[ai], "--priv") == 0 && ai + 1 < argc) {
            privileges = (DWORD)strtoul(argv[++ai], NULL, 0);
            if (privileges < 0x100) {
                privileges <<= 16;
            }
        } else if (strcmp(argv[ai], "--v-data-limit") == 0 && ai + 1 < argc) {
            v_data_limit = (DWORD)parse_int(argv[++ai]);
        } else if (strcmp(argv[ai], "--nv-data-limit") == 0 && ai + 1 < argc) {
            nv_data_limit = (DWORD)parse_int(argv[++ai]);
        } else if (strcmp(argv[ai], "--params") == 0 && ai + 1 < argc) {
            params_hex = argv[++ai];
        } else if (strcmp(argv[ai], "--sd-params") == 0 && ai + 1 < argc) {
            sd_params_hex = argv[++ai];
        } else if (strcmp(argv[ai], "--uicc-params") == 0 && ai + 1 < argc) {
            uicc_params_hex = argv[++ai];
        } else if (strcmp(argv[ai], "--sim-params") == 0 && ai + 1 < argc) {
            sim_params_hex = argv[++ai];
        } else {
            break;
        }
        ai++;
    }

    if (argc - ai < 4) {
        fprintf(stderr, "sign-install-token [--output <file>] [--p1 <n>] [--priv <n>] [--v-data-limit <n>] [--nv-data-limit <n>] [--params <hex>] [--sd-params <hex>] [--uicc-params <hex>] [--sim-params <hex>] <load-file-aidhex> <module-aidhex> <app-aidhex> <pem>[:pass]\n");
        return -1;
    }

    const char *load_file_hex = argv[ai++];
    const char *module_hex = argv[ai++];
    const char *app_hex = argv[ai++];
    const char *pem_arg = argv[ai++];
    if (ai != argc) {
        fprintf(stderr, "sign-install-token: unexpected argument %s\n", argv[ai]);
        return -1;
    }

    BYTE load_file_aid[16];
    size_t load_file_aid_len = sizeof(load_file_aid);
    BYTE module_aid[16];
    size_t module_aid_len = sizeof(module_aid);
    BYTE app_aid[16];
    size_t app_aid_len = sizeof(app_aid);

    if (hex_to_bytes(load_file_hex, load_file_aid, &load_file_aid_len) != 0) {
        fprintf(stderr, "sign-install-token: invalid <load-file-aidhex>\n");
        return -1;
    }
    if (hex_to_bytes(module_hex, module_aid, &module_aid_len) != 0) {
        fprintf(stderr, "sign-install-token: invalid <module-aidhex>\n");
        return -1;
    }
    if (hex_to_bytes(app_hex, app_aid, &app_aid_len) != 0) {
        fprintf(stderr, "sign-install-token: invalid <app-aidhex>\n");
        return -1;
    }

    BYTE params[512];
    size_t params_len = 0;
    BYTE sd_params[512];
    size_t sd_params_len = 0;
    BYTE uicc_params[512];
    size_t uicc_params_len = 0;
    BYTE sim_params[512];
    size_t sim_params_len = 0;

    if (params_hex != NULL) {
        params_len = sizeof(params);
        if (hex_to_bytes(params_hex, params, &params_len) != 0) {
            fprintf(stderr, "sign-install-token: invalid --params\n");
            return -1;
        }
    }
    if (sd_params_hex != NULL) {
        sd_params_len = sizeof(sd_params);
        if (hex_to_bytes(sd_params_hex, sd_params, &sd_params_len) != 0) {
            fprintf(stderr, "sign-install-token: invalid --sd-params\n");
            return -1;
        }
    }
    if (uicc_params_hex != NULL) {
        uicc_params_len = sizeof(uicc_params);
        if (hex_to_bytes(uicc_params_hex, uicc_params, &uicc_params_len) != 0) {
            fprintf(stderr, "sign-install-token: invalid --uicc-params\n");
            return -1;
        }
    }
    if (sim_params_hex != NULL) {
        sim_params_len = sizeof(sim_params);
        if (hex_to_bytes(sim_params_hex, sim_params, &sim_params_len) != 0) {
            fprintf(stderr, "sign-install-token: invalid --sim-params\n");
            return -1;
        }
    }

    char pemcopy[MAX_PATH_BUF];
    char *pass = "";
    char *sep;
    TCHAR pem_t[MAX_PATH_BUF];
    OPGP_STRING pem_opgp = NULL;
    strncpy(pemcopy, pem_arg, sizeof(pemcopy) - 1);
    pemcopy[sizeof(pemcopy) - 1] = '\0';
    sep = strchr(pemcopy, ':');
    if (sep != NULL) {
        *sep = '\0';
        pass = sep + 1;
    }
    if (to_opgp_string(pemcopy, pem_t, ARRAY_SIZE(pem_t)) != 0) {
        fprintf(stderr, "sign-install-token: pem path too long\n");
        return -1;
    }
    pem_opgp = pem_t;

    BYTE token[512];
    DWORD token_len = sizeof(token);
    if (!status_ok(GP211_calculate_install_token(p1,
                                                 load_file_aid, (DWORD)load_file_aid_len,
                                                 module_aid, (DWORD)module_aid_len,
                                                 app_aid, (DWORD)app_aid_len,
                                                 privileges, v_data_limit, nv_data_limit,
                                                 params_len ? params : NULL, (DWORD)params_len,
                                                 sd_params_len ? sd_params : NULL, (DWORD)sd_params_len,
                                                 uicc_params_len ? uicc_params : NULL, (DWORD)uicc_params_len,
                                                 sim_params_len ? sim_params : NULL, (DWORD)sim_params_len,
                                                 token, &token_len,
                                                 pem_opgp, pass), false)) {
        fprintf(stderr, "sign-install-token failed\n");
        return -1;
    }

    return write_hex_or_binary_output(token, token_len, output_file);
}

static int cmd_gp211_calculate_extradition_token(int argc, char **argv) {
    const char *output_file = NULL;
    int ai = 0;
    while (ai < argc && argv[ai][0] == '-') {
        if (strcmp(argv[ai], "--output") == 0 && ai + 1 < argc) {
            output_file = argv[++ai];
        } else {
            break;
        }
        ai++;
    }

    if (argc - ai < 3) {
        fprintf(stderr, "sign-extradition-token [--output <file>] <sd-aidhex> <app-aidhex> <pem>[:pass]\n");
        return -1;
    }

    const char *sd_hex = argv[ai++];
    const char *app_hex = argv[ai++];
    const char *pem_arg = argv[ai++];
    if (ai != argc) {
        fprintf(stderr, "sign-extradition-token: unexpected argument %s\n", argv[ai]);
        return -1;
    }

    BYTE sd_aid[16];
    size_t sd_aid_len = sizeof(sd_aid);
    BYTE app_aid[16];
    size_t app_aid_len = sizeof(app_aid);
    if (hex_to_bytes(sd_hex, sd_aid, &sd_aid_len) != 0) {
        fprintf(stderr, "sign-extradition-token: invalid <sd-aidhex>\n");
        return -1;
    }
    if (hex_to_bytes(app_hex, app_aid, &app_aid_len) != 0) {
        fprintf(stderr, "sign-extradition-token: invalid <app-aidhex>\n");
        return -1;
    }

    char pemcopy[MAX_PATH_BUF];
    char *pass = "";
    char *sep;
    TCHAR pem_t[MAX_PATH_BUF];
    OPGP_STRING pem_opgp = NULL;
    strncpy(pemcopy, pem_arg, sizeof(pemcopy) - 1);
    pemcopy[sizeof(pemcopy) - 1] = '\0';
    sep = strchr(pemcopy, ':');
    if (sep != NULL) {
        *sep = '\0';
        pass = sep + 1;
    }
    if (to_opgp_string(pemcopy, pem_t, ARRAY_SIZE(pem_t)) != 0) {
        fprintf(stderr, "sign-extradition-token: pem path too long\n");
        return -1;
    }
    pem_opgp = pem_t;

    BYTE token[512];
    DWORD token_len = sizeof(token);
    if (!status_ok(GP211_calculate_extradition_token(sd_aid, (DWORD)sd_aid_len,
                                                     app_aid, (DWORD)app_aid_len,
                                                     token, &token_len,
                                                     pem_opgp, pass), false)) {
        fprintf(stderr, "sign-extradition-token failed\n");
        return -1;
    }
    return write_hex_or_binary_output(token, token_len, output_file);
}

static int cmd_gp211_calculate_update_registry_token(int argc, char **argv) {
    const char *output_file = NULL;
    DWORD privileges = 0;
    const char *registry_params_hex = NULL;
    int ai = 0;

    while (ai < argc && argv[ai][0] == '-') {
        if (strcmp(argv[ai], "--output") == 0 && ai + 1 < argc) {
            output_file = argv[++ai];
        } else if (strcmp(argv[ai], "--priv") == 0 && ai + 1 < argc) {
            privileges = (DWORD)strtoul(argv[++ai], NULL, 0);
            if (privileges < 0x100) {
                privileges <<= 16;
            }
        } else if (strcmp(argv[ai], "--registry-params") == 0 && ai + 1 < argc) {
            registry_params_hex = argv[++ai];
        } else {
            break;
        }
        ai++;
    }

    if (argc - ai < 3) {
        fprintf(stderr, "sign-update-registry-token [--output <file>] [--priv <n>] [--registry-params <hex>] <sd-aidhex> <app-aidhex> <pem>[:pass]\n");
        return -1;
    }

    const char *sd_hex = argv[ai++];
    const char *app_hex = argv[ai++];
    const char *pem_arg = argv[ai++];
    if (ai != argc) {
        fprintf(stderr, "sign-update-registry-token: unexpected argument %s\n", argv[ai]);
        return -1;
    }

    BYTE sd_aid[16];
    size_t sd_aid_len = sizeof(sd_aid);
    BYTE app_aid[16];
    size_t app_aid_len = sizeof(app_aid);
    if (hex_to_bytes(sd_hex, sd_aid, &sd_aid_len) != 0) {
        fprintf(stderr, "sign-update-registry-token: invalid <sd-aidhex>\n");
        return -1;
    }
    if (hex_to_bytes(app_hex, app_aid, &app_aid_len) != 0) {
        fprintf(stderr, "sign-update-registry-token: invalid <app-aidhex>\n");
        return -1;
    }

    BYTE registry_params[512];
    size_t registry_params_len = 0;
    if (registry_params_hex != NULL) {
        registry_params_len = sizeof(registry_params);
        if (hex_to_bytes(registry_params_hex, registry_params, &registry_params_len) != 0) {
            fprintf(stderr, "sign-update-registry-token: invalid --registry-params\n");
            return -1;
        }
    }

    char pemcopy[MAX_PATH_BUF];
    char *pass = "";
    char *sep;
    TCHAR pem_t[MAX_PATH_BUF];
    OPGP_STRING pem_opgp = NULL;
    strncpy(pemcopy, pem_arg, sizeof(pemcopy) - 1);
    pemcopy[sizeof(pemcopy) - 1] = '\0';
    sep = strchr(pemcopy, ':');
    if (sep != NULL) {
        *sep = '\0';
        pass = sep + 1;
    }
    if (to_opgp_string(pemcopy, pem_t, ARRAY_SIZE(pem_t)) != 0) {
        fprintf(stderr, "sign-update-registry-token: pem path too long\n");
        return -1;
    }
    pem_opgp = pem_t;

    BYTE token[512];
    DWORD token_len = sizeof(token);
    if (!status_ok(GP211_calculate_update_registry_token(sd_aid, (DWORD)sd_aid_len,
                                                         app_aid, (DWORD)app_aid_len,
                                                         privileges,
                                                         registry_params_len ? registry_params : NULL,
                                                         (DWORD)registry_params_len,
                                                         token, &token_len,
                                                         pem_opgp, pass), false)) {
        fprintf(stderr, "sign-update-registry-token failed\n");
        return -1;
    }
    return write_hex_or_binary_output(token, token_len, output_file);
}

static int cmd_gp211_calculate_delete_token(int argc, char **argv) {
    const char *output_file = NULL;
    int ai = 0;
    while (ai < argc && argv[ai][0] == '-') {
        if (strcmp(argv[ai], "--output") == 0 && ai + 1 < argc) {
            output_file = argv[++ai];
        } else {
            break;
        }
        ai++;
    }

    if (argc - ai < 2) {
        fprintf(stderr, "sign-delete-token [--output <file>] <aidhex> <pem>[:pass]\n");
        return -1;
    }

    const char *aid_hex = argv[ai++];
    const char *pem_arg = argv[ai++];
    if (ai != argc) {
        fprintf(stderr, "sign-delete-token: unexpected argument %s\n", argv[ai]);
        return -1;
    }

    BYTE aid[16];
    size_t aid_len = sizeof(aid);
    if (hex_to_bytes(aid_hex, aid, &aid_len) != 0) {
        fprintf(stderr, "sign-delete-token: invalid <aidhex>\n");
        return -1;
    }

    char pemcopy[MAX_PATH_BUF];
    char *pass = "";
    char *sep;
    TCHAR pem_t[MAX_PATH_BUF];
    OPGP_STRING pem_opgp = NULL;
    strncpy(pemcopy, pem_arg, sizeof(pemcopy) - 1);
    pemcopy[sizeof(pemcopy) - 1] = '\0';
    sep = strchr(pemcopy, ':');
    if (sep != NULL) {
        *sep = '\0';
        pass = sep + 1;
    }
    if (to_opgp_string(pemcopy, pem_t, ARRAY_SIZE(pem_t)) != 0) {
        fprintf(stderr, "sign-delete-token: pem path too long\n");
        return -1;
    }
    pem_opgp = pem_t;

    BYTE token[512];
    DWORD token_len = sizeof(token);
    if (!status_ok(GP211_calculate_delete_token(aid, (DWORD)aid_len,
                                                token, &token_len,
                                                pem_opgp, pass), false)) {
        fprintf(stderr, "sign-delete-token failed\n");
        return -1;
    }
    return write_hex_or_binary_output(token, token_len, output_file);
}

static int cmd_status(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "status: missing element type (isd|sd|app|sd-app)\n"); return -1; }

    const char *element_type = argv[0];
    const char *lc_state = NULL;
    const char *aid_hex = NULL;

    int ai = 1;
    for (; ai < argc; ++ai) {
        if (strcmp(argv[ai], "--lc") == 0 && ai+1 < argc) {
            lc_state = argv[++ai];
        } else {
            aid_hex = argv[ai];
            break;
        }
    }

    if (!aid_hex) { fprintf(stderr, "status: missing <AIDhex>\n"); return -1; }

    // Parse AID
    unsigned char aid[16]; size_t aidlen = sizeof(aid);
    if (hex_to_bytes(aid_hex, aid, &aidlen) != 0) {
        fprintf(stderr, "Invalid AID hex\n");
        return -1;
    }

    // Determine status type and lifecycle state
    BYTE statusType = 0;
    BYTE lifeCycleState = 0;

    if (strcmp(element_type, "isd") == 0) {
        statusType = GP211_STATUS_TYPE_ISSUER_SECURITY_DOMAIN;

        if (!lc_state) {
            fprintf(stderr, "status isd: --lc <state> required (locked|terminated)\n");
            return -1;
        }

        if (strcmp(lc_state, "locked") == 0) {
            lifeCycleState = GP211_LIFE_CYCLE_CARD_LOCKED;
        } else if (strcmp(lc_state, "terminated") == 0) {
            lifeCycleState = GP211_LIFE_CYCLE_CARD_TERMINATED;

            // Display prominent warning for terminated state
            fprintf(stderr, "\n");
            fprintf(stderr, "================================================================================\n");
            fprintf(stderr, "                              *** WARNING ***\n");
            fprintf(stderr, "================================================================================\n");
            fprintf(stderr, "You are about to TERMINATE the Issuer Security Domain!\n");
            fprintf(stderr, "\n");
            fprintf(stderr, "THIS ACTION CANNOT BE UNDONE!\n");
            fprintf(stderr, "The card will be PERMANENTLY TERMINATED and UNUSABLE after this operation.\n");
            fprintf(stderr, "\n");
            fprintf(stderr, "To confirm, please enter the AID again: ");
            fprintf(stderr, "\n> ");

            char confirm[64];
            if (fgets(confirm, sizeof(confirm), stdin)) {
                // Remove trailing newline
                size_t len = strlen(confirm);
                if (len > 0 && confirm[len-1] == '\n') confirm[len-1] = '\0';

                if (strcmp(confirm, aid_hex) != 0) {
                    fprintf(stderr, "AID does not match. Operation cancelled.\n");
                    return 0;
                }
            } else {
                fprintf(stderr, "Failed to read confirmation. Operation cancelled.\n");
                return 0;
            }
            fprintf(stderr, "================================================================================\n");
            fprintf(stderr, "\n");
        } else {
            fprintf(stderr, "status isd: invalid lifecycle state '%s' (use: locked|terminated)\n", lc_state);
            return -1;
        }
    } else if (strcmp(element_type, "sd") == 0) {
        statusType = GP211_STATUS_TYPE_APPLICATIONS;

        if (!lc_state) {
            fprintf(stderr, "status sd: --lc <state> required (personalized|locked)\n");
            return -1;
        }

        if (strcmp(lc_state, "personalized") == 0) {
            lifeCycleState = GP211_LIFE_CYCLE_SECURITY_DOMAIN_PERSONALIZED;
        } else if (strcmp(lc_state, "locked") == 0) {
            lifeCycleState = GP211_LIFE_CYCLE_SECURITY_DOMAIN_LOCKED;
        } else {
            fprintf(stderr, "status sd: invalid lifecycle state '%s' (use: personalized|locked)\n", lc_state);
            return -1;
        }
    } else if (strcmp(element_type, "app") == 0) {
        statusType = GP211_STATUS_TYPE_APPLICATIONS;

        if (!lc_state) {
            fprintf(stderr, "status app: --lc <state> required (locked|selectable)\n");
            return -1;
        }

        if (strcmp(lc_state, "locked") == 0) {
            lifeCycleState = GP211_LIFE_CYCLE_APPLICATION_LOCKED;
        } else if (strcmp(lc_state, "selectable") == 0) {
            lifeCycleState = GP211_LIFE_CYCLE_APPLICATION_SELECTABLE;
        } else {
            fprintf(stderr, "status app: invalid lifecycle state '%s' (use: locked|selectable)\n", lc_state);
            return -1;
        }
    } else if (strcmp(element_type, "sd-app") == 0) {
        statusType = GP211_STATUS_TYPE_SECURITY_DOMAIN_AND_APPLICATIONS;

        if (!lc_state) {
            fprintf(stderr, "status sd-app: --lc <state> required (locked|unlocked)\n");
            return -1;
        }

        if (strcmp(lc_state, "locked") == 0) {
            lifeCycleState = GP211_LIFE_CYCLE_SECURITY_DOMAIN_LOCKED;
        } else if (strcmp(lc_state, "unlocked") == 0) {
            lifeCycleState = 0;
        } else {
            fprintf(stderr, "status app: invalid lifecycle state '%s' (use: locked|unlocked)\n", lc_state);
            return -1;
        }
    } else {
        fprintf(stderr, "status: invalid element type '%s' (use: isd|sd|app|sd-app)\n", element_type);
        return -1;
    }

    // Call GP211_set_status
    if (!status_ok(GP211_set_status(ctx, info, sec, statusType, aid, (DWORD)aidlen, lifeCycleState), true)) {
        return -1;
    }

    return 0;
}

static int cmd_store(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "store: requires <aid> <data> arguments\n");
        return -1;
    }

    // Parse options
    BYTE encryptionFlags = STORE_DATA_ENCRYPTION_NO_INFORMATION;
    BYTE formatFlags = STORE_DATA_FORMAT_NO_INFORMATION;
    BOOL responseDataExpected = false;

    int i = 0;
    while (i < argc - 2) {  // Leave at least 2 args for aid and data
        const char *arg = argv[i];
        if (strcmp(arg, "--encryption") == 0 || strcmp(arg, "-e") == 0) {
            if (i + 1 >= argc - 2) {
                fprintf(stderr, "store: --encryption requires argument\n");
                return -1;
            }
            i++;
            const char *val = argv[i];
            if (strcmp(val, "noinfo") == 0) {
                encryptionFlags = STORE_DATA_ENCRYPTION_NO_INFORMATION;
            } else if (strcmp(val, "app") == 0) {
                encryptionFlags = STORE_DATA_ENCRYPTION_APPLICATION_DEPENDENT;
            } else if (strcmp(val, "enc") == 0) {
                encryptionFlags = STORE_DATA_ENCRYPTION_ENCRYPTED;
            } else {
                fprintf(stderr, "store: unknown encryption value '%s' (use: noinfo, app, enc)\n", val);
                return -1;
            }
        } else if (strcmp(arg, "--format") == 0 || strcmp(arg, "-f") == 0) {
            if (i + 1 >= argc - 2) {
                fprintf(stderr, "store: --format requires argument\n");
                return -1;
            }
            i++;
            const char *val = argv[i];
            if (strcmp(val, "noinfo") == 0) {
                formatFlags = STORE_DATA_FORMAT_NO_INFORMATION;
            } else if (strcmp(val, "dgi") == 0) {
                formatFlags = STORE_DATA_FORMAT_DGI;
            } else if (strcmp(val, "ber") == 0) {
                formatFlags = STORE_DATA_FORMAT_BER_TLV;
            } else {
                fprintf(stderr, "store: unknown format value '%s' (use: noinfo, dgi, ber)\n", val);
                return -1;
            }
        } else if (strcmp(arg, "--response") == 0 || strcmp(arg, "-r") == 0) {
            if (i + 1 >= argc - 2) {
                fprintf(stderr, "store: --response requires argument\n");
                return -1;
            }
            i++;
            const char *val = argv[i];
            if (strcmp(val, "true") == 0 || strcmp(val, "1") == 0) {
                responseDataExpected = true;
            } else if (strcmp(val, "false") == 0 || strcmp(val, "0") == 0) {
                responseDataExpected = false;
            } else {
                fprintf(stderr, "store: --response expects true/false or 1/0\n");
                return -1;
            }
        } else {
            break;  // Not an option, must be aid
        }
        i++;
    }

    if (argc - i < 2) {
        fprintf(stderr, "store: requires <aid> <data> positional arguments\n");
        return -1;
    }

    const char *aid_hex = argv[i];
    const char *data_str = argv[i + 1];

    // Parse AID
    unsigned char aid[16];
    size_t aidlen = sizeof(aid);
    if (hex_to_bytes(aid_hex, aid, &aidlen) != 0) {
        fprintf(stderr, "store: invalid AID hex string\n");
        return -1;
    }

    // Parse data using compact_hex to support flexible format
    char compacted[8192];
    if (compact_hex(data_str, compacted, sizeof(compacted)) != 0) {
        fprintf(stderr, "store: invalid data hex string\n");
        return -1;
    }

    unsigned char data[4096];
    size_t datalen = sizeof(data);
    if (hex_to_bytes(compacted, data, &datalen) != 0) {
        fprintf(stderr, "store: failed to parse data hex\n");
        return -1;
    }

    // Step 1: Install for personalization
    if (!status_ok(GP211_install_for_personalization(ctx, info, sec, aid, (DWORD)aidlen), false)) {
        fprintf(stderr, "store: GP211_install_for_personalization failed\n");
        return -1;
    }

    // Step 2: Store data
    if (!status_ok(GP211_store_data(ctx, info, sec, encryptionFlags, formatFlags,
                                     responseDataExpected, data, (DWORD)datalen), false)) {
        fprintf(stderr, "store: GP211_store_data failed\n");
        return -1;
    }

    printf("Store data successful\n");
    return 0;
}

static int cmd_list_readers(void) {
    // Establish a temporary PC/SC context and enumerate all readers (like gpshell.c:list_readers)
    OPGP_CARD_CONTEXT ctx; memset(&ctx, 0, sizeof(ctx));
    _tcsncpy(ctx.libraryName, _T("gppcscconnectionplugin"), _tcslen(_T("gppcscconnectionplugin"))+1);
    _tcsncpy(ctx.libraryVersion, _T("1"), _tcslen(_T("1"))+1);
    OPGP_ERROR_STATUS s = OPGP_establish_context(&ctx);
    if (!status_ok(s, true)) { fprintf(stderr, "list-readers: failed to establish PC/SC context\n"); return -1; }

    TCHAR buf[MAX_READERS_BUF];
    DWORD len = (DWORD)ARRAY_SIZE(buf);
    s = OPGP_list_readers(ctx, buf, &len, 0);
    if (!status_ok(s, true)) {
        _ftprintf(stderr, _T("list-readers failed with error 0x%08X (%s)\n"), (unsigned int)s.errorCode, s.errorMessage);
        OPGP_release_context(&ctx);
        return -1;
    }
    for (DWORD j = 0; j < len; ) {
        if (buf[j] == _T('\0')) break; // end of multi-string
        _tprintf(_T("* reader name %s\n"), &buf[j]);
        j += (DWORD)_tcslen(&buf[j]) + 1;
    }
    OPGP_release_context(&ctx);
    return 0;
}


static const char* get_ic_fab_name(USHORT id) {
    switch (id) {
        case 0x4790: return "NXP Semiconductors";
        case 0x4090: return "Infineon Technologies";
        case 0x4070: return "Infineon (Legacy)";
        case 0x4250: return "Samsung";
        case 0x3060: return "Renesas";
        case 0x4180: return "Atmel";
        case 0x4220: return "Thales (Legacy Gemplus/Gemalto)";
        case 0x1671: return "Giesecke+Devrient (G+D)";
        case 0x4750:
        case 0x2050: return "STMicroelectronics";
        default: return "Unknown Fabricator";
    }
}

static const char* get_ic_type_name(USHORT id) {
    switch (id) {
        // NXP SmartMX3 (P71 Family)
        case 0xD321: return "NXP SmartMX3 P71D321";
        case 0xD600: return "NXP SmartMX3 P71D600";

            // NXP SmartMX2 (P60 Family)
        case 0x5183: return "NXP SmartMX2 (P60-Series)";
            // NXP Legacy
        case 0x5205: return "SmartMX (P5C-Series)";
            // Infineon
        case 0x1915: return "Infineon SLC38-Series";
        case 0x0062:
        case 0x6642:
        case 0x5072: return "Infineon SLE66-Series";
        case 0x6128:
        case 0x6162: return "Infineon SLE66PE-Series";
        case 0x6514: return "Infineon SLE78-Series";

            // STMicroelectronics
        case 0x5000: return "STMicroelectronics ST23-Series";
        case 0x0061: return "STMicroelectronics ST33-Series";

        default: return "Unknown IC Type";
    }
}

static const char* get_os_id_name(USHORT id) {
    switch (id) {
        case 0x4090: return "Infineon Technologies";
        case 0x4700:
        case 0x4791: return "NXP JCOP";
        case 0x4051: return "IBM JCOP";
        case 0x4041: return "Oberthur / IDEMIA OS";
        case 0xA005: return "Oberthur AuthentIC";
        case 0x1671: return "G+D Sm@rtCafe";
        case 0xD001: return "G+D OS";
        case 0x0011: return "Cyberflex OS";
        case 0x1981: return "Palmera Protect V5";
        case 0x1291: return "GemXpresso Pro";
        default: return "Unknown OS";
    }
}

static int cmd_cplc(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    OPGP_CPLC cplc_data;

    if (!status_ok(OPGP_get_cplc(ctx, info, sec, &cplc_data), false)) {
        fprintf(stderr, "clpc: OPGP_get_cplc failed\n");
        return -1;
    }

    {
        const char *name = get_ic_fab_name(cplc_data.icFabricator);
        if (strncmp(name, "Unknown", 7) == 0) {
            printf("IC Fabricator : %04X\n", cplc_data.icFabricator);
        } else {
            printf("IC Fabricator : %s\n", name);
        }
    }
    {
        const char *name = get_ic_type_name(cplc_data.icType);
        if (strncmp(name, "Unknown", 7) == 0) {
            printf("IC Type       : %04X\n", cplc_data.icType);
        } else {
            printf("IC Type       : %s\n", name);
        }
    }
    {
        const char *name = get_os_id_name(cplc_data.operatingSystemId);
        if (strncmp(name, "Unknown", 7) == 0) {
            printf("OS ID         : %04X\n", cplc_data.operatingSystemId);
        } else {
            printf("OS ID         : %s\n", name);
        }
    }

    print_cplc_date_field_ushort("Operating System release date", cplc_data.operatingSystemReleaseDate);
    printf("Operating System release level : %04X\n", cplc_data.operatingSystemReleaseLevel);
    print_cplc_date_field_ushort("IC Fabrication Date", cplc_data.icFabricationDate);
    {
        DWORD serial = ((DWORD)cplc_data.icSerialNumberHigh << 16) | cplc_data.icSerialNumberLow;
        printf("IC Serial Number : %u\n", (unsigned int)serial);
    }
    printf("IC Batch Identifier : %04X\n", cplc_data.icBatchIdentifier);
    printf("IC Module Fabricator : %04X\n", cplc_data.icModuleFabricator);
    print_cplc_date_field_ushort("IC Module Packaging Date", cplc_data.icModulePackagingDate);
    printf("ICC Manufacturer : %04X\n", cplc_data.iccManufacturer);
    print_cplc_date_field_ushort("IC Embedding Date", cplc_data.icEmbeddingDate);
    printf("IC Pre-Personalizer : %04X\n", cplc_data.icPrePersonalizer);
    print_cplc_date_field_ushort("IC Pre-Perso. Equipment Date", cplc_data.icPrePersonalizationEquipmentDate);
    {
        printf("IC Pre-Perso. Equipment ID : %08lX", (unsigned long)cplc_data.icPrePersonalizationEquipmentId);
        printf("\n");
    }
    printf("IC Personalizer : %04X\n", cplc_data.icPersonalizer);
    print_cplc_date_field_ushort("IC Personalization Date", cplc_data.icPersonalizationDate);
    {
        printf("IC Perso. Equipment ID : %08lX\n", (unsigned long)cplc_data.icPersonalizationEquipmentId);
    }
    return 0;
}

static int cmd_card_info(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    GP211_CARD_RECOGNITION_DATA data;
    if (!status_ok(GP211_get_card_recognition_data(ctx, info, sec, &data), false)) {
        fprintf(stderr, "card-info: GP211_get_card_recognition_data failed\n");
        return -1;
    }

    if (data.version[0] != '\0') {
        printf("GlobalPlatform Version : %s\n", data.version);
    }

    if (data.scpLength == 0) {
        printf("SCP List : (none)\n");
    } else {
        for (DWORD i = 0; i < data.scpLength; i++) {
            BYTE implBytes[GP211_MAX_CARD_RECOGNITION_SCP_IMPL_OID_BYTES];
            size_t implLen = 0;
            char implHex[2 * GP211_MAX_CARD_RECOGNITION_SCP_IMPL_OID_BYTES + 1];
            char scpiDetails[256];
            implLen = scp_impl_to_bytes(&data, i, implBytes, sizeof(implBytes));
            scp_impl_to_hex(&data, i, implHex, sizeof(implHex));
            scpi_to_string(data.scp[i], implBytes, implLen, scpiDetails, sizeof(scpiDetails));
            if (data.scpLength == 1) {
                if (scpiDetails[0] != '\0') {
                    printf("SCP : SCP%02X i=%s [%s]\n", data.scp[i], implHex, scpiDetails);
                } else {
                    printf("SCP : SCP%02X i=%s\n", data.scp[i], implHex);
                }
            } else {
                if (scpiDetails[0] != '\0') {
                    printf("SCP #%u : SCP%02X i=%s [%s]\n", (unsigned int)i, data.scp[i], implHex, scpiDetails);
                } else {
                    printf("SCP #%u : SCP%02X i=%s\n", (unsigned int)i, data.scp[i], implHex);
                }
            }
        }
    }

    if (data.cardConfigurationDetailsOidLength > 0) {
        print_card_data_oid_field("Card Configuration Details", data.cardConfigurationDetailsOid,
                                  data.cardConfigurationDetailsOidLength);
    }
    if (data.cardConfigurationDetailsLength > 0) {
        print_card_data_hex_field("Card Configuration Details Data", data.cardConfigurationDetails,
                                  data.cardConfigurationDetailsLength);
    }

    if (data.cardChipDetailsOidLength > 0) {
        print_card_data_oid_field("Card/Chip Details", data.cardChipDetailsOid,
                                  data.cardChipDetailsOidLength);
    }
    if (data.cardChipDetailsLength > 0) {
        print_card_data_hex_field("Card/Chip Details Data", data.cardChipDetails,
                                  data.cardChipDetailsLength);
    }

    if (data.issuerSecurityDomainsTrustPointCertificateInformationOidLength > 0) {
        print_card_data_oid_field("ISD Trust Point Cert Info",
                                  data.issuerSecurityDomainsTrustPointCertificateInformationOid,
                                  data.issuerSecurityDomainsTrustPointCertificateInformationOidLength);
    }
    if (data.issuerSecurityDomainsTrustPointCertificateInformationLength > 0) {
        print_card_data_hex_field("ISD Trust Point Cert Info Data",
                                  data.issuerSecurityDomainsTrustPointCertificateInformation,
                                  data.issuerSecurityDomainsTrustPointCertificateInformationLength);
    }

    if (data.issuerSecurityDomainCertificateInformationOidLength > 0) {
        print_card_data_oid_field("ISD Certificate Info", data.issuerSecurityDomainCertificateInformationOid,
                                  data.issuerSecurityDomainCertificateInformationOidLength);
    }
    if (data.issuerSecurityDomainCertificateInformationLength > 0) {
        print_card_data_hex_field("ISD Certificate Info Data",
                                  data.issuerSecurityDomainCertificateInformation,
                                  data.issuerSecurityDomainCertificateInformationLength);
    }

    return 0;
}

static int cmd_card_capability(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    GP211_CARD_CAPABILITY_INFORMATION data;
    if (!status_ok(GP211_get_card_capability_information(ctx, info, sec, &data), false)) {
        fprintf(stderr, "card-cap: GP211_get_card_capability_information failed\n");
        return -1;
    }

    for (DWORD i = 0; i < data.scpInformationLength; i++) {
        char label[64];
        if (data.scpInformationLength == 1) {
            printf("SCP : SCP%02X\n", data.scpInformation[i].scpIdentifier);
        } else {
            printf("SCP #%u : SCP%02X\n", (unsigned int)i, data.scpInformation[i].scpIdentifier);
        }
        if (data.scpInformation[i].scpOptionsLength > 0) {
            if (data.scpInformationLength == 1) snprintf(label, sizeof(label), "SCP Options");
            else snprintf(label, sizeof(label), "SCP #%u Options", (unsigned int)i);
            print_capability_scpi_csv(label, data.scpInformation[i].scpOptions, data.scpInformation[i].scpOptionsLength);
        }
        if (data.scpInformation[i].scpOptionsMaskLength > 0) {
            if (data.scpInformationLength == 1) snprintf(label, sizeof(label), "SCP Options Mask");
            else snprintf(label, sizeof(label), "SCP #%u Options Mask", (unsigned int)i);
            print_capability_hex_bytes_csv(label, data.scpInformation[i].scpOptionsMask, data.scpInformation[i].scpOptionsMaskLength);
        }
        if (data.scpInformation[i].supportedKeySizes != 0) {
            if (data.scpInformationLength == 1) snprintf(label, sizeof(label), "SCP Supported Key Sizes");
            else snprintf(label, sizeof(label), "SCP #%u Supported Key Sizes", (unsigned int)i);
            {
                char kbuf[64];
                gp211_scp_supported_key_sizes_to_string(data.scpInformation[i].supportedKeySizes, kbuf, sizeof(kbuf));
                if (strcmp(kbuf, "none") == 0) {
                    printf("%s : 0x%02X\n", label, data.scpInformation[i].supportedKeySizes);
                } else {
                    printf("%s : %s\n", label, kbuf);
                }
            }
        }
        if (data.scpInformation[i].tlsCipherSuitesLength > 0) {
            if (data.scpInformationLength == 1) snprintf(label, sizeof(label), "SCP TLS Cipher Suites");
            else snprintf(label, sizeof(label), "SCP #%u TLS Cipher Suites", (unsigned int)i);
            print_capability_hex_field(label, data.scpInformation[i].tlsCipherSuites, data.scpInformation[i].tlsCipherSuitesLength);
        }
        if (data.scpInformation[i].maxPskLength != 0) {
            if (data.scpInformationLength == 1) snprintf(label, sizeof(label), "SCP Max PSK Length");
            else snprintf(label, sizeof(label), "SCP #%u Max PSK Length", (unsigned int)i);
            printf("%s : %u\n", label, (unsigned int)data.scpInformation[i].maxPskLength);
        }
    }

    if (data.ssdPrivileges[0] || data.ssdPrivileges[1] || data.ssdPrivileges[2]) {
        DWORD p = gp211_privileges_3bytes_to_dword(data.ssdPrivileges);
        char pbuf[512];
        privileges_to_string(p, pbuf, sizeof(pbuf));
        printf("SSD Privileges : [%s]\n", pbuf);
    }
    if (data.appPrivileges[0] || data.appPrivileges[1] || data.appPrivileges[2]) {
        DWORD p = gp211_privileges_3bytes_to_dword(data.appPrivileges);
        char pbuf[512];
        privileges_to_string(p, pbuf, sizeof(pbuf));
        printf("Application Privileges : [%s]\n", pbuf);
    }
    if (data.lfdbhAlgorithmsLength > 0) {
        char abuf[256];
        gp211_lfdbh_algorithms_to_string(data.lfdbhAlgorithms, data.lfdbhAlgorithmsLength, abuf, sizeof(abuf));
        printf("Load-file data block hash Algorithms : %s\n", abuf);
    }
    if (data.lfdbencryptionCipherSuites != 0) {
        char sbuf[256];
        gp211_lfdb_encryption_to_string(data.lfdbencryptionCipherSuites, sbuf, sizeof(sbuf));
        if (strcmp(sbuf, "none") == 0) {
            printf("Load-file data block Encryption Cipher Suites : 0x%02X\n", data.lfdbencryptionCipherSuites);
        } else {
            printf("Load-file data block Encryption Cipher Suites : %s\n", sbuf);
        }
    }
    if (data.tokenCipherSuites != 0) {
        char sbuf[256];
        gp211_signature_cs_to_string(data.tokenCipherSuites, sbuf, sizeof(sbuf));
        if (strcmp(sbuf, "none") == 0) {
            printf("Token Cipher Suites : 0x%04X\n", data.tokenCipherSuites);
        } else {
            printf("Token Cipher Suites : %s\n", sbuf);
        }
    }
    if (data.receiptCipherSuites != 0) {
        char sbuf[256];
        gp211_signature_cs_to_string(data.receiptCipherSuites, sbuf, sizeof(sbuf));
        if (strcmp(sbuf, "none") == 0) {
            printf("Receipt Cipher Suites : 0x%04X\n", data.receiptCipherSuites);
        } else {
            printf("Receipt Cipher Suites : %s\n", sbuf);
        }
    }
    if (data.dapCipherSuites != 0) {
        char sbuf[256];
        gp211_signature_cs_to_string(data.dapCipherSuites, sbuf, sizeof(sbuf));
        if (strcmp(sbuf, "none") == 0) {
            printf("DAP Cipher Suites : 0x%04X\n", data.dapCipherSuites);
        } else {
            printf("DAP Cipher Suites : %s\n", sbuf);
        }
    }
    if (data.keyParameterReferenceListLength > 0) {
        print_capability_hex_field("Key Parameter Reference List", data.keyParameterReferenceList,
                                   data.keyParameterReferenceListLength);
    }

    {
        const char *elf = gp211_elf_upgrade_to_string(data.elfUpgrade);
        if (elf) printf("ELF Upgrade Options : %s\n", elf);
        else if (data.elfUpgrade != 0) printf("ELF Upgrade Options : 0x%02X\n", data.elfUpgrade);
    }

    if (data.tokenIdentifierDenyList) {
        printf("Token Identifier Deny List : yes\n");
    }
    if (data.securityDomainSelfRemoval) {
        printf("Security Domain Self-Removal : yes\n");
    }

    return 0;
}

static int cmd_card_resources(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    OPGP_EXTENDED_CARD_RESOURCE_INFORMATION data;
    if (!status_ok(OPGP_get_extended_card_resources_information(ctx, info, sec, &data), false)) {
        fprintf(stderr, "card-resources: OPGP_get_extended_card_resources_information failed\n");
        return -1;
    }

    printf("Num Applications : %lu\n", (unsigned long)data.numInstalledApplications);
    printf("Free non-volatile memory (B) : %lu\n", (unsigned long)data.freeNonVolatileMemory);
    printf("Free volatile memory (B) : %lu\n", (unsigned long)data.freeVolatileMemory);
    return 0;
}

static int cmd_diversification(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    BYTE data[256];
    DWORD dataLen = sizeof(data);
    if (!status_ok(GP211_get_diversification_data(ctx, info, sec, data, &dataLen), false)) {
        fprintf(stderr, "diversification: GP211_get_diversification_data failed\n");
        return -1;
    }
    print_hex(data, dataLen);
    printf("\n");
    return 0;
}

static int cmd_iin(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    BYTE data[256];
    DWORD dataLen = sizeof(data);
    if (!status_ok(GP211_get_data(ctx, info, sec, (BYTE *)GP211_GET_DATA_ISSUER_IDENTIFICATION_NUMBER, data, &dataLen), false)) {
        fprintf(stderr, "iin: GP211_get_data failed\n");
        return -1;
    }
    print_hex(data, dataLen);
    printf("\n");
    return 0;
}

static int cmd_cin(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    BYTE data[256];
    DWORD dataLen = sizeof(data);
    if (!status_ok(GP211_get_data(ctx, info, sec, (BYTE *)GP211_GET_DATA_CARD_IMAGE_NUMBER, data, &dataLen), false)) {
        fprintf(stderr, "cin: GP211_get_data failed\n");
        return -1;
    }
    print_hex(data, dataLen);
    printf("\n");
    return 0;
}

static int cmd_seq_counter(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    DWORD counter = 0;
    if (!status_ok(GP211_get_sequence_counter(ctx, info, sec, &counter), false)) {
        fprintf(stderr, "seq-counter: GP211_get_sequence_counter failed\n");
        return -1;
    }
    printf("Sequence Counter : %lu\n", (unsigned long)counter);
    return 0;
}

static int cmd_confirm_counter(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    DWORD counter = 0;
    if (!status_ok(GP211_get_confirmation_counter(ctx, info, sec, &counter), false)) {
        fprintf(stderr, "confirm-counter: GP211_get_confirmation_counter failed\n");
        return -1;
    }
    printf("Confirmation Counter : %lu\n", (unsigned long)counter);
    return 0;
}

static int cmd_card_data(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    int rc = 0;

    printf("== iin ==\n");
    rc = cmd_iin(ctx, info, sec);

    printf("\n== cin ==\n");
    rc |= cmd_cin(ctx, info, sec);

    printf("\n== cplc ==\n");
    rc |= cmd_cplc(ctx, info, sec);

    printf("\n== card-info ==\n");
    rc |= cmd_card_info(ctx, info, sec);

    printf("\n== card-cap ==\n");
    rc |= cmd_card_capability(ctx, info, sec);

    printf("\n== card-resources ==\n");
    rc |= cmd_card_resources(ctx, info, sec);

    printf("\n== confirm-counter ==\n");
    rc |= cmd_confirm_counter(ctx, info, sec);

    printf("\n== seq-counter ==\n");
    rc |= cmd_seq_counter(ctx, info, sec);

    printf("\n== div-data ==\n");
    rc |= cmd_diversification(ctx, info, sec);
    return rc;
}

static int cmd_scp11_cert_data(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec) {
    typedef struct {
        BYTE keyIdentifier;
        BYTE keyVersionNumber;
    } key_ref_t;

    int rc = 0;
    key_ref_t klccKeyRefs[64];
    size_t klccKeyRefCount = 0;
    BYTE certificateStore[4096];
    BYTE supportedCaData[4096];
    DWORD supportedCaDataLength;

    for (int caType = 0; caType < 2; caType++) {
        BOOL isKlcc = (caType == 1);
        unsigned short expectedOuterTag = isKlcc ? 0xFF34 : 0xFF33;
        const char *title = isKlcc ? "supported-ca-klcc-identifiers" : "supported-ca-kloc-identifiers";
        size_t offset = 0;
        size_t entry = 0;
        simple_tlv_view_t outer;

        supportedCaDataLength = sizeof(supportedCaData);
        printf("\n== %s ==\n", title);
        {
            OPGP_ERROR_STATUS status = GP211_get_supported_ca_identifiers(ctx, info, sec, isKlcc,
                                                                           supportedCaData, &supportedCaDataLength);
            if (!status_ok(status, false)) {
                fprintf(stderr, "scp11-cert-data: GP211_get_supported_ca_identifiers failed (%s): 0x%08X (%s)\n",
                        title, (unsigned int)status.errorCode, status.errorMessage);
                rc = -1;
                continue;
            }
        }

        if (parse_simple_tlv_view(supportedCaData, (size_t)supportedCaDataLength, &outer) != 0
            || outer.tag != expectedOuterTag) {
            fprintf(stderr, "scp11-cert-data: could not parse %s response\n", title);
            rc = -1;
            continue;
        }

        while (offset < outer.length) {
            simple_tlv_view_t caIdTlv;
            size_t nextOffset;

            if (parse_simple_tlv_view(outer.value + offset, outer.length - offset, &caIdTlv) != 0) {
                fprintf(stderr, "scp11-cert-data: malformed %s entry\n", title);
                rc = -1;
                break;
            }

            if (caIdTlv.tag == 0x42) {
                int hasKidKvn = 0;
                BYTE listedKid = 0;
                BYTE listedKvn = 0;
                printf("CA[%lu] : ", (unsigned long)entry++);
                print_hex(caIdTlv.value, caIdTlv.length);

                nextOffset = offset + caIdTlv.tlv_length;
                if (nextOffset < outer.length) {
                    simple_tlv_view_t kidKvnTlv;
                    if (parse_simple_tlv_view(outer.value + nextOffset, outer.length - nextOffset, &kidKvnTlv) == 0
                        && kidKvnTlv.tag == 0x83 && kidKvnTlv.length == 2) {
                        hasKidKvn = 1;
                        listedKid = kidKvnTlv.value[0];
                        listedKvn = kidKvnTlv.value[1];
                        printf("  listed-kid=0x%02X listed-kvn=0x%02X",
                               listedKid, listedKvn);
                    }
                }
                if (isKlcc && hasKidKvn) {
                    int duplicate = 0;
                    for (size_t i = 0; i < klccKeyRefCount; i++) {
                        if (klccKeyRefs[i].keyIdentifier == listedKid
                            && klccKeyRefs[i].keyVersionNumber == listedKvn) {
                            duplicate = 1;
                            break;
                        }
                    }
                    if (!duplicate) {
                        if (klccKeyRefCount < ARRAY_SIZE(klccKeyRefs)) {
                            klccKeyRefs[klccKeyRefCount].keyIdentifier = listedKid;
                            klccKeyRefs[klccKeyRefCount].keyVersionNumber = listedKvn;
                            klccKeyRefCount++;
                        } else {
                            fprintf(stderr, "scp11-cert-data: too many KLCC key references, truncating\n");
                        }
                    }
                }
                printf("\n");
            }

            offset += caIdTlv.tlv_length;
        }
    }

    printf("\n== ecka-certificate-store ==\n");
    if (klccKeyRefCount == 0) {
        printf("(skipped: no KLCC identifier with key reference returned)\n");
        return rc;
    }

    for (size_t i = 0; i < klccKeyRefCount; i++) {
        DWORD certificateStoreLength = sizeof(certificateStore);
        BYTE parsedCertificateStore[16384];
        DWORD parsedCertificateStoreLength = sizeof(parsedCertificateStore);
        BYTE keyIdentifier = klccKeyRefs[i].keyIdentifier;
        BYTE keyVersionNumber = klccKeyRefs[i].keyVersionNumber;
        int parsed = 1;
        simple_tlv_view_t certificateStoreTlv;
        size_t certificateOffset = 0;
        size_t certificateIndex = 0;
        unsigned short certificateTag = 0;

        if (i > 0) {
            printf("\n");
        }
        printf("KID=0x%02X KVN=0x%02X\n", keyIdentifier, keyVersionNumber);

        {
            OPGP_ERROR_STATUS status = GP211_get_ecka_certificate(ctx, info, sec, keyVersionNumber, keyIdentifier,
                                                                  certificateStore, &certificateStoreLength);
            if (!status_ok(status, false)) {
                fprintf(stderr,
                        "scp11-cert-data: GP211_get_ecka_certificate failed (kid=0x%02X kvn=0x%02X): 0x%08X (%s)\n",
                        keyIdentifier, keyVersionNumber, (unsigned int)status.errorCode, status.errorMessage);
                rc = -1;
                continue;
            }
        }

        printf("Length : %lu\n", (unsigned long)certificateStoreLength);
        if (parse_simple_tlv_view(certificateStore, (size_t)certificateStoreLength, &certificateStoreTlv) != 0
            || certificateStoreTlv.tag != 0xBF21
            || certificateStoreTlv.tlv_length != (size_t)certificateStoreLength) {
            parsed = 0;
        }

        while (parsed && certificateOffset < certificateStoreTlv.length) {
            simple_tlv_view_t certificateTlv;
            if (parse_simple_tlv_view(certificateStoreTlv.value + certificateOffset,
                                      certificateStoreTlv.length - certificateOffset, &certificateTlv) != 0
                || certificateTlv.tlv_length == 0) {
                parsed = 0;
                break;
            }

            if (certificateTag == 0) {
                certificateTag = certificateTlv.tag;
                if (certificateTag != 0x7F21 && certificateTag != 0x30) {
                    parsed = 0;
                    break;
                }
            } else if (certificateTlv.tag != certificateTag) {
                parsed = 0;
                break;
            }

            if (certificateTag == 0x7F21) {
                GP211_SCP11_CERTIFICATE certificate;
                OPGP_ERROR_STATUS status = GP211_parse_scp11_certificate((PBYTE)(certificateStoreTlv.value + certificateOffset),
                                                                         (DWORD)certificateTlv.tlv_length, &certificate);
                if (!status_ok(status, false)) {
                    fprintf(stderr,
                            "scp11-cert-data: GP211_parse_scp11_certificate failed (kid=0x%02X kvn=0x%02X): 0x%08X (%s)\n",
                            keyIdentifier, keyVersionNumber, (unsigned int)status.errorCode, status.errorMessage);
                    parsed = 0;
                    break;
                }
                if (certificateIndex > 0) {
                    printf("\n");
                }
                print_scp11_certificate(&certificate, certificateIndex);
            }

            certificateOffset += certificateTlv.tlv_length;
            certificateIndex++;
        }

        if (parsed && (certificateTag == 0 || certificateOffset != certificateStoreTlv.length)) {
            parsed = 0;
        }

        if (parsed && certificateTag == 0x30) {
            OPGP_ERROR_STATUS status = GP211_parse_certificate_store(certificateStore, certificateStoreLength,
                                                                     parsedCertificateStore, &parsedCertificateStoreLength);
            if (!status_ok(status, false)) {
                fprintf(stderr,
                        "scp11-cert-data: GP211_parse_certificate_store failed (kid=0x%02X kvn=0x%02X): 0x%08X (%s)\n",
                        keyIdentifier, keyVersionNumber, (unsigned int)status.errorCode, status.errorMessage);
                parsed = 0;
            } else {
                fwrite(parsedCertificateStore, 1, parsedCertificateStoreLength, stdout);
            }
        }

        if (parsed && certificateTag == 0x30
            && (parsedCertificateStoreLength == 0 || parsedCertificateStore[parsedCertificateStoreLength - 1] != '\n')) {
            printf("\n");
        }

        if (!parsed) {
            printf("Data   : ");
            print_hex(certificateStore, certificateStoreLength);
            printf("\n");
            rc = -1;
        }
    }

    return rc;
}

static int cmd_scp11_store_cert(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    BYTE keyVersionNumber = 0;
    BYTE keyIdentifier = 0;
    int haveKeyVersionNumber = 0;
    int haveKeyIdentifier = 0;
    const char *certificateStoreFile = NULL;
    TCHAR certificateStoreFileName[MAX_PATH_BUF];
    OPGP_ERROR_STATUS status;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--kv") == 0 && i + 1 < argc) {
            keyVersionNumber = (BYTE)parse_int(argv[++i]);
            haveKeyVersionNumber = 1;
        } else if (strcmp(argv[i], "--idx") == 0 && i + 1 < argc) {
            keyIdentifier = (BYTE)parse_int(argv[++i]);
            haveKeyIdentifier = 1;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "scp11-store-cert: unknown option '%s'\n", argv[i]);
            return -1;
        } else if (certificateStoreFile == NULL) {
            certificateStoreFile = argv[i];
        } else {
            fprintf(stderr, "scp11-store-cert: unexpected argument '%s'\n", argv[i]);
            return -1;
        }
    }

    if (!haveKeyVersionNumber || !haveKeyIdentifier || certificateStoreFile == NULL) {
        fprintf(stderr, "Usage: scp11-store-cert --kv <ver> --idx <idx> <certificate-store-file>\n");
        return -1;
    }
    if (to_opgp_string(certificateStoreFile, certificateStoreFileName, ARRAY_SIZE(certificateStoreFileName)) != 0) {
        fprintf(stderr, "scp11-store-cert: certificate file path too long\n");
        return -1;
    }

    status = GP211_store_data_ecka_certificate(ctx, info, sec, keyVersionNumber, keyIdentifier, certificateStoreFileName);
    if (!status_ok(status, false)) {
        fprintf(stderr,
                "scp11-store-cert: GP211_store_data_ecka_certificate failed (kid=0x%02X kvn=0x%02X): 0x%08X (%s)\n",
                keyIdentifier, keyVersionNumber, (unsigned int)status.errorCode, status.errorMessage);
        return -1;
    }
    return 0;
}

static int cmd_scp11_store_ca_id(OPGP_CARD_CONTEXT ctx, OPGP_CARD_INFO info, GP211_SECURITY_INFO *sec, int argc, char **argv) {
    BYTE keyVersionNumber = 0;
    BYTE keyIdentifier = 0;
    int haveKeyVersionNumber = 0;
    int haveKeyIdentifier = 0;
    const char *caIdHex = NULL;
    BYTE caId[128];
    size_t caIdLength = sizeof(caId);
    OPGP_ERROR_STATUS status;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--ca-id") == 0 && i + 1 < argc) {
            caIdHex = argv[++i];
        } else if (strcmp(argv[i], "--kv") == 0 && i + 1 < argc) {
            keyVersionNumber = (BYTE)parse_int(argv[++i]);
            haveKeyVersionNumber = 1;
        } else if (strcmp(argv[i], "--idx") == 0 && i + 1 < argc) {
            keyIdentifier = (BYTE)parse_int(argv[++i]);
            haveKeyIdentifier = 1;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "scp11-store-ca-id: unknown option '%s'\n", argv[i]);
            return -1;
        } else {
            fprintf(stderr, "scp11-store-ca-id: unexpected argument '%s'\n", argv[i]);
            return -1;
        }
    }

    if (caIdHex == NULL || !haveKeyVersionNumber || !haveKeyIdentifier) {
        fprintf(stderr, "Usage: scp11-store-ca-id --ca-id <hex> --kv <ver> --idx <idx>\n");
        return -1;
    }
    if (hex_to_bytes(caIdHex, caId, &caIdLength) != 0 || caIdLength == 0) {
        fprintf(stderr, "scp11-store-ca-id: invalid --ca-id\n");
        return -1;
    }

    status = GP211_store_data_ca_kloc_kid_kvn(ctx, info, sec, caId, (DWORD)caIdLength, keyIdentifier, keyVersionNumber);
    if (!status_ok(status, false)) {
        fprintf(stderr,
                "scp11-store-ca-id: GP211_store_data_ca_kloc_kid_kvn failed (kid=0x%02X kvn=0x%02X): 0x%08X (%s)\n",
                keyIdentifier, keyVersionNumber, (unsigned int)status.errorCode, status.errorMessage);
        return -1;
    }
    return 0;
}

static int cmd_store_iin_cin(const char *cmd, int argc, char **argv,
                             const char *reader, const char *protocol, int trace, int verbose,
                             BYTE keyset_ver, BYTE key_index, int derivation, const char *sec_level_opt,
                             const BYTE *baseKey, const BYTE *enc_key, const BYTE *mac_key, const BYTE *dek_key,
                             BYTE keyLength, const char *scp_protocol, const char *scp_impl,
                             const char *scp11_cert_file, const char *scp11_sd_public_key,
                             BYTE scp11SessionKeyLength) {
    if (strcmp(cmd, "store-iin") != 0 && strcmp(cmd, "store-cin") != 0) {
        return -1;
    }
    if (argc < 1) {
        fprintf(stderr, "%s: missing identification number\n", cmd);
        return 1;
    }
    const char *id_str = argv[0];
    BYTE bcd[64];
    DWORD bcdLen = sizeof(bcd);
    OPGP_ERROR_STATUS status = OPGP_build_bcd_encoding(id_str, bcd, &bcdLen);
    if (!status_ok(status, false)) {
        fprintf(stderr, "%s: BCD encoding failed\n", cmd);
        return 1;
    }

    BYTE tlv[128];
    DWORD tlvLen = 0;
    tlv[tlvLen++] = (strcmp(cmd, "store-iin") == 0) ? 0x42 : 0x45;
    tlv[tlvLen++] = (BYTE)bcdLen;
    memcpy(tlv + tlvLen, bcd, bcdLen);
    tlvLen += bcdLen;

    OPGP_CARD_CONTEXT ctx; OPGP_CARD_INFO info; GP211_SECURITY_INFO sec;
    if (connect_pcsc(&ctx, &info, reader, protocol, trace, verbose) != 0) return 1;
    if (mutual_auth(ctx, info, &sec, keyset_ver, key_index, derivation, sec_level_opt, verbose,
                    baseKey, enc_key, mac_key, dek_key, keyLength, scp_protocol, scp_impl, scp11_cert_file,
                    scp11_sd_public_key, scp11SessionKeyLength) != 0) {
        return 1;
    }

    status = GP211_store_data(ctx, info, &sec, STORE_DATA_ENCRYPTION_NO_INFORMATION,
                              STORE_DATA_FORMAT_BER_TLV, false, tlv, tlvLen);
    if (!status_ok(status, false)) {
        fprintf(stderr, "%s: GP211_store_data failed\n", cmd);
        return 1;
    }
    return 0;
}


/* --- Dispatcher Adapters & JSON Schemas --- */

static void sync_session_globals_to(const gpshell3_session_t *session) {
    if (session) {
        if (session->selected_isd_len > 0) {
            memcpy(g_selected_isd, session->selected_isd, session->selected_isd_len);
            g_selected_isd_len = session->selected_isd_len;
        }
        if (session->current_scp) {
            g_current_scp = session->current_scp;
            g_current_scp_impl = session->current_scp_impl;
            g_current_scp_set = 1;
        }
    }
}

static void sync_session_globals_from(gpshell3_session_t *session) {
    if (session) {
        if (g_selected_isd_len > 0) {
            memcpy(session->selected_isd, g_selected_isd, g_selected_isd_len);
            session->selected_isd_len = g_selected_isd_len;
        }
        if (g_current_scp_set) {
            session->current_scp = g_current_scp;
            session->current_scp_impl = g_current_scp_impl;
        }
    }
}


/* ========================================================================= */
/* --- Command Adapters and Schemas (44 Commands) ---                        */
/* ========================================================================= */

#define GEN_SCHEMA_STUBS(name)

/* Helper to convert cJSON args to argv */
static char** json_to_argv(cJSON *args, int *argc_out) {
    if (!args || !cJSON_IsObject(args)) {
        *argc_out = 0;
        return NULL;
    }
    int count = 0;
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, args) {
        if (cJSON_IsBool(item)) {
            if (cJSON_IsTrue(item)) count += 1;
        } else if (cJSON_IsNumber(item)) {
            count += 2;
        } else if (cJSON_IsString(item)) {
            count += 2;
        }
    }
    char **argv = (char **)calloc(count + 1, sizeof(char *));
    int i = 0;
    cJSON_ArrayForEach(item, args) {
        const char *k = item->string;
        char flag[128];
        flag[0] = '\0';
        if (k) {
            snprintf(flag, sizeof(flag), "--");
            size_t flen = 2;
            for (const char *p = k; *p && flen + 2 < sizeof(flag); p++) {
                if (isupper((unsigned char)*p)) {
                    flag[flen++] = '-';
                    flag[flen++] = (char)tolower((unsigned char)*p);
                } else {
                    flag[flen++] = *p;
                }
            }
            flag[flen] = '\0';
        }

        if (cJSON_IsBool(item)) {
            if (cJSON_IsTrue(item)) {
                argv[i++] = strdup(flag);
            }
        } else if (cJSON_IsNumber(item)) {
            argv[i++] = strdup(flag);
            char numbuf[32];
            snprintf(numbuf, sizeof(numbuf), "%ld", (long)item->valuedouble);
            argv[i++] = strdup(numbuf);
        } else if (cJSON_IsString(item)) {
            if (!strcmp(k, "capFile") || !strcmp(k, "dataFile") || !strcmp(k, "pemFile") || !strcmp(k, "keyFile") || !strcmp(k, "certFile") || !strcmp(k, "data") || !strcmp(k, "aid") || !strcmp(k, "instanceAid") || !strcmp(k, "apdu")) {
                argv[i++] = strdup(item->valuestring);
            } else {
                argv[i++] = strdup(flag);
                argv[i++] = strdup(item->valuestring);
            }
        }
    }
    *argc_out = i;
    return argv;
}

static void free_argv(int argc, char **argv) {
    if (!argv) return;
    for (int i = 0; i < argc; i++) {
        if (argv[i]) free(argv[i]);
    }
    free(argv);
}

/* 1. list-readers */
cJSON *gpshell3_cmd_list_readers_input_schema(void) { return gpshell3_schema_object(); }
cJSON *gpshell3_cmd_list_readers_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_array(s, "readers", "List of smart card reader names", "string", true);
    return s;
}
int gpshell3_cmd_list_readers_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)session; (void)argc; (void)argv;
    gpshell3_output_set_command(out, "gpshell3_list_readers");
    if (out && out->mode == OUTPUT_FORMAT_JSON) {
        OPGP_CARD_CONTEXT local_ctx; memset(&local_ctx, 0, sizeof(local_ctx));
        _tcsncpy(local_ctx.libraryName, _T("gppcscconnectionplugin"), _tcslen(_T("gppcscconnectionplugin")) + 1);
        _tcsncpy(local_ctx.libraryVersion, _T("1"), _tcslen(_T("1")) + 1);
        OPGP_CARD_CONTEXT *pctx = (session && session->is_connected) ? &session->ctx : &local_ctx;
        if (!session || !session->is_connected) {
            OPGP_ERROR_STATUS s = OPGP_establish_context(pctx);
            if (!status_ok(s, false)) { gpshell3_report_opgp_error(out, NULL, s, "Failed to establish context"); return -1; }
        }
        TCHAR rlist[MAX_READERS_BUF]; DWORD rlen = (DWORD)ARRAY_SIZE(rlist);
        OPGP_ERROR_STATUS s = OPGP_list_readers(*pctx, rlist, &rlen, 0);
        if (!session || !session->is_connected) OPGP_release_context(pctx);
        if (!status_ok(s, false)) { gpshell3_report_opgp_error(out, NULL, s, "Failed to list readers"); return -1; }
        cJSON *arr = cJSON_CreateArray();
        DWORD j = 0;
        while (j < rlen && rlist[j] != _T('\0')) {
            char rname[256];
#if defined(_WIN32) && defined(UNICODE)
            WideCharToMultiByte(CP_UTF8, 0, &rlist[j], -1, rname, sizeof(rname), NULL, NULL);
#else
            strncpy(rname, &rlist[j], sizeof(rname) - 1); rname[sizeof(rname) - 1] = '\0';
#endif
            cJSON_AddItemToArray(arr, cJSON_CreateString(rname));
            j += (DWORD)_tcslen(&rlist[j]) + 1;
        }
        gpshell3_output_add_array(out, "readers", arr);
        return 0;
    }
    return cmd_list_readers();
}
int gpshell3_cmd_list_readers_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    (void)args;
    return gpshell3_cmd_list_readers_cli(session, 0, NULL, out);
}

/* 2. hash */
cJSON *gpshell3_cmd_hash_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "capFile", "Path to the Java Card CAP file", true);
    const char *algs[] = {"sha1", "sha256"};
    gpshell3_schema_add_prop_enum(s, "algorithm", "Hash algorithm (sha1 or sha256)", algs, 2, false);
    return s;
}
cJSON *gpshell3_cmd_hash_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "hash", "Hex-encoded cryptographic hash", true);
    return s;
}
int gpshell3_cmd_hash_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)session;
    gpshell3_output_set_command(out, "gpshell3_hash");
    if (out && out->mode == OUTPUT_FORMAT_JSON) {
        const char *hash_alg = "sha256";
        int ai = 0;
        for (; ai < argc; ai++) {
            if (!strcmp(argv[ai], "--sha1")) hash_alg = "sha1";
            else if (!strcmp(argv[ai], "--sha256") || !strcmp(argv[ai], "--sha2-256")) hash_alg = "sha256";
            else if (!strcmp(argv[ai], "--sha384") || !strcmp(argv[ai], "--sha2-384")) hash_alg = "sha384";
            else if (!strcmp(argv[ai], "--sha512") || !strcmp(argv[ai], "--sha2-512")) hash_alg = "sha512";
            else if (!strcmp(argv[ai], "--sm3")) hash_alg = "sm3";
            else break;
        }
        if (ai >= argc) { gpshell3_report_error(out, "MISSING_ARGUMENT", "Missing CAP file"); return -1; }
        TCHAR cap_t[MAX_PATH_BUF];
        if (to_opgp_string(argv[ai], cap_t, ARRAY_SIZE(cap_t)) != 0) { gpshell3_report_error(out, "INVALID_PATH", "Path too long"); return -1; }
        BYTE hashType = GP211_HASH_SHA256;
        DWORD hash_len = 32;
        if (!strcmp(hash_alg, "sha1")) { hashType = GP211_HASH_SHA1; hash_len = 20; }
        else if (!strcmp(hash_alg, "sha256")) { hashType = GP211_HASH_SHA256; hash_len = 32; }
        else if (!strcmp(hash_alg, "sha384")) { hashType = GP211_HASH_SHA384; hash_len = 48; }
        else if (!strcmp(hash_alg, "sha512")) { hashType = GP211_HASH_SHA512; hash_len = 64; }
        else if (!strcmp(hash_alg, "sm3")) { hashType = GP211_HASH_SM3; hash_len = 32; }

        BYTE hash[64]; memset(hash, 0, sizeof(hash));
        if (!status_ok(GP211_calculate_load_file_data_block_hash(cap_t, hash, hash_len, hashType), false)) {
            gpshell3_report_error(out, "HASH_FAILED", "Failed to calculate hash");
            return -1;
        }
        gpshell3_output_add_hex(out, "hash", hash, hash_len);
        return 0;
    }
    return cmd_hash(argc, argv);
}
int gpshell3_cmd_hash_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    if (!args) {
        gpshell3_report_error(out, "MISSING_ARGUMENT", "Missing arguments for hash");
        return -1;
    }
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_hash_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 3. sign-dap */
cJSON *gpshell3_cmd_sign_dap_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    const char *types[] = {"rsa", "ecc", "aes"};
    gpshell3_schema_add_prop_enum(s, "type", "DAP key type (rsa, ecc, aes)", types, 3, false);
    gpshell3_schema_add_prop_string(s, "hash", "Hash hex string", true);
    gpshell3_schema_add_prop_string(s, "key", "Key (hex string for aes, PEM path for rsa/ecc)", true);
    gpshell3_schema_add_prop_string(s, "outputFile", "Output file for signature", false);
    return s;
}
cJSON *gpshell3_cmd_sign_dap_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "dap", "Hex-encoded DAP signature", true);
    return s;
}
int gpshell3_cmd_sign_dap_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)session;
    gpshell3_output_set_command(out, "gpshell3_sign_dap");
    const char *dap_type = "aes";
    int ai = 0;
    if (argc > 0 && (argv[0][0] != '-' || !strcmp(argv[0], "rsa") || !strcmp(argv[0], "ecc") || !strcmp(argv[0], "aes"))) {
        if (!strcmp(argv[0], "rsa") || !strcmp(argv[0], "ecc") || !strcmp(argv[0], "aes")) {
            dap_type = argv[0];
            ai = 1;
        }
    }
    return cmd_sign_dap(dap_type, argc - ai, argv + ai);
}
int gpshell3_cmd_sign_dap_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_sign_dap_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 4. sign-load-token */
cJSON *gpshell3_cmd_sign_load_token_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "key", "Private key (PEM path)", true);
    gpshell3_schema_add_prop_string(s, "loadFileAid", "Load File AID (hex)", true);
    gpshell3_schema_add_prop_string(s, "targetSd", "Target Security Domain AID (hex)", true);
    gpshell3_schema_add_prop_string(s, "hash", "Load File Data Block Hash (hex)", true);
    return s;
}
cJSON *gpshell3_cmd_sign_load_token_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "token", "Hex-encoded Delegated Management Load Token", true);
    return s;
}
int gpshell3_cmd_sign_load_token_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)session;
    gpshell3_output_set_command(out, "gpshell3_sign_load_token");
    return cmd_sign_load_token(argc, argv);
}
int gpshell3_cmd_sign_load_token_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_sign_load_token_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 5. sign-install-token */
cJSON *gpshell3_cmd_sign_install_token_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "key", "Private key (PEM path)", true);
    gpshell3_schema_add_prop_string(s, "loadFileAid", "Load File AID (hex)", true);
    gpshell3_schema_add_prop_string(s, "moduleAid", "Module AID (hex)", true);
    gpshell3_schema_add_prop_string(s, "appletAid", "Applet instance AID (hex)", true);
    gpshell3_schema_add_prop_string(s, "privileges", "Privileges bitfield (hex)", true);
    return s;
}
cJSON *gpshell3_cmd_sign_install_token_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "token", "Hex-encoded Delegated Management Install Token", true);
    return s;
}
int gpshell3_cmd_sign_install_token_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)session;
    gpshell3_output_set_command(out, "gpshell3_sign_install_token");
    return cmd_gp211_calculate_install_token(argc, argv);
}
int gpshell3_cmd_sign_install_token_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_sign_install_token_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 6. sign-extradition-token */
cJSON *gpshell3_cmd_sign_extradition_token_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "key", "Private key (PEM path)", true);
    gpshell3_schema_add_prop_string(s, "targetSd", "Target Security Domain AID (hex)", true);
    gpshell3_schema_add_prop_string(s, "applet", "Application AID to extradite (hex)", true);
    return s;
}
cJSON *gpshell3_cmd_sign_extradition_token_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "token", "Hex-encoded Delegated Management Extradition Token", true);
    return s;
}
int gpshell3_cmd_sign_extradition_token_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)session;
    gpshell3_output_set_command(out, "gpshell3_sign_extradition_token");
    return cmd_gp211_calculate_extradition_token(argc, argv);
}
int gpshell3_cmd_sign_extradition_token_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_sign_extradition_token_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 7. sign-update-registry-token */
cJSON *gpshell3_cmd_sign_update_registry_token_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "key", "Private key (PEM path)", true);
    gpshell3_schema_add_prop_string(s, "applet", "Application AID (hex)", true);
    gpshell3_schema_add_prop_string(s, "privileges", "New privileges (hex)", true);
    return s;
}
cJSON *gpshell3_cmd_sign_update_registry_token_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "token", "Hex-encoded Delegated Management Update Registry Token", true);
    return s;
}
int gpshell3_cmd_sign_update_registry_token_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)session;
    gpshell3_output_set_command(out, "gpshell3_sign_update_registry_token");
    return cmd_gp211_calculate_update_registry_token(argc, argv);
}
int gpshell3_cmd_sign_update_registry_token_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_sign_update_registry_token_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 8. sign-delete-token */
cJSON *gpshell3_cmd_sign_delete_token_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "key", "Private key (PEM path)", true);
    gpshell3_schema_add_prop_string(s, "aid", "Application or Load File AID (hex)", true);
    return s;
}
cJSON *gpshell3_cmd_sign_delete_token_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "token", "Hex-encoded Delegated Management Delete Token", true);
    return s;
}
int gpshell3_cmd_sign_delete_token_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)session;
    gpshell3_output_set_command(out, "gpshell3_sign_delete_token");
    return cmd_gp211_calculate_delete_token(argc, argv);
}
int gpshell3_cmd_sign_delete_token_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_sign_delete_token_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 9. verify-delete-receipt */
cJSON *gpshell3_cmd_verify_delete_receipt_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    const char *types[] = {"aes", "des", "rsa", "ecc"};
    gpshell3_schema_add_prop_enum(s, "type", "Key type (aes, des, rsa, ecc)", types, 4, false);
    gpshell3_schema_add_prop_string(s, "key", "Symmetric key hex string", false);
    gpshell3_schema_add_prop_string(s, "pem", "PEM file path [:passphrase]", false);
    gpshell3_schema_add_prop_string(s, "receipt", "Response APDU hex string containing receipt payload", true);
    return s;
}
cJSON *gpshell3_cmd_verify_delete_receipt_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "valid", "True if receipt is cryptographically valid", true);
    return s;
}
int gpshell3_cmd_verify_delete_receipt_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)session;
    gpshell3_output_set_command(out, "gpshell3_verify_delete_receipt");
    return cmd_verify_delete_receipt(argc, argv);
}
int gpshell3_cmd_verify_delete_receipt_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_verify_delete_receipt_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 10. verify-load-receipt */
cJSON *gpshell3_cmd_verify_load_receipt_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    const char *types[] = {"aes", "des", "rsa", "ecc"};
    gpshell3_schema_add_prop_enum(s, "type", "Key type (aes, des, rsa, ecc)", types, 4, false);
    gpshell3_schema_add_prop_string(s, "key", "Symmetric key hex string", false);
    gpshell3_schema_add_prop_string(s, "pem", "PEM file path [:passphrase]", false);
    gpshell3_schema_add_prop_string(s, "aid", "Load File AID (hex)", false);
    gpshell3_schema_add_prop_string(s, "receipt", "Response APDU hex string containing receipt payload", true);
    return s;
}
cJSON *gpshell3_cmd_verify_load_receipt_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "valid", "True if receipt is cryptographically valid", true);
    return s;
}
int gpshell3_cmd_verify_load_receipt_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)session;
    gpshell3_output_set_command(out, "gpshell3_verify_load_receipt");
    return cmd_verify_load_receipt(argc, argv);
}
int gpshell3_cmd_verify_load_receipt_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_verify_load_receipt_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 11. verify-install-receipt */
cJSON *gpshell3_cmd_verify_install_receipt_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    const char *types[] = {"aes", "des", "rsa", "ecc"};
    gpshell3_schema_add_prop_enum(s, "type", "Key type (aes, des, rsa, ecc)", types, 4, false);
    gpshell3_schema_add_prop_string(s, "key", "Symmetric key hex string", false);
    gpshell3_schema_add_prop_string(s, "pem", "PEM file path [:passphrase]", false);
    gpshell3_schema_add_prop_string(s, "aid", "Applet instance AID (hex)", false);
    gpshell3_schema_add_prop_string(s, "receipt", "Response APDU hex string containing receipt payload", true);
    return s;
}
cJSON *gpshell3_cmd_verify_install_receipt_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "valid", "True if receipt is cryptographically valid", true);
    return s;
}
int gpshell3_cmd_verify_install_receipt_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)session;
    gpshell3_output_set_command(out, "gpshell3_verify_install_receipt");
    return cmd_verify_install_receipt(argc, argv);
}
int gpshell3_cmd_verify_install_receipt_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_verify_install_receipt_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 12. verify-move-receipt */
cJSON *gpshell3_cmd_verify_move_receipt_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    const char *types[] = {"aes", "des", "rsa", "ecc"};
    gpshell3_schema_add_prop_enum(s, "type", "Key type (aes, des, rsa, ecc)", types, 4, false);
    gpshell3_schema_add_prop_string(s, "key", "Symmetric key hex string", false);
    gpshell3_schema_add_prop_string(s, "pem", "PEM file path [:passphrase]", false);
    gpshell3_schema_add_prop_string(s, "aid", "Applet AID (hex)", true);
    gpshell3_schema_add_prop_string(s, "oldSd", "Old Security Domain AID (hex)", true);
    gpshell3_schema_add_prop_string(s, "newSd", "New Security Domain AID (hex)", true);
    gpshell3_schema_add_prop_string(s, "receipt", "Response APDU hex string containing receipt payload", true);
    return s;
}
cJSON *gpshell3_cmd_verify_move_receipt_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "valid", "True if receipt is cryptographically valid", true);
    return s;
}
int gpshell3_cmd_verify_move_receipt_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)session;
    gpshell3_output_set_command(out, "gpshell3_verify_move_receipt");
    return cmd_verify_move_receipt(argc, argv);
}
int gpshell3_cmd_verify_move_receipt_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_verify_move_receipt_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 13. verify-registry-update-receipt */
cJSON *gpshell3_cmd_verify_registry_update_receipt_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    const char *types[] = {"aes", "des", "rsa", "ecc"};
    gpshell3_schema_add_prop_enum(s, "type", "Key type (aes, des, rsa, ecc)", types, 4, false);
    gpshell3_schema_add_prop_string(s, "key", "Symmetric key hex string", false);
    gpshell3_schema_add_prop_string(s, "pem", "PEM file path [:passphrase]", false);
    gpshell3_schema_add_prop_string(s, "aid", "Applet AID (hex)", true);
    gpshell3_schema_add_prop_string(s, "oldSd", "Old Security Domain AID (hex)", true);
    gpshell3_schema_add_prop_string(s, "newSd", "New Security Domain AID (hex)", true);
    gpshell3_schema_add_prop_string(s, "privileges", "Privileges list (e.g. sd,token)", true);
    gpshell3_schema_add_prop_string(s, "receipt", "Response APDU hex string containing receipt payload", true);
    return s;
}
cJSON *gpshell3_cmd_verify_registry_update_receipt_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "valid", "True if receipt is cryptographically valid", true);
    return s;
}
int gpshell3_cmd_verify_registry_update_receipt_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)session;
    gpshell3_output_set_command(out, "gpshell3_verify_registry_update_receipt");
    return cmd_verify_registry_update_receipt(argc, argv);
}
int gpshell3_cmd_verify_registry_update_receipt_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_verify_registry_update_receipt_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 14. list-apps */
cJSON *gpshell3_cmd_list_apps_input_schema(void) { return gpshell3_schema_object(); }
cJSON *gpshell3_cmd_list_apps_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_array(s, "securityDomains", "List of Security Domains", "object", false);
    gpshell3_schema_add_prop_array(s, "applications", "List of installed Applications", "object", false);
    gpshell3_schema_add_prop_array(s, "loadFiles", "List of Executable Load Files", "object", false);
    return s;
}
int gpshell3_cmd_list_apps_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)argc; (void)argv;
    gpshell3_output_set_command(out, "gpshell3_list_apps");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "list-apps requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_list_apps(session->ctx, session->info, &session->sec);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_list_apps_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    (void)args;
    return gpshell3_cmd_list_apps_cli(session, 0, NULL, out);
}

/* 15. list-keys */
cJSON *gpshell3_cmd_list_keys_input_schema(void) { return gpshell3_schema_object(); }
cJSON *gpshell3_cmd_list_keys_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_array(s, "keys", "List of key templates", "object", true);
    return s;
}
int gpshell3_cmd_list_keys_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)argc; (void)argv;
    gpshell3_output_set_command(out, "gpshell3_list_keys");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "list-keys requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_list_keys(session->ctx, session->info, &session->sec);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_list_keys_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    (void)args;
    return gpshell3_cmd_list_keys_cli(session, 0, NULL, out);
}

/* 16. cplc */
cJSON *gpshell3_cmd_cplc_input_schema(void) { return gpshell3_schema_object(); }
cJSON *gpshell3_cmd_cplc_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "cplc", "Raw CPLC data (hex)", true);
    return s;
}
int gpshell3_cmd_cplc_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)argc; (void)argv;
    gpshell3_output_set_command(out, "gpshell3_cplc");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "cplc requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_cplc(session->ctx, session->info, &session->sec);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_cplc_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    (void)args;
    return gpshell3_cmd_cplc_cli(session, 0, NULL, out);
}

/* 17. card-data */
cJSON *gpshell3_cmd_card_data_input_schema(void) { return gpshell3_schema_object(); }
cJSON *gpshell3_cmd_card_data_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "cardData", "Card data (tag 0x0066)", true);
    return s;
}
int gpshell3_cmd_card_data_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)argc; (void)argv;
    gpshell3_output_set_command(out, "gpshell3_card_data");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "card-data requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_card_data(session->ctx, session->info, &session->sec);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_card_data_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    (void)args;
    return gpshell3_cmd_card_data_cli(session, 0, NULL, out);
}

/* 18. iin */
cJSON *gpshell3_cmd_iin_input_schema(void) { return gpshell3_schema_object(); }
cJSON *gpshell3_cmd_iin_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "iin", "IIN hex", true);
    return s;
}
int gpshell3_cmd_iin_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)argc; (void)argv;
    gpshell3_output_set_command(out, "gpshell3_iin");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "iin requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_iin(session->ctx, session->info, &session->sec);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_iin_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    (void)args;
    return gpshell3_cmd_iin_cli(session, 0, NULL, out);
}

/* 19. cin */
cJSON *gpshell3_cmd_cin_input_schema(void) { return gpshell3_schema_object(); }
cJSON *gpshell3_cmd_cin_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "cin", "CIN hex", true);
    return s;
}
int gpshell3_cmd_cin_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)argc; (void)argv;
    gpshell3_output_set_command(out, "gpshell3_cin");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "cin requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_cin(session->ctx, session->info, &session->sec);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_cin_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    (void)args;
    return gpshell3_cmd_cin_cli(session, 0, NULL, out);
}

/* 20. card-info */
cJSON *gpshell3_cmd_card_info_input_schema(void) { return gpshell3_schema_object(); }
cJSON *gpshell3_cmd_card_info_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "cardRecognitionData", "Card recognition data", true);
    return s;
}
int gpshell3_cmd_card_info_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)argc; (void)argv;
    gpshell3_output_set_command(out, "gpshell3_card_info");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "card-info requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_card_info(session->ctx, session->info, &session->sec);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_card_info_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    (void)args;
    return gpshell3_cmd_card_info_cli(session, 0, NULL, out);
}

/* 21. card-cap */
cJSON *gpshell3_cmd_card_cap_input_schema(void) { return gpshell3_schema_object(); }
cJSON *gpshell3_cmd_card_cap_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "capabilities", "Card capability data", true);
    return s;
}
int gpshell3_cmd_card_cap_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)argc; (void)argv;
    gpshell3_output_set_command(out, "gpshell3_card_cap");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "card-cap requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_card_capability(session->ctx, session->info, &session->sec);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_card_cap_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    (void)args;
    return gpshell3_cmd_card_cap_cli(session, 0, NULL, out);
}

/* 22. card-resources */
cJSON *gpshell3_cmd_card_resources_input_schema(void) { return gpshell3_schema_object(); }
cJSON *gpshell3_cmd_card_resources_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "resources", "Card resources data", true);
    return s;
}
int gpshell3_cmd_card_resources_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)argc; (void)argv;
    gpshell3_output_set_command(out, "gpshell3_card_resources");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "card-resources requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_card_resources(session->ctx, session->info, &session->sec);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_card_resources_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    (void)args;
    return gpshell3_cmd_card_resources_cli(session, 0, NULL, out);
}

/* 23. div-data */
cJSON *gpshell3_cmd_div_data_input_schema(void) { return gpshell3_schema_object(); }
cJSON *gpshell3_cmd_div_data_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "diversificationData", "Diversification data", true);
    return s;
}
int gpshell3_cmd_div_data_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)argc; (void)argv;
    gpshell3_output_set_command(out, "gpshell3_div_data");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "div-data requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_diversification(session->ctx, session->info, &session->sec);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_div_data_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    (void)args;
    return gpshell3_cmd_div_data_cli(session, 0, NULL, out);
}

/* 24. seq-counter */
cJSON *gpshell3_cmd_seq_counter_input_schema(void) { return gpshell3_schema_object(); }
cJSON *gpshell3_cmd_seq_counter_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "sequenceCounter", "Sequence counter hex", true);
    return s;
}
int gpshell3_cmd_seq_counter_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)argc; (void)argv;
    gpshell3_output_set_command(out, "gpshell3_seq_counter");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "seq-counter requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_seq_counter(session->ctx, session->info, &session->sec);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_seq_counter_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    (void)args;
    return gpshell3_cmd_seq_counter_cli(session, 0, NULL, out);
}

/* 25. confirm-counter */
cJSON *gpshell3_cmd_confirm_counter_input_schema(void) { return gpshell3_schema_object(); }
cJSON *gpshell3_cmd_confirm_counter_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "confirmationCounter", "Confirmation counter hex", true);
    return s;
}
int gpshell3_cmd_confirm_counter_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)argc; (void)argv;
    gpshell3_output_set_command(out, "gpshell3_confirm_counter");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "confirm-counter requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_confirm_counter(session->ctx, session->info, &session->sec);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_confirm_counter_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    (void)args;
    return gpshell3_cmd_confirm_counter_cli(session, 0, NULL, out);
}

/* 26. scp11-cert-data */
cJSON *gpshell3_cmd_scp11_cert_data_input_schema(void) { return gpshell3_schema_object(); }
cJSON *gpshell3_cmd_scp11_cert_data_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "scp11CertData", "SCP11 certificate data", true);
    return s;
}
int gpshell3_cmd_scp11_cert_data_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    (void)argc; (void)argv;
    gpshell3_output_set_command(out, "gpshell3_scp11_cert_data");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "scp11-cert-data requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_scp11_cert_data(session->ctx, session->info, &session->sec);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_scp11_cert_data_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    (void)args;
    return gpshell3_cmd_scp11_cert_data_cli(session, 0, NULL, out);
}

/* 27. store-iin */
cJSON *gpshell3_cmd_store_iin_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "iin", "Issuer Identification Number (hex)", true);
    return s;
}
cJSON *gpshell3_cmd_store_iin_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "stored", "True on success", true);
    return s;
}
int gpshell3_cmd_store_iin_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_store_iin");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "store-iin requires active session"); return -1; }
    if (argc < 1) { gpshell3_report_error(out, "USAGE", "Usage: store-iin <identification number>"); return -1; }
    BYTE bcd[64]; DWORD bcdLen = sizeof(bcd);
    OPGP_ERROR_STATUS status = OPGP_build_bcd_encoding(argv[0], bcd, &bcdLen);
    if (!status_ok(status, false)) { gpshell3_report_error(out, "BCD_ERROR", "BCD encoding failed"); return -1; }
    BYTE tlv[128]; DWORD tlvLen = 0;
    tlv[tlvLen++] = 0x42; tlv[tlvLen++] = (BYTE)bcdLen;
    memcpy(tlv + tlvLen, bcd, bcdLen); tlvLen += bcdLen;
    status = GP211_store_data(session->ctx, session->info, &session->sec, STORE_DATA_ENCRYPTION_NO_INFORMATION, STORE_DATA_FORMAT_BER_TLV, false, tlv, tlvLen);
    if (!status_ok(status, false)) { gpshell3_report_opgp_error(out, NULL, status, "GP211_store_data failed"); return -1; }
    if (out && out->mode == OUTPUT_FORMAT_JSON) gpshell3_output_add_bool(out, "stored", true);
    return 0;
}
int gpshell3_cmd_store_iin_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_store_iin_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 28. store-cin */
cJSON *gpshell3_cmd_store_cin_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "cin", "Card Image Number (hex)", true);
    return s;
}
cJSON *gpshell3_cmd_store_cin_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "stored", "True on success", true);
    return s;
}
int gpshell3_cmd_store_cin_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_store_cin");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "store-cin requires active session"); return -1; }
    if (argc < 1) { gpshell3_report_error(out, "USAGE", "Usage: store-cin <identification number>"); return -1; }
    BYTE bcd[64]; DWORD bcdLen = sizeof(bcd);
    OPGP_ERROR_STATUS status = OPGP_build_bcd_encoding(argv[0], bcd, &bcdLen);
    if (!status_ok(status, false)) { gpshell3_report_error(out, "BCD_ERROR", "BCD encoding failed"); return -1; }
    BYTE tlv[128]; DWORD tlvLen = 0;
    tlv[tlvLen++] = 0x45; tlv[tlvLen++] = (BYTE)bcdLen;
    memcpy(tlv + tlvLen, bcd, bcdLen); tlvLen += bcdLen;
    status = GP211_store_data(session->ctx, session->info, &session->sec, STORE_DATA_ENCRYPTION_NO_INFORMATION, STORE_DATA_FORMAT_BER_TLV, false, tlv, tlvLen);
    if (!status_ok(status, false)) { gpshell3_report_opgp_error(out, NULL, status, "GP211_store_data failed"); return -1; }
    if (out && out->mode == OUTPUT_FORMAT_JSON) gpshell3_output_add_bool(out, "stored", true);
    return 0;
}
int gpshell3_cmd_store_cin_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_store_cin_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 29. scp11-store-cert */
cJSON *gpshell3_cmd_scp11_store_cert_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "certFile", "Path to certificate file", true);
    return s;
}
cJSON *gpshell3_cmd_scp11_store_cert_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "stored", "True on success", true);
    return s;
}
int gpshell3_cmd_scp11_store_cert_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_scp11_store_cert");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "scp11-store-cert requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_scp11_store_cert(session->ctx, session->info, &session->sec, argc, argv);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_scp11_store_cert_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_scp11_store_cert_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 30. scp11-store-ca-id */
cJSON *gpshell3_cmd_scp11_store_ca_id_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "caKeyId", "CA Key Identifier (hex)", true);
    return s;
}
cJSON *gpshell3_cmd_scp11_store_ca_id_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "stored", "True on success", true);
    return s;
}
int gpshell3_cmd_scp11_store_ca_id_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_scp11_store_ca_id");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "scp11-store-ca-id requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_scp11_store_ca_id(session->ctx, session->info, &session->sec, argc, argv);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_scp11_store_ca_id_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_scp11_store_ca_id_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 31. install */
cJSON *gpshell3_cmd_install_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "capFile", "Path to CAP file", false);
    gpshell3_schema_add_prop_bool(s, "loadOnly", "Only load", false);
    gpshell3_schema_add_prop_bool(s, "installOnly", "Only install instance", false);
    gpshell3_schema_add_prop_string(s, "loadFile", "Load File AID (hex)", false);
    gpshell3_schema_add_prop_string(s, "module", "Module AID (hex)", false);
    gpshell3_schema_add_prop_string(s, "applet", "Applet instance AID (hex)", false);
    gpshell3_schema_add_prop_string(s, "privileges", "Privileges list", false);
    gpshell3_schema_add_prop_string(s, "params", "Install params (hex)", false);
    return s;
}
cJSON *gpshell3_cmd_install_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "installed", "True on success", true);
    return s;
}
int gpshell3_cmd_install_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_install");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "install requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_install(session->ctx, session->info, &session->sec, argc, argv);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_install_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_install_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 32. install-sd */
cJSON *gpshell3_cmd_install_sd_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "instanceAid", "Security Domain instance AID (hex)", true);
    return s;
}
cJSON *gpshell3_cmd_install_sd_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "installed", "True on success", true);
    return s;
}
int gpshell3_cmd_install_sd_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_install_sd");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "install-sd requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_install_sd(session->ctx, session->info, &session->sec, argc, argv,
                            1, 0, 0, "mac+enc", 0, NULL, NULL, NULL, NULL, 16, NULL, NULL);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_install_sd_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_install_sd_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 33. delete */
cJSON *gpshell3_cmd_delete_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "aid", "Application or Package AID (hex)", true);
    return s;
}
cJSON *gpshell3_cmd_delete_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "deleted", "True on success", true);
    return s;
}
int gpshell3_cmd_delete_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_delete");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "delete requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_delete(session->ctx, session->info, &session->sec, argc, argv);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_delete_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_delete_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 34. update-registry */
cJSON *gpshell3_cmd_update_registry_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "aid", "Target AID (hex)", true);
    return s;
}
cJSON *gpshell3_cmd_update_registry_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "updated", "True on success", true);
    return s;
}
int gpshell3_cmd_update_registry_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_update_registry");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "update-registry requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_update_registry(session->ctx, session->info, &session->sec, argc, argv);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_update_registry_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_update_registry_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 35. move */
cJSON *gpshell3_cmd_move_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "applicationAid", "Application AID (hex)", true);
    gpshell3_schema_add_prop_string(s, "securityDomainAid", "Target SD AID (hex)", true);
    return s;
}
cJSON *gpshell3_cmd_move_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "moved", "True on success", true);
    return s;
}
int gpshell3_cmd_move_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_move");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "move requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_move(session->ctx, session->info, &session->sec, argc, argv);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_move_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_move_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 36. put-key */
cJSON *gpshell3_cmd_put_key_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_int(s, "keySetVersion", "Current key set version", true);
    gpshell3_schema_add_prop_int(s, "newKeySetVersion", "New key set version", true);
    return s;
}
cJSON *gpshell3_cmd_put_key_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "updated", "True on success", true);
    return s;
}
int gpshell3_cmd_put_key_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_put_key");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "put-key requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_put_key(session->ctx, session->info, &session->sec, argc, argv);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_put_key_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_put_key_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 37. put-auth */
cJSON *gpshell3_cmd_put_auth_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_int(s, "keySetVersion", "Key set version", false);
    return s;
}
cJSON *gpshell3_cmd_put_auth_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "updated", "True on success", true);
    return s;
}
int gpshell3_cmd_put_auth_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_put_auth");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "put-auth requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_put_auth(session->ctx, session->info, &session->sec, argc, argv);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_put_auth_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_put_auth_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 38. put-dm-token */
cJSON *gpshell3_cmd_put_dm_token_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "pemFile", "PEM file path", true);
    return s;
}
cJSON *gpshell3_cmd_put_dm_token_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "updated", "True on success", true);
    return s;
}
int gpshell3_cmd_put_dm_token_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_put_dm_token");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "put-dm-token requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_put_dm_token(session->ctx, session->info, &session->sec, argc, argv);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_put_dm_token_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_put_dm_token_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 39. put-dm-receipt */
cJSON *gpshell3_cmd_put_dm_receipt_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "receiptKey", "Receipt key in hex", true);
    return s;
}
cJSON *gpshell3_cmd_put_dm_receipt_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "updated", "True on success", true);
    return s;
}
int gpshell3_cmd_put_dm_receipt_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_put_dm_receipt");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "put-dm-receipt requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_put_dm_receipt(session->ctx, session->info, &session->sec, argc, argv);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_put_dm_receipt_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_put_dm_receipt_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 40. put-dap-key */
cJSON *gpshell3_cmd_put_dap_key_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "keyValue", "Key value", true);
    return s;
}
cJSON *gpshell3_cmd_put_dap_key_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "updated", "True on success", true);
    return s;
}
int gpshell3_cmd_put_dap_key_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_put_dap_key");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "put-dap-key requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_put_dap_key(session->ctx, session->info, &session->sec, argc, argv);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_put_dap_key_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_put_dap_key_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 41. del-key */
cJSON *gpshell3_cmd_del_key_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_int(s, "keySetVersion", "Key set version", true);
    return s;
}
cJSON *gpshell3_cmd_del_key_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "deleted", "True on success", true);
    return s;
}
int gpshell3_cmd_del_key_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_del_key");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "del-key requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_del_key(session->ctx, session->info, &session->sec, argc, argv);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_del_key_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_del_key_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 42. apdu */
cJSON *gpshell3_cmd_apdu_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "apdu", "APDU hex string", true);
    return s;
}
cJSON *gpshell3_cmd_apdu_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "response", "Response APDU hex string", true);
    return s;
}
int gpshell3_cmd_apdu_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_apdu");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "apdu requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_apdu(session->ctx, session->info, session->is_authenticated ? &session->sec : NULL, argc, argv);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_apdu_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_apdu_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 43. status */
cJSON *gpshell3_cmd_status_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    const char *types[] = {"isd", "sd", "app", "sd-app"};
    gpshell3_schema_add_prop_enum(s, "elementType", "Element type", types, 4, true);
    gpshell3_schema_add_prop_string(s, "aid", "Target AID (hex)", true);
    const char *states[] = {"locked", "terminated", "personalized", "selectable", "unlocked"};
    gpshell3_schema_add_prop_enum(s, "state", "Target life cycle state", states, 5, true);
    return s;
}
cJSON *gpshell3_cmd_status_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "updated", "True on success", true);
    return s;
}
int gpshell3_cmd_status_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_status");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "status requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_status(session->ctx, session->info, &session->sec, argc, argv);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_status_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_status_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}

/* 44. store */
cJSON *gpshell3_cmd_store_input_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_string(s, "data", "Raw data to store (hex)", true);
    return s;
}
cJSON *gpshell3_cmd_store_output_schema(void) {
    cJSON *s = gpshell3_schema_object();
    gpshell3_schema_add_prop_bool(s, "stored", "True on success", true);
    return s;
}
int gpshell3_cmd_store_cli(gpshell3_session_t *session, int argc, char **argv, gpshell3_output_ctx_t *out) {
    gpshell3_output_set_command(out, "gpshell3_store");
    if (!session || !session->is_connected) { gpshell3_report_error(out, "SESSION_REQUIRED", "store requires active session"); return -1; }
    sync_session_globals_to(session);
    int rc = cmd_store(session->ctx, session->info, &session->sec, argc, argv);
    sync_session_globals_from(session);
    return rc;
}
int gpshell3_cmd_store_cmd(gpshell3_session_t *session, cJSON *args, gpshell3_output_ctx_t *out) {
    int argc = 0; char **argv = json_to_argv(args, &argc);
    int rc = gpshell3_cmd_store_cli(session, argc, argv, out);
    free_argv(argc, argv);
    return rc;
}
