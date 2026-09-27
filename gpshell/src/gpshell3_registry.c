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

#include "gpshell3_registry.h"
#include "gpshell3_commands.h"
#include <string.h>

cJSON *gpshell3_schema_object(void) {
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return NULL;
    cJSON_AddStringToObject(obj, "type", "object");
    cJSON *props = cJSON_CreateObject();
    if (props) {
        cJSON_AddItemToObject(obj, "properties", props);
    }
    return obj;
}

void gpshell3_schema_add_prop_string(cJSON *schema, const char *name, const char *desc, bool required) {
    if (!schema || !name) return;
    cJSON *props = cJSON_GetObjectItemCaseSensitive(schema, "properties");
    if (!props) {
        props = cJSON_CreateObject();
        cJSON_AddItemToObject(schema, "properties", props);
    }
    cJSON *prop = cJSON_CreateObject();
    cJSON_AddStringToObject(prop, "type", "string");
    if (desc) cJSON_AddStringToObject(prop, "description", desc);
    cJSON_AddItemToObject(props, name, prop);

    if (required) {
        cJSON *req = cJSON_GetObjectItemCaseSensitive(schema, "required");
        if (!req) {
            req = cJSON_CreateArray();
            cJSON_AddItemToObject(schema, "required", req);
        }
        cJSON_AddItemToArray(req, cJSON_CreateString(name));
    }
}

void gpshell3_schema_add_prop_int(cJSON *schema, const char *name, const char *desc, bool required) {
    if (!schema || !name) return;
    cJSON *props = cJSON_GetObjectItemCaseSensitive(schema, "properties");
    if (!props) {
        props = cJSON_CreateObject();
        cJSON_AddItemToObject(schema, "properties", props);
    }
    cJSON *prop = cJSON_CreateObject();
    cJSON_AddStringToObject(prop, "type", "integer");
    if (desc) cJSON_AddStringToObject(prop, "description", desc);
    cJSON_AddItemToObject(props, name, prop);

    if (required) {
        cJSON *req = cJSON_GetObjectItemCaseSensitive(schema, "required");
        if (!req) {
            req = cJSON_CreateArray();
            cJSON_AddItemToObject(schema, "required", req);
        }
        cJSON_AddItemToArray(req, cJSON_CreateString(name));
    }
}

void gpshell3_schema_add_prop_bool(cJSON *schema, const char *name, const char *desc, bool required) {
    if (!schema || !name) return;
    cJSON *props = cJSON_GetObjectItemCaseSensitive(schema, "properties");
    if (!props) {
        props = cJSON_CreateObject();
        cJSON_AddItemToObject(schema, "properties", props);
    }
    cJSON *prop = cJSON_CreateObject();
    cJSON_AddStringToObject(prop, "type", "boolean");
    if (desc) cJSON_AddStringToObject(prop, "description", desc);
    cJSON_AddItemToObject(props, name, prop);

    if (required) {
        cJSON *req = cJSON_GetObjectItemCaseSensitive(schema, "required");
        if (!req) {
            req = cJSON_CreateArray();
            cJSON_AddItemToObject(schema, "required", req);
        }
        cJSON_AddItemToArray(req, cJSON_CreateString(name));
    }
}

void gpshell3_schema_add_prop_enum(cJSON *schema, const char *name, const char *desc, const char **enum_values, size_t count, bool required) {
    if (!schema || !name) return;
    cJSON *props = cJSON_GetObjectItemCaseSensitive(schema, "properties");
    if (!props) {
        props = cJSON_CreateObject();
        cJSON_AddItemToObject(schema, "properties", props);
    }
    cJSON *prop = cJSON_CreateObject();
    cJSON_AddStringToObject(prop, "type", "string");
    if (desc) cJSON_AddStringToObject(prop, "description", desc);
    if (enum_values && count > 0) {
        cJSON *enum_arr = cJSON_CreateArray();
        for (size_t i = 0; i < count; i++) {
            cJSON_AddItemToArray(enum_arr, cJSON_CreateString(enum_values[i]));
        }
        cJSON_AddItemToObject(prop, "enum", enum_arr);
    }
    cJSON_AddItemToObject(props, name, prop);

    if (required) {
        cJSON *req = cJSON_GetObjectItemCaseSensitive(schema, "required");
        if (!req) {
            req = cJSON_CreateArray();
            cJSON_AddItemToObject(schema, "required", req);
        }
        cJSON_AddItemToArray(req, cJSON_CreateString(name));
    }
}

void gpshell3_schema_add_prop_array(cJSON *schema, const char *name, const char *desc, const char *item_type, bool required) {
    if (!schema || !name) return;
    cJSON *props = cJSON_GetObjectItemCaseSensitive(schema, "properties");
    if (!props) {
        props = cJSON_CreateObject();
        cJSON_AddItemToObject(schema, "properties", props);
    }
    cJSON *prop = cJSON_CreateObject();
    cJSON_AddStringToObject(prop, "type", "array");
    if (desc) cJSON_AddStringToObject(prop, "description", desc);
    if (item_type) {
        cJSON *items = cJSON_CreateObject();
        cJSON_AddStringToObject(items, "type", item_type);
        cJSON_AddItemToObject(prop, "items", items);
    }
    cJSON_AddItemToObject(props, name, prop);

    if (required) {
        cJSON *req = cJSON_GetObjectItemCaseSensitive(schema, "required");
        if (!req) {
            req = cJSON_CreateArray();
            cJSON_AddItemToObject(schema, "required", req);
        }
        cJSON_AddItemToArray(req, cJSON_CreateString(name));
    }
}

void gpshell3_schema_add_prop_object(cJSON *schema, const char *name, const char *desc, bool required) {
    if (!schema || !name) return;
    cJSON *props = cJSON_GetObjectItemCaseSensitive(schema, "properties");
    if (!props) {
        props = cJSON_CreateObject();
        cJSON_AddItemToObject(schema, "properties", props);
    }
    cJSON *prop = cJSON_CreateObject();
    cJSON_AddStringToObject(prop, "type", "object");
    if (desc) cJSON_AddStringToObject(prop, "description", desc);
    cJSON_AddItemToObject(props, name, prop);

    if (required) {
        cJSON *req = cJSON_GetObjectItemCaseSensitive(schema, "required");
        if (!req) {
            req = cJSON_CreateArray();
            cJSON_AddItemToObject(schema, "required", req);
        }
        cJSON_AddItemToArray(req, cJSON_CreateString(name));
    }
}

#define CMD_ENTRY(cli_name, mcp_name, desc_str, req_sess, is_destruct, func_suffix) \
    { \
        .name = cli_name, \
        .tool_name = mcp_name, \
        .description = desc_str, \
        .requires_session = req_sess, \
        .is_destructive = is_destruct, \
        .get_input_schema = gpshell3_cmd_##func_suffix##_input_schema, \
        .get_output_schema = gpshell3_cmd_##func_suffix##_output_schema, \
        .execute_cmd = gpshell3_cmd_##func_suffix##_cmd, \
        .execute_cli = gpshell3_cmd_##func_suffix##_cli \
    }

static const gpshell3_cmd_def_t s_command_registry[] = {
    /* Offline / Token / Receipt commands (14) */
    CMD_ENTRY("list-readers", "gpshell3_list_readers",
              "Use this when the user asks to list, detect, or discover available smart card readers connected to the system. Returns a list of reader names. Offline tool; does not require an active card session.",
              false, false, list_readers),

    CMD_ENTRY("inspect-card", "gpshell3_inspect_card",
              "Use this when the user asks to inspect, detect, identify, or discover a connected smart card without requiring a session ID or authentication. Returns card presence, reader name, ISD AID, CPLC hardware lifecycle data, card recognition info, and accessible applications. Discovers connected cards automatically; does not require an existing session.",
              false, false, inspect_card),

    CMD_ENTRY("hash", "gpshell3_hash",
              "Use this when the user asks to compute the cryptographic hash (SHA-1, SHA-256, SHA-384, SHA-512, SM3) of a Java Card CAP file's load-file data block for DAP signatures or tokens. Returns the hex-encoded hash. Offline tool; does not require a card connection.",
              false, false, hash),

    CMD_ENTRY("sign-dap", "gpshell3_sign_dap",
              "Use this when the user asks to generate a Data Authentication Pattern (DAP) signature over a CAP file or precomputed hash using an RSA, ECC, or AES private key. Returns the hex-encoded DAP signature block. Offline tool; does not require a card connection.",
              false, false, sign_dap),

    CMD_ENTRY("sign-load-token", "gpshell3_sign_load_token",
              "Use this when the user asks to generate a Delegated Management (DM) Load Token for loading an Executable Load File (ELF) onto a card using an RSA or ECC private key. Returns the hex-encoded token. Offline tool; does not require a card connection.",
              false, false, sign_load_token),

    CMD_ENTRY("sign-install-token", "gpshell3_sign_install_token",
              "Use this when the user asks to generate a Delegated Management (DM) Install Token for installing an application or Security Domain instance using an RSA or ECC private key. Returns the hex-encoded token. Offline tool; does not require a card connection.",
              false, false, sign_install_token),

    CMD_ENTRY("sign-extradition-token", "gpshell3_sign_extradition_token",
              "Use this when the user asks to generate a Delegated Management (DM) Extradition (Move) Token for transferring an application or SD to a target Security Domain using an RSA or ECC private key. Returns the hex-encoded token. Offline tool; does not require a card connection.",
              false, false, sign_extradition_token),

    CMD_ENTRY("sign-update-registry-token", "gpshell3_sign_update_registry_token",
              "Use this when the user asks to generate a Delegated Management (DM) Update Registry Token for modifying application privileges or life cycle state using an RSA or ECC private key. Returns the hex-encoded token. Offline tool; does not require a card connection.",
              false, false, sign_update_registry_token),

    CMD_ENTRY("sign-delete-token", "gpshell3_sign_delete_token",
              "Use this when the user asks to generate a Delegated Management (DM) Delete Token for deleting an applet instance or package using an RSA or ECC private key. Returns the hex-encoded token. Offline tool; does not require a card connection.",
              false, false, sign_delete_token),

    CMD_ENTRY("verify-delete-receipt", "gpshell3_verify_delete_receipt",
              "Use this when the user asks to verify a Delegated Management (DM) Delete Receipt returned by the card against an ECDSA, RSA, or AES key. Returns verification validity. Offline tool; does not require a card connection.",
              false, false, verify_delete_receipt),

    CMD_ENTRY("verify-load-receipt", "gpshell3_verify_load_receipt",
              "Use this when the user asks to verify a Delegated Management (DM) Load Receipt returned by the card against an ECDSA, RSA, or AES key. Returns verification validity. Offline tool; does not require a card connection.",
              false, false, verify_load_receipt),

    CMD_ENTRY("verify-install-receipt", "gpshell3_verify_install_receipt",
              "Use this when the user asks to verify a Delegated Management (DM) Install Receipt returned by the card against an ECDSA, RSA, or AES key. Returns verification validity. Offline tool; does not require a card connection.",
              false, false, verify_install_receipt),

    CMD_ENTRY("verify-registry-update-receipt", "gpshell3_verify_registry_update_receipt",
              "Use this when the user asks to verify a Delegated Management (DM) Update Registry Receipt returned by the card against an ECDSA, RSA, or AES key. Returns verification validity. Offline tool; does not require a card connection.",
              false, false, verify_registry_update_receipt),

    CMD_ENTRY("verify-move-receipt", "gpshell3_verify_move_receipt",
              "Use this when the user asks to verify a Delegated Management (DM) Extradition (Move) Receipt returned by the card against an ECDSA, RSA, or AES key. Returns verification validity. Offline tool; does not require a card connection.",
              false, false, verify_move_receipt),

    /* Card Query commands (13) */
    CMD_ENTRY("list-apps", "gpshell3_list_apps",
              "Use this when the user asks to list, query, or inspect installed applications, Security Domains, Executable Load Files (packages), and executable modules on the connected card. Returns lists of Security Domains, applications, and load files with life cycle states and privileges. Requires an open card session; the card may require authentication.",
              true, false, list_apps),

    CMD_ENTRY("list-keys", "gpshell3_list_keys",
              "Use this when the user asks to list, query, or inspect cryptographic keys stored in the current Security Domain. Returns key set versions (KVN), key identifiers, key types, and key lengths. Requires an open card session; the card may require authentication.",
              true, false, list_keys),

    CMD_ENTRY("cplc", "gpshell3_cplc",
              "Use this when the user asks to read Card Production Life Cycle (CPLC) data from the smart card. Returns IC fabricator, IC type, OS ID, fabrication dates, and serial numbers. Requires an open card session.",
              true, false, cplc),

    CMD_ENTRY("card-data", "gpshell3_card_data",
              "Use this when the user asks to read comprehensive card identification and status data (tag 0x0066). Returns IIN, CIN, CPLC, card recognition data, capabilities, and sequence counters. Requires an open card session.",
              true, false, card_data),

    CMD_ENTRY("iin", "gpshell3_iin",
              "Use this when the user asks to retrieve the Issuer Identification Number (IIN) from the smart card. Returns the IIN hex string. Requires an open card session.",
              true, false, iin),

    CMD_ENTRY("cin", "gpshell3_cin",
              "Use this when the user asks to retrieve the Card Image Number (CIN) from the smart card. Returns the CIN hex string. Requires an open card session.",
              true, false, cin),

    CMD_ENTRY("card-info", "gpshell3_card_info",
              "Use this when the user asks to retrieve Card Recognition Data from the smart card. Returns GlobalPlatform version, card management type, and supported SCP options. Requires an open card session.",
              true, false, card_info),

    CMD_ENTRY("card-cap", "gpshell3_card_capability",
              "Use this when the user asks to retrieve Card Capability Information from the smart card. Returns card capability descriptors and supported features. Requires an open card session.",
              true, false, card_cap),

    CMD_ENTRY("card-resources", "gpshell3_card_resources",
              "Use this when the user asks to check smart card memory and resource availability. Returns installed applications count, free non-volatile memory (NVM/Flash), and free volatile memory (RAM). Requires an open card session.",
              true, false, card_resources),

    CMD_ENTRY("div-data", "gpshell3_diversification",
              "Use this when the user asks to retrieve Key Diversification Data from the smart card. Returns key diversification data bytes used for diversified key calculations. Requires an open card session.",
              true, false, div_data),

    CMD_ENTRY("seq-counter", "gpshell3_seq_counter",
              "Use this when the user asks to retrieve the Sequence Counter from the smart card. Returns the sequence counter hex string for key derivation or transaction tracking. Requires an open card session.",
              true, false, seq_counter),

    CMD_ENTRY("confirm-counter", "gpshell3_confirm_counter",
              "Use this when the user asks to retrieve the Confirmation Counter from the smart card. Returns the confirmation counter hex string for delegated management receipt verification. Requires an open card session.",
              true, false, confirm_counter),

    CMD_ENTRY("scp11-cert-data", "gpshell3_scp11_cert_data",
              "Use this when the user asks to retrieve and decode SCP11 Security Domain certificates (CERT.SD.ECKA, CERT.SD.AUT) stored on the smart card. Returns decoded certificate data. Requires an open card session.",
              true, false, scp11_cert_data),

    /* Card Mutation & Personalization commands (18) */
    CMD_ENTRY("store-iin", "gpshell3_store_iin",
              "Use this when the user asks to store or personalize the Issuer Identification Number (IIN) on the smart card. Returns operation success status. Requires an open card session; the card may require authentication.",
              true, true, store_iin),

    CMD_ENTRY("store-cin", "gpshell3_store_cin",
              "Use this when the user asks to store or personalize the Card Image Number (CIN) on the smart card. Returns operation success status. Requires an open card session; the card may require authentication.",
              true, true, store_cin),

    CMD_ENTRY("scp11-store-cert", "gpshell3_scp11_store_cert",
              "Use this when the user asks to store an SCP11 ECKA or AUT certificate file on the smart card for a specific key set version and key index. Returns storage success status. Requires an open card session; the card may require authentication.",
              true, true, scp11_store_cert),

    CMD_ENTRY("scp11-store-ca-id", "gpshell3_scp11_store_ca_id",
              "Use this when the user asks to store a Certificate Authority Identifier (CA ID / KL-OC) on the smart card for SCP11 trust anchoring. Returns storage success status. Requires an open card session; the card may require authentication.",
              true, true, scp11_store_ca_id),

    CMD_ENTRY("install", "gpshell3_install",
              "Use this when the user asks to load and/or install a Java Card CAP file, create applet instances, or set application privileges and install parameters. Returns installation success status. Requires an open card session; the card may require authentication.",
              true, true, install),

    CMD_ENTRY("install-sd", "gpshell3_install_sd",
              "Use this when the user asks to instantiate a Security Domain (SD) from an already loaded package with specific privileges and policies. Returns installation success status. Requires an open card session; the card may require authentication.",
              true, true, install_sd),

    CMD_ENTRY("delete", "gpshell3_delete",
              "Use this when the user asks to delete an application instance, Security Domain, or Executable Load File (package) from the smart card by AID. Returns deletion success status. Requires an open card session; the card may require authentication.",
              true, true, delete),

    CMD_ENTRY("update-registry", "gpshell3_update_registry",
              "Use this when the user asks to update privileges or life cycle state of an application or Security Domain in the GlobalPlatform registry. Returns update success status. Requires an open card session; the card may require authentication.",
              true, true, update_registry),

    CMD_ENTRY("move", "gpshell3_move",
              "Use this when the user asks to extradite (move) an application or Security Domain to a target Security Domain. Returns extradition success status. Requires an open card session; the card may require authentication.",
              true, true, move),

    CMD_ENTRY("put-key", "gpshell3_put_key",
              "Use this when the user asks to add or replace cryptographic keys (symmetric AES/3DES or asymmetric RSA/ECC) in a Security Domain. Returns key update success status. Requires an open card session; the card may require authentication.",
              true, true, put_key),

    CMD_ENTRY("put-auth", "gpshell3_put_auth",
              "Use this when the user asks to store authentication credentials (e.g. password, PIN, or token data) on the smart card. Returns credential storage success status. Requires an open card session; the card may require authentication.",
              true, true, put_auth),

    CMD_ENTRY("put-dm-token", "gpshell3_put_dm_token",
              "Use this when the user asks to store a Delegated Management token verification public key (RSA or ECC) in the Security Domain. Returns key storage success status. Requires an open card session; the card may require authentication.",
              true, true, put_dm_token),

    CMD_ENTRY("put-dm-receipt", "gpshell3_put_dm_receipt",
              "Use this when the user asks to store a Delegated Management receipt generation key (private or secret key) in the Security Domain. Returns key storage success status. Requires an open card session; the card may require authentication.",
              true, true, put_dm_receipt),

    CMD_ENTRY("put-dap-key", "gpshell3_put_dap_key",
              "Use this when the user asks to store a Data Authentication Pattern (DAP) verification key (RSA, ECC, or AES) on the smart card. Returns key storage success status. Requires an open card session; the card may require authentication.",
              true, true, put_dap_key),

    CMD_ENTRY("del-key", "gpshell3_del_key",
              "Use this when the user asks to delete a cryptographic key or an entire key set from the Security Domain. Returns key deletion success status. Requires an open card session; the card may require authentication.",
              true, true, del_key),

    CMD_ENTRY("apdu", "gpshell3_apdu",
              "Use this when the user asks to transmit a raw ISO 7816-4 / GlobalPlatform APDU command to the connected smart card. Returns response data bytes and Status Word (SW). Requires an open card session.",
              true, true, apdu),

    CMD_ENTRY("status", "gpshell3_status",
              "Use this when the user asks to set the life cycle status of an application, Security Domain, or the smart card (e.g. LOCK, UNLOCK, TERMINATE). Returns status update success. Requires an open card session; the card may require authentication.",
              true, true, status),

    CMD_ENTRY("store", "gpshell3_store",
              "Use this when the user asks to execute a STORE DATA command to store raw BER-TLV or DGI data blocks on the smart card. Returns store success status. Requires an open card session; the card may require authentication.",
              true, true, store)
};

#undef CMD_ENTRY

static const size_t s_command_count = sizeof(s_command_registry) / sizeof(s_command_registry[0]);

void gpshell3_registry_init(void) {
    /* No-op dynamic initialization needed for static array */
}

const gpshell3_cmd_def_t *gpshell3_registry_find_by_name(const char *name) {
    if (!name) return NULL;
    for (size_t i = 0; i < s_command_count; i++) {
        if (strcmp(s_command_registry[i].name, name) == 0) {
            return &s_command_registry[i];
        }
    }
    return NULL;
}

const gpshell3_cmd_def_t *gpshell3_registry_find_by_tool_name(const char *tool_name) {
    if (!tool_name) return NULL;
    for (size_t i = 0; i < s_command_count; i++) {
        if (strcmp(s_command_registry[i].tool_name, tool_name) == 0) {
            return &s_command_registry[i];
        }
    }
    return NULL;
}

size_t gpshell3_registry_count(void) {
    return s_command_count;
}

const gpshell3_cmd_def_t *gpshell3_registry_get(size_t index) {
    if (index >= s_command_count) return NULL;
    return &s_command_registry[index];
}
