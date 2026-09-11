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
    /* Offline / Token / Receipt commands (13) */
    CMD_ENTRY("list-readers", "gpshell3_list_readers",
              "List all available PC/SC smart card readers detected on the system.",
              false, false, list_readers),

    CMD_ENTRY("hash", "gpshell3_hash",
              "Compute cryptographic hash (SHA-1 or SHA-256) of a Java Card CAP file's load-file data block for DAP signature or token generation.",
              false, false, hash),

    CMD_ENTRY("sign-dap", "gpshell3_sign_dap",
              "Generate a Data Authentication Pattern (DAP) signature over a CAP file or precomputed hash using an AES, RSA, or ECC private key.",
              false, false, sign_dap),

    CMD_ENTRY("sign-load-token", "gpshell3_sign_load_token",
              "Calculate Delegated Management (DM) Load Token using an RSA or ECC private key for loading an Executable Load File.",
              false, false, sign_load_token),

    CMD_ENTRY("sign-install-token", "gpshell3_sign_install_token",
              "Calculate Delegated Management (DM) Install Token for installing an application or security domain instance.",
              false, false, sign_install_token),

    CMD_ENTRY("sign-extradition-token", "gpshell3_sign_extradition_token",
              "Calculate Delegated Management (DM) Extradition Token for extraditing an application or SD to a target SD.",
              false, false, sign_extradition_token),

    CMD_ENTRY("sign-update-registry-token", "gpshell3_sign_update_registry_token",
              "Calculate Delegated Management (DM) Update Registry Token for updating application privileges or life cycle state.",
              false, false, sign_update_registry_token),

    CMD_ENTRY("sign-delete-token", "gpshell3_sign_delete_token",
              "Calculate Delegated Management (DM) Delete Token for deleting an applet or package.",
              false, false, sign_delete_token),

    CMD_ENTRY("verify-delete-receipt", "gpshell3_verify_delete_receipt",
              "Verify a Delegated Management Delete Receipt returned by the card against an ECDSA, RSA, or AES key.",
              false, false, verify_delete_receipt),

    CMD_ENTRY("verify-load-receipt", "gpshell3_verify_load_receipt",
              "Verify a Delegated Management Load Receipt returned by the card against an ECDSA, RSA, or AES key.",
              false, false, verify_load_receipt),

    CMD_ENTRY("verify-install-receipt", "gpshell3_verify_install_receipt",
              "Verify a Delegated Management Install Receipt returned by the card against an ECDSA, RSA, or AES key.",
              false, false, verify_install_receipt),

    CMD_ENTRY("verify-registry-update-receipt", "gpshell3_verify_registry_update_receipt",
              "Verify a Delegated Management Update Registry Receipt returned by the card against an ECDSA, RSA, or AES key.",
              false, false, verify_registry_update_receipt),

    CMD_ENTRY("verify-move-receipt", "gpshell3_verify_move_receipt",
              "Verify a Delegated Management Extradition (Move) Receipt returned by the card against an ECDSA, RSA, or AES key.",
              false, false, verify_move_receipt),

    /* Card Query commands (13) */
    CMD_ENTRY("list-apps", "gpshell3_list_apps",
              "List Issuer Security Domains (ISDs), Security Domains (SDs), Applications, Executable Load Files (ELFs), and Executable Modules on the card.",
              true, false, list_apps),

    CMD_ENTRY("list-keys", "gpshell3_list_keys",
              "List cryptographic key information on the card grouped by key set version (kvn) and key index, including key types and lengths.",
              true, false, list_keys),

    CMD_ENTRY("cplc", "gpshell3_cplc",
              "Read Card Production Life Cycle (CPLC) data from the card (IC fabricator, OS ID, fabrication dates, serial numbers).",
              true, false, cplc),

    CMD_ENTRY("card-data", "gpshell3_card_data",
              "Read all card identification and status data (IIN, CIN, CPLC, card info, capabilities, resources, sequence counter).",
              true, false, card_data),

    CMD_ENTRY("iin", "gpshell3_iin",
              "Get Issuer Identification Number (IIN) from the card.",
              true, false, iin),

    CMD_ENTRY("cin", "gpshell3_cin",
              "Get Card Image Number (CIN) from the card.",
              true, false, cin),

    CMD_ENTRY("card-info", "gpshell3_card_info",
              "Get Card Recognition Data (GlobalPlatform version, card management type, SCP options).",
              true, false, card_info),

    CMD_ENTRY("card-cap", "gpshell3_card_capability",
              "Get Card Capability Information.",
              true, false, card_cap),

    CMD_ENTRY("card-resources", "gpshell3_card_resources",
              "Get Extended Card Resource Information (installed applications count, free non-volatile memory, free volatile memory).",
              true, false, card_resources),

    CMD_ENTRY("div-data", "gpshell3_diversification",
              "Get Key Diversification Data from the card.",
              true, false, div_data),

    CMD_ENTRY("seq-counter", "gpshell3_seq_counter",
              "Get Sequence Counter for key derivation and transaction tracking.",
              true, false, seq_counter),

    CMD_ENTRY("confirm-counter", "gpshell3_confirm_counter",
              "Get Confirmation Counter for delegated management receipt verification.",
              true, false, confirm_counter),

    CMD_ENTRY("scp11-cert-data", "gpshell3_scp11_cert_data",
              "Retrieve and decode SCP11 Security Domain certificates (CERT.SD.ECKA, CERT.SD.AUT) stored on the card.",
              true, false, scp11_cert_data),

    /* Card Mutation & Personalization commands (18) */
    CMD_ENTRY("store-iin", "gpshell3_store_iin",
              "Store Issuer Identification Number (IIN) on the card.",
              true, true, store_iin),

    CMD_ENTRY("store-cin", "gpshell3_store_cin",
              "Store Card Image Number (CIN) on the card.",
              true, true, store_cin),

    CMD_ENTRY("scp11-store-cert", "gpshell3_scp11_store_cert",
              "Store an SCP11 ECKA/AUT certificate store file on the card for a specified key version and index.",
              true, true, scp11_store_cert),

    CMD_ENTRY("scp11-store-ca-id", "gpshell3_scp11_store_ca_id",
              "Store Certificate Authority Identifier (CA ID / KL-OC) on the card for SCP11 trust anchoring.",
              true, true, scp11_store_ca_id),

    CMD_ENTRY("install", "gpshell3_install",
              "Load and/or install a Java Card CAP file, optionally creating and making selectable applet instances with privileges and install parameters.",
              true, true, install),

    CMD_ENTRY("install-sd", "gpshell3_install_sd",
              "Install a Security Domain instance from a loaded package with specific privileges and extradition policies.",
              true, true, install_sd),

    CMD_ENTRY("delete", "gpshell3_delete",
              "Delete an application instance or Executable Load File (package) from the card by AID.",
              true, true, delete),

    CMD_ENTRY("update-registry", "gpshell3_update_registry",
              "Update privileges or life cycle state of an application or security domain in the GlobalPlatform registry.",
              true, true, update_registry),

    CMD_ENTRY("move", "gpshell3_move",
              "Extradite (move) an application or security domain to a target security domain.",
              true, true, move),

    CMD_ENTRY("put-key", "gpshell3_put_key",
              "Add or replace symmetric (DES, AES) or asymmetric (RSA, ECC) cryptographic keys on the card.",
              true, true, put_key),

    CMD_ENTRY("put-auth", "gpshell3_put_auth",
              "Store authentication credentials (e.g., password or token) on the card.",
              true, true, put_auth),

    CMD_ENTRY("put-dm-token", "gpshell3_put_dm_token",
              "Store a Delegated Management token verification public key (RSA or ECC) on the card.",
              true, true, put_dm_token),

    CMD_ENTRY("put-dm-receipt", "gpshell3_put_dm_receipt",
              "Store a Delegated Management receipt generation private/secret key on the card.",
              true, true, put_dm_receipt),

    CMD_ENTRY("put-dap-key", "gpshell3_put_dap_key",
              "Store a Data Authentication Pattern (DAP) verification key (RSA, ECC, or AES) on the card.",
              true, true, put_dap_key),

    CMD_ENTRY("del-key", "gpshell3_del_key",
              "Delete a key or an entire key set from the card.",
              true, true, del_key),

    CMD_ENTRY("apdu", "gpshell3_apdu",
              "Transmit a raw APDU (Application Protocol Data Unit) to the card and receive the response data and status word.",
              true, true, apdu),

    CMD_ENTRY("status", "gpshell3_status",
              "Set the life cycle status of an application, security domain, or the card (e.g., LOCK, UNLOCK, TERMINATE).",
              true, true, status),

    CMD_ENTRY("store", "gpshell3_store",
              "Execute GlobalPlatform STORE DATA command to store raw BER-TLV or DGI data blocks.",
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
