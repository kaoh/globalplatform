/*  Copyright (c) 2009, Karsten Ohme
 *  This file is part of GlobalPlatform.
 *
 *  GlobalPlatform is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GlobalPlatform is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with GlobalPlatform.  If not, see <http://www.gnu.org/licenses/>.
 */

/*! \file
 * This file contains all GlobalPlatform related functionality.
*/

#ifndef OPGP_GLOBALPLATFORM_H
#define OPGP_GLOBALPLATFORM_H

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef WIN32
#include "stdafx.h"
#endif


#ifndef max
#define max(a,b) (((a)>(b))?(a):(b))
#endif

#include <stdio.h>
#include "types.h"
#include "unicode.h"
#include "error.h"
#include "errorcodes.h"
#include "library.h"
#include "connection.h"
#include "security.h"
#include "stringify.h"


/** The default key value for new cards defined in a VISA specification. */
static const BYTE OPGP_VISA_DEFAULT_KEY[16] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};

/** The default mother key value for new GemXpresso cards. */
static const BYTE OPGP_GEMXPRESSO_DEFAULT_KEY[16] = {0x47, 0x45, 0x4d, 0x58, 0x50, 0x52, 0x45, 0x53, 0x53, 0x4f, 0x53, 0x41, 0x4d, 0x50, 0x4c, 0x45};



static const BYTE GP211_CARD_MANAGER_AID[7] = {0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00}; //!< The AID of the Issuer Security Domain defined by GlobalPlatform 2.1.1 specification.

static const BYTE GP211_CARD_MANAGER_AID_ALT1[8] = {0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}; //!< This AID is also used for the Issuer Security Domain, e.g. by JCOP 41 cards.

static const BYTE GP211_LIFE_CYCLE_LOAD_FILE_LOADED = 0x01; //!< Executable Load File is loaded.
static const BYTE GP211_LIFE_CYCLE_CARD_OP_READY = 0x01; //!< Card is OP ready.
static const BYTE GP211_LIFE_CYCLE_CARD_INITIALIZED = 0x07; //!< Card is initialized.
static const BYTE GP211_LIFE_CYCLE_CARD_SECURED = 0x0f; //!< Card is in secured state.
static const BYTE GP211_LIFE_CYCLE_CARD_LOCKED = 0x7f; //!< Card is locked.
static const BYTE GP211_LIFE_CYCLE_CARD_TERMINATED = 0xff; //!< Card is terminated.
static const BYTE GP211_LIFE_CYCLE_APPLICATION_INSTALLED = 0x03; //!< Application is installed
static const BYTE GP211_LIFE_CYCLE_APPLICATION_SELECTABLE = 0x07; //!< Application is selectable.
static const BYTE GP211_LIFE_CYCLE_APPLICATION_LOCKED = 0xff; //!< Application is locked.
static const BYTE GP211_LIFE_CYCLE_SECURITY_DOMAIN_INSTALLED = 0x03; //!< Application is installed
static const BYTE GP211_LIFE_CYCLE_SECURITY_DOMAIN_SELECTABLE = 0x07; //!< Application is selectable.
static const BYTE GP211_LIFE_CYCLE_SECURITY_DOMAIN_PERSONALIZED = 0xff; //!< Application is personalized.
static const BYTE GP211_LIFE_CYCLE_SECURITY_DOMAIN_LOCKED = 0xff; //!< Application is locked.

/* consts for MANAGE CHANNEL */

static const BYTE GP211_MANAGE_CHANNEL_OPEN = 0x00; //!< Open the next available Supplementary Logical Channel.
static const BYTE GP211_MANAGE_CHANNEL_CLOSE = 0x80; //!< Close the Supplementary Logical Channel.


static const BYTE GP211_APPLICATION_PRIVILEGE_SECURITY_DOMAIN = 0x80; //!< Application is security domain.
static const BYTE GP211_APPLICATION_PRIVILEGE_DAP_VERIFICATION = 0x40; //!< Application can require DAP verification for loading and installating applications.
static const BYTE GP211_APPLICATION_PRIVILEGE_DELEGATED_MANAGEMENT = 0x20; //!< Security domain has delegeted management right.
static const BYTE GP211_APPLICATION_PRIVILEGE_CARD_MANAGER_LOCK_PRIVILEGE = 0x10; //!< Application can lock the Card Manager.
static const BYTE GP211_APPLICATION_PRIVILEGE_CARD_MANAGER_TERMINATE_PRIVILEGE = 0x08; //!< Application can terminate the card.
static const BYTE GP211_APPLICATION_PRIVILEGE_DEFAULT_SELECTED = 0x04; //!< Application is default selected.
static const BYTE GP211_APPLICATION_PRIVILEGE_PIN_CHANGE_PRIVILEGE = 0x02; //!< Application can change global PIN.
static const BYTE GP211_APPLICATION_PRIVILEGE_MANDATED_DAP_VERIFICATION = 0x01; //!< Security domain requires DAP verification for loading and installating applications.

static const BYTE GP211_STATUS_APPLICATIONS = 0x40; //!< Indicate Applications or Security Domains in GP211_get_status() (request GP211_APPLICATION_DATA) or GP211_set_status().
static const BYTE GP211_STATUS_ISSUER_SECURITY_DOMAIN = 0x80; //!< Indicate Issuer Security Domain in GP211_get_status() (request GP211_APPLICATION_DATA) or GP211_set_status().
static const BYTE GP211_STATUS_LOAD_FILES = 0x20; //!< Request GP211_APPLICATION_DATA for Executable Load Files in GP211_get_status().
static const BYTE GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES = 0x10; //!< Request GP211_EXECUTABLE_MODULES_DATA for Executable Load Files and their Executable Modules in GP211_get_status().





// Some possible identifiers to retrieve card data with get_data() and put_data().

static const BYTE GP211_GET_DATA_ISSUER_IDENTIFICATION_NUMBER[2] = {0x00, 0x42}; //!< Issuer Identification Number, if Card Manager selected.
static const BYTE GP211_GET_DATA_APPLICATION_PROVIDER_IDENTIFICATION_NUMBER[2] = {0x00, 0x42}; //!< Application Provider Identification Number, if Security Domain selected.

static const BYTE GP211_GET_DATA_CARD_IMAGE_NUMBER[2] = {0x00, 0x45}; //!< Card Image Number, if Card Manager selected.
static const BYTE GP211_GET_DATA_SECURITY_DOMAIN_IMAGE_NUMBER[2] = {0x00, 0x45}; //!< Security Domain Image Number, if Security Domain selected.

static const BYTE GP211_GET_DATA_ISSUER_SECURITY_DOMAIN_AID[2] = {0x00, 0x4F}; //!< Change Issuer Security Domain AID, if Issuer Security Domain selected.
static const BYTE GP211_GET_DATA_SECURITY_DOMAIN_AID[2] = {0x00, 0x4F}; //!< Change Security Domain AID, if Security Domain selected.

static const BYTE GP211_GET_DATA_CARD_DATA[2] = {0x00, 0x66}; //!< Card Data.
static const BYTE GP211_GET_DATA_SEQUENCE_COUNTER_DEFAULT_KEY_VERSION[2] = {0x00, 0xC1}; //!< Sequence Counter of the default Key Version Number.
static const BYTE GP211_GET_DATA_CONFIRMATION_COUNTER[2] = {0x00, 0xC2}; //!< Confirmation Counter.
static const BYTE GP211_GET_DATA_FREE_EEPROM_MEMORY_SPACE[2] = {0x00, 0xC6}; //!< Free EEPROM memory space.
static const BYTE GP211_GET_DATA_FREE_COR_RAM[2] = {0x00, 0xC7}; //!< Free transient Clear on Reset memory space (COR RAM).
static const BYTE GP211_GET_DATA_DIVERSIFICATION_DATA[2] = {0x00, 0xCF}; //!< Diversification data.

/**
 * Key Information Template of first 31 keys.
 * Next templates can be obtained with the tag 0x0x 0xE0, where x > 0.
 */
static const BYTE GP211_GET_DATA_KEY_INFORMATION_TEMPLATE[2] = {0x00, 0xE0};

static const BYTE GP211_GET_DATA_CPLC_PERSONALIZATION_DATE[2] = {0x9F, 0x66}; //!< CPLC personalization date.
static const BYTE GP211_GET_DATA_CPLC_PRE_PERSONALIZATION_DATE[2] = {0x9F, 0x67}; //!< CPLC pre-personalization date.
static const BYTE GP211_GET_DATA_CPLC_ICC_MANUFACTURER_EMBEDDING_DATE[2] = {0x9F, 0x68}; //!< CPLC ICC manufacturer, embedding date.
static const BYTE GP211_GET_DATA_CPLC_MODULE_FABRICATOR_PACKAGING_DATE[2] = {0x9F, 0x69}; //!< CPLC module fabricator, module packaging date.
static const BYTE GP211_GET_DATA_CPLC_FABRICATION_DATE_SERIAL_NUMBER_BATCH_IDENTIFIER[2] = {0x9F, 0x6A}; //!< CPLC fabrication date, serial number, batch identifier.
static const BYTE GP211_GET_DATA_CPLC_WHOLE_CPLC[2] = {0x9F, 0x7F}; //!< Whole CPLC data from ROM and EEPROM.

static const BYTE GP211_GET_DATA_FCI_DATA[2] = {0xBF, 0x0C}; //!< File Control Information (FCI) discretionary data.

static const BYTE GP211_GET_DATA_PROTOCOL[2] = {0xDF, 0x70}; //!< Data for protocol change.
static const BYTE GP211_GET_DATA_ATR_HISTRORICAL_BYTES[2] = {0xDF, 0x71}; //!< Change ATR historical bytes.

static const BYTE GP211_GET_DATA_EF_PROD_DATA_INITIALIZATION_FINGERPRINT[2] = {0xDF, 0x76}; //!< EF<sub>prod</sub> data initialization fingerprint.
static const BYTE GP211_GET_DATA_EF_PROD_DATA_INITIALIZATION_DATA[2] = {0xDF, 0x77}; //!< EF<sub>prod</sub> data initialization data.
static const BYTE GP211_GET_DATA_EF_PROD_DATA_PRODUCTION_KEY_INDEX[2] = {0xDF, 0x78}; //!< EF<sub>prod</sub> data production key index.
static const BYTE GP211_GET_DATA_EF_PROD_DATA_PROTOCOL_VERSION[2] = {0xDF, 0x79}; //!< EF<sub>prod</sub> data protocol version.
static const BYTE GP211_GET_DATA_EF_PROD_DATA_CHECKSUM[2] = {0xDF, 0x7A}; //!< EF<sub>prod</sub> data checksum.
static const BYTE GP211_GET_DATA_EF_PROD_DATA_SOFTWARE_VERSION[2] = {0xDF, 0x7B}; //!< EF<sub>prod</sub> data software version.
static const BYTE GP211_GET_DATA_EF_PROD_DATA_RFU[2] = {0xDF, 0x7C}; //!< EF<sub>prod</sub> data RFU.
static const BYTE GP211_GET_DATA_EF_PROD_DATA_PROFILE_WITH_PROFILE_VERSION[2] = {0xDF, 0x7D}; //!< EF<sub>prod</sub> data profile with profile version.
static const BYTE GP211_GET_DATA_EF_PROD_DATA_LOCATION_MACHINE_DATE_TIME[2] = {0xDF, 0x7E}; //!< EF<sub>prod</sub> data location, machine number, date, time.

static const BYTE GP211_GET_DATA_WHOLE_EF_PROD[2] = {0xDF, 0x7F}; //!< Whole EF<sub>prod</sub> data block (39 Byte).

static const BYTE GP211_GET_DATA_KEY_DIVERSIFICATION[2] = {0x00, 0xCF}; //!< Key diversification data. KMC_ID (6 bytes) + CSN (4 bytes). KMC_ID is usually the IIN (Issuer identification number). CSN is the card serial number.






static const BYTE OP201_CARD_MANAGER_AID[7] = {0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00}; //!< The AID of the Card Manager defined by Open Platform specification.


static const BYTE OP201_LIFE_CYCLE_LOAD_FILE_LOGICALLY_DELETED = 0x00; //!< Executable Load File is logically deleted.
static const BYTE OP201_LIFE_CYCLE_LOAD_FILE_LOADED = 0x01; //!< Executable Load File is loaded.
static const BYTE OP201_LIFE_CYCLE_CARD_MANAGER_OP_READY = 0x01; //!< Card is OP ready.
static const BYTE OP201_LIFE_CYCLE_CARD_MANAGER_INITIALIZED = 0x07; //!< Card is initialized.
static const BYTE OP201_LIFE_CYCLE_CARD_MANAGER_SECURED = 0x0f; //!< Card is in secured state.
static const BYTE OP201_LIFE_CYCLE_CARD_MANAGER_CM_LOCKED = 0x7f; //!< Card is locked.
static const BYTE OP201_LIFE_CYCLE_CARD_MANAGER_TERMINATED = 0xff; //!< Card is terminated.
static const BYTE OP201_LIFE_CYCLE_APPLICATION_LOGICALLY_DELETED = 0x00; //!< Application is logically deleted.
static const BYTE OP201_LIFE_CYCLE_APPLICATION_INSTALLED = 0x03; //!< Application is installed
static const BYTE OP201_LIFE_CYCLE_APPLICATION_SELECTABLE = 0x07; //!< Application is selectable.
static const BYTE OP201_LIFE_CYCLE_APPLICATION_PERSONALIZED = 0x0f; //!< Application is personalized.
static const BYTE OP201_LIFE_CYCLE_APPLICATION_BLOCKED = 0x7f; //!< Application is blocked.
static const BYTE OP201_LIFE_CYCLE_APPLICATION_LOCKED = 0xff; //!< Application is locked.

static const BYTE OP201_APPLICATION_PRIVILEGE_SECURITY_DOMAIN = 0x80; //!< Application is security domain.
static const BYTE OP201_APPLICATION_PRIVILEGE_DAP_VERIFICATION = 0x40; //!< Application can require DAP verification for loading and installating applications.
static const BYTE OP201_APPLICATION_PRIVILEGE_DELEGATED_MANAGEMENT = 0x20; //!< Security domain has delegeted management right.
static const BYTE OP201_APPLICATION_PRIVILEGE_CARD_MANAGER_LOCK_PRIVILEGE = 0x10; //!< Application can lock the Card Manager.
static const BYTE OP201_APPLICATION_PRIVILEGE_CARD_MANAGER_TERMINATE_PRIVILEGE = 0x08; //!< Application can terminate the card.
static const BYTE OP201_APPLICATION_PRIVILEGE_DEFAULT_SELECTED = 0x04; //!< Application is default selected.
static const BYTE OP201_APPLICATION_PRIVILEGE_PIN_CHANGE_PRIVILEGE = 0x02; //!< Application can change global PIN.
static const BYTE OP201_APPLICATION_PRIVILEGE_MANDATED_DAP_VERIFICATION = 0x01; //!< Security domain requires DAP verification for loading and installating applications.

static const BYTE OP201_STATUS_APPLICATIONS = 0x40; //!< Indicate Applications or Security Domains in OP201_get_status() or OP201_set_status().
static const BYTE OP201_STATUS_CARD_MANAGER = 0x80; //!< Indicate Card Manager in OP201_get_status() or OP201_set_status().
static const BYTE OP201_STATUS_LOAD_FILES = 0x20; //!< Request OP201_APPLICATION_DATA for Executable Load Files in OP201_get_status().


// Some possible identifiers to retrieve card data with get_data() and put_data().
static const BYTE OP201_GET_DATA_ISSUER_BIN[2] = {0x00, 0x42}; //!< Issuer BIN, if Card Manager selected.
static const BYTE OP201_GET_DATA_APPLICATION_PROVIDER_IDENTIFICATION_NUMBER[2] = {0x00, 0x42}; //!< Application provider identification number, if Security Domain selected.

static const BYTE OP201_GET_DATA_ISSUER_DATA[2] = {0x00, 0x45}; //!< Card issuer data, if Card Manager selected.
static const BYTE OP201_GET_DATA_SECURITY_DOMAIN_IMAGE_NUMBER[2] = {0x00, 0x45}; //!< Security domain image number, if Security Domain selected.

static const BYTE OP201_GET_DATA_CARD_MANAGER_AID[2] = {0x00, 0x4F}; //!< Change Card Manager AID, if Card Manager selected.
static const BYTE OP201_GET_DATA_SECURITY_DOMAIN_AID[2] = {0x00, 0x4F}; //!< Change Security Domain AID, if Security Domain selected.

static const BYTE OP201_GET_DATA_CARD_RECOGNITION_DATA[2] = {0x00, 0x66}; //!< Card recognition data.
static const BYTE OP201_GET_DATA_SEQUENCE_COUNTER_DEFAULT_KEY_VERSION[2] = {0x00, 0xC1}; //!< Sequence Counter of the default Key Version Number.
static const BYTE OP201_GET_DATA_CONFIRMATION_COUNTER[2] = {0x00, 0xC2}; //!< Confirmation Counter.
static const BYTE OP201_GET_DATA_FREE_EEPROM_MEMORY_SPACE[2] = {0x00, 0xC6}; //!< Free EEPROM memory space.
static const BYTE OP201_GET_DATA_FREE_COR_RAM[2] = {0x00, 0xC7}; //!< Free transient Clear on Reset memory space (COR RAM).
static const BYTE OP201_GET_DATA_DIVERSIFICATION_DATA[2] = {0x00, 0xCF}; //!< Diversification data.

/**
 * Key Information Template of first 31 keys.
 * Next templates can be obtained with the tag 0x0x 0xE0, where x > 0.
 */
static const BYTE OP201_GET_DATA_KEY_INFORMATION_TEMPLATE[2] = {0x00, 0xE0};

static const BYTE OP201_GET_DATA_CPLC_PERSONALIZATION_DATE[2] = {0x9F, 0x66}; //!< CPLC personalization date.
static const BYTE OP201_GET_DATA_CPLC_PRE_PERSONALIZATION_DATE[2] = {0x9F, 0x67}; //!< CPLC pre-personalization date.
static const BYTE OP201_GET_DATA_CPLC_ICC_MANUFACTURER_EMBEDDING_DATE[2] = {0x9F, 0x68}; //!< CPLC ICC manufacturer, embedding date.
static const BYTE OP201_GET_DATA_CPLC_MODULE_FABRICATOR_PACKAGING_DATE[2] = {0x9F, 0x69}; //!< CPLC module fabricator, module packaging date.
static const BYTE OP201_GET_DATA_CPLC_FABRICATION_DATE_SERIAL_NUMBER_BATCH_IDENTIFIER[2] = {0x9F, 0x6A}; //!< CPLC fabrication date, serial number, batch identifier.
static const BYTE OP201_GET_DATA_CPLC_WHOLE_CPLC[2] = {0x9F, 0x7F}; //!< Whole CPLC data from ROM and EEPROM.

static const BYTE OP201_GET_DATA_FCI_DATA[2] = {0xBF, 0x0C}; //!< File Control Information (FCI) discretionary data.

static const BYTE OP201_GET_DATA_PROTOCOL[2] = {0xDF, 0x70}; //!< Data for protocol change.
static const BYTE OP201_GET_DATA_ATR_HISTRORICAL_BYTES[2] = {0xDF, 0x71}; //!< Change ATR historical bytes.

static const BYTE OP201_GET_DATA_EF_PROD_DATA_INITIALIZATION_FINGERPRINT[2] = {0xDF, 0x76}; //!< EF<sub>prod</sub> data initialization fingerprint.
static const BYTE OP201_GET_DATA_EF_PROD_DATA_INITIALIZATION_DATA[2] = {0xDF, 0x77}; //!< EF<sub>prod</sub> data initialization data.
static const BYTE OP201_GET_DATA_EF_PROD_DATA_PRODUCTION_KEY_INDEX[2] = {0xDF, 0x78}; //!< EF<sub>prod</sub> data production key index.
static const BYTE OP201_GET_DATA_EF_PROD_DATA_PROTOCOL_VERSION[2] = {0xDF, 0x79}; //!< EF<sub>prod</sub> data protocol version.
static const BYTE OP201_GET_DATA_EF_PROD_DATA_CHECKSUM[2] = {0xDF, 0x7A}; //!< EF<sub>prod</sub> data checksum.
static const BYTE OP201_GET_DATA_EF_PROD_DATA_SOFTWARE_VERSION[2] = {0xDF, 0x7B}; //!< EF<sub>prod</sub> data software version.
static const BYTE OP201_GET_DATA_EF_PROD_DATA_RFU[2] = {0xDF, 0x7C}; //!< EF<sub>prod</sub> data RFU.
static const BYTE OP201_GET_DATA_EF_PROD_DATA_PROFILE_WITH_PROFILE_VERSION[2] = {0xDF, 0x7D}; //!< EF<sub>prod</sub> data profile with profile version.
static const BYTE OP201_GET_DATA_EF_PROD_DATA_LOCATION_MACHINE_DATE_TIME[2] = {0xDF, 0x7E}; //!< EF<sub>prod</sub> data location, machine number, date, time.

static const BYTE OP201_GET_DATA_WHOLE_EF_PROD[2] = {0xDF, 0x7F}; //!< Whole EF<sub>prod</sub> data block (39 Byte).

static const BYTE OPGP_DERIVATION_METHOD_NONE = 0; //!< No key derivation is used during mutual authentication.
static const BYTE OPGP_DERIVATION_METHOD_VISA2 = 1; //!< The VISA2 key derivation is used during mutual authentication.
static const BYTE OPGP_DERIVATION_METHOD_EMV_CPS11 = 2; //!< The EMV CPS 11 derivation is used during mutual authentication.

#define OPGP_WORK_UNKNOWN -1 //!< The amount of work is not known.
#define OPGP_TASK_FINISHED 1 //!< The task is finished.

#define INIT_PROGRESS_CALLBACK_PARAMETERS(callbackParameters, callback) 	if (callback != NULL) {callbackParameters.parameters = callback->parameters; \
	callbackParameters.finished = !OPGP_TASK_FINISHED;}

/**
 * The structure measures the progress of a task. This structure is passed to the callback function.
 */
typedef struct {
	DWORD currentWork; //!< The current work which is done. If not known this contains #OPGP_WORK_UNKNOWN
	DWORD totalWork; //!< The total work which needs to be done. If not known this contains #OPGP_WORK_UNKNOWN
	DWORD finished; //!< Task is finished. If finished contains #OPGP_TASK_FINISHED.
	PVOID parameters; //!< Proprietary parameters for the function passed in with #OPGP_PROGRESS_CALLBACK.
} OPGP_PROGRESS_CALLBACK_PARAMETERS;

/**
 * The structure is used when the progress for a task changes in functions supporting callbacks.
 */
typedef struct {
	PVOID callback; //!< The callback function. The must accept a #OPGP_PROGRESS_CALLBACK_PARAMETERS parameter and return void, so the function signature is: void (*callback)(OPGP_PROGRESS_CALLBACK_PARAMETERS).
	PVOID parameters; //!< Proprietary parameters for the callback function. Passed in when the function is called.
} OPGP_PROGRESS_CALLBACK;

/**
 * The structure containing Card Manager, Executable Load File and application life cycle states and privileges returned by get_status().
 */
typedef struct {
	BYTE AIDLength; //!< The length of the AID.
	BYTE AID[16]; //!< The AID.
	BYTE lifeCycleState; //!< The Card Manager, Executable Load File or application life cycle state.
	BYTE privileges; //!< The Card Manager or application privileges.
} OP201_APPLICATION_DATA;


/**
 * A structure describing an AID.
 */
typedef struct {
	BYTE AIDLength; //!< The length of the AID.
	BYTE AID[16]; //!< The AID.
} OPGP_AID;


/**
 * A structure describing an Executable Load File.
 * This structure is limited to 32 applets in the Load File.
 */
typedef struct {
	DWORD loadFileSize; //!< The size of the Load File.
	OPGP_AID loadFileAID; //!< The AID of the Load File.
	BYTE numAppletAIDs; //!< The number of applets contained in the Load File.
	OPGP_AID appletAIDs[32]; //!< The contained applets in the Load File.
} OPGP_LOAD_FILE_PARAMETERS;


/**
 * The structure containing Issuer Security Domain, Security Domains, Executable Load Files
 * and Application life cycle states and privileges returned by get_status().
 */
typedef struct {
	BYTE AIDLength; //!< The length of the AID.
	BYTE AID[16]; //!< The AID.
	BYTE lifeCycleState; //!< The Issuer Security Domain, Security Domains, Executable Load Files and Application life cycle state.
	BYTE privileges; //!< The Issuer Security Domain, Security Domains or Application privileges. Has no meaning for Executable Load Files.
} GP211_APPLICATION_DATA;

/**
 * The structure containing Executable Load Files and their Executable Module returned by get_status().
 */
typedef struct {
	BYTE AIDLength; //!< The length of the Executable Load File AID.
	BYTE AID[16]; //!< The Executable Load File AID.
	BYTE lifeCycleState; //!< The Executable Load File life cycle state.
	BYTE numExecutableModules; //!< Number of associated Executable Modules.
	OPGP_AID executableModules[256]; //!< Array for the maximum possible associated Executable Modules.
} GP211_EXECUTABLE_MODULES_DATA;

//! \brief GlobalPlatform2.1.1: Selects an application on a card by AID.
OPGP_API
OPGP_ERROR_STATUS OPGP_select_application(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, PBYTE AID, DWORD AIDLength);

/** \brief GlobalPlatform2.1.1: Gets the life cycle status of Applications, the Issuer Security
 * Domains, Security Domains and Executable Load Files and their privileges or information about
 * Executable Modules of the Executable Load Files.
 */
OPGP_API
OPGP_ERROR_STATUS GP211_get_status(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				BYTE cardElement, GP211_APPLICATION_DATA *applData,
				GP211_EXECUTABLE_MODULES_DATA *executableData, PDWORD dataLength);

//! \brief GlobalPlatform2.1.1: Sets the life cycle status of Applications, Security Domains or the Card Manager.
OPGP_API
OPGP_ERROR_STATUS GP211_set_status(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE cardElement, PBYTE AID, DWORD AIDLength, BYTE lifeCycleState);

//! \brief GlobalPlatform2.1.1: Mutual authentication.
OPGP_API
OPGP_ERROR_STATUS GP211_mutual_authentication(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo,
						   BYTE baseKey[16], BYTE S_ENC[16], BYTE S_MAC[16],
						   BYTE DEK[16], BYTE keySetVersion,
						   BYTE keyIndex, BYTE secureChannelProtocol,
						   BYTE secureChannelProtocolImpl,
						   BYTE securityLevel, BYTE derivationMethod, GP211_SECURITY_INFO *secInfo);

//! \brief GlobalPlatform2.1.1: Inits a Secure Channel implicitly.
OPGP_API
OPGP_ERROR_STATUS GP211_init_implicit_secure_channel(PBYTE AID, DWORD AIDLength, BYTE baseKey[16],
								  BYTE S_ENC[16], BYTE S_MAC[16], BYTE DEK[16],
								  BYTE secureChannelProtocolImpl, BYTE sequenceCounter[2],
								  GP211_SECURITY_INFO *secInfo);

//! \brief GlobalPlatform2.1.1: Closes a Secure Channel implicitly.
OPGP_API
OPGP_ERROR_STATUS close_implicit_secure_channel(GP211_SECURITY_INFO *secInfo);

//! \brief GlobalPlatform2.1.1: Retrieve card data.
OPGP_API
OPGP_ERROR_STATUS GP211_get_data(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
			  BYTE identifier[2], PBYTE recvBuffer, PDWORD recvBufferLength);

//! \brief Retrieve card data according ISO/IEC 7816-4 command not within a secure channel.
OPGP_API
OPGP_ERROR_STATUS GP211_get_data_iso7816_4(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, BYTE identifier[2], PBYTE recvBuffer, PDWORD recvBufferLength);

//! \brief GlobalPlatform2.1.1: This returns the Secure Channel Protocol and the Secure Channel Protocol implementation.
OPGP_API
OPGP_ERROR_STATUS GP211_get_secure_channel_protocol_details(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo,
										 BYTE *secureChannelProtocol, BYTE *secureChannelProtocolImpl);

//! \brief GlobalPlatform2.1.1: This returns the current Sequence Counter.
OPGP_API
OPGP_ERROR_STATUS GP211_get_sequence_counter(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo,
						  BYTE sequenceCounter[2]);

//! \brief GlobalPlatform2.1.1: Put card data.
OPGP_API
OPGP_ERROR_STATUS GP211_put_data(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
			  BYTE identifier[2], PBYTE dataObject, DWORD dataObjectLength);

//! \brief GlobalPlatform2.1.1: Changes or unblocks the global PIN.
OPGP_API
OPGP_ERROR_STATUS GP211_pin_change(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				BYTE tryLimit, PBYTE newPIN, DWORD newPINLength);

//! \brief GlobalPlatform2.1.1: replaces a single 3DES key in a key set or adds a new 3DES key.
OPGP_API
OPGP_ERROR_STATUS GP211_put_3des_key(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				  BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, BYTE _3DESKey[16]);

//! \brief GlobalPlatform2.1.1: replaces a single public RSA key in a key set or adds a new public RSA key.
OPGP_API
OPGP_ERROR_STATUS GP211_put_rsa_key(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, OPGP_STRING PEMKeyFileName, char *passPhrase);

//! \brief GlobalPlatform2.1.1: replaces or adds a secure channel key set consisting of S-ENC, S-MAC and DEK.
OPGP_API
OPGP_ERROR_STATUS GP211_put_secure_channel_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
							 BYTE keySetVersion, BYTE newKeySetVersion, BYTE baseKey[16],
							 BYTE newS_ENC[16], BYTE newS_MAC[16], BYTE newDEK[16]);

//! \brief GlobalPlatform2.1.1: deletes a key or multiple keys.
OPGP_API
OPGP_ERROR_STATUS GP211_delete_key(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				BYTE keySetVersion, BYTE keyIndex);

//! \brief GlobalPlatform2.1.1: Retrieves key information of keys on the card.
OPGP_API
OPGP_ERROR_STATUS GP211_get_key_information_templates(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								   BYTE keyInformationTemplate,
								   GP211_KEY_INFORMATION *keyInformation, PDWORD keyInformationLength);

//! \brief GlobalPlatform2.1.1: Deletes a Executable Load File or an application.
OPGP_API
OPGP_ERROR_STATUS GP211_delete_application(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				   OPGP_AID *AIDs, DWORD AIDsLength,
				   GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataLength);

//! \brief GlobalPlatform2.1.1: Prepares the card for loading an application.
OPGP_API
OPGP_ERROR_STATUS GP211_install_for_load(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
					  PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
					  PBYTE securityDomainAID,
					  DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20], BYTE loadToken[128],
					  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
					  DWORD nonVolatileDataSpaceLimit);

//! \brief GlobalPlatform2.1.1: Function to retrieve the data to sign by the Card Issuer in an Extradition Token.
OPGP_API
OPGP_ERROR_STATUS GP211_get_extradition_token_signature_data(PBYTE securityDomainAID,
										  DWORD securityDomainAIDLength,
										  PBYTE applicationAID, DWORD applicationAIDLength,
										  PBYTE extraditionTokenSignatureData,
										  PDWORD extraditionTokenSignatureDataLength);

//! \brief GlobalPlatform2.1.1: Function to retrieve the data to sign by the Card Issuer in a Load Token.
OPGP_API
OPGP_ERROR_STATUS GP211_get_load_token_signature_data(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
								   PBYTE securityDomainAID,
								   DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20],
								   DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
								   DWORD nonVolatileDataSpaceLimit, PBYTE loadTokenSignatureData,
								   PDWORD loadTokenSignatureDataLength);

//! \brief GlobalPlatform2.1.1: Function to retrieve the data to sign by the Card Issuer in an Install Token.
OPGP_API
OPGP_ERROR_STATUS GP211_get_install_token_signature_data(BYTE P1, PBYTE executableLoadFileAID,
									  DWORD executableLoadFileAIDLength,
									  PBYTE executableModuleAID, DWORD executableModuleAIDLength,
									  PBYTE applicationAID, DWORD applicationAIDLength,
									  BYTE applicationPrivileges, DWORD volatileDataSpaceLimit,
									  DWORD nonVolatileDataSpaceLimit, PBYTE installParameters,
									  DWORD installParametersLength, PBYTE installTokenSignatureData,
									  PDWORD installTokenSignatureDataLength);

//! \brief GlobalPlatform2.1.1: Calculates a Load Token using PKCS#1.
OPGP_API
OPGP_ERROR_STATUS GP211_calculate_load_token(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						  PBYTE securityDomainAID,
						  DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20],
						  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
						  DWORD nonVolatileDataSpaceLimit, BYTE loadToken[128],
						  OPGP_STRING PEMKeyFileName, char *passPhrase);

//! \brief GlobalPlatform2.1.1: Calculates an Install Token using PKCS#1.
OPGP_API
OPGP_ERROR_STATUS GP211_calculate_install_token(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
							 PBYTE executableModuleAID,
							 DWORD executableModuleAIDLength, PBYTE applicationAID,
							 DWORD applicationAIDLength, BYTE applicationPrivileges,
							 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
							 PBYTE installParameters, DWORD installParametersLength,
							 BYTE installToken[128], OPGP_STRING PEMKeyFileName, char *passPhrase);

//! \brief GlobalPlatform2.1.1: Calculates a Load File Data Block Hash.
OPGP_API
OPGP_ERROR_STATUS GP211_calculate_load_file_data_block_hash(OPGP_STRING executableLoadFileName,
							 unsigned char hash[20]);

//! \brief GlobalPlatform2.1.1: Loads a Executable Load File (containing an application) to the card.
OPGP_API
OPGP_ERROR_STATUS GP211_load(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 GP211_DAP_BLOCK *dapBlock, DWORD dapBlockLength, OPGP_STRING executableLoadFileName,
				 GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable, OPGP_PROGRESS_CALLBACK *callback);

//! \brief GlobalPlatform2.1.1: Loads a Executable Load File (containing an application) from a buffer to the card.
OPGP_API
OPGP_ERROR_STATUS GP211_load_from_buffer(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 GP211_DAP_BLOCK *dapBlock, DWORD dapBlockLength,
				 PBYTE loadFileBuffer, DWORD loadFileBufSize,
				 GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable, OPGP_PROGRESS_CALLBACK *callback);

//! \brief GlobalPlatform2.1.1: Installs an application on the card.
OPGP_API
OPGP_ERROR_STATUS GP211_install_for_install(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE executableModuleAID,
						 DWORD executableModuleAIDLength, PBYTE applicationAID, DWORD applicationAIDLength,
						 BYTE applicationPrivileges, DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE installParameters, DWORD installParametersLength,
						 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief GlobalPlatform2.1.1: Makes an installed application selectable.
OPGP_API
OPGP_ERROR_STATUS GP211_install_for_make_selectable(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								 PBYTE applicationAID, DWORD applicationAIDLength,
								 BYTE applicationPrivileges, BYTE installToken[128],
								 GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief GlobalPlatform2.1.1: Installs and makes an installed application selectable.
OPGP_API
OPGP_ERROR_STATUS GP211_install_for_install_and_make_selectable(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE executableModuleAID,
						 DWORD executableModuleAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE installParameters, DWORD installParametersLength,
						 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief GlobalPlatform2.1.1: Informs a Security Domain that a associated application will retrieve personalization data.
OPGP_API
OPGP_ERROR_STATUS GP211_install_for_personalization(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo,
											 GP211_SECURITY_INFO *secInfo,
						 PBYTE applicationAID,
						 DWORD applicationAIDLength);

//! \brief GlobalPlatform2.1.1: Associates an application with another Security Domain.
OPGP_API
OPGP_ERROR_STATUS GP211_install_for_extradition(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
							  PBYTE securityDomainAID,
						 DWORD securityDomainAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength,
						 BYTE extraditionToken[128], GP211_RECEIPT_DATA *receiptData,
						 PDWORD receiptDataAvailable);

//! \brief GlobalPlatform2.1.1: Adds a key set for Delegated Management.
OPGP_API
OPGP_ERROR_STATUS GP211_put_delegated_management_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								   BYTE keySetVersion,
								   BYTE newKeySetVersion,
								   OPGP_STRING PEMKeyFileName, char *passPhrase,
								   BYTE receiptKey[16]);

//! \brief Sends an application protocol data unit.
OPGP_API
OPGP_ERROR_STATUS GP211_send_APDU(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
			   PBYTE capdu, DWORD capduLength, PBYTE rapdu,
			   PDWORD rapduLength);

//! \brief GlobalPlatform2.1.1: Calculates a Load File Data Block Signature using 3DES.
OPGP_API
OPGP_ERROR_STATUS GP211_calculate_3des_DAP(BYTE loadFileDataBlockHash[20],
						PBYTE securityDomainAID,
						DWORD securityDomainAIDLength,
						BYTE DAPVerificationKey[16], GP211_DAP_BLOCK *loadFileDataBlockSignature);

//! \brief GlobalPlatform2.1.1: Calculates a Load File Data Block Signature using SHA-1 and PKCS#1 (RSA).
OPGP_API
OPGP_ERROR_STATUS GP211_calculate_rsa_DAP(BYTE loadFileDataBlockHash[20], PBYTE securityDomainAID,
					   DWORD securityDomainAIDLength, OPGP_STRING PEMKeyFileName,
					   char *passPhrase, GP211_DAP_BLOCK *loadFileDataBlockSignature);

//! \brief GlobalPlatform2.1.1: Validates a Load Receipt.
OPGP_API
OPGP_ERROR_STATUS GP211_validate_delete_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
						   DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE AID, DWORD AIDLength);

//! \brief GlobalPlatform2.1.1: Validates an Install Receipt.
OPGP_API
OPGP_ERROR_STATUS GP211_validate_install_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
						   DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE applicationAID, DWORD applicationAIDLength);

//! \brief GlobalPlatform2.1.1: Validates a Load Receipt.
OPGP_API
OPGP_ERROR_STATUS GP211_validate_load_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
						   DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE securityDomainAID, DWORD securityDomainAIDLength);

//! \brief GlobalPlatform2.1.1: Validates an Extradition Receipt.
OPGP_ERROR_STATUS GP211_validate_extradition_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
							  DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE oldSecurityDomainAID, DWORD oldSecurityDomainAIDLength,
						   PBYTE newSecurityDomainAID, DWORD newSecurityDomainAIDLength,
						   PBYTE applicationOrExecutableLoadFileAID,
						   DWORD applicationOrExecutableLoadFileAIDLength);

//! \brief ISO 7816-4 / GlobalPlatform2.1.1: Opens or closes a Logical Channel.
OPGP_API
OPGP_ERROR_STATUS OPGP_manage_channel(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO *cardInfo, GP211_SECURITY_INFO *secInfo,
					BYTE openClose, BYTE channelNumberToClose,
					BYTE *channelNumberOpened);

//! \brief ISO 7816-4 / GlobalPlatform2.1.1: If multiple Logical Channels are open or a new Logical Channel is opened with select_application(), selects the Logical Channel.
OPGP_API
OPGP_ERROR_STATUS OPGP_select_channel(OPGP_CARD_INFO *cardInfo, BYTE channelNumber);

//! \brief GlobalPlatform2.1.1: The STORE DATA command is used to transfer data to an Application or the Security Domain processing the command.
OPGP_API
OPGP_ERROR_STATUS GP211_store_data(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 PBYTE data, DWORD dataLength);

//! \brief Open Platform: Gets the life cycle status of Applications, the Card Manager and Executable Load Files and their privileges.
OPGP_API
OPGP_ERROR_STATUS OP201_get_status(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo, BYTE cardElement, OP201_APPLICATION_DATA *applData, PDWORD applDataLength);

//! \brief Open Platform: Sets the life cycle status of Applications, Security Domains or the Card Manager.
OPGP_API
OPGP_ERROR_STATUS OP201_set_status(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo, BYTE cardElement, PBYTE AID, DWORD AIDLength, BYTE lifeCycleState);


//! \brief Open Platform: Mutual authentication.
OPGP_API
OPGP_ERROR_STATUS OP201_mutual_authentication(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, BYTE baseKey[16], BYTE encKey[16], BYTE macKey[16],
								 BYTE kekKey[16], BYTE keySetVersion,
						   BYTE keyIndex, BYTE securityLevel, BYTE derivationMethod,
						   OP201_SECURITY_INFO *secInfo);

//! \brief Open Platform: Retrieve card data.
OPGP_API
OPGP_ERROR_STATUS OP201_get_data(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
					BYTE identifier[2], PBYTE recvBuffer, PDWORD recvBufferLength);

//! \brief Open Platform: Put card data.
OPGP_API
OPGP_ERROR_STATUS OP201_put_data(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
					BYTE identifier[2], PBYTE dataObject, DWORD dataObjectLength);

//! \brief Open Platform: Changes or unblocks the global PIN.
OPGP_API
OPGP_ERROR_STATUS OP201_pin_change(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				BYTE tryLimit, PBYTE newPIN, DWORD newPINLength, BYTE KEK[16]);

//! \brief Open Platform: replaces a single 3DES key in a key set or adds a new 3DES key.
OPGP_API
OPGP_ERROR_STATUS OP201_put_3desKey(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				  BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, BYTE _3desKey[16],
				  BYTE KEK[16]);

//! \brief Open Platform: replaces a single public RSA key in a key set or adds a new public RSA key.
OPGP_API
OPGP_ERROR_STATUS OP201_put_rsa_key(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				 BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, OPGP_STRING PEMKeyFileName, char *passPhrase);

//! \brief Open Platform: replaces or adds a secure channel key set consisting of encryption key, MAC key and key encryption.
OPGP_API
OPGP_ERROR_STATUS OP201_put_secure_channel_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
							 BYTE keySetVersion, BYTE newKeySetVersion,
							 BYTE new_encKey[16], BYTE new_macKey[16], BYTE new_KEK[16], BYTE KEK[16]);

//! \brief Open Platform: deletes a key or multiple keys.
OPGP_API
OPGP_ERROR_STATUS OP201_delete_key(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				BYTE keySetVersion, BYTE keyIndex);

//! \brief Open Platform: Retrieves key information of keys on the card.
OPGP_API
OPGP_ERROR_STATUS OP201_get_key_information_templates(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
								   BYTE keyInformationTemplate,
								   OP201_KEY_INFORMATION *keyInformation, PDWORD keyInformationLength);

//! \brief Open Platform: Deletes a Executable Load File or an application.
OPGP_API
OPGP_ERROR_STATUS OP201_delete_application(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				   OPGP_AID *AIDs, DWORD AIDsLength,
				   OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataLength);

//! \brief Open Platform: Prepares the card for loading an application.
OPGP_API
OPGP_ERROR_STATUS OP201_install_for_load(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
					  PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
					  DWORD securityDomainAIDLength, BYTE loadFileDAP[20], BYTE loadToken[128],
					  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
					  DWORD nonVolatileDataSpaceLimit);

//! \brief Open Platform: Function to retrieve the data to sign by the Card Issuer in a Load Token.
OPGP_API
OPGP_ERROR_STATUS OP201_get_load_token_signature_data(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
								   PBYTE securityDomainAID, DWORD securityDomainAIDLength,
								   BYTE loadFileDAP[20], DWORD nonVolatileCodeSpaceLimit,
								   DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
								   PBYTE loadTokenSignatureData, PDWORD loadTokenSignatureDataLength);

//! \brief Open Platform: Function to retrieve the data to sign by the Card Issuer in an Install Token.
OPGP_API
OPGP_ERROR_STATUS OP201_get_install_token_signature_data(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
									  PBYTE AIDWithinLoadFileAID, DWORD AIDWithinLoadFileAIDLength,
									  PBYTE applicationInstanceAID, DWORD applicationInstanceAIDLength,
									  BYTE applicationPrivileges, DWORD volatileDataSpaceLimit,
									  DWORD nonVolatileDataSpaceLimit, PBYTE applicationInstallParameters,
									  DWORD applicationInstallParametersLength, PBYTE installTokenSignatureData,
									  PDWORD installTokenSignatureDataLength);

//! \brief Open Platform: Calculates a Load Token using PKCS#1.
OPGP_API
OPGP_ERROR_STATUS OP201_calculate_load_token(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
						  DWORD securityDomainAIDLength, BYTE loadFileDAP[20],
						  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
						  DWORD nonVolatileDataSpaceLimit, BYTE loadToken[128],
						  OPGP_STRING PEMKeyFileName, char *passPhrase);

//! \brief Open Platform: Calculates an Install Token using PKCS#1.
OPGP_API
OPGP_ERROR_STATUS OP201_calculate_install_token(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE AIDWithinLoadFileAID,
							 DWORD AIDWithinLoadFileAIDLength, PBYTE applicationInstanceAID,
							 DWORD applicationInstanceAIDLength, BYTE applicationPrivileges,
							 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
							 PBYTE applicationInstallParameters, DWORD applicationInstallParametersLength,
							 BYTE installToken[128], OPGP_STRING PEMKeyFileName, char *passPhrase);

//! \brief Open Platform: Calculates a Load File DAP.
OPGP_API
OPGP_ERROR_STATUS OP201_calculate_load_file_DAP(OP201_DAP_BLOCK *dapBlock, DWORD dapBlockLength,
							 OPGP_STRING executableLoadFileName, unsigned char hash[20]);

//! \brief Open Platform: Loads a Executable Load File (containing an application) to the card.
OPGP_API
OPGP_ERROR_STATUS OP201_load(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				 OP201_DAP_BLOCK *dapBlock, DWORD dapBlockLength, OPGP_STRING executableLoadFileName,
				 OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable, OPGP_PROGRESS_CALLBACK *callback);

//! \brief Open Platform: Loads a Executable Load File (containing an application) from a buffer to the card.
OPGP_API
OPGP_ERROR_STATUS OP201_load_from_buffer(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				 OP201_DAP_BLOCK *dapBlock, DWORD dapBlockLength,
				 PBYTE loadFilebuf, DWORD loadFileBufSize,
				 OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable, OPGP_PROGRESS_CALLBACK *callback);

//! \brief Open Platform: Installs an application on the card.
OPGP_API
OPGP_ERROR_STATUS OP201_install_for_install(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE AIDWithinLoadFileAID,
						 DWORD AIDWithinLoadFileAIDLength, PBYTE applicationInstanceAID, DWORD applicationInstanceAIDLength,
						 BYTE applicationPrivileges, DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE applicationInstallParameters, DWORD applicationInstallParametersLength,
						 BYTE installToken[128], OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief Open Platform: Makes an installed application selectable.
OPGP_API
OPGP_ERROR_STATUS OP201_install_for_make_selectable(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
								 PBYTE applicationInstanceAID, DWORD applicationInstanceAIDLength,
								 BYTE applicationPrivileges, BYTE installToken[128],
								 OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief Open Platform: Installs and makes an installed application selectable.
OPGP_API
OPGP_ERROR_STATUS OP201_install_for_install_and_make_selectable(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo, 						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE AIDWithinLoadFileAID,
						 DWORD AIDWithinLoadFileAIDLength, PBYTE applicationInstanceAID,
						 DWORD applicationInstanceAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE applicationInstallParameters, DWORD applicationInstallParametersLength,
						 BYTE installToken[128], OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief Open Platform: Adds a key set for Delegated Management.
OPGP_API
OPGP_ERROR_STATUS OP201_put_delegated_management_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
								   BYTE keySetVersion,
								   BYTE newKeySetVersion,
								   OPGP_STRING PEMKeyFileName, char *passPhrase,
								   BYTE receiptGenerationKey[16], BYTE KEK[16]);

//! \brief Sends an application protocol data unit.
OPGP_API
OPGP_ERROR_STATUS OP201_send_APDU(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
					 PBYTE capdu, DWORD capduLength, PBYTE rapdu,
			   PDWORD rapduLength);

//! \brief Open Platform: Calculates a Load File Data Block DAP using 3DES.
OPGP_API
OPGP_ERROR_STATUS OP201_calculate_3des_DAP(PBYTE securityDomainAID, DWORD securityDomainAIDLength, OPGP_STRING executableLoadFileName,
						BYTE DAP_verification_key[16], OP201_DAP_BLOCK *dapBlock);

//! \brief Open Platform: Calculates a Load File Data Block DAP using SHA-1 and PKCS#1 (RSA).
OPGP_API
OPGP_ERROR_STATUS OP201_calculate_rsa_DAP(PBYTE securityDomainAID, DWORD securityDomainAIDLength, OPGP_STRING executableLoadFileName,
					   OPGP_STRING PEMKeyFileName, char *passPhrase, OP201_DAP_BLOCK *dapBlock);

//! \brief Open Platform: Validates a Load Receipt.
OPGP_API
OPGP_ERROR_STATUS OP201_validate_delete_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receiptGenerationKey[16], OP201_RECEIPT_DATA receiptData,
						   PBYTE AID, DWORD AIDLength);

//! \brief Open Platform: Validates an Install Receipt.
OPGP_API
OPGP_ERROR_STATUS OP201_validate_install_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receiptGenerationKey[16], OP201_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE applicationInstanceAID, DWORD applicationInstanceAIDLength);

//! \brief Open Platform: Validates a Load Receipt.
OPGP_API
OPGP_ERROR_STATUS OP201_validate_load_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receiptGenerationKey[16], OP201_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE securityDomainAID, DWORD securityDomainAIDLength);


//! \brief Initiates a R-MAC session.
OPGP_API
OPGP_ERROR_STATUS GP211_begin_R_MAC(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE securityLevel, PBYTE data, DWORD dataLength);

//! \brief Terminates a R-MAC session.
OPGP_API
OPGP_ERROR_STATUS GP211_end_R_MAC(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo);

//! \brief Reads the parameters of an Executable Load File.
OPGP_API
OPGP_ERROR_STATUS OPGP_read_executable_load_file_parameters(OPGP_STRING loadFileName, OPGP_LOAD_FILE_PARAMETERS *loadFileParams);

//! \brief Derives the static keys from a master key according the VISA 2 key derivation scheme.
OPGP_API
OPGP_ERROR_STATUS OPGP_VISA2_derive_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, PBYTE AID, DWORD AIDLength, BYTE masterKey[16],
								 BYTE S_ENC[16], BYTE S_MAC[16], BYTE DEK[16]);

//! \brief Converts a CAP file to an IJC file (Executable Load File).
OPGP_API
OPGP_ERROR_STATUS OPGP_cap_to_ijc(OPGP_CSTRING capFileName, OPGP_STRING ijcFileName);

//! \brief Extracts a CAP file into a buffer.
OPGP_API
OPGP_ERROR_STATUS OPGP_extract_cap_file(OPGP_CSTRING fileName, PBYTE loadFileBuf, PDWORD loadFileBufSize);

//! \brief Receives Executable Load File as a buffer instead of a FILE.
OPGP_API
OPGP_ERROR_STATUS OPGP_read_executable_load_file_parameters_from_buffer(PBYTE loadFileBuf, DWORD loadFileBufSize, OPGP_LOAD_FILE_PARAMETERS *loadFileParams);

//! \brief Derives the static keys from a master key according the EMV CPS 1.1 key derivation scheme.
OPGP_API
OPGP_ERROR_STATUS OPGP_EMV_CPS11_derive_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, BYTE masterKey[16],
							BYTE S_ENC[16], BYTE S_MAC[16], BYTE DEK[16]);

#ifdef __cplusplus
}
#endif
#endif
