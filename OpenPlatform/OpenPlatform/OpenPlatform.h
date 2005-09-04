/* Copyright (c) 2005, Karsten Ohme
 * All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*! @file
*/

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef WIN32
#include "stdafx.h"
#endif

#ifdef WIN32
#ifdef OPSP_EXPORTS
#define OPSP_API __declspec(dllexport)
#else
#define OPSP_API __declspec(dllimport)
#endif
#else
#define OPSP_API
#endif

#ifndef max
#define max(a,b) (((a)>(b))?(a):(b))
#endif

#include <winscard.h>
#include "unicode.h"

typedef SCARDCONTEXT OPSP_CARDCONTEXT; //!< Reference to the reader ressource manager.
typedef SCARDHANDLE OPSP_CARDHANDLE; //!< Reference to a card.
typedef LPTSTR OPSP_STRING; //!< A Microsoft/Muscle PC/SC LPTSTR.
typedef LPCTSTR OPSP_CSTRING; //!< A Microsoft/Muscle PC/SC LPCTSTR.
typedef LPBYTE PBYTE; //!< A Microsoft/Muscle PC/SC LPBYTE, pointer to unsigned char.
#ifdef _WIN32
typedef LPDWORD PDWORD; //!< A Microsoft LPDWORD/Muscle PC/SC, a pointer to a double word, pointer to unsigned long.
#endif




static const BYTE OPSP_CARD_MANAGER_AID[] = {0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00}; //!< The AID of the Card Manager defined by Open Platform specification.


static const BYTE OPSP_SECURITY_LEVEL_ENC_MAC = 0x03; //!< Command messages are signed and encrypted.
static const BYTE OPSP_SECURITY_LEVEL_MAC = 0x01; //!< Command messages are signed.
static const BYTE OPSP_SECURITY_LEVEL_PLAIN = 0x00; //!< Command messages are plaintext.

static const BYTE OPSP_KEY_TYPE_RSA = 0xA1; //!< RSA key
static const BYTE OPSP_KEY_TYPE_3DES = 0x81; //!< 3DES key.
static const BYTE OPSP_LIFE_CYCLE_LOAD_FILE_LOGICALLY_DELETED = 0x00; //!< Executable Load File is logically deleted.
static const BYTE OPSP_LIFE_CYCLE_LOAD_FILE_LOADED = 0x01; //!< Executable Load File is loaded.
static const BYTE OPSP_LIFE_CYCLE_CARD_MANAGER_OP_READY = 0x01; //!< Card is OP ready.
static const BYTE OPSP_LIFE_CYCLE_CARD_MANAGER_INITIALIZED = 0x07; //!< Card is initialized.
static const BYTE OPSP_LIFE_CYCLE_CARD_MANAGER_SECURED = 0x0f; //!< Card is in secured state.
static const BYTE OPSP_LIFE_CYCLE_CARD_MANAGER_CM_LOCKED = 0x7f; //!< Card is locked.
static const BYTE OPSP_LIFE_CYCLE_CARD_MANAGER_TERMINATED = 0xff; //!< Card is termonated.
static const BYTE OPSP_LIFE_CYCLE_APPLICATION_LOGICALLY_DELETED = 0x00; //!< Application is logically deleted.
static const BYTE OPSP_LIFE_CYCLE_APPLICATION_INSTALLED = 0x03; //!< Application is installed
static const BYTE OPSP_LIFE_CYCLE_APPLICATION_SELECTABLE = 0x07; //!< Application is selectable.
static const BYTE OPSP_LIFE_CYCLE_APPLICATION_PERSONALIZED = 0x0f; //!< Application is personalized.
static const BYTE OPSP_LIFE_CYCLE_APPLICATION_BLOCKED = 0x7f; //!< Application is blocked.
static const BYTE OPSP_LIFE_CYCLE_APPLICATION_LOCKED = 0xff; //!< Application is locked.

static const BYTE OPSP_APPLICATION_PRIVILEGE_SECURITY_DOMAIN = 0x80; //!< Application is security domain.
static const BYTE OPSP_APPLICATION_PRIVILEGE_DAP_VERIFICATION = 0x40; //!< Application can require DAP verification for loading and installating applications.
static const BYTE OPSP_APPLICATION_PRIVILEGE_DELEGATED_MANAGEMENT = 0x20; //!< Security domain has delegeted management right.
static const BYTE OPSP_APPLICATION_PRIVILEGE_CARD_MANAGER_LOCK_PRIVILEGE = 0x10; //!< Application can lock the Card Manager.
static const BYTE OPSP_APPLICATION_PRIVILEGE_CARD_MANAGER_TERMINATE_PRIVILEGE = 0x08; //!< Application can terminate the card.
static const BYTE OPSP_APPLICATION_PRIVILEGE_DEFAULT_SELECTED = 0x04; //!< Application is default selected.
static const BYTE OPSP_APPLICATION_PRIVILEGE_PIN_CHANGE_PRIVILEGE = 0x02; //!< Application can change global PIN.
static const BYTE OPSP_APPLICATION_PRIVILEGE_MANDATED_DAP_VERIFICATION = 0x01; //!< Security domain requires DAP verification for loading and installating applications.

static const BYTE OPSP_STATUS_APPLICATIONS = 0x40; //!< Indicate Applications or Security Domains in get_status() or set_status().
static const BYTE OPSP_STATUS_CARD_MANAGER = 0x80; //!< Indicate Card Manager in get_status() or set_status().
static const BYTE OPSP_STATUS_LOAD_FILES = 0x20; //!< Request OPSP_APPLICATION_DATA for Executable Load Files in get_status().





// Some card states.
static const DWORD OPSP_CARD_ABSENT = SCARD_ABSENT; //!< There is no card in the reader.
static const DWORD OPSP_CARD_PRESENT = SCARD_PRESENT; //!< There is a card in the reader, but it has not been moved into position for use.
static const DWORD OPSP_CARD_SWALLOWED = SCARD_SWALLOWED; //!< There is a card in the reader in position for use. The card is not powered.
static const DWORD OPSP_CARD_POWERED = SCARD_POWERED; //!< Power is being provided to the card, but the reader driver is unaware of the mode of the card.
static const DWORD OPSP_CARD_NEGOTIABLE = SCARD_NEGOTIABLE; //!< The card has been reset and is awaiting PTS negotiation.
static const DWORD OPSP_CARD_SPECIFIC = SCARD_SPECIFIC; //!< The card has been reset and specific communication protocols have been established.





// Some possible identifiers to retrieve card data with get_data() and put_data().
static const BYTE OPSP_GET_DATA_ISSUER_BIN[2] = {0x00, 0x42}; //!< Issuer BIN, if Card Manager selected.
static const BYTE OPSP_GET_DATA_APPLICATION_PROVIDER_IDENTIFICATION_NUMBER[2] = {0x00, 0x42}; //!< Application provider identification number, if Security Domain selected.

static const BYTE OPSP_GET_DATA_ISSUER_DATA[2] = {0x00, 0x45}; //!< Card issuer data, if Card Manager selected.
static const BYTE OPSP_GET_DATA_SECURITY_DOMAIN_IMAGE_NUMBER[2] = {0x00, 0x45}; //!< Security domain image number, if Security Domain selected.

static const BYTE OPSP_GET_DATA_CARD_MANAGER_AID[2] = {0x00, 0x4F}; //!< Change Card Manager AID, if Card Manager selected.
static const BYTE OPSP_GET_DATA_SECURITY_DOMAIN_AID[2] = {0x00, 0x4F}; //!< Change Security Domain AID, if Security Domain selected.

static const BYTE OPSP_GET_DATA_CARD_RECOGNITION_DATA[2] = {0x00, 0x66}; //!< Card recognition data.
static const BYTE OPSP_GET_DATA_SEQUENCE_COUNTER_DEFAULT_KEY_VERSION[2] = {0x00, 0xC1}; //!< Sequence Counter of the default Key Version Number.
static const BYTE OPSP_GET_DATA_CONFIRMATION_COUNTER[2] = {0x00, 0xC2}; //!< Confirmation Counter.
static const BYTE OPSP_GET_DATA_FREE_EEPROM_MEMORY_SPACE[2] = {0x00, 0xC6}; //!< Free EEPROM memory space.
static const BYTE OPSP_GET_DATA_FREE_COR_RAM[2] = {0x00, 0xC7}; //!< Free transient Clear on Reset memory space (COR RAM).
static const OPSP_BYTE_DIVERSIFICATION_DATA[2] = {0x00, 0xCF}; //!< Diversification data.

/**
 * Key Information Template of first 31 keys.
 * Next templates can be obtained with the tag 0x0x 0xE0, where x > 0.
 */
static const BYTE OPSP_GET_DATA_KEY_INFORMATION_TEMPLATE[2] = {0x00, 0xE0};

static const BYTE OPSP_GET_DATA_CPLC_PERSONALIZATION_DATE[2] = {0x9F, 0x66}; //!< CPLC personalization date.
static const BYTE OPSP_GET_DATA_CPLC_PRE_PERSONALIZATION_DATE[2] = {0x9F, 0x67}; //!< CPLC pre-personalization date.
static const BYTE OPSP_GET_DATA_CPLC_ICC_MANUFACTURER_EMBEDDING_DATE[2] = {0x9F, 0x68}; //!< CPLC ICC manufacturer, embedding date.
static const BYTE OPSP_GET_DATA_CPLC_MODULE_FABRICATOR_PACKAGING_DATE[2] = {0x9F, 0x69}; //!< CPLC module fabricator, module packaging date.
static const BYTE OPSP_GET_DATA_CPLC_FABRICATION_DATE_SERIAL_NUMBER_BATCH_IDENTIFIER[2] = {0x9F, 0x6A}; //!< CPLC fabrication date, serail number, batch identifier.
static const BYTE OPSP_GET_DATA_CPLC_WHOLE_CPLC[2] = {0x9F, 0x7F}; //!< Whole CPLC data from ROM and EEPROM.

static const BYTE OPSP_GET_DATA_FCI_DATA[2] = {0xBF, 0x0C}; //!< File Control Information (FCI) discretionary data.

static const BYTE OPSP_GET_DATA_PROTOCOL[2] = {0xDF, 0x70}; //!< Data for protocol change.
static const BYTE OPSP_GET_DATA_ATR_HISTRORICAL_BYTES[2] = {0xDF, 0x71}; //!< Change ATR historical bytes.

static const BYTE OPSP_GET_DATA_EF_PROD_DATA_INITIALIZATION_FINGERPRINT[2] = {0xDF, 0x76}; //!< EF<sub>prod</sub> data initialization fingerprint.
static const BYTE OPSP_GET_DATA_EF_PROD_DATA_INITIALIZATION_DATA[2] = {0xDF, 0x77}; //!< EF<sub>prod</sub> data initialization data.
static const BYTE OPSP_GET_DATA_EF_PROD_DATA_PRODUCTION_KEY_INDEX[2] = {0xDF, 0x78}; //!< EF<sub>prod</sub> data production key index.
static const BYTE OPSP_GET_DATA_EF_PROD_DATA_PROTOCOL_VERSION[2] = {0xDF, 0x79}; //!< EF<sub>prod</sub> data protocol version.
static const BYTE OPSP_GET_DATA_EF_PROD_DATA_CHECKSUM[2] = {0xDF, 0x7A}; //!< EF<sub>prod</sub> data checksum.
static const BYTE OPSP_GET_DATA_EF_PROD_DATA_SOFTWARE_VERSION[2] = {0xDF, 0x7B}; //!< EF<sub>prod</sub> data software version.
static const BYTE OPSP_GET_DATA_EF_PROD_DATA_RFU[2] = {0xDF, 0x7C}; //!< EF<sub>prod</sub> data RFU.
static const BYTE OPSP_GET_DATA_EF_PROD_DATA_PROFILE_WITH_PROFILE_VERSION[2] = {0xDF, 0x7D}; //!< EF<sub>prod</sub> data profile with profile version.
static const BYTE OPSP_GET_DATA_EF_PROD_DATA_LOCATION_MACHINE_DATE_TIME[2] = {0xDF, 0x7E}; //!< EF<sub>prod</sub> data location, machine number, date, time.

static const BYTE OPSP_GET_DATA_WHOLE_EF_PROD[2] = {0xDF, 0x7F}; //!< Whole EF<sub>prod</sub> data block (39 Byte).




/**
 * The security information negotiated at mutual_authentication().
 */
typedef struct {
	BYTE security_level; //!< The security level.
	BYTE session_mac_key[16]; //!< The MAC session key.
	BYTE session_enc_key[16]; //!< The ENC session key.
	BYTE last_mac[8]; //!< The last computed mac.
} OPSP_SECURITY_INFO;


/**
 * A structure describing a Load File Data Block DAP block according to the Open Platform specification 2.0.1'.
 * The structure comprises 3 Tag Length Value (TLV) fields after the ASN.1 specification.
 * The outer tag 0xE2 contains the two inner tags.
 */
typedef struct {
	BYTE DAPBlockLength; //!< DEPRECATED. Ignore this. The length of the DAP block. The length of all following fields.
	BYTE securityDomainAIDLength; //!< The length of the Security Domain.
	BYTE securityDomainAID[16]; //!< The AID of the Security Domain.
	BYTE signatureLength; //!< The length of the signature. Can be 8 for a 3DES signature or 128 for a RSA signature.
	BYTE signature[128]; //!< The signature.
} OPSP_DAP_BLOCK, OPSP_RSA_DAP_BLOCK, OPSP_3DES_DAP_BLOCK;




/**
 * A structure returned in DELETE, LOAD, INSTALL[for load], INSTALL[for install] with delegated management.
 */
typedef struct {
	BYTE receiptLength; //!< The length of the receipt DAP.
	BYTE receipt[8]; //!< The receipt DAP.
	BYTE confirmationCounterLength; //!< Length of the confirmation counter buffer.
	BYTE confirmationCounter[2]; //!< The confirmation counter buffer.
	BYTE cardUniqueDataLength; //!< The length of the card unique data buffer.
	BYTE cardUniqueData[10]; //!< Card unique data buffer.
} OPSP_RECEIPT_DATA;




/**
 * A structure containing key information. Key set version, key index, key type and key length.
 */
typedef struct {
	BYTE keySetVersion; //!< The key set version.
	BYTE keyIndex; //!< The key index.
	BYTE keyType; //!< The key type.
	BYTE keyLength; //!< The key length.
} OPSP_KEY_INFORMATION;



/**
 * A structure describing an AID.
 */
typedef struct {
	BYTE AIDLength; //!< The length of the AID.
	BYTE AID[16]; //!< The AID.
} OPSP_AID;



/**
 * The structure containing Card Manager, package and application life cycle states and privileges returned by get_status().
 */
typedef struct {
	BYTE AIDLength; //!< The length of the AID.
	BYTE AID[16]; //!< The AID.
	BYTE lifeCycleState; //!< The Card Manager, package or application life cycle state.
	BYTE privileges; //!< The Card Manager or applet privileges.
} OPSP_APPLICATION_DATA;






/**
 * The card information returned by a card_connect().
 */
typedef struct {
	/**
	 * The mechanical state of the card:
	 *	- OPSP_CARD_ABSENT There is no card in the reader.
	 *	- OPSP_CARD_PRESENT There is a card in the reader, but it has not been moved into position for use.
	 *	- OPSP_CARD_SWALLOWED There is a card in the reader in position for use. The card is not powered.
	 *	- OPSP_CARD_POWERED Power is being provided to the card, but the reader driver is unaware of the mode of the card.
	 *	- OPSP_CARD_NEGOTIABLE The card has been reset and is awaiting PTS negotiation.
	 *	- OPSP_CARD_SPECIFIC The card has been reset and specific communication protocols have been established.
	 *.
	 */
	DWORD state;
	DWORD protocol; //!< The card protocol T0 or T1.
	BYTE ATR[32]; //!< The Answer To Reset from the card.
	DWORD ATRLength;
} OPSP_CARD_INFO;





#define OPSP_CARD_PROTOCOL_T0 SCARD_PROTOCOL_T0 //!< The protocol T0.
#define OPSP_CARD_PROTOCOL_T1 SCARD_PROTOCOL_T1 //!< The protocol T1.





// Mapping of system errors to error codes.
#ifdef _WIN32
#define OPSP_ERROR_SUCCESS ERROR_SUCCESS //!< No error occured.
#define OPSP_ERROR_READ ERROR_READ_FAULT //!< Read error.
#define OPSP_ERROR_BAD_FILE_DESCRIPTOR ERROR_INVALID_HANDLE //!< Bad file descriptor.
#define OPSP_ERROR_FILE_NOT_FOUND ERROR_FILE_NOT_FOUND //!< File not found.
#define OPSP_ERROR_NOMEM ERROR_NOT_ENOUGH_MEMORY //!< No memory.
#else
#define OPSP_ERROR_SUCCESS 0 //!< No error occured.
#define OPSP_ERROR_READ EIO //!< Read error.
#define OPSP_ERROR_BAD_FILE_DESCRIPTOR EBADF //!< Bad file descriptor.
#define OPSP_ERROR_FILE_NOT_FOUND ENOENT //!< File not found.
#define OPSP_ERROR_NOMEM ENOMEM //!< No memory.
#endif


// Self defined errors.
#define OPSP_ERROR_UNRECOGNIZED_APDU_COMMAND ((DWORD)0x80301000L) //!< A APDU command can't be recognized as a valid T=0 protocol Case 1-4 ISO7816-4 APDU
#define OPSP_ERROR_CARD_CRYPTOGRAM_VERIFICATION ((DWORD)0x80302000L) //!< The verification of the card cryptogram failed.
#define OPSP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE ((DWORD)0x80303000L) //!< The command data is too large for secure messaging.
#define OPSP_ERROR_COMMAND_TOO_LARGE ((DWORD)0x80303001L) //!< The command data is too large.
#define OPSP_ERROR_INSUFFICIENT_BUFFER ((DWORD)0x80304000L) //!< A used buffer is too small.
#define OPSP_ERROR_MORE_APPLICATION_DATA ((DWORD)0x80305000L) //!< More Card Manager, package or application data is available.
#define OPSP_ERROR_WRONG_TRY_LIMIT ((DWORD)0x80306000L) //!< Wrong maximum try limit.
#define OPSP_ERROR_WRONG_PIN_LENGTH ((DWORD)0x80307000L) //!< Wrong PIN length.
#define OPSP_ERROR_WRONG_KEY_VERSION ((DWORD)0x80308000L) //!< Wrong key version.
#define OPSP_ERROR_WRONG_KEY_INDEX ((DWORD)0x80309000L) //!< Wrong key index.
#define OPSP_ERROR_WRONG_KEY_TYPE ((DWORD)0x8030A000L) //!< Wrong key type.
#define OPSP_ERROR_KEY_CHECK_VALUE ((DWORD)0x8030B000L) //!< Key check value reported does not match.
#define OPSP_ERROR_INVALID_COMBINATION_KEY_SET_VERSION_KEY_INDEX ((DWORD)0x8030C000L) //!< The combination of key set version and key index is invalid.
#define OPSP_ERROR_MORE_KEY_INFORMATION_TEMPLATES ((DWORD)0x8030D000L) //!< More key information templates are available.
#define OPSP_ERROR_APPLICATION_TOO_BIG ((DWORD)0x8030E000L) //!< The application to load must be less than 32535 bytes.
#define OPSP_ERROR_VALIDATION_FAILED ((DWORD)0x8030F000L) //!< A validation has failed.
#define OPSP_ERROR_INVALID_FILENAME ((DWORD)0x8030F001L) //!< A file name is invalid.
#define OPSP_ERROR_INVALID_PASSWORD ((DWORD)0x8030F002L) //!< A password is invalid.
#define OPSP_ERROR_WRONG_EXPONENT ((DWORD)0x8030F003L) //!< The exponent must be 3 or 65537.
#define OPSP_ERROR_LOAD_FILE_DAP_NULL ((DWORD)0x8030F004L) //!< The Load File DAP is <code>NULL</code>.

// Mapping of relevant WinSCard API errors to error codes.
#define OPSP_CARD_E_CANCELLED SCARD_E_CANCELLED //!< The action was canceled by an SCardCancel request.
#define OPSP_CARD_E_CANT_DISPOSE SCARD_E_CANT_DISPOSE //!< The system could not dispose of the media in the requested manner.
#define OPSP_CARD_E_CARD_UNSUPPORTED SCARD_E_CARD_UNSUPPORTED //!< The smart card does not meet minimal requirements for support.
#define OPSP_CARD_E_COMM_DATA_LOST SCARD_E_COMM_DATA_LOST //!< A communications error with the smart card has been detected.
#define OPSP_CARD_E_DUPLICATE_READER SCARD_E_DUPLICATE_READER //!< The reader driver did not produce a unique reader name.
#define OPSP_CARD_E_INSUFFICIENT_BUFFER SCARD_E_INSUFFICIENT_BUFFER //!< The data buffer for returned data is too small for the returned data.
#define OPSP_CARD_E_INVALID_ATR SCARD_E_INVALID_ATR //!< An ATR string obtained from the registry is not a valid ATR string.
#define OPSP_CARD_E_INVALID_HANDLE SCARD_E_INVALID_HANDLE //!< The supplied handle was invalid.
#define OPSP_CARD_E_INVALID_PARAMETER SCARD_E_INVALID_PARAMETER //!< One or more of the supplied parameters could not be properly interpreted.
#define OPSP_CARD_E_INVALID_TARGET SCARD_E_INVALID_TARGET //!< Registry startup information is missing or invalid.
#define OPSP_CARD_E_INVALID_VALUE SCARD_E_INVALID_VALUE //!< One or more of the supplied parameter values could not be properly interpreted.
#define OPSP_CARD_E_NO_MEMORY SCARD_E_NO_MEMORY //!< Not enough memory available to complete this command.
#define OPSP_CARD_E_NO_READERS_AVAILABLE SCARD_E_NO_READERS_AVAILABLE //!< No smart card reader is available.
#define OPSP_CARD_E_NO_SERVICE SCARD_E_NO_SERVICE //!< The smart card resource manager is not running.
#define OPSP_CARD_E_NO_SMARTCARD SCARD_E_NO_SMARTCARD //!< The operation requires a smart card, but no smart card is currently in the device.
#define OPSP_CARD_E_NOT_READY SCARD_E_NOT_READY //!< The reader or card is not ready to accept commands.
#define OPSP_CARD_E_NOT_TRANSACTED SCARD_E_NOT_TRANSACTED //!< An attempt was made to end a non-existent transaction.
#define OPSP_CARD_E_PCI_TOO_SMALL SCARD_E_PCI_TOO_SMALL //!< The PCI receive buffer was too small.
#define OPSP_CARD_E_PROTO_MISMATCH SCARD_E_PROTO_MISMATCH //!< The requested protocols are incompatible with the protocol currently in use with the card.
#define OPSP_CARD_E_READER_UNAVAILABLE SCARD_E_READER_UNAVAILABLE //!< The specified reader is not currently available for use.
#define OPSP_CARD_E_READER_UNSUPPORTED SCARD_E_READER_UNSUPPORTED //!< The reader driver does not meet minimal requirements for support.
#define OPSP_CARD_E_SERVICE_STOPPED SCARD_E_SERVICE_STOPPED //!< The smart card resource manager has shut down.
#define OPSP_CARD_E_SHARING_VIOLATION SCARD_E_SHARING_VIOLATION //!< The smart card cannot be accessed because of other outstanding connections.
#define OPSP_CARD_E_SYSTEM_CANCELLED SCARD_E_SYSTEM_CANCELLED //!< The action was canceled by the system, presumably to log off or shut down.
#define OPSP_CARD_E_TIMEOUT SCARD_E_TIMEOUT //!< The user-specified timeout value has expired.
#define OPSP_CARD_E_UNEXPECTED SCARD_E_UNEXPECTED //!< An unexpected card error has occurred.
#define OPSP_CARD_E_UNKNOWN_CARD SCARD_E_UNKNOWN_CARD //!< The specified smart card name is not recognized.
#define OPSP_CARD_E_UNKNOWN_READER SCARD_E_UNKNOWN_READER //!< The specified reader name is not recognized.
#define OPSP_CARD_E_UNSUPPORTED_FEATURE SCARD_E_UNSUPPORTED_FEATURE //!< This smart card does not support the requested feature.
#define OPSP_CARD_F_COMM_ERROR SCARD_F_COMM_ERROR //!< An internal communications error has been detected.
#define OPSP_CARD_F_INTERNAL_ERROR SCARD_F_INTERNAL_ERROR //!< An internal consistency check failed.
#define OPSP_CARD_F_UNKNOWN_ERROR SCARD_F_UNKNOWN_ERROR //!< An internal error has been detected, but the source is unknown.
#define OPSP_CARD_F_WAITED_TOO_LONG SCARD_F_WAITED_TOO_LONG //!< An internal consistency timer has expired.
#define OPSP_CARD_S_SUCCESS SCARD_S_SUCCESS //!< No error was encountered.
#define OPSP_CARD_W_CANCELLED_BY_USER SCARD_W_CANCELLED_BY_USER //!< The action was canceled by the user.
#define OPSP_CARD_W_REMOVED_CARD SCARD_W_REMOVED_CARD //!< The smart card has been removed, so that further communication is not possible.
#define OPSP_CARD_W_RESET_CARD SCARD_W_RESET_CARD //!< The smart card has been reset, so any shared state information is invalid.
#define OPSP_CARD_W_UNPOWERED_CARD SCARD_W_UNPOWERED_CARD //!< Power has been removed from the smart card, so that further communication is not possible.
#define OPSP_CARD_W_UNRESPONSIVE_CARD SCARD_W_UNRESPONSIVE_CARD //!< The smart card is not responding to a reset.
#define OPSP_CARD_W_UNSUPPORTED_CARD SCARD_W_UNSUPPORTED_CARD //!< The reader cannot communicate with the card, due to ATR string configuration conflicts.

// Mapping of ISO7816-4 / Open Platform 2.0.1' errors to error codes.
// 0x8020XXXX is the generell meaning error.
// 0x802YXXXX is a special meaning for a use case.

#define OPSP_ISO7816_ERROR_PREFIX ((DWORD)0x80200000L) //!< Error prefix for all ISO7816 errors.

//
// Normal processing
//

#define OPSP_ISO7816_ERROR_RESPONSE_LENGTH (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6100L) //!< Response bytes available indicated the last 2 Bytes.

// State of non-volatile memory unchanged
#define OPSP_ISO7816_ERROR_FILE_INVALIDATED (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6283L) //!< Selected file invalidated.
#define OPSP_ISO7816_WARNING_CM_LOCKED (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x16283L) //!< Card life cycle is CM_LOCKED.

#define OPSP_ISO7816_ERROR_FILE_TERMINATED (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6285L) //!< SELECT FILE Warning: selected file is terminated.

// State of non-volatile memory changed
#define OPSP_ISO7816_ERROR_6300 (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6300L) //!< No information given.
#define OPSP_ISO7816_ERROR_HOST_CRYPTOGRAM_VERIFICATION (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x16300L) //!< Authentication of host cryptogram failed.

#define OPSP_ISO7816_ERROR_MORE_DATA_AVAILABLE (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6310L) //!< More data available.

//
// Execution errors
//

#define OPSP_ISO7816_ERROR_NOTHING_SPECIFIC (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6400L) //!< No specific diagnosis.
#define OPSP_ISO7816_ERROR_MEMORY_FAILURE (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6581L) //!< Memory failure or EDC check failed.

#define OPSP_ISO7816_ERROR_WRONG_LENGTH (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6700L) //!< Wrong length.

#define OPSP_ISO7816_ERROR_CHANNEL_NOT_SUPPORTED (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6881L) //!< Function not supported - Logical channel not supported/open.
#define OPSP_ISO7816_ERROR_SECURE_MESSAGING_NOT_SUPPORTED (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6882L) //!< Function not supported - Secure messaging not supported.

// Command not allowed class.
#define OPSP_ISO7816_ERROR_CONDITIONS_NOT_SATISFIED (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6985L) //!< Command not allowed - Conditions of use not satisfied.
#define OPSP_ISO7816_ERROR_NOT_MULTI_SELECTABLE (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x16985L) //!< The applet to be selected is not multi-selectable, but its context is already active.

#define OPSP_ISO7816_ERROR_SECURITY_STATUS_NOT_SATISFIED (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6982L) //!< Command not allowed - Security status not satisfied.

#define OPSP_ISO7816_ERROR_6999 (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6999L)
#define OPSP_ISO7816_ERROR_SELECTION_REJECTED (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x16999L) //!< The applet to be selected rejects selection or throws an exception.

// Wrong parameter(s) P1-P2 class.
#define OPSP_ISO7816_ERROR_WRONG_DATA (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6A80L) //!< Wrong data / Incorrect values in command data.
#define OPSP_ISO7816_ERROR_WRONG_GLOBAL_PIN_FORMAT (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x16A80L) //!< Wrong format for global PIN.

#define OPSP_ISO7816_ERROR_FUNC_NOT_SUPPORTED (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6A81L) //!< Function not supported.
#define OPSP_ISO7816_ERROR_APPLET_NOT_SELECTABLE (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x16A81L) //!< Card life cycle is CM_LOCKED or selected application was not in a selectable state.

#define OPSP_ISO7816_ERROR_FILE_NOT_FOUND (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6A82L) // !< File not found.
#define OPSP_ISO7816_ERROR_APPLET_NOT_FOUND (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x16A82L) //!< The applet to be selected could not be found.

#define OPSP_ISO7816_ERROR_NOT_ENOUGH_MEMORY (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6A84L) //!< Not enough memory space.

#define OPSP_ISO7816_ERROR_INCORRECT_P1P2 (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6A86L) //!< Incorrect parameters (P1, P2).
#define OPSP_ISO7816_ERROR_WRONG_PIN_TRY_LIMIT (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x16A86L) //!< Wrong parameter P2 (PIN try limit).

#define OPSP_ISO7816_ERROR_DATA_NOT_FOUND (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6A88L) //!< Referenced data not found.

#define OPSP_ISO7816_ERROR_WRONG_P1P2 (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6B00L) //!< Wrong parameters (P1, P2).
#define OPSP_ISO7816_ERROR_CORRECT_LENGTH (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6C00L) //!< Correct expected length (Le) indicated by last 2 Bytes.
#define OPSP_ISO7816_ERROR_INVALID_INS (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6D00L) //!< Invalid instruction byte / Command not supported or invalid.
#define OPSP_ISO7816_ERROR_WRONG_CLA (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6E00L) //!< Wrong CLA byte.

#define OPSP_ISO7816_ERROR_ILLEGAL_PARAMETER (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x6F74L) //!< Illegal parameter.

#define OPSP_ISO7816_ERROR_ALGORITHM_NOT_SUPPORTED (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x9484L) //!< Algorithm not supported.
#define OPSP_ISO7816_ERROR_INVALID_KEY_CHECK_VALUE (OPSP_ISO7816_ERROR_PREFIX | (DWORD)0x9485L) //!< Invalid key check value.

/**
 * General error code for OpenSSL.
 * There is no comprehensive list.
 * The last OpenSSL error code can be obtained with a call to get_last_OpenSSL_error_code(),
 * a string representation of the last OpenSSL error as usual by a call to stringify_error().
 */
#define OPSP_OPENSSL_ERROR ((DWORD)0x80400000L) //!< OpenSSL error.

//! \brief Returns the last OpenSSL error code.
OPSP_API
unsigned long get_last_OpenSSL_error_code(void);

//! \brief This function establishes a context to the PC/SC resource manager.
OPSP_API
LONG establish_context(OPSP_CARDCONTEXT *cardContext);

//! \brief This function releases the context to the PC/SC resource manager established by establish_context().
OPSP_API
LONG release_context(OPSP_CARDCONTEXT cardContext);

//! \brief This function returns a list of currently available readers on the system.
OPSP_API
LONG list_readers(OPSP_CARDCONTEXT cardContext, OPSP_STRING readerNames, PDWORD readerNamesLength);

//! \brief This function connects to a reader on the system.
OPSP_API
LONG card_connect(OPSP_CARDCONTEXT cardContext, OPSP_CSTRING readerName, OPSP_CARDHANDLE *cardHandle, DWORD protocol);

//! \brief This function disconnects a reader on the system.
OPSP_API
LONG card_disconnect(OPSP_CARDHANDLE cardHandle);

//! \brief Open Platform: Selects an application on a card by AID.
OPSP_API
LONG select_application(OPSP_CARDHANDLE cardHandle, OPSP_CARD_INFO cardInfo, PBYTE AID, DWORD AIDLength);

//! \brief Open Platform: Gets the life cycle status of Applications, the Card Manager and Executable Load Files and their privileges.
OPSP_API
LONG get_status(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo, BYTE cardElement, OPSP_APPLICATION_DATA *applData, PDWORD applDataLength);

//! \brief Open Platform: Sets the life cycle status of Applications, Security Domains or the Card Manager.
OPSP_API
LONG set_status(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo, BYTE cardElement, PBYTE AID, DWORD AIDLength, BYTE lifeCycleState);

//! \brief Formats an error code to a human readable string.
OPSP_API
OPSP_STRING stringify_error(DWORD errorCode);

//! \brief Retrieves the card status.
OPSP_API
LONG get_card_status(OPSP_CARDHANDLE cardHandle, OPSP_CARD_INFO *cardInfo);

//! \brief Open Platform: Mutual authentication.
OPSP_API
LONG mutual_authentication(OPSP_CARDHANDLE cardHandle, BYTE enc_key[16], BYTE mac_key[16], BYTE keySetVersion,
						   BYTE keyIndex, OPSP_CARD_INFO cardInfo, BYTE securityLevel,
						   OPSP_SECURITY_INFO *secInfo);

//! \brief Open Platform: Retrieve card data.
OPSP_API
LONG get_data(OPSP_CARDHANDLE cardHandle, BYTE identifier[2], PBYTE recvBuffer, PDWORD recvBufferLength,
			  OPSP_CARD_INFO cardInfo, OPSP_SECURITY_INFO *secInfo);

//! \brief Open Platform: Put card data.
OPSP_API
LONG put_data(OPSP_CARDHANDLE cardHandle, BYTE identifier[2], PBYTE dataObject, DWORD dataObjectLength,
			  OPSP_CARD_INFO cardInfo, OPSP_SECURITY_INFO *secInfo);

//! \brief Open Platform: Changes or unblocks the global PIN.
OPSP_API
LONG pin_change(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo,
				BYTE tryLimit, PBYTE newPIN, DWORD newPINLength, BYTE kek_key[16]);

//! \brief Open Platform: replaces a single 3DES key in a key set or adds a new 3DES key.
OPSP_API
LONG put_3des_key(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo,
				  BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, BYTE _3des_key[16],
				  BYTE kek_key[16]);

//! \brief Open Platform: replaces a single public RSA key in a key set or adds a new public RSA key.
OPSP_API
LONG put_rsa_key(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo,
				 BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, OPSP_STRING PEMKeyFileName, char *passPhrase);

//! \brief Open Platform: replaces or adds a secure channel key set consisting of encryption key, MAC key and key encryption.
OPSP_API
LONG put_secure_channel_keys(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo,
							 OPSP_CARD_INFO cardInfo, BYTE keySetVersion, BYTE newKeySetVersion,
							 BYTE new_enc_key[16], BYTE new_mac_key[16], BYTE new_kek_key[16], BYTE kek_key[16]);

//! \brief Open Platform: deletes a key or multiple keys.
OPSP_API
LONG delete_key(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo,
				BYTE keySetVersion, BYTE keyIndex);

//! \brief Open Platform: Retrieves key information of keys on the card.
OPSP_API
LONG get_key_information_templates(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo,
								   OPSP_CARD_INFO cardInfo, BYTE keyInformationTemplate,
								   OPSP_KEY_INFORMATION *keyInformation, PDWORD keyInformationLength);

//! \brief Open Platform: Deletes a package or an applet.
OPSP_API
LONG delete_applet(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo,
				   OPSP_AID *AIDs, DWORD AIDsLength,
				   OPSP_RECEIPT_DATA **receiptData, PDWORD receiptDataLength);

//! \brief Open Platform: Prepares the card for loading an applet.
OPSP_API
LONG install_for_load(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo,
					  PBYTE packageAID, DWORD packageAIDLength, PBYTE securityDomainAID,
					  DWORD securityDomainAIDLength, BYTE loadFileDAP[20], BYTE loadToken[128],
					  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
					  DWORD nonVolatileDataSpaceLimit);

//! \brief Open Platform: Function to retrieve the data to sign by the Card Issuer in a Load Token.
OPSP_API
LONG get_load_token_signature_data(PBYTE packageAID, DWORD packageAIDLength,
								   PBYTE securityDomainAID, DWORD securityDomainAIDLength,
								   BYTE loadFileDAP[20], DWORD nonVolatileCodeSpaceLimit,
								   DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
								   PBYTE loadTokenSignatureData, PDWORD loadTokenSignatureDataLength);

//! \brief Open Platform: Function to retrieve the data to sign by the Card Issuer in an Install Token.
OPSP_API
LONG get_install_token_signature_data(BYTE P1, PBYTE packageAID, DWORD packageAIDLength,
									  PBYTE appletClassAID, DWORD appletClassAIDLength,
									  PBYTE appletInstanceAID, DWORD appletInstanceAIDLength,
									  BYTE appletPrivileges, DWORD volatileDataSpaceLimit,
									  DWORD nonVolatileDataSpaceLimit, PBYTE appletInstallParameters,
									  DWORD appletInstallParametersLength, PBYTE installTokenSignatureData,
									  PDWORD installTokenSignatureDataLength);

//! \brief Open Platform: Calculates a Load Token using PKCS#1.
OPSP_API
LONG calculate_load_token(PBYTE packageAID, DWORD packageAIDLength, PBYTE securityDomainAID,
						  DWORD securityDomainAIDLength, BYTE loadFileDAP[20],
						  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
						  DWORD nonVolatileDataSpaceLimit, BYTE loadToken[128],
						  OPSP_STRING PEMKeyFileName, char *passPhrase);

//! \brief Open Platform: Calculates an Install Token using PKCS#1.
OPSP_API
LONG calculate_install_token(BYTE P1, PBYTE packageAID, DWORD packageAIDLength, PBYTE appletClassAID,
							 DWORD appletClassAIDLength, PBYTE appletInstanceAID,
							 DWORD appletInstanceAIDLength, BYTE appletPrivileges,
							 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
							 PBYTE appletInstallParameters, DWORD appletInstallParametersLength,
							 BYTE installToken[128], OPSP_STRING PEMKeyFileName, char *passPhrase);

//! \brief Open Platform: Calculates a Load File DAP.
OPSP_API
LONG calculate_load_file_DAP(OPSP_DAP_BLOCK *dapBlock, DWORD dapBlockLength,
							 OPSP_STRING CAPFileName, unsigned char hash[20]);

//! \brief Open Platform: Loads a package (containing an applet) to the card.
OPSP_API
LONG load_applet(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo,
				 OPSP_DAP_BLOCK *dapBlock, DWORD dapBlockLength, OPSP_STRING CAPFileName,
				 OPSP_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief Open Platform: Installs an applet on the card.
OPSP_API
LONG install_for_install(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo,
						 PBYTE packageAID, DWORD packageAIDLength, PBYTE appletClassAID,
						 DWORD appletClassAIDLength, PBYTE appletInstanceAID, DWORD appletInstanceAIDLength,
						 BYTE appletPrivileges, DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE appletInstallParameters, DWORD appletInstallParametersLength,
						 BYTE installToken[128], OPSP_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief Open Platform: Makes an installed applet selectable.
OPSP_API
LONG install_for_make_selectable(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo,
								 OPSP_CARD_INFO cardInfo,
								 PBYTE appletInstanceAID, DWORD appletInstanceAIDLength,
								 BYTE appletPrivileges, BYTE installToken[128],
								 OPSP_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief Open Platform: Installs and makes an installed applet selectable.
OPSP_API
LONG install_for_install_and_make_selectable(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo,
						 PBYTE packageAID, DWORD packageAIDLength, PBYTE appletClassAID,
						 DWORD appletClassAIDLength, PBYTE appletInstanceAID,
						 DWORD appletInstanceAIDLength, BYTE appletPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE appletInstallParameters, DWORD appletInstallParametersLength,
						 BYTE installToken[128], OPSP_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief Open Platform: Adds a key set for Delegated Management.
OPSP_API
LONG put_delegated_management_keys(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo,
								   OPSP_CARD_INFO cardInfo, BYTE keySetVersion,
								   BYTE newKeySetVersion,
								   OPSP_STRING PEMKeyFileName, char *passPhrase,
								   BYTE receipt_generation_key[16], BYTE kek_key[16]);

//! \brief Sends an application protocol data unit.
OPSP_API
LONG send_APDU(OPSP_CARDHANDLE cardHandle, PBYTE capdu, DWORD capduLength, PBYTE rapdu,
			   PDWORD rapduLength, OPSP_CARD_INFO cardInfo, OPSP_SECURITY_INFO *secInfo);

//! \brief Open Platform: Calculates a Load File Data Block DAP using 3DES.
OPSP_API
LONG calculate_3des_DAP(PBYTE securityDomainAID, DWORD securityDomainAIDLength, OPSP_STRING CAPFileName,
						BYTE DAP_verification_key[16], OPSP_DAP_BLOCK *dapBlock);

//! \brief Open Platform: Calculates a Load File Data Block DAP using SHA-1 and PKCS#1 (RSA).
OPSP_API
LONG calculate_rsa_DAP(PBYTE securityDomainAID, DWORD securityDomainAIDLength, OPSP_STRING CAPFileName,
					   OPSP_STRING PEMKeyFileName, char *passPhrase, OPSP_DAP_BLOCK *dapBlock);

//! \brief Open Platform: Validates a Load Receipt.
OPSP_API
LONG validate_delete_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receipt_generation_key[16], OPSP_RECEIPT_DATA receiptData,
						   PBYTE AID, DWORD AIDLength);

//! \brief Open Platform: Validates an Install Receipt.
OPSP_API
LONG validate_install_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receipt_generation_key[16], OPSP_RECEIPT_DATA receiptData,
						   PBYTE packageAID, DWORD packageAIDLength,
						   PBYTE appletInstanceAID, DWORD appletInstanceAIDLength);

//! \brief Open Platform: Validates a Load Receipt.
OPSP_API
LONG validate_load_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receipt_generation_key[16], OPSP_RECEIPT_DATA receiptData,
						   PBYTE packageAID, DWORD packageAIDLength,
						   PBYTE securityDomainAID, DWORD securityDomainAIDLength);

#ifdef __cplusplus
}
#endif
