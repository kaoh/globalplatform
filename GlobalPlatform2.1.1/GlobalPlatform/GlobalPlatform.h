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
#ifdef GP_EXPORTS
#define GP_API __declspec(dllexport)
#else
#define GP_API __declspec(dllimport)
#endif
#else
#define GP_API
#endif

#ifndef max
#define max(a,b) (((a)>(b))?(a):(b))
#endif

#include <winscard.h>
#include "unicode.h"

typedef SCARDCONTEXT GP_CARDCONTEXT; //!< Reference to the reader ressource manager.
typedef SCARDHANDLE GP_CARDHANDLE; //!< Reference to a card.
typedef LPTSTR GP_STRING; //!< A Microsoft/Muscle PC/SC LPTSTR.
typedef LPCTSTR GP_CSTRING; //!< A Microsoft/Muscle PC/SC LPCTSTR.
typedef LPBYTE PBYTE; //!< A Microsoft/Muscle PC/SC LPBYTE, pointer to unsigned char.
#ifdef _WIN32
typedef LPDWORD PDWORD; //!< A Microsoft LPDWORD/Muscle PC/SC, a pointer to a double word, pointer to unsigned long.
#endif

/* The default key value for new cards defined in a VISA specification. */
static const BYTE GP_VISA_DEFAULT_KEY[] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};

/* Secure Channel stuff */

static const BYTE GP_SCP01 = 0x01; //!< Secure Channel Protocol '01'
static const BYTE GP_SCP02 = 0x02; //!< Secure Channel Protocol '02'

/** Secure Channel Protocol '01': "i" = '05': Initiation mode explicit, C-MAC on modified APDU, 
  * ICV set to zero, no ICV encryption, 3 Secure Channel Keys
  */
static const BYTE GP_SCP01_IMPL_i05 = 0x05; 
/** Secure Channel Protocol '01': "i" = '15': Initiation mode explicit, C-MAC on modified APDU, 
  * ICV set to zero, ICV encryption, 3 Secure Channel Keys
  */
static const BYTE GP_SCP01_IMPL_i15 = 0x15;

/** Secure Channel Protocol '02': "i" = '04': Initiation mode explicit, C-MAC on modified APDU, 
  * ICV set to zero, no ICV encryption, 1 Secure Channel base key 
  */
static const BYTE GP_SCP02_IMPL_i04 = 0x04;
/** Secure Channel Protocol '02': "i" = '05': Initiation mode explicit, C-MAC on modified APDU, 
  * ICV set to zero, no ICV encryption, 3 Secure Channel Keys 
  */
static const BYTE GP_SCP02_IMPL_i05 = 0x05;
/** Secure Channel Protocol '02': "i" = '0A': Initiation mode implicit, C-MAC on unmodified APDU, 
  *ICV set to MAC over AID, no ICV encryption, 1 Secure Channel base key 
  */
static const BYTE GP_SCP02_IMPL_i0A = 0x0A;
/** Secure Channel Protocol '02': "i" = '0B': Initiation mode implicit, C-MAC on unmodified APDU, 
  * ICV set to MAC over AID, no ICV encryption, 3 Secure Channel Keys 
  */
static const BYTE GP_SCP02_IMPL_i0B = 0x0B;
/** Secure Channel Protocol '02': "i" = '14': Initiation mode explicit, C-MAC on modified APDU, 
  * ICV set to zero, ICV encryption for CMAC session, 1 Secure Channel base key
  */
static const BYTE GP_SCP02_IMPL_i14 = 0x14;
/** Secure Channel Protocol '02': "i" = '15': Initiation mode explicit, C-MAC on modified APDU, 
  *ICV set to zero, ICV encryption for CMAC session, 3 Secure Channel Keys
  */
static const BYTE GP_SCP02_IMPL_i15 = 0x15;
/** Secure Channel Protocol '02': "i" = '1A': Initiation mode implicit, C-MAC on unmodified APDU, 
  * ICV set to MAC over AID, ICV encryption for C-MAC session, 1 Secure Channel base key
  */
static const BYTE GP_SCP02_IMPL_i1A = 0x1A;
/** Secure Channel Protocol '02': "i" = '1B': Initiation mode implicit, C-MAC on unmodified APDU, 
  *ICV set to MAC over AID, ICV encryption for C-MAC session, 3 Secure Channel Keys
  */
static const BYTE GP_SCP02_IMPL_i1B = 0x1B;


static const BYTE GP_SCP01_SECURITY_LEVEL_C_DEC_C_MAC = 0x03; //!< Secure Channel Protocol '01': C-DECRYPTION and C-MAC
static const BYTE GP_SCP01_SECURITY_LEVEL_C_MAC = 0x01;  //!< Secure Channel Protocol '01': C-MAC
static const BYTE GP_SCP01_SECURITY_LEVEL_NO_SECURE_MESSAGING = 0x00; //!< Secure Channel Protocol '01': No secure messaging expected.

static const BYTE GP_SCP02_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC = 0x13; //!< Secure Channel Protocol '02': C-DECRYPTION, C-MAC and R-MAC
static const BYTE GP_SCP02_SECURITY_LEVEL_C_MAC_R_MAC = 0x11; //!< Secure Channel Protocol '02': C-MAC and R-MAC
static const BYTE GP_SCP02_SECURITY_LEVEL_R_MAC = 0x10; //!< Secure Channel Protocol '02': R-MAC
static const BYTE GP_SCP02_SECURITY_LEVEL_C_DEC_C_MAC = 0x03; //!< Secure Channel Protocol '02': C-DECRYPTION and C-MAC
static const BYTE GP_SCP02_SECURITY_LEVEL_C_MAC = 0x01; //!< Secure Channel Protocol '02': C-MAC
static const BYTE GP_SCP02_SECURITY_LEVEL_NO_SECURE_MESSAGING = 0x00; //!< Secure Channel Protocol '02': No secure messaging expected.


static const BYTE GP_CARD_MANAGER_AID[] = {0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00}; //!< The AID of the Card Manager defined by GlobalPlatform specification.

static const BYTE GP_KEY_TYPE_RSA = 0xA1; //!< RSA key
static const BYTE GP_KEY_TYPE_3DES = 0x81; //!< 3DES key.
static const BYTE GP_LIFE_CYCLE_LOAD_FILE_LOADED = 0x01; //!< Executable Load File is loaded.
static const BYTE GP_LIFE_CYCLE_CARD_OP_READY = 0x01; //!< Card is OP ready.
static const BYTE GP_LIFE_CYCLE_CARD_INITIALIZED = 0x07; //!< Card is initialized.
static const BYTE GP_LIFE_CYCLE_CARD_SECURED = 0x0f; //!< Card is in secured state.
static const BYTE GP_LIFE_CYCLE_CARD_LOCKED = 0x7f; //!< Card is locked.
static const BYTE GP_LIFE_CYCLE_CARD_TERMINATED = 0xff; //!< Card is termonated.
static const BYTE GP_LIFE_CYCLE_APPLICATION_INSTALLED = 0x03; //!< Application is installed
static const BYTE GP_LIFE_CYCLE_APPLICATION_SELECTABLE = 0x07; //!< Application is selectable.
static const BYTE GP_LIFE_CYCLE_APPLICATION_LOCKED = 0xff; //!< Application is locked.
static const BYTE GP_LIFE_CYCLE_SECURITY_DOMAIN_INSTALLED = 0x03; //!< Application is installed
static const BYTE GP_LIFE_CYCLE_SECURITY_DOMAIN_SELECTABLE = 0x07; //!< Application is selectable.
static const BYTE GP_LIFE_CYCLE_SECURITY_DOMAIN_PERSONALIZED = 0xff; //!< Application is personalized.
static const BYTE GP_LIFE_CYCLE_SECURITY_DOMAIN_LOCKED = 0xff; //!< Application is locked.


/* consts for MANAGE CHANNEL */

static const BYTE GP_MANAGE_CHANNEL_OPEN = 0x00; //!< Open the next available Supplementary Logical Channel.
static const BYTE GP_MANAGE_CHANNEL_CLOSE = 0x80; //!< Close the Supplementary Logical Channel.


static const BYTE GP_APPLICATION_PRIVILEGE_SECURITY_DOMAIN = 0x80; //!< Application is security domain.
static const BYTE GP_APPLICATION_PRIVILEGE_DAP_VERIFICATION = 0x40; //!< Application can require DAP verification for loading and installating applications.
static const BYTE GP_APPLICATION_PRIVILEGE_DELEGATED_MANAGEMENT = 0x20; //!< Security domain has delegeted management right.
static const BYTE GP_APPLICATION_PRIVILEGE_CARD_MANAGER_LOCK_PRIVILEGE = 0x10; //!< Application can lock the Card Manager.
static const BYTE GP_APPLICATION_PRIVILEGE_CARD_MANAGER_TERMINATE_PRIVILEGE = 0x08; //!< Application can terminate the card.
static const BYTE GP_APPLICATION_PRIVILEGE_DEFAULT_SELECTED = 0x04; //!< Application is default selected.
static const BYTE GP_APPLICATION_PRIVILEGE_PIN_CHANGE_PRIVILEGE = 0x02; //!< Application can change global PIN.
static const BYTE GP_APPLICATION_PRIVILEGE_MANDATED_DAP_VERIFICATION = 0x01; //!< Security domain requires DAP verification for loading and installating applications.

static const BYTE GP_STATUS_APPLICATIONS = 0x40; //!< Indicate Applications or Security Domains in get_status() or set_status().
static const BYTE GP_STATUS_ISSUER_SECURITY_DOMAIN = 0x80; //!< Indicate Issuer Security Domain in get_status() or set_status().
static const BYTE GP_STATUS_LOAD_FILES = 0x20; //!< Request GP_APPLICATION_DATA for Executable Load Files in get_status().
static const BYTE GP_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES = 0x10; //!< Request GP_APPLICATION_DATA for Executable Load Files and their Executable Modules in get_status().





// Some card states.
static const DWORD GP_CARD_ABSENT = SCARD_ABSENT; //!< There is no card in the reader.
static const DWORD GP_CARD_PRESENT = SCARD_PRESENT; //!< There is a card in the reader, but it has not been moved into position for use.
static const DWORD GP_CARD_SWALLOWED = SCARD_SWALLOWED; //!< There is a card in the reader in position for use. The card is not powered.
static const DWORD GP_CARD_POWERED = SCARD_POWERED; //!< Power is being provided to the card, but the reader driver is unaware of the mode of the card.
static const DWORD GP_CARD_NEGOTIABLE = SCARD_NEGOTIABLE; //!< The card has been reset and is awaiting PTS negotiation.
static const DWORD GP_CARD_SPECIFIC = SCARD_SPECIFIC; //!< The card has been reset and specific communication protocols have been established.





// Some possible identifiers to retrieve card data with get_data() and put_data().

static const BYTE GP_GET_DATA_ISSUER_IDENTIFICATION_NUMBER[2] = {0x00, 0x42}; //!< Issuer Identification Number, if Card Manager selected.
static const BYTE GP_GET_DATA_APPLICATION_PROVIDER_IDENTIFICATION_NUMBER[2] = {0x00, 0x42}; //!< Application Provider Identification Number, if Security Domain selected.

static const BYTE GP_GET_DATA_CARD_IMAGE_NUMBER[2] = {0x00, 0x45}; //!< Card Image Number, if Card Manager selected.
static const BYTE GP_GET_DATA_SECURITY_DOMAIN_IMAGE_NUMBER[2] = {0x00, 0x45}; //!< Security Domain Image Number, if Security Domain selected.

static const BYTE GP_GET_DATA_CARD_MANAGER_AID[2] = {0x00, 0x4F}; //!< Change Card Manager AID, if Card Manager selected.
static const BYTE GP_GET_DATA_SECURITY_DOMAIN_AID[2] = {0x00, 0x4F}; //!< Change Security Domain AID, if Security Domain selected.

static const BYTE GP_GET_DATA_CARD_DATA[2] = {0x00, 0x66}; //!< Card Data.
static const BYTE GP_GET_DATA_SEQUENCE_COUNTER_DEFAULT_KEY_VERSION[2] = {0x00, 0xC1}; //!< Sequence Counter of the default Key Version Number.
static const BYTE GP_GET_DATA_CONFIRMATION_COUNTER[2] = {0x00, 0xC2}; //!< Confirmation Counter.
static const BYTE GP_GET_DATA_FREE_EEPROM_MEMORY_SPACE[2] = {0x00, 0xC6}; //!< Free EEPROM memory space.
static const BYTE GP_GET_DATA_FREE_COR_RAM[2] = {0x00, 0xC7}; //!< Free transient Clear on Reset memory space (COR RAM).
static const GP_BYTE_DIVERSIFICATION_DATA[2] = {0x00, 0xCF}; //!< Diversification data.

/**
 * Key Information Template of first 31 keys.
 * Next templates can be obtained with the tag 0x0x 0xE0, where x > 0.
 */
static const BYTE GP_GET_DATA_KEY_INFORMATION_TEMPLATE[2] = {0x00, 0xE0};

static const BYTE GP_GET_DATA_CPLC_PERSONALIZATION_DATE[2] = {0x9F, 0x66}; //!< CPLC personalization date.
static const BYTE GP_GET_DATA_CPLC_PRE_PERSONALIZATION_DATE[2] = {0x9F, 0x67}; //!< CPLC pre-personalization date.
static const BYTE GP_GET_DATA_CPLC_ICC_MANUFACTURER_EMBEDDING_DATE[2] = {0x9F, 0x68}; //!< CPLC ICC manufacturer, embedding date.
static const BYTE GP_GET_DATA_CPLC_MODULE_FABRICATOR_PACKAGING_DATE[2] = {0x9F, 0x69}; //!< CPLC module fabricator, module packaging date.
static const BYTE GP_GET_DATA_CPLC_FABRICATION_DATE_SERIAL_NUMBER_BATCH_IDENTIFIER[2] = {0x9F, 0x6A}; //!< CPLC fabrication date, serail number, batch identifier.
static const BYTE GP_GET_DATA_CPLC_WHOLE_CPLC[2] = {0x9F, 0x7F}; //!< Whole CPLC data from ROM and EEPROM.

static const BYTE GP_GET_DATA_FCI_DATA[2] = {0xBF, 0x0C}; //!< File Control Information (FCI) discretionary data.

static const BYTE GP_GET_DATA_PROTOCOL[2] = {0xDF, 0x70}; //!< Data for protocol change.
static const BYTE GP_GET_DATA_ATR_HISTRORICAL_BYTES[2] = {0xDF, 0x71}; //!< Change ATR historical bytes.

static const BYTE GP_GET_DATA_EF_PROD_DATA_INITIALIZATION_FINGERPRINT[2] = {0xDF, 0x76}; //!< EF<sub>prod</sub> data initialization fingerprint.
static const BYTE GP_GET_DATA_EF_PROD_DATA_INITIALIZATION_DATA[2] = {0xDF, 0x77}; //!< EF<sub>prod</sub> data initialization data.
static const BYTE GP_GET_DATA_EF_PROD_DATA_PRODUCTION_KEY_INDEX[2] = {0xDF, 0x78}; //!< EF<sub>prod</sub> data production key index.
static const BYTE GP_GET_DATA_EF_PROD_DATA_PROTOCOL_VERSION[2] = {0xDF, 0x79}; //!< EF<sub>prod</sub> data protocol version.
static const BYTE GP_GET_DATA_EF_PROD_DATA_CHECKSUM[2] = {0xDF, 0x7A}; //!< EF<sub>prod</sub> data checksum.
static const BYTE GP_GET_DATA_EF_PROD_DATA_SOFTWARE_VERSION[2] = {0xDF, 0x7B}; //!< EF<sub>prod</sub> data software version.
static const BYTE GP_GET_DATA_EF_PROD_DATA_RFU[2] = {0xDF, 0x7C}; //!< EF<sub>prod</sub> data RFU.
static const BYTE GP_GET_DATA_EF_PROD_DATA_PROFILE_WITH_PROFILE_VERSION[2] = {0xDF, 0x7D}; //!< EF<sub>prod</sub> data profile with profile version.
static const BYTE GP_GET_DATA_EF_PROD_DATA_LOCATION_MACHINE_DATE_TIME[2] = {0xDF, 0x7E}; //!< EF<sub>prod</sub> data location, machine number, date, time.

static const BYTE GP_GET_DATA_WHOLE_EF_PROD[2] = {0xDF, 0x7F}; //!< Whole EF<sub>prod</sub> data block (39 Byte).




/**
 * The security information negotiated at mutual_authentication().
 */
typedef struct {
	BYTE securityLevel; //!< The security level.
	BYTE secureChannelProtocol; //!< The Secure Channel Protocol.
	BYTE secureChannelProtocolImpl; //!< The Secure Channel Protocol implementation.
	BYTE C_MACSession_Key[16]; //!< The Secure Channel C-MAC session key.
	BYTE R_MACSession_Key[16]; //!< The Secure Channel R-MAC session key.
	BYTE encryptionSessionKey[16]; //!< The Secure Channel encryption session key.
	BYTE dataEncryptionSessionKey[16]; //!< Secure Channel data encryption key.
	BYTE lastC_MAC[8]; //!< The last computed C-MAC.
	BYTE lastR_MAC[8]; //!< The last computed R-MAC.
} GP_SECURITY_INFO;


/**
 * A structure describing a Load File Data Block Signature according to the GlobalPlatform 
 * specification 2.1.1.
 */
typedef struct {
	BYTE securityDomainAIDLength; //!< The length of the Security Domain.
	BYTE securityDomainAID[16]; //!< The AID of the Security Domain.
	BYTE signatureLength; //!< The length of the signature. Can be 8 for a 3DES signature or 128 for a RSA signature.
	BYTE signature[128]; //!< The signature.
} GP_DAP_BLOCK, GP_RSA_DAP_BLOCK, GP_3DES_DAP_BLOCK;




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
} GP_RECEIPT_DATA;




/**
 * A structure containing key information. Key set version, key index, key type and key length.
 */
typedef struct {
	BYTE keySetVersion; //!< The key set version.
	BYTE keyIndex; //!< The key index.
	BYTE keyType; //!< The key type.
	BYTE keyLength; //!< The key length.
} GP_KEY_INFORMATION;



/**
 * A structure describing an AID.
 */
typedef struct {
	BYTE AIDLength; //!< The length of the AID.
	BYTE AID[16]; //!< The AID.
} GP_AID;



/**
 * The structure containing Issuer Security Domain, Security Domains, Executable Load Files 
 * and Application life cycle states and privileges returned by get_status().
 */
typedef struct {
	BYTE AIDLength; //!< The length of the AID.
	BYTE AID[16]; //!< The AID.
	BYTE lifeCycleState; //!< The Issuer Security Domain, Security Domains, Executable Load Files and Application life cycle state.
	BYTE privileges; //!< The Issuer Security Domain, Security Domains or Application privileges. Has no meaning for Executable Load Files.
} GP_APPLICATION_DATA;

/**
 * The structure containing Executable Load Files and their Executable Module returned by get_status().
 */
typedef struct {
	BYTE AIDLength; //!< The length of the Executable Load File AID.
	BYTE AID[16]; //!< The Executable Load File AID.
	BYTE lifeCycleState; //!< The Executable Load File life cycle state.
	BYTE numExecutableModules; //!< Number of associated Executable Modules.
	GP_AID executableModules[256]; //!< Array for the maximum possible associated Executable Modules.
} GP_EXECUTABLE_MODULES_DATA;






/**
 * The card information returned by a card_connect().
 */
typedef struct {
	/**
	 * The mechanical state of the card:
	 *	- GP_CARD_ABSENT There is no card in the reader.
	 *	- GP_CARD_PRESENT There is a card in the reader, but it has not been moved into position for use.
	 *	- GP_CARD_SWALLOWED There is a card in the reader in position for use. The card is not powered.
	 *	- GP_CARD_POWERED Power is being provided to the card, but the reader driver is unaware of the mode of the card.
	 *	- GP_CARD_NEGOTIABLE The card has been reset and is awaiting PTS negotiation.
	 *	- GP_CARD_SPECIFIC The card has been reset and specific communication protocols have been established.
	 *.
	 */
	DWORD state;
	DWORD protocol; //!< The card protocol T0 or T1.
	BYTE ATR[32]; //!< The Answer To Reset from the card.
	DWORD ATRLength;
	GP_CARDHANDLE cardHandle;
	BYTE logicalChannel;
} GP_CARD_INFO;





#define GP_CARD_PROTOCOL_T0 SCARD_PROTOCOL_T0 //!< The protocol T0.
#define GP_CARD_PROTOCOL_T1 SCARD_PROTOCOL_T1 //!< The protocol T1.





// Mapping of system errors to error codes.
#ifdef _WIN32
#define GP_ERROR_SUCCESS ERROR_SUCCESS //!< No error occured.
#define GP_ERROR_READ ERROR_READ_FAULT //!< Read error.
#define GP_ERROR_BAD_FILE_DESCRIPTOR ERROR_INVALID_HANDLE //!< Bad file descriptor.
#define GP_ERROR_FILE_NOT_FOUND ERROR_FILE_NOT_FOUND //!< File not found.
#define GP_ERROR_NOMEM ERROR_NOT_ENOUGH_MEMORY //!< No memory.
#else
#define GP_ERROR_SUCCESS 0 //!< No error occured.
#define GP_ERROR_READ EIO //!< Read error.
#define GP_ERROR_BAD_FILE_DESCRIPTOR EBADF //!< Bad file descriptor.
#define GP_ERROR_FILE_NOT_FOUND ENOENT //!< File not found.
#define GP_ERROR_NOMEM ENOMEM //!< No memory.
#endif


// Self defined errors.
#define GP_ERROR_UNRECOGNIZED_APDU_COMMAND ((DWORD)0x80301000L) //!< A APDU command can't be recognized as a valid T=0 protocol Case 1-4 ISO7816-4 APDU
#define GP_ERROR_CARD_CRYPTOGRAM_VERIFICATION ((DWORD)0x80302000L) //!< The verification of the card cryptogram failed.
#define GP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE ((DWORD)0x80303000L) //!< The command data is too large for secure messaging.
#define GP_ERROR_COMMAND_TOO_LARGE ((DWORD)0x80303001L) //!< The command data is too large.
#define GP_ERROR_INSUFFICIENT_BUFFER ((DWORD)0x80304000L) //!< A used buffer is too small.
#define GP_ERROR_MORE_APPLICATION_DATA ((DWORD)0x80305000L) //!< More Card Manager, Executable Load File or application data is available.
#define GP_ERROR_WRONG_TRY_LIMIT ((DWORD)0x80306000L) //!< Wrong maximum try limit.
#define GP_ERROR_WRONG_PIN_LENGTH ((DWORD)0x80307000L) //!< Wrong PIN length.
#define GP_ERROR_WRONG_KEY_VERSION ((DWORD)0x80308000L) //!< Wrong key version.
#define GP_ERROR_WRONG_KEY_INDEX ((DWORD)0x80309000L) //!< Wrong key index.
#define GP_ERROR_WRONG_KEY_TYPE ((DWORD)0x8030A000L) //!< Wrong key type.
#define GP_ERROR_KEY_CHECK_VALUE ((DWORD)0x8030B000L) //!< Key check value reported does not match.
#define GP_ERROR_INVALID_COMBINATION_KEY_SET_VERSION_KEY_INDEX ((DWORD)0x8030C000L) //!< The combination of key set version and key index is invalid.
#define GP_ERROR_MORE_KEY_INFORMATION_TEMPLATES ((DWORD)0x8030D000L) //!< More key information templates are available.
#define GP_ERROR_APPLICATION_TOO_BIG ((DWORD)0x8030E000L) //!< The application to load must be less than 32535 bytes.
#define GP_ERROR_VALIDATION_FAILED ((DWORD)0x8030F000L) //!< A validation has failed.
#define GP_ERROR_INVALID_FILENAME ((DWORD)0x8030F001L) //!< A file name is invalid.
#define GP_ERROR_INVALID_PASSWORD ((DWORD)0x8030F002L) //!< A password is invalid.
#define GP_ERROR_WRONG_EXPONENT ((DWORD)0x8030F003L) //!< The exponent must be 3 or 65537.
#define GP_ERROR_LOAD_FILE_DAP_NULL ((DWORD)0x8030F004L) //!< The Load File DAP is <code>NULL</code>.
#define GP_ERROR_INVALID_SCP ((DWORD)0x8030F005L) //!< The Secure Channel Protocol is invalid.
#define GP_ERROR_INVALID_SCP_IMPL ((DWORD)0x8030F006L) //!< The Secure Channel Protocol Implementation is invalid.

// Mapping of relevant WinSCard API errors to error codes.
#define GP_CARD_E_CANCELLED SCARD_E_CANCELLED //!< The action was canceled by an SCardCancel request.
#define GP_CARD_E_CANT_DISPOSE SCARD_E_CANT_DISPOSE //!< The system could not dispose of the media in the requested manner.
#define GP_CARD_E_CARD_UNSUPPORTED SCARD_E_CARD_UNSUPPORTED //!< The smart card does not meet minimal requirements for support.
#define GP_CARD_E_COMM_DATA_LOST SCARD_E_COMM_DATA_LOST //!< A communications error with the smart card has been detected.
#define GP_CARD_E_DUPLICATE_READER SCARD_E_DUPLICATE_READER //!< The reader driver did not produce a unique reader name.
#define GP_CARD_E_INSUFFICIENT_BUFFER SCARD_E_INSUFFICIENT_BUFFER //!< The data buffer for returned data is too small for the returned data.
#define GP_CARD_E_INVALID_ATR SCARD_E_INVALID_ATR //!< An ATR string obtained from the registry is not a valid ATR string.
#define GP_CARD_E_INVALID_HANDLE SCARD_E_INVALID_HANDLE //!< The supplied handle was invalid.
#define GP_CARD_E_INVALID_PARAMETER SCARD_E_INVALID_PARAMETER //!< One or more of the supplied parameters could not be properly interpreted.
#define GP_CARD_E_INVALID_TARGET SCARD_E_INVALID_TARGET //!< Registry startup information is missing or invalid.
#define GP_CARD_E_INVALID_VALUE SCARD_E_INVALID_VALUE //!< One or more of the supplied parameter values could not be properly interpreted.
#define GP_CARD_E_NO_MEMORY SCARD_E_NO_MEMORY //!< Not enough memory available to complete this command.
#define GP_CARD_E_NO_READERS_AVAILABLE SCARD_E_NO_READERS_AVAILABLE //!< No smart card reader is available.
#define GP_CARD_E_NO_SERVICE SCARD_E_NO_SERVICE //!< The smart card resource manager is not running.
#define GP_CARD_E_NO_SMARTCARD SCARD_E_NO_SMARTCARD //!< The operation requires a smart card, but no smart card is currently in the device.
#define GP_CARD_E_NOT_READY SCARD_E_NOT_READY //!< The reader or card is not ready to accept commands.
#define GP_CARD_E_NOT_TRANSACTED SCARD_E_NOT_TRANSACTED //!< An attempt was made to end a non-existent transaction.
#define GP_CARD_E_PCI_TOO_SMALL SCARD_E_PCI_TOO_SMALL //!< The PCI receive buffer was too small.
#define GP_CARD_E_PROTO_MISMATCH SCARD_E_PROTO_MISMATCH //!< The requested protocols are incompatible with the protocol currently in use with the card.
#define GP_CARD_E_READER_UNAVAILABLE SCARD_E_READER_UNAVAILABLE //!< The specified reader is not currently available for use.
#define GP_CARD_E_READER_UNSUPPORTED SCARD_E_READER_UNSUPPORTED //!< The reader driver does not meet minimal requirements for support.
#define GP_CARD_E_SERVICE_STOPPED SCARD_E_SERVICE_STOPPED //!< The smart card resource manager has shut down.
#define GP_CARD_E_SHARING_VIOLATION SCARD_E_SHARING_VIOLATION //!< The smart card cannot be accessed because of other outstanding connections.
#define GP_CARD_E_SYSTEM_CANCELLED SCARD_E_SYSTEM_CANCELLED //!< The action was canceled by the system, presumably to log off or shut down.
#define GP_CARD_E_TIMEOUT SCARD_E_TIMEOUT //!< The user-specified timeout value has expired.
#define GP_CARD_E_UNEXPECTED SCARD_E_UNEXPECTED //!< An unexpected card error has occurred.
#define GP_CARD_E_UNKNOWN_CARD SCARD_E_UNKNOWN_CARD //!< The specified smart card name is not recognized.
#define GP_CARD_E_UNKNOWN_READER SCARD_E_UNKNOWN_READER //!< The specified reader name is not recognized.
#define GP_CARD_E_UNSUPPORTED_FEATURE SCARD_E_UNSUPPORTED_FEATURE //!< This smart card does not support the requested feature.
#define GP_CARD_F_COMM_ERROR SCARD_F_COMM_ERROR //!< An internal communications error has been detected.
#define GP_CARD_F_INTERNAL_ERROR SCARD_F_INTERNAL_ERROR //!< An internal consistency check failed.
#define GP_CARD_F_UNKNOWN_ERROR SCARD_F_UNKNOWN_ERROR //!< An internal error has been detected, but the source is unknown.
#define GP_CARD_F_WAITED_TOO_LONG SCARD_F_WAITED_TOO_LONG //!< An internal consistency timer has expired.
#define GP_CARD_S_SUCCESS SCARD_S_SUCCESS //!< No error was encountered.
#define GP_CARD_W_CANCELLED_BY_USER SCARD_W_CANCELLED_BY_USER //!< The action was canceled by the user.
#define GP_CARD_W_REMOVED_CARD SCARD_W_REMOVED_CARD //!< The smart card has been removed, so that further communication is not possible.
#define GP_CARD_W_RESET_CARD SCARD_W_RESET_CARD //!< The smart card has been reset, so any shared state information is invalid.
#define GP_CARD_W_UNPOWERED_CARD SCARD_W_UNPOWERED_CARD //!< Power has been removed from the smart card, so that further communication is not possible.
#define GP_CARD_W_UNRESPONSIVE_CARD SCARD_W_UNRESPONSIVE_CARD //!< The smart card is not responding to a reset.
#define GP_CARD_W_UNSUPPORTED_CARD SCARD_W_UNSUPPORTED_CARD //!< The reader cannot communicate with the card, due to ATR string configuration conflicts.

// Mapping of ISO7816-4 / GlobalPlatform 2.1.1 errors to error codes.
// 0x8020XXXX is the generell meaning error.
// 0x802YXXXX is a special meaning for a use case.

#define GP_ISO7816_ERROR_PREFIX ((DWORD)0x80200000L) //!< Error prefix for all ISO7816 errors.

//
// Normal processing
//

#define GP_ISO7816_ERROR_RESPONSE_LENGTH (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6100L) //!< Response bytes available indicated the last 2 Bytes.

// State of non-volatile memory unchanged
#define GP_ISO7816_ERROR_FILE_INVALIDATED (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6283L) //!< Selected file invalidated.
#define GP_ISO7816_WARNING_CM_LOCKED (GP_ISO7816_ERROR_PREFIX | (DWORD)0x16283L) //!< Card life cycle is CM_LOCKED.

#define GP_ISO7816_ERROR_FILE_TERMINATED (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6285L) //!< SELECT FILE Warning: selected file is terminated.

// State of non-volatile memory changed
#define GP_ISO7816_ERROR_6300 (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6300L) //!< No information given.
#define GP_ISO7816_ERROR_HOST_CRYPTOGRAM_VERIFICATION (GP_ISO7816_ERROR_PREFIX | (DWORD)0x16300L) //!< Authentication of host cryptogram failed.

#define GP_ISO7816_ERROR_MORE_DATA_AVAILABLE (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6310L) //!< More data available.

//
// Execution errors
//

#define GP_ISO7816_ERROR_NOTHING_SPECIFIC (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6400L) //!< No specific diagnosis.
#define GP_ISO7816_ERROR_MEMORY_FAILURE (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6581L) //!< Memory failure or EDC check failed.

#define GP_ISO7816_ERROR_WRONG_LENGTH (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6700L) //!< Wrong length.

#define GP_ISO7816_ERROR_CHANNEL_NOT_SUPPORTED (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6881L) //!< Function not supported - Logical channel not supported/open.
#define GP_ISO7816_ERROR_SECURE_MESSAGING_NOT_SUPPORTED (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6882L) //!< Function not supported - Secure messaging not supported.

// Command not allowed class.
#define GP_ISO7816_ERROR_CONDITIONS_NOT_SATISFIED (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6985L) //!< Command not allowed - Conditions of use not satisfied.
#define GP_ISO7816_ERROR_NOT_MULTI_SELECTABLE (GP_ISO7816_ERROR_PREFIX | (DWORD)0x16985L) //!< The application to be selected is not multi-selectable, but its context is already active.

#define GP_ISO7816_ERROR_SECURITY_STATUS_NOT_SATISFIED (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6982L) //!< Command not allowed - Security status not satisfied.

#define GP_ISO7816_ERROR_6999 (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6999L)
#define GP_ISO7816_ERROR_SELECTION_REJECTED (GP_ISO7816_ERROR_PREFIX | (DWORD)0x16999L) //!< The application to be selected rejects selection or throws an exception.

// Wrong parameter(s) P1-P2 class.
#define GP_ISO7816_ERROR_WRONG_DATA (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6A80L) //!< Wrong data / Incorrect values in command data.
#define GP_ISO7816_ERROR_WRONG_GLOBAL_PIN_FORMAT (GP_ISO7816_ERROR_PREFIX | (DWORD)0x16A80L) //!< Wrong format for global PIN.

#define GP_ISO7816_ERROR_FUNC_NOT_SUPPORTED (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6A81L) //!< Function not supported.
#define GP_ISO7816_ERROR_APPLET_NOT_SELECTABLE (GP_ISO7816_ERROR_PREFIX | (DWORD)0x16A81L) //!< Card life cycle is CM_LOCKED or selected application was not in a selectable state.

#define GP_ISO7816_ERROR_FILE_NOT_FOUND (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6A82L) // !< File not found.
#define GP_ISO7816_ERROR_APPLET_NOT_FOUND (GP_ISO7816_ERROR_PREFIX | (DWORD)0x16A82L) //!< The application to be selected could not be found.

#define GP_ISO7816_ERROR_NOT_ENOUGH_MEMORY (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6A84L) //!< Not enough memory space.

#define GP_ISO7816_ERROR_INCORRECT_P1P2 (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6A86L) //!< Incorrect parameters (P1, P2).
#define GP_ISO7816_ERROR_WRONG_PIN_TRY_LIMIT (GP_ISO7816_ERROR_PREFIX | (DWORD)0x16A86L) //!< Wrong parameter P2 (PIN try limit).

#define GP_ISO7816_ERROR_DATA_NOT_FOUND (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6A88L) //!< Referenced data not found.

#define GP_ISO7816_ERROR_WRONG_P1P2 (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6B00L) //!< Wrong parameters (P1, P2).
#define GP_ISO7816_ERROR_CORRECT_LENGTH (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6C00L) //!< Correct expected length (Le) indicated by last 2 Bytes.
#define GP_ISO7816_ERROR_INVALID_INS (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6D00L) //!< Invalid instruction byte / Command not supported or invalid.
#define GP_ISO7816_ERROR_WRONG_CLA (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6E00L) //!< Wrong CLA byte.

#define GP_ISO7816_ERROR_ILLEGAL_PARAMETER (GP_ISO7816_ERROR_PREFIX | (DWORD)0x6F74L) //!< Illegal parameter.

#define GP_ISO7816_ERROR_ALGORITHM_NOT_SUPPORTED (GP_ISO7816_ERROR_PREFIX | (DWORD)0x9484L) //!< Algorithm not supported.
#define GP_ISO7816_ERROR_INVALID_KEY_CHECK_VALUE (GP_ISO7816_ERROR_PREFIX | (DWORD)0x9485L) //!< Invalid key check value.

/**
 * General error code for OpenSSL.
 * There is no comprehensive list.
 * The last OpenSSL error code can be obtained with a call to get_last_OpenSSL_error_code(),
 * a string representation of the last OpenSSL error as usual by a call to stringify_error().
 */
#define GP_OPENSSL_ERROR ((DWORD)0x80400000L) //!< OpenSSL error.

//! \brief Returns the last OpenSSL error code.
GP_API
unsigned long get_last_OpenSSL_error_code(void);

//! \brief This function establishes a context to the PC/SC resource manager.
GP_API
LONG establish_context(GP_CARDCONTEXT *cardContext);

//! \brief This function releases the context to the PC/SC resource manager established by establish_context().
GP_API
LONG release_context(GP_CARDCONTEXT cardContext);

//! \brief This function returns a list of currently available readers on the system.
GP_API
LONG list_readers(GP_CARDCONTEXT cardContext, GP_STRING readerNames, PDWORD readerNamesLength);

//! \brief This function connects to a reader on the system.
GP_API
LONG card_connect(GP_CARDCONTEXT cardContext, GP_CSTRING readerName, GP_CARD_INFO *cardInfo, DWORD protocol);

//! \brief This function disconnects a reader on the system.
GP_API
LONG card_disconnect(GP_CARDHANDLE cardHandle);

//! \brief GlobalPlatform: Selects an application on a card by AID.
GP_API
LONG select_application(GP_CARD_INFO cardInfo, PBYTE AID, DWORD AIDLength);

/** \brief GlobalPlatform: Gets the life cycle status of Applications, the Issuer Security 
 * Domains, Security Domains and Executable Load Files and their privileges or information about
 * Executable Modules of the Executable Load Files.
 */
GP_API
LONG get_status(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo, 
				BYTE cardElement, GP_APPLICATION_DATA *applData, 
				GP_EXECUTABLE_MODULES_DATA *executableData, PDWORD dataLength);

//! \brief GlobalPlatform: Sets the life cycle status of Applications, Security Domains or the Card Manager.
GP_API
LONG set_status(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo, BYTE cardElement, PBYTE AID, DWORD AIDLength, BYTE lifeCycleState);

//! \brief Formats an error code to a human readable string.
GP_API
GP_STRING stringify_error(DWORD errorCode);

//! \brief GlobalPlatform: Mutual authentication.
GP_API
LONG mutual_authentication(GP_CARD_INFO cardInfo, 
						   BYTE baseKey[16], BYTE S_ENC[16], BYTE S_MAC[16], 
						   BYTE DEK[16], BYTE keySetVersion,
						   BYTE keyIndex, BYTE secureChannelProtocol, 
						   BYTE secureChannelProtocolImpl, 
						   BYTE securityLevel, GP_SECURITY_INFO *secInfo);

//! \brief GlobalPlatform: Inits a Secure Channel implicitly.
GP_API
LONG init_implicit_secure_channel(PBYTE AID, DWORD AIDLength, BYTE baseKey[16], 
								  BYTE S_ENC[16], BYTE S_MAC[16], BYTE DEK[16],
								  BYTE secureChannelProtocolImpl, BYTE sequenceCounter[2], 
								  GP_SECURITY_INFO *secInfo);

//! \brief GlobalPlatform: Retrieve card data.
GP_API
LONG get_data(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo, 
			  const BYTE identifier[2], PBYTE recvBuffer, PDWORD recvBufferLength);

//! \brief Retrieve card data according ISO/IEC 7816-4 command not within a secure channel.
GP_API
LONG get_data_iso7816_4(GP_CARD_INFO cardInfo, const BYTE identifier[2], PBYTE recvBuffer, PDWORD recvBufferLength);

//! \brief GlobalPlatform: This returns the Secure Channel Protocol and the Secure Channel Protocol implementation.
GP_API
LONG get_secure_channel_protocol_details(GP_CARD_INFO cardInfo,
										 BYTE *secureChannelProtocol, BYTE *secureChannelProtocolImpl);

//! \brief GlobalPlatform: This returns the current Sequence Counter.
GP_API
LONG get_sequence_counter(GP_CARD_INFO cardInfo,
						  BYTE sequenceCounter[2]);

//! \brief GlobalPlatform: Put card data.
GP_API
LONG put_data(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo, 
			  BYTE identifier[2], PBYTE dataObject, DWORD dataObjectLength);

//! \brief GlobalPlatform: Changes or unblocks the global PIN.
GP_API
LONG pin_change(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo,
				BYTE tryLimit, PBYTE newPIN, DWORD newPINLength);

//! \brief GlobalPlatform: replaces a single 3DES key in a key set or adds a new 3DES key.
GP_API
LONG put_3des_key(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo,
				  BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, BYTE _3DESKey[16]);

//! \brief GlobalPlatform: replaces a single public RSA key in a key set or adds a new public RSA key.
GP_API
LONG put_rsa_key(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo,
				 BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, GP_STRING PEMKeyFileName, char *passPhrase);

//! \brief GlobalPlatform: replaces or adds a secure channel key set consisting of S-ENC, S-MAC and DEK.
GP_API
LONG put_secure_channel_keys(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo,
							 BYTE keySetVersion, BYTE newKeySetVersion,
							 BYTE newS_ENC[16], BYTE newS_MAC[16], BYTE newDEK[16]);

//! \brief GlobalPlatform: deletes a key or multiple keys.
GP_API
LONG delete_key(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo,
				BYTE keySetVersion, BYTE keyIndex);

//! \brief GlobalPlatform: Retrieves key information of keys on the card.
GP_API
LONG get_key_information_templates(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo,
								   BYTE keyInformationTemplate,
								   GP_KEY_INFORMATION *keyInformation, PDWORD keyInformationLength);

//! \brief GlobalPlatform: Deletes a Executable Load File or an applet.
GP_API
LONG delete_applet(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo,
				   GP_AID *AIDs, DWORD AIDsLength,
				   GP_RECEIPT_DATA **receiptData, PDWORD receiptDataLength);

//! \brief GlobalPlatform: Prepares the card for loading an applet.
GP_API
LONG install_for_load(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo,
					  PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, 
					  PBYTE securityDomainAID,
					  DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20], BYTE loadToken[128],
					  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
					  DWORD nonVolatileDataSpaceLimit);

//! \brief GlobalPlatform: Function to retrieve the data to sign by the Card Issuer in an Extradition Token.
GP_API
LONG get_extradition_token_signature_data(PBYTE securityDomainAID, 
										  DWORD securityDomainAIDLength,
										  PBYTE applicationAID, DWORD applicationAIDLength, 
										  PBYTE extraditionTokenSignatureData, 
										  PDWORD extraditionTokenSignatureDataLength);

//! \brief GlobalPlatform: Function to retrieve the data to sign by the Card Issuer in a Load Token.
GP_API
LONG get_load_token_signature_data(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, 
								   PBYTE securityDomainAID,
								   DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20],
								   DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
								   DWORD nonVolatileDataSpaceLimit, PBYTE loadTokenSignatureData,
								   PDWORD loadTokenSignatureDataLength);

//! \brief GlobalPlatform: Function to retrieve the data to sign by the Card Issuer in an Install Token.
GP_API
LONG get_install_token_signature_data(BYTE P1, PBYTE executableLoadFileAID, 
									  DWORD executableLoadFileAIDLength,
									  PBYTE executableModuleAID, DWORD executableModuleAIDLength,
									  PBYTE applicationAID, DWORD applicationAIDLength,
									  BYTE applicationPrivileges, DWORD volatileDataSpaceLimit,
									  DWORD nonVolatileDataSpaceLimit, PBYTE installParameters,
									  DWORD installParametersLength, PBYTE installTokenSignatureData,
									  PDWORD installTokenSignatureDataLength);

//! \brief GlobalPlatform: Calculates a Load Token using PKCS#1.
GP_API
LONG calculate_load_token(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, 
						  PBYTE securityDomainAID,
						  DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20],
						  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
						  DWORD nonVolatileDataSpaceLimit, BYTE loadToken[128],
						  GP_STRING PEMKeyFileName, char *passPhrase);

//! \brief GlobalPlatform: Calculates an Install Token using PKCS#1.
GP_API
LONG calculate_install_token(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, 
							 PBYTE executableModuleAID,
							 DWORD executableModuleAIDLength, PBYTE applicationAID,
							 DWORD applicationAIDLength, BYTE applicationPrivileges,
							 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
							 PBYTE installParameters, DWORD installParametersLength,
							 BYTE installToken[128], GP_STRING PEMKeyFileName, char *passPhrase);

//! \brief GlobalPlatform: Calculates a Load File Data Block Hash.
GP_API
LONG calculate_load_file_data_block_hash(GP_STRING executableLoadFileName,
							 unsigned char hash[20]);

//! \brief GlobalPlatform: Loads a Executable Load File (containing an applet) to the card.
GP_API
LONG load(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo,
				 GP_DAP_BLOCK *dapBlock, DWORD dapBlockLength, GP_STRING executableLoadFileName,
				 GP_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief GlobalPlatform: Installs an application on the card.
GP_API
LONG install_for_install(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo, 
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE executableModuleAID,
						 DWORD executableModuleAIDLength, PBYTE applicationAID, DWORD applicationAIDLength,
						 BYTE applicationPrivileges, DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE installParameters, DWORD installParametersLength,
						 BYTE installToken[128], GP_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief GlobalPlatform: Makes an installed application selectable.
GP_API
LONG install_for_make_selectable(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo,
								 PBYTE applicationAID, DWORD applicationAIDLength,
								 BYTE applicationPrivileges, BYTE installToken[128],
								 GP_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief GlobalPlatform: Installs and makes an installed application selectable.
GP_API
LONG install_for_install_and_make_selectable(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE executableModuleAID,
						 DWORD executableModuleAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE installParameters, DWORD installParametersLength,
						 BYTE installToken[128], GP_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief GlobalPlatform: Informs a Security Domain that a associated application will retrieve personalization data.
GP_API
LONG install_for_personalization(GP_CARD_INFO cardInfo, 
											 GP_SECURITY_INFO *secInfo, 
						 PBYTE applicationAID,
						 DWORD applicationAIDLength);

//! \brief GlobalPlatform: Associates an application with another Security Domain.
GP_API
LONG install_for_extradition(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo, 
							  PBYTE securityDomainAID, 
						 DWORD securityDomainAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength, 
						 BYTE extraditionToken[128], GP_RECEIPT_DATA *receiptData, 
						 PDWORD receiptDataAvailable);

//! \brief GlobalPlatform: Adds a key set for Delegated Management.
GP_API
LONG put_delegated_management_keys(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo,
								   BYTE keySetVersion,
								   BYTE newKeySetVersion,
								   GP_STRING PEMKeyFileName, char *passPhrase,
								   BYTE receipt_generation_key[16]);

//! \brief Sends an application protocol data unit.
GP_API
LONG send_APDU(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo, 
			   PBYTE capdu, DWORD capduLength, PBYTE rapdu,
			   PDWORD rapduLength);

//! \brief GlobalPlatform: Calculates a Load File Data Block Signature using 3DES.
GP_API
LONG calculate_3des_DAP(BYTE loadFileDataBlockHash[20], 
						PBYTE securityDomainAID, 
						DWORD securityDomainAIDLength, 
						BYTE DAPVerificationKey[16], GP_DAP_BLOCK *loadFileDataBlockSignature);

//! \brief GlobalPlatform: Calculates a Load File Data Block Signature using SHA-1 and PKCS#1 (RSA).
GP_API
LONG calculate_rsa_DAP(BYTE loadFileDataBlockHash[20], PBYTE securityDomainAID, 
					   DWORD securityDomainAIDLength, GP_STRING PEMKeyFileName, 
					   char *passPhrase, GP_DAP_BLOCK *loadFileDataBlockSignature);

//! \brief GlobalPlatform: Validates a Load Receipt.
GP_API
LONG validate_delete_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receipt_generation_key[16], GP_RECEIPT_DATA receiptData,
						   PBYTE AID, DWORD AIDLength);

//! \brief GlobalPlatform: Validates an Install Receipt.
GP_API
LONG validate_install_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receipt_generation_key[16], GP_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE applicationAID, DWORD applicationAIDLength);

//! \brief GlobalPlatform: Validates a Load Receipt.
GP_API
LONG validate_load_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receipt_generation_key[16], GP_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE securityDomainAID, DWORD securityDomainAIDLength);

//! \brief GlobalPlatform: Opens or closes a Logical Channel.
GP_API
LONG manage_channel(GP_SECURITY_INFO *secInfo, 
					GP_CARD_INFO *cardInfo, BYTE openClose, BYTE channelNumberToClose, 
					BYTE *channelNumberOpened);

//! \brief GlobalPlatform: If multiple Logical Channels are open, selects the Logical Channel.
GP_API
LONG select_channel(GP_CARD_INFO *cardInfo, BYTE channelNumber);

//! \brief GlobalPlatform: The STORE DATA command is used to transfer data to an Application or the Security Domain processing the command.
GP_API
LONG store_data(GP_CARD_INFO cardInfo, GP_SECURITY_INFO *secInfo,
				 PBYTE data, DWORD dataLength);

#ifdef __cplusplus
}
#endif
