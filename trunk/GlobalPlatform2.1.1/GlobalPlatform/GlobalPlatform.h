/*  Copyright (c) 2007, Karsten Ohme
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
#ifdef OPGP_EXPORTS
#define OPGP_API __declspec(dllexport)
#else
#define OPGP_API __declspec(dllimport)
#endif
#else
#define OPGP_API
#endif

#ifndef max
#define max(a,b) (((a)>(b))?(a):(b))
#endif

#include <winscard.h>
#include "unicode.h"
#include <stdio.h>

typedef SCARDCONTEXT OPGP_CARDCONTEXT; //!< Reference to the reader resource manager.
typedef SCARDHANDLE OPGP_CARDHANDLE; //!< Reference to a card.
typedef LPTSTR OPGP_STRING; //!< A Microsoft/Muscle PC/SC LPTSTR.
typedef LPCTSTR OPGP_CSTRING; //!< A Microsoft/Muscle PC/SC LPCTSTR.
typedef LPBYTE PBYTE; //!< A Microsoft/Muscle PC/SC LPBYTE, pointer to unsigned char.
#ifdef _WIN32
typedef LPDWORD PDWORD; //!< A Microsoft LPDWORD/Muscle PC/SC, a pointer to a double word, pointer to unsigned long.
#endif


#define OPGP_TRACE_MODE_ENABLE 1 //!< Switch trace mode on
#define OPGP_TRACE_MODE_DISABLE 0 //!< Switch trace mode off

/* Some card states. */

#define OPGP_CARD_ABSENT SCARD_ABSENT //!< There is no card in the reader.
#define OPGP_CARD_PRESENT SCARD_PRESENT //!< There is a card in the reader, but it has not been moved into position for use.
#define OPGP_CARD_SWALLOWED SCARD_SWALLOWED //!< There is a card in the reader in position for use. The card is not powered.
#define OPGP_CARD_POWERED SCARD_POWERED //!< Power is being provided to the card, but the reader driver is unaware of the mode of the card.
#define OPGP_CARD_NEGOTIABLE SCARD_NEGOTIABLE //!< The card has been reset and is awaiting PTS negotiation.
#define OPGP_CARD_SPECIFIC SCARD_SPECIFIC //!< The card has been reset and specific communication protocols have been established.


#define OPGP_CARD_PROTOCOL_T0 SCARD_PROTOCOL_T0 //!< The protocol T0.
#define OPGP_CARD_PROTOCOL_T1 SCARD_PROTOCOL_T1 //!< The protocol T1.


/** The default key value for new cards defined in a VISA specification. */
static const BYTE OPGP_VISA_DEFAULT_KEY[16] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};

/** The default mother key value for new GemXpresso cards. */
static const BYTE OPGP_GEMXPRESSO_DEFAULT_KEY[16] = {0x47, 0x45, 0x4d, 0x58, 0x50, 0x52, 0x45, 0x53, 0x53, 0x4f, 0x53, 0x41, 0x4d, 0x50, 0x4c, 0x45};

/* Secure Channel stuff */

#define GP211_SCP01 0x01 //!< Secure Channel Protocol '01'
#define GP211_SCP02 0x02 //!< Secure Channel Protocol '02'

/** Secure Channel Protocol '01': "i" '05': Initiation mode explicit, C-MAC on modified APDU,
  * ICV set to zero, no ICV encryption, 3 Secure Channel Keys
  */
#define GP211_SCP01_IMPL_i05 0x05
/** Secure Channel Protocol '01': "i" '15': Initiation mode explicit, C-MAC on modified APDU,
  * ICV set to zero, ICV encryption, 3 Secure Channel Keys
  */
#define GP211_SCP01_IMPL_i15 0x15

/** Secure Channel Protocol '02': "i" = '44': Initiation mode explicit, C-MAC on modified APDU, 
  * ICV set to zero, no ICV encryption, 1 Secure Channel base key, 
  * well-known pseudo-random algorithm (card challenge),
  */
#define GP211_SCP02_IMPL_i44 0x44
/** Secure Channel Protocol '02': "i" = '45': Initiation mode explicit, C-MAC on modified APDU, 
  * ICV set to zero, no ICV encryption, 3 Secure Channel Keys, 
  * well-known pseudo-random algorithm (card challenge),
  */
#define GP211_SCP02_IMPL_i45 0x45
/** Secure Channel Protocol '02': "i" = '54': Initiation mode explicit, C-MAC on modified APDU, 
  * ICV set to zero, ICV encryption for C-MAC session, 1 Secure Channel base key, 
  * well-known pseudo-random algorithm (card challenge),
  */
#define GP211_SCP02_IMPL_i54 0x54
/** Secure Channel Protocol '02': "i" = '55': Initiation mode explicit, C-MAC on modified APDU, 
  * ICV set to zero, ICV encryption for C-MAC session, 3 Secure Channel Keys, 
  * well-known pseudo-random algorithm (card challenge).”
  */
#define GP211_SCP02_IMPL_i55 0x55
/** Secure Channel Protocol '02': "i" '04': Initiation mode explicit, C-MAC on modified APDU,
  * ICV set to zero, no ICV encryption, 1 Secure Channel base key, unspecified card challenge generation method
  */
#define GP211_SCP02_IMPL_i04 0x04
/** Secure Channel Protocol '02': "i" '05': Initiation mode explicit, C-MAC on modified APDU,
  * ICV set to zero, no ICV encryption, 3 Secure Channel Keys, unspecified card challenge generation method
  */
#define GP211_SCP02_IMPL_i05 0x05
/** Secure Channel Protocol '02': "i" '0A': Initiation mode implicit, C-MAC on unmodified APDU,
  * ICV set to MAC over AID, no ICV encryption, 1 Secure Channel base key
  */
#define GP211_SCP02_IMPL_i0A 0x0A
/** Secure Channel Protocol '02': "i" '0B': Initiation mode implicit, C-MAC on unmodified APDU,
  * ICV set to MAC over AID, no ICV encryption, 3 Secure Channel Keys
  */
#define GP211_SCP02_IMPL_i0B 0x0B
/** Secure Channel Protocol '02': "i" '14': Initiation mode explicit, C-MAC on modified APDU,
  * ICV set to zero, ICV encryption for CMAC session, 1 Secure Channel base key,
  * unspecified card challenge generation method
  */
#define GP211_SCP02_IMPL_i14 0x14
/** Secure Channel Protocol '02': "i" '15': Initiation mode explicit, C-MAC on modified APDU,
  * ICV set to zero, ICV encryption for CMAC session, 3 Secure Channel Keys,
  * unspecified card challenge generation method
  */
#define GP211_SCP02_IMPL_i15 0x15
/** Secure Channel Protocol '02': "i" '1A': Initiation mode implicit, C-MAC on unmodified APDU,
  * ICV set to MAC over AID, ICV encryption for C-MAC session, 1 Secure Channel base key
  */
#define GP211_SCP02_IMPL_i1A 0x1A
/** Secure Channel Protocol '02': "i" '1B': Initiation mode implicit, C-MAC on unmodified APDU,
  * ICV set to MAC over AID, ICV encryption for C-MAC session, 3 Secure Channel Keys
  */
#define GP211_SCP02_IMPL_i1B 0x1B


#define GP211_SCP01_SECURITY_LEVEL_C_DEC_C_MAC 0x03 //!< Secure Channel Protocol '01': C-DECRYPTION and C-MAC
#define GP211_SCP01_SECURITY_LEVEL_C_MAC 0x01  //!< Secure Channel Protocol '01': C-MAC
#define GP211_SCP01_SECURITY_LEVEL_NO_SECURE_MESSAGING 0x00 //!< Secure Channel Protocol '01': No secure messaging expected.

#define GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC 0x13 //!< Secure Channel Protocol '02': C-DECRYPTION, C-MAC and R-MAC
#define GP211_SCP02_SECURITY_LEVEL_C_MAC_R_MAC 0x11 //!< Secure Channel Protocol '02': C-MAC and R-MAC
#define GP211_SCP02_SECURITY_LEVEL_R_MAC 0x10 //!< Secure Channel Protocol '02': R-MAC
#define GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC 0x03 //!< Secure Channel Protocol '02': C-DECRYPTION and C-MAC
#define GP211_SCP02_SECURITY_LEVEL_C_MAC 0x01 //!< Secure Channel Protocol '02': C-MAC
#define GP211_SCP02_SECURITY_LEVEL_NO_SECURE_MESSAGING 0x00 //!< Secure Channel Protocol '02': No secure messaging expected.


static const BYTE GP211_CARD_MANAGER_AID[8] = {0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00}; //!< The AID of the Issuer Security Domain defined by GlobalPlatform 2.1.1 specification.

#define GP211_KEY_TYPE_RSA_PUB_N 0xA1 //!< 'A1' RSA Public Key - modulus N component (clear text).
#define GP211_KEY_TYPE_RSA_PUB_E 0xA0 //!< 'A0' RSA Public Key - public exponent e component (clear text)
#define GP211_KEY_TYPE_RSA_PRIV_N 0xA2 //!< ''A2' RSA Private Key - modulus N component
#define GP211_KEY_TYPE_RSA_PRIV_D 0xA3 //!< ''A3' RSA Private Key - private exponent d component
#define GP211_KEY_TYPE_RSA_PRIV_P 0xA4 //!< ''A4' RSA Private Key - Chinese Remainder P component
#define GP211_KEY_TYPE_RSA_PRIV_Q 0xA5 //!< ''A5' RSA Private Key - Chinese Remainder Q component
#define GP211_KEY_TYPE_RSA_PRIV_PQ 0xA6 //!< ''A6' RSA Private Key - Chinese Remainder PQ component
#define GP211_KEY_TYPE_RSA_PRIV_DP1 0xA7 //!< ''A7' RSA Private Key - Chinese Remainder DP1 component
#define GP211_KEY_TYPE_RSA_PRIV_DQ1 0xA8 //!< ''A8' RSA Private Key - Chinese Remainder DQ1 component


#define GP211_KEY_TYPE_3DES 0x81 //!< Reserved (triple DES).
#define GP211_KEY_TYPE_DES 0x80 //!< '80' DES – mode (EBC/CBC) implicitly known.
#define GP211_KEY_TYPE_3DES_CBC 0x82 //!<'82' Triple DES in CBC mode.
#define GP211_KEY_TYPE_DES_ECB 0x83 //!<'83' DES in ECB mode.
#define GP211_KEY_TYPE_DES_CBC 0x84 //!<'84' DES in CBC mode.

#define GP211_LIFE_CYCLE_LOAD_FILE_LOADED 0x01 //!< Executable Load File is loaded.
#define GP211_LIFE_CYCLE_CARD_OP_READY 0x01 //!< Card is OP ready.
#define GP211_LIFE_CYCLE_CARD_INITIALIZED 0x07 //!< Card is initialized.
#define GP211_LIFE_CYCLE_CARD_SECURED 0x0f //!< Card is in secured state.
#define GP211_LIFE_CYCLE_CARD_LOCKED 0x7f //!< Card is locked.
#define GP211_LIFE_CYCLE_CARD_TERMINATED 0xff //!< Card is termonated.
#define GP211_LIFE_CYCLE_APPLICATION_INSTALLED 0x03 //!< Application is installed
#define GP211_LIFE_CYCLE_APPLICATION_SELECTABLE 0x07 //!< Application is selectable.
#define GP211_LIFE_CYCLE_APPLICATION_LOCKED 0xff //!< Application is locked.
#define GP211_LIFE_CYCLE_SECURITY_DOMAIN_INSTALLED 0x03 //!< Application is installed
#define GP211_LIFE_CYCLE_SECURITY_DOMAIN_SELECTABLE 0x07 //!< Application is selectable.
#define GP211_LIFE_CYCLE_SECURITY_DOMAIN_PERSONALIZED 0xff //!< Application is personalized.
#define GP211_LIFE_CYCLE_SECURITY_DOMAIN_LOCKED 0xff //!< Application is locked.


/* consts for MANAGE CHANNEL */

#define GP211_MANAGE_CHANNEL_OPEN 0x00 //!< Open the next available Supplementary Logical Channel.
#define GP211_MANAGE_CHANNEL_CLOSE 0x80 //!< Close the Supplementary Logical Channel.


#define GP211_APPLICATION_PRIVILEGE_SECURITY_DOMAIN 0x80 //!< Application is security domain.
#define GP211_APPLICATION_PRIVILEGE_DAP_VERIFICATION 0x40 //!< Application can require DAP verification for loading and installating applications.
#define GP211_APPLICATION_PRIVILEGE_DELEGATED_MANAGEMENT 0x20 //!< Security domain has delegeted management right.
#define GP211_APPLICATION_PRIVILEGE_CARD_MANAGER_LOCK_PRIVILEGE 0x10 //!< Application can lock the Card Manager.
#define GP211_APPLICATION_PRIVILEGE_CARD_MANAGER_TERMINATE_PRIVILEGE 0x08 //!< Application can terminate the card.
#define GP211_APPLICATION_PRIVILEGE_DEFAULT_SELECTED 0x04 //!< Application is default selected.
#define GP211_APPLICATION_PRIVILEGE_PIN_CHANGE_PRIVILEGE 0x02 //!< Application can change global PIN.
#define GP211_APPLICATION_PRIVILEGE_MANDATED_DAP_VERIFICATION 0x01 //!< Security domain requires DAP verification for loading and installating applications.

#define GP211_STATUS_APPLICATIONS 0x40 //!< Indicate Applications or Security Domains in GP211_get_status() (request GP211_APPLICATION_DATA) or GP211_set_status().
#define GP211_STATUS_ISSUER_SECURITY_DOMAIN 0x80 //!< Indicate Issuer Security Domain in GP211_get_status() (request GP211_APPLICATION_DATA) or GP211_set_status().
#define GP211_STATUS_LOAD_FILES 0x20 //!< Request GP211_APPLICATION_DATA for Executable Load Files in GP211_get_status().
#define GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES 0x10 //!< Request GP211_EXECUTABLE_MODULES_DATA for Executable Load Files and their Executable Modules in GP211_get_status().





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
static const BYTE GP211_DIVERSIFICATION_DATA[2] = {0x00, 0xCF}; //!< Diversification data.

/**
 * Key Information Template of first 31 keys.
 * Next templates can be obtained with the tag 0x0x 0xE0, where x > 0.
 */
static const BYTE GP211_GET_DATA_KEY_INFORMATION_TEMPLATE[2] = {0x00, 0xE0};

static const BYTE GP211_GET_DATA_CPLC_PERSONALIZATION_DATE[2] = {0x9F, 0x66}; //!< CPLC personalization date.
static const BYTE GP211_GET_DATA_CPLC_PRE_PERSONALIZATION_DATE[2] = {0x9F, 0x67}; //!< CPLC pre-personalization date.
static const BYTE GP211_GET_DATA_CPLC_ICC_MANUFACTURER_EMBEDDING_DATE[2] = {0x9F, 0x68}; //!< CPLC ICC manufacturer, embedding date.
static const BYTE GP211_GET_DATA_CPLC_MODULE_FABRICATOR_PACKAGING_DATE[2] = {0x9F, 0x69}; //!< CPLC module fabricator, module packaging date.
static const BYTE GP211_GET_DATA_CPLC_FABRICATION_DATE_SERIAL_NUMBER_BATCH_IDENTIFIER[2] = {0x9F, 0x6A}; //!< CPLC fabrication date, serail number, batch identifier.
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





static const BYTE OP201_CARD_MANAGER_AID[7] = {0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00}; //!< The AID of the Card Manager defined by Open Platform specification.


#define OP201_SECURITY_LEVEL_ENC_MAC 0x03 //!< Command messages are signed and encrypted.
#define OP201_SECURITY_LEVEL_MAC 0x01 //!< Command messages are signed.
#define OP201_SECURITY_LEVEL_PLAIN 0x00 //!< Command messages are plaintext.

#define OP201_KEY_TYPE_RSA_PUP_N 0xA1 //!< 'A1' RSA Public Key - modulus N component (clear text).
#define OP201_KEY_TYPE_RSA_PUP_E 0xA0 //!< 'A0' RSA Public Key - public exponent e component (clear text)
#define OP201_KEY_TYPE_DES 0x80 //!< DES (ECB/CBC) key.
#define OP201_KEY_TYPE_DES_ECB 0x81 //!< DES ECB.
#define OP201_KEY_TYPE_DES_CBC 0x82 //!< DES CBC.
#define OP201_LIFE_CYCLE_LOAD_FILE_LOGICALLY_DELETED 0x00 //!< Executable Load File is logically deleted.
#define OP201_LIFE_CYCLE_LOAD_FILE_LOADED 0x01 //!< Executable Load File is loaded.
#define OP201_LIFE_CYCLE_CARD_MANAGER_OP_READY 0x01 //!< Card is OP ready.
#define OP201_LIFE_CYCLE_CARD_MANAGER_INITIALIZED 0x07 //!< Card is initialized.
#define OP201_LIFE_CYCLE_CARD_MANAGER_SECURED 0x0f //!< Card is in secured state.
#define OP201_LIFE_CYCLE_CARD_MANAGER_CM_LOCKED 0x7f //!< Card is locked.
#define OP201_LIFE_CYCLE_CARD_MANAGER_TERMINATED 0xff //!< Card is termonated.
#define OP201_LIFE_CYCLE_APPLICATION_LOGICALLY_DELETED 0x00 //!< Application is logically deleted.
#define OP201_LIFE_CYCLE_APPLICATION_INSTALLED 0x03 //!< Application is installed
#define OP201_LIFE_CYCLE_APPLICATION_SELECTABLE 0x07 //!< Application is selectable.
#define OP201_LIFE_CYCLE_APPLICATION_PERSONALIZED 0x0f //!< Application is personalized.
#define OP201_LIFE_CYCLE_APPLICATION_BLOCKED 0x7f //!< Application is blocked.
#define OP201_LIFE_CYCLE_APPLICATION_LOCKED 0xff //!< Application is locked.

#define OP201_APPLICATION_PRIVILEGE_SECURITY_DOMAIN 0x80 //!< Application is security domain.
#define OP201_APPLICATION_PRIVILEGE_DAP_VERIFICATION 0x40 //!< Application can require DAP verification for loading and installating applications.
#define OP201_APPLICATION_PRIVILEGE_DELEGATED_MANAGEMENT 0x20 //!< Security domain has delegeted management right.
#define OP201_APPLICATION_PRIVILEGE_CARD_MANAGER_LOCK_PRIVILEGE 0x10 //!< Application can lock the Card Manager.
#define OP201_APPLICATION_PRIVILEGE_CARD_MANAGER_TERMINATE_PRIVILEGE 0x08 //!< Application can terminate the card.
#define OP201_APPLICATION_PRIVILEGE_DEFAULT_SELECTED 0x04 //!< Application is default selected.
#define OP201_APPLICATION_PRIVILEGE_PIN_CHANGE_PRIVILEGE 0x02 //!< Application can change global PIN.
#define OP201_APPLICATION_PRIVILEGE_MANDATED_DAP_VERIFICATION 0x01 //!< Security domain requires DAP verification for loading and installating applications.

#define OP201_STATUS_APPLICATIONS 0x40 //!< Indicate Applications or Security Domains in OP201_get_status() or OP201_set_status().
#define OP201_STATUS_CARD_MANAGER 0x80 //!< Indicate Card Manager in OP201_get_status() or OP201_set_status().
#define OP201_STATUS_LOAD_FILES 0x20 //!< Request OP201_APPLICATION_DATA for Executable Load Files in OP201_get_status().



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
static const BYTE OP201_DIVERSIFICATION_DATA[2] = {0x00, 0xCF}; //!< Diversification data.

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




/**
 * The security information negotiated at mutual_authentication().
 */
typedef struct {
	BYTE securityLevel; //!< The security level.
	BYTE sessionMacKey[16]; //!< The MAC session key.
	BYTE sessionEncKey[16]; //!< The ENC session key.
	BYTE lastMac[8]; //!< The last computed mac
	/* Augusto: added two more attributes for key information */
	BYTE keySetVersion; //!< The keyset version used in the secure channel
	BYTE keyIndex; //!< The key index used in the secure channel
	/* end */
} OP201_SECURITY_INFO;



/**
 * A structure describing a Load File Data Block DAP block according to the Open Platform specification 2.0.1'.
 * The structure comprises 3 Tag Length Value (TLV) fields after the ASN.1 specification.
 * The outer tag 0xE2 contains the two inner tags.
 */
typedef struct {
	BYTE securityDomainAIDLength; //!< The length of the Security Domain.
	BYTE securityDomainAID[16]; //!< The AID of the Security Domain.
	BYTE signatureLength; //!< The length of the signature. Can be 8 for a 3DES signature or 128 for a RSA signature.
	BYTE signature[128]; //!< The signature.
} OP201_DAP_BLOCK, OP201_RSA_DAP_BLOCK, OP201_3DES_DAP_BLOCK;




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
} OP201_RECEIPT_DATA;




/**
 * A structure containing key information. Key set version, key index, key type and key length.
 */
typedef struct {
	BYTE keySetVersion; //!< The key set version.
	BYTE keyIndex; //!< The key index.
	BYTE keyType; //!< The key type.
	BYTE keyLength; //!< The key length.
} OP201_KEY_INFORMATION;




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
 * The security information negotiated at GP211_mutual_authentication().
 */
typedef struct {
	BYTE securityLevel; //!< The security level.
	BYTE secureChannelProtocol; //!< The Secure Channel Protocol.
	BYTE secureChannelProtocolImpl; //!< The Secure Channel Protocol implementation.
	BYTE C_MACSessionKey[16]; //!< The Secure Channel C-MAC session key.
	BYTE R_MACSessionKey[16]; //!< The Secure Channel R-MAC session key.
	BYTE encryptionSessionKey[16]; //!< The Secure Channel encryption session key.
	BYTE dataEncryptionSessionKey[16]; //!< Secure Channel data encryption key.
	BYTE lastC_MAC[8]; //!< The last computed C-MAC.
	BYTE lastR_MAC[8]; //!< The last computed R-MAC.
	/* Augusto: added two more attributes for key information */
	BYTE keySetVersion; //!< The keyset version used in secure channel
	BYTE keyIndex; //! The key index used in secured channel
	/* end */
} GP211_SECURITY_INFO;


/**
 * A structure describing a Load File Data Block Signature according to the GlobalPlatform
 * specification 2.1.1.
 */
typedef struct {
	BYTE securityDomainAIDLength; //!< The length of the Security Domain.
	BYTE securityDomainAID[16]; //!< The AID of the Security Domain.
	BYTE signatureLength; //!< The length of the signature. Can be 8 for a 3DES signature or 128 for a RSA signature.
	BYTE signature[128]; //!< The signature.
} GP211_DAP_BLOCK, GP211_RSA_DAP_BLOCK, GP211_3DES_DAP_BLOCK;




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
} GP211_RECEIPT_DATA;




/**
 * A structure containing key information. Key set version, key index, key type and key length.
 */
typedef struct {
	BYTE keySetVersion; //!< The key set version.
	BYTE keyIndex; //!< The key index.
	BYTE keyType; //!< The key type.
	BYTE keyLength; //!< The key length.
} GP211_KEY_INFORMATION;



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






/**
 * The card information returned by a card_connect() and select_channel().
 */
typedef struct {
	/**
	 * The mechanical state of the card:
	 *	- OPGP_CARD_ABSENT There is no card in the reader.
	 *	- OPGP_CARD_PRESENT There is a card in the reader, but it has not been moved into position for use.
	 *	- OPGP_CARD_SWALLOWED There is a card in the reader in position for use. The card is not powered.
	 *	- OPGP_CARD_POWERED Power is being provided to the card, but the reader driver is unaware of the mode of the card.
	 *	- OPGP_CARD_NEGOTIABLE The card has been reset and is awaiting PTS negotiation.
	 *	- OPGP_CARD_SPECIFIC The card has been reset and specific communication protocols have been established.
	 *.
	 */
	DWORD state;
	DWORD protocol; //!< The card protocol T0 or T1.
	BYTE ATR[32]; //!< The Answer To Reset from the card.
	DWORD ATRLength; //!< The length of the ATR buffer.
	OPGP_CARDHANDLE cardHandle; //!< Internal used card handle
	BYTE logicalChannel; //!< The current logical channel.

} OPGP_CARD_INFO;







// Mapping of system errors to error codes.
#ifdef _WIN32
#define OPGP_ERROR_SUCCESS ERROR_SUCCESS //!< No error occured.
#else
#define OPGP_ERROR_SUCCESS 0 //!< No error occured.
#endif


// Self defined errors.
#define OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND ((DWORD)0x80301000L) //!< A APDU command can't be recognized as a valid T=0 protocol Case 1-4 ISO7816-4 APDU
#define OPGP_ERROR_CARD_CRYPTOGRAM_VERIFICATION ((DWORD)0x80302000L) //!< The verification of the card cryptogram failed.
#define OPGP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE ((DWORD)0x80303000L) //!< The command data is too large for secure messaging.
#define OPGP_ERROR_COMMAND_TOO_LARGE ((DWORD)0x80303001L) //!< The command data is too large.
#define OPGP_ERROR_INSUFFICIENT_BUFFER ((DWORD)0x80304000L) //!< A used buffer is too small.
#define OPGP_ERROR_WRONG_TRY_LIMIT ((DWORD)0x80306000L) //!< Wrong maximum try limit.
#define OPGP_ERROR_WRONG_PIN_LENGTH ((DWORD)0x80307000L) //!< Wrong PIN length.
#define OPGP_ERROR_WRONG_KEY_VERSION ((DWORD)0x80308000L) //!< Wrong key version.
#define OPGP_ERROR_WRONG_KEY_INDEX ((DWORD)0x80309000L) //!< Wrong key index.
#define OPGP_ERROR_WRONG_KEY_TYPE ((DWORD)0x8030A000L) //!< Wrong key type.
#define OPGP_ERROR_KEY_CHECK_VALUE ((DWORD)0x8030B000L) //!< Key check value reported does not match.
#define OPGP_ERROR_INVALID_COMBINATION_KEY_SET_VERSION_KEY_INDEX ((DWORD)0x8030C000L) //!< The combination of key set version and key index is invalid.
#define OPGP_ERROR_MORE_KEY_INFORMATION_TEMPLATES ((DWORD)0x8030D000L) //!< More key information templates are available.
#define OPGP_ERROR_APPLICATION_TOO_BIG ((DWORD)0x8030E000L) //!< The application to load must be less than 32535 bytes.
#define OPGP_ERROR_VALIDATION_FAILED ((DWORD)0x8030F000L) //!< A validation has failed.
#define OPGP_ERROR_INVALID_FILENAME ((DWORD)0x8030F001L) //!< A file name is invalid.
#define OPGP_ERROR_INVALID_PASSWORD ((DWORD)0x8030F002L) //!< A password is invalid.
#define OPGP_ERROR_WRONG_EXPONENT ((DWORD)0x8030F003L) //!< The exponent must be 3 or 65537.
#define OPGP_ERROR_INVALID_LOAD_FILE ((DWORD)0x8030F008L) //!< The load file has an invalid structure.
#define OPGP_ERROR_CAP_UNZIP ((DWORD)0x8030F009L) //!< The CAP file cannot be unzipped.

/* Open Platform 2.0.1' specific errors */

#define OP201_ERROR_LOAD_FILE_DAP_NULL ((DWORD)0x8030F007L) //!< The Load File DAP is <code>NULL</code>.
#define OP201_ERROR_MORE_APPLICATION_DATA ((DWORD)0x80305001L) //!< More Card Manager, Executable Load File or application data is available.

/* GlobalPlatform 2.1.1 specific errors */

#define GP211_ERROR_MORE_APPLICATION_DATA ((DWORD)0x80305000L) //!< More Issuer Security Domain, Executable Load File, Executable Load Files and Executable Modules or application data is available.
#define GP211_ERROR_LOAD_FILE_DATA_BLOCK_HASH_NULL ((DWORD)0x8030F004L) //!< The Load File Data Block Hash is <code>NULL</code>.
#define GP211_ERROR_INVALID_SCP ((DWORD)0x8030F005L) //!< The Secure Channel Protocol is invalid.
#define GP211_ERROR_INVALID_SCP_IMPL ((DWORD)0x8030F006L) //!< The Secure Channel Protocol Implementation is invalid.
#define GP211_ERROR_VALIDATION_R_MAC ((DWORD)0x8030F007L) //!< The validation of the R-MAC has failed.

/* Mapping of ISO7816-4 errors to error codes.
 * 0x8020XXXX is the generell meaning error.
 * 0x802YXXXX is a special meaning for a use case.
*/

#define OPGP_ISO7816_ERROR_PREFIX ((DWORD)0x80200000L) //!< Error prefix for all ISO7816 errors.


/* Normal processing */


#define OPGP_ISO7816_ERROR_RESPONSE_LENGTH (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6100L) //!< Response bytes available indicated the last 2 Bytes.

// State of non-volatile memory unchanged
#define OPGP_ISO7816_ERROR_FILE_INVALIDATED (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6283L) //!< Selected file invalidated.
#define OPGP_ISO7816_WARNING_CM_LOCKED (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x16283L) //!< Card life cycle is CM_LOCKED.

#define OPGP_ISO7816_ERROR_FILE_TERMINATED (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6285L) //!< SELECT FILE Warning: selected file is terminated.

// State of non-volatile memory changed
#define OPGP_ISO7816_ERROR_6300 (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6300L) //!< No information given.
#define OPGP_ISO7816_ERROR_HOST_CRYPTOGRAM_VERIFICATION (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x16300L) //!< Authentication of host cryptogram failed.

#define OPGP_ISO7816_ERROR_MORE_DATA_AVAILABLE (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6310L) //!< More data available.


/* Execution errors */


#define OPGP_ISO7816_ERROR_NOTHING_SPECIFIC (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6400L) //!< No specific diagnosis.
#define OPGP_ISO7816_ERROR_MEMORY_FAILURE (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6581L) //!< Memory failure or EDC check failed.

#define OPGP_ISO7816_ERROR_WRONG_LENGTH (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6700L) //!< Wrong length.

#define OPGP_ISO7816_ERROR_CHANNEL_NOT_SUPPORTED (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6881L) //!< Function not supported - Logical channel not supported/open.
#define OPGP_ISO7816_ERROR_SECURE_MESSAGING_NOT_SUPPORTED (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6882L) //!< Function not supported - Secure messaging not supported.

// Command not allowed class.
#define OPGP_ISO7816_ERROR_CONDITIONS_NOT_SATISFIED (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6985L) //!< Command not allowed - Conditions of use not satisfied.
#define OPGP_ISO7816_ERROR_NOT_MULTI_SELECTABLE (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x16985L) //!< The application to be selected is not multi-selectable, but its context is already active.

#define OPGP_ISO7816_ERROR_SECURITY_STATUS_NOT_SATISFIED (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6982L) //!< Command not allowed - Security status not satisfied.

#define OPGP_ISO7816_ERROR_6999 (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6999L)
#define OPGP_ISO7816_ERROR_SELECTION_REJECTED (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x16999L) //!< The application to be selected rejects selection or throws an exception.

// Wrong parameter(s) P1-P2 class.
#define OPGP_ISO7816_ERROR_WRONG_DATA (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6A80L) //!< Wrong data / Incorrect values in command data.
#define OPGP_ISO7816_ERROR_WRONG_GLOBAL_PIN_FORMAT (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x16A80L) //!< Wrong format for global PIN.

#define OPGP_ISO7816_ERROR_FUNC_NOT_SUPPORTED (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6A81L) //!< Function not supported.
#define OPGP_ISO7816_ERROR_APPLET_NOT_SELECTABLE (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x16A81L) //!< Card is locked or selected application was not in a selectable state.

#define OPGP_ISO7816_ERROR_FILE_NOT_FOUND (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6A82L) // !< File not found.
#define OPGP_ISO7816_ERROR_APPLET_NOT_FOUND (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x16A82L) //!< The application to be selected could not be found.

#define OPGP_ISO7816_ERROR_NOT_ENOUGH_MEMORY (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6A84L) //!< Not enough memory space.

#define OPGP_ISO7816_ERROR_INCORRECT_P1P2 (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6A86L) //!< Incorrect parameters (P1, P2).
#define OPGP_ISO7816_ERROR_WRONG_PIN_TRY_LIMIT (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x16A86L) //!< Wrong parameter P2 (PIN try limit).

#define OPGP_ISO7816_ERROR_DATA_NOT_FOUND (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6A88L) //!< Referenced data not found.

#define OPGP_ISO7816_ERROR_WRONG_P1P2 (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6B00L) //!< Wrong parameters (P1, P2).
#define OPGP_ISO7816_ERROR_CORRECT_LENGTH (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6C00L) //!< Correct expected length (Le) indicated by last 2 Bytes.
#define OPGP_ISO7816_ERROR_INVALID_INS (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6D00L) //!< Invalid instruction byte / Command not supported or invalid.
#define OPGP_ISO7816_ERROR_WRONG_CLA (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6E00L) //!< Wrong CLA byte.

#define OPGP_ISO7816_ERROR_ILLEGAL_PARAMETER (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6F74L) //!< Illegal parameter.

#define OPGP_ISO7816_ERROR_ALGORITHM_NOT_SUPPORTED (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x9484L) //!< Algorithm not supported.
#define OPGP_ISO7816_ERROR_INVALID_KEY_CHECK_VALUE (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x9485L) //!< Invalid key check value.

/**
 * General error code for OpenSSL.
 * There is no comprehensive list.
 * The last OpenSSL error code can be obtained with a call to get_last_OpenSSL_error_code(),
 * a string representation of the last OpenSSL error as usual by a call to stringify_error().
 */
#define OPGP_OPENSSL_ERROR ((DWORD)0x80400000L) //!< OpenSSL error.

//! \brief Returns the last OpenSSL error code.
OPGP_API
unsigned long get_last_OpenSSL_error_code(void);

//! \brief This function establishes a context to the PC/SC resource manager.
OPGP_API
LONG establish_context(OPGP_CARDCONTEXT *cardContext);

//! \brief This function releases the context to the PC/SC resource manager established by establish_context().
OPGP_API
LONG release_context(OPGP_CARDCONTEXT cardContext);

//! \brief This function returns a list of currently available readers on the system.
OPGP_API
LONG list_readers(OPGP_CARDCONTEXT cardContext, OPGP_STRING readerNames, PDWORD readerNamesLength);

//! \brief This function connects to a reader on the system.
OPGP_API
LONG card_connect(OPGP_CARDCONTEXT cardContext, OPGP_CSTRING readerName, OPGP_CARD_INFO *cardInfo, DWORD protocol);

//! \brief This function disconnects a reader on the system.
OPGP_API
LONG card_disconnect(OPGP_CARD_INFO cardInfo);

//! \brief GlobalPlatform2.1.1: Selects an application on a card by AID.
OPGP_API
LONG select_application(OPGP_CARD_INFO cardInfo, PBYTE AID, DWORD AIDLength);

/** \brief GlobalPlatform2.1.1: Gets the life cycle status of Applications, the Issuer Security
 * Domains, Security Domains and Executable Load Files and their privileges or information about
 * Executable Modules of the Executable Load Files.
 */
OPGP_API
LONG GP211_get_status(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				BYTE cardElement, GP211_APPLICATION_DATA *applData,
				GP211_EXECUTABLE_MODULES_DATA *executableData, PDWORD dataLength);

//! \brief GlobalPlatform2.1.1: Sets the life cycle status of Applications, Security Domains or the Card Manager.
OPGP_API
LONG GP211_set_status(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE cardElement, PBYTE AID, DWORD AIDLength, BYTE lifeCycleState);

//! \brief Formats an error code to a human readable string.
OPGP_API
OPGP_STRING stringify_error(DWORD errorCode);

//! \brief GlobalPlatform2.1.1: Mutual authentication.
OPGP_API
LONG GP211_mutual_authentication(OPGP_CARD_INFO cardInfo,
						   BYTE baseKey[16], BYTE S_ENC[16], BYTE S_MAC[16],
						   BYTE DEK[16], BYTE keySetVersion,
						   BYTE keyIndex, BYTE secureChannelProtocol,
						   BYTE secureChannelProtocolImpl,
						   BYTE securityLevel, GP211_SECURITY_INFO *secInfo);

//! \brief GlobalPlatform2.1.1: Inits a Secure Channel implicitly.
OPGP_API
LONG GP211_init_implicit_secure_channel(PBYTE AID, DWORD AIDLength, BYTE baseKey[16],
								  BYTE S_ENC[16], BYTE S_MAC[16], BYTE DEK[16],
								  BYTE secureChannelProtocolImpl, BYTE sequenceCounter[2],
								  GP211_SECURITY_INFO *secInfo);

//! \brief GlobalPlatform2.1.1: Retrieve card data.
OPGP_API
LONG GP211_get_data(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
			  const BYTE identifier[2], PBYTE recvBuffer, PDWORD recvBufferLength);

//! \brief Retrieve card data according ISO/IEC 7816-4 command not within a secure channel.
OPGP_API
LONG GP211_get_data_iso7816_4(OPGP_CARD_INFO cardInfo, const BYTE identifier[2], PBYTE recvBuffer, PDWORD recvBufferLength);

//! \brief GlobalPlatform2.1.1: This returns the Secure Channel Protocol and the Secure Channel Protocol implementation.
OPGP_API
LONG GP211_get_secure_channel_protocol_details(OPGP_CARD_INFO cardInfo,
										 BYTE *secureChannelProtocol, BYTE *secureChannelProtocolImpl);

//! \brief GlobalPlatform2.1.1: This returns the current Sequence Counter.
OPGP_API
LONG GP211_get_sequence_counter(OPGP_CARD_INFO cardInfo,
						  BYTE sequenceCounter[2]);

//! \brief GlobalPlatform2.1.1: Put card data.
OPGP_API
LONG GP211_put_data(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
			  BYTE identifier[2], PBYTE dataObject, DWORD dataObjectLength);

//! \brief GlobalPlatform2.1.1: Changes or unblocks the global PIN.
OPGP_API
LONG GP211_pin_change(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				BYTE tryLimit, PBYTE newPIN, DWORD newPINLength);

//! \brief GlobalPlatform2.1.1: replaces a single 3DES key in a key set or adds a new 3DES key.
OPGP_API
LONG GP211_put_3des_key(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				  BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, BYTE _3DESKey[16]);

//! \brief GlobalPlatform2.1.1: replaces a single public RSA key in a key set or adds a new public RSA key.
OPGP_API
LONG GP211_put_rsa_key(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, OPGP_STRING PEMKeyFileName, char *passPhrase);

//! \brief GlobalPlatform2.1.1: replaces or adds a secure channel key set consisting of S-ENC, S-MAC and DEK.
OPGP_API
LONG GP211_put_secure_channel_keys(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
							 BYTE keySetVersion, BYTE newKeySetVersion, BYTE baseKey[16],
							 BYTE newS_ENC[16], BYTE newS_MAC[16], BYTE newDEK[16]);

//! \brief GlobalPlatform2.1.1: deletes a key or multiple keys.
OPGP_API
LONG GP211_delete_key(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				BYTE keySetVersion, BYTE keyIndex);

//! \brief GlobalPlatform2.1.1: Retrieves key information of keys on the card.
OPGP_API
LONG GP211_get_key_information_templates(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								   BYTE keyInformationTemplate,
								   GP211_KEY_INFORMATION *keyInformation, PDWORD keyInformationLength);

//! \brief GlobalPlatform2.1.1: Deletes a Executable Load File or an application.
OPGP_API
LONG GP211_delete_application(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				   OPGP_AID *AIDs, DWORD AIDsLength,
				   GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataLength);

//! \brief GlobalPlatform2.1.1: Prepares the card for loading an application.
OPGP_API
LONG GP211_install_for_load(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
					  PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
					  PBYTE securityDomainAID,
					  DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20], BYTE loadToken[128],
					  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
					  DWORD nonVolatileDataSpaceLimit);

//! \brief GlobalPlatform2.1.1: Function to retrieve the data to sign by the Card Issuer in an Extradition Token.
OPGP_API
LONG GP211_get_extradition_token_signature_data(PBYTE securityDomainAID,
										  DWORD securityDomainAIDLength,
										  PBYTE applicationAID, DWORD applicationAIDLength,
										  PBYTE extraditionTokenSignatureData,
										  PDWORD extraditionTokenSignatureDataLength);

//! \brief GlobalPlatform2.1.1: Function to retrieve the data to sign by the Card Issuer in a Load Token.
OPGP_API
LONG GP211_get_load_token_signature_data(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
								   PBYTE securityDomainAID,
								   DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20], 
								   DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit, 
								   DWORD nonVolatileDataSpaceLimit, PBYTE loadTokenSignatureData, 
								   PDWORD loadTokenSignatureDataLength);

//! \brief GlobalPlatform2.1.1: Function to retrieve the data to sign by the Card Issuer in an Install Token.
OPGP_API
LONG GP211_get_install_token_signature_data(BYTE P1, PBYTE executableLoadFileAID,
									  DWORD executableLoadFileAIDLength,
									  PBYTE executableModuleAID, DWORD executableModuleAIDLength,
									  PBYTE applicationAID, DWORD applicationAIDLength,
									  BYTE applicationPrivileges, DWORD volatileDataSpaceLimit,
									  DWORD nonVolatileDataSpaceLimit, PBYTE installParameters,
									  DWORD installParametersLength, PBYTE installTokenSignatureData,
									  PDWORD installTokenSignatureDataLength);

//! \brief GlobalPlatform2.1.1: Calculates a Load Token using PKCS#1.
OPGP_API
LONG GP211_calculate_load_token(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						  PBYTE securityDomainAID,
						  DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20],
						  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
						  DWORD nonVolatileDataSpaceLimit, BYTE loadToken[128],
						  OPGP_STRING PEMKeyFileName, char *passPhrase);

//! \brief GlobalPlatform2.1.1: Calculates an Install Token using PKCS#1.
OPGP_API
LONG GP211_calculate_install_token(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
							 PBYTE executableModuleAID,
							 DWORD executableModuleAIDLength, PBYTE applicationAID,
							 DWORD applicationAIDLength, BYTE applicationPrivileges,
							 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
							 PBYTE installParameters, DWORD installParametersLength,
							 BYTE installToken[128], OPGP_STRING PEMKeyFileName, char *passPhrase);

//! \brief GlobalPlatform2.1.1: Calculates a Load File Data Block Hash.
OPGP_API
LONG GP211_calculate_load_file_data_block_hash(OPGP_STRING executableLoadFileName,
							 unsigned char hash[20]);

//! \brief GlobalPlatform2.1.1: Loads a Executable Load File (containing an application) to the card.
OPGP_API
LONG GP211_load(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 GP211_DAP_BLOCK *dapBlock, DWORD dapBlockLength, OPGP_STRING executableLoadFileName,
				 GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief GlobalPlatform2.1.1: Installs an application on the card.
OPGP_API
LONG GP211_install_for_install(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE executableModuleAID,
						 DWORD executableModuleAIDLength, PBYTE applicationAID, DWORD applicationAIDLength,
						 BYTE applicationPrivileges, DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE installParameters, DWORD installParametersLength,
						 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief GlobalPlatform2.1.1: Makes an installed application selectable.
OPGP_API
LONG GP211_install_for_make_selectable(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								 PBYTE applicationAID, DWORD applicationAIDLength,
								 BYTE applicationPrivileges, BYTE installToken[128],
								 GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief GlobalPlatform2.1.1: Installs and makes an installed application selectable.
OPGP_API
LONG GP211_install_for_install_and_make_selectable(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE executableModuleAID,
						 DWORD executableModuleAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE installParameters, DWORD installParametersLength,
						 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief GlobalPlatform2.1.1: Informs a Security Domain that a associated application will retrieve personalization data.
OPGP_API
LONG GP211_install_for_personalization(OPGP_CARD_INFO cardInfo,
											 GP211_SECURITY_INFO *secInfo,
						 PBYTE applicationAID,
						 DWORD applicationAIDLength);

//! \brief GlobalPlatform2.1.1: Associates an application with another Security Domain.
OPGP_API
LONG GP211_install_for_extradition(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
							  PBYTE securityDomainAID,
						 DWORD securityDomainAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength,
						 BYTE extraditionToken[128], GP211_RECEIPT_DATA *receiptData,
						 PDWORD receiptDataAvailable);

//! \brief GlobalPlatform2.1.1: Adds a key set for Delegated Management.
OPGP_API
LONG GP211_put_delegated_management_keys(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								   BYTE keySetVersion,
								   BYTE newKeySetVersion,
								   OPGP_STRING PEMKeyFileName, char *passPhrase,
								   BYTE receiptKey[16]);

//! \brief Sends an application protocol data unit.
OPGP_API
LONG GP211_send_APDU(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
			   PBYTE capdu, DWORD capduLength, PBYTE rapdu,
			   PDWORD rapduLength);

//! \brief GlobalPlatform2.1.1: Calculates a Load File Data Block Signature using 3DES.
OPGP_API
LONG GP211_calculate_3des_DAP(BYTE loadFileDataBlockHash[20],
						PBYTE securityDomainAID,
						DWORD securityDomainAIDLength,
						BYTE DAPVerificationKey[16], GP211_DAP_BLOCK *loadFileDataBlockSignature);

//! \brief GlobalPlatform2.1.1: Calculates a Load File Data Block Signature using SHA-1 and PKCS#1 (RSA).
OPGP_API
LONG GP211_calculate_rsa_DAP(BYTE loadFileDataBlockHash[20], PBYTE securityDomainAID,
					   DWORD securityDomainAIDLength, OPGP_STRING PEMKeyFileName,
					   char *passPhrase, GP211_DAP_BLOCK *loadFileDataBlockSignature);

//! \brief GlobalPlatform2.1.1: Validates a Load Receipt.
OPGP_API
LONG GP211_validate_delete_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
						   DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE AID, DWORD AIDLength);

//! \brief GlobalPlatform2.1.1: Validates an Install Receipt.
OPGP_API
LONG GP211_validate_install_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
						   DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE applicationAID, DWORD applicationAIDLength);

//! \brief GlobalPlatform2.1.1: Validates a Load Receipt.
OPGP_API
LONG GP211_validate_load_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
						   DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE securityDomainAID, DWORD securityDomainAIDLength);

//! \brief GlobalPlatform2.1.1: Validates an Extradition Receipt.
LONG GP211_validate_extradition_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
							  DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE oldSecurityDomainAID, DWORD oldSecurityDomainAIDLength,
						   PBYTE newSecurityDomainAID, DWORD newSecurityDomainAIDLength,
						   PBYTE applicationOrExecutableLoadFileAID,
						   DWORD applicationOrExecutableLoadFileAIDLength);

//! \brief ISO 7816-4 / GlobalPlatform2.1.1: Opens or closes a Logical Channel.
OPGP_API
LONG manage_channel(GP211_SECURITY_INFO *secInfo,
					OPGP_CARD_INFO *cardInfo, BYTE openClose, BYTE channelNumberToClose,
					BYTE *channelNumberOpened);

//! \brief ISO 7816-4 / GlobalPlatform2.1.1: If multiple Logical Channels are open or a new Logical Channel is opened with select_application(), selects the Logical Channel.
OPGP_API
LONG select_channel(OPGP_CARD_INFO *cardInfo, BYTE channelNumber);

//! \brief GlobalPlatform2.1.1: The STORE DATA command is used to transfer data to an Application or the Security Domain processing the command.
OPGP_API
LONG GP211_store_data(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 PBYTE data, DWORD dataLength);

//! \brief Open Platform: Gets the life cycle status of Applications, the Card Manager and Executable Load Files and their privileges.
OPGP_API
LONG OP201_get_status(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo, BYTE cardElement, OP201_APPLICATION_DATA *applData, PDWORD applDataLength);

//! \brief Open Platform: Sets the life cycle status of Applications, Security Domains or the Card Manager.
OPGP_API
LONG OP201_set_status(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo, BYTE cardElement, PBYTE AID, DWORD AIDLength, BYTE lifeCycleState);


//! \brief Open Platform: Mutual authentication.
OPGP_API
LONG OP201_mutual_authentication(OPGP_CARD_INFO cardInfo, BYTE encKey[16], BYTE macKey[16], 
								 BYTE kekKey[16], BYTE keySetVersion,
						   BYTE keyIndex, BYTE securityLevel,
						   OP201_SECURITY_INFO *secInfo);

//! \brief Open Platform: Retrieve card data.
OPGP_API
LONG OP201_get_data(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
					BYTE identifier[2], PBYTE recvBuffer, PDWORD recvBufferLength);

//! \brief Open Platform: Put card data.
OPGP_API
LONG OP201_put_data(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
					BYTE identifier[2], PBYTE dataObject, DWORD dataObjectLength);

//! \brief Open Platform: Changes or unblocks the global PIN.
OPGP_API
LONG OP201_pin_change(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				BYTE tryLimit, PBYTE newPIN, DWORD newPINLength, BYTE KEK[16]);

//! \brief Open Platform: replaces a single 3DES key in a key set or adds a new 3DES key.
OPGP_API
LONG OP201_put_3desKey(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				  BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, BYTE _3desKey[16],
				  BYTE KEK[16]);

//! \brief Open Platform: replaces a single public RSA key in a key set or adds a new public RSA key.
OPGP_API
LONG OP201_put_rsa_key(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				 BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, OPGP_STRING PEMKeyFileName, char *passPhrase);

//! \brief Open Platform: replaces or adds a secure channel key set consisting of encryption key, MAC key and key encryption.
OPGP_API
LONG OP201_put_secure_channel_keys(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
							 BYTE keySetVersion, BYTE newKeySetVersion,
							 BYTE new_encKey[16], BYTE new_macKey[16], BYTE new_KEK[16], BYTE KEK[16]);

//! \brief Open Platform: deletes a key or multiple keys.
OPGP_API
LONG OP201_delete_key(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				BYTE keySetVersion, BYTE keyIndex);

//! \brief Open Platform: Retrieves key information of keys on the card.
OPGP_API
LONG OP201_get_key_information_templates(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
								   BYTE keyInformationTemplate,
								   OP201_KEY_INFORMATION *keyInformation, PDWORD keyInformationLength);

//! \brief Open Platform: Deletes a Executable Load File or an application.
OPGP_API
LONG OP201_delete_application(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				   OPGP_AID *AIDs, DWORD AIDsLength,
				   OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataLength);

//! \brief Open Platform: Prepares the card for loading an application.
OPGP_API
LONG OP201_install_for_load(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
					  PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
					  DWORD securityDomainAIDLength, BYTE loadFileDAP[20], BYTE loadToken[128],
					  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
					  DWORD nonVolatileDataSpaceLimit);

//! \brief Open Platform: Function to retrieve the data to sign by the Card Issuer in a Load Token.
OPGP_API
LONG OP201_get_load_token_signature_data(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
								   PBYTE securityDomainAID, DWORD securityDomainAIDLength,
								   BYTE loadFileDAP[20], DWORD nonVolatileCodeSpaceLimit,
								   DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
								   PBYTE loadTokenSignatureData, PDWORD loadTokenSignatureDataLength);

//! \brief Open Platform: Function to retrieve the data to sign by the Card Issuer in an Install Token.
OPGP_API
LONG OP201_get_install_token_signature_data(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
									  PBYTE AIDWithinLoadFileAID, DWORD AIDWithinLoadFileAIDLength,
									  PBYTE applicationInstanceAID, DWORD applicationInstanceAIDLength,
									  BYTE applicationPrivileges, DWORD volatileDataSpaceLimit,
									  DWORD nonVolatileDataSpaceLimit, PBYTE applicationInstallParameters,
									  DWORD applicationInstallParametersLength, PBYTE installTokenSignatureData,
									  PDWORD installTokenSignatureDataLength);

//! \brief Open Platform: Calculates a Load Token using PKCS#1.
OPGP_API
LONG OP201_calculate_load_token(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
						  DWORD securityDomainAIDLength, BYTE loadFileDAP[20],
						  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
						  DWORD nonVolatileDataSpaceLimit, BYTE loadToken[128],
						  OPGP_STRING PEMKeyFileName, char *passPhrase);

//! \brief Open Platform: Calculates an Install Token using PKCS#1.
OPGP_API
LONG OP201_calculate_install_token(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE AIDWithinLoadFileAID,
							 DWORD AIDWithinLoadFileAIDLength, PBYTE applicationInstanceAID,
							 DWORD applicationInstanceAIDLength, BYTE applicationPrivileges,
							 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
							 PBYTE applicationInstallParameters, DWORD applicationInstallParametersLength,
							 BYTE installToken[128], OPGP_STRING PEMKeyFileName, char *passPhrase);

//! \brief Open Platform: Calculates a Load File DAP.
OPGP_API
LONG OP201_calculate_load_file_DAP(OP201_DAP_BLOCK *dapBlock, DWORD dapBlockLength,
							 OPGP_STRING executableLoadFileName, unsigned char hash[20]);

//! \brief Open Platform: Loads a Executable Load File (containing an application) to the card.
OPGP_API
LONG OP201_load(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				 OP201_DAP_BLOCK *dapBlock, DWORD dapBlockLength, OPGP_STRING executableLoadFileName,
				 OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief Open Platform: Installs an application on the card.
OPGP_API
LONG OP201_install_for_install(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE AIDWithinLoadFileAID,
						 DWORD AIDWithinLoadFileAIDLength, PBYTE applicationInstanceAID, DWORD applicationInstanceAIDLength,
						 BYTE applicationPrivileges, DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE applicationInstallParameters, DWORD applicationInstallParametersLength,
						 BYTE installToken[128], OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief Open Platform: Makes an installed application selectable.
OPGP_API
LONG OP201_install_for_make_selectable(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
								 PBYTE applicationInstanceAID, DWORD applicationInstanceAIDLength,
								 BYTE applicationPrivileges, BYTE installToken[128],
								 OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief Open Platform: Installs and makes an installed application selectable.
OPGP_API
LONG OP201_install_for_install_and_make_selectable(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo, 						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE AIDWithinLoadFileAID,
						 DWORD AIDWithinLoadFileAIDLength, PBYTE applicationInstanceAID,
						 DWORD applicationInstanceAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE applicationInstallParameters, DWORD applicationInstallParametersLength,
						 BYTE installToken[128], OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

//! \brief Open Platform: Adds a key set for Delegated Management.
OPGP_API
LONG OP201_put_delegated_management_keys(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
								   BYTE keySetVersion,
								   BYTE newKeySetVersion,
								   OPGP_STRING PEMKeyFileName, char *passPhrase,
								   BYTE receiptGenerationKey[16], BYTE KEK[16]);

//! \brief Sends an application protocol data unit.
OPGP_API
LONG OP201_send_APDU(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
					 PBYTE capdu, DWORD capduLength, PBYTE rapdu,
			   PDWORD rapduLength);

//! \brief Open Platform: Calculates a Load File Data Block DAP using 3DES.
OPGP_API
LONG OP201_calculate_3des_DAP(PBYTE securityDomainAID, DWORD securityDomainAIDLength, OPGP_STRING executableLoadFileName,
						BYTE DAP_verification_key[16], OP201_DAP_BLOCK *dapBlock);

//! \brief Open Platform: Calculates a Load File Data Block DAP using SHA-1 and PKCS#1 (RSA).
OPGP_API
LONG OP201_calculate_rsa_DAP(PBYTE securityDomainAID, DWORD securityDomainAIDLength, OPGP_STRING executableLoadFileName,
					   OPGP_STRING PEMKeyFileName, char *passPhrase, OP201_DAP_BLOCK *dapBlock);

//! \brief Open Platform: Validates a Load Receipt.
OPGP_API
LONG OP201_validate_delete_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receiptGenerationKey[16], OP201_RECEIPT_DATA receiptData,
						   PBYTE AID, DWORD AIDLength);

//! \brief Open Platform: Validates an Install Receipt.
OPGP_API
LONG OP201_validate_install_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receiptGenerationKey[16], OP201_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE applicationInstanceAID, DWORD applicationInstanceAIDLength);

//! \brief Open Platform: Validates a Load Receipt.
OPGP_API
LONG OP201_validate_load_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receiptGenerationKey[16], OP201_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE securityDomainAID, DWORD securityDomainAIDLength);


//! \brief Enables the trace mode.
OPGP_API
void enableTraceMode(DWORD enable, FILE *out);

//! \brief Initiates a R-MAC session.
OPGP_API
LONG GP211_begin_R_MAC(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE securityLevel, PBYTE data, DWORD dataLength);

//! \brief Terminates a R-MAC session.
OPGP_API
LONG GP211_end_R_MAC(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo);

//! \brief Reads the parameters of an Executable Load File.
OPGP_API
LONG read_executable_load_file_parameters(OPGP_STRING loadFileName, OPGP_LOAD_FILE_PARAMETERS *loadFileParams);

//! \brief Derives the static keys from a mother key for GemXpresso Pro cards.
OPGP_API
LONG GemXpressoPro_create_daughter_keys(OPGP_CARD_INFO cardInfo, PBYTE AID, DWORD AIDLength, BYTE motherKey[16], 
								 BYTE S_ENC[16], BYTE S_MAC[16], BYTE DEK[16]);

//! \brief Converts a CAP file to an IJC file (Executable Load File).
OPGP_API
LONG cap_to_ijc(OPGP_CSTRING capFileName, OPGP_STRING ijcFileName);

#ifdef __cplusplus
}
#endif
