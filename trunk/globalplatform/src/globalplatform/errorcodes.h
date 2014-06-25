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
 * This file contains all GlobalPlatform error codes.
*/

// Self defined errors.
#define OPGP_ERROR_SUCCESS 0 //!< No error occurred.
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
#define OPGP_ERROR_INVALID_RESPONSE_DATA ((DWORD)0x8030F00BL) //!< The response of the command was invalid.
#define OPGP_ERROR_CRYPT ((DWORD)0x8030F00CL) //!< An encryption or decryption error occurred.
#define OPGP_ERROR_PSEUDO_RANDOM_SCP03_NOT_SUPPORTED ((DWORD)0x8030F00DL) //!< SCP03 with Pseudo-random challenge generation is not supported
// Philip Wendland: added this because security level 3 of SCP03 is not supported yet.
#define OPGP_ERROR_SCP03_SECURITY_LEVEL_3_NOT_SUPPORTED ((DWORD)0x8030F00EL) //!< SCP03 with security level 3 is not supported.
// Philip Wendland: added this because security level 3 of SCP03 is not supported yet.
#define OPGP_ERROR_SCP03_SECURITY_LEVEL_3_NOT_SUPPORTED ((DWORD)0x8030F00EL) //!< SCP03 with security level 3 is not supported.

/* Open Platform 2.0.1' specific errors */

#define OP201_ERROR_LOAD_FILE_DAP_NULL ((DWORD)0x8030F007L) //!< The Load File DAP is <code>NULL</code>.
#define OP201_ERROR_MORE_APPLICATION_DATA ((DWORD)0x80305001L) //!< More Card Manager, Executable Load File or application data is available.

/* GlobalPlatform 2.1.1 specific errors */

#define GP211_ERROR_MORE_APPLICATION_DATA ((DWORD)0x80305000L) //!< More Issuer Security Domain, Executable Load File, Executable Load Files and Executable Modules or application data is available.
#define GP211_ERROR_LOAD_FILE_DATA_BLOCK_HASH_NULL ((DWORD)0x8030F004L) //!< The Load File Data Block Hash is <code>NULL</code>.
#define GP211_ERROR_INVALID_SCP ((DWORD)0x8030F005L) //!< The Secure Channel Protocol is invalid.
#define GP211_ERROR_INVALID_SCP_IMPL ((DWORD)0x8030F006L) //!< The Secure Channel Protocol Implementation is invalid.
#define GP211_ERROR_VALIDATION_R_MAC ((DWORD)0x8030F007L) //!< The validation of the R-MAC has failed.
#define GP211_ERROR_INCONSISTENT_SCP ((DWORD)0x8030F00AL) //!< The Secure Channel Protocol passed and the one reported by the card do not match.

/* Mapping of ISO7816-4 errors to error codes.
 * 0x8020XXXX is the general meaning error.
 * 0x802YXXXX is a special meaning for a use case.
*/

#define OPGP_ISO7816_ERROR_PREFIX ((DWORD)0x80200000L) //!< Error prefix for all ISO7816 errors.


/* Normal processing */

#define OPGP_ISO7816_ERROR_SUCCESS (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x9000L) //!< Success. No error.
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

#define OPGP_ISO7816_ERROR_FILE_NOT_FOUND (OPGP_ISO7816_ERROR_PREFIX | (DWORD)0x6A82L) //!< File not found.
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
