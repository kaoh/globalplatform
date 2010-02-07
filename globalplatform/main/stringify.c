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

#include "GlobalPlatform/stringify.h"
#include "GlobalPlatform/errorcodes.h"
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <string.h>


/**
 * This method can stringify many general purpose error codes defined in #errorcodes.h and system error codes.
 * \param errorCode IN The error code.
 * \return OPGP_STRING representation of the error code.
 */
OPGP_STRING OPGP_stringify_error(DWORD errorCode) {
	static TCHAR strError[256];
	int rv;
	unsigned int strErrorSize = 256;

#ifdef _WIN32
#ifdef _UNICODE
	char str1[256];
	unsigned int str1Size = 256;
#endif
#endif
#ifdef _WIN32
	LPVOID lpMsgBuf;
#endif
	if (errorCode == OPGP_ERROR_CRYPT) {
		ERR_load_crypto_strings();
#ifdef _WIN32
#ifdef _UNICODE
		ERR_error_string_n(ERR_get_error(), str1, str1Size);
		MultiByteToWideChar(CP_ACP, 0, str1, -1, strError, strErrorSize);
		return strError;
#endif
#else
		ERR_error_string_n(ERR_get_error(), strError, strErrorSize);
		return strError;
#endif
	}
	if (errorCode == OPGP_ERROR_INVALID_RESPONSE_DATA)
		return _T("The response of the command was invalid.");
	if (errorCode == GP211_ERROR_INCONSISTENT_SCP)
		return _T("The Secure Channel Protocol passed and reported do not match.");
	if (errorCode == OPGP_ERROR_CAP_UNZIP)
		return _T("The CAP file cannot be unzipped.");
	if (errorCode == OPGP_ERROR_INVALID_LOAD_FILE)
		return _T("The load file has an invalid structure.");
	if (errorCode == GP211_ERROR_VALIDATION_R_MAC)
		return _T("The validation of the R-MAC has failed.");
	if (errorCode == OP201_ERROR_MORE_APPLICATION_DATA)
		return _T("More Card Manager, Executable Load File or application data is available.");
	if (errorCode == OP201_ERROR_LOAD_FILE_DAP_NULL)
		return _T("The Load File DAP is NULL.");
	if (errorCode == GP211_ERROR_LOAD_FILE_DATA_BLOCK_HASH_NULL)
		return _T("The Load File Data Block Hash is NULL.");
	if (errorCode == GP211_ERROR_INVALID_SCP)
		return _T("The Secure Channel Protocol is invalid.");
	if (errorCode == GP211_ERROR_INVALID_SCP_IMPL)
		return _T("The Secure Channel Protocol Implementation is invalid.");
	if (errorCode == OPGP_ERROR_COMMAND_TOO_LARGE)
		return _T("The command data is too large.");
	if (errorCode == OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND)
		return _T("A APDU command can't be recognized as a valid T=0 protocol Case 1-4 ISO7816-4 APDU");
	if (errorCode == OPGP_ERROR_CARD_CRYPTOGRAM_VERIFICATION)
		return _T("The verification of the card cryptogram failed.");
	if (errorCode == OPGP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE)
		return _T("The command is too large for secure messaging.");
	if (errorCode == OPGP_ERROR_INSUFFICIENT_BUFFER)
		return _T("A used buffer is too small.");
	if (errorCode == GP211_ERROR_MORE_APPLICATION_DATA)
		return _T("More Issuer Security Domain, Executable Load File, Executable Load Files and Executable Modules or application data is available.");
	if (errorCode == OPGP_ERROR_WRONG_TRY_LIMIT)
		return _T("Wrong maximum try limit.");
	if (errorCode == OPGP_ERROR_WRONG_PIN_LENGTH)
		return _T("Wrong PIN length.");
	if (errorCode == OPGP_ERROR_WRONG_KEY_VERSION)
		return _T("Wrong key version.");
	if (errorCode == OPGP_ERROR_WRONG_KEY_INDEX)
		return _T("Wrong key index.");
	if (errorCode == OPGP_ERROR_WRONG_KEY_TYPE)
		return _T("Wrong key type.");
	if (errorCode == OPGP_ERROR_KEY_CHECK_VALUE)
		return _T("Key check value reported does not match.");
	if (errorCode == OPGP_ERROR_INVALID_COMBINATION_KEY_SET_VERSION_KEY_INDEX)
		return _T("The combination of key set version and key index is invalid.");
	if (errorCode == OPGP_ERROR_MORE_KEY_INFORMATION_TEMPLATES)
		return _T("More key information templates are available.");
	if (errorCode == OPGP_ERROR_APPLICATION_TOO_BIG)
		return _T("The application to load must be less than 32535 bytes.");
	if (errorCode == OPGP_ERROR_VALIDATION_FAILED)
		return _T("A validation has failed.");
	if (errorCode == OPGP_ERROR_INVALID_PASSWORD)
		return _T("A password is invalid.");
	if (errorCode == OPGP_ERROR_WRONG_EXPONENT)
		return _T("The exponent must be 3 or 65537.");
	if ((errorCode & ((DWORD)0xFFFFFF00L)) == OPGP_ISO7816_ERROR_CORRECT_LENGTH) {
        _sntprintf(strError, strErrorSize, _T("Wrong length Le: Exact length: 0x%02lX"),
					errorCode&0x000000ff);
		strError[strErrorSize-1] = _T('\0');
		return strError;
	}
	if ((errorCode & ((DWORD)0xFFFFFF00L)) == OPGP_ISO7816_ERROR_RESPONSE_LENGTH) {
        _sntprintf(strError, strErrorSize, _T("Number of response bytes still available: 0x%02lX"),
					errorCode&0x000000ff);
		strError[strErrorSize-1] = _T('\0');
		return strError;
	}
	if ((errorCode & ((DWORD)0xFFF00000L)) == ((DWORD)0x80200000L)) {
		switch(errorCode) {
// 0x63
			case OPGP_ISO7816_ERROR_HOST_CRYPTOGRAM_VERIFICATION:
				return _T("6300: Authentication of host cryptogram failed.");
			case OPGP_ISO7816_ERROR_MORE_DATA_AVAILABLE:
				return _T("6310: More data available.");
// 0x63

// 0x67
			case OPGP_ISO7816_ERROR_WRONG_LENGTH:
				return _T("6700: Wrong length.");
// 0x67
			case OPGP_ISO7816_ERROR_SECURE_MESSAGING_NOT_SUPPORTED:
				return _T("6882: Function not supported - Secure messaging not supported.");
// 0x69
			case OPGP_ISO7816_ERROR_CONDITIONS_NOT_SATISFIED:
				return _T("6985: Command not allowed - Conditions of use not satisfied.");
			case OPGP_ISO7816_ERROR_NOT_MULTI_SELECTABLE:
				return _T("6985: The application to be selected is not multi-selectable, but its context is already active.");
			case OPGP_ISO7816_ERROR_SELECTION_REJECTED:
				return _T("6999: The application to be selected rejects selection or throws an exception.");
			case OPGP_ISO7816_ERROR_SECURITY_STATUS_NOT_SATISFIED:
				return _T("6982: Command not allowed - Security status not satisfied.");

// 0x69

// 0x6a
			case OPGP_ISO7816_ERROR_WRONG_DATA:
				return _T("6A80: Wrong data / Incorrect values in command data.");
			case OPGP_ISO7816_ERROR_WRONG_GLOBAL_PIN_FORMAT:
				return _T("6A80: Wrong format for global PIN.");

			case OPGP_ISO7816_ERROR_FUNC_NOT_SUPPORTED:
				return _T("6A81: Function not supported.");
			case OPGP_ISO7816_ERROR_APPLET_NOT_SELECTABLE:
				return _T("6A81: Card is locked or selected application was not in a selectable state.");

			case OPGP_ISO7816_ERROR_NOT_ENOUGH_MEMORY:
				return _T("6A84: Not enough memory space.");
			case OPGP_ISO7816_ERROR_INCORRECT_P1P2:
				return _T("6A86: Incorrect parameters (P1, P2).");
			case OPGP_ISO7816_ERROR_WRONG_PIN_TRY_LIMIT:
				return _T("6A86: Wrong parameter P2 (PIN try limit).");
			case OPGP_ISO7816_ERROR_DATA_NOT_FOUND:
				return _T("6A88: Referenced data not found.");

			case OPGP_ISO7816_ERROR_FILE_NOT_FOUND:
				return _T("6A82: File not found.");
			case OPGP_ISO7816_ERROR_APPLET_NOT_FOUND:
				return _T("6A82: The application to be selected could not be found.");
// 0x6a
			case OPGP_ISO7816_ERROR_NOTHING_SPECIFIC:
				return _T("6400: No specific diagnostic.");
// 0x62
			case OPGP_ISO7816_ERROR_FILE_INVALIDATED:
				return _T("6283: Selected file invalidated.");
			case OPGP_ISO7816_WARNING_CM_LOCKED:
				return _T("6283: Card life cycle state is CM_LOCKED.");
			case OPGP_ISO7816_ERROR_FILE_TERMINATED:
				return _T("6285: SELECT FILE Warning: selected file is terminated.");
// 0x62
			case OPGP_ISO7816_ERROR_MEMORY_FAILURE:
				return _T("6581: Memory failure or EDC check failed.");
			case OPGP_ISO7816_ERROR_CHANNEL_NOT_SUPPORTED:
				return _T("6881: Function not supported - Logical channel not supported/open.");
			case OPGP_ISO7816_ERROR_ILLEGAL_PARAMETER:
				return _T("6F74: Illegal parameter.");
			case OPGP_ISO7816_ERROR_WRONG_CLA:
				return _T("6E00: Wrong CLA byte.");
			case OPGP_ISO7816_ERROR_INVALID_INS:
				return _T("6D00: Invalid instruction byte / Command not supported or invalid.");
			case OPGP_ISO7816_ERROR_WRONG_P1P2:
				return _T("6B00: Wrong parameters (P1, P2).");
// 0x94
			case OPGP_ISO7816_ERROR_ALGORITHM_NOT_SUPPORTED:
				return _T("9484: Algorithm not supported.");
			case OPGP_ISO7816_ERROR_INVALID_KEY_CHECK_VALUE:
				return _T("9485: Invalid key check value.");
// 0x94

			default:
                _sntprintf(strError, strErrorSize, _T("Unknown ISO7816 error: 0x%04lX"),
					errorCode&0x0000ffff);
				strError[strErrorSize-1] = _T('\0');
				return strError;
		} // switch(errorCode)
	} // if ((errorCode & ((DWORD)0xFFF00000L)) == ((DWORD)0x80200000L))
	else {
		switch (errorCode)
		{
			case OPGP_ERROR_SUCCESS:
	#ifdef WIN32
			default:
				FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
					NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (OPGP_STRING) &lpMsgBuf, 0, NULL);
				if (lpMsgBuf == NULL) {
					return _T("Unknown error.");
				}
				if (_tcslen((OPGP_STRING)lpMsgBuf)+1 > strErrorSize) {
					_tcsncpy(strError, (OPGP_STRING)lpMsgBuf, strErrorSize-1);
					strError[strErrorSize-1] = _T('\0');
				}
				else {
					_tcscpy(strError, (OPGP_STRING)lpMsgBuf);
				}
				LocalFree(lpMsgBuf);
				return strError;
	#else
			default:

				rv = _tcserror_s(errorCode, strError, strErrorSize);
				if (rv != 0) {
				   return _T("Could not generate error string.");
				}
				return (OPGP_STRING)strError;
	#endif
		}
	}
}


