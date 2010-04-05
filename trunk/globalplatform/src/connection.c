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

#include "globalplatform/connection.h"
#include "dyn_generic.h"
#include "globalplatform/globalplatform.h"
#include "globalplatform/debug.h"
#include "globalplatform/stringify.h"
#include "globalplatform/error.h"
#include "crypto.h"
#include <string.h>

static DWORD traceEnable; //!< Enable trace mode.
static FILE *traceFile; //!< The trace file for trace mode.

/**
 * \param enable [in] Enables or disables the trace mode.
 * <ul>
 * <li>#OPGP_TRACE_MODE_ENABLE
 * <li>#OPGP_TRACE_MODE_DISABLE
 * </ul>
 * \param *out [out] The pointer to to FILE to print result.
 */
void OPGP_enable_trace_mode(DWORD enable, FILE *out) {
    if (out == NULL)
 		traceFile = stdout;
    else
 		traceFile = out;
    traceEnable = enable;
}

/**
 * #OPGP_release_context MUST be called to release allocated resources.
 * \param cardContext [out] The returned OPGP_CARD_CONTEXT.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_establish_context(OPGP_CARD_CONTEXT *cardContext) {
	OPGP_ERROR_STATUS errorStatus;
	// plugin function pointer
	OPGP_ERROR_STATUS(*plugin_establishContextFunction) (OPGP_CARD_CONTEXT *);

	OPGP_LOG_START(_T("OPGP_establish_context"));

	// unload library
	OPGP_release_context(cardContext);

	errorStatus = DYN_LoadLibrary(&cardContext->libraryHandle, (LPCTSTR)cardContext->libraryName, (LPCTSTR)cardContext->libraryVersion);
	if (OPGP_ERROR_CHECK(errorStatus)) {
		goto end;
	}
	// now load functions
	errorStatus = DYN_GetAddress(cardContext->libraryHandle, &cardContext->connectionFunctions.cardConnect, _T("OPGP_PL_card_connect"));
	if (OPGP_ERROR_CHECK(errorStatus)) {
		goto end;
	}
	errorStatus = DYN_GetAddress(cardContext->libraryHandle, &cardContext->connectionFunctions.cardDisconnect, _T("OPGP_PL_card_disconnect"));
	if (OPGP_ERROR_CHECK(errorStatus)) {
		goto end;
	}
	errorStatus = DYN_GetAddress(cardContext->libraryHandle, &cardContext->connectionFunctions.establishContext, _T("OPGP_PL_establish_context"));
	if (OPGP_ERROR_CHECK(errorStatus)) {
		goto end;
	}
	errorStatus = DYN_GetAddress(cardContext->libraryHandle, &cardContext->connectionFunctions.listReaders, _T("OPGP_PL_list_readers"));
	if (OPGP_ERROR_CHECK(errorStatus)) {
		goto end;
	}
	errorStatus = DYN_GetAddress(cardContext->libraryHandle, &cardContext->connectionFunctions.releaseContext, _T("OPGP_PL_release_context"));
	if (OPGP_ERROR_CHECK(errorStatus)) {
		goto end;
	}
	errorStatus = DYN_GetAddress(cardContext->libraryHandle, &cardContext->connectionFunctions.sendAPDU, _T("OPGP_PL_send_APDU"));
	if (OPGP_ERROR_CHECK(errorStatus)) {
		goto end;
	}
	OPGP_ERROR_CREATE_NO_ERROR(errorStatus);
	// call the establish function
	plugin_establishContextFunction = (OPGP_ERROR_STATUS(*)(OPGP_CARD_CONTEXT*)) cardContext->connectionFunctions.establishContext;
	errorStatus = (*plugin_establishContextFunction) (cardContext);
end:
	OPGP_LOG_END(_T("OPGP_establish_context"), errorStatus);
    return errorStatus;
}

/**
 * \param cardContext [in, out] The valid OPGP_CARD_CONTEXT returned by establish_context()
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_release_context(OPGP_CARD_CONTEXT *cardContext) {
	OPGP_ERROR_STATUS errorStatus;
	// plugin function pointer
	OPGP_ERROR_STATUS(*plugin_release_context) (OPGP_CARD_CONTEXT *);

	OPGP_LOG_START(_T("OPGP_release_context"));
	// only if handle is not NULL unload it
	if (cardContext->libraryHandle != NULL) {
		// call the release function
		plugin_release_context = (OPGP_ERROR_STATUS(*)(OPGP_CARD_CONTEXT *)) cardContext->connectionFunctions.releaseContext;
		if (plugin_release_context != NULL) {
			errorStatus = (*plugin_release_context) (cardContext);
			if (OPGP_ERROR_CHECK(errorStatus)) {
				goto end;
			}
		}
		errorStatus = DYN_CloseLibrary(&cardContext->libraryHandle);
		if (OPGP_ERROR_CHECK(errorStatus)) {
			goto end;
		}
	}
	cardContext->connectionFunctions.cardConnect = NULL;
	cardContext->connectionFunctions.cardDisconnect = NULL;
	cardContext->connectionFunctions.establishContext = NULL;
	cardContext->connectionFunctions.listReaders = NULL;
	cardContext->connectionFunctions.releaseContext = NULL;
	cardContext->connectionFunctions.sendAPDU = NULL;
	OPGP_ERROR_CREATE_NO_ERROR(errorStatus);
end:
	OPGP_LOG_END(_T("OPGP_release_context"), errorStatus);
    return errorStatus;
}

/**
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by establish_context()
 * \param readerNames [out] The reader names will be a multi-string and separated by a NULL character and ended by a double NULL.
 *  (ReaderA\\0ReaderB\\0\\0). If this value is NULL, list_readers ignores the buffer length supplied in
 *  readerNamesLength, writes the length of the multi-string that would have been returned if this parameter
 *  had not been NULL to readerNamesLength.
 * \param readerNamesLength [in, out] The length of the multi-string including all trailing null characters.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_list_readers(OPGP_CARD_CONTEXT cardContext, OPGP_STRING readerNames, PDWORD readerNamesLength) {
	OPGP_ERROR_STATUS errorStatus;
	OPGP_ERROR_STATUS(*plugin_listReadersFunction) (OPGP_CARD_CONTEXT, OPGP_STRING, PDWORD);
	OPGP_LOG_START(_T("OPGP_list_readers"));
	plugin_listReadersFunction = (OPGP_ERROR_STATUS(*)(OPGP_CARD_CONTEXT, OPGP_STRING, PDWORD)) cardContext.connectionFunctions.listReaders;
	errorStatus = (*plugin_listReadersFunction) (cardContext, readerNames, readerNamesLength);
	OPGP_LOG_END(_T("OPGP_list_readers"), errorStatus);
	return errorStatus;
}

/**
 * #OPGP_card_disconnect MUST be called to release allocated resources.
 * If something is not working, you may want to change the protocol type.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by establish_context()
 * \param readerName [in] The name of the reader to connect.
 * \param *cardInfo [out] The returned OPGP_CARD_INFO.
 * \param protocol [in] The transmit protocol type to use. Can be OPGP_CARD_PROTOCOL_T0 or OPGP_CARD_PROTOCOL_T1 or both ORed.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_card_connect(OPGP_CARD_CONTEXT cardContext, OPGP_CSTRING readerName, OPGP_CARD_INFO *cardInfo, DWORD protocol) {
	OPGP_ERROR_STATUS errorStatus;
	OPGP_ERROR_STATUS(*plugin_cardConnectFunction) (OPGP_CARD_CONTEXT, OPGP_CSTRING, OPGP_CARD_INFO *, DWORD);
	OPGP_LOG_START(_T("OPGP_card_connect"));
	// set the default spec version
	cardInfo->specVersion = GP_211;
	plugin_cardConnectFunction = (OPGP_ERROR_STATUS(*)(OPGP_CARD_CONTEXT, OPGP_CSTRING, OPGP_CARD_INFO*, DWORD)) cardContext.connectionFunctions.cardConnect;
	errorStatus = (*plugin_cardConnectFunction) (cardContext, readerName, cardInfo, protocol);
	OPGP_LOG_END(_T("OPGP_card_connect"), errorStatus);
	return errorStatus;
}

/**
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by establish_context()
 * \param cardInfo [in, out] The OPGP_CARD_INFO structure returned by card_connect().
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_card_disconnect(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO *cardInfo) {
    OPGP_ERROR_STATUS errorStatus;
    OPGP_ERROR_STATUS(*plugin_cardDisconnectFunction) (OPGP_CARD_CONTEXT, OPGP_CARD_INFO *);
    OPGP_LOG_START(_T("OPGP_card_disconnect"));
    plugin_cardDisconnectFunction = (OPGP_ERROR_STATUS(*)(OPGP_CARD_CONTEXT, OPGP_CARD_INFO *)) cardContext.connectionFunctions.cardDisconnect; ///<same here
    errorStatus = (*plugin_cardDisconnectFunction) (cardContext, cardInfo);
    OPGP_LOG_END(_T("OPGP_card_disconnect"), errorStatus);
    return errorStatus;
}

/**
 * If the transmission is successful then the APDU status word is returned as errorCode in the OPGP_ERROR_STATUS structure.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param capdu [in] The command APDU.
 * \param capduLength [in] The length of the command APDU.
 * \param rapdu [out] The response APDU.
 * \param rapduLength [in, out] The length of the the response APDU.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_send_APDU(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, PBYTE capdu, DWORD capduLength, PBYTE rapdu, PDWORD rapduLength) {
	OPGP_ERROR_STATUS errorStatus;
	OPGP_ERROR_STATUS securityStatus;
	OPGP_ERROR_STATUS(*plugin_sendAPDUFunction) (OPGP_CARD_CONTEXT, OPGP_CARD_INFO, PBYTE, DWORD, PBYTE, PDWORD);
	BYTE apduCommand[261];
	DWORD apduCommandLength = 261;
	int i=0;

	OPGP_LOG_START(_T("OPGP_send_APDU"));
	plugin_sendAPDUFunction = (OPGP_ERROR_STATUS(*)(OPGP_CARD_CONTEXT, OPGP_CARD_INFO, PBYTE, DWORD, PBYTE, PDWORD)) cardContext.connectionFunctions.sendAPDU;

#ifdef DEBUG
	OPGP_log_Hex(_T("OPGP_send_APDU: Command --> "), capdu, capduLength);
#endif

	if (traceEnable) {
		_ftprintf(traceFile, _T("Command --> "));
		for (i=0; (DWORD)i<capduLength; i++) {
			_ftprintf(traceFile, _T("%02X"), capdu[i] & 0x00FF);
		}
		_ftprintf(traceFile, _T("\n"));
	}

	// wrap command
	errorStatus = wrap_command(capdu, capduLength, apduCommand, &apduCommandLength, secInfo);
	if (OPGP_ERROR_CHECK(errorStatus)) {
		goto end;
	}

	capdu[0] |= cardInfo.logicalChannel;

	if (traceEnable) {
		_ftprintf(traceFile, _T("Wrapped command --> "));
		for (i=0; (DWORD)i<apduCommandLength; i++) {
			_ftprintf(traceFile, _T("%02X"), apduCommand[i] & 0x00FF);
		}
		_ftprintf(traceFile, _T("\n"));
	}

	errorStatus = (*plugin_sendAPDUFunction) (cardContext, cardInfo, apduCommand, apduCommandLength, rapdu, rapduLength);
	if (OPGP_ERROR_CHECK(errorStatus)) {
		goto end;
	}

#ifdef DEBUG
	OPGP_log_Hex(_T("OPGP_send_APDU: Response <-- "), rapdu, *rapduLength);
#endif

	securityStatus = GP211_check_R_MAC(capdu, capduLength, rapdu, *rapduLength, secInfo);
	if (OPGP_ERROR_CHECK(securityStatus)) {
		goto securityFailed;
	}

	if (traceEnable) {
		_ftprintf(traceFile, _T("Response <-- "));
		for (i=0; (DWORD)i<*rapduLength; i++) {
			_ftprintf(traceFile, _T("%02X"), rapdu[i] & 0x00FF);
		}
		_ftprintf(traceFile, _T("\n"));
	}

end:
	OPGP_LOG_END(_T("OPGP_send_APDU"), errorStatus);
	return errorStatus;
securityFailed:
	OPGP_LOG_END(_T("OPGP_send_APDU"), securityStatus);
	return securityStatus;

}


