/*
 *  Copyright (c) 2010-2026, Karsten Ohme
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
 *  along with GlobalPlatform.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "globalplatform/connection.h"
#include "dyn_generic.h"
#include "globalplatform/globalplatform.h"
#include "globalplatform/debug.h"
#include "globalplatform/stringify.h"
#include "globalplatform/error.h"
#include "crypto.h"
#include <string.h>
#include <stdlib.h>
#include "util.h"

DWORD traceEnable; //!< Enable trace mode.
FILE *traceFile; //!< The trace file for trace mode.

#define ASSIGN_FUNC_PTR(dest, src) do { \
		PVOID _fn = (src); \
		memcpy(&(dest), &_fn, sizeof(dest)); \
	} while (0)

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

#if defined(OPGP_STATIC_PCSC)
	/* If statically linked PC/SC plugin is requested, wire symbols directly */
	if (_tcscmp(cardContext->libraryName, _T("gppcscconnectionplugin")) == 0) {
		/* Avoid dynamic loading; set function pointers to linked-in plugin */
		/* Include header locally to get prototypes */
		/* Declarations to avoid additional includes */
		OPGP_ERROR_STATUS OPGP_PL_establish_context(OPGP_CARD_CONTEXT *);
		OPGP_ERROR_STATUS OPGP_PL_release_context(OPGP_CARD_CONTEXT *);
		OPGP_ERROR_STATUS OPGP_PL_card_connect(OPGP_CARD_CONTEXT, OPGP_CSTRING, OPGP_CARD_INFO *, DWORD);
		OPGP_ERROR_STATUS OPGP_PL_card_disconnect(OPGP_CARD_CONTEXT, OPGP_CARD_INFO *);
		OPGP_ERROR_STATUS OPGP_PL_list_readers(OPGP_CARD_CONTEXT, OPGP_STRING, PDWORD, DWORD);
		OPGP_ERROR_STATUS OPGP_PL_send_APDU(OPGP_CARD_CONTEXT, OPGP_CARD_INFO, PBYTE, DWORD, PBYTE, PDWORD);

		cardContext->libraryHandle = NULL; /* No dlopen handle when static */
		cardContext->connectionFunctions.cardConnect = OPGP_PL_card_connect;
		cardContext->connectionFunctions.cardDisconnect = OPGP_PL_card_disconnect;
		cardContext->connectionFunctions.establishContext = OPGP_PL_establish_context;
		cardContext->connectionFunctions.listReaders = OPGP_PL_list_readers;
		cardContext->connectionFunctions.releaseContext = OPGP_PL_release_context;
		cardContext->connectionFunctions.sendAPDU = OPGP_PL_send_APDU;

		/* call the establish function */
		plugin_establishContextFunction = cardContext->connectionFunctions.establishContext;
		errorStatus = (*plugin_establishContextFunction) (cardContext);
		goto end;
	}
#endif

	errorStatus = DYN_LoadLibrary(&cardContext->libraryHandle, (LPCTSTR)cardContext->libraryName, (LPCTSTR)cardContext->libraryVersion);
	if (OPGP_ERROR_CHECK(errorStatus)) {
		goto end;
	}
	// now load functions
	{
		PVOID fn = NULL;
		errorStatus = DYN_GetAddress(cardContext->libraryHandle, &fn, _T("OPGP_PL_card_connect"));
		if (OPGP_ERROR_CHECK(errorStatus)) {
			goto end;
		}
		ASSIGN_FUNC_PTR(cardContext->connectionFunctions.cardConnect, fn);
	}
	errorStatus = DYN_GetAddress(cardContext->libraryHandle, NULL, NULL);
	if (OPGP_ERROR_CHECK(errorStatus)) {
		goto end;
	}
	{
		PVOID fn = NULL;
		errorStatus = DYN_GetAddress(cardContext->libraryHandle, &fn, _T("OPGP_PL_card_disconnect"));
		if (OPGP_ERROR_CHECK(errorStatus)) {
			goto end;
		}
		ASSIGN_FUNC_PTR(cardContext->connectionFunctions.cardDisconnect, fn);
	}
	if (OPGP_ERROR_CHECK(errorStatus)) {
		goto end;
	}
	{
		PVOID fn = NULL;
		errorStatus = DYN_GetAddress(cardContext->libraryHandle, &fn, _T("OPGP_PL_establish_context"));
		if (OPGP_ERROR_CHECK(errorStatus)) {
			goto end;
		}
		ASSIGN_FUNC_PTR(cardContext->connectionFunctions.establishContext, fn);
	}
	if (OPGP_ERROR_CHECK(errorStatus)) {
		goto end;
	}
	{
		PVOID fn = NULL;
		errorStatus = DYN_GetAddress(cardContext->libraryHandle, &fn, _T("OPGP_PL_list_readers"));
		if (OPGP_ERROR_CHECK(errorStatus)) {
			goto end;
		}
		ASSIGN_FUNC_PTR(cardContext->connectionFunctions.listReaders, fn);
	}
	if (OPGP_ERROR_CHECK(errorStatus)) {
		goto end;
	}
	{
		PVOID fn = NULL;
		errorStatus = DYN_GetAddress(cardContext->libraryHandle, &fn, _T("OPGP_PL_release_context"));
		if (OPGP_ERROR_CHECK(errorStatus)) {
			goto end;
		}
		ASSIGN_FUNC_PTR(cardContext->connectionFunctions.releaseContext, fn);
	}
	if (OPGP_ERROR_CHECK(errorStatus)) {
		goto end;
	}
	{
		PVOID fn = NULL;
		errorStatus = DYN_GetAddress(cardContext->libraryHandle, &fn, _T("OPGP_PL_send_APDU"));
		if (OPGP_ERROR_CHECK(errorStatus)) {
			goto end;
		}
		ASSIGN_FUNC_PTR(cardContext->connectionFunctions.sendAPDU, fn);
	}
	if (OPGP_ERROR_CHECK(errorStatus)) {
		goto end;
	}
	OPGP_ERROR_CREATE_NO_ERROR(errorStatus);
	// call the establish function
	plugin_establishContextFunction = cardContext->connectionFunctions.establishContext;
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
	// call the release function even for statically linked plugins
	plugin_release_context = cardContext->connectionFunctions.releaseContext;
	if (plugin_release_context != NULL) {
		errorStatus = (*plugin_release_context) (cardContext);
		if (OPGP_ERROR_CHECK(errorStatus)) {
			goto end;
		}
	}
	// only if handle is not NULL unload it
	if (cardContext->libraryHandle != NULL) {
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
 * \param presentOnly If non-zero, only readers with a smart card inserted are returned.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_list_readers(OPGP_CARD_CONTEXT cardContext, OPGP_STRING readerNames, PDWORD readerNamesLength, DWORD presentOnly) {
    OPGP_ERROR_STATUS errorStatus;
    OPGP_ERROR_STATUS(*plugin_listReadersFunction) (OPGP_CARD_CONTEXT, OPGP_STRING, PDWORD, DWORD);
    OPGP_LOG_START(_T("OPGP_list_readers"));
    plugin_listReadersFunction = cardContext.connectionFunctions.listReaders;
    errorStatus = (*plugin_listReadersFunction) (cardContext, readerNames, readerNamesLength, presentOnly);
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
	plugin_cardConnectFunction = cardContext.connectionFunctions.cardConnect;
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
    plugin_cardDisconnectFunction = cardContext.connectionFunctions.cardDisconnect; ///<same here
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
 * \param rapduLength [in, out] The length of the response APDU.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_send_APDU(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, PBYTE capdu, DWORD capduLength, PBYTE rapdu, PDWORD rapduLength) {
	OPGP_ERROR_STATUS errorStatus;
	OPGP_ERROR_STATUS(*plugin_sendAPDUFunction) (OPGP_CARD_CONTEXT, OPGP_CARD_INFO, PBYTE, DWORD, PBYTE, PDWORD);
	BYTE apduCommand[APDU_COMMAND_LEN] = {0};
	DWORD apduCommandLength = APDU_COMMAND_LEN;
	DWORD errorCode;
	int i=0;

	OPGP_LOG_START(_T("OPGP_send_APDU"));
	plugin_sendAPDUFunction = cardContext.connectionFunctions.sendAPDU;

	OPGP_LOG_HEX(_T("OPGP_send_APDU: Command --> "), capdu, capduLength);

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

    /* AC Bugfix: Don't attempt to call function if fpointer is null */
    if (plugin_sendAPDUFunction == NULL){
        OPGP_ERROR_CREATE_ERROR(errorStatus, 0, _T("sendAPDUFunction is NULL. Likely no connection library is set."));
        goto end;
    } else {
        errorStatus = (*plugin_sendAPDUFunction) (cardContext, cardInfo, apduCommand, apduCommandLength, rapdu, rapduLength);
        if (OPGP_ERROR_CHECK(errorStatus)) {
            goto end;
        }
        errorCode = errorStatus.errorCode;
    }

	OPGP_LOG_HEX(_T("OPGP_send_APDU: Response <-- "), rapdu, *rapduLength);

	if (traceEnable) {
		_ftprintf(traceFile, _T("Response <-- "));
		for (i=0; (DWORD)i<*rapduLength; i++) {
			_ftprintf(traceFile, _T("%02X"), rapdu[i] & 0x00FF);
		}
		_ftprintf(traceFile, _T("\n"));
	}

	errorStatus = unwrap_command(capdu, capduLength, rapdu, *rapduLength, rapdu, rapduLength, secInfo);
	if (OPGP_ERROR_CHECK(errorStatus)) {
		goto end;
	}
	// add code from sendAPDUFunction again
	errorStatus.errorCode = errorCode;
	if (traceEnable) {
		_ftprintf(traceFile, _T("Unwrapped response <-- "));
		for (i=0; (DWORD)i<*rapduLength; i++) {
			_ftprintf(traceFile, _T("%02X"), rapdu[i] & 0x00FF);
		}
		_ftprintf(traceFile, _T("\n"));
	}

end:
	OPGP_LOG_END(_T("OPGP_send_APDU"), errorStatus);
	return errorStatus;
}

OPGP_ERROR_STATUS OPGP_send_chained_APDU(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
		PBYTE capdus[], DWORD capduLengths[], DWORD numCapdus, PBYTE rapdu, PDWORD rapduLength) {
	OPGP_ERROR_STATUS status;
	OPGP_ERROR_STATUS(*plugin_sendAPDUFunction) (OPGP_CARD_CONTEXT, OPGP_CARD_INFO, PBYTE, DWORD, PBYTE, PDWORD);
	DWORD i;
	DWORD totalData = 0;
	DWORD le = 0;
	BOOL haveLe = 0;
	BYTE logicalHeader[4] = {0};
	PBYTE concat = NULL;
	DWORD concatLen = 0;
	PBYTE wrapped = NULL;
	DWORD wrappedLen = 0;
	PBYTE wrappedData = NULL;
	DWORD wrappedLc = 0;
	DWORD pos = 0;
	DWORD errorCode = 0;

	OPGP_LOG_START(_T("OPGP_send_chained_APDU"));
	plugin_sendAPDUFunction = cardContext.connectionFunctions.sendAPDU;
	if (plugin_sendAPDUFunction == NULL){
		OPGP_ERROR_CREATE_ERROR(status, 0, _T("sendAPDUFunction is NULL. Likely no connection library is set."));
		goto end;
	}
	if (numCapdus == 0 || capdus == NULL || capduLengths == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND, OPGP_stringify_error(OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND));
		goto end;
	}

	// Use CLA/INS/P1/P2 from the last APDU for the logical command
	if (capduLengths[numCapdus - 1] < 4) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND, OPGP_stringify_error(OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND));
		goto end;
	}
	memcpy(logicalHeader, capdus[numCapdus - 1], 4);

	// Sum data length and detect Le from last
	for (i = 0; i < numCapdus; ++i) {
		DWORD ilc = 0, ile = 0;
		BYTE icase = 0;
		if (parse_apdu_case(capdus[i], capduLengths[i], &icase, &ilc, &ile)) {
			OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND, OPGP_stringify_error(OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND));
			goto end;
		}
		totalData += ilc;
		if (i == numCapdus - 1) {
			if (icase == 2 || icase == 4) { haveLe = 1; le = ile; }
		}
	}

	// Build concatenated APDU
	concatLen = 4 + (totalData > 0 ? ((totalData > 255) ? 3 : 1) : 0) + totalData + (haveLe ? ((totalData > 255) ? 2 : 1) : 0);
	concat = (PBYTE)malloc(concatLen);
	if (!concat) { OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
	memcpy(concat, logicalHeader, 4);
	pos = 4;
	if (totalData > 255) {
		concat[pos++] = 0x00;
		concat[pos++] = (BYTE)((totalData >> 8) & 0xFF);
		concat[pos++] = (BYTE)(totalData & 0xFF);
	} else if (totalData > 0) {
		concat[pos++] = (BYTE)totalData;
	}
	for (i = 0; i < numCapdus; ++i) {
		DWORD ilc = 0, ile = 0; BYTE icase = 0; DWORD ihlen = 5;
		parse_apdu_case(capdus[i], capduLengths[i], &icase, &ilc, &ile);
		if (capduLengths[i] >= 7 && capdus[i][4] == 0) ihlen = 7;
		memcpy(concat + pos, capdus[i] + ihlen, ilc);
		pos += ilc;
	}
	if (haveLe) {
		if (totalData > 255) {
			// extended Le, store as two-byte
			concat[pos++] = (BYTE)((le >> 8) & 0xFF);
			concat[pos++] = (BYTE)(le & 0xFF);
		} else {
			concat[pos++] = (BYTE)(le & 0xFF);
		}
	}
	concatLen = pos;

	// Wrap once
	OPGP_LOG_HEX(_T("OPGP_send_chained_APDU: Command --> "), concat, concatLen);
	if (traceEnable) {
		_ftprintf(traceFile, _T("Command --> "));
		for (i = 0; i < concatLen; i++) {
			_ftprintf(traceFile, _T("%02X"), concat[i] & 0x00FF);
		}
		_ftprintf(traceFile, _T("\n"));
	}

	wrappedLen = concatLen + 128; // generous buffer for encryption/MAC
	wrapped = (PBYTE)malloc(wrappedLen);
	if (!wrapped) { OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
	{
		DWORD tmpLen = wrappedLen;
		status = wrap_command(concat, concatLen, wrapped, &tmpLen, secInfo);
		if (OPGP_ERROR_CHECK(status)) { goto end; }
		wrappedLen = tmpLen;
	}

	if (traceEnable) {
		_ftprintf(traceFile, _T("Wrapped command --> "));
		for (i = 0; i < wrappedLen; i++) {
			_ftprintf(traceFile, _T("%02X"), wrapped[i] & 0x00FF);
		}
		_ftprintf(traceFile, _T("\n"));
	}

	// Determine wrapped header/data
	{
		BYTE wcase = 0; DWORD wlc = 0, wle = 0; DWORD whlen = 5;
		if (parse_apdu_case(wrapped, wrappedLen, &wcase, &wlc, &wle)) {
			OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND, OPGP_stringify_error(OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND));
			goto end;
		}
		if (wrappedLen >= 7 && wrapped[4] == 0) whlen = 7;
		wrappedLc = wlc;
		wrappedData = wrapped + whlen;
		// Overwrite CLA in output with wrapped CLA incl. security/channel bits
	}

	// Now split the wrapped APDU into "short" chunks and send via plugin
	{
		DWORD remaining = wrappedLc;
		DWORD chunkIdx;
		DWORD sendLen;
		PBYTE tmpResp = rapdu;
		DWORD tmpRespLen;
		for (chunkIdx = 0; chunkIdx < numCapdus; ++chunkIdx) {
			BOOL isLast = (chunkIdx == numCapdus - 1);
			sendLen = remaining;
			if (!isLast && sendLen > 255) sendLen = 255;
			if (!isLast && sendLen == 0) sendLen = 0; // safety
			// Build transport APDU chunk
			BYTE header[5];
			memcpy(header, capdus[chunkIdx], 4);
			header[0] = wrapped[0] | cardInfo.logicalChannel; // copy CLA from wrapped and apply logical channel
			// Lc one byte
			header[4] = (BYTE)sendLen;
			DWORD capduChunkLen = 5 + sendLen + ((isLast && haveLe) ? 1 : 0);
			PBYTE capduChunk = (PBYTE)malloc(capduChunkLen);
			if (!capduChunk) { OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
			memcpy(capduChunk, header, 5);
			memcpy(capduChunk + 5, wrappedData + (wrappedLc - remaining), sendLen);
			if (isLast && haveLe) {
				capduChunk[5 + sendLen] = 0x00; // request all available
			}
			// Send via plugin
			tmpRespLen = *rapduLength;

			OPGP_LOG_HEX(_T("OPGP_send_chained_APDU: Command --> "), capduChunk, capduChunkLen);
			if (traceEnable) {
				_ftprintf(traceFile, _T("Command --> "));
				for (i = 0; i < capduChunkLen; i++) {
					_ftprintf(traceFile, _T("%02X"), capduChunk[i] & 0x00FF);
				}
				_ftprintf(traceFile, _T("\n"));
			}

			status = (*plugin_sendAPDUFunction)(cardContext, cardInfo, capduChunk, capduChunkLen, tmpResp, &tmpRespLen);

			OPGP_LOG_HEX(_T("OPGP_send_chained_APDU: Response <-- "), tmpResp, tmpRespLen);
			if (traceEnable) {
				_ftprintf(traceFile, _T("Response <-- "));
				for (i = 0; i < tmpRespLen; i++) {
					_ftprintf(traceFile, _T("%02X"), tmpResp[i] & 0x00FF);
				}
				_ftprintf(traceFile, _T("\n"));
			}

			free(capduChunk);
			if (OPGP_ERROR_CHECK(status)) { goto end; }
			// For intermediate chunks, ignore response. For last, store result in caller's buffer
			if (isLast) {
				errorCode = status.errorCode;

				*rapduLength = tmpRespLen;
				// After final response, unwrap once using the concatenated original APDU
				status = unwrap_command(concat, concatLen, tmpResp, tmpRespLen, rapdu, rapduLength, secInfo);
				if (OPGP_ERROR_CHECK(status)) { goto end; }

				status.errorCode = errorCode;
				if (traceEnable) {
					_ftprintf(traceFile, _T("Unwrapped response <-- "));
					for (i = 0; i < *rapduLength; i++) {
						_ftprintf(traceFile, _T("%02X"), rapdu[i] & 0x00FF);
					}
					_ftprintf(traceFile, _T("\n"));
				}
			}
			remaining -= sendLen;
		}
	}
end:
	if (wrapped) free(wrapped);
	if (concat) free(concat);
	OPGP_LOG_END(_T("OPGP_send_chained_APDU"), status);
	return status;
}
