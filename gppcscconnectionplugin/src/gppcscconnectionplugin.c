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

/*! \mainpage GlobalPlatform PC/SC Connection Plugin
 *
 * \author Karsten Ohme
 * \section intro_sec Introduction
 * This plugin uses PC/SC to connect to a smart card.
 *
 */

#include <globalplatform/connectionplugin.h>
#include "gppcscconnectionplugin.h"
#include <globalplatform/debug.h>
#include <globalplatform/error.h>
#include <globalplatform/errorcodes.h>
#include <globalplatform/unicode.h>
#include <globalplatform/stringify.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"


#define CHECK_CARD_CONTEXT_INITIALIZATION(cardContext, status)	if (cardContext.librarySpecific == NULL) { OPGP_ERROR_CREATE_ERROR(status, OPGP_PL_ERROR_NO_CARD_CONTEXT_INITIALIZED, OPGP_PL_stringify_error(OPGP_PL_ERROR_NO_CARD_CONTEXT_INITIALIZED)); goto end;}

#define CHECK_CARD_INFO_INITIALIZATION(cardInfo, status)	if (cardInfo.librarySpecific == NULL) { OPGP_ERROR_CREATE_ERROR(status, OPGP_PL_ERROR_NO_CARD_INFO_INITIALIZED, OPGP_PL_stringify_error(OPGP_PL_ERROR_NO_CARD_INFO_INITIALIZED)); goto end;}

/**
 * Handles the error status for the result.
 */
#define HANDLE_STATUS(status, result) if (result != SCARD_S_SUCCESS) {\
		OPGP_ERROR_CREATE_ERROR(status,result,OPGP_PL_stringify_error((DWORD)result));\
	}\
	else {\
		OPGP_ERROR_CREATE_NO_ERROR(status);\
	}

/**
 * Convenience function to get the SCARDCONTEXT from a pointer to OPGP_CARD_CONTEXT struct.
 * @param pContext The pointer to a OPGP_CARD_CONTEXT struct.
 */
#define GET_SCARDCONTEXT_P(pContext) ((PCSC_CARD_CONTEXT_SPECIFIC *)(pContext->librarySpecific))->cardContext

/**
 * Convenience function to get the SCARDCONTEXT from a OPGP_CARD_CONTEXT struct.
 * @param context The OPGP_CARD_CONTEXT struct.
 */
#define GET_SCARDCONTEXT(context) ((PCSC_CARD_CONTEXT_SPECIFIC *)(context.librarySpecific))->cardContext

/**
 * Convenience function to get a reference to the PCSC_CARD_INFO_SPECIFIC from a pointer to OPGP_CARD_INFO struct.
 * @param pCardInfo The pointer to a OPGP_CARD_INFO struct.
 */
#define GET_PCSC_CARD_INFO_SPECIFIC_P(pCardInfo) ((PCSC_CARD_INFO_SPECIFIC *)(pCardInfo->librarySpecific))

/**
 * Convenience function to get a reference to the PCSC_CARD_INFO_SPECIFIC from a OPGP_CARD_INFO struct.
 * @param pCardInfo The pointer to a OPGP_CARD_INFO struct.
 */
#define GET_PCSC_CARD_INFO_SPECIFIC(cardInfo) ((PCSC_CARD_INFO_SPECIFIC *)(cardInfo.librarySpecific))

/**
 * Memory is allocated in this method for the card context. It must be freed with a call to #OPGP_PL_release_context.
 * \param cardContext [out] The returned OPGP_CARDCONTEXT.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_PL_establish_context(OPGP_CARD_CONTEXT *cardContext) {
	OPGP_ERROR_STATUS status;
	LONG result;
	OPGP_LOG_START(_T("OPGP_PL_establish_context"));
	cardContext->librarySpecific = malloc(sizeof(PCSC_CARD_CONTEXT_SPECIFIC));
	if (cardContext->librarySpecific == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
		goto end;
	}
	result = SCardEstablishContext( SCARD_SCOPE_USER,
									NULL,
									NULL,
									&GET_SCARDCONTEXT_P(cardContext)
									);
	HANDLE_STATUS(status, result);
end:
	OPGP_LOG_END(_T("OPGP_PL_establish_context"), status);
	return status;
}

/**
 * \param cardContext [in, out] The valid OPGP_CARDCONTEXT returned by establish_context()
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_PL_release_context(OPGP_CARD_CONTEXT *cardContext) {
	OPGP_ERROR_STATUS status;
	LONG result;
	OPGP_LOG_START(_T("OPGP_PL_release_context"));
	CHECK_CARD_CONTEXT_INITIALIZATION((*cardContext), status)
	result = SCardReleaseContext(GET_SCARDCONTEXT((*cardContext)));
	HANDLE_STATUS(status, result);
	// frees the allocated memory
	if (cardContext->librarySpecific != NULL) {
		free(cardContext->librarySpecific);
		cardContext->librarySpecific = NULL;
	}
end:
	OPGP_LOG_END(_T("OPGP_PL_release_context"), status);
	return status;
}

/**
 * \param cardContext [in] The valid OPGP_CARDCONTEXT returned by establish_context()
 * \param readerNames [out] The reader names will be a multi-string and separated by a NULL character and ended by a double NULL.
 *  (ReaderA\\0ReaderB\\0\\0). If this value is NULL, list_readers ignores the buffer length supplied in
 *  readerNamesLength, writes the length of the multi-string that would have been returned if this parameter
 *  had not been NULL to readerNamesLength.
 * \param readerNamesLength [in, out] The length of the multi-string including all trailing null characters.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_PL_list_readers(OPGP_CARD_CONTEXT cardContext, OPGP_STRING readerNames, PDWORD readerNamesLength) {
	OPGP_ERROR_STATUS status;
	LONG result = SCARD_S_SUCCESS;
	DWORD readersSize = 0;
	OPGP_STRING readers = NULL;
	OPGP_LOG_START(_T("OPGP_PL_list_readers"));
	CHECK_CARD_CONTEXT_INITIALIZATION(cardContext, status)
	result = SCardListReaders(GET_SCARDCONTEXT(cardContext), NULL, NULL, &readersSize );
	if ( SCARD_S_SUCCESS != result ) {
		goto end;
	}
#ifdef DEBUG
	OPGP_log_Msg(_T("OPGP_PL_list_readers: readerSize: %d"), readersSize);
#endif
	if (readerNames == NULL) {
		*readerNamesLength = readersSize;
		result = SCARD_S_SUCCESS;
		goto end;
	}
	readers = (OPGP_STRING)malloc(sizeof(TCHAR)*readersSize);
	if (readers == NULL) {
		result = ENOMEM;
		goto end;
	}

	result = SCardListReaders(GET_SCARDCONTEXT(cardContext), NULL, readers, &readersSize);
	if ( SCARD_S_SUCCESS != result ) {
		goto end;
	}
	if (*readerNamesLength < readersSize) {
		_tcsncpy(readerNames, readers, (*readerNamesLength)-2);
		*(readerNames+(*readerNamesLength)-2) = _T('\0');
		*(readerNames+(*readerNamesLength)-1) = _T('\0');
		*readerNamesLength = readersSize;
	}
	else {
		memcpy(readerNames, readers, sizeof(TCHAR)*readersSize);
		*readerNamesLength = readersSize;
	}
end:
	if (readers) {
		free(readers);
	}
	HANDLE_STATUS(status, result);
	OPGP_LOG_END(_T("OPGP_PL_list_readers"), status);
	return status;
}

/**
 * Memory is allocated in this method for the card context. It must be freed with a call to #OPGP_PL_card_disconnect.
 * If something is not working, you may want to change the protocol type.
 * \param cardContext [in] The valid OPGP_CARDCONTEXT returned by establish_context()
 * \param readerName [in] The name of the reader to connect.
 * \param *cardInfo [out] The returned OPGP_CARD_INFO.
 * \param protocol [in] The transmit protocol type to use. Can be OPGP_CARD_PROTOCOL_T0 or OPGP_CARD_PROTOCOL_T1 or both ORed.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct.
 */
OPGP_ERROR_STATUS OPGP_PL_card_connect(OPGP_CARD_CONTEXT cardContext, OPGP_CSTRING readerName, OPGP_CARD_INFO *cardInfo,
				  DWORD protocol) {
	OPGP_ERROR_STATUS status;
	LONG result = SCARD_S_SUCCESS;
    PCSC_CARD_INFO_SPECIFIC *pcscCardInfo;
	DWORD activeProtocol;
	DWORD state;
	DWORD dummy;
	BYTE ATR[32];
	DWORD ATRLength=32;
	TCHAR readerNameTemp[1024];
	DWORD readerNameTempLength = 1024;

	OPGP_LOG_START(_T("OPGP_PL_card_connect"));
	CHECK_CARD_CONTEXT_INITIALIZATION(cardContext, status)

	cardInfo->librarySpecific = malloc(sizeof(PCSC_CARD_INFO_SPECIFIC));
	if (cardInfo->librarySpecific == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
		goto end;
	}

	pcscCardInfo = GET_PCSC_CARD_INFO_SPECIFIC_P(cardInfo);

	result = SCardConnect( GET_SCARDCONTEXT(cardContext),
							readerName,
							SCARD_SHARE_SHARED,
							protocol,
							&(pcscCardInfo->cardHandle),
							&activeProtocol );
	if ( SCARD_S_SUCCESS != result ) {
		goto end;
	}

	result = SCardStatus(pcscCardInfo->cardHandle, readerNameTemp, &readerNameTempLength, &state, &dummy, ATR, &ATRLength);
	if ( SCARD_S_SUCCESS != result ) {
		goto end;
	}
	memcpy(cardInfo->ATR, ATR, MAX_ATR_SIZE);
	cardInfo->ATRLength = ATRLength;

	pcscCardInfo->protocol = dummy;
	pcscCardInfo->state = state;

#ifdef DEBUG
	OPGP_log_Msg(_T("OPGP_PL_card_connect: Connected to card in reader %s with protocol %d in card state %d"), readerName, pcscCardInfo->protocol, pcscCardInfo->state);
	OPGP_log_Hex(_T("OPGP_PL_card_connect: Card ATR: "), cardInfo->ATR, cardInfo->ATRLength);
#endif

	cardInfo->logicalChannel = 0;

end:
	HANDLE_STATUS(status, result);
	OPGP_LOG_END(_T("OPGP_PL_card_connect"), status);
	return status;
}

/**
 * \param cardContext [in] The valid OPGP_CARDCONTEXT returned by establish_context()
 * \param cardInfo [in, out] The OPGP_CARD_INFO structure returned by card_connect().
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct.
 */
OPGP_ERROR_STATUS OPGP_PL_card_disconnect(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO *cardInfo) {
	OPGP_ERROR_STATUS status;
	LONG result;
	OPGP_LOG_START(_T("OPGP_PL_card_disconnect"));
	CHECK_CARD_CONTEXT_INITIALIZATION(cardContext, status)
	CHECK_CARD_INFO_INITIALIZATION((*cardInfo), status)
	result = SCardDisconnect(GET_PCSC_CARD_INFO_SPECIFIC((*cardInfo))->cardHandle, SCARD_RESET_CARD);
	HANDLE_STATUS(status, result);
	// frees the allocated memory
	if (cardInfo->librarySpecific != NULL) {
		free(cardInfo->librarySpecific);
		cardInfo->librarySpecific = NULL;
	}
	cardInfo->ATRLength = 0;
end:
	OPGP_LOG_END(_T("OPGP_PL_card_disconnect"), status);
	return status;
}

/**
 * If the transmission is successful then the APDU status word is returned as errorCode in the OPGP_ERROR_STATUS structure.
 * \param cardContext [in] The valid OPGP_CARDCONTEXT returned by establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by card_connect().
 * \param capdu [in] The command APDU.
 * \param capduLength [in] The length of the command APDU.
 * \param rapdu [out] The response APDU.
 * \param rapduLength [in, out] The length of the the response APDU.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct.
 */
OPGP_ERROR_STATUS OPGP_PL_send_APDU(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, PBYTE capdu, DWORD capduLength, PBYTE rapdu, PDWORD rapduLength) {
	OPGP_ERROR_STATUS status;
	// modified for managing all 4 cases with automatic APDU chaining

	DWORD result;
	DWORD caseAPDU;
	BYTE lc;
	BYTE le=0;
	BYTE la;

	DWORD offset = 0;

	PBYTE responseData = NULL;
	DWORD responseDataLength = *rapduLength;
	DWORD tempDataLength = 0;

	OPGP_LOG_START(_T("OPGP_PL_send_APDU"));
	CHECK_CARD_CONTEXT_INITIALIZATION(cardContext, status)
	CHECK_CARD_INFO_INITIALIZATION(cardInfo, status)
	responseData = (PBYTE)malloc(sizeof(BYTE)*responseDataLength);
	if (responseData == NULL) {
		result = ENOMEM;
		HANDLE_STATUS(status, result);
		goto end;
	}

	// if T=1 or else T=0
	if (GET_PCSC_CARD_INFO_SPECIFIC(cardInfo)->protocol == SCARD_PROTOCOL_T1) {

		// T=1 transmission

		result = SCardTransmit(GET_PCSC_CARD_INFO_SPECIFIC(cardInfo)->cardHandle,
				SCARD_PCI_T1,
				capdu,
				capduLength,
				NULL,
				responseData,
				&responseDataLength
				);
		if (SCARD_S_SUCCESS != result) {
			HANDLE_STATUS(status, result);
			goto end;
		} // if ( SCARD_S_SUCCESS != result)
        offset += responseDataLength - 2;
	} else {
		// Determine which type of Exchange between the reader
		if (capduLength == 4) {
		// Case 1 short

		caseAPDU = 1;
		} else if (capduLength == 5) {
		// Case 2 short

		caseAPDU = 2;
		le = capdu[4];
		} else {
			lc = capdu[4];
			if ((convert_byte(lc) + 5) == capduLength) {
			// Case 3 short

			caseAPDU = 3;
			} else if ((convert_byte(lc) + 5 + 1) == capduLength) {
			// Case 4 short

			caseAPDU = 4;

			le = capdu[capduLength - 1];
			capduLength--;
			} else {
				result = OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND;
				HANDLE_STATUS(status, result);
				goto end;
			}
		} // if (Determine which type of Exchange)

		// T=0 transmission (first command)

		responseDataLength = *rapduLength;
		result = SCardTransmit(GET_PCSC_CARD_INFO_SPECIFIC(cardInfo)->cardHandle,
				SCARD_PCI_T0,
				capdu,
				capduLength,
				NULL,
				responseData,
				&responseDataLength
				);
		if ( SCARD_S_SUCCESS != result) {
			HANDLE_STATUS(status, result);
			goto end;
		} // if ( SCARD_S_SUCCESS != result)
		offset += responseDataLength - 2;
		// main switch block for cases 2 and 4

		switch (caseAPDU) {
			case 2: {

				while ((responseData[offset] == 0x61)
					|| (responseData[offset] == 0x6c)) {

					//Le is not accepted by the card and the card indicates the available length La.
					//The response TPDU from the card indicates that the command is aborted due to
					//a wrong length and that the right length is La: (SW1='6C' and SW2 codes La).

					if (responseData[offset] == 0x6c) {

						la = responseData[offset + 1];

						capdu[capduLength-1] = la; // P3

						// T=0 transmission (command w/ La)

						responseDataLength = *rapduLength - offset;
						result = SCardTransmit(GET_PCSC_CARD_INFO_SPECIFIC(cardInfo)->cardHandle,
								SCARD_PCI_T0,
								capdu,
								capduLength,
								NULL,
								responseData+offset,
								&responseDataLength
								);
						if ( SCARD_S_SUCCESS != result) {
							HANDLE_STATUS(status, result);
							goto end;
						}

						// If La is greater that Le, then the response TPDU is mapped
						// onto the response APDU by keeping only the first Le bytes
						// of the body and the status bytes SW1-SW2.

						if (convert_byte(le) < convert_byte(la)) {
							memmove(responseData+offset+convert_byte(le), responseData+offset+responseDataLength-2, 2);
							offset += convert_byte(le);
							break;
						} // if (convert_byte(le) < convert_byte(la))
						offset += responseDataLength - 2;
						le = la;
						continue;

					} // if (6C)

					// Java Card specific. Java Card RE Specification Chapter 9

					// if (61)

					if (responseData[offset] == 0x61) {

						// Lr < Le
						// 1. The card sends <0x61,Lr> completion status bytes
						// 2. The CAD sends GET RESPONSE command with Le = Lr.
						// 3. The card sends Lr bytes of output data using the standard T=0 <INS> or <~INS>
						// procedure byte mechanism.
						// 4. The card sends <SW1,SW2> completion status on completion of the
						// Applet.process method.

						// Lr > Le
						// 1. The card sends Le bytes of output data using the standard T=0 <INS> or
						// <~INS> procedure byte mechanism.
						// 2. The card sends <0x61,(Lr-Le)> completion status bytes
						// 3. The CAD sends GET RESPONSE command with new Le <= Lr.
						// 4. The card sends (new) Le bytes of output data using the standard T=0 <INS> or
						// <~INS> procedure byte mechanism.
						// 5. Repeat steps 2-4 as necessary to send the remaining output data bytes (Lr) as
						// required.
						// 6. The card sends <SW1,SW2> completion status on completion of the
						// Applet.process method.

						// These two cases behave the same way
						la = responseData[offset + 1];

						capdu[0] = 0x00;;
						capdu[1] = 0xC0; // INS (Get Response)
						capdu[2] = 0x00; // P1
						capdu[3] = 0x00; // P2
						capdu[4] = la;
						capduLength = 5;
						le = la;
						// T=0 transmission (command w/ La)

						responseDataLength = *rapduLength - offset;
						result = SCardTransmit(GET_PCSC_CARD_INFO_SPECIFIC(cardInfo)->cardHandle,
								SCARD_PCI_T0,
								capdu,
								capduLength,
								NULL,
								responseData+offset,
								&responseDataLength
								);
						if ( SCARD_S_SUCCESS != result) {
							HANDLE_STATUS(status, result);
							goto end;
						} // if ( SCARD_S_SUCCESS != result)
						offset += responseDataLength - 2;
						continue;
					} // if (61)
				} // while (61) || (6c)
			break;
			} // case 2

			case 4: {

				/* Note: Some smartcard are not fully compatible
					with ISO normatives in case short 4.
					So when a card returns a 0x9000 to inform a good
					transfer of the APDU command then the terminal
					have to terminate the transaction and it shall
					return the sw1 sw2 to the user. In the case of
					fully ISO, the terminal sends a get response
					to extract the "le" bytes requested inside
					the APDU command. */

				// if 61 etc.

				if (responseData[offset] == 0x61
					|| responseData[offset] == 0x90
					|| responseData[offset] == 0x9F) {

					capdu[0] = 0x00;
					capdu[1] = 0xC0; // INS (Get Response)
					capdu[2] = 0x00; // P1
					capdu[3] = 0x00; // P2
					capduLength = 5;

					// Default Case Le is requested in the get response

					capdu[4] = le; // P3

					// verify if we have La < Le in the case of sw2 = 0x61 or 0x9f

					if (responseData[offset] != 0x90) {
						if (convert_byte(responseData[offset + 1]) < convert_byte(le)) {
						// La is requested in the get response

						capdu[4] = responseData[offset + 1];
						le = responseData[offset + 1];
						}
					}

					// T=0 transmission (command w/ Le or La)

					responseDataLength = *rapduLength - offset;

					// copy the data to an intermediate buffer to restore it in case of a broken ISO implementation not supporting GET RESPONSE on 0x9000
					memcpy(responseData, rapdu, offset + 2);
					tempDataLength = offset + 2;

					result = SCardTransmit(GET_PCSC_CARD_INFO_SPECIFIC(cardInfo)->cardHandle,
							SCARD_PCI_T0,
							capdu,
							capduLength,
							NULL,
							responseData+offset,
							&responseDataLength
							);
					if ( SCARD_S_SUCCESS != result) {
						HANDLE_STATUS(status, result);
						goto end;
					} // if ( SCARD_S_SUCCESS != result)
					result = get_short(rapdu, *rapduLength-2);
					// if the result is 0x6E00 then this should be a broken ISO implementation not supporting GET RESPONSE on 0x9000 and we return the previous response data
					if (result == 0x6E00) {
						memcpy(rapdu, responseData, tempDataLength);
						responseDataLength = tempDataLength;
					}
					offset += responseDataLength - 2;

				} // if (61 etc.)

				while ((responseData[offset] == 0x61)
					|| (responseData[offset] == 0x6c)
					|| (responseData[offset] == 0x9f)) {

					// if (6c)

					if (responseData[offset ] == 0x6c) {

						la = responseData[offset + 1];
						capdu[capduLength -1] = la; // P3

						// T=0 transmition (command w/ La)

						responseDataLength = *rapduLength - offset;
						result = SCardTransmit(GET_PCSC_CARD_INFO_SPECIFIC(cardInfo)->cardHandle,
								SCARD_PCI_T0,
								capdu,
								capduLength,
								NULL,
								responseData+offset,
								&responseDataLength
								);
						if ( SCARD_S_SUCCESS != result) {
							HANDLE_STATUS(status, result);
							goto end;
						}

						// If La is greater that Le, then the response TPDU is mapped
						// onto the response APDU by keeping only the first Le bytes
						// of the body and the status bytes SW1-SW2.

						if (convert_byte(le) < convert_byte(la)) {
							memmove(responseData+offset+convert_byte(le), responseData+offset+responseDataLength-2, 2);
							offset += convert_byte(le);
							break;
						} // if (convert_byte(le) < convert_byte(la))
						offset += responseDataLength - 2;
						le = la;
						continue;

					} // if (6c)

					// if (61) || (9f)

					if ((responseData[offset] == 0x61)
					|| (responseData[offset] == 0x9f)) {

						// Lr < Le
						// 1. The card sends <0x61,Lr> completion status bytes
						// 2. The CAD sends GET RESPONSE command with Le = Lr.
						// 3. The card sends Lr bytes of output data using the standard T=0 <INS> or <~INS>
						// procedure byte mechanism.
						// 4. The card sends <SW1,SW2> completion status on completion of the
						// Applet.process method.

						// Lr > Le
						// 1. The card sends Le bytes of output data using the standard T=0 <INS> or
						// <~INS> procedure byte mechanism.
						// 2. The card sends <0x61,(Lr-Le)> completion status bytes
						// 3. The CAD sends GET RESPONSE command with new Le <= Lr.
						// 4. The card sends (new) Le bytes of output data using the standard T=0 <INS> or
						// <~INS> procedure byte mechanism.
						// 5. Repeat steps 2-4 as necessary to send the remaining output data bytes (Lr) as
						// required.
						// 6. The card sends <SW1,SW2> completion status on completion of the
						// Applet.process method.

						la = responseData[offset + 1];

						capdu[0] = 0x00;
						capdu[1] = 0xC0; // INS (Get Response)
						capdu[2] = 0x00; // P1
						capdu[3] = 0x00; // P2
						capdu[4] = la;
						capduLength = 5;
						le = la;
						// T=0 transmission (command w/ La)

						responseDataLength = *rapduLength - offset;
						result = SCardTransmit(GET_PCSC_CARD_INFO_SPECIFIC(cardInfo)->cardHandle,
								SCARD_PCI_T0,
								capdu,
								capduLength,
								NULL,
								responseData+offset,
								&responseDataLength
								);
						if ( SCARD_S_SUCCESS != result) {
							HANDLE_STATUS(status, result);
							goto end;
						}
						offset += responseDataLength - 2;
						continue;

					} // if (61) || (9f)

				} // while (61) || (6c) || (9f)

			break;
			} // case 4

		} // switch (main switch block for cases 2 and 4)

	} // if (if T=1 or else T=0)

	// if the case 3 command is actually a case 4 command and the cards wants to responds something.

	if (responseData[offset] == 0x61) {

		la = responseData[offset + 1];

		capdu[0] = 0x00;;
		capdu[1] = 0xC0; // INS (Get Response)
		capdu[2] = 0x00; // P1
		capdu[3] = 0x00; // P2
		capdu[4] = la;
		capduLength = 5;
		le = la;
		// T=0 transmission (command w/ La)

		responseDataLength = *rapduLength - offset;
		result = SCardTransmit(GET_PCSC_CARD_INFO_SPECIFIC(cardInfo)->cardHandle,
				GET_PCSC_CARD_INFO_SPECIFIC(cardInfo)->protocol == OPGP_CARD_PROTOCOL_T0 ? SCARD_PCI_T0 : SCARD_PCI_T1,
				capdu,
				capduLength,
				NULL,
				responseData+offset,
				&responseDataLength
				);
		if ( SCARD_S_SUCCESS != result) {
			HANDLE_STATUS(status, result);
			goto end;
		} // if ( SCARD_S_SUCCESS != result)
		offset += responseDataLength - 2;
	} // if (61)

	memcpy(rapdu, responseData, offset + 2);
	*rapduLength = offset + 2;

	// get SW
	result = get_short(rapdu, *rapduLength-2);

	OPGP_ERROR_CREATE_NO_ERROR_WITH_CODE(status, OPGP_ISO7816_ERROR_PREFIX | result, OPGP_stringify_error(OPGP_ISO7816_ERROR_PREFIX | result));
end:
	if (responseData) {
		free(responseData);
	}
	OPGP_LOG_END(_T("OPGP_PL_send_APDU"), status);
	return status;
}

/**
 * \param errorCode [in] The error code.
 * \return OPGP_STRING representation of the error code.
 */
OPGP_STRING OPGP_PL_stringify_error(DWORD errorCode) {
	if (errorCode == OPGP_PL_ERROR_NO_CARD_CONTEXT_INITIALIZED) {
		return (OPGP_STRING)_T("PC/SC plugin is not initialized. A card context must be established first.");
	}
	if (errorCode == OPGP_PL_ERROR_NO_CARD_INFO_INITIALIZED) {
		return (OPGP_STRING)_T("PC/SC plugin is not initialized. A card connection must be created first.");
	}
	#ifndef WIN32
		if ((errorCode & ((DWORD)0xFFF00000L)) == ((DWORD)0x80100000L)) {
			return (OPGP_STRING)pcsc_stringify_error((long)(errorCode & 0xFFFFFFFF));
		}
	#endif
	// delegate to general stringify function
	return OPGP_stringify_error(errorCode);
}
