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
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU Lesser General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.
 */

/*! \file
 * This file contains all connection related functions.
 * The real functionality is implemented by plugins.
 */

#ifndef OPGP_CONNECTION_H
#define OPGP_CONNECTION_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#ifdef WIN32
#include <WinSCard.h>
#else
#include <winscard.h>
#endif
#include "unicode.h"
#include "types.h"
#include "library.h"
#include "security.h"
#include "error.h"

#if !defined __winscard_h__
#define MAX_ATR_SIZE 33 //!< Maximum ATR size
#endif

#define OPGP_TRACE_MODE_ENABLE 1 //!< Switch trace mode on
#define OPGP_TRACE_MODE_DISABLE 0 //!< Switch trace mode off

#define OPGP_CARD_PROTOCOL_T0 SCARD_PROTOCOL_T0 //!< Transport protocol T=0
#define OPGP_CARD_PROTOCOL_T1 SCARD_PROTOCOL_T1 //!< Transport protocol T=1

typedef struct OPGP_CARD_CONTEXT OPGP_CARD_CONTEXT;
typedef struct OPGP_CARD_INFO OPGP_CARD_INFO;

typedef OPGP_ERROR_STATUS (*OPGP_ESTABLISH_CONTEXT_FN)(OPGP_CARD_CONTEXT *);
typedef OPGP_ERROR_STATUS (*OPGP_RELEASE_CONTEXT_FN)(OPGP_CARD_CONTEXT *);
typedef OPGP_ERROR_STATUS (*OPGP_CARD_CONNECT_FN)(OPGP_CARD_CONTEXT, OPGP_CSTRING, OPGP_CARD_INFO *, DWORD);
typedef OPGP_ERROR_STATUS (*OPGP_CARD_DISCONNECT_FN)(OPGP_CARD_CONTEXT, OPGP_CARD_INFO *);
typedef OPGP_ERROR_STATUS (*OPGP_LIST_READERS_FN)(OPGP_CARD_CONTEXT, OPGP_STRING, PDWORD, DWORD);
typedef OPGP_ERROR_STATUS (*OPGP_SEND_APDU_FN)(OPGP_CARD_CONTEXT, OPGP_CARD_INFO, PBYTE, DWORD, PBYTE, PDWORD);

/**
 * Structure for holding all connection related functions for connection plugin libraries.
 */
typedef struct
{
	OPGP_ESTABLISH_CONTEXT_FN establishContext; //!< Function to establish the context.
	OPGP_RELEASE_CONTEXT_FN releaseContext; //!< Function to release the context.
	OPGP_CARD_CONNECT_FN cardConnect; //!< Function to connect to the card.
	OPGP_CARD_DISCONNECT_FN cardDisconnect; //!< Function to disconnect from the card.
	OPGP_LIST_READERS_FN listReaders; //!< Function to list the readers.
	OPGP_SEND_APDU_FN sendAPDU; //!< Function to send an APDU.

} OPGP_CONNECTION_FUNCTIONS;

/**
 * Card context necessary for #OPGP_establish_context().
 */
typedef struct OPGP_CARD_CONTEXT {
	PVOID librarySpecific; //!< Library specific data.
	TCHAR libraryName[64]; //!< The name of the connection library to use.
	TCHAR libraryVersion[32]; //!< The version of the connection library to use.
	PVOID libraryHandle; //!< The handle to the library.
	OPGP_CONNECTION_FUNCTIONS connectionFunctions; //!< Connection functions of the connection library. Is automatically filled in if the connection library can be loaded correctly.
} OPGP_CARD_CONTEXT;

/**
 * The card information returned by a #OPGP_card_connect() and modified by select_channel().
 */
typedef struct OPGP_CARD_INFO {
	BYTE ATR[MAX_ATR_SIZE]; //!< The Answer To Reset from the card.
	DWORD ATRLength; //!< The length of the ATR buffer.
	BYTE logicalChannel; //!< The current logical channel.
	BYTE specVersion; //!< The specification version, see #OP_201 or #GP_211.
	PVOID librarySpecific; //!< Specific data for the library.
} OPGP_CARD_INFO;

// functions

//! \brief Enables the trace mode.
OPGP_API
void OPGP_enable_trace_mode(DWORD enable, FILE *out);

extern DWORD traceEnable;
extern FILE *traceFile;

//! \brief This function establishes a context to connection layer.
OPGP_API
OPGP_ERROR_STATUS OPGP_establish_context(OPGP_CARD_CONTEXT *cardContext);

//! \brief This function releases the context to the connection layer established by #OPGP_establish_context().
OPGP_API
OPGP_ERROR_STATUS OPGP_release_context(OPGP_CARD_CONTEXT *cardContext);

//! \brief This function returns a list of currently available readers.
OPGP_API
OPGP_ERROR_STATUS OPGP_list_readers(OPGP_CARD_CONTEXT cardContext, OPGP_STRING readerNames, PDWORD readerNamesLength, DWORD presentOnly);

//! \brief This function connects to a reader.
OPGP_API
OPGP_ERROR_STATUS OPGP_card_connect(OPGP_CARD_CONTEXT cardContext, OPGP_CSTRING readerName, OPGP_CARD_INFO *cardInfo, DWORD protocol);

//! \brief This function disconnects a reader.
OPGP_API
OPGP_ERROR_STATUS OPGP_card_disconnect(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO *cardInfo);

//! \brief This function sends an APDU.
OPGP_API
OPGP_ERROR_STATUS OPGP_send_APDU(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, PBYTE capdu, DWORD capduLength, PBYTE rapdu, PDWORD rapduLength);

//! \brief This function sends multiple APDUs that belong to one logical command.
OPGP_API
OPGP_ERROR_STATUS OPGP_send_chained_APDU(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, PBYTE capdus[], DWORD capduLengths[], DWORD numCapdus, PBYTE rapdu, PDWORD rapduLength);

#ifdef __cplusplus
}
#endif
#endif
