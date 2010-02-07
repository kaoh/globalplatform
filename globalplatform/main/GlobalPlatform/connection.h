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
#include <PCSC/winscard.h>
#include "types.h"
#include "library.h"
#include "security.h"
#include "error.h"

#if !defined __winscard_h__
#define MAX_ATR_SIZE 32 //!< Maximum ATR size
#endif

#define OPGP_TRACE_MODE_ENABLE 1 //!< Switch trace mode on
#define OPGP_TRACE_MODE_DISABLE 0 //!< Switch trace mode off

#define OPGP_CARD_PROTOCOL_T0 SCARD_PROTOCOL_T0 //!< Transport protocol T=0
#define OPGP_CARD_PROTOCOL_T1 SCARD_PROTOCOL_T1 //!< Transport protocol T=1

/**
 * Structure for holding all connection related functions for connection plugin libraries.
 */
typedef struct
{
	PVOID establishContext; //!< Function to establish the context.
	PVOID releaseContext; //!< Function to release the context.
	PVOID cardConnect; //!< Function to connect to the card.
	PVOID cardDisconnect; //!< Function to disconnect from the card.
	PVOID listReaders; //!< Function to list the readers.
	PVOID sendAPDU; //!< Function to send an APDU.

} OPGP_CONNECTION_FUNCTIONS;

/**
 * Card context necessary for #establish_context().
 */
typedef struct {
	PVOID librarySpecific; //!< Library specific data.
	TCHAR libraryName[32]; //!< The name of the connection library to use.
	PVOID libraryHandle; //!< The handle to the library.
	OPGP_CONNECTION_FUNCTIONS connectionFunctions; //!< Connection functions of the connection library. Is automatically filled in if the connection library can be loaded correctly.
} OPGP_CARD_CONTEXT;

/**
 * The card information returned by a card_connect() and modified by select_channel().
 */
typedef struct {
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

//! \brief This function establishes a context to connection layer.
OPGP_API
OPGP_ERROR_STATUS OPGP_establish_context(OPGP_CARD_CONTEXT *cardContext);

//! \brief This function releases the context to the connection layer established by establish_context().
OPGP_API
OPGP_ERROR_STATUS OPGP_release_context(OPGP_CARD_CONTEXT *cardContext);

//! \brief This function returns a list of currently available readers.
OPGP_API
OPGP_ERROR_STATUS OPGP_list_readers(OPGP_CARD_CONTEXT cardContext, OPGP_STRING readerNames, PDWORD readerNamesLength);

//! \brief This function connects to a reader.
OPGP_API
OPGP_ERROR_STATUS OPGP_card_connect(OPGP_CARD_CONTEXT cardContext, OPGP_CSTRING readerName, OPGP_CARD_INFO *cardInfo, DWORD protocol);

//! \brief This function disconnects a reader.
OPGP_API
OPGP_ERROR_STATUS OPGP_card_disconnect(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO *cardInfo);

//! \brief This function sends an APDU.
OPGP_API
OPGP_ERROR_STATUS OPGP_send_APDU(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, PBYTE capdu, DWORD capduLength, PBYTE rapdu, PDWORD rapduLength);

#ifdef __cplusplus
}
#endif
#endif
