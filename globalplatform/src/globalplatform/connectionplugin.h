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
 * This file defines all connection plugin related type definitions and must be implemented by plugins.
 * <p>
 * For errors of the plugins use the #OPGP_PL_ERROR_PREFIX prefix.
 *
 *
*/

#ifndef OPGP_CONNECTION_PLUGIN_H
#define OPGP_CONNECTION_PLUGIN_H

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef WIN32
#include "stdafx.h"
#endif

#include "connection.h"
#include "error.h"
#include "library.h"

#define OPGP_PL_ERROR_PREFIX ((DWORD) 0x80500000) //!< Error prefix for errors of the plugin.

#define OPGP_PL_ERROR_NO_CARD_CONTEXT_INITIALIZED (OPGP_PL_ERROR_PREFIX | (DWORD)0x0001L) //!< The plugin is not initialized by executing #OPGP_PL_establish_context. Specific error message must be stringified in plugin implementation.
#define OPGP_PL_ERROR_NO_CARD_INFO_INITIALIZED (OPGP_PL_ERROR_PREFIX | (DWORD)0x0002L) //!< The plugin is not initialized by executing #OPGP_PL_card_connect. Specific error message must be stringified in plugin implementation.


//! \brief This function establishes a context to connection layer.
OPGP_PL_API
OPGP_ERROR_STATUS OPGP_PL_establish_context(OPGP_CARD_CONTEXT *cardContext);

//! \brief This function releases the context to the connection layer established by establish_context().
OPGP_PL_API
OPGP_ERROR_STATUS OPGP_PL_release_context(OPGP_CARD_CONTEXT *cardContext);

//! \brief This function returns a list of currently available readers.
OPGP_PL_API
OPGP_ERROR_STATUS OPGP_PL_list_readers(OPGP_CARD_CONTEXT cardContext, OPGP_STRING readerNames, PDWORD readerNamesLength);

//! \brief This function connects to a reader.
OPGP_PL_API
OPGP_ERROR_STATUS OPGP_PL_card_connect(OPGP_CARD_CONTEXT cardContext, OPGP_CSTRING readerName, OPGP_CARD_INFO *cardInfo, DWORD protocol);

//! \brief This function disconnects a reader.
OPGP_PL_API
OPGP_ERROR_STATUS OPGP_PL_card_disconnect(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO *cardInfo);

//! \brief This function sends an APDU.
OPGP_PL_API
OPGP_ERROR_STATUS OPGP_PL_send_APDU(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, PBYTE capdu, DWORD capduLength, PBYTE rapdu, PDWORD rapduLength);

#ifdef __cplusplus
}
#endif
#endif
