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
 * This file defines all PC/SC connection related type definitions.
*/

#ifndef OPGP_PCSC_CONNECTION_PLUGIN_H
#define OPGP_PCSC_CONNECTION_PLUGIN_H

#include <PCSC/winscard.h>
#include "../../main/GlobalPlatform/library.h"

/**
 * PC/SC specific context information. Used in #OPGP_CARD_CONTEXT.librarySpecific.
 */
typedef struct {
	SCARDCONTEXT cardContext; //!<  Reference to the reader resource manager.
} PCSC_CARD_CONTEXT_SPECIFIC;

/**
 * PC/SC specific card information. Used in #OPGP_CARD_INFO.librarySpecific.
 */
typedef struct {
	DWORD state; //!<  The mechanical state of the card.
	DWORD protocol; //!< The card protocol T0 or T1.
	SCARDHANDLE cardHandle; //!< Internal used card handle.
} PCSC_CARD_INFO_SPECIFIC;


/**
 * \brief Stringifies an error code.
 */
OPGP_API
OPGP_STRING OPGP_PL_stringify_error(DWORD errorCode);

#endif


