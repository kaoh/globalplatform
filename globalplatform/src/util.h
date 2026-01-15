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
 * This file contains all GlobalPlatform utility functionality.
*/

#ifndef OPGP_UTIL_H
#define OPGP_UTIL_H

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef WIN32
#include "stdafx.h"
#endif

#include "globalplatform/types.h"
#include "globalplatform/library.h"

/**
 * A TLV object.
 **/
typedef struct {
	USHORT tag; //!< The Tag.
	DWORD length; //!< The length of the value.
	BYTE value[256]; //!< The value.
	PBYTE extendedValue; //!< The extended value if length > 256. Must be manually allocated and deallocated.
	DWORD tlvLength; //!< The length of the whole TLV.
} TLV;

//! \brief Reads a TLV struct from the given buffer
OPGP_NO_API
LONG read_TLV(PBYTE buffer, DWORD length, TLV *tlv);

//! \brief Converts a ISO 7816-4 Le Byte into its value.
OPGP_NO_API
DWORD convert_byte(BYTE b);

//! \brief Returns an unsigned short int from the given position
OPGP_NO_API
DWORD get_short(PBYTE buf, DWORD offset);

//! \brief Returns an unsigned int from the given position
OPGP_NO_API
DWORD get_int(PBYTE buf, DWORD offset);

//! \brief Returns an unsigned int from the given position by taking just numLength bytes starting at offset into account.
DWORD get_number(PBYTE buf, DWORD offset, BYTE numLength);

//! \brief Parse the APDU case.
OPGP_NO_API
LONG parse_apdu_case(PBYTE apduCommand, DWORD apduCommandLength, PBYTE caseAPDU, PBYTE lc, PBYTE le);

//! \brief Writes a TLV length field following DER BER rules.
OPGP_NO_API
LONG write_TLV_length(PBYTE buffer, DWORD offset, DWORD lengthLeft, USHORT length);

#ifdef __cplusplus
}
#endif

#endif
