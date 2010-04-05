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

#include "util.h"
#include <string.h>

/**
 * \param b [in] The Le BYTE.
 * \return Value of b.
 */
DWORD convert_byte(BYTE b) {
	return (b == 0) ? 256 : b;
}

/**
 * \param buf [in] The buffer.
 * \param offset [in] The offset in the buffer.
 * \return the short int value.
 */
DWORD get_short(PBYTE buf, DWORD offset) {
	return ((buf[offset] & 0xFF) << 8) | (buf[offset+1] & 0xFF);
}

/**
 * \param buffer [in] The buffer.
 * \param length [in] The length of the buffer.
 * \param *tlv [out] the returned TLV struct.
 * \return -1 in case of error, consumed length otherwise.
 */
LONG read_TLV(PBYTE buffer, DWORD length, TLV *tlv) {
	LONG result;
	if (length < 2) {
		result = -1;
		goto end;
	}
	tlv->tag = buffer[0];
	tlv->length = buffer[1];
	if (tlv->length > 127) {
		result = -1;
		goto end;
	}
	if (length - 2 < tlv->length) {
		result = -1;
		goto end;
	}
	memcpy(tlv->value, buffer+2, tlv->length);
	result = tlv->length + 2;
end:
	return result;
}

