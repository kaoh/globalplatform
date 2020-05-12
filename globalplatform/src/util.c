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
 * The tag must be coded on two octet and the length must be < 127.
 * \param buffer [in] The buffer.
 * \param length [in] The length of the buffer.
 * \param *tlv [out] the returned TLV struct.
 * \param numOctetsForTag [in] The number of octes for the tag. 1 or 2.
 * \return -1 in case of error, consumed length otherwise.
 */
static LONG _read_TLV(PBYTE buffer, DWORD length, TLV *tlv, DWORD numOctetsForTag) {
	LONG result;
	LONG tlSize = 1 + numOctetsForTag;
	if (numOctetsForTag != 1 && numOctetsForTag != 2) {
		result = -1;
		goto end;
	}

	if (length < tlSize) {
		result = -1;
		goto end;
	}
	if (numOctetsForTag == 1) {
		tlv->tag = buffer[0];
	}
	else {
		tlv->tag = get_short(buffer, 0);
	}
	tlv->length = buffer[tlSize-1];
	if (tlv->length > 127) {
		result = -1;
		goto end;
	}
	if (length - tlSize < tlv->length) {
		result = -1;
		goto end;
	}
	memcpy(tlv->value, buffer+tlSize, tlv->length);
	result = tlv->length + tlSize;
end:
	return result;
}

/**
 * The tag must be coded on one octet and the length must be < 127.
 * \param buffer [in] The buffer.
 * \param length [in] The length of the buffer.
 * \param *tlv [out] the returned TLV struct.
 * \return -1 in case of error, consumed length otherwise.
 */
LONG read_TLV(PBYTE buffer, DWORD length, TLV *tlv) {
	return _read_TLV(buffer, length, tlv, 1);
}

/**
 * The tag must be coded on two octet and the length must be < 127.
 * \param buffer [in] The buffer.
 * \param length [in] The length of the buffer.
 * \param *tlv [out] the returned TLV struct.
 * \return -1 in case of error, consumed length otherwise.
 */
LONG read_TTLV(PBYTE buffer, DWORD length, TLV *tlv) {
	return _read_TLV(buffer, length, tlv, 2);
}

