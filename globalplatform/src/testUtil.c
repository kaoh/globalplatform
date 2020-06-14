/*  Copyright (c) 2020, Karsten Ohme
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include "testUtil.h"
#include "util.h"
#include <cmocka.h>

#define MIN(a,b) a < b ? a : b

void hex_to_byte_array(OPGP_CSTRING hexString, PBYTE buffer, PDWORD bufferLength) {
	OPGP_CSTRING pos = hexString;
    DWORD count;
     /* WARNING: no sanitization or error-checking whatsoever */
    DWORD hexStrLen = MIN(strlen(hexString)/2, *bufferLength);
    for (count = 0; count < hexStrLen; count++) {
        sscanf(pos, "%2hhx", &buffer[count]);
        pos += 2;
    }
    *bufferLength = count;
}

int __wrap_RAND_bytes(unsigned char *buf, int num) {
	BYTE *__random = (BYTE *) mock();
	check_expected(num);
	memcpy(buf, __random,  num);
	return 1;
}

OPGP_ERROR_STATUS send_APDU(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, PBYTE capdu, DWORD capduLength, PBYTE rapdu, PDWORD rapduLength) {
	OPGP_ERROR_STATUS status;
	DWORD result;
	PBYTE __rapdu = (PBYTE) mock();
	PDWORD __rapduLength = (PDWORD) mock();
	check_expected(capdu);
	memcpy(rapdu, __rapdu, *__rapduLength);
	*rapduLength = *__rapduLength;
	result = get_short(rapdu, *rapduLength-2);
	OPGP_ERROR_CREATE_NO_ERROR_WITH_CODE(status, OPGP_ISO7816_ERROR_PREFIX | result, OPGP_stringify_error(OPGP_ISO7816_ERROR_PREFIX | result));
	return status;
}

void enqueue_commands(OPGP_CSTRING *commands, OPGP_CSTRING *responses, int size) {
	// prevent clean from heap after return
	static BYTE commandRequest[10][APDU_COMMAND_LEN];
	static BYTE commandResponse[10][APDU_RESPONSE_LEN];
	static DWORD commandRequestLen[10];
	static DWORD commandResponseLen[10];

	for (int i=0; i<size; i++) {
		commandRequestLen[i] = APDU_COMMAND_LEN;
		commandResponseLen[i] = APDU_RESPONSE_LEN;
		hex_to_byte_array(*(commands + i), commandRequest[i], &commandRequestLen[i]);
		hex_to_byte_array(*(responses + i), commandResponse[i], &commandResponseLen[i]);
		expect_memory(send_APDU, capdu, commandRequest[i], commandRequestLen[i]);
		will_return(send_APDU, commandResponse[i]);
		will_return(send_APDU, &commandResponseLen[i]);
	}
}

