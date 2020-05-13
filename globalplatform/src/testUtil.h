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
#include "globalplatform/globalplatform.h"

// This as a function gives a segmentation fault when accessing the responses
#define ENQUEUE_COMMANDS(commands, responses, numCommands) {\
	BYTE commandRequest[APDU_COMMAND_LEN];\
	DWORD commandRequestLen = APDU_COMMAND_LEN;\
	BYTE commandResponse[APDU_RESPONSE_LEN];\
	DWORD commandResponseLen = APDU_RESPONSE_LEN;\
	for (int i=0; i<numCommands; i++) {\
		commandRequestLen = APDU_COMMAND_LEN;\
		commandResponseLen = APDU_RESPONSE_LEN;\
		hex_to_byte_array(*(commands + i), commandRequest, &commandRequestLen);\
		hex_to_byte_array(*(responses + i), commandResponse, &commandResponseLen);\
		expect_memory(send_APDU, capdu, commandRequest, commandRequestLen);\
		will_return(send_APDU, commandResponse);\
		will_return(send_APDU, &commandResponseLen);\
	}\
}

void hex_to_byte_array(OPGP_CSTRING hexString, PBYTE buffer, PDWORD bufferLength);

int __wrap_RAND_bytes(unsigned char *buf, int num);

OPGP_ERROR_STATUS send_APDU(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, PBYTE capdu, DWORD capduLength, PBYTE rapdu, PDWORD rapduLength);
