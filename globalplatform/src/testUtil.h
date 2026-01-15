/*
 *  Copyright (c) 2005-2026, Karsten Ohme
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
 */
#ifndef OPGP_TESTUTIL_H
#define OPGP_TESTUTIL_H

#ifdef __cplusplus
extern "C"
{
#endif

// MSVC does not the linker wrap flag to mock functions, it must be done in the code by using #pragma comment(linker, "/alternatename:real_foo=foo")
// https://stackoverflow.com/questions/33790425/visual-studio-c-linker-wrap-option
//#if _MSC_VER
//#define RAND_bytes real_RAND_bytes
//#include <openssl/rand.h>
//#undef RAND_bytes
//#pragma comment(linker, "/alternatename:real_RAND_bytes=RAND_bytes")
//#endif

//#define RAND_bytes __wrap_RAND_bytes

#include "globalplatform/globalplatform.h"

void mock_setup();

void hex_to_byte_array(OPGP_CSTRING hexString, PBYTE buffer, PDWORD bufferLength);

int __wrap_RAND_bytes(unsigned char *buf, int num);

OPGP_ERROR_STATUS send_APDU(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, PBYTE capdu, DWORD capduLength, PBYTE rapdu, PDWORD rapduLength);

void enqueue_commands(OPGP_CSTRING *commands, OPGP_CSTRING *responses, int size);

#ifdef __cplusplus
}
#endif

#endif
