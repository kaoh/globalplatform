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
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
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
