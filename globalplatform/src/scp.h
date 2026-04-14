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
 * version.
 */

/*! \file
 * This file contains internal Secure Channel Protocol handling for SCP01/SCP02/SCP03.
 */

#ifndef OPGP_SCP_H
#define OPGP_SCP_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "globalplatform/library.h"
#include "globalplatform/types.h"
#include "globalplatform/error.h"
#include "globalplatform/security.h"

typedef struct {
	BYTE keyInformationDataLength;
	BYTE cardChallenge[8];
	BYTE cardChallengeLength;
	BYTE sequenceCounter[3];
	BYTE sequenceCounterLength;
	BYTE cardCryptogram[8];
} SCP_INITIALIZE_UPDATE_RESPONSE;

typedef struct {
	BYTE caseAPDU;
	DWORD lc;
	DWORD wrappedLength;
	DWORD paddingSize;
	DWORD headerLength;
	BOOL isExtended;
} SCP_WRAP_COMMAND_CONTEXT;

OPGP_NO_API
OPGP_ERROR_STATUS scp_parse_initialize_update_response(
	BYTE secureChannelProtocol,
	BYTE *secureChannelProtocolImpl,
	BYTE securityLevel,
	PBYTE keyInformationData,
	PBYTE recvBuffer,
	DWORD recvBufferLength,
	SCP_INITIALIZE_UPDATE_RESPONSE *response);

OPGP_NO_API
OPGP_ERROR_STATUS scp_derive_session_keys_and_verify_card_cryptogram(
	BYTE secureChannelProtocol,
	GP211_SECURITY_INFO *secInfo,
	PBYTE baseKey,
	PBYTE sEnc,
	PBYTE sMac,
	PBYTE dek,
	DWORD keyLength,
	PBYTE hostChallenge,
	const SCP_INITIALIZE_UPDATE_RESPONSE *response);

OPGP_NO_API
OPGP_ERROR_STATUS scp_prepare_external_authentication(
	BYTE secureChannelProtocol,
	GP211_SECURITY_INFO *secInfo,
	DWORD keyLength,
	BYTE securityLevel,
	PBYTE hostChallenge,
	const SCP_INITIALIZE_UPDATE_RESPONSE *response,
	PBYTE hostCryptogram,
	PBYTE mac);

OPGP_NO_API
OPGP_ERROR_STATUS scp_wrap_command_by_protocol(
	GP211_SECURITY_INFO *secInfo,
	PBYTE apduCommand,
	PBYTE wrappedApduCommand,
	SCP_WRAP_COMMAND_CONTEXT *context,
	PBYTE encryption,
	PDWORD encryptionLength,
	PBYTE mac);

#ifdef __cplusplus
}
#endif

#endif
