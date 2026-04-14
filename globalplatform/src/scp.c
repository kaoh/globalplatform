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

#ifdef WIN32
#include "stdafx.h"
#endif

#include <string.h>

#include "scp.h"
#include "crypto.h"
#include "globalplatform/debug.h"
#include "globalplatform/errorcodes.h"
#include "globalplatform/stringify.h"

static BYTE C_MACDerivationConstant[2] = {0x01, 0x01}; //!< Constant for C-MAC session key calculation.
static BYTE ENCDerivationConstant[2] = {0x01, 0x82};//!< Constant for encryption session key calculation.
static BYTE DEKDerivationConstant[2] = {0x01, 0x81};//!< Constant for data encryption session key calculation.
static BYTE R_MACDerivationConstant[2] = {0x01, 0x02};//!< Constant for R-MAC session key calculation.

static BYTE S_ENC_DerivationConstant_SCP03  = 0x04; //!< Constant to derive S-ENC session key for SCP03.
static BYTE S_MAC_DerivationConstant_SCP03  = 0x06; //!< Constant to derive S-MAC session key for SCP03.
static BYTE S_RMAC_DerivationConstant_SCP03 = 0x07; //!< Constant to derive S-RMAC session key for SCP03.

static OPGP_ERROR_STATUS scp_create_error(DWORD errorCode) {
	OPGP_ERROR_STATUS status;
	OPGP_ERROR_CREATE_ERROR(status, errorCode, OPGP_stringify_error(errorCode));
	return status;
}

static OPGP_ERROR_STATUS scp_no_error(void) {
	OPGP_ERROR_STATUS status;
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS scp01_parse_initialize_update_response(
		BYTE *secureChannelProtocolImpl,
		PBYTE recvBuffer,
		SCP_INITIALIZE_UPDATE_RESPONSE *response) {
	if (!*secureChannelProtocolImpl) {
		return scp_create_error(GP211_ERROR_MISSING_SCP_IMPL);
	}
	response->keyInformationDataLength = 2;
	response->cardChallengeLength = 8;
	memcpy(response->cardChallenge, recvBuffer+12, 8);
	memcpy(response->cardCryptogram, recvBuffer+20, 8);
	return scp_no_error();
}

static OPGP_ERROR_STATUS scp02_parse_initialize_update_response(
		BYTE *secureChannelProtocolImpl,
		PBYTE recvBuffer,
		SCP_INITIALIZE_UPDATE_RESPONSE *response) {
	if (!*secureChannelProtocolImpl) {
		return scp_create_error(GP211_ERROR_MISSING_SCP_IMPL);
	}
	response->keyInformationDataLength = 2;
	response->cardChallengeLength = 6;
	response->sequenceCounterLength = 2;
	memcpy(response->sequenceCounter, recvBuffer+12, 2);
	memcpy(response->cardChallenge, recvBuffer+14, 6);
	memcpy(response->cardCryptogram, recvBuffer+20, 8);
	return scp_no_error();
}

static OPGP_ERROR_STATUS scp03_parse_initialize_update_response(
		BYTE *secureChannelProtocolImpl,
		BYTE securityLevel,
		PBYTE keyInformationData,
		PBYTE recvBuffer,
		DWORD recvBufferLength,
		SCP_INITIALIZE_UPDATE_RESPONSE *response) {
	if (!*secureChannelProtocolImpl) {
		*secureChannelProtocolImpl = keyInformationData[2];
	}
	else if (*secureChannelProtocolImpl != keyInformationData[2]) {
		return scp_create_error(GP211_ERROR_INCONSISTENT_SCP_IMPL);
	}

	if (securityLevel == GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC ||
			securityLevel == GP211_SCP03_SECURITY_LEVEL_C_DEC_R_ENC_C_MAC_R_MAC ||
			securityLevel == GP211_SCP03_SECURITY_LEVEL_C_MAC_R_MAC) {
		return scp_create_error(OPGP_ERROR_SCP03_SECURITY_R_ENCRYPTION_R_MAC_NOT_SUPPORTED);
	}

	response->keyInformationDataLength = 3;
	response->cardChallengeLength = 8;
	memcpy(response->cardChallenge, recvBuffer+13, 8);
	memcpy(response->cardCryptogram, recvBuffer+21, 8);
	if (recvBufferLength == 34) {
		response->sequenceCounterLength = 3;
		memcpy(response->sequenceCounter, recvBuffer+29, 3);
	}
	return scp_no_error();
}

OPGP_ERROR_STATUS scp_parse_initialize_update_response(
	BYTE secureChannelProtocol,
	BYTE *secureChannelProtocolImpl,
	BYTE securityLevel,
	PBYTE keyInformationData,
	PBYTE recvBuffer,
	DWORD recvBufferLength,
	SCP_INITIALIZE_UPDATE_RESPONSE *response) {
	if (secureChannelProtocolImpl == NULL || keyInformationData == NULL || recvBuffer == NULL || response == NULL) {
		return scp_create_error(OPGP_ERROR_INVALID_RESPONSE_DATA);
	}

	memset(response, 0, sizeof(*response));

	if (secureChannelProtocol == GP211_SCP03) {
		return scp03_parse_initialize_update_response(secureChannelProtocolImpl, securityLevel, keyInformationData,
				recvBuffer, recvBufferLength, response);
	}
	if (secureChannelProtocol == GP211_SCP02) {
		return scp02_parse_initialize_update_response(secureChannelProtocolImpl, recvBuffer, response);
	}
	if (secureChannelProtocol == GP211_SCP01) {
		return scp01_parse_initialize_update_response(secureChannelProtocolImpl, recvBuffer, response);
	}
	return scp_create_error(GP211_ERROR_INVALID_SCP);
}

static OPGP_ERROR_STATUS scp01_derive_session_keys(
		GP211_SECURITY_INFO *secInfo,
		PBYTE sEnc,
		PBYTE sMac,
		PBYTE dek,
		PBYTE hostChallenge,
		const SCP_INITIALIZE_UPDATE_RESPONSE *response) {
	OPGP_ERROR_STATUS status;

	if (secInfo->secureChannelProtocolImpl != GP211_SCP01_IMPL_i05
			&& secInfo->secureChannelProtocolImpl != GP211_SCP01_IMPL_i15) {
		return scp_create_error(GP211_ERROR_INVALID_SCP_IMPL);
	}

	status = create_session_key_SCP01(sEnc, (PBYTE)response->cardChallenge, hostChallenge, secInfo->encryptionSessionKey);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	status = create_session_key_SCP01(sMac, (PBYTE)response->cardChallenge, hostChallenge, secInfo->C_MACSessionKey);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	memcpy(secInfo->dataEncryptionSessionKey, dek, 16);

	return scp_no_error();
}

static OPGP_ERROR_STATUS scp02_derive_session_keys(
		GP211_SECURITY_INFO *secInfo,
		PBYTE baseKey,
		PBYTE sEnc,
		PBYTE sMac,
		PBYTE dek,
		const SCP_INITIALIZE_UPDATE_RESPONSE *response) {
	OPGP_ERROR_STATUS status;

	/* 1 Secure Channel base key */
	if ((secInfo->secureChannelProtocolImpl & 0x01) == 0) {
		status = create_session_key_SCP02(baseKey, ENCDerivationConstant, (PBYTE)response->sequenceCounter, secInfo->encryptionSessionKey);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
		status = create_session_key_SCP02(baseKey, C_MACDerivationConstant, (PBYTE)response->sequenceCounter, secInfo->C_MACSessionKey);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
		status = create_session_key_SCP02(baseKey, R_MACDerivationConstant, (PBYTE)response->sequenceCounter, secInfo->R_MACSessionKey);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
		status = create_session_key_SCP02(baseKey, DEKDerivationConstant, (PBYTE)response->sequenceCounter, secInfo->dataEncryptionSessionKey);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
	}
	/* 3 Secure Channel Keys */
	else {
		status = create_session_key_SCP02(sEnc, ENCDerivationConstant, (PBYTE)response->sequenceCounter, secInfo->encryptionSessionKey);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
		status = create_session_key_SCP02(sMac, C_MACDerivationConstant, (PBYTE)response->sequenceCounter, secInfo->C_MACSessionKey);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
		status = create_session_key_SCP02(sMac, R_MACDerivationConstant, (PBYTE)response->sequenceCounter, secInfo->R_MACSessionKey);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
		status = create_session_key_SCP02(dek, DEKDerivationConstant, (PBYTE)response->sequenceCounter, secInfo->dataEncryptionSessionKey);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
	}

	return scp_no_error();
}

static OPGP_ERROR_STATUS scp03_derive_session_keys(
		GP211_SECURITY_INFO *secInfo,
		PBYTE sEnc,
		PBYTE sMac,
		PBYTE dek,
		DWORD keyLength,
		PBYTE hostChallenge,
		const SCP_INITIALIZE_UPDATE_RESPONSE *response) {
	OPGP_ERROR_STATUS status;
	BYTE calculatedCardChallenge[8];

	/* compare card challenge value when calculated from pseudo random value */
	if ((secInfo->secureChannelProtocolImpl & 0x10) != 0) {
		if (secInfo->invokingAidLength == 0) {
			return scp_create_error(GP211_ERROR_MISSING_SD_AID);
		}
		status = calculate_card_challenge_SCP03(sEnc, keyLength, (PBYTE)response->sequenceCounter,
				secInfo->invokingAid, secInfo->invokingAidLength, calculatedCardChallenge);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
		if (memcmp(response->cardChallenge, calculatedCardChallenge, 8) != 0) {
			return scp_create_error(GP211_ERROR_INCORRECT_CARD_CHALLENGE);
		}
	}

	status = create_session_key_SCP03(sEnc, keyLength, S_ENC_DerivationConstant_SCP03, (PBYTE)response->cardChallenge,
			hostChallenge, secInfo->encryptionSessionKey);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	status = create_session_key_SCP03(sMac, keyLength, S_MAC_DerivationConstant_SCP03, (PBYTE)response->cardChallenge,
			hostChallenge, secInfo->C_MACSessionKey);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	status = create_session_key_SCP03(sMac, keyLength, S_RMAC_DerivationConstant_SCP03, (PBYTE)response->cardChallenge,
			hostChallenge, secInfo->R_MACSessionKey);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	/* In SCP03 there is no data encryption session key. */
	memcpy(secInfo->dataEncryptionSessionKey, dek, keyLength);

	return scp_no_error();
}

static OPGP_ERROR_STATUS scp01_verify_card_cryptogram(
		GP211_SECURITY_INFO *secInfo,
		PBYTE hostChallenge,
		const SCP_INITIALIZE_UPDATE_RESPONSE *response) {
	OPGP_ERROR_STATUS status;
	BYTE cardCryptogramVer[8];

	status = calculate_card_cryptogram_SCP01(secInfo->encryptionSessionKey, (PBYTE)response->cardChallenge,
			hostChallenge, cardCryptogramVer);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	if (memcmp(response->cardCryptogram, cardCryptogramVer, 8) != 0) {
		return scp_create_error(OPGP_ERROR_CARD_CRYPTOGRAM_VERIFICATION);
	}
	return scp_no_error();
}

static OPGP_ERROR_STATUS scp02_verify_card_cryptogram(
		GP211_SECURITY_INFO *secInfo,
		PBYTE hostChallenge,
		const SCP_INITIALIZE_UPDATE_RESPONSE *response) {
	OPGP_ERROR_STATUS status;
	BYTE cardCryptogramVer[8];

	status = calculate_card_cryptogram_SCP02(secInfo->encryptionSessionKey, (PBYTE)response->sequenceCounter,
			(PBYTE)response->cardChallenge, hostChallenge, cardCryptogramVer);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	if (memcmp(response->cardCryptogram, cardCryptogramVer, 8) != 0) {
		return scp_create_error(OPGP_ERROR_CARD_CRYPTOGRAM_VERIFICATION);
	}
	return scp_no_error();
}

static OPGP_ERROR_STATUS scp03_verify_card_cryptogram(
		GP211_SECURITY_INFO *secInfo,
		DWORD keyLength,
		PBYTE hostChallenge,
		const SCP_INITIALIZE_UPDATE_RESPONSE *response) {
	OPGP_ERROR_STATUS status;
	BYTE cardCryptogramVer[8];

	status = calculate_card_cryptogram_SCP03(secInfo->C_MACSessionKey, keyLength, (PBYTE)response->cardChallenge,
			hostChallenge, cardCryptogramVer);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	if (memcmp(response->cardCryptogram, cardCryptogramVer, 8) != 0) {
		return scp_create_error(OPGP_ERROR_CARD_CRYPTOGRAM_VERIFICATION);
	}
	return scp_no_error();
}

OPGP_ERROR_STATUS scp_derive_session_keys_and_verify_card_cryptogram(
	BYTE secureChannelProtocol,
	GP211_SECURITY_INFO *secInfo,
	PBYTE baseKey,
	PBYTE sEnc,
	PBYTE sMac,
	PBYTE dek,
	DWORD keyLength,
	PBYTE hostChallenge,
	const SCP_INITIALIZE_UPDATE_RESPONSE *response) {
	OPGP_ERROR_STATUS status;

	if (secureChannelProtocol == GP211_SCP03) {
		status = scp03_derive_session_keys(secInfo, sEnc, sMac, dek, keyLength, hostChallenge, response);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
		return scp03_verify_card_cryptogram(secInfo, keyLength, hostChallenge, response);
	}
	if (secureChannelProtocol == GP211_SCP02) {
		status = scp02_derive_session_keys(secInfo, baseKey, sEnc, sMac, dek, response);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
		return scp02_verify_card_cryptogram(secInfo, hostChallenge, response);
	}
	if (secureChannelProtocol == GP211_SCP01) {
		status = scp01_derive_session_keys(secInfo, sEnc, sMac, dek, hostChallenge, response);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
		return scp01_verify_card_cryptogram(secInfo, hostChallenge, response);
	}

	return scp_create_error(GP211_ERROR_INVALID_SCP);
}

static void scp_build_external_auth_header(BYTE securityLevel, BYTE hostCryptogram[8], BYTE commandHeader[13]) {
	commandHeader[0] = 0x84;
	commandHeader[1] = 0x82;
	commandHeader[2] = securityLevel;
	commandHeader[3] = 0x00;
	commandHeader[4] = 0x10;
	memcpy(commandHeader + 5, hostCryptogram, 8);
}

static OPGP_ERROR_STATUS scp01_prepare_external_authentication(
		GP211_SECURITY_INFO *secInfo,
		BYTE securityLevel,
		PBYTE hostChallenge,
		const SCP_INITIALIZE_UPDATE_RESPONSE *response,
		PBYTE hostCryptogram,
		PBYTE mac) {
	OPGP_ERROR_STATUS status;
	BYTE commandHeader[13];

	status = calculate_host_cryptogram_SCP01(secInfo->encryptionSessionKey, (PBYTE)response->cardChallenge, hostChallenge, hostCryptogram);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}

	scp_build_external_auth_header(securityLevel, hostCryptogram, commandHeader);
	status = calculate_MAC(secInfo->C_MACSessionKey, commandHeader, sizeof(commandHeader), (PBYTE)ICV, mac);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	memcpy(secInfo->lastC_MAC, mac, 8);
	memcpy(secInfo->lastR_MAC, mac, 8);

	return scp_no_error();
}

static OPGP_ERROR_STATUS scp02_prepare_external_authentication(
		GP211_SECURITY_INFO *secInfo,
		BYTE securityLevel,
		PBYTE hostChallenge,
		const SCP_INITIALIZE_UPDATE_RESPONSE *response,
		PBYTE hostCryptogram,
		PBYTE mac) {
	OPGP_ERROR_STATUS status;
	BYTE commandHeader[13];

	status = calculate_host_cryptogram_SCP02(secInfo->encryptionSessionKey, (PBYTE)response->sequenceCounter,
			(PBYTE)response->cardChallenge, hostChallenge, hostCryptogram);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}

	scp_build_external_auth_header(securityLevel, hostCryptogram, commandHeader);
	status = calculate_MAC_des_3des(secInfo->C_MACSessionKey, commandHeader, sizeof(commandHeader), (PBYTE)ICV, mac);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	memcpy(secInfo->lastC_MAC, mac, 8);
	memcpy(secInfo->lastR_MAC, mac, 8);

	return scp_no_error();
}

static OPGP_ERROR_STATUS scp03_prepare_external_authentication(
		GP211_SECURITY_INFO *secInfo,
		DWORD keyLength,
		BYTE securityLevel,
		PBYTE hostChallenge,
		const SCP_INITIALIZE_UPDATE_RESPONSE *response,
		PBYTE hostCryptogram,
		PBYTE mac) {
	OPGP_ERROR_STATUS status;
	BYTE commandHeader[13];

	status = calculate_host_cryptogram_SCP03(secInfo->C_MACSessionKey, keyLength, (PBYTE)response->cardChallenge, hostChallenge, hostCryptogram);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}

	scp_build_external_auth_header(securityLevel, hostCryptogram, commandHeader);
	status = calculate_CMAC_aes(secInfo->C_MACSessionKey, keyLength, commandHeader, sizeof(commandHeader), (PBYTE)SCP03_ICV, mac);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	memcpy(secInfo->lastC_MAC, mac, 16);

	return scp_no_error();
}

OPGP_ERROR_STATUS scp_prepare_external_authentication(
	BYTE secureChannelProtocol,
	GP211_SECURITY_INFO *secInfo,
	DWORD keyLength,
	BYTE securityLevel,
	PBYTE hostChallenge,
	const SCP_INITIALIZE_UPDATE_RESPONSE *response,
	PBYTE hostCryptogram,
	PBYTE mac) {
	if (secureChannelProtocol == GP211_SCP03) {
		return scp03_prepare_external_authentication(secInfo, keyLength, securityLevel, hostChallenge, response,
				hostCryptogram, mac);
	}
	if (secureChannelProtocol == GP211_SCP02) {
		return scp02_prepare_external_authentication(secInfo, securityLevel, hostChallenge, response, hostCryptogram,
				mac);
	}
	if (secureChannelProtocol == GP211_SCP01) {
		return scp01_prepare_external_authentication(secInfo, securityLevel, hostChallenge, response, hostCryptogram,
				mac);
	}

	return scp_create_error(GP211_ERROR_INVALID_SCP);
}

static void scp_update_modified_apdu_header(PBYTE apduCommand, PBYTE wrappedApduCommand, const SCP_WRAP_COMMAND_CONTEXT *context) {
	switch (context->caseAPDU) {
		case 1:
		case 2: {
			if (context->isExtended) {
				wrappedApduCommand[4] = 0;
				wrappedApduCommand[5] = 0;
				wrappedApduCommand[6] = 0x08;
			} else {
				wrappedApduCommand[4] = 0x08;
			}
			break;
		}
		case 3:
		case 4: {
			if (context->isExtended) {
				DWORD newLc = ((wrappedApduCommand[5] << 8) | wrappedApduCommand[6]) + 8;
				wrappedApduCommand[5] = (BYTE)(newLc >> 8);
				wrappedApduCommand[6] = (BYTE)(newLc & 0xFF);
			} else {
				wrappedApduCommand[4] += 8;
			}
			break;
		}
	}
	wrappedApduCommand[0] = apduCommand[0] | 0x04;
}

static void scp_update_unmodified_apdu_header_scp02(PBYTE apduCommand, PBYTE wrappedApduCommand, const SCP_WRAP_COMMAND_CONTEXT *context) {
	switch (context->caseAPDU) {
		case 1:
		case 2: {
			if (context->isExtended) {
				wrappedApduCommand[4] = 0;
				wrappedApduCommand[5] = 0;
				wrappedApduCommand[6] = 0x08;
			} else {
				wrappedApduCommand[4] = 0x08;
			}
			break;
		}
		case 3:
		case 4: {
			if (context->isExtended) {
				DWORD newLc = ((wrappedApduCommand[5] << 8) | wrappedApduCommand[6]) + 8;
				wrappedApduCommand[5] = (BYTE)(newLc >> 8);
				wrappedApduCommand[6] = (BYTE)(newLc & 0xFF);
			} else {
				wrappedApduCommand[4] += 8;
			}
			break;
		}
	}
	wrappedApduCommand[0] = apduCommand[0] | 0x04;
}

static void scp_add_padding_to_lc(PBYTE wrappedApduCommand, const SCP_WRAP_COMMAND_CONTEXT *context) {
	if (context->isExtended) {
		DWORD newLc = ((wrappedApduCommand[5] << 8) | wrappedApduCommand[6]) + context->paddingSize;
		wrappedApduCommand[5] = (BYTE)(newLc >> 8);
		wrappedApduCommand[6] = (BYTE)(newLc & 0xFF);
	} else {
		wrappedApduCommand[4] += (BYTE)context->paddingSize;
	}
}

static OPGP_ERROR_STATUS scp01_wrap_command(
		GP211_SECURITY_INFO *secInfo,
		PBYTE apduCommand,
		PBYTE wrappedApduCommand,
		SCP_WRAP_COMMAND_CONTEXT *context,
		PBYTE encryption,
		PDWORD encryptionLength,
		PBYTE mac) {
	OPGP_ERROR_STATUS status;
	BYTE C_MAC_ICV[8];
	DWORD C_MAC_ICVLength = 8;

	scp_update_modified_apdu_header(apduCommand, wrappedApduCommand, context);

	if (secInfo->secureChannelProtocolImpl == GP211_SCP01_IMPL_i15) {
		status = calculate_enc_ecb_two_key_triple_des(secInfo->C_MACSessionKey,
				secInfo->lastC_MAC, 8, C_MAC_ICV, &C_MAC_ICVLength);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
	}
	else {
		memcpy(C_MAC_ICV, secInfo->lastC_MAC, 8);
	}

	status = calculate_MAC(secInfo->C_MACSessionKey, wrappedApduCommand, context->wrappedLength - context->paddingSize - 8,
			C_MAC_ICV, mac);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}

	OPGP_LOG_HEX(_T("wrap_command: ICV for MAC: "), C_MAC_ICV, 8);
	OPGP_LOG_HEX(_T("wrap_command: Generated MAC: "), mac, 8);

	memcpy(secInfo->lastC_MAC, mac, 8);
	memcpy(wrappedApduCommand + context->wrappedLength - 8, mac, 8);

	if (secInfo->securityLevel == GP211_SCP01_SECURITY_LEVEL_C_DEC_C_MAC && context->lc != 0) {
		DWORD wrappedLc;
		if (context->isExtended) {
			wrappedLc = (wrappedApduCommand[5] << 8) | wrappedApduCommand[6];
			wrappedApduCommand[6] = (BYTE)context->lc;
			status = calculate_enc_cbc(secInfo->encryptionSessionKey,
					wrappedApduCommand + 6, context->lc + 1, encryption, encryptionLength);
		} else {
			wrappedLc = wrappedApduCommand[4];
			wrappedApduCommand[4] = (BYTE)context->lc;
			status = calculate_enc_cbc(secInfo->encryptionSessionKey,
					wrappedApduCommand + 4, context->lc + 1, encryption, encryptionLength);
		}
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
		if (context->isExtended) {
			wrappedApduCommand[5] = (BYTE)(wrappedLc >> 8);
			wrappedApduCommand[6] = (BYTE)(wrappedLc & 0xFF);
		} else {
			wrappedApduCommand[4] = (BYTE)wrappedLc;
		}

		scp_add_padding_to_lc(wrappedApduCommand, context);
		memcpy(wrappedApduCommand + context->headerLength, encryption, *encryptionLength);
		memcpy(wrappedApduCommand + *encryptionLength + context->headerLength, mac, 8);
	}

	return scp_no_error();
}

static OPGP_ERROR_STATUS scp02_wrap_command(
		GP211_SECURITY_INFO *secInfo,
		PBYTE apduCommand,
		PBYTE wrappedApduCommand,
		SCP_WRAP_COMMAND_CONTEXT *context,
		PBYTE encryption,
		PDWORD encryptionLength,
		PBYTE mac) {
	OPGP_ERROR_STATUS status;
	BYTE C_MAC_ICV[8];
	DWORD C_MAC_ICVLength = 8;

	if ((secInfo->secureChannelProtocolImpl & 0x02) == 0) {
		scp_update_modified_apdu_header(apduCommand, wrappedApduCommand, context);
	}

	/* ICV set to MAC over AID */
	if ((secInfo->secureChannelProtocolImpl & 0x08) != 0) {
		memcpy(C_MAC_ICV, secInfo->lastC_MAC, 8);
	}
	/* ICV encryption */
	if ((secInfo->secureChannelProtocolImpl & 0x10) != 0) {
		status = calculate_enc_ecb_single_des(secInfo->C_MACSessionKey,
				secInfo->lastC_MAC, 8, C_MAC_ICV, &C_MAC_ICVLength);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
	}

	status = calculate_MAC_des_3des(secInfo->C_MACSessionKey, wrappedApduCommand, context->wrappedLength - context->paddingSize - 8,
			C_MAC_ICV, mac);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}

	if ((secInfo->secureChannelProtocolImpl & 0x02) != 0) {
		scp_update_unmodified_apdu_header_scp02(apduCommand, wrappedApduCommand, context);
	}

	OPGP_LOG_HEX(_T("wrap_command: ICV for MAC: "), C_MAC_ICV, 8);
	OPGP_LOG_HEX(_T("wrap_command: Generated MAC: "), mac, 8);

	memcpy(secInfo->lastC_MAC, mac, 8);
	memcpy(wrappedApduCommand + context->wrappedLength - 8, mac, 8);

	if (secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC
			|| secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC) {
		status = calculate_enc_cbc_SCP02(secInfo->encryptionSessionKey,
				wrappedApduCommand + context->headerLength, context->lc, encryption, encryptionLength);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
		scp_add_padding_to_lc(wrappedApduCommand, context);
		memcpy(wrappedApduCommand + context->headerLength, encryption, *encryptionLength);
		memcpy(wrappedApduCommand + *encryptionLength + context->headerLength, mac, 8);
	}

	return scp_no_error();
}

static OPGP_ERROR_STATUS scp03_wrap_command(
		GP211_SECURITY_INFO *secInfo,
		PBYTE apduCommand,
		PBYTE wrappedApduCommand,
		SCP_WRAP_COMMAND_CONTEXT *context,
		PBYTE encryption,
		PDWORD encryptionLength,
		PBYTE mac) {
	OPGP_ERROR_STATUS status;
	BYTE ENC_ICV[32] = {0};

	scp_update_modified_apdu_header(apduCommand, wrappedApduCommand, context);

	/* SCP03 with encryption encrypts first, calculates C-MAC afterwards. */
	if (secInfo->securityLevel == GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC
			|| secInfo->securityLevel == GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC
			|| secInfo->securityLevel == GP211_SCP03_SECURITY_LEVEL_C_DEC_R_ENC_C_MAC_R_MAC) {
		if (context->caseAPDU != 1 && context->caseAPDU != 2) {
			status = calculate_enc_icv_SCP03(secInfo->encryptionSessionKey, secInfo->keyLength,
					secInfo->sessionEncryptionCounter, ENC_ICV, 0);
			if (OPGP_ERROR_CHECK(status)) {
				return status;
			}
			status = calculate_enc_cbc_SCP03(secInfo->encryptionSessionKey, secInfo->keyLength,
					wrappedApduCommand + context->headerLength, context->lc, ENC_ICV, encryption, encryptionLength);
			if (OPGP_ERROR_CHECK(status)) {
				return status;
			}
			memcpy(wrappedApduCommand + context->headerLength, encryption, *encryptionLength);
			scp_add_padding_to_lc(wrappedApduCommand, context);
		}
		secInfo->sessionEncryptionCounter++;
	}

	status = calculate_CMAC_aes(secInfo->C_MACSessionKey, secInfo->keyLength, wrappedApduCommand,
			context->wrappedLength - 8, secInfo->lastC_MAC, mac);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}

	OPGP_LOG_HEX(_T("wrap_command: ICV for MAC: "), secInfo->lastC_MAC, 16);
	OPGP_LOG_HEX(_T("wrap_command: Generated MAC: "), mac, 16);

	memcpy(secInfo->lastC_MAC, mac, 16);
	memcpy(wrappedApduCommand + context->wrappedLength - 8, mac, 8);

	return scp_no_error();
}

OPGP_ERROR_STATUS scp_wrap_command_by_protocol(
		GP211_SECURITY_INFO *secInfo,
		PBYTE apduCommand,
		PBYTE wrappedApduCommand,
		SCP_WRAP_COMMAND_CONTEXT *context,
		PBYTE encryption,
		PDWORD encryptionLength,
		PBYTE mac) {
	if (secInfo->secureChannelProtocol == GP211_SCP01) {
		return scp01_wrap_command(secInfo, apduCommand, wrappedApduCommand, context, encryption, encryptionLength, mac);
	}
	if (secInfo->secureChannelProtocol == GP211_SCP02) {
		return scp02_wrap_command(secInfo, apduCommand, wrappedApduCommand, context, encryption, encryptionLength, mac);
	}
	if (secInfo->secureChannelProtocol == GP211_SCP03) {
		return scp03_wrap_command(secInfo, apduCommand, wrappedApduCommand, context, encryption, encryptionLength, mac);
	}

	return scp_create_error(GP211_ERROR_INVALID_SCP);
}
