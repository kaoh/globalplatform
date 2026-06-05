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
#include <stdlib.h>
#include <openssl/objects.h>

#include "scp.h"
#include "crypto.h"
#include "util.h"
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

BYTE map_scp11a_key_usage_qualifier(BYTE securityLevel) {
	if (securityLevel == GP211_SCP11_KEY_USAGE_QUALIFIER_C_MAC_R_MAC
			|| securityLevel == GP211_SCP11_KEY_USAGE_QUALIFIER_C_DEC_R_ENC_C_MAC_R_MAC) {
		return securityLevel;
	}
	if (securityLevel == GP211_SCP03_SECURITY_LEVEL_C_MAC
			|| securityLevel == GP211_SCP03_SECURITY_LEVEL_C_MAC_R_MAC
			|| securityLevel == GP211_SCP02_SECURITY_LEVEL_C_MAC
			|| securityLevel == GP211_SCP02_SECURITY_LEVEL_C_MAC_R_MAC
			|| securityLevel == GP211_SCP01_SECURITY_LEVEL_C_MAC) {
		return GP211_SCP11_KEY_USAGE_QUALIFIER_C_MAC_R_MAC;
	}
	return GP211_SCP11_KEY_USAGE_QUALIFIER_C_DEC_R_ENC_C_MAC_R_MAC;
}

BYTE map_scp11a_security_level(BYTE keyUsageQualifier) {
	if (keyUsageQualifier == GP211_SCP11_KEY_USAGE_QUALIFIER_C_MAC_R_MAC) {
		return GP211_SCP03_SECURITY_LEVEL_C_MAC_R_MAC;
	}
	return GP211_SCP03_SECURITY_LEVEL_C_DEC_R_ENC_C_MAC_R_MAC;
}

BYTE map_scp11a_scp03_impl(BYTE keyUsageQualifier) {
	if (keyUsageQualifier == GP211_SCP11_KEY_USAGE_QUALIFIER_C_MAC_R_MAC) {
		return GP211_SCP03_IMPL_i30;
	}
	return GP211_SCP03_IMPL_i70;
}

DWORD scp11_private_key_length_from_key_parameter_reference(BYTE keyParameterReference) {
	switch (keyParameterReference) {
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_P256:
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_BRAINPOOLP256R1:
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_BRAINPOOLP256T1:
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_SM2P256V1:
			return 32;
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_P384:
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_BRAINPOOLP384R1:
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_BRAINPOOLP384T1:
			return 48;
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_P521:
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_BRAINPOOLP512R1:
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_BRAINPOOLP512T1:
			return 66;
		default:
			return 0;
	}
}

OPGP_ERROR_STATUS extract_scp11_sd_public_key_from_certificate_store(PBYTE certificateStore, DWORD certificateStoreLength,
		PBYTE sdPublicKey, PDWORD sdPublicKeyLength, BYTE *keyParameterReference) {
	GP_SIMPLE_TLV outer;
	GP_SIMPLE_TLV current;
	GP_SIMPLE_TLV certInner;
	GP_SIMPLE_TLV publicKeyTlv;
	const BYTE *certificateListValue;
	DWORD certificateListLength;
	const BYTE *lastCertificateTlv = NULL;
	DWORD lastCertificateTlvLength = 0;
	const BYTE *lastCertificate = NULL;
	DWORD lastCertificateLength = 0;
	DWORD offset;
	USHORT certificateTag = 0;
	BYTE parsedKeyParameterReference = GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_P256;
	BOOL keyParameterReferenceFound = 0;
	BOOL publicKeyFound = 0;

	if (certificateStore == NULL || sdPublicKey == NULL || sdPublicKeyLength == NULL || keyParameterReference == NULL) {
		return scp_create_error(OPGP_ERROR_INVALID_RESPONSE_DATA);
	}

	if (parse_simple_tlv(certificateStore, certificateStoreLength, &outer) > 0 && outer.tag == 0xBF21) {
		certificateListValue = outer.value;
		certificateListLength = outer.length;
	} else {
		certificateListValue = certificateStore;
		certificateListLength = certificateStoreLength;
	}

	offset = 0;
	while (offset < certificateListLength) {
		LONG result = parse_simple_tlv(certificateListValue + offset, certificateListLength - offset, &current);
		if (result < 0 || current.tlvLength == 0) {
			return scp_create_error(OPGP_ERROR_INVALID_RESPONSE_DATA);
		}
		if (certificateTag == 0) {
			certificateTag = current.tag;
			if (certificateTag != 0x7F21 && certificateTag != 0x30) {
				return scp_create_error(OPGP_ERROR_INVALID_RESPONSE_DATA);
			}
		} else if (current.tag != certificateTag) {
			return scp_create_error(OPGP_ERROR_INVALID_RESPONSE_DATA);
		}
		lastCertificateTlv = certificateListValue + offset;
		lastCertificateTlvLength = current.tlvLength;
		lastCertificate = current.value;
		lastCertificateLength = current.length;
		offset += current.tlvLength;
	}
	if (lastCertificate == NULL || lastCertificateLength == 0) {
		return scp_create_error(OPGP_ERROR_INVALID_RESPONSE_DATA);
	}

	if (certificateTag == 0x30) {
		OPGP_ERROR_STATUS status;
		BYTE eccKeyComponentType;

		status = read_public_ecc_key_from_der_certificate(lastCertificateTlv, lastCertificateTlvLength,
				sdPublicKey, sdPublicKeyLength, &eccKeyComponentType, keyParameterReference);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
		if (eccKeyComponentType != GP211_KEY_TYPE_ECC_PUBLIC_OR_PRIVATE
				&& eccKeyComponentType != GP211_KEY_TYPE_ECC_SM2_PUBLIC_OR_PRIVATE) {
			return scp_create_error(OPGP_ERROR_WRONG_KEY_TYPE);
		}
		return status;
	}

	offset = 0;
	publicKeyTlv.tag = 0;
	while (offset < lastCertificateLength) {
		LONG result = parse_simple_tlv(lastCertificate + offset, lastCertificateLength - offset, &certInner);
		if (result < 0) {
			return scp_create_error(OPGP_ERROR_INVALID_RESPONSE_DATA);
		}
		if (certInner.tag == 0x7F49) {
			publicKeyTlv = certInner;
			break;
		}
		offset += certInner.tlvLength;
	}
	if (publicKeyTlv.tag != 0x7F49) {
		return scp_create_error(OPGP_ERROR_INVALID_RESPONSE_DATA);
	}

	offset = 0;
	while (offset < publicKeyTlv.length) {
		LONG result = parse_simple_tlv(publicKeyTlv.value + offset, publicKeyTlv.length - offset, &certInner);
		if (result < 0) {
			return scp_create_error(OPGP_ERROR_INVALID_RESPONSE_DATA);
		}
		if (certInner.tag == 0xB0) {
			if (certInner.length > *sdPublicKeyLength) {
				return scp_create_error(OPGP_ERROR_INSUFFICIENT_BUFFER);
			}
			memcpy(sdPublicKey, certInner.value, certInner.length);
			*sdPublicKeyLength = certInner.length;
			publicKeyFound = 1;
		}
		if (certInner.tag == 0xF0 && certInner.length > 0) {
			parsedKeyParameterReference = certInner.value[certInner.length - 1];
			keyParameterReferenceFound = 1;
		}
		offset += certInner.tlvLength;
	}
	if (!publicKeyFound) {
		return scp_create_error(OPGP_ERROR_INVALID_RESPONSE_DATA);
	}
	if (!keyParameterReferenceFound) {
		if (*sdPublicKeyLength == 65) {
			parsedKeyParameterReference = GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_P256;
		} else if (*sdPublicKeyLength == 97) {
			parsedKeyParameterReference = GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_P384;
		} else if (*sdPublicKeyLength == 133) {
			parsedKeyParameterReference = GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_P521;
		}
	}

	*keyParameterReference = parsedKeyParameterReference;
	return scp_no_error();
}

OPGP_ERROR_STATUS parse_scp11_mutual_authentication_response(PBYTE responseData, DWORD responseDataLength,
		PBYTE sdEphemeralPublicKey, PDWORD sdEphemeralPublicKeyLength, PBYTE receipt, PDWORD receiptLength) {
	DWORD offset = 0;
	GP_SIMPLE_TLV tlv;
	BOOL publicKeyFound = 0;
	BOOL receiptFound = 0;

	if (responseData == NULL || sdEphemeralPublicKey == NULL || sdEphemeralPublicKeyLength == NULL
			|| receipt == NULL || receiptLength == NULL) {
		return scp_create_error(OPGP_ERROR_INVALID_RESPONSE_DATA);
	}

	while (offset < responseDataLength) {
		LONG result = parse_simple_tlv(responseData + offset, responseDataLength - offset, &tlv);
		if (result < 0) {
			return scp_create_error(OPGP_ERROR_INVALID_RESPONSE_DATA);
		}
		if (tlv.tag == 0x5F49) {
			if (tlv.length > *sdEphemeralPublicKeyLength) {
				return scp_create_error(OPGP_ERROR_INSUFFICIENT_BUFFER);
			}
			memcpy(sdEphemeralPublicKey, tlv.value, tlv.length);
			*sdEphemeralPublicKeyLength = tlv.length;
			publicKeyFound = 1;
		} else if (tlv.tag == 0x86) {
			if (tlv.length > *receiptLength) {
				return scp_create_error(OPGP_ERROR_INSUFFICIENT_BUFFER);
			}
			memcpy(receipt, tlv.value, tlv.length);
			*receiptLength = tlv.length;
			receiptFound = 1;
		}
		offset += tlv.tlvLength;
	}

	if (!publicKeyFound || !receiptFound) {
		return scp_create_error(OPGP_ERROR_INVALID_RESPONSE_DATA);
	}

	return scp_no_error();
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

static int scp11_curve_nid_from_key_parameter_reference(BYTE keyParameterReference) {
	switch (keyParameterReference) {
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_P256:
			return NID_X9_62_prime256v1;
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_P384:
			return NID_secp384r1;
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_P521:
			return NID_secp521r1;
#ifdef NID_brainpoolP256r1
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_BRAINPOOLP256R1:
			return NID_brainpoolP256r1;
#endif
#ifdef NID_brainpoolP256t1
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_BRAINPOOLP256T1:
			return NID_brainpoolP256t1;
#endif
#ifdef NID_brainpoolP384r1
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_BRAINPOOLP384R1:
			return NID_brainpoolP384r1;
#endif
#ifdef NID_brainpoolP384t1
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_BRAINPOOLP384T1:
			return NID_brainpoolP384t1;
#endif
#ifdef NID_brainpoolP512r1
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_BRAINPOOLP512R1:
			return NID_brainpoolP512r1;
#endif
#ifdef NID_brainpoolP512t1
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_BRAINPOOLP512T1:
			return NID_brainpoolP512t1;
#endif
#if defined(NID_sm2)
		case GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_SM2P256V1:
			return NID_sm2;
#endif
		default:
			return NID_undef;
	}
}

static OPGP_ERROR_STATUS scp11_x963_kdf_sha256(
		PBYTE sharedSecret,
		DWORD sharedSecretLength,
		PBYTE sharedInfo,
		DWORD sharedInfoLength,
		PBYTE keyData,
		DWORD keyDataLength) {
	OPGP_ERROR_STATUS status;
	BYTE hash[64];
	DWORD offset = 0;
	DWORD counter = 1;
	DWORD inputLength;
	PBYTE input = NULL;
	DWORD toCopy;

	if (sharedSecret == NULL || keyData == NULL || keyDataLength == 0) {
		return scp_create_error(OPGP_ERROR_INVALID_RESPONSE_DATA);
	}

	inputLength = sharedSecretLength + 4 + sharedInfoLength;
	input = (PBYTE)malloc(inputLength);
	if (input == NULL) {
		return scp_create_error(OPGP_ERROR_INSUFFICIENT_BUFFER);
	}

	while (offset < keyDataLength) {
		memcpy(input, sharedSecret, sharedSecretLength);
		input[sharedSecretLength] = (BYTE)((counter >> 24) & 0xFF);
		input[sharedSecretLength + 1] = (BYTE)((counter >> 16) & 0xFF);
		input[sharedSecretLength + 2] = (BYTE)((counter >> 8) & 0xFF);
		input[sharedSecretLength + 3] = (BYTE)(counter & 0xFF);
		if (sharedInfoLength > 0) {
			memcpy(input + sharedSecretLength + 4, sharedInfo, sharedInfoLength);
		}
		status = calculate_sha2_hash(input, inputLength, hash, 32);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
		toCopy = (keyDataLength - offset > 32) ? 32 : (keyDataLength - offset);
		memcpy(keyData + offset, hash, toCopy);
		offset += toCopy;
		counter++;
	}
	status = scp_no_error();

end:
	if (input != NULL) {
		free(input);
	}
	return status;
}

OPGP_ERROR_STATUS scp11a_generate_ephemeral_keypair(
		BYTE keyParameterReference,
		PBYTE privateKey,
		PDWORD privateKeyLength,
		PBYTE publicKey,
		PDWORD publicKeyLength) {
	int curveNid;

	if (privateKey == NULL || privateKeyLength == NULL || publicKey == NULL || publicKeyLength == NULL) {
		return scp_create_error(OPGP_ERROR_INVALID_RESPONSE_DATA);
	}

	curveNid = scp11_curve_nid_from_key_parameter_reference(keyParameterReference);
	if (curveNid == NID_undef) {
		return scp_create_error(OPGP_ERROR_WRONG_KEY_TYPE);
	}

	return generate_ecc_keypair(curveNid, privateKey, privateKeyLength, publicKey, publicKeyLength);
}

OPGP_ERROR_STATUS scp11a_derive_session_keys_and_verify_receipt(
		GP211_SECURITY_INFO *secInfo,
		BYTE keyLength,
		BYTE keyParameterReference,
		PBYTE oceStaticPrivateKey,
		DWORD oceStaticPrivateKeyLength,
		PBYTE sdStaticPublicKey,
		DWORD sdStaticPublicKeyLength,
		PBYTE oceEphemeralPrivateKey,
		DWORD oceEphemeralPrivateKeyLength,
		PBYTE sdEphemeralPublicKey,
		DWORD sdEphemeralPublicKeyLength,
		PBYTE sharedInfo,
		DWORD sharedInfoLength,
		PBYTE receiptInput,
		DWORD receiptInputLength,
		PBYTE receipt,
		DWORD receiptLength) {
	OPGP_ERROR_STATUS status;
	int curveNid;
	BYTE sharedSecretStatic[80];
	BYTE sharedSecretEphemeral[80];
	DWORD sharedSecretStaticLength = sizeof(sharedSecretStatic);
	DWORD sharedSecretEphemeralLength = sizeof(sharedSecretEphemeral);
	BYTE concatenatedSharedSecret[160];
	DWORD concatenatedSharedSecretLength;
	BYTE keyData[160];
	DWORD keyDataLength;
	BYTE expectedReceipt[16];

	if (secInfo == NULL || receipt == NULL) {
		return scp_create_error(OPGP_ERROR_INVALID_RESPONSE_DATA);
	}
	if (keyLength != 16 && keyLength != 24 && keyLength != 32) {
		return scp_create_error(OPGP_ERROR_WRONG_KEY_TYPE);
	}
	if (receiptLength != 16) {
		return scp_create_error(OPGP_ERROR_INVALID_RESPONSE_DATA);
	}

	curveNid = scp11_curve_nid_from_key_parameter_reference(keyParameterReference);
	if (curveNid == NID_undef) {
		return scp_create_error(OPGP_ERROR_WRONG_KEY_TYPE);
	}

	status = calculate_ecc_shared_secret(curveNid, oceStaticPrivateKey, oceStaticPrivateKeyLength,
			sdStaticPublicKey, sdStaticPublicKeyLength, sharedSecretStatic, &sharedSecretStaticLength);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	status = calculate_ecc_shared_secret(curveNid, oceEphemeralPrivateKey, oceEphemeralPrivateKeyLength,
			sdEphemeralPublicKey, sdEphemeralPublicKeyLength, sharedSecretEphemeral, &sharedSecretEphemeralLength);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}

	concatenatedSharedSecretLength = sharedSecretEphemeralLength + sharedSecretStaticLength;
	if (concatenatedSharedSecretLength > sizeof(concatenatedSharedSecret)) {
		return scp_create_error(OPGP_ERROR_INSUFFICIENT_BUFFER);
	}
	memcpy(concatenatedSharedSecret, sharedSecretEphemeral, sharedSecretEphemeralLength);
	memcpy(concatenatedSharedSecret + sharedSecretEphemeralLength, sharedSecretStatic, sharedSecretStaticLength);

	keyDataLength = keyLength * 5;
	if (keyDataLength > sizeof(keyData)) {
		return scp_create_error(OPGP_ERROR_INSUFFICIENT_BUFFER);
	}
	status = scp11_x963_kdf_sha256(concatenatedSharedSecret, concatenatedSharedSecretLength,
			sharedInfo, sharedInfoLength, keyData, keyDataLength);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}

	status = calculate_CMAC_aes(keyData, keyLength, receiptInput, receiptInputLength, NULL, expectedReceipt);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	if (memcmp(expectedReceipt, receipt, 16) != 0) {
		return scp_create_error(OPGP_ERROR_CARD_CRYPTOGRAM_VERIFICATION);
	}

	memset(secInfo->encryptionSessionKey, 0, sizeof(secInfo->encryptionSessionKey));
	memset(secInfo->C_MACSessionKey, 0, sizeof(secInfo->C_MACSessionKey));
	memset(secInfo->R_MACSessionKey, 0, sizeof(secInfo->R_MACSessionKey));
	memset(secInfo->dataEncryptionSessionKey, 0, sizeof(secInfo->dataEncryptionSessionKey));

	memcpy(secInfo->encryptionSessionKey, keyData + keyLength, keyLength);
	memcpy(secInfo->C_MACSessionKey, keyData + (2 * keyLength), keyLength);
	memcpy(secInfo->R_MACSessionKey, keyData + (3 * keyLength), keyLength);
	memcpy(secInfo->dataEncryptionSessionKey, keyData + (4 * keyLength), keyLength);
	memcpy(secInfo->lastC_MAC, receipt, 16);
	memset(secInfo->lastR_MAC, 0, sizeof(secInfo->lastR_MAC));

	return scp_no_error();
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
