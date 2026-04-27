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
#include <stdlib.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <cmocka.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

#include "globalplatform/globalplatform.h"
#include "crypto.h"
#include "util.h"
#include "globalplatform/stringify.h"

static OPGP_CARD_CONTEXT cardContext;
static OPGP_CARD_INFO cardInfo;
static GP211_SECURITY_INFO securityInfo211;

static BYTE oceStaticPrivateKey[32];
static DWORD oceStaticPrivateKeyLength;
static BYTE oceStaticPublicKey[133];
static DWORD oceStaticPublicKeyLength;

static BYTE sdStaticPrivateKey[32];
static DWORD sdStaticPrivateKeyLength;
static BYTE sdStaticPublicKey[133];
static DWORD sdStaticPublicKeyLength;

static BYTE sdCertificateStore[256];
static DWORD sdCertificateStoreLength;

static BYTE expectedSEnc[32];
static BYTE expectedSMac[32];
static BYTE expectedRMac[32];
static BYTE expectedSdek[32];
static BYTE expectedKeyLength;

static int apduCallCount;

static const BYTE testKeyVersion = 0x20;
static const BYTE testKeyIdentifier = 0x11;

static OPGP_ERROR_STATUS build_test_scp11_certificate(const BYTE *keyUsage, DWORD keyUsageLength,
		PBYTE certificateData, PDWORD certificateDataLength) {
	GP211_SCP11_CERTIFICATE certificate;

	memset(&certificate, 0, sizeof(certificate));
	certificate.certificateSerialNumber[0] = 0x01;
	certificate.certificateSerialNumber[1] = 0x02;
	certificate.certificateSerialNumber[2] = 0x03;
	certificate.certificateSerialNumberLength = 3;
	certificate.authorityIdentifier[0] = 0xA1;
	certificate.authorityIdentifier[1] = 0xA2;
	certificate.authorityIdentifier[2] = 0xA3;
	certificate.authorityIdentifierLength = 3;
	certificate.subjectIdentifier[0] = 0xB1;
	certificate.subjectIdentifier[1] = 0xB2;
	certificate.subjectIdentifier[2] = 0xB3;
	certificate.subjectIdentifierLength = 3;
	memcpy(certificate.keyUsage, keyUsage, keyUsageLength);
	certificate.keyUsageLength = keyUsageLength;
	certificate.effectiveDatePresent = 1;
	certificate.effectiveDate[0] = 0x20;
	certificate.effectiveDate[1] = 0x24;
	certificate.effectiveDate[2] = 0x01;
	certificate.effectiveDate[3] = 0x01;
	certificate.expirationDate[0] = 0x20;
	certificate.expirationDate[1] = 0x30;
	certificate.expirationDate[2] = 0x12;
	certificate.expirationDate[3] = 0x31;
	certificate.expirationDateLength = 4;
	return GP211_build_scp11_certificate(&certificate,
			_T("ecc_public_key_test.pem"), NULL,
			_T("ecc_private_key_test.pem"), NULL,
			certificateData, certificateDataLength);
}

static OPGP_ERROR_STATUS build_test_scp11_certificate_chain(PBYTE certificateChainData, PDWORD certificateChainDataLength,
		BOOL wrapInCertificateStore) {
	OPGP_ERROR_STATUS status;
	BYTE intermediateCertificate[512];
	DWORD intermediateCertificateLength = sizeof(intermediateCertificate);
	BYTE oceCertificate[512];
	DWORD oceCertificateLength = sizeof(oceCertificate);
	BYTE certificateList[1024];
	DWORD certificateListLength = 0;
	DWORD outputSize;

	if (certificateChainData == NULL || certificateChainDataLength == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
		return status;
	}

	status = build_test_scp11_certificate(GP211_SCP11_KEY_USAGE_DIGITAL_SIGNATURE_VERIFICATION,
			sizeof(GP211_SCP11_KEY_USAGE_DIGITAL_SIGNATURE_VERIFICATION),
			intermediateCertificate, &intermediateCertificateLength);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	status = build_test_scp11_certificate(GP211_SCP11_KEY_USAGE_KEY_AGREEMENT,
			sizeof(GP211_SCP11_KEY_USAGE_KEY_AGREEMENT),
			oceCertificate, &oceCertificateLength);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}

	if (intermediateCertificateLength + oceCertificateLength > sizeof(certificateList)) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER));
		return status;
	}
	memcpy(certificateList, intermediateCertificate, intermediateCertificateLength);
	certificateListLength += intermediateCertificateLength;
	memcpy(certificateList + certificateListLength, oceCertificate, oceCertificateLength);
	certificateListLength += oceCertificateLength;

	outputSize = *certificateChainDataLength;
	*certificateChainDataLength = 0;
	if (wrapInCertificateStore) {
		return append_tlv(certificateChainData, outputSize, certificateChainDataLength,
				0xBF21, certificateList, certificateListLength);
	}
	if (outputSize < certificateListLength) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER));
		return status;
	}
	memcpy(certificateChainData, certificateList, certificateListLength);
	*certificateChainDataLength = certificateListLength;
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS set_apdu_response(PBYTE rapdu, PDWORD rapduLength, PBYTE data, DWORD dataLength, USHORT sw) {
	OPGP_ERROR_STATUS status;
	DWORD statusCode = OPGP_ISO7816_ERROR_PREFIX | sw;

	if (rapdu == NULL || rapduLength == NULL || *rapduLength < dataLength + 2) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER));
		return status;
	}

	if (data != NULL && dataLength > 0) {
		memcpy(rapdu, data, dataLength);
	}
	rapdu[dataLength] = (BYTE)(sw >> 8);
	rapdu[dataLength + 1] = (BYTE)(sw & 0xFF);
	*rapduLength = dataLength + 2;

	OPGP_ERROR_CREATE_NO_ERROR_WITH_CODE(status, statusCode, OPGP_stringify_error(statusCode));
	return status;
}

static OPGP_ERROR_STATUS load_private_key_bytes_p256(OPGP_STRING keyFileName, PBYTE privateKey, PDWORD privateKeyLength) {
	OPGP_ERROR_STATUS status;
	FILE *pemFile = NULL;
	EVP_PKEY *key = NULL;
	EC_KEY *ec = NULL;
	const BIGNUM *privateBn = NULL;
	int privateBytes;

	if (keyFileName == NULL || privateKey == NULL || privateKeyLength == NULL || *privateKeyLength < 32) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER));
		return status;
	}

	pemFile = _tfopen(keyFileName, _T("rb"));
	if (pemFile == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, errno, OPGP_stringify_error(errno));
		goto end;
	}
	key = PEM_read_PrivateKey(pemFile, NULL, NULL, NULL);
	if (key == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}
	ec = EVP_PKEY_get1_EC_KEY(key);
	if (ec == NULL || EC_GROUP_get_curve_name(EC_KEY_get0_group(ec)) != NID_X9_62_prime256v1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_WRONG_KEY_TYPE, OPGP_stringify_error(OPGP_ERROR_WRONG_KEY_TYPE));
		goto end;
	}
	privateBn = EC_KEY_get0_private_key(ec);
	if (privateBn == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}

	privateBytes = BN_num_bytes(privateBn);
	if (privateBytes <= 0 || privateBytes > 32) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}

	memset(privateKey, 0, 32);
	if (BN_bn2bin(privateBn, privateKey + (32 - privateBytes)) != privateBytes) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}
	*privateKeyLength = 32;
	OPGP_ERROR_CREATE_NO_ERROR(status);

end:
	if (ec != NULL) {
		EC_KEY_free(ec);
	}
	if (key != NULL) {
		EVP_PKEY_free(key);
	}
	if (pemFile != NULL) {
		fclose(pemFile);
	}
	return status;
}

static OPGP_ERROR_STATUS build_sd_certificate_store(BYTE keyParameterReference) {
	OPGP_ERROR_STATUS status;
	BYTE publicKeyData[200];
	DWORD publicKeyDataLength = 0;
	BYTE certData[220];
	DWORD certDataLength = 0;
	BYTE certStoreData[240];
	DWORD certStoreDataLength = 0;

	status = append_tlv(publicKeyData, sizeof(publicKeyData), &publicKeyDataLength, 0xB0, sdStaticPublicKey, sdStaticPublicKeyLength);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	status = append_tlv(publicKeyData, sizeof(publicKeyData), &publicKeyDataLength, 0xF0, &keyParameterReference, 1);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}

	status = append_tlv(certData, sizeof(certData), &certDataLength, 0x7F49, publicKeyData, publicKeyDataLength);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	status = append_tlv(certStoreData, sizeof(certStoreData), &certStoreDataLength, 0x7F21, certData, certDataLength);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	sdCertificateStoreLength = 0;
	status = append_tlv(sdCertificateStore, sizeof(sdCertificateStore), &sdCertificateStoreLength, 0xBF21, certStoreData, certStoreDataLength);
	return status;
}

static OPGP_ERROR_STATUS compute_shared_secret_p256(
		PBYTE privateKey, DWORD privateKeyLength,
		PBYTE peerPublicKey, DWORD peerPublicKeyLength,
		PBYTE sharedSecret, PDWORD sharedSecretLength) {
	OPGP_ERROR_STATUS status;
	EC_KEY *localEc = NULL;
	EC_KEY *peerEc = NULL;
	const EC_GROUP *group;
	BIGNUM *privateBn = NULL;
	EC_POINT *peerPoint = NULL;
	EVP_PKEY *localPkey = NULL;
	EVP_PKEY *peerPkey = NULL;
	EVP_PKEY_CTX *deriveCtx = NULL;
	size_t derivedLength;
	int result;

	if (privateKey == NULL || privateKeyLength == 0 || peerPublicKey == NULL || peerPublicKeyLength == 0
			|| sharedSecret == NULL || sharedSecretLength == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
		return status;
	}

	localEc = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	peerEc = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (localEc == NULL || peerEc == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}

	privateBn = BN_bin2bn(privateKey, (int)privateKeyLength, NULL);
	if (privateBn == NULL || EC_KEY_set_private_key(localEc, privateBn) != 1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}

	group = EC_KEY_get0_group(peerEc);
	if (group == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}
	peerPoint = EC_POINT_new(group);
	if (peerPoint == NULL || EC_POINT_oct2point(group, peerPoint, peerPublicKey, peerPublicKeyLength, NULL) != 1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}
	if (EC_KEY_set_public_key(peerEc, peerPoint) != 1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}

	localPkey = EVP_PKEY_new();
	peerPkey = EVP_PKEY_new();
	if (localPkey == NULL || peerPkey == NULL
			|| EVP_PKEY_set1_EC_KEY(localPkey, localEc) != 1
			|| EVP_PKEY_set1_EC_KEY(peerPkey, peerEc) != 1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}

	deriveCtx = EVP_PKEY_CTX_new(localPkey, NULL);
	if (deriveCtx == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}
	result = EVP_PKEY_derive_init(deriveCtx);
	if (result != 1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}
	result = EVP_PKEY_derive_set_peer(deriveCtx, peerPkey);
	if (result != 1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}
	result = EVP_PKEY_derive(deriveCtx, NULL, &derivedLength);
	if (result != 1 || derivedLength > *sharedSecretLength) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER));
		goto end;
	}
	result = EVP_PKEY_derive(deriveCtx, sharedSecret, &derivedLength);
	if (result != 1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}

	*sharedSecretLength = (DWORD)derivedLength;
	OPGP_ERROR_CREATE_NO_ERROR(status);

end:
	if (deriveCtx != NULL) {
		EVP_PKEY_CTX_free(deriveCtx);
	}
	if (peerPkey != NULL) {
		EVP_PKEY_free(peerPkey);
	}
	if (localPkey != NULL) {
		EVP_PKEY_free(localPkey);
	}
	if (peerPoint != NULL) {
		EC_POINT_free(peerPoint);
	}
	if (privateBn != NULL) {
		BN_free(privateBn);
	}
	if (peerEc != NULL) {
		EC_KEY_free(peerEc);
	}
	if (localEc != NULL) {
		EC_KEY_free(localEc);
	}
	return status;
}

static OPGP_ERROR_STATUS generate_ephemeral_keypair_p256(
		PBYTE privateKey, PDWORD privateKeyLength,
		PBYTE publicKey, PDWORD publicKeyLength) {
	OPGP_ERROR_STATUS status;
	EC_KEY *ec = NULL;
	const EC_GROUP *group;
	const EC_POINT *point;
	const BIGNUM *privateBn;
	size_t encodedPublicLength;
	int privateLength;

	ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (ec == NULL || EC_KEY_generate_key(ec) != 1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}

	group = EC_KEY_get0_group(ec);
	point = EC_KEY_get0_public_key(ec);
	privateBn = EC_KEY_get0_private_key(ec);
	if (group == NULL || point == NULL || privateBn == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}

	encodedPublicLength = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	if (encodedPublicLength == 0 || encodedPublicLength > *publicKeyLength) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER));
		goto end;
	}
	if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, publicKey, *publicKeyLength, NULL) != encodedPublicLength) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}
	*publicKeyLength = (DWORD)encodedPublicLength;

	privateLength = BN_num_bytes(privateBn);
	if (privateLength <= 0 || (DWORD)privateLength > *privateKeyLength) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER));
		goto end;
	}
	if (BN_bn2bin(privateBn, privateKey) != privateLength) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}
	*privateKeyLength = (DWORD)privateLength;
	OPGP_ERROR_CREATE_NO_ERROR(status);

end:
	if (ec != NULL) {
		EC_KEY_free(ec);
	}
	return status;
}

static OPGP_ERROR_STATUS x963_kdf_sha256(
		PBYTE sharedSecret, DWORD sharedSecretLength,
		PBYTE sharedInfo, DWORD sharedInfoLength,
		PBYTE keyData, DWORD keyDataLength) {
	OPGP_ERROR_STATUS status;
	BYTE hash[64];
	DWORD offset = 0;
	DWORD counter = 1;
	DWORD inputLength = sharedSecretLength + 4 + sharedInfoLength;
	PBYTE input = (PBYTE)malloc(inputLength);

	if (input == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER));
		return status;
	}

	while (offset < keyDataLength) {
		DWORD toCopy;
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
			free(input);
			return status;
		}
		toCopy = ((keyDataLength - offset) > 32) ? 32 : (keyDataLength - offset);
		memcpy(keyData + offset, hash, toCopy);
		offset += toCopy;
		counter++;
	}

	free(input);
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS build_mutual_authenticate_response(
		PBYTE commandData, DWORD commandDataLength, PBYTE responseData, PDWORD responseDataLength) {
	OPGP_ERROR_STATUS status;
	GP_SIMPLE_TLV commandTlv;
	GP_SIMPLE_TLV publicKeyTlv;
	GP_SIMPLE_TLV inner;
	DWORD offset;
	BYTE keyUsageQualifier = 0;
	BYTE keyType = 0;
	BYTE keyLength = 0;
	const BYTE *hostEphemeralPublicKey = NULL;
	DWORD hostEphemeralPublicKeyLength = 0;
	BYTE sdEphemeralPrivateKey[64];
	DWORD sdEphemeralPrivateKeyLength = sizeof(sdEphemeralPrivateKey);
	BYTE sdEphemeralPublicKey[133];
	DWORD sdEphemeralPublicKeyLength = sizeof(sdEphemeralPublicKey);
	BYTE sharedSecretStatic[80];
	DWORD sharedSecretStaticLength = sizeof(sharedSecretStatic);
	BYTE sharedSecretEphemeral[80];
	DWORD sharedSecretEphemeralLength = sizeof(sharedSecretEphemeral);
	BYTE concatenatedSharedSecret[160];
	DWORD concatenatedSharedSecretLength;
	BYTE sharedInfo[3];
	BYTE keyData[160];
	DWORD keyDataLength;
	BYTE receiptInput[1024];
	DWORD receiptInputLength = 0;
	BYTE receipt[16];
	DWORD localResponseLength = 0;

	if (parse_simple_tlv(commandData, commandDataLength, &commandTlv) < 0 || commandTlv.tag != 0xA6) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
		return status;
	}
	if (parse_simple_tlv(commandData + commandTlv.tlvLength, commandDataLength - commandTlv.tlvLength, &publicKeyTlv) < 0
			|| publicKeyTlv.tag != 0x5F49 || commandTlv.tlvLength + publicKeyTlv.tlvLength != commandDataLength) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
		return status;
	}
	hostEphemeralPublicKey = publicKeyTlv.value;
	hostEphemeralPublicKeyLength = publicKeyTlv.length;

	offset = 0;
	while (offset < commandTlv.length) {
		if (parse_simple_tlv(commandTlv.value + offset, commandTlv.length - offset, &inner) < 0) {
			OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
			return status;
		}
		if (inner.tag == 0x95 && inner.length == 1) {
			keyUsageQualifier = inner.value[0];
		} else if (inner.tag == 0x80 && inner.length == 1) {
			keyType = inner.value[0];
		} else if (inner.tag == 0x81 && inner.length == 1) {
			keyLength = inner.value[0];
		}
		offset += inner.tlvLength;
	}

	assert_int_equal(keyType, GP211_KEY_TYPE_AES);
	assert_true(keyLength == 16 || keyLength == 24 || keyLength == 32);
	assert_non_null(hostEphemeralPublicKey);

	status = generate_ephemeral_keypair_p256(sdEphemeralPrivateKey, &sdEphemeralPrivateKeyLength, sdEphemeralPublicKey, &sdEphemeralPublicKeyLength);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}

	status = compute_shared_secret_p256(sdStaticPrivateKey, sdStaticPrivateKeyLength,
			oceStaticPublicKey, oceStaticPublicKeyLength, sharedSecretStatic, &sharedSecretStaticLength);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	status = compute_shared_secret_p256(sdEphemeralPrivateKey, sdEphemeralPrivateKeyLength,
			(PBYTE)hostEphemeralPublicKey, hostEphemeralPublicKeyLength, sharedSecretEphemeral, &sharedSecretEphemeralLength);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}

	concatenatedSharedSecretLength = sharedSecretEphemeralLength + sharedSecretStaticLength;
	memcpy(concatenatedSharedSecret, sharedSecretEphemeral, sharedSecretEphemeralLength);
	memcpy(concatenatedSharedSecret + sharedSecretEphemeralLength, sharedSecretStatic, sharedSecretStaticLength);

	sharedInfo[0] = keyUsageQualifier;
	sharedInfo[1] = keyType;
	sharedInfo[2] = keyLength;
	keyDataLength = keyLength * 5;
	status = x963_kdf_sha256(concatenatedSharedSecret, concatenatedSharedSecretLength,
			sharedInfo, sizeof(sharedInfo), keyData, keyDataLength);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}

	memset(expectedSEnc, 0, sizeof(expectedSEnc));
	memset(expectedSMac, 0, sizeof(expectedSMac));
	memset(expectedRMac, 0, sizeof(expectedRMac));
	memset(expectedSdek, 0, sizeof(expectedSdek));
	expectedKeyLength = keyLength;
	memcpy(expectedSEnc, keyData + keyLength, keyLength);
	memcpy(expectedSMac, keyData + (2 * keyLength), keyLength);
	memcpy(expectedRMac, keyData + (3 * keyLength), keyLength);
	memcpy(expectedSdek, keyData + (4 * keyLength), keyLength);

	memcpy(receiptInput + receiptInputLength, commandData, commandDataLength);
	receiptInputLength += commandDataLength;
	status = append_tlv(receiptInput, sizeof(receiptInput), &receiptInputLength, 0x5F49,
			sdEphemeralPublicKey, sdEphemeralPublicKeyLength);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}

	status = calculate_CMAC_aes(keyData, keyLength, receiptInput, receiptInputLength, NULL, receipt);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}

	status = append_tlv(responseData, *responseDataLength, &localResponseLength, 0x5F49, sdEphemeralPublicKey, sdEphemeralPublicKeyLength);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	status = append_tlv(responseData, *responseDataLength, &localResponseLength, 0x86, receipt, sizeof(receipt));
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}

	*responseDataLength = localResponseLength;
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS mock_send_APDU(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo,
		PBYTE capdu, DWORD capduLength, PBYTE rapdu, PDWORD rapduLength) {
	OPGP_ERROR_STATUS status;
	BYTE ins;

	(void)cardContext;
	(void)cardInfo;

	assert_non_null(capdu);
	assert_true(capduLength >= 5);

	ins = capdu[1];
	if (ins == 0xCA) {
		BYTE expectedCommand[] = {
				0x80, 0xCA, 0xBF, 0x21, 0x06, 0xA6, 0x04, 0x83, 0x02, testKeyIdentifier, testKeyVersion, 0x00
		};
		assert_true(apduCallCount == 0 || apduCallCount == 2);
		assert_int_equal(capduLength, sizeof(expectedCommand));
		assert_memory_equal(capdu, expectedCommand, sizeof(expectedCommand));
		apduCallCount++;
		return set_apdu_response(rapdu, rapduLength, sdCertificateStore, sdCertificateStoreLength, 0x9000);
	}

	if (ins == 0x2A) {
		DWORD lc;
		GP211_SCP11_CERTIFICATE certificate;

		assert_true(apduCallCount == 0 || apduCallCount == 1);
		assert_int_equal(capdu[0], 0x80);
		assert_int_equal(capdu[2], testKeyVersion);
		assert_int_equal(capdu[3] & 0x7F, testKeyIdentifier);
		if (apduCallCount == 0) {
			assert_true((capdu[3] & 0x80) != 0);
		} else {
			assert_true((capdu[3] & 0x80) == 0);
		}
		lc = capdu[4];
		assert_int_equal(capduLength, lc + 5);
		status = GP211_parse_scp11_certificate(capdu + 5, lc, &certificate);
		assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
		apduCallCount++;
		return set_apdu_response(rapdu, rapduLength, NULL, 0, 0x9000);
	}

	if (ins == 0x82) {
		BYTE responseData[256];
		DWORD responseDataLength = sizeof(responseData);
		DWORD lc;
		const BYTE *commandData;

		assert_true(apduCallCount == 1 || apduCallCount == 3);
		assert_int_equal(capdu[0], 0x80);
		assert_int_equal(capdu[2], testKeyVersion);
		assert_int_equal(capdu[3], testKeyIdentifier);
		lc = capdu[4];
		assert_int_equal(capduLength, lc + 6);
		assert_int_equal(capdu[capduLength - 1], 0x00);
		commandData = capdu + 5;

		status = build_mutual_authenticate_response((PBYTE)commandData, lc, responseData, &responseDataLength);
		assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
		apduCallCount++;
		return set_apdu_response(rapdu, rapduLength, responseData, responseDataLength, 0x9000);
	}

	assert_true(0);
	OPGP_ERROR_CREATE_ERROR(status, OPGP_ISO7816_ERROR_FUNC_NOT_SUPPORTED, OPGP_stringify_error(OPGP_ISO7816_ERROR_FUNC_NOT_SUPPORTED));
	return status;
}

static void reset_scp11a_test_state(void) {
	memset(&securityInfo211, 0, sizeof(securityInfo211));
	memset(expectedSEnc, 0, sizeof(expectedSEnc));
	memset(expectedSMac, 0, sizeof(expectedSMac));
	memset(expectedRMac, 0, sizeof(expectedRMac));
	memset(expectedSdek, 0, sizeof(expectedSdek));
	expectedKeyLength = 0;
	apduCallCount = 0;
}

static void assert_scp11a_security_info(int expectedApduCallCount) {
	assert_int_equal(apduCallCount, expectedApduCallCount);
	assert_int_equal(securityInfo211.secureChannelProtocol, GP211_SCP03);
	assert_int_equal(securityInfo211.secureChannelProtocolImpl, GP211_SCP03_IMPL_i30);
	assert_int_equal(securityInfo211.securityLevel, GP211_SCP03_SECURITY_LEVEL_C_MAC_R_MAC);
	assert_int_equal(securityInfo211.keyLength, expectedKeyLength);
	assert_int_equal(securityInfo211.keySetVersion, testKeyVersion);
	assert_int_equal(securityInfo211.keyIndex, testKeyIdentifier);
	assert_int_equal(securityInfo211.sessionEncryptionCounter, 1);

	assert_memory_equal(securityInfo211.encryptionSessionKey, expectedSEnc, expectedKeyLength);
	assert_memory_equal(securityInfo211.C_MACSessionKey, expectedSMac, expectedKeyLength);
	assert_memory_equal(securityInfo211.R_MACSessionKey, expectedRMac, expectedKeyLength);
	assert_memory_equal(securityInfo211.dataEncryptionSessionKey, expectedSdek, expectedKeyLength);
}

static void scp11_certificate_parse_and_build(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE certificateData[512];
	DWORD certificateDataLength = sizeof(certificateData);
	GP211_SCP11_CERTIFICATE certificate;

	(void)state;

	status = build_test_scp11_certificate(GP211_SCP11_KEY_USAGE_KEY_AGREEMENT,
			sizeof(GP211_SCP11_KEY_USAGE_KEY_AGREEMENT),
			certificateData, &certificateDataLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_true(certificateDataLength > 0);

	status = GP211_parse_scp11_certificate(certificateData, certificateDataLength, &certificate);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(certificate.certificateSerialNumberLength, 3);
	assert_int_equal(certificate.authorityIdentifierLength, 3);
	assert_int_equal(certificate.subjectIdentifierLength, 3);
	assert_int_equal(certificate.keyUsageLength, sizeof(GP211_SCP11_KEY_USAGE_KEY_AGREEMENT));
	assert_memory_equal(certificate.keyUsage, GP211_SCP11_KEY_USAGE_KEY_AGREEMENT,
			sizeof(GP211_SCP11_KEY_USAGE_KEY_AGREEMENT));
	assert_true(certificate.effectiveDatePresent);
	assert_int_equal(certificate.expirationDateLength, GP211_SCP11_CERTIFICATE_MAX_DATE_LENGTH);
	assert_int_equal(certificate.publicKeyLength, oceStaticPublicKeyLength);
	assert_memory_equal(certificate.publicKey, oceStaticPublicKey, oceStaticPublicKeyLength);
	assert_int_equal(certificate.keyParameterReferenceLength, 1);
	assert_int_equal(certificate.keyParameterReference[0], GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_P256);
	assert_int_equal(certificate.signatureLength, 64);
}

static void perform_security_operation_certificate_chain(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE certificateChain[1024];
	DWORD certificateChainLength = sizeof(certificateChain);

	(void)state;

	status = build_test_scp11_certificate_chain(certificateChain, &certificateChainLength, 0);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	apduCallCount = 0;
	status = GP211_perform_security_operation_certificate_chain(cardContext, cardInfo, NULL,
			testKeyVersion, testKeyIdentifier, certificateChain, certificateChainLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(apduCallCount, 2);
}

static void mutual_authentication_scp11a(void **state) {
	OPGP_ERROR_STATUS status;

	(void)state;
	reset_scp11a_test_state();

	status = GP211_mutual_authentication(cardContext, cardInfo,
			oceStaticPrivateKey, NULL, NULL, NULL,
			16, testKeyVersion, testKeyIdentifier,
			GP211_SCP11, 0x00,
			GP211_SCP03_SECURITY_LEVEL_C_MAC, OPGP_DERIVATION_METHOD_NONE,
			NULL, 0, &securityInfo211);

	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_scp11a_security_info(2);
}

static void mutual_authentication_scp11a_with_certificate_chain(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE certificateChain[1024];
	DWORD certificateChainLength = sizeof(certificateChain);

	(void)state;
	reset_scp11a_test_state();

	status = build_test_scp11_certificate_chain(certificateChain, &certificateChainLength, 1);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	status = GP211_mutual_authentication(cardContext, cardInfo,
			oceStaticPrivateKey, NULL, NULL, NULL,
			16, testKeyVersion, testKeyIdentifier,
			GP211_SCP11, 0x00,
			GP211_SCP03_SECURITY_LEVEL_C_MAC, OPGP_DERIVATION_METHOD_NONE,
			certificateChain, certificateChainLength, &securityInfo211);

	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_scp11a_security_info(4);
}

static int setup(void **state) {
	OPGP_ERROR_STATUS status;
	DWORD keyLength;
	DWORD publicPointLength;
	BYTE eccKeyComponentType;
	BYTE keyParameterReference;

	(void)state;

	cardContext.connectionFunctions.sendAPDU = &mock_send_APDU;
	cardInfo.specVersion = GP_211;

	keyLength = sizeof(oceStaticPrivateKey);
	status = load_private_key_bytes_p256(_T("ecc_private_key_test.pem"), oceStaticPrivateKey, &keyLength);
	if (OPGP_ERROR_CHECK(status)) {
		return -1;
	}
	oceStaticPrivateKeyLength = keyLength;

	publicPointLength = sizeof(oceStaticPublicKey);
	status = read_public_ecc_key(_T("ecc_public_key_test.pem"), NULL, oceStaticPublicKey, &publicPointLength,
			&eccKeyComponentType, &keyParameterReference, NULL);
	if (OPGP_ERROR_CHECK(status)) {
		return -1;
	}
	oceStaticPublicKeyLength = publicPointLength;

	assert_int_equal(eccKeyComponentType, GP211_KEY_TYPE_ECC_PUBLIC_OR_PRIVATE);
	assert_int_equal(keyParameterReference, GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_P256);

	memcpy(sdStaticPrivateKey, oceStaticPrivateKey, oceStaticPrivateKeyLength);
	sdStaticPrivateKeyLength = oceStaticPrivateKeyLength;
	memcpy(sdStaticPublicKey, oceStaticPublicKey, oceStaticPublicKeyLength);
	sdStaticPublicKeyLength = oceStaticPublicKeyLength;

	status = build_sd_certificate_store(keyParameterReference);
	if (OPGP_ERROR_CHECK(status)) {
		return -1;
	}
	return 0;
}

int main(void) {
	const struct CMUnitTest tests[] = {
			cmocka_unit_test(scp11_certificate_parse_and_build),
			cmocka_unit_test(perform_security_operation_certificate_chain),
			cmocka_unit_test(mutual_authentication_scp11a),
			cmocka_unit_test(mutual_authentication_scp11a_with_certificate_chain)
	};
	return cmocka_run_group_tests_name("SCP11", tests, setup, NULL);
}
