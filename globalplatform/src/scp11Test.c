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
#include <openssl/x509.h>
#include <openssl/x509v3.h>

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

static BYTE sdCertificateStore[1200];
static DWORD sdCertificateStoreLength;
static BYTE expectedStoreData[1200];
static DWORD expectedStoreDataLength;

static BYTE expectedSEnc[32];
static BYTE expectedSMac[32];
static BYTE expectedRMac[32];
static BYTE expectedSdek[32];
static BYTE expectedKeyLength;

static int apduCallCount;

typedef enum {
	SCP11_TEST_MODE_NONE = 0,
	SCP11_TEST_MODE_PSO_CHAIN,
	SCP11_TEST_MODE_PSO_CHAIN_X509,
	SCP11_TEST_MODE_PSO_LARGE_X509,
	SCP11_TEST_MODE_PSO_LARGE_X509_EXTENDED,
	SCP11_TEST_MODE_PSO_SMALL_X509_EXTENDED_AVAILABLE,
	SCP11_TEST_MODE_PSO_LEAF_FIRST_X509_WITH_ROOT,
	SCP11_TEST_MODE_MUTUAL_NO_CERTIFICATE,
	SCP11_TEST_MODE_MUTUAL_OCE_CERTIFICATE,
	SCP11_TEST_MODE_MUTUAL_CERTIFICATE_CHAIN,
	SCP11_TEST_MODE_MUTUAL_CERTIFICATE_CHAIN_CA_LOOKUP_FALLBACK,
	SCP11_TEST_MODE_MUTUAL_X509_CERTIFICATE_STORE,
	SCP11_TEST_MODE_STORE_ECKA_CERTIFICATE,
	SCP11_TEST_MODE_STORE_WHITELIST,
	SCP11_TEST_MODE_STORE_WHITELIST_EMPTY
} SCP11_TEST_MODE;

static SCP11_TEST_MODE scp11TestMode;

static const BYTE testKeyVersion = 0x20;
static const BYTE testKeyIdentifier = 0x11;
static const BYTE testCaKlocKeyIdentifier = 0x10;
static const BYTE testCaKlocIdentifier[] = {0xA1, 0xA2, 0xA3};
static BYTE testWhitelistCsn1[] = {0x01, 0x02, 0x03};
static BYTE testWhitelistCsn2[] = {0x10, 0x11, 0x12, 0x13};
static const BYTE testX509IntermediateCertificate[] = {0x30, 0x03, 0x02, 0x01, 0x01};
static const BYTE testX509OceCertificate[] = {0x30, 0x03, 0x02, 0x01, 0x02};
static const BYTE testValidX509Certificate[] = {
		0x30, 0x82, 0x01, 0x76, 0x30, 0x82, 0x01, 0x1D, 0xA0, 0x03, 0x02, 0x01,
		0x02, 0x02, 0x14, 0x23, 0x4C, 0x97, 0x37, 0x69, 0x88, 0x43, 0x33, 0x3B,
		0xB4, 0x14, 0xAB, 0x90, 0x57, 0xF0, 0x3E, 0x8E, 0x92, 0x09, 0xB2, 0x30,
		0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30,
		0x11, 0x31, 0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x06,
		0x47, 0x50, 0x54, 0x65, 0x73, 0x74, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x36,
		0x30, 0x36, 0x30, 0x31, 0x30, 0x31, 0x31, 0x31, 0x32, 0x39, 0x5A, 0x17,
		0x0D, 0x32, 0x36, 0x30, 0x36, 0x30, 0x32, 0x30, 0x31, 0x31, 0x31, 0x32,
		0x39, 0x5A, 0x30, 0x11, 0x31, 0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04,
		0x03, 0x0C, 0x06, 0x47, 0x50, 0x54, 0x65, 0x73, 0x74, 0x30, 0x59, 0x30,
		0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08,
		0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
		0xC1, 0xA7, 0x67, 0xD0, 0x74, 0xD5, 0xD0, 0x93, 0xEA, 0xA3, 0x7E, 0xFA,
		0x58, 0xAD, 0xE1, 0xF7, 0x10, 0xA7, 0xD5, 0x1F, 0xA5, 0x39, 0xE4, 0x98,
		0x4E, 0xAC, 0x34, 0xAD, 0xEC, 0x21, 0x30, 0x18, 0xAF, 0x12, 0x20, 0x74,
		0x3A, 0x7A, 0xDE, 0x40, 0xA8, 0xA3, 0x7E, 0xC5, 0x74, 0x0F, 0x11, 0xF9,
		0xCA, 0xC1, 0xFD, 0xF0, 0xC8, 0x02, 0xDF, 0x2F, 0xE5, 0x6F, 0x45, 0xE8,
		0xE0, 0x30, 0x7D, 0xD6, 0xA3, 0x53, 0x30, 0x51, 0x30, 0x1D, 0x06, 0x03,
		0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x50, 0xA4, 0xA7, 0x17, 0x8E,
		0x3E, 0x63, 0x15, 0x90, 0xE8, 0x05, 0x61, 0x4E, 0x2A, 0x18, 0x99, 0xD0,
		0x46, 0xCB, 0xC0, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18,
		0x30, 0x16, 0x80, 0x14, 0x50, 0xA4, 0xA7, 0x17, 0x8E, 0x3E, 0x63, 0x15,
		0x90, 0xE8, 0x05, 0x61, 0x4E, 0x2A, 0x18, 0x99, 0xD0, 0x46, 0xCB, 0xC0,
		0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05,
		0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48,
		0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20,
		0x2E, 0xD6, 0xE7, 0xC6, 0x6B, 0xFC, 0x23, 0x71, 0x9F, 0xCE, 0x59, 0x80,
		0x2D, 0x25, 0x03, 0x92, 0x54, 0x70, 0x48, 0x69, 0xEB, 0xCF, 0x12, 0x39,
		0x03, 0xFD, 0xF9, 0x71, 0x17, 0xBB, 0x4D, 0xE4, 0x02, 0x20, 0x3D, 0xD2,
		0x02, 0xD7, 0x51, 0x62, 0xC5, 0xA6, 0xA5, 0xBD, 0x1C, 0xBE, 0x05, 0xB4,
		0xCA, 0x3A, 0xEF, 0x13, 0xC2, 0xF9, 0xF1, 0xED, 0xB2, 0x7E, 0x91, 0xED,
		0xFA, 0x72, 0xEC, 0x66, 0x68, 0x93
};

static void init_test_scp11_certificate(GP211_SCP11_CERTIFICATE *certificate, const BYTE *keyUsage, DWORD keyUsageLength) {
	memset(certificate, 0, sizeof(*certificate));
	certificate->certificateSerialNumber[0] = 0x01;
	certificate->certificateSerialNumber[1] = 0x02;
	certificate->certificateSerialNumber[2] = 0x03;
	certificate->certificateSerialNumberLength = 3;
	memcpy(certificate->authorityIdentifier, testCaKlocIdentifier, sizeof(testCaKlocIdentifier));
	certificate->authorityIdentifierLength = sizeof(testCaKlocIdentifier);
	certificate->subjectIdentifier[0] = 0xB1;
	certificate->subjectIdentifier[1] = 0xB2;
	certificate->subjectIdentifier[2] = 0xB3;
	certificate->subjectIdentifierLength = 3;
	memcpy(certificate->keyUsage, keyUsage, keyUsageLength);
	certificate->keyUsageLength = keyUsageLength;
	certificate->effectiveDatePresent = 1;
	certificate->effectiveDate[0] = 0x20;
	certificate->effectiveDate[1] = 0x24;
	certificate->effectiveDate[2] = 0x01;
	certificate->effectiveDate[3] = 0x01;
	certificate->expirationDate[0] = 0x20;
	certificate->expirationDate[1] = 0x30;
	certificate->expirationDate[2] = 0x12;
	certificate->expirationDate[3] = 0x31;
	certificate->expirationDateLength = 4;
}

static OPGP_ERROR_STATUS build_test_scp11_certificate(const BYTE *keyUsage, DWORD keyUsageLength,
		PBYTE certificateData, PDWORD certificateDataLength) {
	GP211_SCP11_CERTIFICATE certificate;

	init_test_scp11_certificate(&certificate, keyUsage, keyUsageLength);
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

static OPGP_ERROR_STATUS build_test_x509_certificate_chain(PBYTE certificateChainData, PDWORD certificateChainDataLength,
		BOOL wrapInCertificateStore) {
	OPGP_ERROR_STATUS status;
	DWORD outputSize;
	DWORD certificateListLength = sizeof(testX509IntermediateCertificate) + sizeof(testX509OceCertificate);
	BYTE certificateList[64];

	if (certificateChainData == NULL || certificateChainDataLength == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
		return status;
	}

	memcpy(certificateList, testX509IntermediateCertificate, sizeof(testX509IntermediateCertificate));
	memcpy(certificateList + sizeof(testX509IntermediateCertificate),
			testX509OceCertificate, sizeof(testX509OceCertificate));

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

static int write_test_file(OPGP_STRING fileName, const BYTE *data, DWORD dataLength) {
	FILE *file = _tfopen(fileName, _T("wb"));
	size_t writeLength;

	if (file == NULL) {
		return -1;
	}
	writeLength = fwrite(data, 1, dataLength, file);
	if (fclose(file) != 0) {
		return -1;
	}
	return writeLength == dataLength ? 0 : -1;
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

static OPGP_ERROR_STATUS build_test_x509_named_certificate(const char *subjectCn, const char *issuerCn,
		BOOL caCertificate, PBYTE certificateData, PDWORD certificateDataLength) {
	OPGP_ERROR_STATUS status;
	FILE *publicKeyFile = NULL;
	FILE *privateKeyFile = NULL;
	EVP_PKEY *publicKey = NULL;
	EVP_PKEY *privateKey = NULL;
	X509 *certificate = NULL;
	X509_NAME *subjectName = NULL;
	X509_NAME *issuerName = NULL;
	X509_EXTENSION *extension = NULL;
	unsigned char *writePtr;
	int derLength;

	if (subjectCn == NULL || issuerCn == NULL || certificateData == NULL || certificateDataLength == NULL
			|| *certificateDataLength == 0) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
		goto end;
	}

	publicKeyFile = _tfopen(_T("ecc_public_key_test.pem"), _T("rb"));
	if (publicKeyFile == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, errno, OPGP_stringify_error(errno));
		goto end;
	}
	publicKey = PEM_read_PUBKEY(publicKeyFile, NULL, NULL, NULL);
	if (publicKey == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}

	privateKeyFile = _tfopen(_T("ecc_private_key_test.pem"), _T("rb"));
	if (privateKeyFile == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, errno, OPGP_stringify_error(errno));
		goto end;
	}
	privateKey = PEM_read_PrivateKey(privateKeyFile, NULL, NULL, NULL);
	if (privateKey == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}

	certificate = X509_new();
	if (certificate == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}
	if (X509_set_version(certificate, 2) != 1
			|| ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1) != 1
			|| X509_gmtime_adj(X509_get_notBefore(certificate), 0) == NULL
			|| X509_gmtime_adj(X509_get_notAfter(certificate), 3600) == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}
	subjectName = X509_NAME_new();
	issuerName = X509_NAME_new();
	if (subjectName == NULL || issuerName == NULL
			|| X509_NAME_add_entry_by_txt(subjectName, "CN", MBSTRING_ASC, (unsigned char *)subjectCn, -1, -1, 0) != 1
			|| X509_NAME_add_entry_by_txt(issuerName, "CN", MBSTRING_ASC, (unsigned char *)issuerCn, -1, -1, 0) != 1
			|| X509_set_subject_name(certificate, subjectName) != 1
			|| X509_set_issuer_name(certificate, issuerName) != 1
			|| X509_set_pubkey(certificate, publicKey) != 1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}

	extension = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
			caCertificate ? "critical,CA:TRUE" : "critical,CA:FALSE");
	if (extension == NULL || X509_add_ext(certificate, extension, -1) != 1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}
	X509_EXTENSION_free(extension);
	extension = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage,
			caCertificate ? "critical,digitalSignature,keyCertSign,cRLSign" : "critical,keyAgreement");
	if (extension == NULL || X509_add_ext(certificate, extension, -1) != 1
			|| X509_sign(certificate, privateKey, EVP_sha256()) <= 0) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}
	X509_EXTENSION_free(extension);
	extension = NULL;

	derLength = i2d_X509(certificate, NULL);
	if (derLength <= 0) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}
	if ((DWORD)derLength > *certificateDataLength) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER));
		goto end;
	}
	writePtr = certificateData;
	if (i2d_X509(certificate, &writePtr) != derLength) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT));
		goto end;
	}
	*certificateDataLength = (DWORD)derLength;
	OPGP_ERROR_CREATE_NO_ERROR(status);

end:
	if (extension != NULL) {
		X509_EXTENSION_free(extension);
	}
	if (issuerName != NULL) {
		X509_NAME_free(issuerName);
	}
	if (subjectName != NULL) {
		X509_NAME_free(subjectName);
	}
	if (certificate != NULL) {
		X509_free(certificate);
	}
	if (privateKey != NULL) {
		EVP_PKEY_free(privateKey);
	}
	if (publicKey != NULL) {
		EVP_PKEY_free(publicKey);
	}
	if (privateKeyFile != NULL) {
		fclose(privateKeyFile);
	}
	if (publicKeyFile != NULL) {
		fclose(publicKeyFile);
	}
	return status;
}

static OPGP_ERROR_STATUS build_test_x509_certificate(PBYTE certificateData, PDWORD certificateDataLength) {
	return build_test_x509_named_certificate("GPTest", "GPTest", 0, certificateData, certificateDataLength);
}

static OPGP_ERROR_STATUS build_sd_x509_certificate_store(void) {
	OPGP_ERROR_STATUS status;
	BYTE certificateData[1024];
	DWORD certificateDataLength = sizeof(certificateData);

	status = build_test_x509_certificate(certificateData, &certificateDataLength);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}

	sdCertificateStoreLength = 0;
	return append_tlv(sdCertificateStore, sizeof(sdCertificateStore), &sdCertificateStoreLength,
			0xBF21, certificateData, certificateDataLength);
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
		if (capdu[2] == 0xBF && capdu[3] == 0x21) {
			BYTE expectedCommand[] = {
					0x80, 0xCA, 0xBF, 0x21, 0x06, 0xA6, 0x04, 0x83, 0x02, testKeyIdentifier, testKeyVersion, 0x00
			};
			assert_true(scp11TestMode == SCP11_TEST_MODE_MUTUAL_NO_CERTIFICATE
					|| scp11TestMode == SCP11_TEST_MODE_MUTUAL_OCE_CERTIFICATE
					|| scp11TestMode == SCP11_TEST_MODE_MUTUAL_CERTIFICATE_CHAIN
					|| scp11TestMode == SCP11_TEST_MODE_MUTUAL_CERTIFICATE_CHAIN_CA_LOOKUP_FALLBACK
					|| scp11TestMode == SCP11_TEST_MODE_MUTUAL_X509_CERTIFICATE_STORE);
			assert_int_equal(apduCallCount, 0);
			assert_int_equal(capduLength, sizeof(expectedCommand));
			assert_memory_equal(capdu, expectedCommand, sizeof(expectedCommand));
			apduCallCount++;
			return set_apdu_response(rapdu, rapduLength, sdCertificateStore, sdCertificateStoreLength, 0x9000);
		}
		if (capdu[2] == 0x00 && capdu[3] == 0x83) {
			BYTE expectedCommand[] = {
					0x80, 0xCA, 0x00, 0x83, 0x07,
					0xA6, 0x05, 0x42, 0x03, 0xA1, 0xA2, 0xA3, 0x00
			};
			BYTE responseData[] = {0x83, 0x02, testCaKlocKeyIdentifier, testKeyVersion};
			assert_true(scp11TestMode == SCP11_TEST_MODE_MUTUAL_OCE_CERTIFICATE
					|| scp11TestMode == SCP11_TEST_MODE_MUTUAL_CERTIFICATE_CHAIN
					|| scp11TestMode == SCP11_TEST_MODE_MUTUAL_CERTIFICATE_CHAIN_CA_LOOKUP_FALLBACK);
			assert_int_equal(apduCallCount, 1);
			assert_int_equal(capduLength, sizeof(expectedCommand));
			assert_memory_equal(capdu, expectedCommand, sizeof(expectedCommand));
			apduCallCount++;
			if (scp11TestMode == SCP11_TEST_MODE_MUTUAL_CERTIFICATE_CHAIN_CA_LOOKUP_FALLBACK) {
				return set_apdu_response(rapdu, rapduLength, NULL, 0, 0x6A88);
			}
			return set_apdu_response(rapdu, rapduLength, responseData, sizeof(responseData), 0x9000);
		}
		if (capdu[2] == 0xFF && capdu[3] == 0x33) {
			BYTE responseData[] = {
					0xFF, 0x33, 0x09,
					0x42, 0x03, 0xA1, 0xA2, 0xA3,
					0x83, 0x02, testCaKlocKeyIdentifier, testKeyVersion
			};
			BYTE expectedCommand[] = {
					0x80, 0xCA, 0xFF, 0x33, 0x00
			};
			assert_true(scp11TestMode == SCP11_TEST_MODE_MUTUAL_CERTIFICATE_CHAIN_CA_LOOKUP_FALLBACK);
			assert_int_equal(apduCallCount, 2);
			assert_int_equal(capduLength, sizeof(expectedCommand));
			assert_memory_equal(capdu, expectedCommand, sizeof(expectedCommand));
			apduCallCount++;
			return set_apdu_response(rapdu, rapduLength, responseData, sizeof(responseData), 0x9000);
		}
		assert_true(0);
		return set_apdu_response(rapdu, rapduLength, NULL, 0, 0x6A88);
	}

	if (ins == 0x2A) {
		DWORD lc;
		BOOL moreCertificatesExpected;
		const BYTE *certificateData;
		int psoStartCallCount = scp11TestMode == SCP11_TEST_MODE_MUTUAL_CERTIFICATE_CHAIN_CA_LOOKUP_FALLBACK ? 3 : 2;

		if (scp11TestMode == SCP11_TEST_MODE_PSO_LARGE_X509_EXTENDED) {
			BYTE apduCase;
			DWORD le;

			assert_int_equal(apduCallCount, 0);
			assert_int_equal(capdu[0], 0x80);
			assert_int_equal(capdu[2], testKeyVersion);
			assert_int_equal(capdu[3], testKeyIdentifier);
			assert_int_equal(parse_apdu_case(capdu, capduLength, &apduCase, &lc, &le), 0);
			assert_int_equal(apduCase, 3);
			assert_int_equal(lc, sizeof(testValidX509Certificate));
			assert_int_equal(capduLength, lc + 7);
			assert_memory_equal(capdu + 7, testValidX509Certificate, sizeof(testValidX509Certificate));
			apduCallCount++;
			return set_apdu_response(rapdu, rapduLength, NULL, 0, 0x9000);
		}

		if (scp11TestMode == SCP11_TEST_MODE_PSO_SMALL_X509_EXTENDED_AVAILABLE) {
			assert_int_equal(apduCallCount, 0);
			assert_int_equal(capdu[0], 0x80);
			assert_int_equal(capdu[2], testKeyVersion);
			assert_int_equal(capdu[3], testKeyIdentifier);
			lc = capdu[4];
			assert_int_equal(lc, sizeof(testX509OceCertificate));
			assert_int_equal(capduLength, lc + 5);
			assert_memory_equal(capdu + 5, testX509OceCertificate, sizeof(testX509OceCertificate));
			apduCallCount++;
			return set_apdu_response(rapdu, rapduLength, NULL, 0, 0x9000);
		}

		if (scp11TestMode == SCP11_TEST_MODE_PSO_LARGE_X509
				|| scp11TestMode == SCP11_TEST_MODE_PSO_LEAF_FIRST_X509_WITH_ROOT) {
			assert_true(apduCallCount == 0 || apduCallCount == 1);
			assert_int_equal(capdu[0], 0x80);
			assert_int_equal(capdu[2], apduCallCount == 0 ? (testKeyVersion | 0x80) : testKeyVersion);
			assert_int_equal(capdu[3], testKeyIdentifier);
			lc = capdu[4];
			assert_int_equal(capduLength, lc + 5);
			if (apduCallCount == 0) {
				assert_int_equal(lc, 0xFF);
			} else {
				assert_true(lc > 0);
			}
			apduCallCount++;
			return set_apdu_response(rapdu, rapduLength, NULL, 0, 0x9000);
		}

		assert_int_equal(capdu[0], 0x80);
		assert_int_equal(capdu[2], testKeyVersion);
		assert_int_equal(capdu[3] & 0x7F,
				(scp11TestMode == SCP11_TEST_MODE_MUTUAL_OCE_CERTIFICATE
				 || scp11TestMode == SCP11_TEST_MODE_MUTUAL_CERTIFICATE_CHAIN
				 || scp11TestMode == SCP11_TEST_MODE_MUTUAL_CERTIFICATE_CHAIN_CA_LOOKUP_FALLBACK)
					? testCaKlocKeyIdentifier : testKeyIdentifier);
		moreCertificatesExpected = (capdu[3] & 0x80) != 0;
		switch (scp11TestMode) {
			case SCP11_TEST_MODE_PSO_CHAIN:
			case SCP11_TEST_MODE_PSO_CHAIN_X509:
				assert_true(apduCallCount == 0 || apduCallCount == 1);
				assert_true((apduCallCount == 0 && moreCertificatesExpected)
						|| (apduCallCount == 1 && !moreCertificatesExpected));
				break;
			case SCP11_TEST_MODE_MUTUAL_OCE_CERTIFICATE:
				assert_int_equal(apduCallCount, 2);
				assert_false(moreCertificatesExpected);
				break;
			case SCP11_TEST_MODE_MUTUAL_CERTIFICATE_CHAIN:
			case SCP11_TEST_MODE_MUTUAL_CERTIFICATE_CHAIN_CA_LOOKUP_FALLBACK:
				assert_true(apduCallCount == psoStartCallCount || apduCallCount == psoStartCallCount + 1);
				assert_true((apduCallCount == psoStartCallCount && moreCertificatesExpected)
						|| (apduCallCount == psoStartCallCount + 1 && !moreCertificatesExpected));
				break;
			default:
				assert_true(0);
				break;
		}
		lc = capdu[4];
		assert_int_equal(capduLength, lc + 5);
		certificateData = capdu + 5;
		if (scp11TestMode == SCP11_TEST_MODE_PSO_CHAIN_X509) {
			if (moreCertificatesExpected) {
				assert_int_equal(lc, sizeof(testX509IntermediateCertificate));
				assert_memory_equal(certificateData, testX509IntermediateCertificate, sizeof(testX509IntermediateCertificate));
			} else {
				assert_int_equal(lc, sizeof(testX509OceCertificate));
				assert_memory_equal(certificateData, testX509OceCertificate, sizeof(testX509OceCertificate));
			}
		} else {
			GP211_SCP11_CERTIFICATE certificate;
			status = GP211_parse_scp11_certificate((PBYTE)certificateData, lc, &certificate);
			assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
			if (moreCertificatesExpected) {
				assert_int_equal(certificate.keyUsageLength, sizeof(GP211_SCP11_KEY_USAGE_DIGITAL_SIGNATURE_VERIFICATION));
				assert_memory_equal(certificate.keyUsage, GP211_SCP11_KEY_USAGE_DIGITAL_SIGNATURE_VERIFICATION,
						sizeof(GP211_SCP11_KEY_USAGE_DIGITAL_SIGNATURE_VERIFICATION));
			} else {
				assert_int_equal(certificate.keyUsageLength, sizeof(GP211_SCP11_KEY_USAGE_KEY_AGREEMENT));
				assert_memory_equal(certificate.keyUsage, GP211_SCP11_KEY_USAGE_KEY_AGREEMENT,
						sizeof(GP211_SCP11_KEY_USAGE_KEY_AGREEMENT));
			}
		}
		apduCallCount++;
		return set_apdu_response(rapdu, rapduLength, NULL, 0, 0x9000);
	}

	if (ins == 0x82) {
		BYTE responseData[256];
		DWORD responseDataLength = sizeof(responseData);
		DWORD lc;
		const BYTE *commandData;

		switch (scp11TestMode) {
			case SCP11_TEST_MODE_MUTUAL_NO_CERTIFICATE:
			case SCP11_TEST_MODE_MUTUAL_X509_CERTIFICATE_STORE:
				assert_int_equal(apduCallCount, 1);
				break;
			case SCP11_TEST_MODE_MUTUAL_OCE_CERTIFICATE:
				assert_int_equal(apduCallCount, 3);
				break;
			case SCP11_TEST_MODE_MUTUAL_CERTIFICATE_CHAIN:
				assert_int_equal(apduCallCount, 4);
				break;
			case SCP11_TEST_MODE_MUTUAL_CERTIFICATE_CHAIN_CA_LOOKUP_FALLBACK:
				assert_int_equal(apduCallCount, 5);
				break;
			default:
				assert_true(0);
				break;
		}
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

	if (ins == 0xE2) {
		DWORD lc;
		GP_SIMPLE_TLV crtTlv;
		GP_SIMPLE_TLV keyReferenceTlv;
		GP_SIMPLE_TLV certificateStoreTlv;
		GP_SIMPLE_TLV expectedCertificateStoreTlv;
		GP_SIMPLE_TLV whitelistCounterTlv;
		GP_SIMPLE_TLV whitelistTlv;
		GP_SIMPLE_TLV csnTlv;
		DWORD offset;
		DWORD whitelistOffset;

		assert_true(scp11TestMode == SCP11_TEST_MODE_STORE_ECKA_CERTIFICATE
				|| scp11TestMode == SCP11_TEST_MODE_STORE_WHITELIST
				|| scp11TestMode == SCP11_TEST_MODE_STORE_WHITELIST_EMPTY);
		assert_int_equal(apduCallCount, 0);
		assert_int_equal(capdu[0], 0x80);
		assert_int_equal(capdu[2], STORE_DATA_FORMAT_BER_TLV | 0x80);
		assert_int_equal(capdu[3], 0x00);
		lc = capdu[4];
		assert_int_equal(capduLength, lc + 5);

		assert_true(parse_simple_tlv(capdu + 5, lc, &crtTlv) > 0);
		assert_int_equal(crtTlv.tag, 0xA6);
		assert_true(parse_simple_tlv(crtTlv.value, crtTlv.length, &keyReferenceTlv) > 0);
		assert_int_equal(keyReferenceTlv.tag, 0x83);
		assert_int_equal(keyReferenceTlv.length, 2);
		assert_int_equal(keyReferenceTlv.value[0], testKeyIdentifier);
		assert_int_equal(keyReferenceTlv.value[1], testKeyVersion);

		offset = crtTlv.tlvLength;
		if (scp11TestMode == SCP11_TEST_MODE_STORE_ECKA_CERTIFICATE) {
			assert_true(expectedStoreDataLength > 0);
			assert_true(parse_simple_tlv(capdu + 5 + offset, lc - offset, &certificateStoreTlv) > 0);
			assert_int_equal(certificateStoreTlv.tag, 0xBF21);
			assert_int_equal(offset + certificateStoreTlv.tlvLength, lc);
			assert_true(parse_simple_tlv(expectedStoreData, expectedStoreDataLength, &expectedCertificateStoreTlv) > 0);
			assert_int_equal(expectedCertificateStoreTlv.tag, 0xBF21);
			assert_int_equal(certificateStoreTlv.length, expectedCertificateStoreTlv.length);
			assert_memory_equal(certificateStoreTlv.value, expectedCertificateStoreTlv.value, expectedCertificateStoreTlv.length);
		} else {
			if (scp11TestMode == SCP11_TEST_MODE_STORE_WHITELIST) {
				assert_true(parse_simple_tlv(capdu + 5 + offset, lc - offset, &whitelistCounterTlv) > 0);
				assert_int_equal(whitelistCounterTlv.tag, 0x92);
				assert_int_equal(whitelistCounterTlv.length, 2);
				assert_int_equal(whitelistCounterTlv.value[0], 0x12);
				assert_int_equal(whitelistCounterTlv.value[1], 0x34);
				offset += whitelistCounterTlv.tlvLength;
			}

			assert_true(parse_simple_tlv(capdu + 5 + offset, lc - offset, &whitelistTlv) > 0);
			assert_int_equal(whitelistTlv.tag, 0x70);
			assert_int_equal(offset + whitelistTlv.tlvLength, lc);

			if (scp11TestMode == SCP11_TEST_MODE_STORE_WHITELIST_EMPTY) {
				assert_int_equal(whitelistTlv.length, 0);
			} else {
				whitelistOffset = 0;
				assert_true(parse_simple_tlv(whitelistTlv.value + whitelistOffset,
							whitelistTlv.length - whitelistOffset, &csnTlv) > 0);
				assert_int_equal(csnTlv.tag, 0x93);
				assert_int_equal(csnTlv.length, sizeof(testWhitelistCsn1));
				assert_memory_equal(csnTlv.value, testWhitelistCsn1, sizeof(testWhitelistCsn1));
				whitelistOffset += csnTlv.tlvLength;

				assert_true(parse_simple_tlv(whitelistTlv.value + whitelistOffset,
							whitelistTlv.length - whitelistOffset, &csnTlv) > 0);
				assert_int_equal(csnTlv.tag, 0x93);
				assert_int_equal(csnTlv.length, sizeof(testWhitelistCsn2));
				assert_memory_equal(csnTlv.value, testWhitelistCsn2, sizeof(testWhitelistCsn2));
				whitelistOffset += csnTlv.tlvLength;
				assert_int_equal(whitelistOffset, whitelistTlv.length);
			}
		}

		apduCallCount++;
		return set_apdu_response(rapdu, rapduLength, NULL, 0, 0x9000);
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
	expectedStoreDataLength = 0;
	apduCallCount = 0;
	scp11TestMode = SCP11_TEST_MODE_NONE;
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

static void scp11_certificate_build_with_embedded_public_key(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE certificateData[512];
	DWORD certificateDataLength = sizeof(certificateData);
	GP211_SCP11_CERTIFICATE certificate;
	GP211_SCP11_CERTIFICATE parsedCertificate;

	(void)state;

	init_test_scp11_certificate(&certificate, GP211_SCP11_KEY_USAGE_KEY_AGREEMENT,
			sizeof(GP211_SCP11_KEY_USAGE_KEY_AGREEMENT));
	memcpy(certificate.publicKey, oceStaticPublicKey, oceStaticPublicKeyLength);
	certificate.publicKeyLength = oceStaticPublicKeyLength;
	certificate.keyParameterReference[0] = GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_P256;
	certificate.keyParameterReferenceLength = 1;

	status = GP211_build_scp11_certificate(&certificate,
			NULL, NULL,
			_T("ecc_private_key_test.pem"), NULL,
			certificateData, &certificateDataLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(certificate.signatureLength, 64);

	status = GP211_parse_scp11_certificate(certificateData, certificateDataLength, &parsedCertificate);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(parsedCertificate.publicKeyLength, oceStaticPublicKeyLength);
	assert_memory_equal(parsedCertificate.publicKey, oceStaticPublicKey, oceStaticPublicKeyLength);
	assert_int_equal(parsedCertificate.keyParameterReferenceLength, 1);
	assert_int_equal(parsedCertificate.keyParameterReference[0], GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_P256);
	assert_int_equal(parsedCertificate.signatureLength, 64);
}

static void parse_certificate_store_gp_legacy(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE certificateStore[1024];
	DWORD certificateStoreLength = sizeof(certificateStore);
	BYTE parsedStore[8192];
	DWORD parsedStoreLength = sizeof(parsedStore);
	GP211_SCP11_CERTIFICATE certificate;

	(void)state;

	status = build_test_scp11_certificate_chain(certificateStore, &certificateStoreLength, 1);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	status = GP211_parse_certificate_store(certificateStore, certificateStoreLength, parsedStore, &parsedStoreLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(parsedStoreLength, 2 * sizeof(GP211_SCP11_CERTIFICATE));

	memcpy(&certificate, parsedStore, sizeof(certificate));
	assert_int_equal(certificate.keyUsageLength, sizeof(GP211_SCP11_KEY_USAGE_DIGITAL_SIGNATURE_VERIFICATION));
	assert_memory_equal(certificate.keyUsage, GP211_SCP11_KEY_USAGE_DIGITAL_SIGNATURE_VERIFICATION,
			sizeof(GP211_SCP11_KEY_USAGE_DIGITAL_SIGNATURE_VERIFICATION));

	memcpy(&certificate, parsedStore + sizeof(certificate), sizeof(certificate));
	assert_int_equal(certificate.keyUsageLength, sizeof(GP211_SCP11_KEY_USAGE_KEY_AGREEMENT));
	assert_memory_equal(certificate.keyUsage, GP211_SCP11_KEY_USAGE_KEY_AGREEMENT,
			sizeof(GP211_SCP11_KEY_USAGE_KEY_AGREEMENT));
}

static void parse_certificate_store_x509(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE certificateList[1024];
	DWORD certificateListLength = 0;
	BYTE certificateStore[1200];
	DWORD certificateStoreLength = 0;
	BYTE parsedStore[8192];
	DWORD parsedStoreLength = sizeof(parsedStore) - 1;

	(void)state;

	memcpy(certificateList + certificateListLength, testValidX509Certificate, sizeof(testValidX509Certificate));
	certificateListLength += sizeof(testValidX509Certificate);
	memcpy(certificateList + certificateListLength, testValidX509Certificate, sizeof(testValidX509Certificate));
	certificateListLength += sizeof(testValidX509Certificate);

	status = append_tlv(certificateStore, sizeof(certificateStore), &certificateStoreLength,
			0xBF21, certificateList, certificateListLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	status = GP211_parse_certificate_store(certificateStore, certificateStoreLength, parsedStore, &parsedStoreLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_true(parsedStoreLength > 0);
	parsedStore[parsedStoreLength] = '\0';

	assert_non_null(strstr((const char *)parsedStore, "-----BEGIN CERTIFICATE-----"));
	assert_non_null(strstr((const char *)parsedStore, "-----END CERTIFICATE-----"));
}

static void perform_security_operation_certificate_chain(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE certificateChain[1024];
	DWORD certificateChainLength = sizeof(certificateChain);

	(void)state;

	status = build_test_scp11_certificate_chain(certificateChain, &certificateChainLength, 0);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	apduCallCount = 0;
	scp11TestMode = SCP11_TEST_MODE_PSO_CHAIN;
	status = GP211_perform_security_operation_certificate_chain(cardContext, cardInfo, NULL,
			testKeyVersion, testKeyIdentifier, certificateChain, certificateChainLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(apduCallCount, 2);
}

static void perform_security_operation_x509_certificate_chain(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE certificateChain[256];
	DWORD certificateChainLength = sizeof(certificateChain);

	(void)state;

	status = build_test_x509_certificate_chain(certificateChain, &certificateChainLength, 1);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	apduCallCount = 0;
	scp11TestMode = SCP11_TEST_MODE_PSO_CHAIN_X509;
	status = GP211_perform_security_operation_certificate_chain(cardContext, cardInfo, NULL,
			testKeyVersion, testKeyIdentifier, certificateChain, certificateChainLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(apduCallCount, 2);
}

static void perform_security_operation_large_x509_certificate_uses_p1_chaining(void **state) {
	OPGP_ERROR_STATUS status;

	(void)state;

	apduCallCount = 0;
	scp11TestMode = SCP11_TEST_MODE_PSO_LARGE_X509;
	status = GP211_perform_security_operation(cardContext, cardInfo, NULL,
			testKeyVersion, testKeyIdentifier,
			(PBYTE)testValidX509Certificate, sizeof(testValidX509Certificate),
			0);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(apduCallCount, 2);
}

static void perform_security_operation_large_x509_certificate_uses_extended_apdu_when_supported(void **state) {
	OPGP_ERROR_STATUS status;

	(void)state;

	apduCallCount = 0;
	scp11TestMode = SCP11_TEST_MODE_PSO_LARGE_X509_EXTENDED;
	cardInfo.extendedAPDUSupported = 1;
	status = GP211_perform_security_operation(cardContext, cardInfo, NULL,
			testKeyVersion, testKeyIdentifier,
			(PBYTE)testValidX509Certificate, sizeof(testValidX509Certificate),
			0);
	cardInfo.extendedAPDUSupported = 0;
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(apduCallCount, 1);
}

static void perform_security_operation_small_x509_certificate_uses_short_apdu_when_extended_available(void **state) {
	OPGP_ERROR_STATUS status;

	(void)state;

	apduCallCount = 0;
	scp11TestMode = SCP11_TEST_MODE_PSO_SMALL_X509_EXTENDED_AVAILABLE;
	cardInfo.extendedAPDUSupported = 1;
	status = GP211_perform_security_operation(cardContext, cardInfo, NULL,
			testKeyVersion, testKeyIdentifier,
			(PBYTE)testX509OceCertificate, sizeof(testX509OceCertificate),
			0);
	cardInfo.extendedAPDUSupported = 0;
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(apduCallCount, 1);
}

static void perform_security_operation_leaf_first_x509_chain_omits_root(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE oceCertificate[1024];
	DWORD oceCertificateLength = sizeof(oceCertificate);
	BYTE caCertificate[1024];
	DWORD caCertificateLength = sizeof(caCertificate);
	BYTE certificateChain[2048];
	DWORD certificateChainLength = 0;

	(void)state;

	status = build_test_x509_named_certificate("GP OCE", "GP CA", 0, oceCertificate, &oceCertificateLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	status = build_test_x509_named_certificate("GP CA", "GP CA", 1, caCertificate, &caCertificateLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	memcpy(certificateChain + certificateChainLength, oceCertificate, oceCertificateLength);
	certificateChainLength += oceCertificateLength;
	memcpy(certificateChain + certificateChainLength, caCertificate, caCertificateLength);
	certificateChainLength += caCertificateLength;

	apduCallCount = 0;
	scp11TestMode = SCP11_TEST_MODE_PSO_LEAF_FIRST_X509_WITH_ROOT;
	status = GP211_perform_security_operation_certificate_chain(cardContext, cardInfo, NULL,
			testKeyVersion, testKeyIdentifier,
			certificateChain, certificateChainLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(apduCallCount, 2);
}

static void store_data_ecka_certificate_with_certificate_list(void **state) {
	OPGP_ERROR_STATUS status;
	GP_SIMPLE_TLV certificateStoreTlv;
	OPGP_STRING certificateStoreFileName = _T("scp11_certificate_list_test.bin");

	(void)state;
	reset_scp11a_test_state();
	scp11TestMode = SCP11_TEST_MODE_STORE_ECKA_CERTIFICATE;

	assert_true(parse_simple_tlv(sdCertificateStore, sdCertificateStoreLength, &certificateStoreTlv) > 0);
	assert_int_equal(certificateStoreTlv.tag, 0xBF21);
	assert_int_equal(write_test_file(certificateStoreFileName, certificateStoreTlv.value, certificateStoreTlv.length), 0);
	assert_true(sdCertificateStoreLength <= sizeof(expectedStoreData));
	memcpy(expectedStoreData, sdCertificateStore, sdCertificateStoreLength);
	expectedStoreDataLength = sdCertificateStoreLength;

	status = GP211_store_data_ecka_certificate(cardContext, cardInfo, NULL,
			testKeyVersion, testKeyIdentifier, certificateStoreFileName);
	remove("scp11_certificate_list_test.bin");

	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(apduCallCount, 1);
}

static void store_data_ecka_certificate_with_certificate_store(void **state) {
	OPGP_ERROR_STATUS status;
	OPGP_STRING certificateStoreFileName = _T("scp11_certificate_store_test.bin");

	(void)state;
	reset_scp11a_test_state();
	scp11TestMode = SCP11_TEST_MODE_STORE_ECKA_CERTIFICATE;

	assert_int_equal(write_test_file(certificateStoreFileName, sdCertificateStore, sdCertificateStoreLength), 0);
	assert_true(sdCertificateStoreLength <= sizeof(expectedStoreData));
	memcpy(expectedStoreData, sdCertificateStore, sdCertificateStoreLength);
	expectedStoreDataLength = sdCertificateStoreLength;

	status = GP211_store_data_ecka_certificate(cardContext, cardInfo, NULL,
			testKeyVersion, testKeyIdentifier, certificateStoreFileName);
	remove("scp11_certificate_store_test.bin");

	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(apduCallCount, 1);
}

static void store_data_ecka_certificate_with_pem_certificate_list(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE expectedDerCertificateList[] = {0x30, 0x03, 0x01, 0x02, 0x03};
	BYTE pemCertificateList[] =
		"-----BEGIN CERTIFICATE-----\n"
		"MAMBAgM=\n"
		"-----END CERTIFICATE-----\n";
	OPGP_STRING certificateStoreFileName = _T("scp11_raw_certificate_test.pem");

	(void)state;
	reset_scp11a_test_state();
	scp11TestMode = SCP11_TEST_MODE_STORE_ECKA_CERTIFICATE;

	assert_int_equal(write_test_file(certificateStoreFileName, pemCertificateList, sizeof(pemCertificateList) - 1), 0);
	expectedStoreDataLength = 0;
	assert_int_equal(append_tlv(expectedStoreData, sizeof(expectedStoreData), &expectedStoreDataLength,
			0xBF21, expectedDerCertificateList, sizeof(expectedDerCertificateList)).errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	status = GP211_store_data_ecka_certificate(cardContext, cardInfo, NULL,
			testKeyVersion, testKeyIdentifier, certificateStoreFileName);
	remove("scp11_raw_certificate_test.pem");

	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(apduCallCount, 1);
}

static void store_data_whitelist_with_certificate_serial_numbers(void **state) {
	OPGP_ERROR_STATUS status;
	PBYTE certificateSerialNumbers[] = {testWhitelistCsn1, testWhitelistCsn2};
	DWORD certificateSerialNumberLengths[] = {sizeof(testWhitelistCsn1), sizeof(testWhitelistCsn2)};

	(void)state;
	reset_scp11a_test_state();
	scp11TestMode = SCP11_TEST_MODE_STORE_WHITELIST;

	status = GP211_store_data_whitelist(cardContext, cardInfo, NULL,
			testKeyVersion, testKeyIdentifier, 1, 0x1234,
			certificateSerialNumbers, certificateSerialNumberLengths,
			sizeof(certificateSerialNumbers) / sizeof(certificateSerialNumbers[0]));

	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(apduCallCount, 1);
}

static void store_data_whitelist_with_empty_certificate_serial_numbers(void **state) {
	OPGP_ERROR_STATUS status;

	(void)state;
	reset_scp11a_test_state();
	scp11TestMode = SCP11_TEST_MODE_STORE_WHITELIST_EMPTY;

	status = GP211_store_data_whitelist(cardContext, cardInfo, NULL,
			testKeyVersion, testKeyIdentifier, 0, 0,
			NULL, NULL, 0);

	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(apduCallCount, 1);
}

static void store_data_whitelist_rejects_invalid_certificate_serial_number(void **state) {
	OPGP_ERROR_STATUS status;
	PBYTE certificateSerialNumbers[] = {testWhitelistCsn1};
	DWORD certificateSerialNumberLengths[] = {0};

	(void)state;
	reset_scp11a_test_state();
	scp11TestMode = SCP11_TEST_MODE_STORE_WHITELIST;

	status = GP211_store_data_whitelist(cardContext, cardInfo, NULL,
			testKeyVersion, testKeyIdentifier, 0, 0,
			certificateSerialNumbers, certificateSerialNumberLengths, 1);

	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_FAILURE);
	assert_int_equal(status.errorCode, OPGP_ERROR_INVALID_RESPONSE_DATA);
	assert_int_equal(apduCallCount, 0);
}

static void mutual_authentication_scp11a(void **state) {
	OPGP_ERROR_STATUS status;

	(void)state;
	reset_scp11a_test_state();
	scp11TestMode = SCP11_TEST_MODE_MUTUAL_NO_CERTIFICATE;

	status = GP211_mutual_authentication(cardContext, cardInfo,
			oceStaticPrivateKey, NULL, NULL, NULL,
			16, testKeyVersion, testKeyIdentifier,
			GP211_SCP11, 0x00,
			GP211_SCP03_SECURITY_LEVEL_C_MAC, OPGP_DERIVATION_METHOD_NONE,
			NULL, 0, &securityInfo211);

	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_scp11a_security_info(2);
}

static void mutual_authentication_scp11a_with_oce_certificate(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE oceCertificate[512];
	DWORD oceCertificateLength = sizeof(oceCertificate);

	(void)state;
	reset_scp11a_test_state();
	scp11TestMode = SCP11_TEST_MODE_MUTUAL_OCE_CERTIFICATE;

	status = build_test_scp11_certificate(GP211_SCP11_KEY_USAGE_KEY_AGREEMENT,
			sizeof(GP211_SCP11_KEY_USAGE_KEY_AGREEMENT),
			oceCertificate, &oceCertificateLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	status = GP211_mutual_authentication(cardContext, cardInfo,
			oceStaticPrivateKey, NULL, NULL, NULL,
			16, testKeyVersion, testKeyIdentifier,
			GP211_SCP11, 0x00,
			GP211_SCP03_SECURITY_LEVEL_C_MAC, OPGP_DERIVATION_METHOD_NONE,
			oceCertificate, oceCertificateLength, &securityInfo211);

	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_scp11a_security_info(4);
}

static void mutual_authentication_scp11a_with_certificate_chain(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE certificateChain[1024];
	DWORD certificateChainLength = sizeof(certificateChain);

	(void)state;
	reset_scp11a_test_state();
	scp11TestMode = SCP11_TEST_MODE_MUTUAL_CERTIFICATE_CHAIN;

	status = build_test_scp11_certificate_chain(certificateChain, &certificateChainLength, 1);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	status = GP211_mutual_authentication(cardContext, cardInfo,
			oceStaticPrivateKey, NULL, NULL, NULL,
			16, testKeyVersion, testKeyIdentifier,
			GP211_SCP11, 0x00,
			GP211_SCP03_SECURITY_LEVEL_C_MAC, OPGP_DERIVATION_METHOD_NONE,
			certificateChain, certificateChainLength, &securityInfo211);

	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_scp11a_security_info(5);
}

static void mutual_authentication_scp11a_with_ca_lookup_fallback(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE certificateChain[1024];
	DWORD certificateChainLength = sizeof(certificateChain);

	(void)state;
	reset_scp11a_test_state();
	scp11TestMode = SCP11_TEST_MODE_MUTUAL_CERTIFICATE_CHAIN_CA_LOOKUP_FALLBACK;

	status = build_test_scp11_certificate_chain(certificateChain, &certificateChainLength, 1);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	status = GP211_mutual_authentication(cardContext, cardInfo,
			oceStaticPrivateKey, NULL, NULL, NULL,
			16, testKeyVersion, testKeyIdentifier,
			GP211_SCP11, 0x00,
			GP211_SCP03_SECURITY_LEVEL_C_MAC, OPGP_DERIVATION_METHOD_NONE,
			certificateChain, certificateChainLength, &securityInfo211);

	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_scp11a_security_info(6);
}

static void mutual_authentication_scp11a_with_x509_sd_certificate_store(void **state) {
	OPGP_ERROR_STATUS status;

	(void)state;
	reset_scp11a_test_state();

	status = build_sd_x509_certificate_store();
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	scp11TestMode = SCP11_TEST_MODE_MUTUAL_X509_CERTIFICATE_STORE;

	status = GP211_mutual_authentication(cardContext, cardInfo,
			oceStaticPrivateKey, NULL, NULL, NULL,
			16, testKeyVersion, testKeyIdentifier,
			GP211_SCP11, 0x00,
			GP211_SCP03_SECURITY_LEVEL_C_MAC, OPGP_DERIVATION_METHOD_NONE,
			NULL, 0, &securityInfo211);

	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_scp11a_security_info(2);

	status = build_sd_certificate_store(GP211_KEY_TYPE_ECC_KEY_PARAMETER_REFERENCE_P256);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
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
			cmocka_unit_test(scp11_certificate_build_with_embedded_public_key),
			cmocka_unit_test(parse_certificate_store_gp_legacy),
			cmocka_unit_test(parse_certificate_store_x509),
			cmocka_unit_test(perform_security_operation_certificate_chain),
			cmocka_unit_test(perform_security_operation_x509_certificate_chain),
			cmocka_unit_test(perform_security_operation_large_x509_certificate_uses_p1_chaining),
			cmocka_unit_test(perform_security_operation_large_x509_certificate_uses_extended_apdu_when_supported),
			cmocka_unit_test(perform_security_operation_small_x509_certificate_uses_short_apdu_when_extended_available),
			cmocka_unit_test(perform_security_operation_leaf_first_x509_chain_omits_root),
			cmocka_unit_test(store_data_ecka_certificate_with_certificate_list),
			cmocka_unit_test(store_data_ecka_certificate_with_certificate_store),
			cmocka_unit_test(store_data_ecka_certificate_with_pem_certificate_list),
			cmocka_unit_test(store_data_whitelist_with_certificate_serial_numbers),
			cmocka_unit_test(store_data_whitelist_with_empty_certificate_serial_numbers),
			cmocka_unit_test(store_data_whitelist_rejects_invalid_certificate_serial_number),
			cmocka_unit_test(mutual_authentication_scp11a),
			cmocka_unit_test(mutual_authentication_scp11a_with_oce_certificate),
			cmocka_unit_test(mutual_authentication_scp11a_with_certificate_chain),
			cmocka_unit_test(mutual_authentication_scp11a_with_ca_lookup_fallback),
			cmocka_unit_test(mutual_authentication_scp11a_with_x509_sd_certificate_store)
	};
	return cmocka_run_group_tests_name("SCP11", tests, setup, NULL);
}
