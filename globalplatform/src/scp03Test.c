/*  Copyright (c) 2019, Karsten Ohme
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
#include <setjmp.h>
#include "globalplatform/globalplatform.h"
#include <stdio.h>
#include <string.h>
#include <cmocka.h>

/**
 * Global card context for the test.
 */
static OPGP_CARD_CONTEXT cardContext;

/**
 * Global card info for the test.
 */
static OPGP_CARD_INFO cardInfo;

/**
 * GP 2.1.1 Security Info.
 */
static GP211_SECURITY_INFO securityInfo211;

int __wrap_RAND_bytes(unsigned char *buf, int num) {
	BYTE *__random = (BYTE *) mock();
	check_expected(num);
	memcpy(buf, __random,  num);
	return 1;
}

OPGP_ERROR_STATUS send_APDU(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, PBYTE capdu, DWORD capduLength, PBYTE rapdu, PDWORD rapduLength) {
	OPGP_ERROR_STATUS status;
	PBYTE __rapdu = (PBYTE) mock();
	PDWORD __rapduLength = (PDWORD) mock();
	check_expected(capdu);
	memcpy(rapdu, __rapdu, *__rapduLength);
	*rapduLength = *__rapduLength;
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static void cencrypt_cmac(void **state) {
	OPGP_ERROR_STATUS status;

	BYTE hostChallenge[] = {0xB2, 0xBD, 0xE1, 0xA2, 0xDC, 0x66, 0xBD, 0x56};

	BYTE sMac[] = {0x58, 0x56, 0x33, 0x62, 0xEC, 0x5A, 0x45, 0x41, 0xAB, 0xCD, 0x32, 0xB3, 0x4B, 0x1E, 0xAE, 0x7D};
	BYTE sEnc[] = {0xF9, 0x95, 0xD0, 0xA0, 0x69, 0x33, 0x5C, 0x7D, 0xF4, 0x2E, 0x59, 0x03, 0x17, 0xFF, 0xEA, 0x6D};
	BYTE dek[] = {0x0A, 0x02, 0xA6, 0xD6, 0x87, 0x40, 0x6D, 0xCF, 0xA0, 0x9D, 0xC7, 0x0B, 0x3E, 0xDB, 0x7E, 0x38};

	BYTE sessionEnc[] = {0x9B, 0x84, 0x1B, 0xB6, 0x3D, 0x10, 0x87, 0x48, 0x4F, 0xF7, 0xF1, 0x68, 0x02, 0x01, 0x72, 0x43};
	BYTE sessionCMac[] = {0x81, 0x17, 0xFE, 0x5A, 0xDE, 0xD7, 0x4A, 0xC0, 0xDA, 0xAB, 0xE9, 0xFB, 0x81, 0xDB, 0xDB, 0x67};
	BYTE sessionRMac[] = {0x45, 0x21, 0xD7, 0x5E, 0x4D, 0x6F, 0x60, 0xDB, 0xFB, 0x8A, 0xB4, 0xEE, 0x25, 0x4E, 0xF6, 0xF1};

	BYTE initializeUpdateRequest[] = {0x80, 0x50, 0x00, 0x00, 0x08, 0xB2, 0xBD, 0xE1, 0xA2, 0xDC, 0x66, 0xBD, 0x56, 0x00};
	BYTE initializeUpdateResponse[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x03, 0x70, 0xC4, 0x09, 0x32, 0xA6, 0xFE, 0xFE, 0xAE, 0xB2, 0xE1,
			0x27, 0x18, 0x51, 0x70, 0xF4, 0x5F, 0xCA, 0x00, 0x00, 0x15, 0x90, 0x00};
	DWORD initializeUpdateResponseLength = sizeof(initializeUpdateResponse);

	BYTE extAuthRequest[] = {0x84, 0x82, 0x03, 0x00, 0x10, 0x59, 0xD5, 0x4D, 0x93, 0x24, 0x23, 0xD2, 0x9F, 0x63, 0x13, 0xC9, 0x70, 0x87, 0x5F, 0x8C, 0x2F};
	BYTE extAuthResponse[] = {0x90, 0x00};
	DWORD extAuthResponseLength = sizeof(extAuthResponse);

	BYTE deleteRequest[] = {0x84, 0xE4, 0x00, 0x80, 0x18, 0x29, 0xF0, 0x6A, 0xEC,
			0x31, 0x80, 0xB3, 0xEF, 0xE9, 0x1F, 0xF6, 0x62, 0x31, 0x0B, 0x94, 0x5D, 0xE0, 0xD5, 0xFE, 0x66, 0xAD, 0x67, 0xA5, 0xB6};
	BYTE deleteResponse[] = {0x00, 0x90, 0x00};
	DWORD deleteResponseLength = sizeof(deleteResponse);

	BYTE cardChallenge[] = {0xC4, 0x09, 0x32, 0xA6, 0xFE, 0xFE, 0xAE, 0xB2};
	BYTE cardCryptogram[] = {0xE1, 0x27, 0x18, 0x51, 0x70, 0xF4, 0x5F, 0xCA};
	BYTE sequenceCounter[] = {0x00, 0x00, 0x15};

	OPGP_AID appAid;
	BYTE aid[] = {0xA0, 0x01, 0x00, 0x01, 0x51, 0x41, 0x43, 0x4C};
	memcpy(appAid.AID, aid, sizeof(aid));
	appAid.AIDLength = sizeof(aid);

	GP211_RECEIPT_DATA receiptData;
	DWORD receiptDataLength;


	will_return(__wrap_RAND_bytes, hostChallenge);
	expect_value(__wrap_RAND_bytes, num, 8);

	expect_memory(send_APDU, capdu, initializeUpdateRequest, sizeof(initializeUpdateRequest));
	will_return(send_APDU, initializeUpdateResponse);
	will_return(send_APDU, &initializeUpdateResponseLength);

	expect_memory(send_APDU, capdu, extAuthRequest, sizeof(extAuthRequest));
	will_return(send_APDU, extAuthResponse);
	will_return(send_APDU, &extAuthResponseLength);

	memcpy(securityInfo211.invokingAid, (void *)GP231_ISD_AID, sizeof(GP231_ISD_AID));
	securityInfo211.invokingAidLength = sizeof(GP231_ISD_AID);

	status = GP211_mutual_authentication(cardContext, cardInfo, NULL, sEnc, sMac, dek, 0, 0,
			GP211_SCP03, GP211_SCP03_IMPL_i70, GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC, 0, &securityInfo211);
	assert_int_equal(status.errorCode, OPGP_ERROR_STATUS_SUCCESS);
	assert_memory_equal(securityInfo211.encryptionSessionKey, sessionEnc, 16);
	assert_memory_equal(securityInfo211.C_MACSessionKey, sessionCMac, 16);
	assert_memory_equal(securityInfo211.R_MACSessionKey, sessionRMac, 16);

//	expect_memory(send_APDU, capdu, deleteRequest, sizeof(deleteRequest));
//	will_return(send_APDU, deleteResponse);
//	will_return(send_APDU, &deleteResponseLength);
//
//	GP211_delete_application(cardContext, cardInfo, &securityInfo211, &appAid, 1, &receiptData, &receiptDataLength);
}

static void mutual_auth2(void **state) {
	OPGP_ERROR_STATUS status;

	BYTE hostChallenge[] = {0x9B, 0xD6, 0xBF, 0x87, 0x8F, 0xB8, 0xE9, 0x91};

	BYTE sMac[] = {0x58, 0x56, 0x33, 0x62, 0xEC, 0x5A, 0x45, 0x41, 0xAB, 0xCD, 0x32, 0xB3, 0x4B, 0x1E, 0xAE, 0x7D};
	BYTE sEnc[] = {0xF9, 0x95, 0xD0, 0xA0, 0x69, 0x33, 0x5C, 0x7D, 0xF4, 0x2E, 0x59, 0x03, 0x17, 0xFF, 0xEA, 0x6D};
	BYTE dek[] = {0x0A, 0x02, 0xA6, 0xD6, 0x87, 0x40, 0x6D, 0xCF, 0xA0, 0x9D, 0xC7, 0x0B, 0x3E, 0xDB, 0x7E, 0x38};

	BYTE sessionEnc[] = {0xD8, 0x3E, 0xE3, 0x8C, 0x99, 0x54, 0xC8, 0x07, 0x89, 0x87, 0xA5, 0xE9, 0xEE, 0x6A, 0xB1, 0x3C};
	BYTE sessionCMac[] = {0x6F, 0xF3, 0x77, 0x16, 0xE0, 0x41, 0x30, 0x65, 0xE8, 0xDF, 0xD0, 0x8B, 0xF1, 0xE9, 0xEC, 0x5E};
	BYTE sessionRMac[] = {0x02, 0x54, 0xC7, 0x86, 0xE5, 0x7A, 0xCA, 0x89, 0x82, 0x67, 0x0C, 0x1C, 0x1A, 0x05, 0xFF, 0x12};

	BYTE initializeUpdateRequest[] = {0x80, 0x50, 0x00, 0x00, 0x08, 0x9B, 0xD6, 0xBF, 0x87, 0x8F, 0xB8, 0xE9, 0x91, 0x00};
	BYTE initializeUpdateResponse[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x03, 0x70, 0x3C,
			0x80, 0xC2, 0xCC, 0x87, 0xEB, 0x3A, 0x35, 0xE4, 0xED, 0xBA, 0x35, 0xE6, 0x29, 0xC3, 0x36, 0x00, 0x00, 0x1E,
			0x90, 0x00};
	DWORD initializeUpdateResponseLength = sizeof(initializeUpdateResponse);

	BYTE extAuthRequest[] = {0x84, 0x82, 0x03, 0x00, 0x10, 0x23, 0xEB, 0xFE, 0xDC, 0x57, 0x9D, 0x22, 0xCD, 0xCD, 0xB6, 0xA2,
			0x5A, 0x5F, 0xF7, 0x89, 0x1F};
	BYTE extAuthResponse[] = {0x90, 0x00};
	DWORD extAuthResponseLength = sizeof(extAuthResponse);

	will_return(__wrap_RAND_bytes, hostChallenge);
	expect_value(__wrap_RAND_bytes, num, 8);

	expect_memory(send_APDU, capdu, initializeUpdateRequest, sizeof(initializeUpdateRequest));
	will_return(send_APDU, initializeUpdateResponse);
	will_return(send_APDU, &initializeUpdateResponseLength);

	expect_memory(send_APDU, capdu, extAuthRequest, sizeof(extAuthRequest));
	will_return(send_APDU, extAuthResponse);
	will_return(send_APDU, &extAuthResponseLength);

	memcpy(securityInfo211.invokingAid, (void *)GP231_ISD_AID, sizeof(GP231_ISD_AID));
	securityInfo211.invokingAidLength = sizeof(GP231_ISD_AID);

	status = GP211_mutual_authentication(cardContext, cardInfo, NULL, sEnc, sMac, dek, 0, 0,
			GP211_SCP03, GP211_SCP03_IMPL_i70, GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC, 0, &securityInfo211);
	assert_int_equal(status.errorCode, OPGP_ERROR_STATUS_SUCCESS);
	assert_memory_equal(securityInfo211.encryptionSessionKey, sessionEnc, 16);
	assert_memory_equal(securityInfo211.C_MACSessionKey, sessionCMac, 16);
	assert_memory_equal(securityInfo211.R_MACSessionKey, sessionRMac, 16);
}

static int setup(void **state) {
	cardContext.connectionFunctions.sendAPDU = &send_APDU;
	return 0;
}

int main(void) {
	const struct CMUnitTest tests[] = {
			cmocka_unit_test(cencrypt_cmac),
			cmocka_unit_test(mutual_auth2)
	};
	return cmocka_run_group_tests_name("SCP03", tests, setup, NULL);
}
