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
#include <setjmp.h>
#include "globalplatform/globalplatform.h"
#include <stdio.h>
#include <string.h>
#include <cmocka.h>
#include "testUtil.h"

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

static void get_status_mac_only(void **state) {
	OPGP_ERROR_STATUS status;

	BYTE hostChallenge[8];
	DWORD hostChallengeLen = 8;
	BYTE initializeUpdateRequest[APDU_COMMAND_LEN], extAuthRequest[APDU_COMMAND_LEN],
	getStatusRequest[APDU_COMMAND_LEN];

	DWORD initializeUpdateRequestLen, extAuthRequestLen, getStatusRequestLen;
	initializeUpdateRequestLen = extAuthRequestLen = getStatusRequestLen = APDU_COMMAND_LEN;

	BYTE getStatusResponse[APDU_RESPONSE_LEN], initializeUpdateResponse[APDU_RESPONSE_LEN];

	DWORD getStatusResponseLen, initializeUpdateResponseLen;
	getStatusResponseLen = initializeUpdateResponseLen = APDU_RESPONSE_LEN;

	BYTE extAuthResponse[] = {0x90, 0x00};
	DWORD extAuthResponseLen = sizeof(extAuthResponse);
	BYTE refAid[16];
	DWORD refAidLen = 16;

	hex_to_byte_array("8050000008D5AD539A60CA5E7200", initializeUpdateRequest, &initializeUpdateRequestLen);
	hex_to_byte_array("000074746E6E6E6262620102069FAA2A0591E73367DD78794D04315E9000", initializeUpdateResponse, &initializeUpdateResponseLen);
	hex_to_byte_array("84820100107C799B3C771DBAE6BEF49310977617BA", extAuthRequest, &extAuthRequestLen);
	hex_to_byte_array("84F220020A4F00BB6E71C0EFCFCF0D00", getStatusRequest, &getStatusRequestLen);
	hex_to_byte_array("E30D4F07A00000000353509F700101E30B4F05A0000000049F700101E30B4F05325041592E9F700101E30B4F05F0000711809F700101E30C4F06A000000421209F700101E30D4F07D0D1D2D3D4D5019F7001019000", getStatusResponse, &getStatusResponseLen);
	hex_to_byte_array("d0d1d2d3d4d501", refAid, &refAidLen);
	hex_to_byte_array("D5AD539A60CA5E72", hostChallenge, &hostChallengeLen);

	GP211_APPLICATION_DATA applicationData[10];
	GP211_EXECUTABLE_MODULES_DATA executablesData[10];
	DWORD dataLength = 10;

	will_return(__wrap_RAND_bytes, hostChallenge);
	expect_value(__wrap_RAND_bytes, num, 8);

	expect_memory(send_APDU, capdu, initializeUpdateRequest, initializeUpdateRequestLen);
	will_return(send_APDU, initializeUpdateResponse);
	will_return(send_APDU, &initializeUpdateResponseLen);

	expect_memory(send_APDU, capdu, extAuthRequest, extAuthRequestLen);
	will_return(send_APDU, extAuthResponse);
	will_return(send_APDU, &extAuthResponseLen);

	status = GP211_mutual_authentication(cardContext, cardInfo, NULL, (PBYTE)OPGP_VISA_DEFAULT_KEY, (PBYTE)OPGP_VISA_DEFAULT_KEY, (PBYTE)OPGP_VISA_DEFAULT_KEY, 0, 0,
			GP211_SCP02, GP211_SCP02_IMPL_i15, GP211_SCP02_SECURITY_LEVEL_C_MAC, 0, &securityInfo211);
	assert_int_equal(status.errorCode, OPGP_ERROR_STATUS_SUCCESS);

	// 80f24002024f0000
	expect_memory(send_APDU, capdu, getStatusRequest, getStatusRequestLen);
	will_return(send_APDU, getStatusResponse);
	will_return(send_APDU, &getStatusResponseLen);

	status = GP211_get_status(cardContext, cardInfo, &securityInfo211, GP211_STATUS_LOAD_FILES, GP211_STATUS_FORMAT_NEW, applicationData,
			executablesData, &dataLength);
	assert_int_equal(status.errorCode, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(dataLength, 6);
	assert_int_equal(applicationData[5].AIDLength, 7);
	assert_memory_equal(applicationData[5].AID, refAid, applicationData[5].AIDLength);
	assert_int_equal(applicationData[5].lifeCycleState, 1);
	assert_int_equal(applicationData[6].privileges, 0);
}

static int setup(void **state) {
	cardContext.connectionFunctions.sendAPDU = &send_APDU;
	return 0;
}

int main(void) {
	const struct CMUnitTest tests[] = {
			cmocka_unit_test(get_status_mac_only)
	};
	return cmocka_run_group_tests_name("SCP02", tests, setup, NULL);
}
