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
#include "testUtil.h"
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

	hex_to_byte_array(_T("8050000008D5AD539A60CA5E7200"), initializeUpdateRequest, &initializeUpdateRequestLen);
	hex_to_byte_array(_T("000074746E6E6E6262620102069FAA2A0591E73367DD78794D04315E9000"), initializeUpdateResponse, &initializeUpdateResponseLen);
	hex_to_byte_array(_T("84820100107C799B3C771DBAE6BEF49310977617BA"), extAuthRequest, &extAuthRequestLen);
	hex_to_byte_array(_T("84F220020A4F00BB6E71C0EFCFCF0D00"), getStatusRequest, &getStatusRequestLen);
	hex_to_byte_array(_T("E30D4F07A00000000353509F700101E30B4F05A0000000049F700101E30B4F05325041592E9F700101E30B4F05F0000711809F700101E30C4F06A000000421209F700101E30D4F07D0D1D2D3D4D5019F7001019000"), getStatusResponse, &getStatusResponseLen);
	hex_to_byte_array(_T("d0d1d2d3d4d501"), refAid, &refAidLen);
	hex_to_byte_array(_T("D5AD539A60CA5E72"), hostChallenge, &hostChallengeLen);

	GP211_APPLICATION_DATA applicationData[10] = {0};
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

	status = GP211_mutual_authentication(cardContext, cardInfo, NULL, (PBYTE)OPGP_VISA_DEFAULT_KEY, (PBYTE)OPGP_VISA_DEFAULT_KEY, (PBYTE)OPGP_VISA_DEFAULT_KEY,
			sizeof(OPGP_VISA_DEFAULT_KEY), 0, 0,
			GP211_SCP02, GP211_SCP02_IMPL_i15, GP211_SCP02_SECURITY_LEVEL_C_MAC, 0, &securityInfo211);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	// 80f24002024f0000
	expect_memory(send_APDU, capdu, getStatusRequest, getStatusRequestLen);
	will_return(send_APDU, getStatusResponse);
	will_return(send_APDU, &getStatusResponseLen);

	status = GP211_get_status(cardContext, cardInfo, &securityInfo211, GP211_STATUS_LOAD_FILES, GP211_STATUS_FORMAT_NEW, applicationData,
			executablesData, &dataLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(dataLength, 6);
	assert_int_equal(applicationData[5].aid.AIDLength, 7);
	assert_memory_equal(applicationData[5].aid.AID, refAid, applicationData[5].aid.AIDLength);
	assert_int_equal(applicationData[5].lifeCycleState, 1);
	assert_int_equal(applicationData[6].privileges, 0);
}

static void install_mac_enc(void **state) {
	OPGP_ERROR_STATUS status;

	BYTE hostChallenge[8];
	DWORD hostChallengeLen = 8;
	BYTE initializeUpdateRequest[APDU_COMMAND_LEN], extAuthRequest[APDU_COMMAND_LEN];

	DWORD initializeUpdateRequestLen, extAuthRequestLen;
	initializeUpdateRequestLen = extAuthRequestLen = APDU_COMMAND_LEN;

	BYTE initializeUpdateResponse[APDU_RESPONSE_LEN];
	DWORD initializeUpdateResponseLen = APDU_RESPONSE_LEN;

	BYTE extAuthResponse[] = {0x90, 0x00};
	DWORD extAuthResponseLen = sizeof(extAuthResponse);

	GP211_RECEIPT_DATA receiptData;
	DWORD receiptDataLength = 1;
	OPGP_AID aid;

	OPGP_CSTRING commands[] = {
				_T("84E4008018BC146FA0403BE4BAD3BC089E4ABD8674DA7EFEA21047B85800"),
				_T("84E4008018C2748C1669FAFC0E20C5253680388A4A49C9A6038D77B45700"),
				_T("84E60200280839B761AA201C218FD6607C56803CFD2D098CBAA9946976EEFAE3F210038EB4965D6E04EDEF801700"),
				_T("84E80000F8562EFDC9F22082A5184831F1DA6A0F495C5DF0FD71E8014A2B94EA81069FB630346197CDF1C3BD9CDBDD9513BFE6FE7992730FCF2089019D1374DA1021BD74E2085B806B8DA57431FF008406E1C695F2E27E0C2A554E01047B9B36F4058CFC1C2FB8D0A45B01C626DF5CB2509436283BE22B9E7750B3B7F36E29E3C97C69533B35C2DBEF13904D06E96BEBB6FA38D3E7EB7EB9170F3004824F5A32278AE7CBC3E591BA0C79B090FBD8038B60AC5F83E4E250B32AD5B92768E775AA974A4FAFC81356FA333D5AB4FAF1A0056E08420AF95D18CA0DF726BA560C5C340CCA81A1BEA294AAFE3AED250EF6865AA2D3F11D058FDFE5EE7622AE19"),
				_T("84E88001787FFE538F755D612CEE738FA68E177E8E146E66EF2A840387F7086C1CA8659C9F985585E11001A12D4940CB3EF200DFEC9EC7FB59CADED4A7F82EDA5BE808552A3CD3B65D41F9F61A23E6FDA2C1BF2493F4929950FA62030FF023B34398247A2E01BBF949E819B5EEA117DC6E0D91D40D85ABDE0BC2A76D8600"),
				_T("84E60C00300839B761AA201C21EDAE7D003F76B62164B363AF56A2C7FE12AEF9FDC790DFC8FFE6B0346E9BF02674684247652F109A00")
	};
	OPGP_CSTRING responses[] = {
				_T("6A88"),
				_T("009000"),
				_T("009000"),
				_T("009000"),
				_T("9000"),
				_T("9000")
	};
	DWORD aidLength;

	OPGP_LOAD_FILE_PARAMETERS loadFileParams;
	DWORD receiptDataAvailable;
	unsigned char installParam[1];
	installParam[0] = 0;

	hex_to_byte_array(_T("8050000008EBAA9E53C696281B00"), initializeUpdateRequest, &initializeUpdateRequestLen);
	hex_to_byte_array(_T("000074746E6E6E626262010206A15086BBEE58F467149061DA4B6EAE9000"), initializeUpdateResponse, &initializeUpdateResponseLen);
	hex_to_byte_array(_T("848203001005814C116071EB67D8BA9D9879454564"), extAuthRequest, &extAuthRequestLen);
	hex_to_byte_array(_T("EBAA9E53C696281B"), hostChallenge, &hostChallengeLen);

	will_return(__wrap_RAND_bytes, hostChallenge);
	expect_value(__wrap_RAND_bytes, num, 8);

	expect_memory(send_APDU, capdu, initializeUpdateRequest, initializeUpdateRequestLen);
	will_return(send_APDU, initializeUpdateResponse);
	will_return(send_APDU, &initializeUpdateResponseLen);

	expect_memory(send_APDU, capdu, extAuthRequest, extAuthRequestLen);
	will_return(send_APDU, extAuthResponse);
	will_return(send_APDU, &extAuthResponseLen);

	status = GP211_mutual_authentication(cardContext, cardInfo, NULL, (PBYTE)OPGP_VISA_DEFAULT_KEY, (PBYTE)OPGP_VISA_DEFAULT_KEY, (PBYTE)OPGP_VISA_DEFAULT_KEY,
			sizeof(OPGP_VISA_DEFAULT_KEY), 0, 0,
			GP211_SCP02, GP211_SCP02_IMPL_i15, GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC, 0, &securityInfo211);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	enqueue_commands(commands, responses, 6);

	aidLength = sizeof(aid.AID);
	hex_to_byte_array(_T("D0D1D2D3D4D50101"), aid.AID, &aidLength);
	aid.AIDLength = aidLength;
	status = GP211_delete_application(cardContext, cardInfo, &securityInfo211, &aid, 1, &receiptData, &receiptDataLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_FAILURE);

	aidLength = sizeof(aid.AID);
	hex_to_byte_array(_T("D0D1D2D3D4D501"), aid.AID, &aidLength);
	aid.AIDLength = aidLength;
	receiptDataLength = 1;
	status = GP211_delete_application(cardContext, cardInfo, &securityInfo211, &aid, 1, &receiptData, &receiptDataLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

//  install -file helloworld.cap -nvDataLimit 2000 -instParam 00 -priv 2

	status = OPGP_read_executable_load_file_parameters("helloworld.cap", &loadFileParams);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	aidLength = sizeof(aid.AID);
	hex_to_byte_array(_T("a000000003000000"), aid.AID, &aidLength);
	aid.AIDLength = aidLength;
	status = GP211_install_for_load(cardContext, cardInfo, &securityInfo211,
								loadFileParams.loadFileAID.AID, loadFileParams.loadFileAID.AIDLength,
								aid.AID, aidLength, NULL, NULL,
								loadFileParams.loadFileSize, 0, 2000);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	status = GP211_load(cardContext, cardInfo, &securityInfo211, NULL, 0, "helloworld.cap", NULL, &receiptDataAvailable, NULL);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	status = GP211_install_for_install_and_make_selectable(
		cardContext, cardInfo, &securityInfo211,
		loadFileParams.loadFileAID.AID, loadFileParams.loadFileAID.AIDLength,
		loadFileParams.appletAIDs[0].AID, loadFileParams.appletAIDs[0].AIDLength,
		loadFileParams.appletAIDs[0].AID, loadFileParams.appletAIDs[0].AIDLength,
		2, 0, 2000, installParam, 1, NULL, &receiptData, &receiptDataAvailable);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
}

static int setup(void **state) {
	cardContext.connectionFunctions.sendAPDU = &send_APDU;
	return 0;
}

int main(void) {
	cardInfo.specVersion = GP_211;
	const struct CMUnitTest tests[] = {
			cmocka_unit_test(get_status_mac_only),
			cmocka_unit_test(install_mac_enc)
	};
	return cmocka_run_group_tests_name("SCP02", tests, setup, NULL);
}
