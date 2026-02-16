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
static OP201_SECURITY_INFO securityInfo211;

static GP211_SECURITY_INFO gpSecurityInfo211;

static void mutual_auth_visa2(void **state) {
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

	hex_to_byte_array(_T("80500000085218A9EAE386313100"), initializeUpdateRequest, &initializeUpdateRequestLen);
	hex_to_byte_array(_T("00004181116665F5B8300101A67BE0F6BB2920AAD421FF3948F1304B9000"), initializeUpdateResponse, &initializeUpdateResponseLen);
	hex_to_byte_array(_T("8482010010ED016D672E8893662E38CF5736E6751A"), extAuthRequest, &extAuthRequestLen);
	hex_to_byte_array(_T("5218A9EAE3863131"), hostChallenge, &hostChallengeLen);

	will_return(__wrap_RAND_bytes, hostChallenge);
	expect_value(__wrap_RAND_bytes, num, 8);

	expect_memory(send_APDU, capdu, initializeUpdateRequest, initializeUpdateRequestLen);
	will_return(send_APDU, initializeUpdateResponse);
	will_return(send_APDU, &initializeUpdateResponseLen);

	expect_memory(send_APDU, capdu, extAuthRequest, extAuthRequestLen);
	will_return(send_APDU, extAuthResponse);
	will_return(send_APDU, &extAuthResponseLen);

	status = OP201_mutual_authentication(cardContext, cardInfo, (PBYTE)OPGP_VISA_DEFAULT_KEY, NULL, NULL, NULL, 0, 0,
			OP201_SECURITY_LEVEL_MAC, OPGP_DERIVATION_METHOD_VISA2, &securityInfo211);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
}

static void get_status(void **state) {
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

	BYTE refAid[16];
	DWORD refAidLen = 16;

	OPGP_CSTRING commands[] = {
				_T("84F220000A4F00B4ADCE707ADF1D3D00"),
				_T("84F240000A4F0089A0484A80D9EDB800"),
				_T("84F280000A4F00183AC641D94785CB00")
	};
	OPGP_CSTRING responses[] = {
				_T("07A0000000620001010007A0000000620101010007A0000000620102010007A0000000620201010007A0000000030000010007D0D1D2D3D4D50101009000"),
				_T("08D0D1D2D3D4D5010107029000"),
				_T("07A000000003000007009000")
	};

	OP201_APPLICATION_DATA appData[10];
	DWORD appDataLen = 10;

	hex_to_byte_array(_T("805000000810DBADDE5E94FCE100"), initializeUpdateRequest, &initializeUpdateRequestLen);
	hex_to_byte_array(_T("0000302300000055FF000101F5571FE5ED3971F5D2FFBE28469E141D9000"), initializeUpdateResponse, &initializeUpdateResponseLen);
	hex_to_byte_array(_T("848201001010674A7E0BAE4B338A9E421D068947FE"), extAuthRequest, &extAuthRequestLen);
	hex_to_byte_array(_T("10DBADDE5E94FCE1"), hostChallenge, &hostChallengeLen);

	will_return(__wrap_RAND_bytes, hostChallenge);
	expect_value(__wrap_RAND_bytes, num, 8);

	expect_memory(send_APDU, capdu, initializeUpdateRequest, initializeUpdateRequestLen);
	will_return(send_APDU, initializeUpdateResponse);
	will_return(send_APDU, &initializeUpdateResponseLen);

	expect_memory(send_APDU, capdu, extAuthRequest, extAuthRequestLen);
	will_return(send_APDU, extAuthResponse);
	will_return(send_APDU, &extAuthResponseLen);

	status = OP201_mutual_authentication(cardContext, cardInfo, NULL, (PBYTE)OPGP_VISA_DEFAULT_KEY, (PBYTE)OPGP_VISA_DEFAULT_KEY, (PBYTE)OPGP_VISA_DEFAULT_KEY, 0, 0,
			OP201_SECURITY_LEVEL_MAC, OPGP_DERIVATION_METHOD_NONE, &securityInfo211);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	enqueue_commands(commands, responses, 3);

	status = OP201_get_status(cardContext, cardInfo, &securityInfo211, OP201_STATUS_LOAD_FILES, appData, &appDataLen);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	hex_to_byte_array(_T("a0000000620001"), refAid, &refAidLen);
	assert_memory_equal(appData[0].aid.AID, refAid, refAidLen);
	assert_int_equal(appData[0].lifeCycleState, 1);

	status = OP201_get_status(cardContext, cardInfo, &securityInfo211, OP201_STATUS_APPLICATIONS, appData, &appDataLen);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	refAidLen = 16;
	hex_to_byte_array(_T("d0d1d2d3d4d50101"), refAid, &refAidLen);
	assert_memory_equal(appData[0].aid.AID, refAid, refAidLen);
	assert_int_equal(appData[0].lifeCycleState, OP201_LIFE_CYCLE_APPLICATION_SELECTABLE);
	assert_int_equal(appData[0].privileges, OP201_PIN_CHANGE_PRIVILEGE);

	status = OP201_get_status(cardContext, cardInfo, &securityInfo211, OP201_STATUS_CARD_MANAGER, appData, &appDataLen);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	refAidLen = 16;
	hex_to_byte_array(_T("a0000000030000"), refAid, &refAidLen);
	assert_memory_equal(appData[0].aid.AID, refAid, refAidLen);
	assert_int_equal(appData[0].lifeCycleState, OP201_LIFE_CYCLE_CARD_MANAGER_INITIALIZED);
	assert_int_equal(appData[0].privileges, 0);
}

static void install(void **state) {
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

	OP201_RECEIPT_DATA receiptData = {0};
	DWORD receiptDataLength = 0;
	OPGP_AID aid = {0};

	OPGP_CSTRING commands[] = {
				_T("84E4000018D1505A4FAA00491BFF5B83C169209CC82896216BDD2CB1B600"),
				_T("84E4000018F375E789AA02A7D0FB9F5DC60381A7B54E1BF1115498939300"),
				_T("84E4000018D1505A4FAA00491BFF5B83C169209CC8446373AABDA55ECE00"),
				_T("84E60200288257ACF6FD916051142025751C97FB03DC8598FDA29F6CC4A381BA81C26097DF7F8E005B06AC5AC000"),
				_T("84E80000F84E7CFC824629CC3FAE7A44501DCB41A76062095FD54A8BE7DF0D17B9B633D28AF60A098799E10A10FE341EF9B57B1A6477134F9A2D5509D7B755FAD9FDD0E7A2AF9A741CEBE9E35404C3859BF584110C1E37187F9CCD9346FAE8207E9468FF00A85A8C4C2A31902241B2109F5D53F85B81AED6E2A526F186557543EBA2DCF43BAE2E51C611CE90AF716DC1BED3FC815CA4446BE7F95E910D752AE1E8AADB255AEF8DA1654D2241B599F36D2CF3F142C9465FCFA26F8C936B1BF221A7EFA5ECA3F0B160B90C67B2CB5BD20FDBCC13A435F5AEFADE5D76E853B89E7E4B6C2A8C310613B7EE56406C6B466A8354973CC7A7CB70B646B9C37C22"),
				_T("84E880017832B8209D94AE72678DBB89B9920212FDCA8DBEE92FB2627D79FB7D80AF88CD1581F80E23D0F888BB8741DCFFA1CF19B098F1F57166C867AF336F173275F160918CDB24F39F4F76EF60CB7E020CC411AAD4DFE1F99A523233D5C976259D7247C60B5D9C27F209AA21A9975CB6F6EBAC2C88CEC2FB1A8D4ABD00"),
				_T("84E60C0030F05ED18664F48724F22C260E28AA26D1DFED71EFF6632A744A2A8DB8C16B48BB171147B25E1D51447A6E1E7095EFB6F800")
	};
	OPGP_CSTRING responses[] = {
				_T("6A88"),
				_T("6A88"),
				_T("6A88"),
				_T("009000"),
				_T("9000"),
				_T("009000"),
				_T("00C7020000C80200069000")
	};
	DWORD aidLength;

	OPGP_LOAD_FILE_PARAMETERS loadFileParams;
	DWORD receiptDataAvailable;

	hex_to_byte_array(_T("80500000086247DF18C5793FFE00"), initializeUpdateRequest, &initializeUpdateRequestLen);
	hex_to_byte_array(_T("00004181116665F5B8300101EAD645A9EE5F2BD718BA2038612600639000"), initializeUpdateResponse, &initializeUpdateResponseLen);
	hex_to_byte_array(_T("8482030010AB6DB8CAE9ADAEF675120B9E61F567E4"), extAuthRequest, &extAuthRequestLen);
	hex_to_byte_array(_T("6247DF18C5793FFE"), hostChallenge, &hostChallengeLen);

	will_return(__wrap_RAND_bytes, hostChallenge);
	expect_value(__wrap_RAND_bytes, num, 8);

	expect_memory(send_APDU, capdu, initializeUpdateRequest, initializeUpdateRequestLen);
	will_return(send_APDU, initializeUpdateResponse);
	will_return(send_APDU, &initializeUpdateResponseLen);

	expect_memory(send_APDU, capdu, extAuthRequest, extAuthRequestLen);
	will_return(send_APDU, extAuthResponse);
	will_return(send_APDU, &extAuthResponseLen);

	status = OP201_mutual_authentication(cardContext, cardInfo, (PBYTE)OPGP_VISA_DEFAULT_KEY, NULL, NULL, NULL, 0, 0,
			OP201_SECURITY_LEVEL_ENC_MAC, OPGP_DERIVATION_METHOD_VISA2, &securityInfo211);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	enqueue_commands(commands, responses, 7);

	aidLength = sizeof(aid.AID);
	hex_to_byte_array(_T("D0D1D2D3D4D50101"), aid.AID, &aidLength);
	aid.AIDLength = aidLength;
	receiptDataLength = 1;
	status = OP201_delete_application(cardContext, cardInfo, &securityInfo211, &aid, 1, &receiptData, &receiptDataLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_FAILURE);

	aidLength = sizeof(aid.AID);
	hex_to_byte_array(_T("D0D1D2D3D4D501"), aid.AID, &aidLength);
	aid.AIDLength = aidLength;
	receiptDataLength = 1;
	status = OP201_delete_application(cardContext, cardInfo, &securityInfo211, &aid, 1, &receiptData, &receiptDataLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_FAILURE);

	aidLength = sizeof(aid.AID);
	hex_to_byte_array(_T("D0D1D2D3D4D50101"), aid.AID, &aidLength);
	aid.AIDLength = aidLength;
	receiptDataLength = 1;
	status = OP201_delete_application(cardContext, cardInfo, &securityInfo211, &aid, 1, &receiptData, &receiptDataLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_FAILURE);

	//  install -file helloworld.cap -priv 2
	status = OPGP_read_executable_load_file_parameters("helloworld.cap", &loadFileParams);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	aidLength = sizeof(aid.AID);
	hex_to_byte_array(_T("a000000003000000"), aid.AID, &aidLength);
	aid.AIDLength = aidLength;
 	status = OP201_install_for_load(cardContext, cardInfo, &securityInfo211,
								loadFileParams.loadFileAID.AID, loadFileParams.loadFileAID.AIDLength,
								aid.AID, aidLength, NULL, NULL,
								loadFileParams.loadFileSize, 0, 0);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	receiptDataAvailable = 0;
 	status = OP201_load(cardContext, cardInfo, &securityInfo211, NULL, 0, "helloworld.cap", NULL, &receiptDataAvailable, NULL);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
  	receiptDataAvailable = 1;
	memset(&receiptData, 0, sizeof(OP201_RECEIPT_DATA));
	status = OP201_install_for_install_and_make_selectable(
		cardContext, cardInfo, &securityInfo211,
		loadFileParams.loadFileAID.AID, loadFileParams.loadFileAID.AIDLength,
		loadFileParams.appletAIDs[0].AID, loadFileParams.appletAIDs[0].AIDLength,
		loadFileParams.appletAIDs[0].AID, loadFileParams.appletAIDs[0].AIDLength,
		2, 0, 0, NULL, 0, NULL, &receiptData, &receiptDataAvailable);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
}

static void get_status_mac_enc(void **state) {
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

	OPGP_CSTRING commands[] = {
				_T("84F2100210EF482121446322C0CD9A3CC2C8E89D8400"),
				_T("84F2200210EF482121446322C0A8C7D22E1EB71EBA00"),
				_T("84F2400210EF482121446322C0E066B55E2551AF3700"),
				_T("84F2800210EF482121446322C0E4C1A88C0341E10700")
	};
	OPGP_CSTRING responses[] = {
				_T("E3304F07A00000000353509F700101C50100CE0202038407A00000015100008408A0000000035350418407A0000000030000E31D4F10A00000007701000300100000000000039F700101C50100CE020100E31E4F07D0D1D2D3D4D5019F700101C50100CE0201008408D0D1D2D3D4D501019000"),
				_T("E3144F07A00000000353509F700101C50100CE020203E31D4F10A00000007701000300100000000000039F700101C50100CE020100E3144F07D0D1D2D3D4D5019F700101C50100CE0201009000"),
				_T("E3284F08D0D1D2D3D4D501019F700107C50102C607D0D1D2D3D4D501CE0201008408D0D1D2D3D4D501019000"),
				_T("E3114F08A0000000030000009F700101C5019E9000")
	};

	hex_to_byte_array(_T("8050000008C504EDBB64DD582900"), initializeUpdateRequest, &initializeUpdateRequestLen);
	hex_to_byte_array(_T("00005237000000470000FF01691FF128720F01AEB82C85804AB776409000"), initializeUpdateResponse, &initializeUpdateResponseLen);
	hex_to_byte_array(_T("8482030010D3C21BB2478977BDA01145D1C12BEDC5"), extAuthRequest, &extAuthRequestLen);
	hex_to_byte_array(_T("C504EDBB64DD5829"), hostChallenge, &hostChallengeLen);

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

	status = GP211_mutual_authentication(cardContext, cardInfo, NULL, (PBYTE)OPGP_VISA_DEFAULT_KEY, (PBYTE)OPGP_VISA_DEFAULT_KEY, (PBYTE)OPGP_VISA_DEFAULT_KEY,
			sizeof(OPGP_VISA_DEFAULT_KEY), 0, 0,
			GP211_SCP01, GP211_SCP01_IMPL_i05, GP211_SCP01_SECURITY_LEVEL_C_DEC_C_MAC, 0, &gpSecurityInfo211);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	enqueue_commands(commands, responses, 4);

	status = GP211_get_status(cardContext, cardInfo, &gpSecurityInfo211, GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES,
			GP211_STATUS_FORMAT_NEW, applicationData, executablesData, &dataLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	hex_to_byte_array(_T("a0000000035350"), refAid, &refAidLen);
	assert_int_equal(dataLength, 3);
	assert_int_equal(executablesData[0].aid.AIDLength, 7);
	assert_memory_equal(executablesData[0].aid.AID, refAid, refAidLen);
	assert_int_equal(executablesData[0].lifeCycleState, 1);
	assert_int_equal(executablesData[0].versionNumber[0], 0x02);
	assert_int_equal(executablesData[0].versionNumber[1], 0x03);
	refAidLen = 16;
	hex_to_byte_array(_T("a0000001510000"), refAid, &refAidLen);
	assert_int_equal(executablesData[0].numExecutableModules, 3);
	assert_memory_equal(executablesData[0].executableModules[0].AID, refAid, refAidLen);

	dataLength = 3;
	status = GP211_get_status(cardContext, cardInfo, &gpSecurityInfo211, GP211_STATUS_LOAD_FILES,
				GP211_STATUS_FORMAT_NEW, applicationData, executablesData, &dataLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	refAidLen = 16;
	hex_to_byte_array(_T("d0d1d2d3d4d501"), refAid, &refAidLen);
	assert_int_equal(dataLength, 3);
	assert_int_equal(applicationData[2].aid.AIDLength, 7);
	assert_memory_equal(applicationData[2].aid.AID, refAid, refAidLen);
	assert_int_equal(applicationData[2].lifeCycleState, 1);
	assert_int_equal(applicationData[2].versionNumber[0], 0x01);
	assert_int_equal(applicationData[2].versionNumber[1], 0x00);

	dataLength = 1;
	status = GP211_get_status(cardContext, cardInfo, &gpSecurityInfo211, GP211_STATUS_APPLICATIONS,
				GP211_STATUS_FORMAT_NEW, applicationData, executablesData, &dataLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	refAidLen = 16;
	hex_to_byte_array(_T("d0d1d2d3d4d50101"), refAid, &refAidLen);
	assert_int_equal(dataLength, 1);
	assert_int_equal(applicationData[0].aid.AIDLength, 8);
	assert_memory_equal(applicationData[0].aid.AID, refAid, refAidLen);
	assert_int_equal(applicationData[0].lifeCycleState, GP211_LIFE_CYCLE_APPLICATION_SELECTABLE);
	assert_int_equal(applicationData[0].versionNumber[0], 0x01);
	assert_int_equal(applicationData[0].versionNumber[1], 0x00);
	assert_int_equal(applicationData[0].privileges, GP211_PIN_CHANGE_PRIVILEGE);

	dataLength = 1;
	status = GP211_get_status(cardContext, cardInfo, &gpSecurityInfo211, GP211_STATUS_ISSUER_SECURITY_DOMAIN,
				GP211_STATUS_FORMAT_NEW, applicationData, executablesData, &dataLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	refAidLen = 16;
	hex_to_byte_array(_T("a000000003000000"), refAid, &refAidLen);
	assert_int_equal(dataLength, 1);
	assert_int_equal(applicationData[0].aid.AIDLength, 8);
	assert_memory_equal(applicationData[0].aid.AID, refAid, refAidLen);
	assert_int_equal(applicationData[0].lifeCycleState, GP211_LIFE_CYCLE_CARD_OP_READY);
	assert_int_equal(applicationData[0].versionNumber[0], 0x00);
	assert_int_equal(applicationData[0].versionNumber[1], 0x00);
	assert_int_equal(applicationData[0].privileges, GP211_SECURITY_DOMAIN | GP211_CARD_MANAGER_LOCK_PRIVILEGE |
			GP211_CARD_MANAGER_TERMINATE_PRIVILEGE | GP211_DEFAULT_SELECTED_CARD_RESET_PRIVILEGE | GP211_PIN_CHANGE_PRIVILEGE);
}

static int setup(void **state) {
	cardContext.connectionFunctions.sendAPDU = &send_APDU;
	return 0;
}

int main(void) {
	cardInfo.specVersion = OP_201;
	const struct CMUnitTest tests[] = {
			cmocka_unit_test(mutual_auth_visa2),
			cmocka_unit_test(install),
			cmocka_unit_test(get_status),
			cmocka_unit_test(get_status_mac_enc)
	};
	return cmocka_run_group_tests_name("SCP01", tests, setup, NULL);
}
