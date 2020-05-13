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
static OP201_SECURITY_INFO securityInfo211;

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

	hex_to_byte_array("80500000085218A9EAE386313100", initializeUpdateRequest, &initializeUpdateRequestLen);
	hex_to_byte_array("00004181116665F5B8300101A67BE0F6BB2920AAD421FF3948F1304B9000", initializeUpdateResponse, &initializeUpdateResponseLen);
	hex_to_byte_array("8482010010ED016D672E8893662E38CF5736E6751A", extAuthRequest, &extAuthRequestLen);
	hex_to_byte_array("5218A9EAE3863131", hostChallenge, &hostChallengeLen);

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
	assert_int_equal(status.errorCode, OPGP_ERROR_STATUS_SUCCESS);
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

	OP201_RECEIPT_DATA receiptData;
	DWORD receiptDataLength = 1;
	OPGP_AID aid;

	OPGP_CSTRING commands[] = {
				"84E4000018D1505A4FAA00491BFF5B83C169209CC82896216BDD2CB1B600",
				"84E4000018F375E789AA02A7D0FB9F5DC60381A7B54E1BF1115498939300",
				"84E4000018D1505A4FAA00491BFF5B83C169209CC8446373AABDA55ECE00",
				"84E60200288257ACF6FD916051142025751C97FB03DC8598FDA29F6CC4A381BA81C26097DF7F8E005B06AC5AC000",
				"84E80000F84E7CFC824629CC3FAE7A44501DCB41A76062095FD54A8BE7DF0D17B9B633D28AF60A098799E10A10FE341EF9B57B1A6477134F9A2D5509D7B755FAD9FDD0E7A2AF9A741CEBE9E35404C3859BF584110C1E37187F9CCD9346FAE8207E9468FF00A85A8C4C2A31902241B2109F5D53F85B81AED6E2A526F186557543EBA2DCF43BAE2E51C611CE90AF716DC1BED3FC815CA4446BE7F95E910D752AE1E8AADB255AEF8DA1654D2241B599F36D2CF3F142C9465FCFA26F8C936B1BF221A7EFA5ECA3F0B160B90C67B2CB5BD20FDBCC13A435F5AEFADE5D76E853B89E7E4B6C2A8C310613B7EE56406C6B466A8354973CC7A7CB70B646B9C37C22",
				"84E880017832B8209D94AE72678DBB89B9920212FDCA8DBEE92FB2627D79FB7D80AF88CD1581F80E23D0F888BB8741DCFFA1CF19B098F1F57166C867AF336F173275F160918CDB24F39F4F76EF60CB7E020CC411AAD4DFE1F99A523233D5C976259D7247C60B5D9C27F209AA21A9975CB6F6EBAC2C88CEC2FB1A8D4ABD00",
				"84E60C0030F05ED18664F48724F22C260E28AA26D1DFED71EFF6632A744A2A8DB8C16B48BB171147B25E1D51447A6E1E7095EFB6F800"
	};
	OPGP_CSTRING responses[] = {
				"6A88",
				"6A88",
				"6A88",
				"009000",
				"9000",
				"009000",
				"00C7020000C80200069000"
	};
	DWORD aidLength;

	OPGP_LOAD_FILE_PARAMETERS loadFileParams;
	DWORD receiptDataAvailable;

	hex_to_byte_array("80500000086247DF18C5793FFE00", initializeUpdateRequest, &initializeUpdateRequestLen);
	hex_to_byte_array("00004181116665F5B8300101EAD645A9EE5F2BD718BA2038612600639000", initializeUpdateResponse, &initializeUpdateResponseLen);
	hex_to_byte_array("8482030010AB6DB8CAE9ADAEF675120B9E61F567E4", extAuthRequest, &extAuthRequestLen);
	hex_to_byte_array("6247DF18C5793FFE", hostChallenge, &hostChallengeLen);

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
	assert_int_equal(status.errorCode, OPGP_ERROR_STATUS_SUCCESS);

	// the macro looses one 9000 response ????
	//ENQUEUE_COMMANDS(commands, responses, 7)
	BYTE commandRequest[APDU_COMMAND_LEN];
	DWORD commandRequestLen = APDU_COMMAND_LEN;
	BYTE commandResponse[APDU_RESPONSE_LEN];
	DWORD commandResponseLen = APDU_RESPONSE_LEN;
	for (int i=0; i<7; i++) {
		commandRequestLen = APDU_COMMAND_LEN;
		commandResponseLen = APDU_RESPONSE_LEN;
		hex_to_byte_array(*(commands + i), commandRequest, &commandRequestLen);
		hex_to_byte_array(*(responses + i), commandResponse, &commandResponseLen);
		expect_memory(send_APDU, capdu, commandRequest, commandRequestLen);
		will_return(send_APDU, commandResponse);
		will_return(send_APDU, &commandResponseLen);
	}

	aidLength = sizeof(aid.AID);
	hex_to_byte_array("D0D1D2D3D4D50101", aid.AID, &aidLength);
	aid.AIDLength = aidLength;
	status = OP201_delete_application(cardContext, cardInfo, &securityInfo211, &aid, 1, &receiptData, &receiptDataLength);
	assert_int_equal(status.errorCode, OPGP_ERROR_STATUS_SUCCESS);

	aidLength = sizeof(aid.AID);
	hex_to_byte_array("D0D1D2D3D4D501", aid.AID, &aidLength);
	aid.AIDLength = aidLength;
	receiptDataLength = 1;
	status = OP201_delete_application(cardContext, cardInfo, &securityInfo211, &aid, 1, &receiptData, &receiptDataLength);
	assert_int_equal(status.errorCode, OPGP_ERROR_STATUS_SUCCESS);

	aidLength = sizeof(aid.AID);
	hex_to_byte_array("D0D1D2D3D4D50101", aid.AID, &aidLength);
	aid.AIDLength = aidLength;
	status = OP201_delete_application(cardContext, cardInfo, &securityInfo211, &aid, 1, &receiptData, &receiptDataLength);
	assert_int_equal(status.errorCode, OPGP_ERROR_STATUS_SUCCESS);

	//  install -file helloworld.cap -priv 2
	status = OPGP_read_executable_load_file_parameters("helloworld.cap", &loadFileParams);
	assert_int_equal(status.errorCode, OPGP_ERROR_STATUS_SUCCESS);

	aidLength = sizeof(aid.AID);
	hex_to_byte_array("a000000003000000", aid.AID, &aidLength);
	aid.AIDLength = aidLength;
	status = OP201_install_for_load(cardContext, cardInfo, &securityInfo211,
								loadFileParams.loadFileAID.AID, loadFileParams.loadFileAID.AIDLength,
								aid.AID, aidLength, NULL, NULL,
								loadFileParams.loadFileSize, 0, 0);
	assert_int_equal(status.errorCode, OPGP_ERROR_STATUS_SUCCESS);
	status = OP201_load(cardContext, cardInfo, &securityInfo211, NULL, 0, "helloworld.cap", NULL, &receiptDataAvailable, NULL);
	assert_int_equal(status.errorCode, OPGP_ERROR_STATUS_SUCCESS);
	receiptDataAvailable = 1;
	status = OP201_install_for_install_and_make_selectable(
		cardContext, cardInfo, &securityInfo211,
		loadFileParams.loadFileAID.AID, loadFileParams.loadFileAID.AIDLength,
		loadFileParams.appletAIDs[0].AID, loadFileParams.appletAIDs[0].AIDLength,
		loadFileParams.appletAIDs[0].AID, loadFileParams.appletAIDs[0].AIDLength,
		2, 0, 0, NULL, 0, NULL, &receiptData, &receiptDataAvailable);
	assert_int_equal(status.errorCode, OPGP_ERROR_STATUS_SUCCESS);
}


static int setup(void **state) {
	cardContext.connectionFunctions.sendAPDU = &send_APDU;
	return 0;
}

int main(void) {
	cardInfo.specVersion = OP_201;
	const struct CMUnitTest tests[] = {
			cmocka_unit_test(mutual_auth_visa2),
			cmocka_unit_test(install)
	};
	return cmocka_run_group_tests_name("SCP01", tests, setup, NULL);
}
