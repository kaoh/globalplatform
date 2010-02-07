/*  Copyright (c) 2008, Karsten Ohme
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
#include <check.h>
#include <stdlib.h>
#include "GlobalPlatform/GlobalPlatform.h"
#include <stdio.h>
#include <string.h>

/**
 * Maximum length of the reader name.
 */
#define READERNAMELEN 256

/**
 * Reader number to connect to.
 */
#define READERNUM 3

/**
 * Maximum buffer size for reader names.
 */
#define BUFLEN 2048

/**
 * Test load file
 */
#define TEST_LOAD_FILE "HelloWorld.cap"

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

/**
 * Package AID for test to delete.
 */
static const BYTE packageAID[9] = {0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0c, 0x01};

/**
 * Applet AID for test to delete.
 */
static const BYTE appletAID[10] = {0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0c, 0x01, 0x01};

/**
 * Readername for the test.
 */
static TCHAR readerName[READERNAMELEN + 1];

static OPGP_ERROR_STATUS internal_disconnect_card() {
	OPGP_ERROR_STATUS status;
	status = OPGP_card_disconnect(cardContext, &cardInfo);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	_tprintf(_T("Disconnected from reader %s\n"), readerName);
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS internal_release_context() {
	OPGP_ERROR_STATUS status;
	status = OPGP_release_context(&cardContext);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS internal_connect_card() {
	OPGP_ERROR_STATUS status;
	status = OPGP_card_connect(cardContext, readerName, &cardInfo,
			(OPGP_CARD_PROTOCOL_T0 | OPGP_CARD_PROTOCOL_T1));
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	_tprintf(_T("Connected to reader %s\n"), readerName);
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS internal_establish_context() {
	OPGP_ERROR_STATUS status;
	_tcsncpy(cardContext.libraryName, _T("gppcscconnectionplugin"),
			sizeof(cardContext.libraryName));
	status = OPGP_establish_context(&cardContext);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS internal_mutual_authentication() {
	OPGP_ERROR_STATUS status;
	BYTE scp;
	BYTE scpImpl;
	status = GP211_get_secure_channel_protocol_details(cardContext, cardInfo,
			&scp, &scpImpl);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	status = GP211_mutual_authentication(cardContext, cardInfo, NULL,
			(PBYTE) OPGP_VISA_DEFAULT_KEY, (PBYTE) OPGP_VISA_DEFAULT_KEY,
			(PBYTE) OPGP_VISA_DEFAULT_KEY, 0, 0, scp, scpImpl,
			GP211_SCP01_SECURITY_LEVEL_C_DEC_C_MAC, &securityInfo211);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS internal_list_readers() {
	OPGP_ERROR_STATUS status;
	TCHAR buf[BUFLEN + 1];
	int j, k;
	DWORD readerStrLen = BUFLEN;
	status = OPGP_list_readers(cardContext, buf, &readerStrLen);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	// we choose the READERNUM reader
	for (j = 0; j < (int) readerStrLen;) {
		/* Check for end of readers */
		if (buf[j] == _T('\0')) {
			break;
		}
		_tcsncpy(readerName, buf + j, READERNAMELEN + 1);
		if (j == READERNUM) {
			break;
		}
		j += (int) _tcslen(buf + j) + 1;
	}
	readerName[READERNAMELEN] = _T('\0');
	if (_tcslen(readerName) == 0) {
		OPGP_ERROR_CREATE_ERROR(status, -1, "No reader found.");
		return status;
	}
	_tprintf(_T("Using reader %s\n"), readerName);
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS internal_connect() {
	OPGP_ERROR_STATUS status;
	status = internal_establish_context();
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	status = internal_list_readers();
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	status = internal_connect_card();
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS internal_disconnect() {
	OPGP_ERROR_STATUS status;
	status = internal_disconnect_card();
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	status = internal_release_context();
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}


static OPGP_ERROR_STATUS internal_delete() {
	OPGP_ERROR_STATUS status;
	GP211_RECEIPT_DATA receiptData;
	DWORD receiptDataLength;
	OPGP_AID deletePackage;
	OPGP_AID deleteApplet;
	memcpy(deletePackage.AID, packageAID, sizeof(packageAID));
	deletePackage.AIDLength = sizeof(packageAID);
	memcpy(deleteApplet.AID, appletAID, sizeof(appletAID));
	deleteApplet.AIDLength = sizeof(appletAID);
	// first try to delete applet
	GP211_delete_application(cardContext, cardInfo, &securityInfo211, &deleteApplet, 1, &receiptData, &receiptDataLength);
	// now delete package
	status = GP211_delete_application(cardContext, cardInfo, &securityInfo211, &deletePackage, 1, &receiptData, &receiptDataLength);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

/**
 * Tests the connection to the card.
 */
START_TEST(test_connect_card)
	{
		OPGP_ERROR_STATUS status;
		status = internal_connect();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not connect: %s", status.errorMessage);
		}
		status = internal_disconnect();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not disconnect: %s", status.errorMessage);
		}
		fail_unless(cardInfo.librarySpecific == NULL, "Library specific data must be NULL after disconnecting.");
		fail_unless(cardContext.libraryHandle == NULL, "Library handle must be NULL after releasing.");
		fail_unless(cardContext.librarySpecific == NULL, "Library specific data must be NULL after releasing.");
	}END_TEST

/**
 * Tests the listing of readers.
 */
START_TEST (test_list_readers)
	{
		OPGP_ERROR_STATUS status;
		status = internal_establish_context();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not establish context: %s", status.errorMessage);
		}
		status = internal_list_readers();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not list readers: %s", status.errorMessage);
		}
		status = internal_release_context();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not release context: %s", status.errorMessage);
		}
	}END_TEST

/**
 * Tests the key derivation according to gemXpresso scheme.
 */
START_TEST (test_OPGP_VISA2_derive_keys)
	{
		OPGP_ERROR_STATUS status;
		status = internal_connect();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not connect: %s", status.errorMessage);
		}
		BYTE motherKey[] = { 0x4D, 0xA5, 0xFC, 0x18, 0xA4, 0x6F, 0x8A, 0x02,
				0x05, 0xC7, 0x7C, 0x37, 0x3B, 0x58, 0x2A, 0x1F };
		BYTE S_ENC[16], S_MAC[16], DEK[16];
		int i;
		status = OPGP_VISA2_derive_keys(cardContext, cardInfo,
				(PBYTE) GP211_CARD_MANAGER_AID_ALT1,
				sizeof(GP211_CARD_MANAGER_AID_ALT1), motherKey, S_ENC, S_MAC,
				DEK);
		if (OPGP_ERROR_CHECK(status)) {
			fail("Derivation of keys failed: %s", status.errorMessage);
		}
		for (i = 0; i < 16; i++) {
			printf("%02X", S_ENC[i]);
		}
		printf("\n");
		for (i = 0; i < 16; i++) {
			printf("%02X", S_MAC[i]);
		}
		printf("\n");
		for (i = 0; i < 16; i++) {
			printf("%02X", DEK[i]);
		}
		printf("\n");
		status = internal_disconnect();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not disconnect: %s", status.errorMessage);
		}
	}END_TEST

/**
 * Tests the mutual authentication.
 */
START_TEST (test_mutual_authentication)
	{
		OPGP_ERROR_STATUS status;
		status = internal_connect();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not connect: %s", status.errorMessage);
		}
		status = internal_mutual_authentication();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not do mutual authentication: %s", status.errorMessage);
		}
		status = internal_disconnect();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not disconnect: %s", status.errorMessage);
		}
		_tprintf(_T("Mutual authentication succeeded\n"));
	}END_TEST


/**
 * Tests the install commands.
 */
START_TEST (test_install)
	{
		OPGP_LOAD_FILE_PARAMETERS loadFileParams;
		DWORD receiptDataAvailable = 0;
		DWORD receiptDataLen = 0;

		char installParam[1];
		installParam[0] = 0;

		OPGP_ERROR_STATUS status;
		GP211_RECEIPT_DATA receipt;

		status = internal_connect();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not connect: %s", status.errorMessage);
		}
		status = internal_mutual_authentication();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not do mutual authentication: %s", status.errorMessage);
		}

		internal_delete();

		status = OPGP_read_executable_load_file_parameters(TEST_LOAD_FILE,
				&loadFileParams);
		if (OPGP_ERROR_CHECK(status)) {
			fail("OPGP_read_executable_load_file_parameters() failed: ", status.errorMessage);
		}

		status = GP211_install_for_load(cardContext, cardInfo,
				&securityInfo211, loadFileParams.loadFileAID.AID,
				loadFileParams.loadFileAID.AIDLength,
				(PBYTE) GP211_CARD_MANAGER_AID_ALT1, sizeof(GP211_CARD_MANAGER_AID_ALT1),
				NULL, NULL, loadFileParams.loadFileSize, 0, 2000);

		if (OPGP_ERROR_CHECK(status)) {
			fail("GP211_install_for_load() failed: ", status.errorMessage);
		}

		status = GP211_load(cardContext, cardInfo, &securityInfo211, NULL, 0,
				TEST_LOAD_FILE, NULL, &receiptDataLen, NULL);

		if (OPGP_ERROR_CHECK(status)) {
			fail("GP211_load() failed: ", status.errorMessage);
		}

		status = GP211_install_for_install_and_make_selectable(cardContext,
				cardInfo, &securityInfo211, loadFileParams.loadFileAID.AID,
				loadFileParams.loadFileAID.AIDLength,
				loadFileParams.appletAIDs[0].AID,
				loadFileParams.appletAIDs[0].AIDLength,
				loadFileParams.appletAIDs[0].AID,
				loadFileParams.appletAIDs[0].AIDLength, 0, 500, 1000, NULL, 0,
				NULL, &receipt, &receiptDataAvailable);

		if (OPGP_ERROR_CHECK(status)) {
			fail("GP211_install_for_install_and_make_selectable() failed: ", status.errorMessage);
		}

		status = internal_disconnect();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not disconnect: %s", status.errorMessage);
		}
	}END_TEST

START_TEST (test_delete) {
		OPGP_ERROR_STATUS status;
		status = internal_connect();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not connect: %s", status.errorMessage);
		}
		status = internal_mutual_authentication();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not do mutual authentication: %s", status.errorMessage);
		}
		status = internal_delete();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not delete applets: %s", status.errorMessage);
		}
		status = internal_disconnect();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not disconnect: %s", status.errorMessage);
		}
} END_TEST

/**
 * Test the get status command.
 */
START_TEST (test_get_status) {
		OPGP_ERROR_STATUS status;
		GP211_APPLICATION_DATA appData[10];
		GP211_EXECUTABLE_MODULES_DATA modulesData[10];
		BYTE appAID[8] = {0xa0,0,0,0,4,0x10,0x10};
		BYTE loadFileAID[8] = {0xa0,0,0,0,3,0x53,0x50};
		BYTE domainAID[8] = {0xa0,00,00,00,03,00,00,00};
		DWORD dataLength = 10;
		status = internal_connect();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not connect: %s", status.errorMessage);
		}
		status = internal_mutual_authentication();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not do mutual authentication: %s", status.errorMessage);
		}
		status = GP211_get_status(cardContext, cardInfo, &securityInfo211, GP211_STATUS_APPLICATIONS, appData, modulesData, &dataLength);
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not get status from applications: %s", status.errorMessage);
		}

		fail_unless(dataLength == 4, "Incorrect application status length");
		fail_unless(appData[0].lifeCycleState == 7, "Incorrect application status life cycle state");
		fail_unless(appData[0].privileges == 2, "Incorrect application status privileges");
		fail_unless(strncmp(appData[0].AID, appAID, sizeof(appAID))==0, "Incorrect application status AID");

        dataLength = 10;
		status = GP211_get_status(cardContext, cardInfo, &securityInfo211, GP211_STATUS_LOAD_FILES, appData, modulesData, &dataLength);
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not get status from applications: %s", status.errorMessage);
		}
		fail_unless(dataLength == 5, "Incorrect load file status");
		fail_unless(appData[0].lifeCycleState == 1, "Incorrect load file status");
		fail_unless(appData[0].privileges == 0, "Incorrect load file status");
		fail_unless(strncmp(appData[0].AID, loadFileAID, sizeof(loadFileAID))==0, "Incorrect load file status");

        dataLength = 10;
		status = GP211_get_status(cardContext, cardInfo, &securityInfo211, GP211_STATUS_ISSUER_SECURITY_DOMAIN, appData, modulesData, &dataLength);
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not get status from applications: %s", status.errorMessage);
		}
		fail_unless(dataLength == 1, "Incorrect issuer security status");
		fail_unless(appData[0].lifeCycleState == 1, "Incorrect issuer security status");
		fail_unless(appData[0].privileges == 0x9e, "Incorrect issuer security status");


		fail_unless(strncmp(appData[0].AID, domainAID, sizeof(domainAID)) == 0, "Incorrect issuer security status");

		status = internal_disconnect();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not disconnect: %s", status.errorMessage);
		}
} END_TEST


START_TEST (test_put_3des_key) {
		OPGP_ERROR_STATUS status;
		BYTE key[16] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5};
		status = internal_connect();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not connect: %s", status.errorMessage);
		}
		status = internal_mutual_authentication();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not do mutual authentication: %s", status.errorMessage);
		}
		status = GP211_put_3des_key(cardContext, cardInfo, &securityInfo211, 0, 1, 5, key);
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not put key: %s", status.errorMessage);
		}
		status = internal_disconnect();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not disconnect: %s", status.errorMessage);
		}
} END_TEST

START_TEST (test_delete_key) {
		OPGP_ERROR_STATUS status;
		status = internal_connect();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not connect: %s", status.errorMessage);
		}
		status = internal_mutual_authentication();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not do mutual authentication: %s", status.errorMessage);
		}
		status = GP211_delete_key(cardContext, cardInfo, &securityInfo211, 5, 1);
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not delete key: %s", status.errorMessage);
		}
		status = internal_disconnect();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not disconnect: %s", status.errorMessage);
		}
} END_TEST

static DWORD totalWork;
static DWORD currentWork;
static DWORD finished;

/**
 * Callback function. Must be called from a callback enabled function.
 */
static void callback_function(OPGP_PROGRESS_CALLBACK_PARAMETERS parameters) {
    currentWork = parameters.currentWork;
    totalWork = parameters.totalWork;
    finished = parameters.finished;
}

/**
 * Tests the install commands.
 */
START_TEST (test_install_callback) {
		OPGP_LOAD_FILE_PARAMETERS loadFileParams;
		DWORD receiptDataAvailable = 0;
		DWORD receiptDataLen = 0;
		OPGP_PROGRESS_CALLBACK callback;

		char installParam[1];
		installParam[0] = 0;

		OPGP_ERROR_STATUS status;
		GP211_RECEIPT_DATA receipt;

		status = internal_connect();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not connect: %s", status.errorMessage);
		}
		status = internal_mutual_authentication();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not do mutual authentication: %s", status.errorMessage);
		}

		internal_delete();

		status = OPGP_read_executable_load_file_parameters(TEST_LOAD_FILE,
				&loadFileParams);
		if (OPGP_ERROR_CHECK(status)) {
			fail("OPGP_read_executable_load_file_parameters() failed: ", status.errorMessage);
		}

		status = GP211_install_for_load(cardContext, cardInfo,
				&securityInfo211, loadFileParams.loadFileAID.AID,
				loadFileParams.loadFileAID.AIDLength,
				(PBYTE) GP211_CARD_MANAGER_AID_ALT1, sizeof(GP211_CARD_MANAGER_AID_ALT1),
				NULL, NULL, loadFileParams.loadFileSize, 0, 2000);

		if (OPGP_ERROR_CHECK(status)) {
			fail("GP211_install_for_load() failed: ", status.errorMessage);
		}

		callback.callback = (void(*)(OPGP_PROGRESS_CALLBACK_PARAMETERS))callback_function;
		status = GP211_load(cardContext, cardInfo, &securityInfo211, NULL, 0,
				TEST_LOAD_FILE, NULL, &receiptDataLen, &callback);

		if (OPGP_ERROR_CHECK(status)) {
			fail("GP211_load() failed: ", status.errorMessage);
		}

        fail_unless(totalWork == 411, "Incorrect total size");
        fail_unless(currentWork == 411, "Incorrect currentWork");
        fail_unless(finished == OPGP_TASK_FINISHED, "Incorrect finished state");

		status = internal_disconnect();
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not disconnect: %s", status.errorMessage);
		}
	}END_TEST

Suite * GlobalPlatform_suite(void) {
	Suite *s = suite_create("GlobalPlatform");
	/* Core test case */
	TCase *tc_core = tcase_create("Core");
    tcase_set_timeout(tc_core, 0);
	tcase_add_test (tc_core, test_list_readers);
	tcase_add_test (tc_core, test_connect_card);
	tcase_add_test (tc_core, test_OPGP_VISA2_derive_keys);
	tcase_add_test (tc_core, test_mutual_authentication);
	tcase_add_test (tc_core, test_install);
    tcase_add_test (tc_core, test_delete);
    tcase_add_test (tc_core, test_get_status);
    tcase_add_test (tc_core, test_install_callback);
    tcase_add_test (tc_core, test_put_3des_key);
    // not working with JCOP
    //tcase_add_test (tc_core, test_delete_key);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {
	int number_failed;
	Suite *s = GlobalPlatform_suite();
	SRunner *sr = srunner_create(s);

	//srunner_set_fork_status(sr, CK_NOFORK);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
