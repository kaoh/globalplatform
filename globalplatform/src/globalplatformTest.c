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
#include <check.h>
#include <stdlib.h>
#include "globalplatform/globalplatform.h"
#include <stdio.h>
#include <string.h>

/**
 * Maximum length of the reader name.
 */
#define READERNAMELEN 256

/**
 * Reader number to connect to.
 */
#define READERNUM 0

/**
 * Maximum buffer size for reader names.
 */
#define BUFLEN 2048

/**
 * Test load file
 */
#define TEST_LOAD_FILE "helloworld.cap"

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
static const BYTE packageAID[7] = {0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0x01};

/**
 * Applet AID for test to delete.
 */
static const BYTE appletAID[8] = {0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0x01,0x01};

/**
 * SD AID for tests.
 */
static const BYTE sdInstanceAID[8] = {0xD4, 0xD4, 0xD4, 0xD4, 0xD4, 0x01, 0x01, 0x01};

static const BYTE sdPackageAID[7] = {0xA0, 0x00, 0x00, 0x01, 0x51, 0x53, 0x50};
static const BYTE sdModuleAID[8] = {0xA0, 0x00, 0x00, 0x01, 0x51, 0x53, 0x50, 0x41};

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
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS internal_establish_context() {
	OPGP_enable_trace_mode(OPGP_TRACE_MODE_ENABLE, stderr);
	OPGP_ERROR_STATUS status;
	_tcsncpy(cardContext.libraryName, _T("gppcscconnectionplugin"),
			sizeof(cardContext.libraryName));
	_tcsncpy(cardContext.libraryVersion, _T("1"),
			sizeof(cardContext.libraryVersion));
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
	memcpy(securityInfo211.invokingAid, GP231_ISD_AID, sizeof(GP231_ISD_AID));
	securityInfo211.invokingAidLength = sizeof(GP231_ISD_AID);
	status = GP211_mutual_authentication(cardContext, cardInfo, NULL,
			(PBYTE)OPGP_VISA_DEFAULT_KEY, (PBYTE) OPGP_VISA_DEFAULT_KEY,
			(PBYTE) OPGP_VISA_DEFAULT_KEY, sizeof(OPGP_VISA_DEFAULT_KEY), 0, 0, scp, scpImpl,
			GP211_SCP01_SECURITY_LEVEL_C_DEC_C_MAC, OPGP_DERIVATION_METHOD_NONE, &securityInfo211);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS internal_list_readers() {
	OPGP_ERROR_STATUS status;
	TCHAR buf[BUFLEN + 1];
	int j,k=0;
	DWORD readerStrLen = BUFLEN;
 status = OPGP_list_readers(cardContext, buf, &readerStrLen, 1);
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
		if (k++ == READERNUM) {
			break;
		}
		j += (int) _tcslen(buf + j) + 1;
	}
	readerName[READERNAMELEN] = _T('\0');
	if (_tcslen(readerName) == 0) {
		OPGP_ERROR_CREATE_ERROR(status, -1, "No reader found.");
		return status;
	}
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
	status = OPGP_select_application(cardContext, cardInfo, (PBYTE)GP231_ISD_AID, 8);
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

static OPGP_ERROR_STATUS internal_delete_sd() {
	OPGP_ERROR_STATUS status;
	GP211_RECEIPT_DATA receiptData;
	DWORD receiptDataLength;
	OPGP_AID deleteSD;
	memcpy(deleteSD.AID, sdInstanceAID, sizeof(sdInstanceAID));
	deleteSD.AIDLength = sizeof(sdInstanceAID);
	status = GP211_delete_application(cardContext, cardInfo, &securityInfo211, &deleteSD, 1, &receiptData, &receiptDataLength);
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
			ck_abort_msg("Could not connect: %s", status.errorMessage);
		}
		status = internal_disconnect();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not disconnect: %s", status.errorMessage);
		}
		if (cardInfo.librarySpecific != NULL) {
			ck_abort_msg("Library specific data must be NULL after disconnecting.");
		}
		if (cardContext.libraryHandle != NULL) {
			ck_abort_msg("Library handle must be NULL after releasing.");
		}
		if (cardContext.librarySpecific != NULL) {
			ck_abort_msg("Library specific data must be NULL after releasing.");
		}
	}END_TEST

/**
 * Tests the listing of readers.
 */
START_TEST (test_list_readers)
	{
		OPGP_ERROR_STATUS status;
		status = internal_establish_context();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not establish context: %s", status.errorMessage);
		}
		status = internal_list_readers();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not list readers: %s", status.errorMessage);
		}
		status = internal_release_context();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not release context: %s", status.errorMessage);
		}
	}END_TEST

/**
 * Tests the key derivation according to gemXpresso scheme.
 */
START_TEST (test_GP211_VISA2_derive_keys)
	{
		OPGP_ERROR_STATUS status;
		status = internal_connect();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not connect: %s", status.errorMessage);
		}
		BYTE motherKey[] = { 0x4D, 0xA5, 0xFC, 0x18, 0xA4, 0x6F, 0x8A, 0x02,
				0x05, 0xC7, 0x7C, 0x37, 0x3B, 0x58, 0x2A, 0x1F };
		BYTE S_ENC[16], S_MAC[16], DEK[16];
		int i;
		status = GP211_VISA2_derive_keys(cardContext, cardInfo, &securityInfo211,
				(PBYTE) GP211_CARD_MANAGER_AID_ALT1,
				sizeof(GP211_CARD_MANAGER_AID_ALT1), motherKey, S_ENC, S_MAC,
				DEK);
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Derivation of keys failed: %s", status.errorMessage);
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
			ck_abort_msg("Could not disconnect: %s", status.errorMessage);
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
			ck_abort_msg("Could not connect: %s", status.errorMessage);
		}
		status = internal_mutual_authentication();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not do mutual authentication: %s", status.errorMessage);
		}
		status = internal_disconnect();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not disconnect: %s", status.errorMessage);
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

		OPGP_ERROR_STATUS status;
		GP211_RECEIPT_DATA receipt;

		status = internal_connect();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not connect: %s", status.errorMessage);
		}
		status = internal_mutual_authentication();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not do mutual authentication: %s", status.errorMessage);
		}

		internal_delete();

		status = OPGP_read_executable_load_file_parameters(TEST_LOAD_FILE,
				&loadFileParams);
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("OPGP_read_executable_load_file_parameters() failed: %s", status.errorMessage);
		}

		status = GP211_install_for_load(cardContext, cardInfo,
				&securityInfo211, loadFileParams.loadFileAID.AID,
				loadFileParams.loadFileAID.AIDLength,
				(PBYTE) GP231_ISD_AID, sizeof(GP231_ISD_AID),
				NULL, 0, NULL, 0, loadFileParams.loadFileSize, 0, 2000);

		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("GP211_install_for_load() failed: %s", status.errorMessage);
		}

		status = GP211_load(cardContext, cardInfo, &securityInfo211, NULL, 0,
				TEST_LOAD_FILE, NULL, &receiptDataLen, NULL);

		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("GP211_load() failed: %s", status.errorMessage);
		}

		status = GP211_install_for_install_and_make_selectable(cardContext,
				cardInfo, &securityInfo211, loadFileParams.loadFileAID.AID,
				loadFileParams.loadFileAID.AIDLength,
				loadFileParams.appletAIDs[0].AID,
				loadFileParams.appletAIDs[0].AIDLength,
				loadFileParams.appletAIDs[0].AID,
				loadFileParams.appletAIDs[0].AIDLength, 0, 500, 1000, NULL, 0,
				NULL, 0, NULL, 0, NULL, 0, NULL, 0, &receipt, &receiptDataAvailable);

		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("GP211_install_for_install_and_make_selectable() failed: %s", status.errorMessage);
		}

		status = internal_disconnect();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not disconnect: %s", status.errorMessage);
		}
	}END_TEST

START_TEST (test_delete) {
		OPGP_ERROR_STATUS status;
		status = internal_connect();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not connect: %s", status.errorMessage);
		}
		status = internal_mutual_authentication();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not do mutual authentication: %s", status.errorMessage);
		}
		status = internal_delete();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not delete applets: %s", status.errorMessage);
		}
		status = internal_disconnect();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not disconnect: %s", status.errorMessage);
		}
} END_TEST

/**
 * Test the get status command.
 */
START_TEST (test_get_status) {
		OPGP_ERROR_STATUS status;
		GP211_APPLICATION_DATA appData[10];
		GP211_EXECUTABLE_MODULES_DATA modulesData[10];
		DWORD dataLength = 10;
		status = internal_connect();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not connect: %s", status.errorMessage);
		}
		status = internal_mutual_authentication();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not do mutual authentication: %s", status.errorMessage);
		}
		status = GP211_get_status(cardContext, cardInfo, &securityInfo211, GP211_STATUS_APPLICATIONS, GP211_STATUS_FORMAT_DEPRECATED, appData, modulesData, &dataLength);
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not get status from applications: %s", status.errorMessage);
		}

		{
			int found = 0;
			DWORD i;
			for (i = 0; i < dataLength; i++) {
				if (appData[i].aid.AIDLength == sizeof(appletAID) &&
						memcmp(appData[i].aid.AID, appletAID, sizeof(appletAID)) == 0) {
					found = 1;
					break;
				}
			}
			if (!found) {
				ck_abort_msg("Applet AID not found in application status");
			}
			if (appData[i].lifeCycleState != 7) {
				ck_abort_msg("Incorrect application status life cycle state");
			}
			if (appData[i].privileges != 0) {
				ck_abort_msg("Incorrect application status privileges");
			}
		}

        dataLength = 10;
		status = GP211_get_status(cardContext, cardInfo, &securityInfo211, GP211_STATUS_LOAD_FILES, GP211_STATUS_FORMAT_DEPRECATED, appData, modulesData, &dataLength);
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not get status from applications: %s", status.errorMessage);
		}

		{
			int found = 0;
			DWORD i;
			for (i = 0; i < dataLength; i++) {
				if (appData[i].aid.AIDLength == sizeof(packageAID) &&
						memcmp(appData[i].aid.AID, packageAID, sizeof(packageAID)) == 0) {
					found = 1;
					break;
						}
			}
			if (!found) {
				ck_abort_msg("Applet AID not found in application status");
			}
			if (appData[i].lifeCycleState != 1) {
				ck_abort_msg("Incorrect load file status");
			}
			if (appData[i].privileges != 0) {
				ck_abort_msg("Incorrect load file status");
			}
		}

		if (dataLength != 5) {
			ck_abort_msg("Incorrect load file status");
		}

        dataLength = 10;
		status = GP211_get_status(cardContext, cardInfo, &securityInfo211, GP211_STATUS_ISSUER_SECURITY_DOMAIN, GP211_STATUS_FORMAT_DEPRECATED, appData, modulesData, &dataLength);
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not get status from applications: %s", status.errorMessage);
		}
		if (dataLength != 1) {
			ck_abort_msg("Incorrect issuer security status");
		}
		if (memcmp(appData[0].aid.AID, GP231_ISD_AID, sizeof(GP231_ISD_AID)) != 0) {
			ck_abort_msg("Incorrect issuer security status");
		}

		status = internal_disconnect();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not disconnect: %s", status.errorMessage);
		}
} END_TEST


START_TEST (test_put_aes_key) {
		OPGP_ERROR_STATUS status;
		BYTE key[16] = {0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5};
		status = internal_connect();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not connect: %s", status.errorMessage);
		}
		status = internal_mutual_authentication();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not do mutual authentication: %s", status.errorMessage);
		}
		GP211_delete_key(cardContext, cardInfo, &securityInfo211, 5, 0xFF);
		status = GP211_put_aes_key(cardContext, cardInfo, &securityInfo211, 0, 1, 5, key, sizeof(key));
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not put key: %s", status.errorMessage);
		}
		status = internal_disconnect();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not disconnect: %s", status.errorMessage);
		}
} END_TEST


START_TEST (test_delete_key) {
		OPGP_ERROR_STATUS status;
		status = internal_connect();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not connect: %s", status.errorMessage);
		}
		status = internal_mutual_authentication();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not do mutual authentication: %s", status.errorMessage);
		}
		status = GP211_delete_key(cardContext, cardInfo, &securityInfo211, 5, 0xFF);
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not delete key: %s", status.errorMessage);
		}
		status = internal_disconnect();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not disconnect: %s", status.errorMessage);
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
		DWORD receiptDataLen = 0;
		OPGP_PROGRESS_CALLBACK callback;
		OPGP_ERROR_STATUS status;

		status = internal_connect();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not connect: %s", status.errorMessage);
		}
		status = internal_mutual_authentication();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not do mutual authentication: %s", status.errorMessage);
		}

		internal_delete();

		status = OPGP_read_executable_load_file_parameters(TEST_LOAD_FILE,
				&loadFileParams);
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("OPGP_read_executable_load_file_parameters() failed: %s", status.errorMessage);
		}

		status = GP211_install_for_load(cardContext, cardInfo,
				&securityInfo211, loadFileParams.loadFileAID.AID,
				loadFileParams.loadFileAID.AIDLength,
				(PBYTE) GP231_ISD_AID, sizeof(GP231_ISD_AID),
				NULL, 0, NULL, 0, loadFileParams.loadFileSize, 0, 2000);

		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("GP211_install_for_load() failed: %s", status.errorMessage);
		}

		callback.callback = callback_function;
		status = GP211_load(cardContext, cardInfo, &securityInfo211, NULL, 0,
				TEST_LOAD_FILE, NULL, &receiptDataLen, &callback);

		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("GP211_load() failed: %s", status.errorMessage);
		}

        if (totalWork != 343) {
            ck_abort_msg("Incorrect total size");
        }
        if (currentWork != 343) {
            ck_abort_msg("Incorrect currentWork");
        }
        if (finished != OPGP_TASK_FINISHED) {
            ck_abort_msg("Incorrect finished state");
        }

		status = internal_disconnect();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("Could not disconnect: %s", status.errorMessage);
		}
	}END_TEST

/**
 * Tests the SD creation.
 */
START_TEST (test_create_sd) {
	OPGP_ERROR_STATUS status;
	GP211_APPLICATION_DATA appData[10];
	GP211_EXECUTABLE_MODULES_DATA modulesData[10];
	DWORD dataLength = 10;
	GP211_RECEIPT_DATA receipt;
	DWORD receiptDataAvailable = 0;
	GP211_SD_INSTALL_PARAMS sdParams;
	BYTE sdParamsBuf[100];
	DWORD sdParamsLen = sizeof(sdParamsBuf);

	status = internal_connect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not connect: %s", status.errorMessage);
	}
	status = internal_mutual_authentication();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not do mutual authentication: %s", status.errorMessage);
	}

	internal_delete_sd();

	memset(&sdParams, 0, sizeof(sdParams));
	// 0x01 = accept from ISD
	sdParams.acceptExtraditionHere[0] = GP211_SD_ACCEPT_ISD;
	sdParams.acceptExtraditionHere[1] = GP211_SD_ACCEPT_ISD;
	sdParams.acceptExtraditionHereLength = 2;
	sdParams.acceptExtraditionAway[0] = GP211_SD_ACCEPT_ISD;
	sdParams.acceptExtraditionAway[1] = GP211_SD_ACCEPT_ISD;
	sdParams.acceptExtraditionAwayLength = 2;
	sdParams.acceptDeletion = GP211_SD_ACCEPT_ISD;
	sdParams.acceptDeletionLength = 1;

	status = GP211_build_sd_parameters(&sdParams, sdParamsBuf, &sdParamsLen);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_build_sd_parameters() failed: %s", status.errorMessage);
	}

	status = GP211_install_for_install_and_make_selectable(cardContext,
			cardInfo, &securityInfo211,
			(PBYTE)sdPackageAID, sizeof(sdPackageAID),
			(PBYTE)sdModuleAID, sizeof(sdModuleAID),
			(PBYTE)sdInstanceAID, sizeof(sdInstanceAID),
			GP211_SECURITY_DOMAIN, 0, 0, NULL, 0,
			sdParamsBuf, sdParamsLen, NULL, 0, NULL, 0, NULL, 0, &receipt, &receiptDataAvailable);

	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_install_for_install_and_make_selectable() failed: %s", status.errorMessage);
	}

	status = GP211_get_status(cardContext, cardInfo, &securityInfo211, GP211_STATUS_APPLICATIONS, GP211_STATUS_FORMAT_NEW, appData, modulesData, &dataLength);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not get status from applications: %s", status.errorMessage);
	}

	{
		int found = 0;
		DWORD i;
		for (i = 0; i < dataLength; i++) {
			if (appData[i].aid.AIDLength == sizeof(sdInstanceAID) &&
					memcmp(appData[i].aid.AID, sdInstanceAID, sizeof(sdInstanceAID)) == 0) {
				found = 1;
				break;
			}
		}
		if (!found) {
			ck_abort_msg("SD AID not found in application status");
		}
		if (appData[i].lifeCycleState != GP211_LIFE_CYCLE_APPLICATION_SELECTABLE) {
			ck_abort_msg("Incorrect SD life cycle state: expected %d, got %d", GP211_LIFE_CYCLE_APPLICATION_SELECTABLE, appData[i].lifeCycleState);
		}
		if (!(appData[i].privileges & GP211_SECURITY_DOMAIN)) {
			ck_abort_msg("Incorrect SD privileges");
		}
	}

	status = internal_disconnect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not disconnect: %s", status.errorMessage);
	}
} END_TEST

/**
 * Tests the SD personalization.
 */
START_TEST (test_personalize_sd) {
	OPGP_ERROR_STATUS status;
	BYTE key[16] = {0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x40};
	GP211_SECURITY_INFO sdSecurityInfo;
	GP211_APPLICATION_DATA appData[10];
	GP211_EXECUTABLE_MODULES_DATA modulesData[10];
	DWORD dataLength = 10;
	GP211_KEY_INFORMATION keyInfo[10];
	DWORD keyInfoLen = 10;

	status = internal_connect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not connect: %s", status.errorMessage);
	}

	// Now select the new SD and authenticate
	status = OPGP_select_application(cardContext, cardInfo, (PBYTE)sdInstanceAID, sizeof(sdInstanceAID));
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Selecting SD failed: %s", status.errorMessage);
	}

	memcpy(sdSecurityInfo.invokingAid, sdInstanceAID, sizeof(sdInstanceAID));
	sdSecurityInfo.invokingAidLength = sizeof(sdInstanceAID);
	status = GP211_mutual_authentication(cardContext, cardInfo, NULL, OPGP_VISA_DEFAULT_KEY, OPGP_VISA_DEFAULT_KEY, OPGP_VISA_DEFAULT_KEY, 16, 0, 0, 0, 0, GP211_SCP03, OPGP_DERIVATION_METHOD_NONE, &sdSecurityInfo);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Mutual authentication with new SD failed: %s", status.errorMessage);
	}

	// Personalize: put-auth
	status = GP211_put_secure_channel_keys(cardContext, cardInfo, &sdSecurityInfo, 0, 1, NULL, key, key, key, 16, GP211_KEY_TYPE_AES);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_put_secure_channel_keys() failed: %s", status.errorMessage);
	}

	// List keys
	status = GP211_get_key_information_templates(cardContext, cardInfo, &sdSecurityInfo, 0, keyInfo, &keyInfoLen);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_get_key_information_templates() failed: %s", status.errorMessage);
	}

	if (keyInfoLen == 0) {
		ck_abort_msg("No keys found in personalized SD");
	}

	// Check life cycle state
	dataLength = 10;
	status = GP211_get_status(cardContext, cardInfo, &sdSecurityInfo, GP211_STATUS_APPLICATIONS, GP211_STATUS_FORMAT_NEW, appData, modulesData, &dataLength);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not get status from applications: %s", status.errorMessage);
	}

	{
		int found = 0;
		DWORD i;
		for (i = 0; i < dataLength; i++) {
			if (appData[i].aid.AIDLength == sizeof(sdInstanceAID) &&
					memcmp(appData[i].aid.AID, sdInstanceAID, sizeof(sdInstanceAID)) == 0) {
				found = 1;
				break;
			}
		}
		if (!found) {
			ck_abort_msg("SD AID not found in application status after personalization");
		}
		if (appData[i].lifeCycleState != GP211_LIFE_CYCLE_SECURITY_DOMAIN_PERSONALIZED) {
			ck_abort_msg("Incorrect SD life cycle state: expected %d, got %d", GP211_LIFE_CYCLE_SECURITY_DOMAIN_PERSONALIZED, appData[i].lifeCycleState);
		}
	}

	status = internal_disconnect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not disconnect: %s", status.errorMessage);
	}
} END_TEST

/**
 * Tests the SD extradition (move).
 */
START_TEST (test_move_sd) {
	OPGP_ERROR_STATUS status;
	GP211_APPLICATION_DATA appData[20];
	GP211_EXECUTABLE_MODULES_DATA modulesData[20];
	DWORD dataLength = 20;
	GP211_RECEIPT_DATA receipt;
	DWORD receiptDataAvailable = 0;

	status = internal_connect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not connect: %s", status.errorMessage);
	}
	status = internal_mutual_authentication();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not do mutual authentication: %s", status.errorMessage);
	}

	status = GP211_install_for_extradition(cardContext, cardInfo, &securityInfo211, (PBYTE)sdInstanceAID, sizeof(sdInstanceAID), (PBYTE)sdInstanceAID, sizeof(sdInstanceAID), NULL, &receipt, &receiptDataAvailable);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_install_for_extradition() failed: %s", status.errorMessage);
	}

	status = GP211_get_status(cardContext, cardInfo, &securityInfo211, GP211_STATUS_APPLICATIONS, GP211_STATUS_FORMAT_NEW, appData, modulesData, &dataLength);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not get status from applications: %s", status.errorMessage);
	}

	{
		DWORD i;
		int sdCount = 0;
		for (i = 0; i < dataLength; i++) {
			if (appData[i].privileges & GP211_SECURITY_DOMAIN) {
				sdCount++;
			}
		}
		if (sdCount != 1) {
			ck_abort_msg("Expected 1 security domain, found %d", sdCount);
		}
	}

	status = internal_disconnect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not disconnect: %s", status.errorMessage);
	}
} END_TEST

/**
 * Tests the SD deletion.
 */
START_TEST (test_delete_sd) {
	OPGP_ERROR_STATUS status;
	GP211_APPLICATION_DATA appData[20];
	GP211_EXECUTABLE_MODULES_DATA modulesData[20];
	DWORD dataLength = 20;

	status = internal_connect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not connect: %s", status.errorMessage);
	}
	status = internal_mutual_authentication();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not do mutual authentication: %s", status.errorMessage);
	}

	status = internal_delete_sd();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not delete SD: %s", status.errorMessage);
	}

	status = GP211_get_status(cardContext, cardInfo, &securityInfo211, GP211_STATUS_APPLICATIONS, GP211_STATUS_FORMAT_NEW, appData, modulesData, &dataLength);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not get status from applications: %s", status.errorMessage);
	}

	{
		DWORD i;
		for (i = 0; i < dataLength; i++) {
			if (appData[i].aid.AIDLength == sizeof(sdInstanceAID) &&
					memcmp(appData[i].aid.AID, sdInstanceAID, sizeof(sdInstanceAID)) == 0) {
				ck_abort_msg("SD AID still found in application status after deletion");
			}
		}
	}

	status = internal_disconnect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not disconnect: %s", status.errorMessage);
	}
} END_TEST

Suite * GlobalPlatform_suite(void) {
	Suite *s = suite_create("GlobalPlatform");
	/* Core test case */
	TCase *tc_core = tcase_create("Core");
    tcase_set_timeout(tc_core, 0);
	tcase_add_test (tc_core, test_list_readers);
	tcase_add_test (tc_core, test_connect_card);
	tcase_add_test (tc_core, test_GP211_VISA2_derive_keys);
	tcase_add_test (tc_core, test_mutual_authentication);
	tcase_add_test (tc_core, test_install);
    tcase_add_test (tc_core, test_get_status);
    tcase_add_test (tc_core, test_delete);
    tcase_add_test (tc_core, test_install_callback);
    tcase_add_test (tc_core, test_put_aes_key);
    tcase_add_test (tc_core, test_delete_key);
	tcase_add_test (tc_core, test_create_sd);
	tcase_add_test (tc_core, test_personalize_sd);
	tcase_add_test (tc_core, test_move_sd);
	tcase_add_test (tc_core, test_delete_sd);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {
	int number_failed;
	Suite *s = GlobalPlatform_suite();
	SRunner *sr = srunner_create(s);

	srunner_set_fork_status(sr, CK_NOFORK);
    if (getenv("CK_VERBOSITY") != NULL && strcmp(getenv("CK_VERBOSITY"), "silent") == 0) {
        srunner_run_all(sr, CK_SILENT);
    } else if (getenv("CK_VERBOSITY") != NULL && strcmp(getenv("CK_VERBOSITY"), "minimal") == 0) {
        srunner_run_all(sr, CK_MINIMAL);
    } else if (getenv("CK_VERBOSITY") != NULL && strcmp(getenv("CK_VERBOSITY"), "normal") == 0) {
        srunner_run_all(sr, CK_NORMAL);
    } else {
        srunner_run_all(sr, CK_VERBOSE);
    }
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
