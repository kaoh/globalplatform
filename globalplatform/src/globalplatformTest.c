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

// NOTE: A JCOP 4.5 is needed to runn all tests

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
#define TEST_ECC_PRIVATE_KEY "ecc_private_key_test.pem"
#define TEST_ECC_PUBLIC_KEY "ecc_public_key_test.pem"
#define TEST_RSA_PRIVATE_KEY "rsa_private_key.pem"
#define TEST_RSA_PUBLIC_KEY "rsa_public_key.pem"
#define TEST_RSA_1024_PRIVATE_KEY "rsa_1024_private_key_test.pem"
#define TEST_RSA_1024_PUBLIC_KEY "rsa_1024_public_key_test.pem"

#define INTERNAL_DELETE_APPLET 0x01
#define INTERNAL_DELETE_PACKAGE 0x02
#define INTERNAL_DELETE_SD 0x04

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
static const BYTE sdPersonalizationKey[16] = {
		0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
		0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x40
};
static const BYTE delegatedReceiptKey[32] = {
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
};

static OPGP_LOAD_FILE_PARAMETERS dmLoadFileParams;
static BYTE dmLoadFileDataBlockHash[64];
static DWORD dmLoadFileDataBlockHashLength;
static BYTE dmLoadToken[512];
static DWORD dmLoadTokenLength;
static BYTE dmInstallToken[512];
static DWORD dmInstallTokenLength;
static int dmLoadFileParamsAvailable = 0;
static const char *dmLoadTokenKeyLabel = NULL;
static const char *dmInstallTokenKeyLabel = NULL;

static OPGP_LOAD_FILE_PARAMETERS dapLoadFileParams;
static BYTE dapLoadFileDataBlockHash[64];
static DWORD dapLoadFileDataBlockHashLength;
static GP211_DAP_BLOCK dapLoadFileSignature;
static int dapLoadFileParamsAvailable = 0;
static int dapLoadFileSignatureAvailable = 0;

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
	status = GP211_get_secure_channel_protocol_details(cardContext, cardInfo, &securityInfo211,
			&scp, &scpImpl);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	memcpy(securityInfo211.invokingAid, GP231_ISD_AID, sizeof(GP231_ISD_AID));
	securityInfo211.invokingAidLength = sizeof(GP231_ISD_AID);
	status = GP211_mutual_authentication(cardContext, cardInfo, NULL,
			(PBYTE)OPGP_VISA_DEFAULT_KEY, (PBYTE) OPGP_VISA_DEFAULT_KEY,
			(PBYTE) OPGP_VISA_DEFAULT_KEY, sizeof(OPGP_VISA_DEFAULT_KEY), 0, 0, scp, scpImpl,
			GP211_SCP01_SECURITY_LEVEL_C_MAC, OPGP_DERIVATION_METHOD_NONE, &securityInfo211);
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
	status = OPGP_select_application(cardContext, cardInfo, &securityInfo211, (PBYTE)GP231_ISD_AID, 8);
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


static OPGP_ERROR_STATUS internal_delete_aid(const BYTE *aid, BYTE aidLength, int ignoreErrors) {
	OPGP_ERROR_STATUS status;
	GP211_RECEIPT_DATA receiptData;
	DWORD receiptDataLength = 0;
	OPGP_AID deleteAID;

	memcpy(deleteAID.AID, aid, aidLength);
	deleteAID.AIDLength = aidLength;
	status = GP211_delete_application(cardContext, cardInfo, &securityInfo211, &deleteAID, 1, &receiptData, &receiptDataLength, NULL, 0);
	if (OPGP_ERROR_CHECK(status)) {
		if (ignoreErrors) {
			OPGP_ERROR_CREATE_NO_ERROR(status);
			return status;
		}
		return status;
	}
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS internal_delete_selected(DWORD deleteFlags, int ignoreErrors) {
	OPGP_ERROR_STATUS status;

	if (deleteFlags & INTERNAL_DELETE_APPLET) {
		status = internal_delete_aid(appletAID, sizeof(appletAID), ignoreErrors);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
	}
	if (deleteFlags & INTERNAL_DELETE_PACKAGE) {
		status = internal_delete_aid(packageAID, sizeof(packageAID), ignoreErrors);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
	}
	if (deleteFlags & INTERNAL_DELETE_SD) {
		status = internal_delete_aid(sdInstanceAID, sizeof(sdInstanceAID), ignoreErrors);
		if (OPGP_ERROR_CHECK(status)) {
			return status;
		}
	}
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS internal_delete_key_set_with_secinfo(GP211_SECURITY_INFO *secInfo, BYTE keySetVersion, int ignoreErrors) {
	OPGP_ERROR_STATUS status;
	status = GP211_delete_key(cardContext, cardInfo, secInfo, keySetVersion, 0xFF);
	if (OPGP_ERROR_CHECK(status)) {
		if (ignoreErrors) {
			OPGP_ERROR_CREATE_NO_ERROR(status);
			return status;
		}
		return status;
	}
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS internal_delete_key_set(BYTE keySetVersion, int ignoreErrors) {
	return internal_delete_key_set_with_secinfo(&securityInfo211, keySetVersion, ignoreErrors);
}

static OPGP_ERROR_STATUS internal_delete() {
	OPGP_ERROR_STATUS status;
	status = internal_delete_selected(INTERNAL_DELETE_APPLET, 1);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	status = internal_delete_selected(INTERNAL_DELETE_PACKAGE, 0);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS internal_delete_sd() {
	return internal_delete_selected(INTERNAL_DELETE_SD, 0);
}

static OPGP_ERROR_STATUS internal_read_dm_load_file_parameters() {
	OPGP_ERROR_STATUS status;
	memset(&dmLoadFileParams, 0, sizeof(dmLoadFileParams));
	status = OPGP_read_executable_load_file_parameters(TEST_LOAD_FILE, &dmLoadFileParams);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	if (dmLoadFileParams.appletAIDs[0].AIDLength == 0) {
		OPGP_ERROR_CREATE_ERROR(status, -1, "No applet AID found in CAP file.");
		return status;
	}
	dmLoadFileParamsAvailable = 1;
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS internal_read_dap_load_file_parameters() {
	OPGP_ERROR_STATUS status;
	memset(&dapLoadFileParams, 0, sizeof(dapLoadFileParams));
	status = OPGP_read_executable_load_file_parameters(TEST_LOAD_FILE, &dapLoadFileParams);
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	if (dapLoadFileParams.appletAIDs[0].AIDLength == 0) {
		OPGP_ERROR_CREATE_ERROR(status, -1, "No applet AID found in CAP file.");
		return status;
	}
	dapLoadFileParamsAvailable = 1;
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS internal_connect_and_authenticate() {
	OPGP_ERROR_STATUS status;
	status = internal_connect();
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	status = internal_mutual_authentication();
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}
	OPGP_ERROR_CREATE_NO_ERROR(status);
	return status;
}

static OPGP_ERROR_STATUS internal_select_and_authenticate_personalized_sd(GP211_SECURITY_INFO *sdSecurityInfo) {
	OPGP_ERROR_STATUS status;
	status = OPGP_select_application(cardContext, cardInfo, sdSecurityInfo, (PBYTE)sdInstanceAID, sizeof(sdInstanceAID));
	if (OPGP_ERROR_CHECK(status)) {
		return status;
	}

	memcpy(sdSecurityInfo->invokingAid, sdInstanceAID, sizeof(sdInstanceAID));
	sdSecurityInfo->invokingAidLength = sizeof(sdInstanceAID);
	status = GP211_mutual_authentication(cardContext, cardInfo, NULL,
			(PBYTE)sdPersonalizationKey, (PBYTE)sdPersonalizationKey, (PBYTE)sdPersonalizationKey,
			sizeof(sdPersonalizationKey), 1, 0, 0, 0, GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC, OPGP_DERIVATION_METHOD_NONE, sdSecurityInfo);
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
	status = OPGP_select_application(cardContext, cardInfo, &sdSecurityInfo, (PBYTE)sdInstanceAID, sizeof(sdInstanceAID));
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Selecting SD failed: %s", status.errorMessage);
	}

	memcpy(sdSecurityInfo.invokingAid, sdInstanceAID, sizeof(sdInstanceAID));
	sdSecurityInfo.invokingAidLength = sizeof(sdInstanceAID);
	status = GP211_mutual_authentication(cardContext, cardInfo, NULL,
			(PBYTE)OPGP_VISA_DEFAULT_KEY, (PBYTE)OPGP_VISA_DEFAULT_KEY, (PBYTE)OPGP_VISA_DEFAULT_KEY,
			16, 0, 0, 0, 0, GP211_SCP03_SECURITY_LEVEL_C_MAC, OPGP_DERIVATION_METHOD_NONE, &sdSecurityInfo);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Mutual authentication with new SD failed: %s", status.errorMessage);
	}

	// Personalize: put-auth
	status = GP211_put_secure_channel_keys(cardContext, cardInfo, &sdSecurityInfo, 0, 1, NULL,
			(PBYTE)sdPersonalizationKey, (PBYTE)sdPersonalizationKey, (PBYTE)sdPersonalizationKey,
			sizeof(sdPersonalizationKey), GP211_KEY_TYPE_AES);
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

	status = GP211_install_for_extradition(cardContext, cardInfo, &securityInfo211, (PBYTE)sdInstanceAID, sizeof(sdInstanceAID), (PBYTE)sdInstanceAID, sizeof(sdInstanceAID), NULL, 0, &receipt, &receiptDataAvailable);
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

/**
 * Delegated management test step 1:
 * Put token verification key.
 */
static void test_dm_put_token_key(OPGP_STRING publicKeyFile, BYTE tokenKeyType, const char *tokenKeyLabel) {
	OPGP_ERROR_STATUS status;
	status = internal_connect_and_authenticate();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not connect and authenticate: %s", status.errorMessage);
	}

	status = internal_delete_key_set(GP211_KEY_VERSION_TOKEN_VERIFICATION, 1);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not pre-delete token key set: %s", status.errorMessage);
	}

	status = GP211_put_delegated_management_token_keys(cardContext, cardInfo, &securityInfo211,
			0, GP211_KEY_VERSION_TOKEN_VERIFICATION,
			publicKeyFile, NULL, tokenKeyType);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_put_delegated_management_token_keys() failed for %s: %s", tokenKeyLabel, status.errorMessage);
	}

	status = internal_disconnect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not disconnect: %s", status.errorMessage);
	}
}

START_TEST (test_dm_put_token_key_ecc) {
	test_dm_put_token_key(TEST_ECC_PUBLIC_KEY, GP211_KEY_TYPE_ECC, "ECC");
} END_TEST

START_TEST (test_dm_put_token_key_rsa1024) {
	test_dm_put_token_key(TEST_RSA_1024_PUBLIC_KEY, GP211_KEY_TYPE_RSA, "RSA1024");
} END_TEST
START_TEST (test_dm_put_token_key_rsa) {
	test_dm_put_token_key(TEST_RSA_PUBLIC_KEY, GP211_KEY_TYPE_RSA, "RSA2048");
} END_TEST

/**
 * Delegated management test step 2:
 * Put AES-256 receipt key.
 */
START_TEST (test_dm_put_receipt_key_aes256) {
	OPGP_ERROR_STATUS status;
	status = internal_connect_and_authenticate();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not connect and authenticate: %s", status.errorMessage);
	}

	status = internal_delete_key_set(GP211_KEY_VERSION_RECEIPT_GENERATION, 1);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not pre-delete receipt key set: %s", status.errorMessage);
	}

	status = GP211_put_delegated_management_receipt_keys(cardContext, cardInfo, &securityInfo211,
			0, GP211_KEY_VERSION_RECEIPT_GENERATION,
			(BYTE *)delegatedReceiptKey, sizeof(delegatedReceiptKey), GP211_KEY_TYPE_AES);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_put_delegated_management_receipt_keys() failed: %s", status.errorMessage);
	}

	status = internal_disconnect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not disconnect: %s", status.errorMessage);
	}
} END_TEST

/**
 * Delegated management test step 3:
 * Install a delegated management SD.
 */
START_TEST (test_dm_install_sd_with_delegated_management) {
	OPGP_ERROR_STATUS status;
	GP211_SD_INSTALL_PARAMS sdParams;
	BYTE sdParamsBuf[100];
	DWORD sdParamsLen = sizeof(sdParamsBuf);
	GP211_RECEIPT_DATA receipt;
	DWORD receiptDataAvailable = 0;
	GP211_APPLICATION_DATA appData[20];
	GP211_EXECUTABLE_MODULES_DATA modulesData[20];
	DWORD dataLength = 20;

	status = internal_connect_and_authenticate();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not connect and authenticate: %s", status.errorMessage);
	}

	status = internal_delete_selected(INTERNAL_DELETE_SD, 1);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not pre-delete delegated management SD: %s", status.errorMessage);
	}

	memset(&sdParams, 0, sizeof(sdParams));
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

	status = GP211_install_for_install_and_make_selectable(cardContext, cardInfo, &securityInfo211,
			(PBYTE)sdPackageAID, sizeof(sdPackageAID),
			(PBYTE)sdModuleAID, sizeof(sdModuleAID),
			(PBYTE)sdInstanceAID, sizeof(sdInstanceAID),
			GP211_SECURITY_DOMAIN | GP211_DELEGATED_MANAGEMENT,
			0, 0,
			NULL, 0,
			sdParamsBuf, sdParamsLen,
			NULL, 0,
			NULL, 0,
			NULL, 0,
			&receipt, &receiptDataAvailable);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_install_for_install_and_make_selectable() failed: %s", status.errorMessage);
	}

	status = GP211_get_status(cardContext, cardInfo, &securityInfo211,
			GP211_STATUS_APPLICATIONS, GP211_STATUS_FORMAT_NEW,
			appData, modulesData, &dataLength);
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
			ck_abort_msg("Delegated management SD AID not found in status.");
		}
		if (!(appData[i].privileges & GP211_SECURITY_DOMAIN) ||
				!(appData[i].privileges & GP211_DELEGATED_MANAGEMENT)) {
			ck_abort_msg("SD privileges do not contain security-domain and delegated-management.");
		}
	}

	status = internal_disconnect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not disconnect: %s", status.errorMessage);
	}
} END_TEST

/**
 * ECC DAP test step 1:
 * Install a Security Domain with mandated DAP verification privileges.
 */
START_TEST (test_dap_install_sd_with_mandated_dap) {
	OPGP_ERROR_STATUS status;
	GP211_SD_INSTALL_PARAMS sdParams;
	BYTE sdParamsBuf[100];
	DWORD sdParamsLen = sizeof(sdParamsBuf);
	GP211_RECEIPT_DATA receipt;
	DWORD receiptDataAvailable = 0;
	GP211_APPLICATION_DATA appData[20];
	GP211_EXECUTABLE_MODULES_DATA modulesData[20];
	DWORD dataLength = 20;

	status = internal_connect_and_authenticate();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not connect and authenticate: %s", status.errorMessage);
	}

	status = internal_delete_selected(INTERNAL_DELETE_SD, 1);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not pre-delete DAP SD: %s", status.errorMessage);
	}

	memset(&sdParams, 0, sizeof(sdParams));
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

	status = GP211_install_for_install_and_make_selectable(cardContext, cardInfo, &securityInfo211,
			(PBYTE)sdPackageAID, sizeof(sdPackageAID),
			(PBYTE)sdModuleAID, sizeof(sdModuleAID),
			(PBYTE)sdInstanceAID, sizeof(sdInstanceAID),
			GP211_SECURITY_DOMAIN | GP211_MANDATED_DAP_VERIFICATION | GP211_DAP_VERIFICATION,
			0, 0,
			NULL, 0,
			sdParamsBuf, sdParamsLen,
			NULL, 0,
			NULL, 0,
			NULL, 0,
			&receipt, &receiptDataAvailable);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_install_for_install_and_make_selectable() failed: %s", status.errorMessage);
	}

	status = GP211_get_status(cardContext, cardInfo, &securityInfo211,
			GP211_STATUS_APPLICATIONS, GP211_STATUS_FORMAT_NEW,
			appData, modulesData, &dataLength);
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
			ck_abort_msg("DAP SD AID not found in status.");
		}
		if (!(appData[i].privileges & GP211_SECURITY_DOMAIN) ||
				!(appData[i].privileges & GP211_DAP_VERIFICATION) ||
				!(appData[i].privileges & GP211_MANDATED_DAP_VERIFICATION)) {
			ck_abort_msg("SD privileges do not contain Security Domain, DAP Verification and Mandated DAP Verification.");
		}
	}

	status = internal_disconnect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not disconnect: %s", status.errorMessage);
	}
} END_TEST

/**
 * ECC DAP test step 2:
 * Personalize the DAP Security Domain and put the ECC DAP verification key.
 */
START_TEST (test_dap_personalize_sd) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO sdSecurityInfo;
	GP211_APPLICATION_DATA appData[10];
	GP211_EXECUTABLE_MODULES_DATA modulesData[10];
	DWORD dataLength = 10;
	GP211_KEY_INFORMATION keyInfo[20];
	DWORD keyInfoLen = 20;

	status = internal_connect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not connect: %s", status.errorMessage);
	}

	status = OPGP_select_application(cardContext, cardInfo, &sdSecurityInfo, (PBYTE)sdInstanceAID, sizeof(sdInstanceAID));
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Selecting DAP SD failed: %s", status.errorMessage);
	}

	memcpy(sdSecurityInfo.invokingAid, sdInstanceAID, sizeof(sdInstanceAID));
	sdSecurityInfo.invokingAidLength = sizeof(sdInstanceAID);
	status = GP211_mutual_authentication(cardContext, cardInfo, NULL,
			(PBYTE)OPGP_VISA_DEFAULT_KEY, (PBYTE)OPGP_VISA_DEFAULT_KEY, (PBYTE)OPGP_VISA_DEFAULT_KEY,
			16, 0, 0, 0, 0, GP211_SCP03_SECURITY_LEVEL_C_MAC, OPGP_DERIVATION_METHOD_NONE, &sdSecurityInfo);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Mutual authentication with new SD failed: %s", status.errorMessage);
	}

	status = GP211_put_secure_channel_keys(cardContext, cardInfo, &sdSecurityInfo, 0, 1, NULL,
			(PBYTE)sdPersonalizationKey, (PBYTE)sdPersonalizationKey, (PBYTE)sdPersonalizationKey,
			sizeof(sdPersonalizationKey), GP211_KEY_TYPE_AES);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_put_secure_channel_keys() failed: %s", status.errorMessage);
	}

	status = internal_select_and_authenticate_personalized_sd(&sdSecurityInfo);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not select/authenticate personalized DAP SD: %s", status.errorMessage);
	}

	status = internal_delete_key_set_with_secinfo(&sdSecurityInfo, GP211_KEY_VERSION_DAP_VERIFICATION, 1);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not pre-delete DAP verification key set: %s", status.errorMessage);
	}

	status = GP211_put_dap_keys(cardContext, cardInfo, &sdSecurityInfo,
			0, GP211_KEY_VERSION_DAP_VERIFICATION,
			TEST_ECC_PUBLIC_KEY, NULL, GP211_KEY_TYPE_ECC);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_put_dap_keys() failed: %s", status.errorMessage);
	}

	keyInfoLen = 20;
	status = GP211_get_key_information_templates(cardContext, cardInfo, &sdSecurityInfo, 0, keyInfo, &keyInfoLen);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_get_key_information_templates() failed: %s", status.errorMessage);
	}
	if (keyInfoLen == 0) {
		ck_abort_msg("No keys found in personalized DAP SD.");
	}
	{
		int found = 0;
		DWORD i;
		for (i = 0; i < keyInfoLen; i++) {
			if (keyInfo[i].keySetVersion == GP211_KEY_VERSION_DAP_VERIFICATION &&
					keyInfo[i].keyIndex == 1) {
				found = 1;
				break;
			}
		}
		if (!found) {
			ck_abort_msg("DAP verification key set not found after GP211_put_dap_keys().");
		}
	}

	dataLength = 10;
	status = GP211_get_status(cardContext, cardInfo, &sdSecurityInfo,
			GP211_STATUS_APPLICATIONS, GP211_STATUS_FORMAT_NEW,
			appData, modulesData, &dataLength);
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
			ck_abort_msg("DAP SD AID not found in application status after personalization.");
		}
		if (appData[i].lifeCycleState != GP211_LIFE_CYCLE_SECURITY_DOMAIN_PERSONALIZED) {
			ck_abort_msg("Incorrect DAP SD life cycle state: expected %d, got %d",
					GP211_LIFE_CYCLE_SECURITY_DOMAIN_PERSONALIZED, appData[i].lifeCycleState);
		}
	}

	status = internal_disconnect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not disconnect: %s", status.errorMessage);
	}
} END_TEST

/**
 * ECC DAP test step 3:
 * Calculate load file hash and ECC DAP for helloworld.cap.
 */
START_TEST (test_dap_calculate_helloworld_ecc_dap) {
	OPGP_ERROR_STATUS status;

	status = internal_read_dap_load_file_parameters();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("OPGP_read_executable_load_file_parameters() failed: %s", status.errorMessage);
	}

	dapLoadFileDataBlockHashLength = 32;
	memset(dapLoadFileDataBlockHash, 0, sizeof(dapLoadFileDataBlockHash));
	status = GP211_calculate_load_file_data_block_hash(TEST_LOAD_FILE,
			dapLoadFileDataBlockHash, dapLoadFileDataBlockHashLength, GP211_HASH_SHA256);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_calculate_load_file_data_block_hash() failed: %s", status.errorMessage);
	}

	memset(&dapLoadFileSignature, 0, sizeof(dapLoadFileSignature));
	status = GP211_calculate_ecc_DAP(dapLoadFileDataBlockHash, dapLoadFileDataBlockHashLength,
			(PBYTE)sdInstanceAID, sizeof(sdInstanceAID),
			TEST_ECC_PRIVATE_KEY, NULL, &dapLoadFileSignature);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_calculate_ecc_DAP() failed: %s", status.errorMessage);
	}
	if (dapLoadFileSignature.signatureLength == 0) {
		ck_abort_msg("ECC DAP calculation returned empty signature.");
	}
	dapLoadFileSignatureAvailable = 1;
} END_TEST

/**
 * ECC DAP test step 5:
 * Install helloworld.cap with ECC DAP.
 */
START_TEST (test_dm_install_helloworld_with_dap) {
	OPGP_ERROR_STATUS status;
	DWORD receiptDataLen = 0;
	GP211_RECEIPT_DATA receipt;
	DWORD receiptDataAvailable = 0;
	GP211_APPLICATION_DATA appData[20];
	GP211_EXECUTABLE_MODULES_DATA modulesData[20];
	DWORD dataLength = 20;

	if (!dapLoadFileParamsAvailable || !dapLoadFileSignatureAvailable || dapLoadFileDataBlockHashLength == 0) {
		ck_abort_msg("DAP preconditions missing. Run DAP hash and DAP calculation tests first.");
	}

	status = internal_connect_and_authenticate();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not connect and authenticate: %s", status.errorMessage);
	}

	status = internal_delete_selected(INTERNAL_DELETE_APPLET | INTERNAL_DELETE_PACKAGE, 1);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not pre-delete applet/package: %s", status.errorMessage);
	}

	status = GP211_install_for_load(cardContext, cardInfo, &securityInfo211,
			dapLoadFileParams.loadFileAID.AID, dapLoadFileParams.loadFileAID.AIDLength,
			(PBYTE)sdInstanceAID, sizeof(sdInstanceAID),
			dapLoadFileDataBlockHash, dapLoadFileDataBlockHashLength,
			NULL, 0,
			dapLoadFileParams.loadFileSize, 0, 0);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_install_for_load() failed: %s", status.errorMessage);
	}

	status = GP211_load(cardContext, cardInfo, &securityInfo211,
			&dapLoadFileSignature, 1, TEST_LOAD_FILE, NULL, &receiptDataLen, NULL);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_load() with DAP failed: %s", status.errorMessage);
	}

	status = GP211_install_for_install_and_make_selectable(cardContext, cardInfo, &securityInfo211,
			dapLoadFileParams.loadFileAID.AID, dapLoadFileParams.loadFileAID.AIDLength,
			dapLoadFileParams.appletAIDs[0].AID, dapLoadFileParams.appletAIDs[0].AIDLength,
			dapLoadFileParams.appletAIDs[0].AID, dapLoadFileParams.appletAIDs[0].AIDLength,
			0, 0, 0,
			NULL, 0,
			NULL, 0,
			NULL, 0,
			NULL, 0,
			NULL, 0,
			&receipt, &receiptDataAvailable);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_install_for_install_and_make_selectable() with DAP failed: %s", status.errorMessage);
	}

	status = GP211_get_status(cardContext, cardInfo, &securityInfo211,
			GP211_STATUS_APPLICATIONS, GP211_STATUS_FORMAT_NEW,
			appData, modulesData, &dataLength);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not get status from applications: %s", status.errorMessage);
	}

	{
		int found = 0;
		DWORD i;
		for (i = 0; i < dataLength; i++) {
			if (appData[i].aid.AIDLength == dapLoadFileParams.appletAIDs[0].AIDLength &&
					memcmp(appData[i].aid.AID, dapLoadFileParams.appletAIDs[0].AID,
							dapLoadFileParams.appletAIDs[0].AIDLength) == 0) {
				found = 1;
				break;
			}
		}
		if (!found) {
			ck_abort_msg("Installed DAP applet AID not found in status.");
		}
		if (appData[i].associatedSecurityDomainAID.AIDLength != sizeof(sdInstanceAID) ||
				memcmp(appData[i].associatedSecurityDomainAID.AID, sdInstanceAID, sizeof(sdInstanceAID)) != 0) {
			ck_abort_msg("Installed DAP applet is not associated with DAP SD.");
		}
	}

	status = internal_disconnect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not disconnect: %s", status.errorMessage);
	}
} END_TEST

/**
 * ECC DAP intermediate cleanup:
 * Delete loaded applet and package before deleting the SD.
 */
START_TEST (test_dap_delete_helloworld) {
	OPGP_ERROR_STATUS status;
	GP211_APPLICATION_DATA appData[20];
	GP211_EXECUTABLE_MODULES_DATA modulesData[20];
	DWORD dataLength = 20;

	if (!dapLoadFileParamsAvailable) {
		ck_abort_msg("DAP load file parameters are missing.");
	}

	status = internal_connect_and_authenticate();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not connect and authenticate: %s", status.errorMessage);
	}

	status = internal_delete_selected(INTERNAL_DELETE_APPLET | INTERNAL_DELETE_PACKAGE, 0);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not delete DAP applet/package: %s", status.errorMessage);
	}

	status = GP211_get_status(cardContext, cardInfo, &securityInfo211,
			GP211_STATUS_APPLICATIONS, GP211_STATUS_FORMAT_NEW,
			appData, modulesData, &dataLength);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not get status from applications: %s", status.errorMessage);
	}
	{
		DWORD i;
		for (i = 0; i < dataLength; i++) {
			if (appData[i].aid.AIDLength == dapLoadFileParams.appletAIDs[0].AIDLength &&
					memcmp(appData[i].aid.AID, dapLoadFileParams.appletAIDs[0].AID,
							dapLoadFileParams.appletAIDs[0].AIDLength) == 0) {
				ck_abort_msg("DAP applet AID still found in status after deletion.");
			}
		}
	}

	dataLength = 20;
	status = GP211_get_status(cardContext, cardInfo, &securityInfo211,
			GP211_STATUS_LOAD_FILES, GP211_STATUS_FORMAT_NEW,
			appData, modulesData, &dataLength);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not get status from load files: %s", status.errorMessage);
	}
	{
		DWORD i;
		for (i = 0; i < dataLength; i++) {
			if (appData[i].aid.AIDLength == dapLoadFileParams.loadFileAID.AIDLength &&
					memcmp(appData[i].aid.AID, dapLoadFileParams.loadFileAID.AID,
							dapLoadFileParams.loadFileAID.AIDLength) == 0) {
				ck_abort_msg("DAP load file AID still found in status after deletion.");
			}
		}
	}

	status = internal_disconnect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not disconnect: %s", status.errorMessage);
	}
} END_TEST

/**
 * ECC DAP test step 6:
 * Delete the DAP key set.
 */
START_TEST (test_dap_delete_key) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO sdSecurityInfo;
	GP211_KEY_INFORMATION keyInfo[20];
	DWORD keyInfoLen = 20;

	status = internal_connect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not connect: %s", status.errorMessage);
	}

	status = internal_select_and_authenticate_personalized_sd(&sdSecurityInfo);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not select/authenticate personalized DAP SD: %s", status.errorMessage);
	}

	status = internal_delete_key_set_with_secinfo(&sdSecurityInfo, GP211_KEY_VERSION_DAP_VERIFICATION, 0);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not delete DAP key set: %s", status.errorMessage);
	}

	status = GP211_get_key_information_templates(cardContext, cardInfo, &sdSecurityInfo, 0, keyInfo, &keyInfoLen);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_get_key_information_templates() failed: %s", status.errorMessage);
	}
	{
		DWORD i;
		for (i = 0; i < keyInfoLen; i++) {
			if (keyInfo[i].keySetVersion == GP211_KEY_VERSION_DAP_VERIFICATION &&
					keyInfo[i].keyIndex == 1) {
				ck_abort_msg("DAP verification key set still present after deletion.");
			}
		}
	}

	status = internal_disconnect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not disconnect: %s", status.errorMessage);
	}
} END_TEST

/**
 * ECC DAP test step 7:
 * Delete the DAP Security Domain.
 */
START_TEST (test_dap_delete_sd) {
	OPGP_ERROR_STATUS status;
	GP211_APPLICATION_DATA appData[20];
	GP211_EXECUTABLE_MODULES_DATA modulesData[20];
	DWORD dataLength = 20;

	status = internal_connect_and_authenticate();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not connect and authenticate: %s", status.errorMessage);
	}

	status = internal_delete_selected(INTERNAL_DELETE_SD, 0);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not delete DAP SD: %s", status.errorMessage);
	}

	status = GP211_get_status(cardContext, cardInfo, &securityInfo211,
			GP211_STATUS_APPLICATIONS, GP211_STATUS_FORMAT_NEW,
			appData, modulesData, &dataLength);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not get status from applications: %s", status.errorMessage);
	}
	{
		DWORD i;
		for (i = 0; i < dataLength; i++) {
			if (appData[i].aid.AIDLength == sizeof(sdInstanceAID) &&
					memcmp(appData[i].aid.AID, sdInstanceAID, sizeof(sdInstanceAID)) == 0) {
				ck_abort_msg("DAP SD AID still found in status after deletion.");
			}
		}
	}

	status = internal_disconnect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not disconnect: %s", status.errorMessage);
	}
} END_TEST

/**
 * Delegated management test step 4:
 * Calculate hash and load token for helloworld.cap.
 */
static void test_dm_calculate_load_token(OPGP_STRING privateKeyFile, char *privateKeyPassPhrase, const char *tokenKeyLabel) {
	OPGP_ERROR_STATUS status;

	status = internal_read_dm_load_file_parameters();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("OPGP_read_executable_load_file_parameters() failed: %s", status.errorMessage);
	}

	dmLoadFileDataBlockHashLength = 32;
	memset(dmLoadFileDataBlockHash, 0, sizeof(dmLoadFileDataBlockHash));
	status = GP211_calculate_load_file_data_block_hash(TEST_LOAD_FILE,
			dmLoadFileDataBlockHash, dmLoadFileDataBlockHashLength, GP211_HASH_SHA256);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_calculate_load_file_data_block_hash() failed: %s", status.errorMessage);
	}

	dmLoadTokenLength = sizeof(dmLoadToken);
	status = GP211_calculate_load_token(
			dmLoadFileParams.loadFileAID.AID, dmLoadFileParams.loadFileAID.AIDLength,
			(PBYTE)sdInstanceAID, sizeof(sdInstanceAID),
			dmLoadFileDataBlockHash, dmLoadFileDataBlockHashLength,
			dmLoadFileParams.loadFileSize, 0, 0,
			dmLoadToken, &dmLoadTokenLength,
			privateKeyFile, privateKeyPassPhrase);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_calculate_load_token() failed: %s", status.errorMessage);
	}
	if (dmLoadTokenLength == 0) {
		ck_abort_msg("Load token calculation returned empty token.");
	}
	dmLoadTokenKeyLabel = tokenKeyLabel;
}

START_TEST (test_dm_calculate_load_token_ecc) {
	test_dm_calculate_load_token(TEST_ECC_PRIVATE_KEY, NULL, "ECC");
} END_TEST

START_TEST (test_dm_calculate_load_token_rsa1024) {
	test_dm_calculate_load_token(TEST_RSA_1024_PRIVATE_KEY, NULL, "RSA1024");
} END_TEST

START_TEST (test_dm_calculate_load_token_rsa) {
	test_dm_calculate_load_token(TEST_RSA_PRIVATE_KEY, "password", "RSA2048");
} END_TEST

START_TEST (test_GP211_calculate_load_token_rsa1024_known_vector) {
	OPGP_ERROR_STATUS status;
	BYTE executableLoadFileAID[] = {0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0x01};
	BYTE securityDomainAID[] = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
	BYTE loadFileDataBlockHash[] = {
			0x9C, 0x8E, 0x7F, 0x3D, 0xA8, 0x9B, 0x91, 0x42,
			0x6B, 0x0F, 0x42, 0x93, 0xA2, 0x3D, 0xDB, 0x63,
			0x9C, 0xAB, 0xFF, 0x9F, 0x68, 0xBF, 0x8C, 0x3E,
			0x8E, 0xB8, 0xC9, 0xBB, 0x4F, 0x71, 0xF6, 0xA4
	};
	BYTE expectedLoadToken[] = {
			0x0A, 0xD0, 0x70, 0x1C, 0x8C, 0x9F, 0xA0, 0xAF,
			0xA1, 0x6E, 0x46, 0xA2, 0x04, 0x06, 0xE0, 0x62,
			0xED, 0xD1, 0xC9, 0xC1, 0xBA, 0xC2, 0x00, 0x98,
			0xDB, 0xAC, 0xA1, 0x5B, 0x81, 0xC6, 0x7B, 0x7A,
			0xB6, 0x30, 0x0C, 0x39, 0xD3, 0xF7, 0x51, 0xAC,
			0x42, 0xBC, 0x71, 0x9F, 0x61, 0x01, 0x09, 0x04,
			0xC2, 0x06, 0x6E, 0x52, 0x14, 0x46, 0xB1, 0x25,
			0x14, 0x55, 0x25, 0xF6, 0xE1, 0x93, 0x9B, 0xCE,
			0x38, 0x43, 0xA6, 0x5D, 0x03, 0x33, 0x28, 0xAC,
			0xB7, 0x41, 0xD8, 0xA6, 0xAB, 0x87, 0xE2, 0x58,
			0xD4, 0xF9, 0x9C, 0xCF, 0x3E, 0x11, 0xD8, 0xC8,
			0xFC, 0xE6, 0x53, 0x69, 0x69, 0xEA, 0x59, 0x8E,
			0x50, 0xB4, 0x25, 0xD2, 0x25, 0xA6, 0x19, 0xD4,
			0xD9, 0x4F, 0xE6, 0xA7, 0x4E, 0x36, 0x6D, 0x28,
			0x21, 0xCA, 0xAF, 0xE2, 0x88, 0x43, 0xCF, 0xB7,
			0x14, 0xB1, 0xFD, 0xB9, 0x71, 0xCC, 0x98, 0x5D
	};
	BYTE loadToken[512];
	DWORD loadTokenLength = sizeof(loadToken);

	status = GP211_calculate_load_token(
			executableLoadFileAID, sizeof(executableLoadFileAID),
			securityDomainAID, sizeof(securityDomainAID),
			loadFileDataBlockHash, sizeof(loadFileDataBlockHash),
			0, 0, 0,
			loadToken, &loadTokenLength,
			TEST_RSA_1024_PRIVATE_KEY, NULL);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_calculate_load_token() failed: %s", status.errorMessage);
	}
	if (loadTokenLength != sizeof(expectedLoadToken)) {
		ck_abort_msg("Unexpected load token length. expected=%lu actual=%lu",
				(unsigned long)sizeof(expectedLoadToken), (unsigned long)loadTokenLength);
	}
	if (memcmp(loadToken, expectedLoadToken, sizeof(expectedLoadToken)) != 0) {
		ck_abort_msg("Unexpected load token value.");
	}
} END_TEST

/**
 * Delegated management test step 5:
 * Calculate install token for helloworld.cap.
 */
static void test_dm_calculate_install_token(OPGP_STRING privateKeyFile, char *privateKeyPassPhrase, const char *tokenKeyLabel) {
	OPGP_ERROR_STATUS status;

	if (!dmLoadFileParamsAvailable) {
		status = internal_read_dm_load_file_parameters();
		if (OPGP_ERROR_CHECK(status)) {
			ck_abort_msg("OPGP_read_executable_load_file_parameters() failed: %s", status.errorMessage);
		}
	}

	dmInstallTokenLength = sizeof(dmInstallToken);
	status = GP211_calculate_install_token(
			0x0C,
			dmLoadFileParams.loadFileAID.AID, dmLoadFileParams.loadFileAID.AIDLength,
			dmLoadFileParams.appletAIDs[0].AID, dmLoadFileParams.appletAIDs[0].AIDLength,
			dmLoadFileParams.appletAIDs[0].AID, dmLoadFileParams.appletAIDs[0].AIDLength,
			0, 0, 0,
			NULL, 0,
			NULL, 0,
			NULL, 0,
			NULL, 0,
			dmInstallToken, &dmInstallTokenLength,
			privateKeyFile, privateKeyPassPhrase);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_calculate_install_token() failed: %s", status.errorMessage);
	}
	if (dmInstallTokenLength == 0) {
		ck_abort_msg("Install token calculation returned empty token.");
	}
	dmInstallTokenKeyLabel = tokenKeyLabel;
}

START_TEST (test_dm_calculate_install_token_ecc) {
	test_dm_calculate_install_token(TEST_ECC_PRIVATE_KEY, NULL, "ECC");
} END_TEST

START_TEST (test_dm_calculate_install_token_rsa1024) {
	test_dm_calculate_install_token(TEST_RSA_1024_PRIVATE_KEY, NULL, "RSA1024");
} END_TEST


START_TEST (test_dm_calculate_install_token_rsa) {
	test_dm_calculate_install_token(TEST_RSA_PRIVATE_KEY, "password", "RSA2048");
} END_TEST

/**
 * Delegated management test step 6:
 * Install helloworld.cap in delegated management SD using load and install tokens.
 */
static void test_dm_install_helloworld_with_tokens(const char *tokenKeyLabel) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO sdSecurityInfo;
	DWORD receiptDataLen = 0;
	GP211_RECEIPT_DATA receipt;
	DWORD receiptDataAvailable = 0;
	GP211_APPLICATION_DATA appData[20];
	GP211_EXECUTABLE_MODULES_DATA modulesData[20];
	DWORD dataLength = 20;

	if (!dmLoadFileParamsAvailable || dmLoadTokenLength == 0 || dmInstallTokenLength == 0 ||
			dmLoadFileDataBlockHashLength == 0 || dmLoadTokenKeyLabel == NULL ||
			dmInstallTokenKeyLabel == NULL ||
			strcmp(dmLoadTokenKeyLabel, tokenKeyLabel) != 0 ||
			strcmp(dmInstallTokenKeyLabel, tokenKeyLabel) != 0) {
		ck_abort_msg("Delegated management token preconditions missing for %s keys. Run matching token calculation tests first.",
				tokenKeyLabel);
	}

	status = internal_connect_and_authenticate();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not connect and authenticate: %s", status.errorMessage);
	}

	status = internal_delete_selected(INTERNAL_DELETE_APPLET | INTERNAL_DELETE_PACKAGE, 1);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not pre-delete applet/package: %s", status.errorMessage);
	}

	status = OPGP_select_application(cardContext, cardInfo, &sdSecurityInfo, (PBYTE)sdInstanceAID, sizeof(sdInstanceAID));
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Selecting delegated management SD failed: %s", status.errorMessage);
	}

	memcpy(sdSecurityInfo.invokingAid, sdInstanceAID, sizeof(sdInstanceAID));
	sdSecurityInfo.invokingAidLength = sizeof(sdInstanceAID);
	status = GP211_mutual_authentication(cardContext, cardInfo, NULL,
			(PBYTE)sdPersonalizationKey, (PBYTE)sdPersonalizationKey, (PBYTE)sdPersonalizationKey,
			sizeof(sdPersonalizationKey), 1, 0, 0, 0, GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC, OPGP_DERIVATION_METHOD_NONE, &sdSecurityInfo);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Mutual authentication with personalized delegated SD failed: %s", status.errorMessage);
	}

	status = GP211_install_for_load(cardContext, cardInfo, &sdSecurityInfo,
			dmLoadFileParams.loadFileAID.AID, dmLoadFileParams.loadFileAID.AIDLength,
			(PBYTE)sdInstanceAID, sizeof(sdInstanceAID),
			dmLoadFileDataBlockHash, dmLoadFileDataBlockHashLength,
			dmLoadToken, dmLoadTokenLength,
			dmLoadFileParams.loadFileSize, 0, 0);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_install_for_load() with delegated token failed: %s", status.errorMessage);
	}

	status = GP211_load(cardContext, cardInfo, &sdSecurityInfo,
			NULL, 0, TEST_LOAD_FILE, NULL, &receiptDataLen, NULL);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_load() failed: %s", status.errorMessage);
	}

	status = GP211_install_for_install_and_make_selectable(cardContext, cardInfo, &sdSecurityInfo,
			dmLoadFileParams.loadFileAID.AID, dmLoadFileParams.loadFileAID.AIDLength,
			dmLoadFileParams.appletAIDs[0].AID, dmLoadFileParams.appletAIDs[0].AIDLength,
			dmLoadFileParams.appletAIDs[0].AID, dmLoadFileParams.appletAIDs[0].AIDLength,
			0, 0, 0,
			NULL, 0,
			NULL, 0,
			NULL, 0,
			NULL, 0,
			dmInstallToken, dmInstallTokenLength,
			&receipt, &receiptDataAvailable);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("GP211_install_for_install_and_make_selectable() with delegated token failed: %s", status.errorMessage);
	}

	status = GP211_get_status(cardContext, cardInfo, &sdSecurityInfo,
			GP211_STATUS_APPLICATIONS, GP211_STATUS_FORMAT_NEW,
			appData, modulesData, &dataLength);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not get status from applications: %s", status.errorMessage);
	}

	{
		int found = 0;
		DWORD i;
		for (i = 0; i < dataLength; i++) {
			if (appData[i].aid.AIDLength == dmLoadFileParams.appletAIDs[0].AIDLength &&
					memcmp(appData[i].aid.AID, dmLoadFileParams.appletAIDs[0].AID,
							dmLoadFileParams.appletAIDs[0].AIDLength) == 0) {
				found = 1;
				break;
			}
		}
		if (!found) {
			ck_abort_msg("Installed delegated applet AID not found in status.");
		}
		if (appData[i].associatedSecurityDomainAID.AIDLength != sizeof(sdInstanceAID) ||
				memcmp(appData[i].associatedSecurityDomainAID.AID, sdInstanceAID, sizeof(sdInstanceAID)) != 0) {
			ck_abort_msg("Installed delegated applet is not associated with delegated management SD.");
		}
	}

	status = internal_disconnect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not disconnect: %s", status.errorMessage);
	}
}

START_TEST (test_dm_install_helloworld_with_tokens_ecc) {
	test_dm_install_helloworld_with_tokens("ECC");
} END_TEST

START_TEST (test_dm_install_helloworld_with_tokens_rsa1024) {
	test_dm_install_helloworld_with_tokens("RSA1024");
} END_TEST

START_TEST (test_dm_install_helloworld_with_tokens_rsa) {
	test_dm_install_helloworld_with_tokens("RSA2048");
} END_TEST

/**
 * Delegated management test step 7:
 * Delete the delegated applet and package.
 */
START_TEST (test_dm_delete_helloworld) {
	OPGP_ERROR_STATUS status;
	GP211_APPLICATION_DATA appData[20];
	GP211_EXECUTABLE_MODULES_DATA modulesData[20];
	DWORD dataLength = 20;
	const BYTE *loadFileAIDToCheck = packageAID;
	DWORD loadFileAIDToCheckLen = sizeof(packageAID);
	const BYTE *appletAIDToCheck = appletAID;
	DWORD appletAIDToCheckLen = sizeof(appletAID);

	if (dmLoadFileParamsAvailable) {
		loadFileAIDToCheck = dmLoadFileParams.loadFileAID.AID;
		loadFileAIDToCheckLen = dmLoadFileParams.loadFileAID.AIDLength;
		appletAIDToCheck = dmLoadFileParams.appletAIDs[0].AID;
		appletAIDToCheckLen = dmLoadFileParams.appletAIDs[0].AIDLength;
	}

	status = internal_connect_and_authenticate();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not connect and authenticate: %s", status.errorMessage);
	}

	status = internal_delete_selected(INTERNAL_DELETE_APPLET | INTERNAL_DELETE_PACKAGE, 0);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not delete delegated applet/package: %s", status.errorMessage);
	}

	status = GP211_get_status(cardContext, cardInfo, &securityInfo211,
			GP211_STATUS_APPLICATIONS, GP211_STATUS_FORMAT_NEW,
			appData, modulesData, &dataLength);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not get status from applications: %s", status.errorMessage);
	}
	{
		DWORD i;
		for (i = 0; i < dataLength; i++) {
			if (appData[i].aid.AIDLength == appletAIDToCheckLen &&
					memcmp(appData[i].aid.AID, appletAIDToCheck, appletAIDToCheckLen) == 0) {
				ck_abort_msg("Delegated applet AID still found in status after deletion.");
			}
		}
	}

	dataLength = 20;
	status = GP211_get_status(cardContext, cardInfo, &securityInfo211,
			GP211_STATUS_LOAD_FILES, GP211_STATUS_FORMAT_NEW,
			appData, modulesData, &dataLength);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not get status from load files: %s", status.errorMessage);
	}
	{
		DWORD i;
		for (i = 0; i < dataLength; i++) {
			if (appData[i].aid.AIDLength == loadFileAIDToCheckLen &&
					memcmp(appData[i].aid.AID, loadFileAIDToCheck, loadFileAIDToCheckLen) == 0) {
				ck_abort_msg("Delegated load file AID still found in status after deletion.");
			}
		}
	}

	status = internal_disconnect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not disconnect: %s", status.errorMessage);
	}
} END_TEST

/**
 * Delegated management test step 8:
 * Delete delegated management SD.
 */
START_TEST (test_dm_delete_sd) {
	OPGP_ERROR_STATUS status;
	GP211_APPLICATION_DATA appData[20];
	GP211_EXECUTABLE_MODULES_DATA modulesData[20];
	DWORD dataLength = 20;

	status = internal_connect_and_authenticate();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not connect and authenticate: %s", status.errorMessage);
	}

	status = internal_delete_selected(INTERNAL_DELETE_SD, 0);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not delete delegated management SD: %s", status.errorMessage);
	}

	status = GP211_get_status(cardContext, cardInfo, &securityInfo211,
			GP211_STATUS_APPLICATIONS, GP211_STATUS_FORMAT_NEW,
			appData, modulesData, &dataLength);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not get status from applications: %s", status.errorMessage);
	}
	{
		DWORD i;
		for (i = 0; i < dataLength; i++) {
			if (appData[i].aid.AIDLength == sizeof(sdInstanceAID) &&
					memcmp(appData[i].aid.AID, sdInstanceAID, sizeof(sdInstanceAID)) == 0) {
				ck_abort_msg("Delegated management SD AID still found in status after deletion.");
			}
		}
	}

	status = internal_disconnect();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not disconnect: %s", status.errorMessage);
	}
} END_TEST

/**
 * Delegated management test step 9:
 * Delete delegated management key sets.
 */
START_TEST (test_dm_delete_keys) {
	OPGP_ERROR_STATUS status;
	status = internal_connect_and_authenticate();
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not connect and authenticate: %s", status.errorMessage);
	}

	status = internal_delete_key_set(GP211_KEY_VERSION_TOKEN_VERIFICATION, 0);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not delete delegated token key set: %s", status.errorMessage);
	}

	status = internal_delete_key_set(GP211_KEY_VERSION_RECEIPT_GENERATION, 0);
	if (OPGP_ERROR_CHECK(status)) {
		ck_abort_msg("Could not delete delegated receipt key set: %s", status.errorMessage);
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
	// tcase_add_test (tc_core, test_list_readers);
	// tcase_add_test (tc_core, test_connect_card);
	// tcase_add_test (tc_core, test_GP211_VISA2_derive_keys);
	// tcase_add_test (tc_core, test_mutual_authentication);
	// tcase_add_test (tc_core, test_install);
 //    tcase_add_test (tc_core, test_get_status);
 //    tcase_add_test (tc_core, test_delete);
 //    tcase_add_test (tc_core, test_install_callback);
	// tcase_add_test (tc_core, test_delete);
 //    tcase_add_test (tc_core, test_put_aes_key);
 //    tcase_add_test (tc_core, test_delete_key);
	// tcase_add_test (tc_core, test_create_sd);
	// tcase_add_test (tc_core, test_personalize_sd);
	// tcase_add_test (tc_core, test_move_sd);
	// tcase_add_test (tc_core, test_delete_sd);
 //
	// // RSA 1024
	// tcase_add_test (tc_core, test_GP211_calculate_load_token_rsa1024_known_vector);
	// tcase_add_test (tc_core, test_dm_put_token_key_rsa1024);
	// tcase_add_test (tc_core, test_dm_put_receipt_key_aes256);
	// tcase_add_test (tc_core, test_dm_install_sd_with_delegated_management);
	// tcase_add_test (tc_core, test_personalize_sd);
	// tcase_add_test (tc_core, test_dm_calculate_load_token_rsa1024);
	// tcase_add_test (tc_core, test_dm_calculate_install_token_rsa1024);
	// tcase_add_test (tc_core, test_dm_install_helloworld_with_tokens_rsa1024);
	// tcase_add_test (tc_core, test_dm_delete_helloworld);
	// tcase_add_test (tc_core, test_dm_delete_sd);
	// tcase_add_test (tc_core, test_dm_delete_keys);
 //
	// // RSA 2048
	// tcase_add_test (tc_core, test_dm_put_token_key_rsa);
	// tcase_add_test (tc_core, test_dm_put_receipt_key_aes256);
	// tcase_add_test (tc_core, test_dm_install_sd_with_delegated_management);
	// tcase_add_test (tc_core, test_personalize_sd);
	// tcase_add_test (tc_core, test_dm_calculate_load_token_rsa);
	// tcase_add_test (tc_core, test_dm_calculate_install_token_rsa);
	// tcase_add_test (tc_core, test_dm_install_helloworld_with_tokens_rsa);
	// tcase_add_test (tc_core, test_dm_delete_helloworld);
	// tcase_add_test (tc_core, test_dm_delete_sd);
	// tcase_add_test (tc_core, test_dm_delete_keys);
 //
	// // ECC 256
	// tcase_add_test (tc_core, test_dm_put_token_key_ecc);
	// tcase_add_test (tc_core, test_dm_put_receipt_key_aes256);
	// tcase_add_test (tc_core, test_dm_install_sd_with_delegated_management);
	// tcase_add_test (tc_core, test_personalize_sd);
	// tcase_add_test (tc_core, test_dm_calculate_load_token_ecc);
	// tcase_add_test (tc_core, test_dm_calculate_install_token_ecc);
	// tcase_add_test (tc_core, test_dm_install_helloworld_with_tokens_ecc);
	// tcase_add_test (tc_core, test_dm_delete_helloworld);
	// tcase_add_test (tc_core, test_dm_delete_sd);
	// tcase_add_test (tc_core, test_dm_delete_keys);

	// ECC DAP verification
	tcase_add_test (tc_core, test_dap_install_sd_with_mandated_dap);
	tcase_add_test (tc_core, test_dap_personalize_sd);
	tcase_add_test (tc_core, test_dap_calculate_helloworld_ecc_dap);
	tcase_add_test (tc_core, test_dm_install_helloworld_with_dap);
	tcase_add_test (tc_core, test_dap_delete_key);
	tcase_add_test (tc_core, test_dap_delete_helloworld);
	tcase_add_test (tc_core, test_dap_delete_sd);

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
