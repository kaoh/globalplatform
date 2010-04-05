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
#include <globalplatform/globalplatform.h>
#include <globalplatform/connectionplugin.h>
#include "gppcscconnectionplugin.h"
#include <string.h>

/**
 * Maximum length of the reader name.
 */
#define READERNAMELEN 256

/**
 * Reader number to connect to.
 */
#define READERNUM 1

/**
 * Maximum buffer size for reader names.
 */
#define BUFLEN 2048

static void internal_release_context(OPGP_CARD_CONTEXT *cardContext) {
	OPGP_ERROR_STATUS status;
	status = OPGP_PL_release_context(cardContext);
	if (OPGP_ERROR_CHECK(status)) {
		fail("Could not release context: %s", status.errorMessage);
	}
}

static void internal_card_disconnect(OPGP_CARD_CONTEXT cardContext,
		OPGP_CARD_INFO cardInfo) {
	OPGP_ERROR_STATUS status;
	status = OPGP_PL_card_disconnect(cardContext, &cardInfo);
	if (OPGP_ERROR_CHECK(status)) {
		fail("Could not disconnect from card: %s", status.errorMessage);
	}
	//_tprintf(_T("Disconnected from reader %s\n"), readerName);
}

static void internal_card_connect(OPGP_CARD_CONTEXT cardContext,
		OPGP_CARD_INFO *cardInfo, OPGP_STRING readerName) {
	OPGP_ERROR_STATUS status;
	status = OPGP_PL_card_connect(cardContext, readerName, cardInfo,
			(OPGP_CARD_PROTOCOL_T0 | OPGP_CARD_PROTOCOL_T1));
	if (OPGP_ERROR_CHECK(status)) {
		fail("Could not connect to card: %s", OPGP_PL_stringify_error(status.errorCode));
	}
	_tprintf(_T("Connected to reader %s\n"), readerName);
}

static void internal_establish_context(OPGP_CARD_CONTEXT *cardContext) {
	OPGP_ERROR_STATUS status;
	status = OPGP_PL_establish_context(cardContext);
	if (OPGP_ERROR_CHECK(status)) {
		fail("Could not establish context: %s", OPGP_PL_stringify_error(status.errorCode));
	}
	_tprintf(
			_T("Using card context %08X\n"),
			(unsigned int) ((PCSC_CARD_CONTEXT_SPECIFIC *) cardContext->librarySpecific)->cardContext);
}

static OPGP_STRING internal_list_readers(OPGP_CARD_CONTEXT cardContext,
		OPGP_CARD_INFO cardInfo) {
	OPGP_ERROR_STATUS status;
	TCHAR buf[BUFLEN + 1];
	int j, k;
	static TCHAR readerName[READERNAMELEN + 1];
	DWORD readerStrLen = BUFLEN;
	status = OPGP_PL_list_readers(cardContext, buf, &readerStrLen);
	if (OPGP_ERROR_CHECK(status)) {
		fail("Could not list readers: %s", OPGP_PL_stringify_error(status.errorCode));
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
		fail("No reader found.");
	}
	_tprintf(_T("Using reader %s\n"), readerName);
	return readerName;
}

/**
 * Tests the connection to the card.
 */
START_TEST(test_card_connect)
	{
		OPGP_CARD_CONTEXT cardContext;
		OPGP_CARD_INFO cardInfo;
		OPGP_STRING readerName;
		internal_establish_context(&cardContext);
		readerName = internal_list_readers(cardContext, cardInfo);
		internal_card_connect(cardContext, &cardInfo, readerName);
		internal_card_disconnect(cardContext, cardInfo);
		internal_release_context(&cardContext);
	}END_TEST

/**
 * Tests the listing of readers.
 */
START_TEST (test_list_readers)
	{
		OPGP_CARD_CONTEXT cardContext;
		OPGP_CARD_INFO cardInfo;
		internal_establish_context(&cardContext);
		internal_list_readers(cardContext, cardInfo);
		internal_release_context(&cardContext);
	}END_TEST

/**
 * Tests the context establishment.
 */
START_TEST (test_establish_context)
	{
		OPGP_CARD_CONTEXT cardContext;
		OPGP_CARD_INFO cardInfo;
		internal_establish_context(&cardContext);
		internal_release_context(&cardContext);
	}END_TEST

/**
 * Tests the context establishment.
 */
START_TEST (test_send_APDU)
	{
		OPGP_CARD_CONTEXT cardContext;
		OPGP_CARD_INFO cardInfo;
		OPGP_STRING readerName;
		OPGP_ERROR_STATUS status;
		BYTE sendBuffer[5];
		DWORD sendBufferLength = 5;
		BYTE cardData[256];
		DWORD cardDataLength = 256;
		int i = 0;
		sendBuffer[i++] = 0x80;
		sendBuffer[i++] = 0xCA;
		sendBuffer[i++] = 0;
		sendBuffer[i++] = 0x66;
		sendBuffer[i] = 0x00;

		internal_establish_context(&cardContext);
		readerName = internal_list_readers(cardContext, cardInfo);
		internal_card_connect(cardContext, &cardInfo, readerName);
		status = OPGP_PL_send_APDU(cardContext, cardInfo, sendBuffer,
				sendBufferLength, cardData, &cardDataLength);
		if (OPGP_ERROR_CHECK(status)) {
			fail("Could not send APDU: %s", OPGP_PL_stringify_error(status.errorCode));
		}
		fail_unless(cardDataLength == 2 + 0x4C + 2, "Invalid data length.");
		fail_unless(cardData[0] == 0x66, "Invalid data returned.");

		internal_card_disconnect(cardContext, cardInfo);
		internal_release_context(&cardContext);
	}END_TEST

Suite * pcscconnectionplugin_suite(void) {
	Suite *s = suite_create("pcscconnectionplugin");
	/* Core test case */
	TCase *tc_core = tcase_create("Core");
	tcase_add_test (tc_core, test_establish_context);
	tcase_add_test (tc_core, test_list_readers);
	tcase_add_test (tc_core, test_card_connect);
	tcase_add_test (tc_core, test_send_APDU);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {
	int number_failed;
	Suite *s = pcscconnectionplugin_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
