/*  Copyright (c) 2023, Karsten Ohme
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
#include <stdio.h>
#include <string.h>
#include <cmocka.h>
#include "globalplatform/globalplatform.h"
#include "testUtil.h"

TCHAR *exec_path;

#ifndef WIN32
#define _tcsrchr strrchr
#endif

OPGP_ERROR_STATUS parse_application_data(PBYTE data, DWORD dataLength,
		BYTE cardElement, BYTE format, GP211_APPLICATION_DATA *applData, PDWORD dataRead);

static void app_status(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE status1[] = {0xE3, 0x3A, 0x4F, 0x10, 0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x02, 0x00, 
	0x9F, 0x70, 0x01, 0x0F, 
	0xC5, 0x03, 0x82, 0xFC, 0x80, 
	0xC4, 0x0B, 0xD2, 0x76, 0x00, 0x00, 0x05, 0xAA, 0xFF, 0xCA, 0xFE, 0x00, 0x01, 
	0xCC, 0x10, 0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x02, 0x00,
	// only first app is parsed
	0xE3, 0x30, 0x4F, 0x08, 0xD2, 0x76, 0x00, 0x00, 0x05, 0xAA, 0x3F, 0x01, 0x9F, 0x70, 0x01, 0x07, 0xC5, 0x01, 0x04, 0xC4, 0x0B, 0xD2, 0x76, 0x00, 0x00, 0x05, 0xAA, 0xFF, 0xCA, 0xFE, 0x00, 0x02, 0xCC, 0x10, 0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x02, 0x00, 0xE3, 0x38, 0x4F, 0x10, 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x01, 0xF3, 0x10, 0xFF, 0xFF, 0x89, 0xFF, 0xFF, 0xFF, 0x01, 0x9F, 0x70, 0x01, 0x07, 0xC5, 0x01, 0x00, 0xC4, 0x0B, 0xD2, 0x76, 0x00, 0x00, 0x05, 0xAA, 0xFF, 0xCA, 0xFE, 0x00, 0x02, 0xCC, 0x10, 0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x02, 0x00, 0xE3, 0x44, 0x4F, 0x10, 0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00, 0x9F, 0x70, 0x01, 0x07, 0xC5, 0x01, 0x00, 0xC4, 0x10, 0xD2, 0x76, 0x00, 0x01, 0x18, 0x01, 0x00, 0xFF, 0x49, 0x10, 0x25, 0x89, 0xC0, 0x02, 0x80, 0x00, 0xCC, 0x10, 0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x02, 0x00, 0xEA, 0x05, 0x80, 0x03, 0x01, 0x80, 0x00, 0xE3, 0x30, 0x4F, 0x09, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x41, 0x43, 0x4C, 0x00, 0x9F, 0x70, 0x01, 0x07, 0x63, 0x10};

	BYTE expected_aid[] = {0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x02, 0x00};
	GP211_APPLICATION_DATA applData;
	DWORD dataRead;

	status = parse_application_data(status1, sizeof(status1), GP211_STATUS_APPLICATIONS, GP211_STATUS_FORMAT_NEW, &applData, &dataRead);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(applData.lifeCycleState, GP211_LIFE_CYCLE_CARD_SECURED);
	assert_int_equal(applData.privileges, GP211_SECURITY_DOMAIN | GP211_PIN_CHANGE_PRIVILEGE | GP211_TRUSTED_PATH | GP211_AUTHORIZED_MANAGEMENT | 
	GP211_TOKEN_VERIFICATION | GP211_GLOBAL_DELETE | GP211_GLOBAL_LOCK | GP211_GLOBAL_REGISTRY | GP211_RECEIPT_GENERATION);
	assert_memory_equal(applData.aid.AID, expected_aid, 16);
	assert_memory_equal(applData.associatedSecurityDomainAID.AID, expected_aid, 16);

}

static int setup(void **state) {
	return 0;
}

int main(int argc, TCHAR *argv[]) {
	TCHAR *end_path;
	exec_path = argv[0];
	end_path = _tcsrchr(exec_path, _T('/'));
	exec_path[_tcslen(exec_path) - _tcslen(end_path)] = _T('\0');
	const struct CMUnitTest tests[] = {
			cmocka_unit_test(app_status),
	};
	return cmocka_run_group_tests_name("status", tests, setup, NULL);
}
