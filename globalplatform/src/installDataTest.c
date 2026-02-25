/*  Copyright (c) 2026, Karsten Ohme
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

static void build_uicc_system_specific_params_toolkit(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE expected[64];
	DWORD expectedLength = sizeof(expected);
	BYTE output[64];
	DWORD outputLength = sizeof(output);
	GP211_UICC_SYSTEM_SPECIFIC_PARAMS params;

	hex_to_byte_array("800d010014000202011e03d501030081180001000010A0000000871002FFFFFFFF8900000100010000",
		expected, &expectedLength);

	memset(&params, 0, sizeof(params));
	params.toolkitParamsPresent = 1;
	params.toolkitParams.priority = 0x01;
	params.toolkitParams.maxTimers = 0x00;
	params.toolkitParams.maxTextLength = 0x14;
	params.toolkitParams.maxMenuEntries = 0x00;
	params.toolkitParams.maxChannels = 0x02;
	params.toolkitParams.mslData = 0x1E;
	params.toolkitParams.tarValuesLength = 0x03;
	params.toolkitParams.tarValues[0] = 0xD5;
	params.toolkitParams.tarValues[1] = 0x01;
	params.toolkitParams.tarValues[2] = 0x03;
	params.toolkitParams.maxServices = 0x00;

	params.accessParamsPresent = 1;
	params.accessParams.rulesLength = 2;
	params.accessParams.rules[0].aidLength = 0x00;
	params.accessParams.rules[0].accessDomainParameter = GP211_UICC_ACCESS_DOMAIN_FULL_ACCESS;
	params.accessParams.rules[0].accessDomainDapLength = 0x00;

	params.accessParams.rules[1].aidLength = 0x10;
	{
		const BYTE aid[16] = {0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0xFF,
			0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00};
		memcpy(params.accessParams.rules[1].aid, aid, sizeof(aid));
	}
	params.accessParams.rules[1].accessDomainParameter = GP211_UICC_ACCESS_DOMAIN_FULL_ACCESS;
	params.accessParams.rules[1].accessDomainDapLength = 0x00;

	status = GP211_build_uicc_system_specific_params(&params, output, &outputLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(outputLength, expectedLength);
	assert_memory_equal(output, expected, expectedLength);
}

static void build_sim_specific_params(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE expected[32];
	DWORD expectedLength = sizeof(expected);
	BYTE output[32];
	DWORD outputLength = sizeof(output);
	GP211_SIM_SPECIFIC_PARAMS params;

	hex_to_byte_array("010001011000010003D50101", expected, &expectedLength);

	memset(&params, 0, sizeof(params));
	params.accessDomainParameter = GP211_UICC_ACCESS_DOMAIN_FULL_ACCESS;

	params.toolkitParams.priority = 0x01;
	params.toolkitParams.maxTimers = 0x01;
	params.toolkitParams.maxTextLength = 0x10;
	params.toolkitParams.maxMenuEntries = 0x00;
	params.toolkitParams.maxChannels = 0x01;
	params.toolkitParams.tarValuesLength = 0x03;
	params.toolkitParams.tarValues[0] = 0xD5;
	params.toolkitParams.tarValues[1] = 0x01;
	params.toolkitParams.tarValues[2] = 0x01;

	status = GP211_build_sim_specific_params(&params, output, &outputLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(outputLength, expectedLength);
	assert_memory_equal(output, expected, expectedLength);
}

static void build_sd_parameters(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE expected[64];
	DWORD expectedLength = sizeof(expected);
	BYTE output[64];
	DWORD outputLength = sizeof(output);
	GP211_SD_INSTALL_PARAMS params;

	hex_to_byte_array("C1148102021582018083018084008602010287028000",
		expected, &expectedLength);

	memset(&params, 0, sizeof(params));
	params.scpEntriesLength = 1;
	params.scpEntries[0].scpIdentifier = 0x02;
	params.scpEntries[0].scpImpl = 0x15;
	params.acceptExtractionLength = 1;
	params.acceptExtraction[0] = 0x80;
	params.acceptDeletionLength = 1;
	params.acceptDeletion = 0x80;
	params.personalizedStatePresent = 1;
	params.casdCapabilityInfo[0] = 0x01;
	params.casdCapabilityInfo[1] = 0x02;
	params.acceptGlobalDeleteLength = 2;
	params.acceptGlobalDelete[0] = 0x80;
	params.acceptGlobalDelete[1] = 0x00;

	status = GP211_build_sd_parameters(&params, output, &outputLength);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(outputLength, expectedLength);
	assert_memory_equal(output, expected, expectedLength);
}

int main(void) {
	const struct CMUnitTest tests[] = {
			cmocka_unit_test(build_uicc_system_specific_params_toolkit),
			cmocka_unit_test(build_sim_specific_params),
			cmocka_unit_test(build_sd_parameters),
	};
	return cmocka_run_group_tests_name("installData", tests, NULL, NULL);
}
