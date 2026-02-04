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
#include <stdlib.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>
#include "globalplatform/globalplatform.h"
#include "testUtil.h"

static void assert_cplc_fields(const OPGP_CPLC *cplc, const OPGP_CPLC *expected) {
	assert_int_equal(cplc->icFabricator, expected->icFabricator);
	assert_int_equal(cplc->icType, expected->icType);
	assert_int_equal(cplc->operatingSystemId, expected->operatingSystemId);
	assert_int_equal(cplc->operatingSystemReleaseDate, expected->operatingSystemReleaseDate);
	assert_int_equal(cplc->operatingSystemReleaseLevel, expected->operatingSystemReleaseLevel);
	assert_int_equal(cplc->icFabricationDate, expected->icFabricationDate);
	assert_int_equal(cplc->icSerialNumberHigh, expected->icSerialNumberHigh);
	assert_int_equal(cplc->icSerialNumberLow, expected->icSerialNumberLow);
	assert_int_equal(cplc->icBatchIdentifier, expected->icBatchIdentifier);
	assert_int_equal(cplc->icModuleFabricator, expected->icModuleFabricator);
	assert_int_equal(cplc->icModulePackagingDate, expected->icModulePackagingDate);
	assert_int_equal(cplc->iccManufacturer, expected->iccManufacturer);
	assert_int_equal(cplc->icEmbeddingDate, expected->icEmbeddingDate);
	assert_int_equal(cplc->icPrePersonalizer, expected->icPrePersonalizer);
	assert_int_equal(cplc->icPrePersonalizationEquipmentDate, expected->icPrePersonalizationEquipmentDate);
	assert_int_equal(cplc->icPrePersonalizationEquipmentId, expected->icPrePersonalizationEquipmentId);
	assert_int_equal(cplc->icPersonalizer, expected->icPersonalizer);
	assert_int_equal(cplc->icPersonalizationDate, expected->icPersonalizationDate);
	assert_int_equal(cplc->icPersonalizationEquipmentId, expected->icPersonalizationEquipmentId);
}

static void test_parse_cplc_vector_1(void **state) {
	OPGP_ERROR_STATUS status;
	OPGP_CPLC cplc;
	BYTE buffer[128];
	DWORD bufferLength = sizeof(buffer);
	const OPGP_CPLC expected = {
		.icFabricator = 0x4790,
		.icType = 0xD600,
		.operatingSystemId = 0x4700,
		.operatingSystemReleaseDate = 0x0000,
		.operatingSystemReleaseLevel = 0x0000,
		.icFabricationDate = 0x3244,
		.icSerialNumberHigh = 0x3429,
		.icSerialNumberLow = 0x5220,
		.icBatchIdentifier = 0x8448,
		.icModuleFabricator = 0x0000,
		.icModulePackagingDate = 0x0000,
		.iccManufacturer = 0x0000,
		.icEmbeddingDate = 0x0000,
		.icPrePersonalizer = 0x1527,
		.icPrePersonalizationEquipmentDate = 0x8234,
		.icPrePersonalizationEquipmentId = 0x32393532,
		.icPersonalizer = 0x0000,
		.icPersonalizationDate = 0x0000,
		.icPersonalizationEquipmentId = 0x00000000
	};

	hex_to_byte_array("9F7F2A4790D6004700000000003244342952208448000000000000000015278234323935320000000000000000",
		buffer, &bufferLength);
	status = OPGP_parse_cplc(buffer, bufferLength, &cplc);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_cplc_fields(&cplc, &expected);
}

static void test_parse_cplc_vector_2(void **state) {
	OPGP_ERROR_STATUS status;
	OPGP_CPLC cplc;
	BYTE buffer[128];
	DWORD bufferLength = sizeof(buffer);
	const OPGP_CPLC expected = {
		.icFabricator = 0x4090,
		.icType = 0x1915,
		.operatingSystemId = 0x4090,
		.operatingSystemReleaseDate = 0x0045,
		.operatingSystemReleaseLevel = 0x0100,
		.icFabricationDate = 0x8301,
		.icSerialNumberHigh = 0xA818,
		.icSerialNumberLow = 0x6827,
		.icBatchIdentifier = 0xA822,
		.icModuleFabricator = 0x0000,
		.icModulePackagingDate = 0x0000,
		.iccManufacturer = 0x0000,
		.icEmbeddingDate = 0x0000,
		.icPrePersonalizer = 0x0000,
		.icPrePersonalizationEquipmentDate = 0x0000,
		.icPrePersonalizationEquipmentId = 0x00000000,
		.icPersonalizer = 0x0000,
		.icPersonalizationDate = 0x0000,
		.icPersonalizationEquipmentId = 0x00000000
	};

	hex_to_byte_array("9F7F2A409019154090004501008301A8186827A822000000000000000000000000000000000000000000000000",
		buffer, &bufferLength);
	status = OPGP_parse_cplc(buffer, bufferLength, &cplc);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_cplc_fields(&cplc, &expected);
}

static void test_parse_cplc_vector_3(void **state) {
	OPGP_ERROR_STATUS status;
	OPGP_CPLC cplc;
	BYTE buffer[128];
	DWORD bufferLength = sizeof(buffer);
	const OPGP_CPLC expected = {
		.icFabricator = 0x4750,
		.icType = 0x0061,
		.operatingSystemId = 0x0000,
		.operatingSystemReleaseDate = 0x8303,
		.operatingSystemReleaseLevel = 0x0080,
		.icFabricationDate = 0x00E6,
		.icSerialNumberHigh = 0x92E0,
		.icSerialNumberLow = 0x82BE,
		.icBatchIdentifier = 0x675C,
		.icModuleFabricator = 0x7287,
		.icModulePackagingDate = 0x7301,
		.iccManufacturer = 0xFFFF,
		.icEmbeddingDate = 0xFFFF,
		.icPrePersonalizer = 0xFFFF,
		.icPrePersonalizationEquipmentDate = 0xFFFF,
		.icPrePersonalizationEquipmentId = 0xFFFFFFFF,
		.icPersonalizer = 0xFFFF,
		.icPersonalizationDate = 0xFFFF,
		.icPersonalizationEquipmentId = 0xFFFFFFFF
	};

	hex_to_byte_array("9F7F2A4750006100008303008000E692E082BE675C72877301FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		buffer, &bufferLength);
	status = OPGP_parse_cplc(buffer, bufferLength, &cplc);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_cplc_fields(&cplc, &expected);
}

static void test_parse_extended_card_resources(void **state) {
	OPGP_ERROR_STATUS status;
	OPGP_EXTENDED_CARD_RESOURCE_INFORMATION info;
	BYTE buffer[64];
	DWORD bufferLength = sizeof(buffer);

	hex_to_byte_array("FF211081020002820400016DB483040000086A", buffer, &bufferLength);
	status = OPGP_parse_extended_card_resources_information(buffer, bufferLength, &info);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(info.numInstalledApplications, 0x0002);
	assert_int_equal(info.freeNonVolatileMemory, 0x00016DB4);
	assert_int_equal(info.freeVolatileMemory, 0x0000086A);
}

static void test_parse_card_recognition_vector_1(void **state) {
	OPGP_ERROR_STATUS status;
	GP211_CARD_RECOGNITION_DATA data;
	BYTE buffer[128];
	DWORD bufferLength = sizeof(buffer);

	hex_to_byte_array("664D734B06072A864886FC6B01600B06092A864886FC6B020203630906072A864886FC6B03640B06092A864886FC6B040370650D060B2A864886FC6B0507020000660C060A2B060104012A026E0103",
		buffer, &bufferLength);
	status = GP211_parse_card_recognition_data(buffer, bufferLength, &data);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_string_equal(data.version, "2.2.3");
	assert_int_equal(data.scpLength, 1);
	assert_int_equal(data.scp[0], 0x03);
	assert_int_equal(data.scpImpl[0], 0x70);
	assert_string_equal(data.cardConfigurationDetailsOid, "1.2.840.114283.5.7.2.0.0");
	assert_string_equal(data.cardChipDetailsOid, "1.3.6.1.4.1.42.2.110.1.3");
}

static void test_parse_card_recognition_vector_2(void **state) {
	OPGP_ERROR_STATUS status;
	GP211_CARD_RECOGNITION_DATA data;
	BYTE buffer[128];
	DWORD bufferLength = sizeof(buffer);

	hex_to_byte_array("664D734B06072A864886FC6B01600B06092A864886FC6B020203630906072A864886FC6B03640B06092A864886FC6B040255650D060B2A864886FC6B0507020000660C060A2B060104012A026E0103",
		buffer, &bufferLength);
	status = GP211_parse_card_recognition_data(buffer, bufferLength, &data);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_string_equal(data.version, "2.2.3");
	assert_int_equal(data.scpLength, 1);
	assert_int_equal(data.scp[0], 0x02);
	assert_int_equal(data.scpImpl[0], 0x55);
	assert_string_equal(data.cardConfigurationDetailsOid, "1.2.840.114283.5.7.2.0.0");
	assert_string_equal(data.cardChipDetailsOid, "1.3.6.1.4.1.42.2.110.1.3");
}

static void test_parse_card_capability_vector_1(void **state) {
	OPGP_ERROR_STATUS status;
	GP211_CARD_CAPABILITY_INFORMATION info;
	BYTE buffer[128];
	DWORD bufferLength = sizeof(buffer);
	const BYTE expected_scp_options[] = {0x15, 0x35, 0x55, 0x75};
	const BYTE expected_ssd_priv[] = {0xE5, 0xBE, 0xC0};
	const BYTE expected_app_priv[] = {0x1E, 0x03, 0x00};

	hex_to_byte_array("6724A0098001028104153555758103E5BEC082031E030083010284010285017B86010C87017B",
		buffer, &bufferLength);
	status = GP211_parse_card_capability_information(buffer, bufferLength, &info);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);
	assert_int_equal(info.scpInformationLength, 1);
	assert_int_equal(info.scpInformation[0].scpIdentifier, 0x02);
	assert_int_equal(info.scpInformation[0].scpOptionsLength, sizeof(expected_scp_options));
	assert_memory_equal(info.scpInformation[0].scpOptions, expected_scp_options, sizeof(expected_scp_options));
	assert_memory_equal(info.ssdPrivileges, expected_ssd_priv, sizeof(expected_ssd_priv));
	assert_memory_equal(info.appPrivileges, expected_app_priv, sizeof(expected_app_priv));
	assert_int_equal(info.lfdbhAlgorithmsLength, 1);
	assert_int_equal(info.lfdbhAlgorithms[0], 0x02);
	assert_int_equal(info.lfdbencryptionCipherSuites, 0x02);
	assert_int_equal(info.tokenCipherSuites, 0x7B00);
	assert_int_equal(info.receiptCipherSuites, 0x0C00);
	assert_int_equal(info.dapCipherSuites, 0x7B00);
}

static void test_parse_card_capability_vector_2_invalid(void **state) {
	OPGP_ERROR_STATUS status;
	GP211_CARD_CAPABILITY_INFORMATION info;
	BYTE buffer[256];
	DWORD bufferLength = sizeof(buffer);

	hex_to_byte_array("6658735606072A864886FC6B01600B06092A864886FC6B020202630906072A864886FC6B03640B06092A864886FC6B048000640B06092A864886FC6B040370650B06092A864886FC6B020101660C060A2B060104012A026E0102",
		buffer, &bufferLength);
	status = GP211_parse_card_capability_information(buffer, bufferLength, &info);
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_FAILURE);
	assert_int_equal(status.errorCode, OPGP_ERROR_INVALID_RESPONSE_DATA);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_parse_cplc_vector_1),
		cmocka_unit_test(test_parse_cplc_vector_2),
		cmocka_unit_test(test_parse_cplc_vector_3),
		cmocka_unit_test(test_parse_extended_card_resources),
		cmocka_unit_test(test_parse_card_recognition_vector_1),
		cmocka_unit_test(test_parse_card_recognition_vector_2),
		cmocka_unit_test(test_parse_card_capability_vector_1),
		cmocka_unit_test(test_parse_card_capability_vector_2_invalid),
	};

	return cmocka_run_group_tests_name("getData", tests, NULL, NULL);
}
