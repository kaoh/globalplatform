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
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU Lesser General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.
 */
#include <stdlib.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>
#include "globalplatform/globalplatform.h"
#include "testUtil.h"

/**
 * Test encoding of STORE DATA for symmetric keys with 3 AES-128 keys (S-ENC, S-MAC, DEK)
 * for SCP03 with key version 0x01 and SD-only access.
 */
static void test_build_store_data_keys_scp03_aes128(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE output[1024];
	DWORD outputLength = sizeof(output);

	// Test keys (16 bytes each for AES-128)
	BYTE key_s_enc[16] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	                      0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F};
	BYTE key_s_mac[16] = {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
	                      0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F};
	BYTE key_dek[16] = {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	                    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F};

	PBYTE keys[3] = {key_s_enc, key_s_mac, key_dek};
	BYTE keyIds[3] = {0x01, 0x02, 0x03};

	// Encryption key for SCP03
	BYTE dataEncryptionKey[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                               0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

	// Call the build function
	status = GP211_build_store_data_keys(
		GP211_SCP03,
		GP211_SCP03_IMPL_i70,
		dataEncryptionKey,
		16,
		GP211_KEY_TYPE_AES,
		GP211_KEY_PURPOSE_SCP03,
		keys,
		keyIds,
		3,
		16, // key length
		0x01, // key version
		GP211_KEY_ACCESS_SD_ONLY,
		output,
		&outputLength
	);

	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	// Expected output structure:
	// 00 B9 30 - DGI '00B9' with length 0x30 (48 bytes)
	// B7 10 - Key Attributes tag with length 0x10 (16 bytes)
	//   80 01 88 - Key Type: AES (0x88)
	//   81 01 10 - Key Length: 16 bytes
	//   83 01 01 - Key Version: 0x01
	//   96 01 01 - Key Access Condition: SD_ONLY (0x01)
	//   97 02 00 03 - Key Purpose: SCP03 (0x0003)
	// B9 08 82 01 01 84 03 50 4A 77 - CRT #1 (Key ID 0x01, KCV)
	// B9 08 82 01 02 84 03 F2 A8 DF - CRT #2 (Key ID 0x02, KCV)
	// B9 08 82 01 03 84 03 D7 D0 E4 - CRT #3 (Key ID 0x03, KCV)
	// 81 13 10 ... - DGI '8113' encrypted key #1 (16 bytes)
	// 81 13 10 ... - DGI '8113' encrypted key #2 (16 bytes)
	// 81 13 10 ... - DGI '8113' encrypted key #3 (16 bytes)

	BYTE expected[] = {
		0x00, 0xB9, 0x30, 0xB7, 0x10, 0x80, 0x01, 0x88, 0x81, 0x01, 0x10, 0x83, 0x01, 0x01, 0x96, 0x01,
		0x01, 0x97, 0x02, 0x00, 0x03, 0xB9, 0x08, 0x82, 0x01, 0x01, 0x84, 0x03, 0x50, 0x4A, 0x77, 0xB9,
		0x08, 0x82, 0x01, 0x02, 0x84, 0x03, 0xF2, 0xA8, 0xDF, 0xB9, 0x08, 0x82, 0x01, 0x03, 0x84, 0x03,
		0xD7, 0xD0, 0xE4, 0x81, 0x13, 0x10, 0xD5, 0x33, 0xE5, 0x9B, 0x45, 0xA1, 0x53, 0xED, 0x7E, 0x5E,
		0x9C, 0x5D, 0xFC, 0xFD, 0x4A, 0xAA, 0x81, 0x13, 0x10, 0x3E, 0xF0, 0xB1, 0xA5, 0xE3, 0x05, 0x9D,
		0xAB, 0x21, 0xFC, 0xE2, 0x3A, 0x7B, 0x61, 0xC4, 0xCA, 0x81, 0x13, 0x10, 0xAD, 0xDE, 0x68, 0xF7,
		0xAD, 0x49, 0x72, 0x68, 0xD3, 0x1A, 0x0D, 0xDD, 0x5C, 0x74, 0xB0, 0x8F
	};

	assert_int_equal(outputLength, sizeof(expected));
	assert_memory_equal(output, expected, sizeof(expected));
}

/**
 * Test encoding of STORE DATA for symmetric keys with single AES-256 key
 * for SCP03 with key version 0x02 and SD+Apps access.
 */
static void test_build_store_data_keys_scp03_aes256_single(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE output[1024];
	DWORD outputLength = sizeof(output);

	// Test key (32 bytes for AES-256)
	BYTE key_s_enc[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};

	PBYTE keys[1] = {key_s_enc};
	BYTE keyIds[1] = {0x01};

	// Encryption key for SCP03 with AES-256
	BYTE dataEncryptionKey[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};

	// Call with only S-ENC key
	status = GP211_build_store_data_keys(
		GP211_SCP03,
		GP211_SCP03_IMPL_i70,
		dataEncryptionKey,
		32,
		GP211_KEY_TYPE_AES,
		GP211_KEY_PURPOSE_SCP03,
		keys,
		keyIds,
		1,
		32, // key length
		0x02, // key version
		GP211_KEY_ACCESS_SD_AND_APPS,
		output,
		&outputLength
	);

	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	BYTE expected[] = {
		0x00, 0xb9, 0x1c, 0xb7, 0x10, 0x80, 0x01, 0x88, 0x81, 0x01, 0x20, 0x83, 0x01, 0x02, 0x96, 0x01,
		0x00, 0x97, 0x02, 0x00, 0x03, 0xb9, 0x08, 0x82, 0x01, 0x01, 0x84, 0x03, 0x75, 0xe2, 0x08, 0x81,
		0x13, 0x20, 0x5a, 0x6e, 0x04, 0x57, 0x08, 0xfb, 0x71, 0x96, 0xf0, 0x2e, 0x55, 0x3d, 0x02, 0xc3,
		0xa6, 0x92, 0xc7, 0x71, 0x47, 0xeb, 0xd5, 0x12, 0x1d, 0xe8, 0xd0, 0xfa, 0xe7, 0x76, 0x24, 0x23,
		0xb6, 0xbf
	};

	assert_int_equal(outputLength, sizeof(expected));
	assert_memory_equal(output, expected, sizeof(expected));
}

/**
 * Test encoding of STORE DATA for SCP04 keys.
 */
static void test_build_store_data_keys_scp04(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE output[1024];
	DWORD outputLength = sizeof(output);

	// Test keys
	BYTE key_s_enc[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	                      0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
	BYTE key_s_mac[16] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	                      0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};

	PBYTE keys[2] = {key_s_enc, key_s_mac};
	BYTE keyIds[2] = {0x01, 0x02};

	// Encryption key for SCP03 (SCP04 uses same encryption)
	BYTE dataEncryptionKey[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                               0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

	// Call with SCP04 purpose
	status = GP211_build_store_data_keys(
		GP211_SCP03,
		GP211_SCP03_IMPL_i70,
		dataEncryptionKey,
		16,
		GP211_KEY_TYPE_AES,
		GP211_KEY_PURPOSE_SCP04,
		keys,
		keyIds,
		2,
		16,
		0x01,
		GP211_KEY_ACCESS_APPS_ONLY,
		output,
		&outputLength
	);

	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	BYTE expected[] = {
		0x00, 0xb9, 0x26, 0xb7, 0x10, 0x80, 0x01, 0x88, 0x81, 0x01, 0x10, 0x83, 0x01, 0x01, 0x96, 0x01,
		0x02, 0x97, 0x02, 0x00, 0x04, 0xb9, 0x08, 0x82, 0x01, 0x01, 0x84, 0x03, 0xed, 0xcc, 0x64, 0xb9,
		0x08, 0x82, 0x01, 0x02, 0x84, 0x03, 0xfb, 0xeb, 0xdc, 0x81, 0x13, 0x10, 0x08, 0x92, 0x08, 0x56,
		0x05, 0xbe, 0x8f, 0x34, 0x9f, 0x58, 0x4a, 0xf9, 0x93, 0xdf, 0x11, 0xf8, 0x81, 0x13, 0x10, 0x18,
		0x14, 0xc5, 0xd9, 0x5b, 0xb4, 0x2f, 0x22, 0x78, 0xc1, 0xdd, 0x6b, 0x74, 0x83, 0x7f, 0x42
	};

	assert_int_equal(outputLength, sizeof(expected));
	assert_memory_equal(output, expected, sizeof(expected));
}

/**
 * Test error case: no keys provided.
 */
static void test_build_store_data_keys_no_keys_error(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE output[1024];
	DWORD outputLength = sizeof(output);

	PBYTE keys[1] = {NULL};
	BYTE keyIds[1] = {0x01};

	// Encryption key
	BYTE dataEncryptionKey[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                               0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

	// Call with no keys (numKeys = 0)
	status = GP211_build_store_data_keys(
		GP211_SCP03,
		GP211_SCP03_IMPL_i70,
		dataEncryptionKey,
		16,
		GP211_KEY_TYPE_AES,
		GP211_KEY_PURPOSE_SCP03,
		keys,
		keyIds,
		0, // no keys
		16,
		0x01,
		GP211_KEY_ACCESS_SD_ONLY,
		output,
		&outputLength
	);

	// Should fail with invalid combination error
	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_FAILURE);
	assert_int_equal(status.errorCode, OPGP_ERROR_INVALID_COMBINATION_KEY_SET_VERSION_KEY_INDEX);
}

/**
 * Test with DAP verification key purpose.
 */
static void test_build_store_data_keys_dap_purpose(void **state) {
	OPGP_ERROR_STATUS status;
	BYTE output[1024];
	DWORD outputLength = sizeof(output);

	BYTE key_dap[16] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
	                    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};

	PBYTE keys[1] = {key_dap};
	BYTE keyIds[1] = {0x01};

	// Encryption key
	BYTE dataEncryptionKey[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                               0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

	// Call with DAP verification purpose
	status = GP211_build_store_data_keys(
		GP211_SCP03,
		GP211_SCP03_IMPL_i70,
		dataEncryptionKey,
		16,
		GP211_KEY_TYPE_AES,
		GP211_KEY_PURPOSE_DAP_VERIFICATION,
		keys,
		keyIds,
		1,
		16,
		0x01,
		GP211_KEY_ACCESS_SD_AND_APPS,
		output,
		&outputLength
	);

	assert_int_equal(status.errorStatus, OPGP_ERROR_STATUS_SUCCESS);

	// Expected output structure:
	// 00 B9 1C - DGI '00B9' with length 0x1C (28 bytes)
	// B7 10 - Key Attributes tag with length 0x10 (16 bytes)
	//   80 01 88 - Key Type: AES (0x88)
	//   81 01 10 - Key Length: 16 bytes
	//   83 01 01 - Key Version: 0x01
	//   96 01 00 - Key Access Condition: SD_AND_APPS (0x00)
	//   97 02 70 03 - Key Purpose: DAP_VERIFICATION (0x7003)
	// B9 08 - CRT with length 0x08 (8 bytes)
	//   82 01 01 - Key ID: 0x01
	//   84 03 61 DD C3 - Key Check Value (3 bytes, depends on key)
	// 81 13 10 - DGI '8113' with length 0x10 (16 bytes encrypted key follows)

	BYTE expected[] = {
		0x00, 0xB9, 0x1C,
		0xB7, 0x10, 0x80, 0x01, 0x88, 0x81, 0x01, 0x10, 0x83, 0x01, 0x01, 0x96, 0x01,
		0x00, 0x97, 0x02, 0x70, 0x03,
		0xB9, 0x08, 0x82, 0x01, 0x01, 0x84, 0x03, 0x61, 0xDD, 0xC3,
		0x81, 0x13, 0x10, 0xA0, 0xCC, 0xF0, 0x98, 0xA3, 0x9D, 0xD2, 0x65, 0x41, 0x06,
		0x8A, 0x6E, 0x94, 0x5F, 0x29, 0x38
	};

	assert_int_equal(outputLength, sizeof(expected));
	assert_memory_equal(output, expected, sizeof(expected));
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_build_store_data_keys_scp03_aes128),
		cmocka_unit_test(test_build_store_data_keys_scp03_aes256_single),
		cmocka_unit_test(test_build_store_data_keys_scp04),
		cmocka_unit_test(test_build_store_data_keys_no_keys_error),
		cmocka_unit_test(test_build_store_data_keys_dap_purpose),
	};

	return cmocka_run_group_tests_name("storeData", tests, NULL, NULL);
}
