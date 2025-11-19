/*  Copyright (c) 2019, Karsten Ohme
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
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

/**
 * @file
 * @brief This implements all crypto functions.
 */

#include "crypto.h"
#include "globalplatform/stringify.h"
#include "globalplatform/errorcodes.h"
#include "globalplatform/error.h"
#include "globalplatform/debug.h"
#include "util.h"

#include <string.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/cmac.h>
#if OPENSSL_VERSION_NUMBER > 0x10100000L
#include <openssl/rsa.h>
#endif
#include <openssl/bn.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_CIPHER_CTX_define EVP_CIPHER_CTX *ctx;  EVP_CIPHER_CTX _ctx
#define EVP_CIPHER_CTX_create &_ctx
#define EVP_CIPHER_CTX_free EVP_CIPHER_CTX_cleanup
#else
#define EVP_CIPHER_CTX_define EVP_CIPHER_CTX *ctx
#define EVP_CIPHER_CTX_create EVP_CIPHER_CTX_new()
#endif

#if defined OPENSSL_VERSION_MAJOR && (OPENSSL_VERSION_MAJOR >= 3)
#define OPENSSL3
#endif

#ifndef OPENSSL3
#define EVP_MAC_update CMAC_Update
#define EVP_MAC_final(ctx, out, outl, outsize) CMAC_Final(ctx, out, outl)
#define EVP_MAC_CTX CMAC_CTX
#define EVP_MAC_CTX_new(mac) CMAC_CTX_new()
#define EVP_MAC_CTX_free CMAC_CTX_free
#define EVP_MAC_init(ctx, key, keyLength, params) CMAC_Init(ctx, key, keyLength, params, NULL)
#endif

static const BYTE PADDING[8] = {(char) 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //!< Applied padding pattern for SCP02.
static const BYTE AES_PADDING[16] = {(char)0x80,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00}; //!< Padding pattern applied for SCP03.

OPGP_NO_API
OPGP_ERROR_STATUS calculate_enc_cbc(BYTE key[16], BYTE *message, DWORD messageLength,
							  BYTE *encryption, DWORD *encryptionLength);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_MAC_aes(BYTE key[32], DWORD keyLength, BYTE *message, DWORD messageLength, BYTE mac[16]);

/**
    * Calculates the a cryptogram for multiple SCP03 operation like host cryptogram, card cryptogram and card challenge calculation.
    *
    * \param key [in] The AES key to use for the calculation.
    * \param keyLength [in] The AES key length in bytes (16, 24, or 32).
    * \param derivationConstant [in] The derivation constant for the key derivation function.
    * \param context1 [in] The context1 for the internal key derivation.
	* \param context1Length [in] The length of the context1 buffer.
    * \param context2 [in] The context2 for the internal key derivation.
	* \param context2Length [in] The length of the context2 buffer.
	* \param cryptogram [out] The calculated cryptogram. Must be large enough to hold the result. For session keys this is 128 bits, 64 bits otherwise.
    * \param cryptogramSize [in] The result size in bits of the cryptogram. Must be a multiple of 8.
    * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
    */
OPGP_ERROR_STATUS calculate_cryptogram_SCP03(BYTE key[32], DWORD keyLength, const BYTE derivationConstant, PBYTE context1, DWORD context1Length,
	PBYTE context2, DWORD context2Length, PBYTE cryptogram, DWORD cryptogramSize) {
		OPGP_ERROR_STATUS status;
		BYTE derivationData[48];
		BYTE mac[16];
		DWORD i;
		DWORD derivationDataLength = 16 + context1Length + context2Length;
		OPGP_LOG_START(_T("calculate_cryptogram_SCP03"));

		memset(derivationData, 0, 48);

		// sanity check, this should never be more than 48 bytes
		if (derivationDataLength > 48) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
		}
		derivationData[11] = derivationConstant; //<! "derivation constant" part of label
		derivationData[12] = 0x00; // <! "separation indicator"
		if (cryptogramSize > 255) {
			derivationData[13] = 0x01; // <! First byte of output length
		}
		else {
			derivationData[13] = 0x00; // <! First byte of output length
		}
		derivationData[14] = (BYTE) (cryptogramSize & 0x00FF); // <! Second byte of output length

		memcpy(derivationData + 16, context1, context1Length);
		memcpy(derivationData + 16 + context1Length, context2, context2Length);

		// support AES > 128 bits, 16 is AES block size
		for (i=0; i<(cryptogramSize/8)/16 + ((cryptogramSize/8) % 16 > 0 ? 1 : 0); i++) {
			derivationData[15] = i+1; // <! byte counter "i"
			status = calculate_MAC_aes(key, keyLength, derivationData, derivationDataLength, mac);
			if (OPGP_ERROR_CHECK(status)) {
				goto end;
			}
			// copy block size
			memcpy(cryptogram + 16*i, mac, (cryptogramSize/8 > 16 ? 16 : cryptogramSize/8));
		}

		{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

		OPGP_LOG_END(_T("calculate_cryptogram_SCP03"), status);
		return status;
}

/**
 * \brief Creates a MAC for commands (APDUs) using CMAC AES.
 * This is used by SCP03.
 * The MAC for the message are the first 8 Bytes of mac.
 * The next chainingValue are the full 16 Bytes of mac. Save this value for the next command MAC calculation.
 *
 * \param sMacKey [in] The S-MAC key (session MAC key) to use for MAC generation.
 * \param keyLength [in] The AES key length in bytes (16, 24, or 32).
 * \param message [in] The message to generate the MAC for.
 * \param messageLength [in] The length of the message.
 * \param chainingValue [in] The chaining value to use for the MAC generation. This is
 *                           usually the full 16 Byte MAC generated for the last command
 *                           or 16 bytes 0x00 for the first one (i.e. EXTERNAL AUTHENTICATE).
 * \param mac [out] The full 16 Byte MAC. Append the first 8 Bytes to the
 *                  message. Save the full 16 Bytes for further MAC generation if needed.
 */
OPGP_ERROR_STATUS calculate_CMAC_aes(PBYTE sMacKey, DWORD keyLength, BYTE *message, DWORD messageLength,
		PBYTE chainingValue, PBYTE mac) {
	LONG result;
	OPGP_ERROR_STATUS status;
	size_t outl;
	EVP_MAC_CTX *ctx;
#ifdef OPENSSL3
	EVP_MAC *_mac = EVP_MAC_fetch(NULL, "cmac", NULL);
	OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("cipher", keyLength == 16 ? "aes-128-cbc" : (keyLength == 24 ?
 			"aes-192-cbc" : "aes-256-cbc"), 0);
	params[1] = OSSL_PARAM_construct_end();
#else
	const EVP_CIPHER *params = keyLength == 16 ? EVP_aes_128_cbc() : (keyLength == 24 ? EVP_aes_192_cbc() : EVP_aes_256_cbc());
#endif

	OPGP_LOG_START(_T("calculate_CMAC_aes"));
	ctx = EVP_MAC_CTX_new(_mac);
	result = EVP_MAC_init(ctx, sMacKey, keyLength, params);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	if (chainingValue != NULL) {
		/*
		 * The input for CMAC is: chainingValue|message.
		 * The chaining value is 16 bytes long.
		*/
		result = EVP_MAC_update(ctx, chainingValue, 16);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
	}
	result = EVP_MAC_update(ctx, message, messageLength);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}

	// Write the final block to the mac
	result = EVP_MAC_final(ctx, mac, &outl, 16);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	EVP_MAC_CTX_free(ctx);
#ifdef OPENSSL3
	EVP_MAC_free(_mac);
#endif
	OPGP_LOG_END(_T("calculate_CMAC_aes"), status);
	return status;
}

/**
 * Calculates a message authentication code, using AES-128 in CBC mode. This is the algorithm specified in NIST 800-38B.
 * \param key [in] The AES key to use.
 * \param keyLength [in] The AES key length in bytes (16, 24, or 32).
 * \param *message [in] The message to calculate the MAC for.
 * \param messageLength [in] The message length.
 * \param mac [out] The calculated MAC.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_MAC_aes(BYTE key[32], DWORD keyLength, BYTE *message, DWORD messageLength, BYTE mac[16]) {
	OPGP_ERROR_STATUS status;
	OPGP_LOG_START(_T("calculate_MAC_aes"));
	status = calculate_CMAC_aes(key, keyLength, message, messageLength, NULL, mac);
	OPGP_LOG_END(_T("calculate_MAC_aes"), status);
	return status;
}

OPGP_ERROR_STATUS calculate_enc_ecb_SCP03(BYTE key[32], DWORD keyLength, BYTE *message, DWORD messageLength,
		BYTE *encryption, DWORD *encryptionLength) {
	OPGP_ERROR_STATUS status;
	int result;
	int outl;
	EVP_CIPHER_CTX_define;
	OPGP_LOG_START(_T("calculate_enc_ecb_SCP03"));
	ctx = EVP_CIPHER_CTX_create;
	EVP_CIPHER_CTX_init(ctx);
	*encryptionLength = 0;

	result = EVP_EncryptInit_ex(ctx, keyLength == 16 ? EVP_aes_128_ecb() :
				(keyLength == 24 ? EVP_aes_192_cbc() : EVP_aes_256_cbc()), NULL, key, NULL);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	result = EVP_EncryptUpdate(ctx, encryption, &outl, message, messageLength);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*encryptionLength += outl;
	result = EVP_EncryptFinal_ex(ctx, encryption+*encryptionLength,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*encryptionLength+=outl;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	EVP_CIPHER_CTX_free(ctx);

	OPGP_LOG_END(_T("calculate_enc_ecb_SCP03"), status);
	return status;

}

/**
 * Calculates the encryption of a message in CBC mode for SCP03 using AES with no padding if not needed.
 * \param key [in] An AES key used to encrypt.
 * \param keyLength [in] The key length. 16, 24 or 32 bytes.
 * \param *message [in] The message to encrypt.
 * \param messageLength [in] The length of the message.
 * \param icv [in] The ICV to use.
 * \param *encryption [out] The encryption.
 * \param *encryptionLength [out] The length of the encryption.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_enc_cbc_SCP03_min_padding(BYTE key[32], DWORD keyLength,
		BYTE *message, DWORD messageLength,
							  BYTE icv[16],
							  BYTE *encryption, DWORD *encryptionLength) {
	OPGP_ERROR_STATUS status;
	int result;
	int outl;
	EVP_CIPHER_CTX_define;
	OPGP_LOG_START(_T("calculate_enc_cbc_SCP03_min_padding"));
	ctx = EVP_CIPHER_CTX_create;
	EVP_CIPHER_CTX_init(ctx);
	*encryptionLength = 0;

	result = EVP_EncryptInit_ex(ctx, keyLength == 16 ? EVP_aes_128_cbc() :
			(keyLength == 24 ? EVP_aes_192_cbc() : EVP_aes_256_cbc()), NULL, key, icv);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	result = EVP_EncryptUpdate(ctx, encryption, &outl, message, messageLength);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*encryptionLength += outl;
	result = EVP_EncryptUpdate(ctx, encryption + *encryptionLength, &outl, AES_PADDING, ((16 - (messageLength % 16)) % 16));
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*encryptionLength += outl;
	result = EVP_EncryptFinal_ex(ctx, encryption+*encryptionLength,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*encryptionLength+=outl;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	EVP_CIPHER_CTX_free(ctx);
	OPGP_LOG_END(_T("calculate_enc_cbc_SCP03_min_padding"), status);
	return status;
}

/**
 * Calculates the encryption of a message in CBC mode for SCP03 using AES.
 * Pads the message with 0x80 and additional 0x00 until message length is a multiple of the block size.
 * \param key [in] An AES key used to encrypt.
 * \param keyLength [in] The key length. 16, 24 or 32 bytes.
 * \param *message [in] The message to encrypt.
 * \param messageLength [in] The length of the message.
 * \param icv [in] The ICV to use.
 * \param *encryption [out] The encryption.
 * \param *encryptionLength [out] The length of the encryption.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_enc_cbc_SCP03(BYTE key[32], DWORD keyLength, BYTE *message, DWORD messageLength,
							  BYTE icv[16],
							  BYTE *encryption, DWORD *encryptionLength) {
	OPGP_ERROR_STATUS status;
	int result;
	int outl;
	EVP_CIPHER_CTX_define;
	OPGP_LOG_START(_T("calculate_enc_cbc_SCP03"));
	ctx = EVP_CIPHER_CTX_create;
	EVP_CIPHER_CTX_init(ctx);
	*encryptionLength = 0;

	result = EVP_EncryptInit_ex(ctx, keyLength == 16 ? EVP_aes_128_cbc() :
			(keyLength == 24 ? EVP_aes_192_cbc() : EVP_aes_256_cbc()), NULL, key, icv);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	result = EVP_EncryptUpdate(ctx, encryption, &outl, message, messageLength);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*encryptionLength += outl;
	result = EVP_EncryptUpdate(ctx, encryption + *encryptionLength, &outl, AES_PADDING, (16 - messageLength % 16));
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*encryptionLength += outl;
	result = EVP_EncryptFinal_ex(ctx, encryption+*encryptionLength,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*encryptionLength+=outl;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
    EVP_CIPHER_CTX_free(ctx);

	OPGP_LOG_END(_T("calculate_enc_cbc_SCP03"), status);
	return status;
}

/**
 * Calculates the decryption of a message in CBC mode for SCP03 using AES.
 * Also take ISO7816-4 padding into account (0x80 and additional 0x00).
 * \param key [in] An AES key used to decrypt.
 * \param keyLength [in] The key length. 16, 24 or 32 bytes.
 * \param *message [in] The message to decrypt.
 * \param messageLength [in] The length of the message.
 * \param icv [in] The ICV to use.
 * \param *decryption [out] The encryption.
 * \param *decryptionLength [out] The length of the encryption.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_dec_cbc_SCP03(PBYTE key, DWORD keyLength, BYTE *message, DWORD messageLength,
						  PBYTE icv,
						  BYTE *decryption, DWORD *decryptionLength) {
	OPGP_ERROR_STATUS status;
	int result;
	int outl;
	EVP_CIPHER_CTX_define;
	OPGP_LOG_START(_T("calculate_dec_cbc_SCP03"));
	ctx = EVP_CIPHER_CTX_create;
	EVP_CIPHER_CTX_init(ctx);
	*decryptionLength = 0;

	// initialize AES-CBC, deactivate padding
	result = EVP_DecryptInit_ex(ctx, keyLength == 16 ? EVP_aes_128_cbc() :
			(keyLength == 24 ? EVP_aes_192_cbc() : EVP_aes_256_cbc()), NULL, key, icv);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	// decrypt ciphertext (which may include padded bytes)
	result = EVP_DecryptUpdate(ctx, decryption, &outl, message, messageLength);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*decryptionLength += outl;

	result = EVP_DecryptFinal_ex(ctx, decryption + *decryptionLength, &outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*decryptionLength += outl;

	// remove ISO7816-4 padding (0x80 followed by 0x00...) from plaintext
	if (*decryptionLength > 0) {
		DWORD len = *decryptionLength;
		int idx = (int)len - 1;

		// skip trailing 0x00 ... 0x00
		while (idx >= 0 && decryption[idx] == 0x00) {
			idx--;
		}

		// check 0x80 padding marker
		if (idx >= 0 && decryption[idx] == 0x80) {
			len = (DWORD)idx;  // everything before is real plaintext
		}

		*decryptionLength = len;
	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
    EVP_CIPHER_CTX_free(ctx);

	OPGP_LOG_END(_T("calculate_dec_cbc_SCP03"), status);
	return status;
}

/**
 * Calculates the encryption ICV for SCP03 using AES.
 * \param key [in] An AES key used to encrypt.
 * \param keyLength [in] The key length. 16, 24 or 32 bytes.
 * \param sessionEncryptionCounter [in] The session encryption counter.
 * \param icv [out] The ICV to use.
 * \param forResponse 1 if the calculation is performed for the response.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_enc_icv_SCP03(PBYTE key, DWORD keyLength, LONG sessionEncryptionCounter, PBYTE icv, BOOL forResponse) {
	OPGP_ERROR_STATUS status;
	int result;
	int outl;
	EVP_CIPHER_CTX_define;
	BYTE encryptionCounter[16];
	OPGP_LOG_START(_T("calculate_enc_icv_SCP03"));
	ctx = EVP_CIPHER_CTX_create;
	EVP_CIPHER_CTX_init(ctx);

	result = EVP_EncryptInit_ex(ctx, keyLength == 16 ? EVP_aes_128_cbc() :
			(keyLength == 24 ? EVP_aes_192_cbc() : EVP_aes_256_cbc()), NULL, key, icv);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	memset(encryptionCounter, 0, 16);
	encryptionCounter[16-4] = (int)((sessionEncryptionCounter >> 24) & 0xFF) ;
	encryptionCounter[16-3] = (int)((sessionEncryptionCounter >> 16) & 0xFF) ;
	encryptionCounter[16-2] = (int)((sessionEncryptionCounter >> 8) & 0XFF);
	encryptionCounter[16-1] = (int)((sessionEncryptionCounter & 0XFF));
	if (forResponse) {
		encryptionCounter[0] |= 0x80;
	}

	result = EVP_EncryptUpdate(ctx, icv, &outl, encryptionCounter, 16);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	result = EVP_EncryptFinal_ex(ctx, icv, &outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
    EVP_CIPHER_CTX_free(ctx);

	OPGP_LOG_END(_T("calculate_enc_icv_SCP03"), status);
	return status;
}


/**
 * Calculates the encryption of a message in CBC mode for SCP02.
 * Pads the message with 0x80 and additional 0x00 until message length is a multiple of 8.
 * \param key [in] A 3DES key used to encrypt.
 * \param *message [in] The message to encrypt.
 * \param messageLength [in] The length of the message.
 * \param *encryption [out] The encryption.
 * \param *encryptionLength [out] The length of the encryption.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_enc_cbc_SCP02(BYTE key[16], BYTE *message, DWORD messageLength,
							  BYTE *encryption, DWORD *encryptionLength) {
	OPGP_ERROR_STATUS status;
	int result;
	int i,outl;
	EVP_CIPHER_CTX_define;
	OPGP_LOG_START(_T("calculate_enc_cbc_SCP02"));
	ctx = EVP_CIPHER_CTX_create;
	EVP_CIPHER_CTX_init(ctx);
	*encryptionLength = 0;

	result = EVP_EncryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, key, ICV);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(ctx, encryption+*encryptionLength,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;
	}
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(ctx, encryption+*encryptionLength,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;
	}
	result = EVP_EncryptUpdate(ctx, encryption+*encryptionLength,
		&outl, PADDING, 8 - (messageLength%8));
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*encryptionLength+=outl;
	result = EVP_EncryptFinal_ex(ctx, encryption+*encryptionLength,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*encryptionLength+=outl;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
    EVP_CIPHER_CTX_free(ctx);

	OPGP_LOG_END(_T("calculate_enc_cbc_SCP02"), status);
	return status;
}

/**
 * Calculates the card cryptogram for SCP01.
 * \param S_ENCSessionKey [in] The S-ENC Session Key for calculating the card cryptogram.
 * \param cardChallenge [in] The card challenge.
 * \param hostChallenge [in] The host challenge.
 * \param cardCryptogram [out] The calculated card cryptogram.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_card_cryptogram_SCP01(BYTE S_ENCSessionKey[16], BYTE cardChallenge[8],
									  BYTE hostChallenge[8], BYTE cardCryptogram[8]) {
	OPGP_ERROR_STATUS status;
	BYTE message[16];
	OPGP_LOG_START(_T("calculate_card_cryptogram_SCP01"));
	memcpy(message, hostChallenge, 8);
	memcpy(message+8, cardChallenge, 8);
	status = calculate_MAC(S_ENCSessionKey, message, 16, (PBYTE)ICV, cardCryptogram);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("calculate_card_cryptogram_SCP01"), status);
	return status;
}

/**
 * Calculates the card cryptogram for SCP02.
 * \param S_ENCSessionKey [in] The S-ENC Session Key for calculating the card cryptogram.
 * \param sequenceCounter [in] The sequence counter.
 * \param cardChallenge [in] The card challenge.
 * \param hostChallenge [in] The host challenge.
 * \param cardCryptogram [out] The calculated card cryptogram.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_card_cryptogram_SCP02(BYTE S_ENCSessionKey[16],
							BYTE sequenceCounter[2],
							PBYTE cardChallenge,
							BYTE hostChallenge[8],
							BYTE cardCryptogram[8]) {
	OPGP_ERROR_STATUS status;
	BYTE message[16];
	OPGP_LOG_START(_T("calculate_card_cryptogram_SCP02"));
	memcpy(message, hostChallenge, 8);
	memcpy(message+8, sequenceCounter, 2);
	memcpy(message+10, cardChallenge, 6);
	status = calculate_MAC(S_ENCSessionKey, message, 16, (PBYTE)ICV, cardCryptogram);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("calculate_card_cryptogram_SCP02"), status);
	return status;
}

/**
 * Calculates the card cryptogram for SCP03.
 * \param S_MACSessionKey [in] The S-MAC Session Key for calculating the card cryptogram.
 * \param keyLength [in] The key length in bytes (16, 24 or 32).
 * \param cardChallenge [in] The card challenge.
 * \param hostChallenge [in] The host challenge.
 * \param cardCryptogram [out] The calculated host cryptogram.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_card_cryptogram_SCP03(BYTE S_MACSessionKey[32],
											DWORD keyLength,
											BYTE cardChallenge[8],
											BYTE hostChallenge[8],
											BYTE cardCryptogram[8])
{
	OPGP_ERROR_STATUS status;
	OPGP_LOG_START(_T("calculate_card_cryptogram_SCP03"));
	status = calculate_cryptogram_SCP03(S_MACSessionKey, keyLength, 0x00, hostChallenge, 8, cardChallenge, 8, cardCryptogram, 64);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("calculate_card_cryptogram_SCP03"), status);
	return status;
}

/**
 * Calculates the card challenge when using pseudo-random challenge generation for SCP03.
 * \param S_ENC [in] The static S-ENC Key.
 * \param keyLength [in] The key length in bytes (16, 24 or 32).
 * \param sequenceCounter [in] The sequence counter.
 * \param invokingAID The invoking AID byte buffer.
 * \param invokingAIDLength The length of the invoking AID byte buffer.
 * \param cardChallenge [out] The calculated challenge.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_card_challenge_SCP03(BYTE S_ENC[32],
											DWORD keyLength,
											BYTE sequenceCounter[3],
											PBYTE invokingAID,
											DWORD invokingAIDLength,
											BYTE cardChallenge[8])
{
	OPGP_ERROR_STATUS status;
	OPGP_LOG_START(_T("calculate_card_challenge_SCP03"));
	status = calculate_cryptogram_SCP03(S_ENC, keyLength, 0x02, sequenceCounter, 3, invokingAID, invokingAIDLength, cardChallenge, 64);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("calculate_card_challenge_SCP03"), status);
	return status;
}

/**
 * Calculates the host cryptogram for SCP01.
 * \param S_ENCSessionKey [in] The S-ENC Session Key for calculating the card cryptogram.
 * \param cardChallenge [in] The card challenge.
 * \param hostChallenge [in] The host challenge.
 * \param hostCryptogram [out] The calculated host cryptogram.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_host_cryptogram_SCP01(BYTE S_ENCSessionKey[16],
											BYTE cardChallenge[8],
											BYTE hostChallenge[8],
											BYTE hostCryptogram[8]) {
	OPGP_ERROR_STATUS status;
	BYTE message[16];
	OPGP_LOG_START(_T("calculate_host_cryptogram_SCP01"));
	memcpy(message, cardChallenge, 8);
	memcpy(message+8, hostChallenge, 8);
	status = calculate_MAC(S_ENCSessionKey, message, 16, (PBYTE)ICV, hostCryptogram);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("calculate_host_cryptogram_SCP01"), status);
	return status;
}

/**
 * Calculates the host cryptogram for SCP02.
 * \param S_ENCSessionKey [in] The S-ENC Session Key for calculating the card cryptogram.
 * \param sequenceCounter [in] The sequence counter.
 * \param cardChallenge [in] The card challenge.
 * \param hostChallenge [in] The host challenge.
 * \param hostCryptogram [out] The calculated host cryptogram.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_host_cryptogram_SCP02(BYTE S_ENCSessionKey[16],
							BYTE sequenceCounter[2],
							PBYTE cardChallenge,
							BYTE hostChallenge[8],
							BYTE hostCryptogram[8]) {
	OPGP_ERROR_STATUS status;
	BYTE message[16];
	OPGP_LOG_START(_T("calculate_host_cryptogram_SCP02"));
	memcpy(message, sequenceCounter, 2);
	memcpy(message+2, cardChallenge, 6);
	memcpy(message+8, hostChallenge, 8);
	status = calculate_MAC(S_ENCSessionKey, message, 16, (PBYTE)ICV, hostCryptogram);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("calculate_host_cryptogram_SCP02"), status);
	return status;
}

/**
 * Calculates the host cryptogram for SCP03.
 * \param S_MACSessionKey [in] The S-MAC Session Key for calculating the card cryptogram.
 * \param keyLength [in] The key length in bytes (16, 24 or 32).
 * \param cardChallenge [in] The card challenge.
 * \param hostChallenge [in] The host challenge.
 * \param hostCryptogram [out] The calculated host cryptogram.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_host_cryptogram_SCP03(BYTE S_MACSessionKey[32],
											DWORD keyLength,
											BYTE cardChallenge[8],
											BYTE hostChallenge[8],
											BYTE hostCryptogram[8])
{
	OPGP_ERROR_STATUS status;
	OPGP_LOG_START(_T("calculate_host_cryptogram_SCP03"));
	status = calculate_cryptogram_SCP03(S_MACSessionKey, keyLength, 0x01, hostChallenge, 8, cardChallenge, 8, hostCryptogram, 64);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("calculate_host_cryptogram_SCP03"), status);
	return status;
}

/**
 * Creates the session key for SCP01.
 * \param key [in] The Secure Channel Encryption Key or Secure Channel Message
 * Authentication Code Key for calculating the corresponding session key.
 * \param cardChallenge [in] The card challenge.
 * \param hostChallenge [in] The host challenge.
 * \param sessionKey [out] The calculated 3DES session key.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS create_session_key_SCP01(BYTE key[16], BYTE cardChallenge[8],
						   BYTE hostChallenge[8], PBYTE sessionKey) {
	OPGP_ERROR_STATUS status;
	BYTE derivation_data[16];
	DWORD outl;

	OPGP_LOG_START(_T("create_session_key_SCP01"));
	memcpy(derivation_data, cardChallenge+4, 4);
	memcpy(derivation_data+4, hostChallenge, 4);
	memcpy(derivation_data+8, cardChallenge, 4);
	memcpy(derivation_data+12, hostChallenge+4, 4);

	status = calculate_enc_ecb_two_key_triple_des(key, derivation_data, 16, sessionKey, &outl);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("create_session_key_SCP01"), status);
	return status;
}

/**
 * Creates the session key for SCP02.
 * \param key [in] The Secure Channel Encryption Key or Secure Channel Message
 * Authentication Code Key or Data Encryption Key for calculating the corresponding session key.
 * \param constant [in] The constant for the corresponding session key.
 * \param sequenceCounter [in] The sequence counter.
 * \param sessionKey [out] The calculated 3DES session key.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS create_session_key_SCP02(BYTE key[16], BYTE constant[2],
									BYTE sequenceCounter[2], PBYTE sessionKey) {
	OPGP_ERROR_STATUS status;
	BYTE derivation_data[16];
	DWORD outl;
	int i;

	OPGP_LOG_START(_T("create_session_key_SCP02"));
	memcpy(derivation_data, constant, 2);
	memcpy(derivation_data+2, sequenceCounter, 2);
	for (i=4; i< 16; i++) {
		derivation_data[i] = 0x00;
	}

	status = calculate_enc_cbc(key, derivation_data, 16, sessionKey, &outl);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("create_session_key_SCP02"), status);
	return status;
}

/**
 * Creates an AES-128 session key for SCP03.
 * \param key [in] The Secure Channel Encryption Key or Secure Channel Message
 * Authentication Code Key for calculating the corresponding session key.
 * \param keyLength [in] The key length. 16, 24 or 32 bytes.
 * \param derivationConstant [in] The derivation constant, as defined in "Table 4-1: Data derivation constants" of SCP03.
 * \param cardChallenge [in] The card challenge.
 * \param hostChallenge [in] The host challenge.
 * \param sessionKey [out] The calculated AES session key.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS create_session_key_SCP03(BYTE key[32], DWORD keyLength, BYTE derivationConstant, BYTE cardChallenge[8],
						   BYTE hostChallenge[8], PBYTE sessionKey) {
	OPGP_ERROR_STATUS status;
	BYTE _sessionKey[32];
	OPGP_LOG_START(_T("create_session_key_SCP03"));

	status = calculate_cryptogram_SCP03(key, keyLength, derivationConstant, hostChallenge, 8, cardChallenge, 8, _sessionKey,
			keyLength == 16 ? 128 : (keyLength == 24 ? 192 : 256));
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	memcpy(sessionKey, _sessionKey, keyLength);
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("create_session_key_SCP03"), status);
	return status;
}

/**
 * Calculates the encryption of a message in ECB mode with two key triple DES.
 * Pads the message with 0x80 and additional 0x00 if message length is not a multiple of 8.
 * \param key [in] A 3DES key used to encrypt.
 * \param *message [in] The message to encrypt.
 * \param messageLength [in] The length of the message.
 * \param *encryption [out] The encryption.
 * \param *encryptionLength [out] The length of the encryption.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STALTUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_enc_ecb_two_key_triple_des(BYTE key[16], BYTE *message, DWORD messageLength,
							  BYTE *encryption, DWORD *encryptionLength) {
	int result;
	OPGP_ERROR_STATUS status;
	int i,outl;
	EVP_CIPHER_CTX_define;
	OPGP_LOG_START(_T("calculate_enc_ecb_two_key_triple_des"));
	ctx = EVP_CIPHER_CTX_create;
	EVP_CIPHER_CTX_init(ctx);
	*encryptionLength = 0;

	result = EVP_EncryptInit_ex(ctx, EVP_des_ede(), NULL, key, ICV);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(ctx, encryption+*encryptionLength,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;
	}
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(ctx, encryption+*encryptionLength,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;

		result = EVP_EncryptUpdate(ctx, encryption+*encryptionLength,
			&outl, PADDING, 8 - (messageLength%8));
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;
	}
	result = EVP_EncryptFinal_ex(ctx, encryption+*encryptionLength,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*encryptionLength+=outl;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
    EVP_CIPHER_CTX_free(ctx);
	OPGP_LOG_END(_T("calculate_enc_ecb_two_key_triple_des"), status);
	return status;
}

/**
 * Calculates the encryption of a message in ECB mode with single DES.
 * Pads the message with 0x80 and additional 0x00 if message length is not a multiple of 8.
 * \param key [in] A DES key used to encrypt.
 * \param *message [in] The message to encrypt.
 * \param messageLength [in] The length of the message.
 * \param *encryption [out] The encryption.
 * \param *encryptionLength [out] The length of the encryption.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_enc_ecb_single_des(BYTE key[8], BYTE *message, DWORD messageLength,
							  BYTE *encryption, DWORD *encryptionLength) {
	int result;
	OPGP_ERROR_STATUS status;
	int i,outl;
	EVP_CIPHER_CTX_define;
	OPGP_LOG_START(_T("calculate_enc_ecb_single_des"));
	ctx = EVP_CIPHER_CTX_create;
	EVP_CIPHER_CTX_init(ctx);
	*encryptionLength = 0;

	result = EVP_EncryptInit_ex(ctx, EVP_des_ecb(), NULL, key, NULL);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(ctx, encryption+*encryptionLength,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;
	}
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(ctx, encryption+*encryptionLength,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;

		result = EVP_EncryptUpdate(ctx, encryption+*encryptionLength,
			&outl, PADDING, 8 - (messageLength%8));
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;
	}
	result = EVP_EncryptFinal_ex(ctx, encryption+*encryptionLength,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*encryptionLength+=outl;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
    EVP_CIPHER_CTX_free(ctx);

	OPGP_LOG_END(_T("calculate_enc_ecb_single_des"), status);
	return status;
}

/**
 * Calculates a message authentication code.
 * Pads the message always with 0x80 and additional 0x00 until message length is a multiple of 8.
 * \param sessionKey [in] A 3DES key used to sign.
 * \param *message [in] The message to authenticate.
 * \param messageLength [in] The message length.
 * \param icv [in] The initial chaining vector.
 * \param mac [out] The calculated MAC.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_MAC(BYTE sessionKey[16], BYTE *message, DWORD messageLength,
						  BYTE icv[8], BYTE mac[8]) {
	LONG result;
	OPGP_ERROR_STATUS status;
	int i,outl;
	EVP_CIPHER_CTX_define;
	OPGP_LOG_START(_T("calculate_MAC"));
	ctx = EVP_CIPHER_CTX_create;
	EVP_CIPHER_CTX_init(ctx);

	result = EVP_EncryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, sessionKey, icv);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(ctx, mac,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
	}
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(ctx, mac,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
	}
	result = EVP_EncryptUpdate(ctx, mac,
		&outl, PADDING, 8 - (messageLength%8));
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	result = EVP_EncryptFinal_ex(ctx, mac,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
    EVP_CIPHER_CTX_free(ctx);

	OPGP_LOG_END(_T("calculate_MAC"), status);
	return status;
}

/**
 * Calculates the encryption of a message in CBC mode.
 * Pads the message with 0x80 and additional 0x00 if message length is not a multiple of 8.
 * \param key [in] A 3DES key used to encrypt.
 * \param *message [in] The message to encrypt.
 * \param messageLength [in] The length of the message.
 * \param *encryption [out] The encryption.
 * \param *encryptionLength [out] The length of the encryption.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_enc_cbc(BYTE key[16], BYTE *message, DWORD messageLength,
							  BYTE *encryption, DWORD *encryptionLength) {
	LONG result;
	OPGP_ERROR_STATUS status;
	int i,outl;
	EVP_CIPHER_CTX_define;
	OPGP_LOG_START(_T("calculate_enc_cbc"));
	ctx = EVP_CIPHER_CTX_create;
	EVP_CIPHER_CTX_init(ctx);
	*encryptionLength = 0;

	result = EVP_EncryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, key, ICV);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(ctx, encryption+*encryptionLength,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;
	}
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(ctx, encryption+*encryptionLength,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;

		result = EVP_EncryptUpdate(ctx, encryption+*encryptionLength,
			&outl, PADDING, 8 - (messageLength%8));
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;
	}
	result = EVP_EncryptFinal_ex(ctx, encryption+*encryptionLength,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*encryptionLength+=outl;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
    EVP_CIPHER_CTX_free(ctx);

	OPGP_LOG_END(_T("calculate_enc_cbc"), status);
	return status;
}

/**
 * Calculates a RSA signature using SHA-1 and PKCS#1.
 * \param message [in] The message to generate the signature for.
 * \param messageLength [in] The length of the message buffer.
 * \param PEMKeyFileName [in] A PEM file name with the private RSA key.
 * \param *passPhrase [in] The passphrase. Must be an ASCII string.
 * \param signature The calculated signature.
 */
OPGP_ERROR_STATUS calculate_rsa_signature(PBYTE message, DWORD messageLength, OPGP_STRING PEMKeyFileName,
									char *passPhrase, BYTE signature[128]) {
	LONG result;
	OPGP_ERROR_STATUS status;
	EVP_PKEY *key = NULL;
	FILE *PEMKeyFile = NULL;
	EVP_MD_CTX *mdctx;
	unsigned int signatureLength=0;
	OPGP_LOG_START(_T("calculate_rsa_signature"));
	mdctx = EVP_MD_CTX_create();
	EVP_MD_CTX_init(mdctx);
	if (passPhrase == NULL)
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_PASSWORD, OPGP_stringify_error(OPGP_ERROR_INVALID_PASSWORD)); goto end; }
	if ((PEMKeyFileName == NULL) || (_tcslen(PEMKeyFileName) == 0))
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_FILENAME, OPGP_stringify_error(OPGP_ERROR_INVALID_FILENAME)); goto end; }
	PEMKeyFile = _tfopen(PEMKeyFileName, _T("rb"));
	if (PEMKeyFile == NULL) {
		{ OPGP_ERROR_CREATE_ERROR(status, errno, OPGP_stringify_error(errno)); goto end; }
	}
	key = EVP_PKEY_new();
	if (!PEM_read_PrivateKey(PEMKeyFile, &key, NULL, passPhrase)) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	};
	result = EVP_SignInit_ex(mdctx, EVP_sha1(), NULL);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	result = EVP_SignUpdate(mdctx, message, messageLength);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	if (EVP_PKEY_size(key) > 128) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
	}
	result = EVP_SignFinal(mdctx, signature, &signatureLength, key);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	EVP_MD_CTX_destroy(mdctx);

	if (PEMKeyFile) {
		fclose(PEMKeyFile);
	}
	if (key) {
		EVP_PKEY_free(key);
	}
	OPGP_LOG_END(_T("calculate_rsa_signature"), status);
	return status;
}

/**
 * Calculates a message authentication code using the left half key of a two key 3DES key
 * and the full key for the final operation.
 * Pads the message always with 0x80 and additional 0x00 until message length is a multiple of 8.
 * \param _3des_key [in] A 3DES key used to sign.
 * \param *message [in] The message to authenticate.
 * \param messageLength [in] The message length.
 * \param initialICV [in] The initial chaining vector.
 * \param mac [out] The calculated MAC.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_MAC_des_3des(BYTE _3des_key[16], BYTE *message, DWORD messageLength,
						  BYTE initialICV[8], BYTE mac[8]) {
	LONG result;
	OPGP_ERROR_STATUS status;
	int i,outl;
	EVP_CIPHER_CTX_define;
	BYTE des_key[8];
	BYTE _icv[8];
	OPGP_LOG_START(_T("calculate_MAC_des_3des"));
	ctx = EVP_CIPHER_CTX_create;
	EVP_CIPHER_CTX_init(ctx);
	if (initialICV == NULL) {
		memcpy(_icv, ICV, 8);
	}
	else {
		memcpy(_icv, initialICV, 8);
	}
	/* If only one block */
	memcpy(mac, initialICV, 8);
//  DES CBC mode
	memcpy(des_key, _3des_key, 8);
	result = EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, des_key, _icv);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(ctx, mac,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
	}
	result = EVP_EncryptFinal_ex(ctx, mac,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_free(ctx);
//  3DES mode
	ctx = EVP_CIPHER_CTX_create;
	EVP_CIPHER_CTX_init(ctx);
	result = EVP_EncryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, _3des_key, mac);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(ctx, mac,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
	}
	result = EVP_EncryptUpdate(ctx, mac,
		&outl, PADDING, 8 - (messageLength%8));
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	result = EVP_EncryptFinal_ex(ctx, mac,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
    EVP_CIPHER_CTX_free(ctx);
	OPGP_LOG_END(_T("calculate_MAC_des_3des"), status);
	return status;
}


/**
 * GlobalPlatform2.1.1: Validates a Receipt.
 * Returns OPGP_ERROR_STATUS_SUCCESS if the receipt is valid.
 * \param validationData [in] The data used to validate the returned receipt.
 * \param validationDataLength [in] The length of the validationData buffer.
 * \param receipt [in] The receipt.
 * \param receiptKey [in] The 3DES or AES key to generate the receipt.
 * \param keyLength [in] The key length. 16, 24 or 32 bytes.
 * \param secureChannelProtocol [in] The Secure Channel Protocol.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS validate_receipt(PBYTE validationData, DWORD validationDataLength,
							 BYTE receipt[16], PBYTE receiptKey, DWORD keyLength, BYTE secureChannelProtocol)
{
	OPGP_ERROR_STATUS status;
	BYTE mac[16];
	BYTE receiptLength = 8;
	OPGP_LOG_START(_T("validate_receipt"));
	if (secureChannelProtocol == GP211_SCP02) {
		status = calculate_MAC_des_3des(receiptKey, validationData, validationDataLength, (PBYTE)ICV, mac);
	}
	else if (secureChannelProtocol == GP211_SCP03) {
		status = calculate_CMAC_aes(receiptKey, keyLength, validationData, validationDataLength, NULL, mac);
		receiptLength = 16;
	}
	else {
		OPGP_ERROR_CREATE_ERROR(status, GP211_ERROR_INVALID_SCP, OPGP_stringify_error(GP211_ERROR_INVALID_SCP));
		goto end;
	}

	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	if (memcmp(mac, receipt, receiptLength) != 0) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_VALIDATION_FAILED, OPGP_stringify_error(OPGP_ERROR_VALIDATION_FAILED)); goto end; }
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("validate_receipt"), status);
	return status;
}

OPGP_ERROR_STATUS validate_delete_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
						 DWORD cardUniqueDataLength,
					   PBYTE receiptKey, DWORD keyLength, GP211_RECEIPT_DATA receiptData,
					   PBYTE AID, DWORD AIDLength, BYTE secureChannelProtocol)
{
	OPGP_ERROR_STATUS status;
	DWORD i=0;
	PBYTE validationData = NULL;
	DWORD validationDataLength;
	OPGP_LOG_START(_T("validate_delete_receipt"));
	validationDataLength = 1 + 2 + 1 + cardUniqueDataLength + 1 + AIDLength;
	validationData = (PBYTE)malloc(validationDataLength);
	if (validationData == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
		goto end;
	}

	validationData[i++] = 2;
	validationData[i++] = (BYTE)((confirmationCounter & 0x0000FF00) >> 8);
	validationData[i++] = (BYTE)(confirmationCounter & 0x000000FF);
	validationData[i++] = (BYTE)cardUniqueDataLength;
	memcpy(validationData, cardUniqueData, cardUniqueDataLength);
	i+=cardUniqueDataLength;
	validationData[i++] = (BYTE)AIDLength;
	memcpy(validationData, AID, AIDLength);
	i+=AIDLength;
	status = validate_receipt(validationData, validationDataLength, receiptData.receipt, receiptKey, keyLength, secureChannelProtocol);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	if (validationData) {
		free(validationData);
	}
	OPGP_LOG_END(_T("validate_delete_receipt"), status);
	return status;
}

/**
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param data [in] The data to encrypt.
 * \param dataLength [in] The data length.
 * \param encryptedData [out] The encrypted data. No length checking is done. The buffer must have sufficient size, e.g. the next block size or twice the data size if unsure.
 * \param encryptedDataLength [out] The length of the encrypted data.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS encrypt_sensitive_data(GP211_SECURITY_INFO *secInfo,
	PBYTE data,
	DWORD dataLength,
	PBYTE encryptedData,
	PDWORD encryptedDataLength) {
	OPGP_ERROR_STATUS status;
	OPGP_LOG_START(_T("encrypt_sensitive_data"));
	// sensitive - encrypt
	// Initiation mode implicit
	if (secInfo->secureChannelProtocol == GP211_SCP02 && (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0B
		|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1B
		|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1A
		|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0A)) {
		status = calculate_enc_cbc_SCP02(secInfo->dataEncryptionSessionKey, data, dataLength, encryptedData, encryptedDataLength);
	}
	else if (secInfo->secureChannelProtocol == GP211_SCP03) {
		status = calculate_enc_cbc_SCP03_min_padding(secInfo->dataEncryptionSessionKey, secInfo->keyLength, data, dataLength, (PBYTE)SCP03_ICV, encryptedData, encryptedDataLength);
	}
	else {
		// same for SCP01 and SCP02 in explicit mode
		status = calculate_enc_ecb_two_key_triple_des(secInfo->dataEncryptionSessionKey, data, dataLength, encryptedData, encryptedDataLength);
	}
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("encrypt_sensitive_data"), status);
	return status;
}

/**
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param keyType [in] The key type. See GP211_KEY_TYPE_AES.
 * \param keyData [in] The key data.
 * \param keyDataLength [in] The key data length.
 * \param keyCheckValue [out] The key check value.
  * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_key_check_value(GP211_SECURITY_INFO *secInfo,
	BYTE keyType,
	PBYTE keyData,
	DWORD keyDataLength,
	BYTE keyCheckValue[3]) {
	OPGP_ERROR_STATUS status;
	BYTE dummy[16];
	DWORD dummyLength;
	BYTE keyCheckTest[16];
	OPGP_LOG_START(_T("calculate_key_check_value"));
	memset(keyCheckTest, 0, 16);
	if (secInfo->secureChannelProtocol == GP211_SCP03 || keyType == GP211_KEY_TYPE_AES) {
		memset(keyCheckTest, 0x01, sizeof(keyCheckTest));
		status = calculate_enc_ecb_SCP03(keyData, keyDataLength, keyCheckTest, 16, dummy, &dummyLength);
	}
	else {
		status = calculate_enc_ecb_two_key_triple_des(keyData, keyCheckTest, 8, dummy, &dummyLength);
	}
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	memcpy(keyCheckValue, dummy, 3);
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("calculate_key_check_value"), status);
	return status;
}

OPGP_ERROR_STATUS get_key_data_field(GP211_SECURITY_INFO *secInfo,
							 PBYTE keyData,
							 DWORD keyDataLength,
							 BYTE keyType,
							 BYTE isSensitive,
							 PBYTE keyDataField,
							 PDWORD keyDataFieldLength,
							 BYTE keyCheckValue[3]) {
	OPGP_ERROR_STATUS status;
	DWORD sizeNeeded=0, i=0;
	BYTE encrypted_key[32];
	DWORD encrypted_key_length;
	BYTE keyCheckTest[16];
	OPGP_LOG_START(_T("get_key_data_field"));
	memset(keyCheckTest, 0, 16);
	// key type + length + key data + length + key check value
	sizeNeeded = 1 + 1 + keyDataLength + 1;
	if (secInfo->secureChannelProtocol == GP211_SCP03 || keyType == GP211_KEY_TYPE_AES) {
		// the length of the key component is always included
		sizeNeeded++;
	}
	if (isSensitive) {
		// 3 byte key check value
		sizeNeeded+=3;
	}
	if (sizeNeeded > *keyDataFieldLength) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER));
		goto end;
	}
	// set key type
	keyDataField[i++] = keyType;
	if (isSensitive) {
		status = encrypt_sensitive_data(secInfo, keyData, keyDataLength, encrypted_key, &encrypted_key_length);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
		if (encrypted_key_length != keyDataLength || secInfo->secureChannelProtocol == GP211_SCP03 || keyType == GP211_KEY_TYPE_AES) {
			// + 1 byte key component length field
			keyDataField[i++] = encrypted_key_length + 1;
			keyDataField[i++] = keyDataLength;
		}
		else {
			// not padded and no length must be specified
			keyDataField[i++] = encrypted_key_length;
		}
		memcpy(keyDataField+i, encrypted_key, encrypted_key_length);
		i+= encrypted_key_length;
	}
	else {
		keyDataField[i++] = (BYTE)keyDataLength;
		// not sensitive - copy directly, no key component length is needed
		memcpy(keyDataField+i, keyData, keyDataLength);
		i+=keyDataLength;
	}
	// we always use key check values
	keyDataField[i++] = 0x03; // length of key check value
	status = calculate_key_check_value(secInfo, keyType, keyData, keyDataLength, keyCheckValue);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	memcpy(keyDataField+i, keyCheckValue, 3);
	i+=3;
	*keyDataFieldLength = i;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("get_key_data_field"), status);
	return status;
}

/**
 * Wraps a APDU with the necessary security information according to secInfo.
 * The wrappedapduCommand must be a buffer with enough space for the potential added padding for the encryption
 * and the MAC. The maximum possible extra space to the apduCommandLength is 8 bytes for the MAC plus 7 bytes for padding
 * and one Lc byte in the encryption process.
 * \param apduCommand [in] The command APDU.
 * \param apduCommandLength [in] The length of the command APDU.
 * \param wrappedApduCommand [out] The buffer for the wrapped APDU command.
 * \param wrappedApduCommandLength [in, out] The available and returned modified length of the wrappedApduCommand buffer.
 * \param *secInfo [in] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS wrap_command(PBYTE apduCommand, DWORD apduCommandLength, PBYTE wrappedApduCommand, PDWORD wrappedApduCommandLength, GP211_SECURITY_INFO *secInfo) {
	OPGP_ERROR_STATUS status;
	BYTE lc = 0, le =0 ;
	DWORD wrappedLength;
	BYTE mac[16]; // only first 8 bytes used by SCP01/02
	// 8 bytes reserved for MAC
	BYTE encryption[247];
	DWORD encryptionLength = 247;
	BYTE caseAPDU;
	BYTE C_MAC_ICV[8];
	DWORD C_MAC_ICVLength = 8;
	BYTE ENC_ICV[32] = {0};
	// padding is only needed for encryption
	DWORD paddingSize = 0;
	DWORD blockSize = 8;
	OPGP_LOG_START(_T("wrap_command"));
	if (*wrappedApduCommandLength < apduCommandLength)
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
	memmove(wrappedApduCommand, apduCommand, apduCommandLength);

	// trivial case, just return
	if (secInfo == NULL || secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_NO_SECURE_MESSAGING
			|| secInfo->securityLevel == GP211_SCP01_SECURITY_LEVEL_NO_SECURE_MESSAGING
		|| secInfo->securityLevel == GP211_SCP03_SECURITY_LEVEL_NO_SECURE_MESSAGING) {
		*wrappedApduCommandLength = apduCommandLength;
		{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
	}

	if (parse_apdu_case(apduCommand, apduCommandLength, &caseAPDU, &lc, &le)) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND, OPGP_stringify_error(OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND)); goto end; }
	}

	switch(caseAPDU) {
		case 1:
		case 2:
			wrappedLength = 4;
			break;
		case 3:
		case 4:
			wrappedLength = lc + 5;
			break;
	}

	/*
	 * Philip Wendland: Check max length of APDU for Security Level 3.
	 * Added SCP03 stuff.
	 * Note: SCP03 AES uses padding to 16 bytes * X. The pad is bigger.
	 */
	if (((lc > 0 && secInfo->secureChannelProtocol == GP211_SCP01 && secInfo->securityLevel == GP211_SCP01_SECURITY_LEVEL_C_DEC_C_MAC)
		|| (secInfo->secureChannelProtocol == GP211_SCP02 &&
			(secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC
					|| secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC))
		|| (lc > 0 && secInfo->secureChannelProtocol == GP211_SCP03
				&& (secInfo->securityLevel == GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC
						|| secInfo->securityLevel == GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC
						|| secInfo->securityLevel == GP211_SCP03_SECURITY_LEVEL_C_DEC_R_ENC_C_MAC_R_MAC)))
			) {

		if (secInfo->secureChannelProtocol == GP211_SCP03) {
			blockSize = 16;
		}
		// compute size of APDU with enc padding + MAC
		// padding 0x80 at least added or in SCP a length byte is prepended
		paddingSize = ((blockSize - ((lc + 1) % blockSize)) % blockSize) + 1;
	}
	// add padding + 8 byte MAC
	wrappedLength += paddingSize + 8;
	// there was no body before, add LC field length
	if (caseAPDU == 1 || caseAPDU == 2) {
		wrappedLength++;
	}
	if (*wrappedApduCommandLength < wrappedLength) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER));
		goto end;
	}
	// C_MAC on modified APDU
	// Philip Wendland: Update the APDU header first, calculate MAC then.
	if ((secInfo->secureChannelProtocol == GP211_SCP02 &&
			(secInfo->secureChannelProtocolImpl & 0x02) == 0)
		|| secInfo->secureChannelProtocol == GP211_SCP03
		|| secInfo->secureChannelProtocol == GP211_SCP01) {
		switch (caseAPDU) {
			case 1:
			case 2: {
				wrappedApduCommand[4] = 0x08;
				break;
			}
			case 3:
			case 4: {
				wrappedApduCommand[4] += 8;
				break;
			}
		}
		// CLA - indicate security level 1 or 3
		wrappedApduCommand[0] = apduCommand[0] | 0x04;
	}

	if (secInfo->secureChannelProtocol == GP211_SCP02) {
		// ICV set to MAC over AID
		if ((secInfo->secureChannelProtocolImpl & 0x08) != 0) {
			memcpy(C_MAC_ICV, secInfo->lastC_MAC, 8);
		}
		// ICV encryption
		if ((secInfo->secureChannelProtocolImpl & 0x10) != 0) {
			 status = calculate_enc_ecb_single_des(secInfo->C_MACSessionKey,
				 secInfo->lastC_MAC, 8, C_MAC_ICV, &C_MAC_ICVLength);
			if (OPGP_ERROR_CHECK(status)) {
				goto end;
			}
		}
	// Philip Wendland: added SCP01 check as this would apply to SCP03 otherwise.
	} else if (secInfo->secureChannelProtocol == GP211_SCP01){
		if (secInfo->secureChannelProtocolImpl == GP211_SCP01_IMPL_i15) {
			status = calculate_enc_ecb_two_key_triple_des(secInfo->C_MACSessionKey,
				secInfo->lastC_MAC, 8, C_MAC_ICV, &C_MAC_ICVLength);
			if (OPGP_ERROR_CHECK(status)) {
				goto end;
			}
		}
		else {
			memcpy(C_MAC_ICV, secInfo->lastC_MAC, 8);
		}
	}
	// MAC calculation
	if (secInfo->secureChannelProtocol == GP211_SCP02) {
		status = calculate_MAC_des_3des(secInfo->C_MACSessionKey, wrappedApduCommand, wrappedLength-paddingSize-8,
			C_MAC_ICV, mac);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
	}
	// Philip Wendland: Added SCP01 check as this would apply to SCP03 otherwise.
	else if (secInfo->secureChannelProtocol == GP211_SCP01) {
		status = calculate_MAC(secInfo->C_MACSessionKey, wrappedApduCommand, wrappedLength-paddingSize-8,
			C_MAC_ICV, mac);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
	} else if (secInfo->secureChannelProtocol == GP211_SCP03) {
		// Philip Wendland: Added SCP03 C-MAC calculation.

		// SCP03 with encryption encrypts FIRST, calculates MAC AFTERWARDS
		if (secInfo->securityLevel == GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC
				|| secInfo->securityLevel == GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC
				|| secInfo->securityLevel == GP211_SCP03_SECURITY_LEVEL_C_DEC_R_ENC_C_MAC_R_MAC) {
			if (caseAPDU != 1 && caseAPDU != 2) {
				status = calculate_enc_icv_SCP03(secInfo->encryptionSessionKey, secInfo->keyLength,
						secInfo->sessionEncryptionCounter, ENC_ICV, 0);
				if (OPGP_ERROR_CHECK(status)) {
					goto end;
				}
				status = calculate_enc_cbc_SCP03(secInfo->encryptionSessionKey, secInfo->keyLength,
						wrappedApduCommand+5, wrappedLength-5-paddingSize-8, ENC_ICV, encryption, &encryptionLength);
				if (OPGP_ERROR_CHECK(status)) {
					goto end;
				}
				memcpy(wrappedApduCommand+5, encryption, encryptionLength);
				wrappedApduCommand[4] += paddingSize;
			}
			secInfo->sessionEncryptionCounter++;
		}
		// wrappedLength-8: exclude size of MAC for CMAC
		status = calculate_CMAC_aes(secInfo->C_MACSessionKey, secInfo->keyLength, wrappedApduCommand, wrappedLength-8, secInfo->lastC_MAC, mac);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
	}
	/* C_MAC on unmodified APDU */
	if (secInfo->secureChannelProtocol == GP211_SCP02 &&
			(secInfo->secureChannelProtocolImpl & 0x02) != 0) {
		switch (caseAPDU) {
			case 1:
			case 2: {
				wrappedApduCommand[4] = 0x08;
				break;
			}
			case 3:
			case 4: {
				wrappedApduCommand[4]+=8;
				break;
			}
		} // switch (caseAPDU)
		wrappedApduCommand[0] = apduCommand[0] | 0x04;
	}
	if (secInfo->secureChannelProtocol != GP211_SCP03) {
		OPGP_LOG_HEX(_T("wrap_command: ICV for MAC: "), C_MAC_ICV, 8);
		OPGP_LOG_HEX(_T("wrap_command: Generated MAC: "), mac, 8);
	} else {
		OPGP_LOG_HEX(_T("wrap_command: ICV for MAC: "), secInfo->lastC_MAC, 16);
		OPGP_LOG_HEX(_T("wrap_command: Generated MAC: "), mac, 16);
	}

	// Philip Wendland: added SCP03 case
	if (secInfo->secureChannelProtocol != GP211_SCP03) {
		memcpy(secInfo->lastC_MAC, mac, 8);
	} else {
		memcpy(secInfo->lastC_MAC, mac, 16);
	}
	memcpy(wrappedApduCommand+wrappedLength-8, mac, 8);

	// Philip Wendland: if we have to encrypt for SCP01 and SCP02:
	if (secInfo->secureChannelProtocol != GP211_SCP03
		&& (
			(secInfo->secureChannelProtocol == GP211_SCP01 && secInfo->securityLevel == GP211_SCP01_SECURITY_LEVEL_C_DEC_C_MAC)
			|| (secInfo->secureChannelProtocol == GP211_SCP02 &&
					(secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC
					|| secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC))
			)
			// SCP01 does not encrypt if no data is contained
			&& !(secInfo->secureChannelProtocol == GP211_SCP01 && lc == 0)) {
		if (secInfo->secureChannelProtocol == GP211_SCP02) {
			status = calculate_enc_cbc_SCP02(secInfo->encryptionSessionKey,
				wrappedApduCommand+5, lc, encryption, &encryptionLength);
			if (OPGP_ERROR_CHECK(status)) {
				goto end;
			}
		}
		else {
			// SCP01 prepends a length byte
			BYTE wrappedLc = wrappedApduCommand[4];
			wrappedApduCommand[4] = lc;
			status = calculate_enc_cbc(secInfo->encryptionSessionKey,
				wrappedApduCommand+4, lc+1, encryption, &encryptionLength);
			if (OPGP_ERROR_CHECK(status)) {
				goto end;
			}
			wrappedApduCommand[4] = wrappedLc;
		}
		wrappedApduCommand[4] += paddingSize;
		memcpy(wrappedApduCommand + 5, encryption, encryptionLength);
		memcpy(wrappedApduCommand + encryptionLength + 5, mac, 8);
	}

	// Set Le
	if (caseAPDU == 2 || caseAPDU == 4) {
		if (*wrappedApduCommandLength < wrappedLength+1)
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
		wrappedApduCommand[wrappedLength] = le;
		wrappedLength++;
	}
	*wrappedApduCommandLength = wrappedLength;

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("wrap_command"), status);
	return status;
}

OPGP_ERROR_STATUS validate_install_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
						  DWORD cardUniqueDataLength,
					   PBYTE receiptKey, DWORD keyLength, GP211_RECEIPT_DATA receiptData,
					   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
					   PBYTE applicationAID, DWORD applicationAIDLength, BYTE secureChannelProtocol)
{
	OPGP_ERROR_STATUS status;
	DWORD i=0;
	PBYTE validationData;
	DWORD validationDataLength;
	OPGP_LOG_START(_T("validate_install_receipt"));
	validationDataLength = 1 + 2 + 1 + cardUniqueDataLength + 1 + executableLoadFileAIDLength + 1 + applicationAIDLength;
	validationData = (PBYTE)malloc(validationDataLength);
	if (validationData == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
		goto end;
	}

	validationData[i++] = 2;
	validationData[i++] = (BYTE)((confirmationCounter & 0x0000FF00) >> 8);
	validationData[i++] = (BYTE)(confirmationCounter & 0x000000FF);
	validationData[i++] = (BYTE)cardUniqueDataLength;
	memcpy(validationData, cardUniqueData, cardUniqueDataLength);
	i+=cardUniqueDataLength;
	validationData[i++] = (BYTE)executableLoadFileAIDLength;
	memcpy(validationData, executableLoadFileAID, executableLoadFileAIDLength);
	i+=executableLoadFileAIDLength;
	validationData[i++] = (BYTE)applicationAIDLength;
	memcpy(validationData, applicationAID, applicationAIDLength);
	i+=applicationAIDLength;
	status = validate_receipt(validationData, validationDataLength, receiptData.receipt, receiptKey, keyLength, secureChannelProtocol);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	if (validationData) {
		free(validationData);
	}
	OPGP_LOG_END(_T("validate_install_receipt"), status);
	return status;
}

OPGP_ERROR_STATUS validate_load_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
						   DWORD cardUniqueDataLength,
						   PBYTE receiptKey, DWORD keyLength, GP211_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE securityDomainAID, DWORD securityDomainAIDLength, BYTE secureChannelProtocol)
{
	OPGP_ERROR_STATUS status;
	PBYTE validationData = NULL;
	DWORD validationDataLength;
	DWORD i=0;
	OPGP_LOG_START(_T("validate_load_receipt"));
	validationDataLength = 1 + 2 + 1 + cardUniqueDataLength + 1 + executableLoadFileAIDLength + 1 + securityDomainAIDLength;
	validationData = (PBYTE)malloc(validationDataLength);
	if (validationData == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
		goto end;
	}

	validationData[i++] = 2;
	validationData[i++] = (BYTE)((confirmationCounter & 0x0000FF00) >> 8);
	validationData[i++] = (BYTE)(confirmationCounter & 0x000000FF);
	validationData[i++] = (BYTE)cardUniqueDataLength;
	memcpy(validationData, cardUniqueData, cardUniqueDataLength);
	i+=cardUniqueDataLength;
	validationData[i++] = (BYTE)executableLoadFileAIDLength;
	memcpy(validationData, executableLoadFileAID, executableLoadFileAIDLength);
	i+=executableLoadFileAIDLength;
	validationData[i++] = (BYTE)securityDomainAIDLength;
	memcpy(validationData, securityDomainAID, securityDomainAIDLength);
	i+=securityDomainAIDLength;
	status = validate_receipt(validationData, validationDataLength, receiptData.receipt, receiptKey, keyLength, secureChannelProtocol);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	if (validationData) {
		free(validationData);
	}
	OPGP_LOG_END(_T("validate_load_receipt"), status);
	return status;
}

/**
 * \brief Calculates a R-MAC.
 * \param apduCommand [in] The APDU command.
 * \param apduCommandLength [in] The APDU command length.
 * \param responseApdu [in] The APDU response APDU.
 * \param responseApduLength [in] The APDU response APDU length.
 * \param *secInfo [in] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param mac [out] The R-MAC.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_calculate_R_MAC(PBYTE apduCommand, DWORD apduCommandLength,
						   PBYTE responseApdu,
						   DWORD responseApduLength,
						   GP211_SECURITY_INFO *secInfo,
						   BYTE mac[8])
{
	OPGP_ERROR_STATUS status;
	BYTE r_MacData[261 + 258];
	DWORD offset=0;
	OPGP_LOG_START(_T("GP211_calculate_R_MAC"));
	if (secInfo->secureChannelProtocol == GP211_SCP02) {
		DWORD r_MacDataLength = sizeof(r_MacData);
		BYTE caseAPDU;
		BYTE lc;
		BYTE le;
		if (parse_apdu_case(apduCommand, apduCommandLength, &caseAPDU, &lc, &le)) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND, OPGP_stringify_error(OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND)); goto end; }
		}
		memcpy(r_MacData, apduCommand, 4);
		offset+=4;
		r_MacData[offset++] = lc;
		// copy data
		memcpy(r_MacData+offset, apduCommand+5, lc);
		offset+=lc;
		// if R-MAC exists
		if (responseApduLength >= 10) {
			r_MacData[offset++] = responseApduLength-10;
			memcpy(r_MacData+offset, responseApdu, responseApduLength-10);
			offset += responseApduLength - 10;
		}
		else {
			r_MacData[offset++] = 0;
		}
		// copy SW
		memcpy(r_MacData+offset, responseApdu+responseApduLength-2, 2);
		offset+=2;
		r_MacDataLength = offset;
		status = calculate_MAC_des_3des(secInfo->R_MACSessionKey, r_MacData, r_MacDataLength, secInfo->lastR_MAC, mac);
		if (OPGP_ERROR_CHECK(status))
			goto end;
		{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
	}
	if (secInfo->secureChannelProtocol == GP211_SCP03) {
		BYTE scp03_mac[16];
		memcpy(r_MacData, responseApdu, responseApduLength-10);
		offset+=responseApduLength-10;
		// append SW
		memcpy(r_MacData+offset, responseApdu+responseApduLength-2, 2);
		offset+=2;
		status = calculate_CMAC_aes(secInfo->R_MACSessionKey, secInfo->keyLength, r_MacData, offset, secInfo->lastC_MAC, scp03_mac);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
		memcpy(mac, scp03_mac, 8);
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("GP211_calculate_R_MAC"), status);
	return status;
}

/**
 * \param apduCommand [in] The command APDU.
 * \param apduCommandLength [in] The length of the command APDU.
 * \param responseApdu [in] The response data.
 * \param responseApduLength [in] The length of the response data.
 * \param unwrappedResponseApdu [out] The buffer for the unwrapped response APDU.
 * \param unwrappedResponseApduLength [in, out] The available and returned modified length of the unwrappedResponseAPDU buffer.
 * \param *secInfo [in] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS unwrap_command(PBYTE apduCommand, DWORD apduCommandLength, PBYTE responseApdu,
				 DWORD responseApduLength, PBYTE unwrappedResponseApdu,
				 PDWORD unwrappedResponseApduLength, GP211_SECURITY_INFO *secInfo) {
	OPGP_ERROR_STATUS status;
	// 8 bytes reserved for MAC - 1 bytes for 0x80 padding at least
	BYTE decryption[246];
	DWORD decryptionLength = 246;
	BYTE ENC_ICV[16] = {0};
	DWORD sw;

	status = GP211_check_R_MAC(apduCommand, apduCommandLength, responseApdu, responseApduLength, unwrappedResponseApdu,
			unwrappedResponseApduLength, secInfo);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	// decrypt for SCP03
	sw = get_short(responseApdu, responseApduLength-2);
	if (secInfo != NULL && secInfo->secureChannelProtocol == GP211_SCP03 &&
			secInfo->securityLevel == GP211_SCP03_SECURITY_LEVEL_C_DEC_R_ENC_C_MAC_R_MAC
			// more than status words
			&& responseApduLength > 2
			// SCP03:	No R-MAC shall be generated and no protection shall be applied to a response that includes an error status
			//word: in this case only the status word shall be returned in the response. All status words except '9000' and
			//warning status words (i.e. '62xx' and '63xx') shall be interpreted as error status words.
			&& (sw == 0x9000 || (sw >> 8) == 0x62 || (sw >> 8) == 0x63)
	) {

        // After GP211_check_R_MAC:
        //   unwrappedResponseApdu = [ciphertext][SW1][SW2]
        //   *unwrappedResponseApduLength = cipherLen + 2
        if (*unwrappedResponseApduLength < 2) {
            OPGP_ERROR_CREATE_ERROR(status,
                OPGP_ERROR_INSUFFICIENT_BUFFER,
                OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER));
            goto end;
        }

        DWORD cipherLen = *unwrappedResponseApduLength - 2;

        // calculate ICV for R-ENC
		status = calculate_enc_icv_SCP03(secInfo->encryptionSessionKey, secInfo->keyLength, secInfo->sessionEncryptionCounter - 1, ENC_ICV, 1);

        if (OPGP_ERROR_CHECK(status)) {
            goto end;
        }

        // decrypt just ciphertext (without SW)
		status = calculate_dec_cbc_SCP03(secInfo->encryptionSessionKey, secInfo->keyLength, unwrappedResponseApdu,
				cipherLen, ENC_ICV, decryption, &decryptionLength);

        if (OPGP_ERROR_CHECK(status)) {
            goto end;
        }

        // buffer overflow check (plaintext + SW)
        if (*unwrappedResponseApduLength < decryptionLength + 2) {
            OPGP_ERROR_CREATE_ERROR(status,
                OPGP_ERROR_INSUFFICIENT_BUFFER,
                OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER));
            goto end;
        }

        // copy plaintext
        memcpy(unwrappedResponseApdu, decryption, decryptionLength);

        // attach SW at the end of plaintext (from original response)  and set correct length
        unwrappedResponseApdu[decryptionLength]     = (BYTE)(sw >> 8);
        unwrappedResponseApdu[decryptionLength + 1] = (BYTE)(sw & 0xFF);

        *unwrappedResponseApduLength = decryptionLength + 2;

    }

    { OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
    OPGP_LOG_END(_T("unwrap_command"), status);
    return status;
}

/**
 * \param apduCommand [in] The command APDU.
 * \param apduCommandLength [in] The length of the command APDU.
 * \param responseApdu [in] The response APDU.
 * \param responseApduLength [in] The length of the response APDU.
 * \param unwrappedResponseApdu [out] The buffer for the unwrapped response APDU.
 * \param unwrappedResponseApduLength [in, out] The available and returned modified length of the unwrappedResponseAPDU buffer.
 * \param *secInfo [in] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_check_R_MAC(PBYTE apduCommand, DWORD apduCommandLength,
		PBYTE responseApdu, DWORD responseApduLength,
				 PBYTE unwrappedResponseApdu, PDWORD unwrappedResponseApduLength,
				 GP211_SECURITY_INFO *secInfo) {
	OPGP_ERROR_STATUS status;
	BYTE mac[8];
	DWORD sw;
	OPGP_LOG_START(_T("GP211_check_R_MAC"));

	// trivial case, just return
	if (secInfo == NULL || secInfo->secureChannelProtocol == 0 || secInfo->secureChannelProtocol == GP211_SCP01
			|| (secInfo->secureChannelProtocol == GP211_SCP02 && (secInfo->securityLevel != GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC) &&
		(secInfo->securityLevel != GP211_SCP02_SECURITY_LEVEL_R_MAC) &&
		(secInfo->securityLevel != GP211_SCP02_SECURITY_LEVEL_C_MAC_R_MAC))
			||
			(secInfo->secureChannelProtocol == GP211_SCP03 && (secInfo->securityLevel != GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC) &&
					(secInfo->securityLevel != GP211_SCP03_SECURITY_LEVEL_C_DEC_R_ENC_C_MAC_R_MAC) &&
					(secInfo->securityLevel != GP211_SCP03_SECURITY_LEVEL_C_MAC_R_MAC))) {
		if (*unwrappedResponseApduLength < responseApduLength)
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
		memmove(unwrappedResponseApdu, responseApdu, responseApduLength);
		*unwrappedResponseApduLength = responseApduLength;
		{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
	}
	sw = get_short(responseApdu, responseApduLength-2);
// SCP03:	No R-MAC shall be generated and no protection shall be applied to a response that includes an error status
//word: in this case only the status word shall be returned in the response. All status words except '9000' and
//warning status words (i.e. '62xx' and '63xx') shall be interpreted as error status words.
	if ((sw == 0x9000 || (sw >> 8) == 0x62 || (sw >> 8) == 0x63) || secInfo->secureChannelProtocol != GP211_SCP03) {
		GP211_calculate_R_MAC(apduCommand, apduCommandLength, responseApdu, responseApduLength, secInfo, mac);
	#ifdef OPGP_DEBUG
		OPGP_LOG_HEX(_T("check_R_MAC: received R-MAC: "), responseApdu+responseApduLength-10, 8);
		OPGP_LOG_HEX(_T("check_R_MAC: calculated R-MAC: "), mac, 8);
	#endif
		if (memcmp(mac, responseApdu+responseApduLength-10, 8)) {
			OPGP_ERROR_CREATE_ERROR(status, GP211_ERROR_VALIDATION_R_MAC, OPGP_stringify_error(GP211_ERROR_VALIDATION_R_MAC));
			goto end;
		}
		memcpy(secInfo->lastR_MAC, mac, 8);
		// remove R-MAC
		if (*unwrappedResponseApduLength < responseApduLength - 8)
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
		// - 8 bytes for MAC and 2 bytes for SW
		// use memmove, because the buffer may overlap
		memmove(unwrappedResponseApdu, responseApdu, responseApduLength - 10);
		// append SW
		memmove(unwrappedResponseApdu + responseApduLength - 10, responseApdu + responseApduLength - 2, 2);
		*unwrappedResponseApduLength = responseApduLength - 8;
	}
	else {
		memmove(unwrappedResponseApdu, responseApdu, responseApduLength);
		*unwrappedResponseApduLength = responseApduLength;
	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("GP211_check_R_MAC"), status);
	return status;
}

/**
 * \param PEMKeyFileName [in] The key file.
 * \param *passPhrase [in] The passphrase. Must be an ASCII string.
 * \param rsaModulus [out] The RSA modulus.
 * \param rsaExponent [out] The RSA exponent.
 */
OPGP_ERROR_STATUS read_public_rsa_key(OPGP_STRING PEMKeyFileName, char *passPhrase, BYTE rsaModulus[128], LONG *rsaExponent) {
	OPGP_ERROR_STATUS status;
	EVP_PKEY *key = NULL;
	FILE *PEMKeyFile = NULL;
#ifndef OPENSSL3
	RSA* rsa = NULL;
#endif
	BIGNUM *n;
    BIGNUM *e;
    BYTE eLength;
    int nLength;
#ifdef OPENSSL3
    OSSL_PARAM *params;
    OSSL_PARAM *_n;
	OSSL_PARAM *_e;
#endif
	OPGP_LOG_START(_T("read_public_rsa_key"));
	if (passPhrase == NULL)
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_PASSWORD, OPGP_stringify_error(OPGP_ERROR_INVALID_PASSWORD)); goto end; }
	if ((PEMKeyFileName == NULL) || (_tcslen(PEMKeyFileName) == 0))
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_FILENAME, OPGP_stringify_error(OPGP_ERROR_INVALID_FILENAME)); goto end; }
	PEMKeyFile = _tfopen(PEMKeyFileName, _T("rb"));
	if (PEMKeyFile == NULL) {
		{ OPGP_ERROR_CREATE_ERROR(status, errno, OPGP_stringify_error(errno)); goto end; }
	}
	key = EVP_PKEY_new();
	if (!PEM_read_PUBKEY(PEMKeyFile, &key, NULL, passPhrase)) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	};
#ifndef OPENSSL3
	rsa = EVP_PKEY_get1_RSA(key);
	if (rsa == NULL) {
        { OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	#if OPENSSL_VERSION_NUMBER < 0x10100000L
	n = rsa->n;
	e = rsa->e;
	*rsaExponent = (LONG)rsa->e->d[0];
	memcpy(rsaModulus, rsa->n->d, sizeof(unsigned long)*rsa->n->top);
	goto exit;
	#else
	RSA_get0_key(rsa, (const BIGNUM **)&n, (const BIGNUM **)&e, NULL);
	#endif
#else
	if (!EVP_PKEY_todata(key, EVP_PKEY_PUBLIC_KEY, &params)) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	_n = OSSL_PARAM_locate(params, "n");
	if (_n == NULL) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	_e = OSSL_PARAM_locate(params, "e");
	if (_e == NULL) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	n = BN_new();
	if (n == NULL || !OSSL_PARAM_get_BN(_n, &n)) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	e = BN_new();
	if (e == NULL || !OSSL_PARAM_get_BN(_e, &e)) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
#endif
    // only 3 and 65537 supported
    eLength = BN_num_bytes(e);
    if (eLength > sizeof(LONG)) {
    	{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
    }
    {
      unsigned char rsaTmp[sizeof(LONG)];
      if (BN_bn2bin(e, rsaTmp) != eLength) {
	{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
      }
      *rsaExponent = get_number(rsaTmp, 0, eLength);
    }
    nLength = BN_num_bytes(n);
    if (nLength != 128) {
        { OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
    }
    BN_bn2bin(n, rsaModulus);
#ifndef OPENSSL3
#if OPENSSL_VERSION_NUMBER < 0x10100000L
exit:
#endif
#endif
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
#ifndef OPENSSL3
    if (rsa != NULL) {
    	RSA_free(rsa);
    }
#else
    if (params != NULL) {
        OSSL_PARAM_free(params);
    }
    if (e != NULL) {
        BN_free(e);
    }
    if (n != NULL) {
        BN_free(n);
    }
#endif
    if (key != NULL) {
        EVP_PKEY_free(key);
    }
    if (PEMKeyFile != NULL) {
        fclose(PEMKeyFile);
    }
	OPGP_LOG_END(_T("read_public_rsa_key"), status);
	return status;
}

/**
 * \param message [in] The message to generate the hash for.
 * \param messageLength [in] The length of the message buffer.
 * \param hash [out] The calculated hash.
 * \param md [in] The message digest to use.
 */
OPGP_ERROR_STATUS calculate_hash(PBYTE message, DWORD messageLength, BYTE hash[32], const EVP_MD *md) {
	int result;
	OPGP_ERROR_STATUS status;
	EVP_MD_CTX *mdctx;
	OPGP_LOG_START(_T("calculate_hash"));
	mdctx = EVP_MD_CTX_create();
	EVP_MD_CTX_init(mdctx);
	result = EVP_DigestInit_ex(mdctx, md, NULL);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}

	result = EVP_DigestUpdate(mdctx, message, messageLength);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}

	result = EVP_DigestFinal_ex(mdctx, hash, NULL);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	EVP_MD_CTX_destroy(mdctx);
	OPGP_LOG_END(_T("calculate_hash"), status);
	return status;
}

/**
 * \param message [in] The message to generate the hash for.
 * \param messageLength [in] The length of the message buffer.
 * \param hash [out] The calculated hash.
 * \param hashLength [in] The hash length for SCP03: 32 for AES-128, 48 for AES-192, 64 for AES-256.
 */
OPGP_ERROR_STATUS calculate_sha2_hash(PBYTE message, DWORD messageLength, BYTE hash[64], DWORD hashLength) {
	return calculate_hash(message, messageLength, hash,
			hashLength == 32 ? EVP_sha256() :
					(hashLength == 48 ? EVP_sha384() : EVP_sha512()));
}

/**
 * \param message [in] The message to generate the hash for.
 * \param messageLength [in] The length of the message buffer.
 * \param hash [out] The calculated hash.
 */
OPGP_ERROR_STATUS calculate_sha1_hash(PBYTE message, DWORD messageLength, BYTE hash[20]) {
	return calculate_hash(message, messageLength, hash, EVP_sha1());
}

/**
 * \param key [in] A 3DES key used to sign. For DES the right half of the key is used.
 * \param *message [in] The message to authenticate.
 * \param messageLength [in] The message length.
 * \param mac [out] The calculated MAC.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_MAC_right_des_3des(BYTE key[16], BYTE *message, DWORD messageLength, BYTE mac[8])
{
	int result;
	OPGP_ERROR_STATUS status;
	int i;
	int outl;
	BYTE des_key[8];
	EVP_CIPHER_CTX_define;
	OPGP_LOG_START(_T("calculate_MAC_des_final_3des"));
	ctx = EVP_CIPHER_CTX_create;
	EVP_CIPHER_CTX_init(ctx);
// DES CBC mode
	memcpy(des_key, key+8, 8);
	result = EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, des_key, ICV);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(ctx, mac,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
	}
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	result = EVP_EncryptFinal_ex(ctx, mac, &outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}

    EVP_CIPHER_CTX_free(ctx);
    ctx = EVP_CIPHER_CTX_create;
	EVP_CIPHER_CTX_init(ctx);

	// 3DES CBC mode
	result = EVP_EncryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, key, ICV);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(ctx, mac,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
	}
	result = EVP_EncryptUpdate(ctx, mac,
		&outl, PADDING, 8 - (messageLength%8));
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	result = EVP_EncryptFinal_ex(ctx, mac,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
    EVP_CIPHER_CTX_free(ctx);
	OPGP_LOG_END(_T("calculate_MAC_des_final_3des"), status);
	return status;
}

/**
 * \param *random [out] The random to generate.
 * \param randomLength [in] The random length to generate.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS get_random(BYTE *random, int randomLength)
{
	OPGP_ERROR_STATUS status;
	int result;
	OPGP_LOG_START(_T("get_random"));
	result = RAND_bytes(random, randomLength);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("get_random"), status);
	return status;
}

