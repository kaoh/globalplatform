/*  Copyright (c) 2009, Karsten Ohme
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


/**
 * Calculates the encryption of a message in CBC mode for SCP02.
 * Pads the message with 0x80 and additional 0x00 until message length is a multiple of 8.
 * \param key[16] [in] A 3DES key used to encrypt.
 * \param *message [in] The message to encrypt.
 * \param messageLength [in] The length of the message.
 * \param *encryption [out] The encryption.
 * \param *encryptionLength [out] The length of the encryption.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_enc_cbc_SCP02(BYTE key[16], BYTE *message, int messageLength,
							  BYTE *encryption, int *encryptionLength) {
	OPGP_ERROR_STATUS status;
	int result;
	int i,outl;
	EVP_CIPHER_CTX ctx;
	OPGP_LOG_START(_T("calculate_enc_cbc_SCP02"));
	EVP_CIPHER_CTX_init(&ctx);
	*encryptionLength = 0;

	result = EVP_EncryptInit_ex(&ctx, EVP_des_ede_cbc(), NULL, key, icv);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;
	}
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;
	}
	result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
		&outl, padding, 8 - (messageLength%8));
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*encryptionLength+=outl;
	result = EVP_EncryptFinal_ex(&ctx, encryption+*encryptionLength,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*encryptionLength+=outl;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); }
	}

	OPGP_LOG_END(_T("calculate_enc_cbc_SCP02"), status);
	return status;
}

/**
 * Calculates the card cryptogram for SCP01.
 * \param S_ENCSessionKey[16] [in] The S-ENC Session Key for calculating the card cryptogram.
 * \param cardChallenge[8] [in] The card challenge.
 * \param hostChallenge[8] [in] The host challenge.
 * \param cardCryptogram[8] [out] The calculated card cryptogram.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_card_cryptogram_SCP01(BYTE S_ENCSessionKey[16], BYTE cardChallenge[8],
									  BYTE hostChallenge[8], BYTE cardCryptogram[8]) {
	OPGP_ERROR_STATUS status;
	BYTE message[16];
	OPGP_LOG_START(_T("calculate_card_cryptogram_SCP01"));
	memcpy(message, hostChallenge, 8);
	memcpy(message+8, cardChallenge, 8);
	status = calculate_MAC(S_ENCSessionKey, message, 16, (PBYTE)icv, cardCryptogram);
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
 * \param S_ENCSessionKey[16] [in] The S-ENC Session Key for calculating the card cryptogram.
 * \param sequenceCounter[2] [in] The sequence counter.
 * \param cardChallenge[6] [in] The card challenge.
 * \param hostChallenge[8] [in] The host challenge.
 * \param cardCryptogram[8] [out] The calculated card cryptogram.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_card_cryptogram_SCP02(BYTE S_ENCSessionKey[16],
											BYTE sequenceCounter[2],
											BYTE cardChallenge[6],
											BYTE hostChallenge[8],
											BYTE cardCryptogram[8]) {
	OPGP_ERROR_STATUS status;
	BYTE message[16];
	OPGP_LOG_START(_T("calculate_card_cryptogram_SCP02"));
	memcpy(message, hostChallenge, 8);
	memcpy(message+8, sequenceCounter, 2);
	memcpy(message+10, cardChallenge, 6);
	status = calculate_MAC(S_ENCSessionKey, message, 16, (PBYTE)icv, cardCryptogram);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("calculate_card_cryptogram_SCP02"), status);
	return status;
}

/**
 * Calculates the host cryptogram for SCP01.
 * \param S_ENCSessionKey[16] [in] The S-ENC Session Key for calculating the card cryptogram.
 * \param cardChallenge[8] [in] The card challenge.
 * \param hostChallenge[8] [in] The host challenge.
 * \param cardCryptogram[8] [out] The calculated host cryptogram.
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
	status = calculate_MAC(S_ENCSessionKey, message, 16, (PBYTE)icv, hostCryptogram);
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
 * \param S_ENCSessionKey[16] [in] The S-ENC Session Key for calculating the card cryptogram.
 * \param sequenceCounter[2] [in] The sequence counter.
 * \param cardChallenge[6] [in] The card challenge.
 * \param hostChallenge[8] [in] The host challenge.
 * \param cardCryptogram[8] [out] The calculated host cryptogram.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_host_cryptogram_SCP02(BYTE S_ENCSessionKey[16],
											BYTE sequenceCounter[2],
											BYTE cardChallenge[6],
											BYTE hostChallenge[8],
											BYTE hostCryptogram[8]) {
	OPGP_ERROR_STATUS status;
	BYTE message[16];
	OPGP_LOG_START(_T("calculate_host_cryptogram_SCP02"));
	memcpy(message, sequenceCounter, 2);
	memcpy(message+2, cardChallenge, 6);
	memcpy(message+8, hostChallenge, 8);
	status = calculate_MAC(S_ENCSessionKey, message, 16, (PBYTE)icv, hostCryptogram);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("calculate_host_cryptogram_SCP02"), status);
	return status;
}

/**
 * Creates the session key for SCP01.
 * \param key[16] [in] The Secure Channel Encryption Key or Secure Channel Message
 * Authentication Code Key for calculating the corresponding session key.
 * \param cardChallenge[8] [in] The card challenge.
 * \param hostChallenge[8] [in] The host challenge.
 * \param sessionKey[8] [out] The calculated 3DES session key.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS create_session_key_SCP01(BYTE key[16], BYTE cardChallenge[8],
							   BYTE hostChallenge[8], BYTE sessionKey[16]) {
	OPGP_ERROR_STATUS status;
	BYTE derivation_data[16];
	int outl;

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
 * \param key[16] [in] The Secure Channel Encryption Key or Secure Channel Message
 * Authentication Code Key or Data Encryption Key for calculating the corresponding session key.
 * \param constant[2] [in] The constant for the corresponding session key.
 * \param sequenceCounter[2] [in] The sequence counter.
 * \param sessionKey[8] [out] The calculated 3DES session key.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS create_session_key_SCP02(BYTE key[16], BYTE constant[2],
									BYTE sequenceCounter[2], BYTE sessionKey[16]) {
	OPGP_ERROR_STATUS status;
	BYTE derivation_data[16];
	int outl;
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
 * Calculates the encryption of a message in ECB mode with two key triple DES.
 * Pads the message with 0x80 and additional 0x00 if message length is not a multiple of 8.
 * \param key[16] [in] A 3DES key used to encrypt.
 * \param *message [in] The message to encrypt.
 * \param messageLength [in] The length of the message.
 * \param *encryption [out] The encryption.
 * \param *encryptionLength [out] The length of the encryption.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_enc_ecb_two_key_triple_des(BYTE key[16], BYTE *message, int messageLength,
							  BYTE *encryption, int *encryptionLength) {
	int result;
	OPGP_ERROR_STATUS status;
	int i,outl;
	EVP_CIPHER_CTX ctx;
	OPGP_LOG_START(_T("calculate_enc_ecb_two_key_triple_des"));
	EVP_CIPHER_CTX_init(&ctx);
	*encryptionLength = 0;

	result = EVP_EncryptInit_ex(&ctx, EVP_des_ede(), NULL, key, icv);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;
	}
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;

		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, padding, 8 - (messageLength%8));
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;
	}
	result = EVP_EncryptFinal_ex(&ctx, encryption+*encryptionLength,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*encryptionLength+=outl;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); }
	}
	OPGP_LOG_END(_T("calculate_enc_ecb_two_key_triple_des"), status);
	return status;
}

/**
 * Calculates the encryption of a message in ECB mode with single DES.
 * Pads the message with 0x80 and additional 0x00 if message length is not a multiple of 8.
 * \param key[8] [in] A DES key used to encrypt.
 * \param *message [in] The message to encrypt.
 * \param messageLength [in] The length of the message.
 * \param *encryption [out] The encryption.
 * \param *encryptionLength [out] The length of the encryption.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_enc_ecb_single_des(BYTE key[8], BYTE *message, int messageLength,
							  BYTE *encryption, int *encryptionLength) {
	int result;
	OPGP_ERROR_STATUS status;
	int i,outl;
	EVP_CIPHER_CTX ctx;
	OPGP_LOG_START(_T("calculate_enc_ecb_single_des"));
	EVP_CIPHER_CTX_init(&ctx);
	*encryptionLength = 0;

	result = EVP_EncryptInit_ex(&ctx, EVP_des_ecb(), NULL, key, NULL);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;
	}
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;

		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, padding, 8 - (messageLength%8));
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;
	}
	result = EVP_EncryptFinal_ex(&ctx, encryption+*encryptionLength,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*encryptionLength+=outl;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); }
	}

	OPGP_LOG_END(_T("calculate_enc_ecb_single_des"), status);
	return status;
}

/**
 * Calculates a message authentication code.
 * Pads the message always with 0x80 and additional 0x00 until message length is a multiple of 8.
 * \param sessionKey[16] [in] A 3DES key used to sign.
 * \param *message [in] The message to authenticate.
 * \param messageLength [in] The message length.
 * \param icv[8] [in] The initial chaining vector.
 * \param mac[8] [out] The calculated MAC.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_MAC(BYTE sessionKey[16], BYTE *message, int messageLength,
						  BYTE icv[8], BYTE mac[8]) {
	LONG result;
	OPGP_ERROR_STATUS status;
	int i,outl;
	EVP_CIPHER_CTX ctx;
	OPGP_LOG_START(_T("calculate_MAC"));
	EVP_CIPHER_CTX_init(&ctx);

	result = EVP_EncryptInit_ex(&ctx, EVP_des_ede_cbc(), NULL, sessionKey, icv);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(&ctx, mac,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
	}
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, mac,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
	}
	result = EVP_EncryptUpdate(&ctx, mac,
		&outl, padding, 8 - (messageLength%8));
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	result = EVP_EncryptFinal_ex(&ctx, mac,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); }
	}

	OPGP_LOG_END(_T("calculate_MAC"), status);
	return status;
}

/**
 * Calculates the encryption of a message in CBC mode.
 * Pads the message with 0x80 and additional 0x00 if message length is not a multiple of 8.
 * \param key[16] [in] A 3DES key used to encrypt.
 * \param *message [in] The message to encrypt.
 * \param messageLength [in] The length of the message.
 * \param *encryption [out] The encryption.
 * \param *encryptionLength [out] The length of the encryption.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_enc_cbc(BYTE key[16], BYTE *message, int messageLength,
							  BYTE *encryption, int *encryptionLength) {
	LONG result;
	OPGP_ERROR_STATUS status;
	int i,outl;
	EVP_CIPHER_CTX ctx;
	OPGP_LOG_START(_T("calculate_enc_cbc"));
	EVP_CIPHER_CTX_init(&ctx);
	*encryptionLength = 0;

	result = EVP_EncryptInit_ex(&ctx, EVP_des_ede_cbc(), NULL, key, icv);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;
	}
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;

		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, padding, 8 - (messageLength%8));
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
		*encryptionLength+=outl;
	}
	result = EVP_EncryptFinal_ex(&ctx, encryption+*encryptionLength,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	*encryptionLength+=outl;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); }
	}

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
	EVP_MD_CTX mdctx;
	unsigned int signatureLength=0;
	OPGP_LOG_START(_T("calculate_rsa_signature"));
	EVP_MD_CTX_init(&mdctx);
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
	result = EVP_SignInit_ex(&mdctx, EVP_sha1(), NULL);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	result = EVP_SignUpdate(&mdctx, message, messageLength);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	if (EVP_PKEY_size(key) > 128) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
	}
	result = EVP_SignFinal(&mdctx, signature, &signatureLength, key);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if (EVP_MD_CTX_cleanup(&mdctx) != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); }
	}

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
 * and the the full key for the final operation.
 * Pads the message always with 0x80 and additional 0x00 until message length is a multiple of 8.
 * \param _3des_key[16] [in] A 3DES key used to sign.
 * \param *message [in] The message to authenticate.
 * \param messageLength [in] The message length.
 * \param initialICV[8] [in] The initial chaining vector.
 * \param mac[8] [out] The calculated MAC.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_MAC_des_3des(BYTE _3des_key[16], BYTE *message, int messageLength,
						  BYTE initialICV[8], BYTE mac[8]) {
	LONG result;
	OPGP_ERROR_STATUS status;
	int i,outl;
	EVP_CIPHER_CTX ctx;
	BYTE des_key[8];
	BYTE _icv[8];
	OPGP_LOG_START(_T("calculate_MAC_des_3des"));
	EVP_CIPHER_CTX_init(&ctx);
	if (initialICV == NULL) {
		memcpy(_icv, icv, 8);
	}
	else {
		memcpy(_icv, initialICV, 8);
	}
	/* If only one block */
	memcpy(mac, initialICV, 8);
//  DES CBC mode
	memcpy(des_key, _3des_key, 8);
	result = EVP_EncryptInit_ex(&ctx, EVP_des_cbc(), NULL, des_key, _icv);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(&ctx, mac,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
	}
	result = EVP_EncryptFinal_ex(&ctx, mac,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	result = EVP_CIPHER_CTX_cleanup(&ctx);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
//  3DES mode
	EVP_CIPHER_CTX_init(&ctx);
	result = EVP_EncryptInit_ex(&ctx, EVP_des_ede_cbc(), NULL, _3des_key, mac);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, mac,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
	}
	result = EVP_EncryptUpdate(&ctx, mac,
		&outl, padding, 8 - (messageLength%8));
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	result = EVP_EncryptFinal_ex(&ctx, mac,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); }
	}

	OPGP_LOG_END(_T("calculate_MAC_des_3des"), status);
	return status;
}


/**
 * GlobalPlatform2.1.1: Validates a Receipt.
 * Returns OPGP_ERROR_STATUS_SUCCESS if the receipt is valid.
 * \param validationData [in] The data used to validate the returned receipt.
 * \param validationDataLength [in] The length of the validationData buffer.
 * \param receipt [in] The receipt.
 * \param receiptKey [in] The 3DES key to generate the receipt.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS validate_receipt(PBYTE validationData, DWORD validationDataLength,
							 BYTE receipt[16], BYTE receiptKey[16])
{
	OPGP_ERROR_STATUS status;
	BYTE mac[8];
	OPGP_LOG_START(_T("validate_receipt"));
	status = calculate_MAC_des_3des(receiptKey, validationData, validationDataLength, (PBYTE)icv, mac);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	if (memcmp(mac, receipt, 8) != 0) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_VALIDATION_FAILED, OPGP_stringify_error(OPGP_ERROR_VALIDATION_FAILED)); goto end; }
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("validate_receipt"), status);
	return status;
}

OPGP_ERROR_STATUS validate_delete_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
							 DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE AID, DWORD AIDLength)
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
	status = validate_receipt(validationData, validationDataLength, receiptData.receipt, receiptKey);
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
	BYTE encrypted_key[24];
	int encrypted_key_length;
	BYTE dummy[16];
	int dummyLength;
	BYTE keyCheckTest[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	OPGP_LOG_START(_T("get_key_data_field"));
	// key type + length + key data + length + key check value
	sizeNeeded = 1 + 1 + keyDataLength + 1;
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
	keyDataField[i++] = (BYTE)keyDataLength;
	if (isSensitive) {
		// sensitive - encrypt
		// Initiation mode implicit
		if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0B
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1B
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1A
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0A) {
				status = calculate_enc_cbc_SCP02(secInfo->dataEncryptionSessionKey, keyData, keyDataLength, encrypted_key, &encrypted_key_length);
		}
		else {
			status = calculate_enc_ecb_two_key_triple_des(secInfo->dataEncryptionSessionKey, keyData, keyDataLength, encrypted_key, &encrypted_key_length);
		}
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
		// we assume that each key is a multiple of 8 bytes.
		memcpy(keyDataField+i, encrypted_key, keyDataLength);
		i+=keyDataLength;

	}
	else {
		// not sensitive - copy directly
		memcpy(keyDataField+i, keyData, keyDataLength);
		i+=keyDataLength;
	}
	// we always use key check values
	keyDataField[i++] = 0x03; // length of key check value
	status = calculate_enc_ecb_two_key_triple_des(keyData, keyCheckTest, 8, dummy, &dummyLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	memcpy(keyDataField+i, dummy, 3);
	memcpy(keyCheckValue, dummy, 3);
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
	BYTE lc;
	BYTE le = 0;
	DWORD wrappedLength;
	BYTE mac[8];
	BYTE encryption[240];
	int encryptionLength = 240;
	DWORD caseAPDU;
	BYTE C_MAC_ICV[8];
	int C_MAC_ICVLength = 8;
	OPGP_LOG_START(_T("wrap_command"));
	if (*wrappedApduCommandLength < apduCommandLength)
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
	memcpy(wrappedApduCommand, apduCommand, apduCommandLength);

	// no security level defined, just return
	if (secInfo == NULL) {
		*wrappedApduCommandLength = apduCommandLength;
		{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
	}

	// trivial case, just return
	if (secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_NO_SECURE_MESSAGING || secInfo->securityLevel == GP211_SCP01_SECURITY_LEVEL_NO_SECURE_MESSAGING) {
		*wrappedApduCommandLength = apduCommandLength;
		{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
	}

	// Determine which type of Exchange between the reader
	if (apduCommandLength == 4) {
	// Case 1 short
		wrappedLength = 4;
		caseAPDU = 1;
	} else if (apduCommandLength == 5) {
	// Case 2 short
		wrappedLength = 4;
		caseAPDU = 2;
		le = apduCommand[4];
	} else {
		lc = apduCommand[4];
		if ((convert_byte(lc) + 5) == apduCommandLength) {
		// Case 3 short
			wrappedLength = convert_byte(lc) + 5;
			caseAPDU = 3;
		} else if ((convert_byte(lc) + 5 + 1) == apduCommandLength) {
		// Case 4 short
			wrappedLength = convert_byte(lc) + 5;
			caseAPDU = 4;

		le = apduCommand[apduCommandLength - 1];
		apduCommandLength--;
		} else {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND, OPGP_stringify_error(OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND)); goto end; }
		}
	} // if (Determine which type of Exchange)

	if  (secInfo->securityLevel != GP211_SCP02_SECURITY_LEVEL_NO_SECURE_MESSAGING && secInfo->securityLevel != GP211_SCP01_SECURITY_LEVEL_NO_SECURE_MESSAGING) {
		if (secInfo->securityLevel == GP211_SCP01_SECURITY_LEVEL_C_DEC_C_MAC
			|| secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC
			|| secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC) {
			switch (caseAPDU) {
				case 3:
					if (apduCommandLength > 239 + 8 + 5) { OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE, OPGP_stringify_error(OPGP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE)); goto end; } // max apdu data size = 239 + 1 byte Lc
					break;
				case 4:
					if (apduCommandLength > 239 + 8 + 5 + 1) { OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE, OPGP_stringify_error(OPGP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE)); goto end; }
					break;
			}
		}
		if (secInfo->securityLevel == GP211_SCP01_SECURITY_LEVEL_C_MAC
			|| secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_C_MAC
			|| secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_C_MAC_R_MAC) {
			switch (caseAPDU) {
				case 3:
					if (apduCommandLength > 247 + 8 + 5) { OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE, OPGP_stringify_error(OPGP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE)); goto end; }
					break;
				case 4:
					if (apduCommandLength > 247 + 8 + 5 + 1) { OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE, OPGP_stringify_error(OPGP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE)); goto end; }
					break;
			}
		}
		/* C_MAC on modified APDU */
		if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i04
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i05
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i14
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i15
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i55
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i45
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i54
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i44) {

			switch (caseAPDU) {
				case 1:
				case 2: {
					if (*wrappedApduCommandLength < apduCommandLength + 8 + 1)
						{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
					wrappedLength += 8 + 1;
					wrappedApduCommand[4] = 0x08;
					break;
				}
				case 3:
				case 4: {
					if (*wrappedApduCommandLength < apduCommandLength + 8) {
						{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
					}
					wrappedLength += 8;
					wrappedApduCommand[4]+=8;
					break;
				}
			} // switch (caseAPDU)
			wrappedApduCommand[0] = apduCommand[0] | 0x04;
		}
		if (secInfo->secureChannelProtocol == GP211_SCP02) {
			if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i14
				 || secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i15
				 || secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1A
				 || secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1B
				 || secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i54
				 || secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i55) {
					 status = calculate_enc_ecb_single_des(secInfo->C_MACSessionKey,
						 secInfo->lastC_MAC, 8,
						 C_MAC_ICV, &C_MAC_ICVLength);
					if (OPGP_ERROR_CHECK(status)) {
						goto end;
					}
			}
			else {
				memcpy(C_MAC_ICV, secInfo->lastC_MAC, 8);
			}
		} else {
			if (secInfo->secureChannelProtocolImpl == GP211_SCP01_IMPL_i15) {
				status = calculate_enc_ecb_two_key_triple_des(secInfo->C_MACSessionKey,
					secInfo->lastC_MAC, 8,
						 C_MAC_ICV, &C_MAC_ICVLength);
				if (OPGP_ERROR_CHECK(status)) {
					goto end;
				}
			}
			else {
				memcpy(C_MAC_ICV, secInfo->lastC_MAC, 8);
			}
		}
		if (secInfo->secureChannelProtocol == GP211_SCP02) {
			status = calculate_MAC_des_3des(secInfo->C_MACSessionKey, wrappedApduCommand, wrappedLength-8,
				C_MAC_ICV, mac);
			if (OPGP_ERROR_CHECK(status)) {
				goto end;
			}
		}
		else {
			status = calculate_MAC(secInfo->C_MACSessionKey, wrappedApduCommand, wrappedLength-8,
				C_MAC_ICV, mac);
			if (OPGP_ERROR_CHECK(status)) {
				goto end;
			}
		}
#ifdef DEBUG
		OPGP_log_Hex(_T("wrap_command: ICV for MAC: "), C_MAC_ICV, 8);
#endif
#ifdef DEBUG
		OPGP_log_Hex(_T("wrap_command: Generated MAC: "), mac, 8);
#endif

		/* C_MAC on unmodified APDU */
		if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0A
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0B
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1A
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1B) {

			switch (caseAPDU) {
				case 1:
				case 2: {
					if (*wrappedApduCommandLength < apduCommandLength + 8 + 1)
						{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
					wrappedLength += 8 + 1;
					wrappedApduCommand[4] = 0x08;
					break;
				}
				case 3:
				case 4: {
					if (*wrappedApduCommandLength < apduCommandLength + 8) {
						{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
					}
					wrappedLength += 8;
					wrappedApduCommand[4]+=8;
					break;
				}
			} // switch (caseAPDU)
			wrappedApduCommand[0] = apduCommand[0] | 0x04;
		}

		memcpy(secInfo->lastC_MAC, mac, 8);
		memcpy(wrappedApduCommand+wrappedLength-8, mac, 8);

		/* Set all remaining fields and length if no encryption is performed */
		if ((caseAPDU == 2) || (caseAPDU == 4)) {
			wrappedApduCommand[wrappedLength] = le;
			wrappedLength++;
		}

		if (secInfo->securityLevel == GP211_SCP01_SECURITY_LEVEL_C_DEC_C_MAC
			|| secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC
			|| secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC) {
			wrappedApduCommand[4] -= 8;
			switch (caseAPDU) {
				case 1:
				case 3:
					if (secInfo->secureChannelProtocol == GP211_SCP02) {
						status = calculate_enc_cbc_SCP02(secInfo->encryptionSessionKey,
							wrappedApduCommand+5, wrappedLength-5-8, encryption, &encryptionLength);
						if (OPGP_ERROR_CHECK(status)) {
							goto end;
						}
					}
					else {
						status = calculate_enc_cbc(secInfo->encryptionSessionKey,
							wrappedApduCommand+4, wrappedLength-4-8, encryption, &encryptionLength);
						if (OPGP_ERROR_CHECK(status)) {
							goto end;
						}
					}
					break;
				case 2:
				case 4:
					if (secInfo->secureChannelProtocol == GP211_SCP02) {
						status = calculate_enc_cbc_SCP02(secInfo->encryptionSessionKey,
							wrappedApduCommand+5, wrappedLength-5-8-1, encryption, &encryptionLength);
						if (OPGP_ERROR_CHECK(status)) {
							goto end;
						}
					}
					else {
						status = calculate_enc_cbc(secInfo->encryptionSessionKey,
							wrappedApduCommand+4, wrappedLength-4-8-1, encryption, &encryptionLength);
						if (OPGP_ERROR_CHECK(status)) {
							goto end;
						}
					}
					break;
			}
			wrappedLength = encryptionLength + 4 + 1 + 8;
			if (*wrappedApduCommandLength < wrappedLength)
				{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
			memcpy(wrappedApduCommand+5, encryption, encryptionLength);
			wrappedApduCommand[4] = encryptionLength + 8;
			memcpy(&wrappedApduCommand[encryptionLength + 5], mac, 8);
			if ((caseAPDU == 2) || (caseAPDU == 4)) {
				if (*wrappedApduCommandLength < wrappedLength+1)
					{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
				wrappedApduCommand[wrappedLength] = le;
				wrappedLength++;
			}
		} // if (secInfo->securityLevel == GP211_SCP01_SECURITY_LEVEL_C_DEC_C_MAC || secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC)
		*wrappedApduCommandLength = wrappedLength;
	} // if (secInfo->securityLevel != GP211_SCP02_SECURITY_LEVEL_NO_SECURE_MESSAGING && secInfo->securityLevel != GP211_SCP01_SECURITY_LEVEL_NO_SECURE_MESSAGING)

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("wrap_command"), status);
	return status;
}

OPGP_ERROR_STATUS validate_install_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
							  DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE applicationAID, DWORD applicationAIDLength)
{
	OPGP_ERROR_STATUS status;
	DWORD i=0;
	PBYTE validationData;
	DWORD validationDataLength;
	OPGP_LOG_START(_T("validate_install_receipt"));
	validationDataLength = 1 + 2 + 1 + cardUniqueDataLength + 1 + executableLoadFileAIDLength + 1 + applicationAIDLength;
	validationData = (PBYTE)malloc(validationDataLength);
	if (validationData == NULL) {

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
	status = validate_receipt(validationData, validationDataLength, receiptData.receipt, receiptKey);
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
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE securityDomainAID, DWORD securityDomainAIDLength)
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
	status = validate_receipt(validationData, validationDataLength, receiptData.receipt, receiptKey);
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
 * \param commandHeader [in] The APDU command header.
 * \param commandData [in] The APDU command body.
 * \param commandDataLength [in] The APDU command body length.
 * \param responseData [in] The APDU response body.
 * \param responseDataLength [in] The APDU response body length.
 * \param statusWord [in] The status word of the response.
 * \param *secInfo [in] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param mac [out] The R-MAC.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_calculate_R_MAC(BYTE commandHeader[4],
						   PBYTE commandData,
						   DWORD commandDataLength,
						   PBYTE responseData,
						   DWORD responseDataLength,
						   BYTE statusWord[2],
						   GP211_SECURITY_INFO *secInfo,
						   BYTE mac[8])
{
	OPGP_ERROR_STATUS status;
	PBYTE r_MacData;
	DWORD offset=0;
	DWORD r_MacDataLength;
	OPGP_LOG_START(_T("GP211_calculate_R_MAC"));
	r_MacDataLength = 4 + 1 + commandDataLength + 1 + responseDataLength + 2;
	r_MacData = (PBYTE)malloc(r_MacDataLength*sizeof(BYTE));
	if (r_MacData == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
		goto end;
	}
	memcpy(r_MacData, commandHeader, 4);
	offset+=4;
	memset(r_MacData+offset++, commandDataLength, sizeof(BYTE));
	memcpy(r_MacData+offset, commandData, commandDataLength);
	offset+=commandDataLength;
	memset(r_MacData+offset++, responseDataLength%256, sizeof(BYTE));
	memcpy(r_MacData+offset, responseData, responseDataLength);
	offset+=responseDataLength;
	memcpy(r_MacData+offset, statusWord, 2);
	offset+=2;
	status = calculate_MAC_des_3des(secInfo->R_MACSessionKey, r_MacData, r_MacDataLength, secInfo->lastR_MAC,
		mac);
	if (OPGP_ERROR_CHECK(status))
		goto end;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	if (r_MacData) {
		free(r_MacData);
	}
	OPGP_LOG_END(_T("GP211_calculate_R_MAC"), status);
	return status;
}

/**
 * \param apduCommand [in] The command APDU.
 * \param apduCommandLength [in] The length of the command APDU.
 * \param responseData [in] The response data.
 * \param responseDataLength [in] The length of the response data.
 * \param *secInfo [in] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_check_R_MAC(PBYTE apduCommand, DWORD apduCommandLength, PBYTE responseData,
				 DWORD responseDataLength, GP211_SECURITY_INFO *secInfo) {
	OPGP_ERROR_STATUS status;
	BYTE lc;
	DWORD le;
	BYTE mac[8];
	DWORD caseAPDU;
	OPGP_LOG_START(_T("GP211_check_R_MAC"));

	// no security level defined, just return
	if (secInfo == NULL) {
		{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
	}

	// trivial case, just return
	if ((secInfo->securityLevel != GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC) &&
		(secInfo->securityLevel != GP211_SCP02_SECURITY_LEVEL_R_MAC) &&
		(secInfo->securityLevel != GP211_SCP02_SECURITY_LEVEL_C_MAC_R_MAC)) {
		{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
	}

	// Determine which type of Exchange between the reader
	if (apduCommandLength == 4) {
	// Case 1 short
		lc = 0;
		caseAPDU = 1;
	} else if (apduCommandLength == 5) {
	// Case 2 short
		lc = 0;
		caseAPDU = 2;
	} else {
		lc = apduCommand[4];
		if ((convert_byte(lc) + 5) == apduCommandLength) {
		// Case 3 short
			caseAPDU = 3;
		} else if ((convert_byte(lc) + 5 + 1) == apduCommandLength) {
		// Case 4 short
			caseAPDU = 4;
		} else {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND, OPGP_stringify_error(OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND)); goto end; }
		}
	} // if (Determine which type of Exchange)
	le = responseDataLength-2;
	GP211_calculate_R_MAC(apduCommand, apduCommand, lc, responseData, le,
			responseData+responseDataLength-2, secInfo, mac);
#ifdef DEBUG
	OPGP_log_Hex(_T("check_R_MAC: received R-MAC: "), responseData-10, responseDataLength-10);
	OPGP_log_Hex(_T("check_R_MAC: calculated R-MAC: "), mac, 8);
#endif
	if (memcmp(mac, responseData+responseDataLength-10, 8)) {
		OPGP_ERROR_CREATE_ERROR(status, GP211_ERROR_VALIDATION_R_MAC, OPGP_stringify_error(GP211_ERROR_VALIDATION_R_MAC));
		goto end;
	}
	memcpy(secInfo->lastR_MAC, mac, 8);

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
OPGP_ERROR_STATUS read_public_rsa_key(OPGP_STRING PEMKeyFileName, char *passPhrase, BYTE rsaModulus[128], long *rsaExponent) {
	OPGP_ERROR_STATUS status;
	EVP_PKEY *key;
	FILE *PEMKeyFile;
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
		fclose(PEMKeyFile);
		EVP_PKEY_free(key);
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	};
	fclose(PEMKeyFile);
	// only 3 and 65337 are supported
	*rsaExponent = key->pkey.rsa->e->d[0];
	memcpy(rsaModulus, key->pkey.rsa->n->d, sizeof(unsigned long)*key->pkey.rsa->n->top);
	EVP_PKEY_free(key);
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("read_public_rsa_key"), status);
	return status;
}

/**
 * \param message [in] The message to generate the signature for.
 * \param messageLength [in] The length of the message buffer.
 * \param hash [out] The calculated hash.
 */
OPGP_ERROR_STATUS calculate_sha1_hash(PBYTE message, DWORD messageLength, BYTE hash[20]) {
	int result;
	OPGP_ERROR_STATUS status;
	EVP_MD_CTX mdctx;
	OPGP_LOG_START(_T("calculate_sha1_hash"));
	EVP_MD_CTX_init(&mdctx);
	result = EVP_DigestInit_ex(&mdctx, EVP_sha1(), NULL);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}

	result = EVP_DigestUpdate(&mdctx, message, messageLength);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}

	result = EVP_DigestFinal_ex(&mdctx, hash, NULL);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if (EVP_MD_CTX_cleanup(&mdctx) != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); }
	}
	OPGP_LOG_END(_T("calculate_sha1_hash"), status);
	return status;
}

/**
 * \param key[16] [in] A 3DES key used to sign. For DES the right half of the key is used.
 * \param *message [in] The message to authenticate.
 * \param messageLength [in] The message length.
 * \param mac[8] [out] The calculated MAC.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS calculate_MAC_right_des_3des(BYTE key[16], BYTE *message, int messageLength, BYTE mac[8])
{
	int result;
	OPGP_ERROR_STATUS status;
	int i;
	int outl;
	BYTE des_key[8];
	EVP_CIPHER_CTX ctx;
	OPGP_LOG_START(_T("calculate_MAC_des_final_3des"));
	EVP_CIPHER_CTX_init(&ctx);
// DES CBC mode
	memcpy(des_key, key+8, 8);
	result = EVP_EncryptInit_ex(&ctx, EVP_des_cbc(), NULL, des_key, icv);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);

	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(&ctx, mac,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
	}
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	result = EVP_EncryptFinal_ex(&ctx, mac, &outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}

	result = EVP_CIPHER_CTX_cleanup(&ctx);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_init(&ctx);

	// 3DES CBC mode
	result = EVP_EncryptInit_ex(&ctx, EVP_des_ede_cbc(), NULL, key, icv);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, mac,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
		}
	}
	result = EVP_EncryptUpdate(&ctx, mac,
		&outl, padding, 8 - (messageLength%8));
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}
	result = EVP_EncryptFinal_ex(&ctx, mac,
		&outl);
	if (result != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); goto end; }
	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CRYPT, OPGP_stringify_error(OPGP_ERROR_CRYPT)); }
	}
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

