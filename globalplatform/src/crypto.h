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

/*! \file
 * This file contains internally used cryptographic related functionality.
*/

#ifndef OPGP_CRYPTO_H
#define OPGP_CRYPTO_H

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef WIN32
#include "stdafx.h"
#endif

#include "globalplatform/types.h"
#include "globalplatform/library.h"
#include "globalplatform/unicode.h"
#include "globalplatform/error.h"
#include "globalplatform/security.h"

static const BYTE ICV[8] = {0}; //!< Initial chaining vector.
static const BYTE SCP03_ICV[32] = {0}; //!< Initial chaining vector for SCP03.

OPGP_NO_API
OPGP_ERROR_STATUS calculate_CMAC_aes(PBYTE sMacKey, DWORD keyLength, BYTE *message,
		DWORD messageLength, PBYTE chainingValue,
							PBYTE mac);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_key_check_value(GP211_SECURITY_INFO *secInfo,
	BYTE keyType,
	PBYTE keyData,
	DWORD keyDataLength,
	BYTE keyCheckValue[3]);

OPGP_NO_API
OPGP_ERROR_STATUS encrypt_sensitive_data(GP211_SECURITY_INFO *secInfo,
	PBYTE data,
	DWORD dataLength,
	PBYTE encryptedData,
	PDWORD encryptedDataLength);

OPGP_NO_API
OPGP_ERROR_STATUS get_key_data_field(GP211_SECURITY_INFO *secInfo,
                                     PBYTE keyData,
                                     DWORD keyDataLength,
                                     BYTE keyType,
                                     PBYTE keyDataField,
                                     PDWORD keyDataFieldLength,
                                     BYTE keyCheckValue[3], BOOL includeKeyCheckValue);

OPGP_NO_API
OPGP_ERROR_STATUS create_session_key_SCP01(BYTE key[16], BYTE cardChallenge[8],
						   BYTE hostChallenge[8], PBYTE sessionKey);

OPGP_NO_API
OPGP_ERROR_STATUS create_session_key_SCP02(BYTE key[16], BYTE constant[2],
						   BYTE sequenceCounter[2], PBYTE sessionKey);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_rsa_signature(PBYTE message, DWORD messageLength, OPGP_STRING PEMKeyFileName,
									char *passPhrase, PBYTE signature, PDWORD signatureLength);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_MAC(BYTE sessionKey[16], BYTE *message, DWORD messageLength,
						  BYTE icv[8], BYTE mac[8]);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_card_cryptogram_SCP01(BYTE S_ENCSessionKey[16],
											BYTE cardChallenge[8],
											BYTE hostChallenge[8],
											BYTE cardCryptogram[8]);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_card_cryptogram_SCP02(BYTE S_ENCSessionKey[16],
							BYTE sequenceCounter[2],
							PBYTE cardChallenge,
							BYTE hostChallenge[8],
							BYTE cardCryptogram[8]);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_host_cryptogram_SCP01(BYTE S_ENCSessionKey[16],
											BYTE cardChallenge[8],
											BYTE hostChallenge[8],
											BYTE hostCryptogram[8]);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_host_cryptogram_SCP02(BYTE S_ENCSessionKey[16],
							BYTE sequenceCounter[2],
							PBYTE cardChallenge,
							BYTE hostChallenge[8],
							BYTE hostCryptogram[8]);

OPGP_NO_API
OPGP_ERROR_STATUS create_session_key_SCP03(BYTE key[32], DWORD keyLength, BYTE derivationConstant, BYTE cardChallenge[8],
						   BYTE hostChallenge[8], PBYTE sessionKey);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_card_challenge_SCP03(BYTE S_ENC[32],
											DWORD keyLength,
											BYTE sequenceCounter[3],
											PBYTE invokingAID,
											DWORD invokingAIDLength,
											BYTE cardChallenge[8]);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_card_cryptogram_SCP03(BYTE S_MACSessionKey[32],
											DWORD keyLength,
											BYTE cardChallenge[8],
											BYTE hostChallenge[8],
											BYTE cardCryptogram[8]);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_host_cryptogram_SCP03(BYTE S_MACSessionKey[32],
											DWORD keyLength,
											BYTE cardChallenge[8],
											BYTE hostChallenge[8],
											BYTE hostCryptogram[8]);

//! \brief Wraps a command, i.e. encrypts and add the MAC to the APDU with the necessary security information according to secInfo.
OPGP_NO_API
OPGP_ERROR_STATUS wrap_command(PBYTE apduCommand, DWORD apduCommandLength, PBYTE wrappedApduCommand,
						 PDWORD wrappedApduCommandLength, GP211_SECURITY_INFO *secInfo);

//! \brief Unwraps a response, i.e. decrypt and check the R-MAC of a response APDU with the necessary security information according to secInfo.
OPGP_NO_API
OPGP_ERROR_STATUS unwrap_command(PBYTE apduCommand, DWORD apduCommandLength, PBYTE responseData,
				 DWORD responseDataLength, PBYTE unwrappedResponseData,
				 PDWORD unwrappedResponseDataLength, GP211_SECURITY_INFO *secInfo);

//! \brief Checks the R-MAC of an APDU with the necessary security information according to secInfo.
OPGP_NO_API
OPGP_ERROR_STATUS GP211_check_R_MAC(PBYTE apduCommand, DWORD apduCommandLength, PBYTE responseData,
				 DWORD responseDataLength, PBYTE unwrappedResponseApdu, PDWORD unwrappedResponseApduLength, GP211_SECURITY_INFO *secInfo);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_enc_ecb_two_key_triple_des(BYTE key[16], BYTE *message,
		DWORD messageLength, BYTE *encryption,
												 DWORD *encryptionLength);

OPGP_NO_API
OPGP_ERROR_STATUS validate_receipt(PBYTE validationData, DWORD validationDataLength,
							 BYTE receipt[16], PBYTE receiptKey, DWORD keyLength, BYTE secureChannelProtocol);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_MAC_des_3des(BYTE _3des_key[16], BYTE *message, DWORD messageLength,
		BYTE initialICV[8], BYTE mac[8]);

OPGP_NO_API
OPGP_ERROR_STATUS validate_install_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
						  DWORD cardUniqueDataLength,
					   PBYTE receiptKey, DWORD keyLength, GP211_RECEIPT_DATA receiptData,
					   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
					   PBYTE applicationAID, DWORD applicationAIDLength, BYTE secureChannelProtocol);

OPGP_NO_API
OPGP_ERROR_STATUS validate_delete_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
						 DWORD cardUniqueDataLength,
					   PBYTE receiptKey, DWORD keyLength, GP211_RECEIPT_DATA receiptData,
					   PBYTE AID, DWORD AIDLengthv, BYTE secureChannelProtocol);

OPGP_NO_API
OPGP_ERROR_STATUS validate_load_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
						   DWORD cardUniqueDataLength,
						   PBYTE receiptKey, DWORD keyLength, GP211_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE securityDomainAID, DWORD securityDomainAIDLength, BYTE secureChannelProtocol);

//! \brief Reads a public RSA key from a file
OPGP_NO_API
OPGP_ERROR_STATUS read_public_rsa_key(OPGP_STRING PEMKeyFileName, char *passPhrase, BYTE rsaModulus[128], PDWORD rsaModulusLength, LONG *rsaExponent);

//! \brief Calculates a SHA-256 hash.
OPGP_NO_API
OPGP_ERROR_STATUS calculate_sha2_hash(PBYTE message, DWORD messageLength, BYTE hash[64], DWORD hashLength);

//! \brief Calculates a SHA-1 hash.
OPGP_NO_API
OPGP_ERROR_STATUS calculate_sha1_hash(PBYTE message, DWORD messageLength, BYTE hash[20]);

//! \brief Calculates a SM3 hash.
OPGP_NO_API
OPGP_ERROR_STATUS calculate_sm3_hash(PBYTE message, DWORD messageLength, BYTE hash[32]);

//! \brief Calculates a MAC using first DES and 3DES for the final round when the padding is applied.
OPGP_NO_API
OPGP_ERROR_STATUS calculate_MAC_right_des_3des(BYTE key[16], BYTE *message, DWORD messageLength, BYTE mac[8]);

OPGP_NO_API
OPGP_ERROR_STATUS get_random(BYTE *random, int randomLength);

#ifdef __cplusplus
}
#endif

#endif
