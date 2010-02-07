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

#include "GlobalPlatform/types.h"
#include "GlobalPlatform/library.h"
#include "GlobalPlatform/unicode.h"
#include "GlobalPlatform/error.h"
#include "GlobalPlatform/security.h"

static unsigned char padding[8] = {(char)0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //!< Applied padding pattern.
static unsigned char icv[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}; //!< First initial chaining vector.

OPGP_NO_API
OPGP_ERROR_STATUS get_key_data_field(GP211_SECURITY_INFO *secInfo,
								 PBYTE keyData,
								 DWORD keyDataLength,
								 BYTE keyType,
								 BYTE isSensitive,
								 PBYTE keyDataField,
								 PDWORD keyDataFieldLength,
								 BYTE keyCheckValue[3]);

OPGP_NO_API
OPGP_ERROR_STATUS create_session_key_SCP01(unsigned char key[16], unsigned char cardChallenge[8],
							   unsigned char hostChallenge[8], unsigned char sessionKey[16]);

OPGP_NO_API
OPGP_ERROR_STATUS create_session_key_SCP02(unsigned char key[16], unsigned char constant[2],
							   unsigned char sequenceCounter[2], unsigned char sessionKey[16]);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_rsa_signature(PBYTE message, DWORD messageLength, OPGP_STRING PEMKeyFileName,
									char *passPhrase, BYTE signature[128]);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_MAC(unsigned char sessionKey[16], unsigned char *message, int messageLength,
						  unsigned char icv[8], unsigned char mac[8]);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_card_cryptogram_SCP01(unsigned char S_ENCSessionKey[16],
											unsigned char cardChallenge[8],
											unsigned char hostChallenge[8],
											unsigned char cardCryptogram[8]);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_card_cryptogram_SCP02(unsigned char S_ENCSessionKey[16],
											unsigned char sequenceCounter[2],
											unsigned char cardChallenge[6],
											unsigned char hostChallenge[8],
											unsigned char cardCryptogram[8]);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_host_cryptogram_SCP01(unsigned char S_ENCSessionKey[16],
											unsigned char cardChallenge[8],
											unsigned char hostChallenge[8],
											unsigned char hostCryptogram[8]);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_host_cryptogram_SCP02(unsigned char S_ENCSessionKey[16],
											unsigned char sequenceCounter[2],
											unsigned char cardChallenge[6],
											unsigned char hostChallenge[8],
											unsigned char hostCryptogram[8]);

OPGP_NO_API
OPGP_ERROR_STATUS wrap_command(PBYTE apduCommand, DWORD apduCommandLength, PBYTE wrappedApduCommand,
						 PDWORD wrappedApduCommandLength, GP211_SECURITY_INFO *secInfo);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_enc_cbc_SCP02(unsigned char key[16], unsigned char *message, int messageLength,
							  unsigned char *encryption, int *encryptionLength);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_enc_cbc(unsigned char key[16], unsigned char *message, int messageLength,
							  unsigned char *encryption, int *encryptionLength);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_enc_ecb_two_key_triple_des(unsigned char key[16], unsigned char *message,
												 int messageLength, unsigned char *encryption,
												 int *encryptionLength);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_enc_ecb_single_des(unsigned char key[8], unsigned char *message, int messageLength,
							  unsigned char *encryption, int *encryptionLength);

OPGP_NO_API
OPGP_ERROR_STATUS validate_receipt(PBYTE validationData, DWORD validationDataLength,
							 BYTE receipt[16], BYTE receiptKey[16]);

OPGP_NO_API
OPGP_ERROR_STATUS calculate_MAC_des_3des(unsigned char _3des_key[16], unsigned char *message, int messageLength,
		unsigned char InitialICV[8], unsigned char mac[8]);

OPGP_NO_API
OPGP_ERROR_STATUS validate_install_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
							  DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE applicationAID, DWORD applicationAIDLength);

OPGP_NO_API
OPGP_ERROR_STATUS validate_delete_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
							 DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE AID, DWORD AIDLength);

OPGP_NO_API
OPGP_ERROR_STATUS validate_load_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
						   DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE securityDomainAID, DWORD securityDomainAIDLength);

//! \brief Checks the R-MAC of an APDU with the necessary security information according to secInfo.
OPGP_NO_API
OPGP_ERROR_STATUS GP211_check_R_MAC(PBYTE apduCommand, DWORD apduCommandLength, PBYTE responseData,
				 DWORD responseDataLength, GP211_SECURITY_INFO *secInfo);


//! \brief Calculates a R-MAC.
OPGP_NO_API
OPGP_ERROR_STATUS GP211_calculate_R_MAC(BYTE commandHeader[4],
						   PBYTE commandData,
						   DWORD commandDataLength,
						   PBYTE responseData,
						   DWORD responseDataLength,
						   BYTE statusWord[2],
						   GP211_SECURITY_INFO *secInfo,
						   BYTE mac[8]);

//! \brief Reads a public RSA key from a file
OPGP_NO_API
OPGP_ERROR_STATUS read_public_rsa_key(OPGP_STRING PEMKeyFileName, char *passPhrase, BYTE rsaModulus[128], long *rsaExponent);

//! \brief Calculates a SHA-1 hash.
OPGP_NO_API
OPGP_ERROR_STATUS calculate_sha1_hash(PBYTE message, DWORD messageLength, BYTE hash[20]);

//! \brief Calculates a MAC using first DES and 3DES for the final round when the padding is applied.
OPGP_NO_API
OPGP_ERROR_STATUS calculate_MAC_right_des_3des(unsigned char key[16], unsigned char *message, int messageLength, unsigned char mac[8]);

OPGP_NO_API
OPGP_ERROR_STATUS get_random(unsigned char *random, int randomLength);

#ifdef __cplusplus
}
#endif

#endif
