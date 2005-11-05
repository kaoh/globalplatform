/* Copyright (c) 2005, Karsten Ohme
 * All rights reserved.

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*! \mainpage GlobalPlatform Library
 *
 * \author Karsten Ohme
 * \section intro_sec Introduction
 *
 * This library offers functions to manage a Open Platform 2.0.1' and GlobalPlatform 2.1.1 conforming card.
 *
 * <h2>Note</h2>
 * <p>
 * Before you call a card related command make sure that the Issuer Security Domain
 * (CardManager for Open Platform 2.0.1') or Security Domain you
 * want to use for the command is selected by select_application().
 * </p>
 * <h2>Unicode support</h2>
 * <p>
 * Obey that this library supports Unicode in Windows. If you develop an application you must use Unicode
 * strings in Windows. Use the <code>LPTSTR</code>, <code>TCHAR</code> and the <code>_T()</code> macro,
 * use Unicode functions and compile your application with the switches UNICODE and _UNICODE. Under Unixes
 * only ASCII is supported but to be portable use the mappings in GlobalPlatform/unicode.h
 * </p>
 *
 */
#ifdef WIN32
#include "stdafx.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include "GlobalPlatform/GlobalPlatform.h"
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#ifndef WIN32
#include <sys/stat.h>
#include <string.h>
#endif
#include "debug.h"

#define MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING 239

static unsigned char padding[8] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //!< Applied padding pattern.
static unsigned char icv[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}; //!< First initial chaining vector.

static unsigned char C_MACDerivationConstant[2] = {0x01, 0x01}; //!< Constant for C-MAC session key calculation.
static unsigned char ENCDerivationConstant[2] = {0x01, 0x82};//!< Constant for encryption session key calculation.
static unsigned char DEKDerivationConstant[2] = {0x01, 0x81};//!< Constant for data encryption session key calculation.
static unsigned char R_MACDerivationConstant[2] = {0x01, 0x02};//!< Constant for R-MAC session key calculation.

static LONG create_sessionKey_SCP01(unsigned char key[16], unsigned char cardChallenge[8],
							   unsigned char hostChallenge[8], unsigned char sessionKey[16]);

static LONG create_sessionKey_SCP02(unsigned char key[16], unsigned char constant[2],
							   unsigned char sequenceCounter[2], unsigned char sessionKey[16]);

static LONG calculate_rsa_signature(PBYTE message, DWORD messageLength, OPGP_STRING PEMKeyFileName,
									char *passPhrase, BYTE signature[128]);

static LONG calculate_MAC(unsigned char sessionKey[16], unsigned char *message, int messageLength,
						  unsigned char icv[8], unsigned char mac[8]);

static LONG calculate_card_cryptogram_SCP01(unsigned char S_ENCSessionKey[16],
											unsigned char cardChallenge[8],
											unsigned char hostChallenge[8],
											unsigned char cardCryptogram[8]);

static LONG calculate_card_cryptogram_SCP02(unsigned char S_ENCSessionKey[16],
											unsigned char sequenceCounter[2],
											unsigned char cardChallenge[6],
											unsigned char hostChallenge[8],
											unsigned char cardCryptogram[8]);

static LONG calculate_host_cryptogram_SCP01(unsigned char S_ENCSessionKey[16],
											unsigned char cardChallenge[8],
											unsigned char hostChallenge[8],
											unsigned char hostCryptogram[8]);

static LONG calculate_host_cryptogram_SCP02(unsigned char S_ENCSessionKey[16],
											unsigned char sequenceCounter[2],
											unsigned char cardChallenge[6],
											unsigned char hostChallenge[8],
											unsigned char hostCryptogram[8]);

static LONG wrap_command(PBYTE apduCommand, DWORD apduCommandLength, PBYTE wrappedApduCommand,
						 PDWORD wrappedApduCommandLength, GP211_SECURITY_INFO *secInfo);

static LONG calculate_enc_cbc_SCP02(unsigned char key[16], unsigned char *message, int messageLength,
							  unsigned char *encryption, int *encryptionLength);

static LONG calculate_enc_cbc(unsigned char key[16], unsigned char *message, int messageLength,
							  unsigned char *encryption, int *encryptionLength);

static LONG calculate_enc_ecb_two_key_triple_des(unsigned char key[16], unsigned char *message,
												 int messageLength, unsigned char *encryption,
												 int *encryptionLength);

static LONG calculate_enc_ecb_single_des(unsigned char key[8], unsigned char *message, int messageLength,
							  unsigned char *encryption, int *encryptionLength);

static LONG validate_receipt(PBYTE validationData, DWORD validationDataLength,
							 BYTE receipt[16], BYTE receiptKey[16]);

static LONG calculate_MAC_des_3des(unsigned char _3des_key[16], unsigned char *message, int messageLength,
						  unsigned char InitialICV[8], unsigned char mac[8]);

static LONG get_load_data(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
								   DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20],
								   DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
								   DWORD nonVolatileDataSpaceLimit, PBYTE loadData,
								   PDWORD loadDataLength);

static LONG send_APDU(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, PBYTE capdu, DWORD capduLength, PBYTE rapdu, PDWORD rapduLength);

static LONG put_rsa_key(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion,
				 OPGP_STRING PEMKeyFileName, char *passPhrase);

static LONG put_3des_key(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				  BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, BYTE _3DESKey[16]);

static LONG put_secure_channel_keys(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
							 BYTE keySetVersion,
							 BYTE newKeySetVersion,
							 BYTE newBaseKey[16],
							 BYTE newS_ENC[16],
							 BYTE newS_MAC[16], BYTE newDEK[16]);

static LONG put_delegated_management_keys(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								   BYTE keySetVersion, BYTE newKeySetVersion,
								   OPGP_STRING PEMKeyFileName, char *passPhrase,
								   BYTE receiptKey[16]);

static LONG delete_key(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE keySetVersion, BYTE keyIndex);

static LONG delete_application(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				   OPGP_AID *AIDs, DWORD AIDsLength, GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataLength);

static LONG get_data(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
			  const BYTE identifier[2], PBYTE recvBuffer, PDWORD recvBufferLength);

static LONG put_data(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE identifier[2], PBYTE dataObject, DWORD dataObjectLength);

static LONG get_key_information_templates(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								   BYTE keyInformationTemplate,
								   GP211_KEY_INFORMATION *keyInformation, PDWORD keyInformationLength);

static LONG set_status(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE cardElement, PBYTE AID, DWORD AIDLength, BYTE lifeCycleState);

static LONG load(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 GP211_DAP_BLOCK *loadFileDataBlockSignature, DWORD loadFileDataBlockSignatureLength,
				 OPGP_STRING executableLoadFileName,
				 GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

static LONG install_for_install_and_make_selectable(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE executableModuleAID,
						 DWORD executableModuleAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE installParameters, DWORD installParametersLength,
						 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData,
						 PDWORD receiptDataAvailable);

static LONG install_for_load(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
					  PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
					  DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20], BYTE loadToken[128],
					  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
					  DWORD nonVolatileDataSpaceLimit);

static LONG install_for_install(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						 PBYTE executableModuleAID,
						 DWORD executableModuleAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE installParameters, DWORD installParametersLength,
						 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

static LONG install_for_make_selectable(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								 PBYTE applicationAID,
								 DWORD applicationAIDLength, BYTE applicationPrivileges,
								 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData,
								 PDWORD receiptDataAvailable);

static LONG calculate_install_token(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
							 PBYTE executableModuleAID,
							 DWORD executableModuleAIDLength, PBYTE applicationAID, DWORD applicationAIDLength,
							 BYTE applicationPrivileges, DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
							 PBYTE installParameters, DWORD installParametersLength,
							 BYTE installToken[128], OPGP_STRING PEMKeyFileName, char *passPhrase);

static LONG validate_load_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
						   DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE securityDomainAID, DWORD securityDomainAIDLength);

static LONG pin_change(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE tryLimit,
				PBYTE newPIN, DWORD newPINLength);

static LONG mutual_authentication(OPGP_CARD_INFO cardInfo, BYTE baseKey[16],
						   BYTE S_ENC[16], BYTE S_MAC[16],
						   BYTE DEK[16], BYTE keySetVersion,
						   BYTE keyIndex, BYTE secureChannelProtocol,
						   BYTE secureChannelProtocolImpl, BYTE securityLevel,
						   GP211_SECURITY_INFO *secInfo);

static LONG validate_install_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
							  DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE applicationAID, DWORD applicationAIDLength);

static LONG validate_delete_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
							 DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE AID, DWORD AIDLength);

static LONG get_install_data(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE executableModuleAID,
									  DWORD executableModuleAIDLength, PBYTE applicationAID,
									  DWORD applicationAIDLength, BYTE applicationPrivileges,
									  DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
									  PBYTE installParameters, DWORD installParametersLength,
									  PBYTE installData, PDWORD installDataLength);



static DWORD traceEnable; //!< Enable trace mode.
static FILE *traceFile; //!< The trace file for trace mode.

static void mapOP201ToGP211SecurityInfo(OP201_SECURITY_INFO op201secInfo,
										GP211_SECURITY_INFO *gp211secInfo) {
	if (gp211secInfo == NULL)
		return;
	memcpy(gp211secInfo->C_MACSessionKey, op201secInfo.sessionMacKey, 16);
	memcpy(gp211secInfo->lastC_MAC, op201secInfo.lastMac, 8);
	memcpy(gp211secInfo->encryptionSessionKey, op201secInfo.sessionEncKey, 16);
	switch (op201secInfo.securityLevel) {
		case OP201_SECURITY_LEVEL_ENC_MAC:
			gp211secInfo->securityLevel = GP211_SCP01_SECURITY_LEVEL_C_DEC_C_MAC;
			break;
		case OP201_SECURITY_LEVEL_PLAIN:
			gp211secInfo->securityLevel = GP211_SCP01_SECURITY_LEVEL_NO_SECURE_MESSAGING;
			break;
		case OP201_SECURITY_LEVEL_MAC:
			gp211secInfo->securityLevel = GP211_SCP01_SECURITY_LEVEL_C_MAC;
			break;
	}
	gp211secInfo->secureChannelProtocol = GP211_SCP01;
	gp211secInfo->secureChannelProtocolImpl = GP211_SCP01_IMPL_i05;
}

static void mapGP211ToOP201SecurityInfo(GP211_SECURITY_INFO gp211secInfo,
										OP201_SECURITY_INFO *op201secInfo) {
	if (op201secInfo == NULL)
		return;
	memcpy(op201secInfo->sessionMacKey, gp211secInfo.C_MACSessionKey, 16);
	memcpy(op201secInfo->lastMac, gp211secInfo.lastC_MAC, 8);
	memcpy(op201secInfo->sessionEncKey, gp211secInfo.encryptionSessionKey, 16);
	switch (gp211secInfo.securityLevel) {
		case GP211_SCP01_SECURITY_LEVEL_C_DEC_C_MAC:
			op201secInfo->securityLevel = OP201_SECURITY_LEVEL_ENC_MAC;
			break;
		case GP211_SCP01_SECURITY_LEVEL_NO_SECURE_MESSAGING:
			op201secInfo->securityLevel = OP201_SECURITY_LEVEL_PLAIN;
			break;
		case GP211_SCP01_SECURITY_LEVEL_C_MAC:
			op201secInfo->securityLevel = OP201_SECURITY_LEVEL_MAC;
			break;
	}
}

static void mapOP201ToGP211DAPBlock(OP201_DAP_BLOCK op201dapBlock,
										GP211_DAP_BLOCK *gp211dapBlock) {
	if (gp211dapBlock == NULL)
		return;
	gp211dapBlock->securityDomainAIDLength = op201dapBlock.securityDomainAIDLength;
	memcpy(gp211dapBlock->securityDomainAID, op201dapBlock.securityDomainAID, op201dapBlock.securityDomainAIDLength);
	gp211dapBlock->signatureLength = op201dapBlock.signatureLength;
	memcpy(gp211dapBlock->signature, op201dapBlock.signature, op201dapBlock.signatureLength);
}

static void mapGP211ToOP201DAPBlock(GP211_DAP_BLOCK gp211dapBlock,
										OP201_DAP_BLOCK *op201dapBlock) {
	if (op201dapBlock == NULL)
		return;
	op201dapBlock->securityDomainAIDLength = gp211dapBlock.securityDomainAIDLength;
	memcpy(op201dapBlock->securityDomainAID, gp211dapBlock.securityDomainAID, gp211dapBlock.securityDomainAIDLength);
	op201dapBlock->signatureLength = gp211dapBlock.signatureLength;
	memcpy(op201dapBlock->signature, gp211dapBlock.signature, gp211dapBlock.signatureLength);
}

static void mapOP201ToGP211ReceiptData(OP201_RECEIPT_DATA op201receiptData,
									   GP211_RECEIPT_DATA *gp211receiptData) {
	if (gp211receiptData == NULL)
		return;
	gp211receiptData->cardUniqueDataLength = op201receiptData.cardUniqueDataLength;
	memcpy(gp211receiptData->cardUniqueData, op201receiptData.cardUniqueData, op201receiptData.cardUniqueDataLength);
	gp211receiptData->confirmationCounterLength = op201receiptData.confirmationCounterLength;
	memcpy(gp211receiptData->confirmationCounter, op201receiptData.confirmationCounter, op201receiptData.confirmationCounterLength);
	gp211receiptData->receiptLength = op201receiptData.receiptLength;
	memcpy(gp211receiptData->receipt, op201receiptData.receipt, op201receiptData.receiptLength);
}

static void mapGP211ToOP201ReceiptData(GP211_RECEIPT_DATA gp211receiptData,
										OP201_RECEIPT_DATA *op201receiptData) {
	if (op201receiptData == NULL)
		return;
	op201receiptData->cardUniqueDataLength = gp211receiptData.cardUniqueDataLength;
	memcpy(op201receiptData->cardUniqueData, gp211receiptData.cardUniqueData, gp211receiptData.cardUniqueDataLength);
	op201receiptData->confirmationCounterLength = gp211receiptData.confirmationCounterLength;
	memcpy(op201receiptData->confirmationCounter, gp211receiptData.confirmationCounter, gp211receiptData.confirmationCounterLength);
	op201receiptData->receiptLength = gp211receiptData.receiptLength;
	memcpy(op201receiptData->receipt, gp211receiptData.receipt, gp211receiptData.receiptLength);
}

static void mapOP201ToGP211KeyInformation(OP201_KEY_INFORMATION op201keyInformation,
										  GP211_KEY_INFORMATION *gp211keyInformation) {
	if (gp211keyInformation == NULL)
		return;
	gp211keyInformation->keyIndex = op201keyInformation.keyIndex;
	gp211keyInformation->keyLength = op201keyInformation.keyLength;
	gp211keyInformation->keySetVersion = op201keyInformation.keySetVersion;
	gp211keyInformation->keyType = op201keyInformation.keyType;
}

static void mapGP211ToOP201KeyInformation(GP211_KEY_INFORMATION gp211keyInformation,
										  OP201_KEY_INFORMATION *op201keyInformation) {
	if (op201keyInformation == NULL)
		return;
	op201keyInformation->keyIndex = gp211keyInformation.keyIndex;
	op201keyInformation->keyLength = gp211keyInformation.keyLength;
	op201keyInformation->keySetVersion = gp211keyInformation.keySetVersion;
	op201keyInformation->keyType = gp211keyInformation.keyType;
}

static void mapOP201ToGP211ApplicationData(OP201_APPLICATION_DATA op201applData,
										  GP211_APPLICATION_DATA *gp211applData) {
	if (gp211applData == NULL)
		return;
	gp211applData->AIDLength = op201applData.AIDLength;
	memcpy(gp211applData->AID, op201applData.AID, op201applData.AIDLength);
	gp211applData->lifeCycleState = op201applData.lifeCycleState;
	gp211applData->privileges = op201applData.privileges;
}

static void mapGP211ToOP201ApplicationData(GP211_APPLICATION_DATA gp211applData,
										   OP201_APPLICATION_DATA *op201applData) {
	if (op201applData == NULL)
		return;
	op201applData->AIDLength = gp211applData.AIDLength;
	memcpy(op201applData->AID, gp211applData.AID, gp211applData.AIDLength);
	op201applData->lifeCycleState = gp211applData.lifeCycleState;
	op201applData->privileges = gp211applData.privileges;
}

static LONG readDAPBlock(PBYTE buf, PDWORD bufLength, OP201_DAP_BLOCK dapBlock);

/**
 * Reads a valid buffer containing a (delete, load, install) receipt and parses it in a GP211_RECEIPT_DATA.
 * \param buf IN The buffer to parse.
 * \param receiptData OUT The receipt data.
 * \return The number of bytes which were consumed while parsing the buffer.
 */
static DWORD fillReceipt(PBYTE buf, GP211_RECEIPT_DATA *receiptData) {
	DWORD j = 0;
	LOG_START(_T("fillReceipt"));
	j++;
	memcpy(receiptData->receipt, buf+j, 8);
	j+=8;
	receiptData->confirmationCounterLength = 2;//buf[j++];
	j++;
	memcpy(receiptData->confirmationCounter, buf+j, receiptData->confirmationCounterLength);
	j+=receiptData->confirmationCounterLength;
	receiptData->cardUniqueDataLength = 1;//buf[j++];
	j++;
	memcpy(receiptData->cardUniqueData, buf+j, receiptData->cardUniqueDataLength);
	j+=receiptData->cardUniqueDataLength;
	LOG_END(_T("fillReceipt"),j);
	return j;
}

/**
 * Reads a DAP block and parses it to the buffer buf.
 * \param buf OUT The buffer.
 * \param bufLength INOUT The length of the buffer and the returned data.
 * \param loadFileDataBlockSignature IN The Load File Data Block Signature.
 * \return OPGP_ERROR_SUCCESS if no error, error code else
 */
static LONG readLoadFileDataBlockSignature(PBYTE buf, PDWORD bufLength, GP211_DAP_BLOCK loadFileDataBlockSignature) {
	DWORD j=0;
	DWORD length;
	LOG_START(_T("readLoadFileDataBlockSignature"));

	/* Length = Tag + length signature block + Tag + length SD AID
	 * + Tag + length signature
	 */
	/* signature length */
	length = loadFileDataBlockSignature.signatureLength;
	/* Tag signature */
	length++;
	/* length byte signature */
	length++;
	/* Dealing with BER length encoding - if greater than 127 coded on two bytes. */
	if (length > 127) {
		length++;
	}
	/* SD AID length */
	length+=loadFileDataBlockSignature.securityDomainAIDLength;
	/* Tag SD */
	length++;
	/* length byte SD */
	length++;

	if (length <= 127) {
		if (length+2 > *bufLength) {
			return OPGP_ERROR_INSUFFICIENT_BUFFER;
		}
	}
	else {
		if (length+3 > *bufLength) {
			return OPGP_ERROR_INSUFFICIENT_BUFFER;
		}
	}

	buf[j++] = 0xE2; // Tag indicating a DAP block.

	if (length <= 127) {
		buf[j++] = (BYTE)length;
	}
	else if (length > 127) {
		buf[j++] = 0x81;
		buf[j++] = (BYTE)length;
	}

	buf[j++] = 0x4F; // Tag indicating a Security Domain AID.
	buf[j++] = loadFileDataBlockSignature.securityDomainAIDLength;
	memcpy(buf+j, loadFileDataBlockSignature.securityDomainAID, loadFileDataBlockSignature.securityDomainAIDLength);
	j+=loadFileDataBlockSignature.securityDomainAIDLength;
	buf[j++] = 0xC3; // The Tag indicating a signature
	/* Dealing with BER length encoding - if greater than 127 coded on two bytes. */
	if (loadFileDataBlockSignature.signatureLength <= 127) {
		buf[j++] = loadFileDataBlockSignature.signatureLength;
	}
	else if (loadFileDataBlockSignature.signatureLength > 127) {
		buf[j++] = 0x81;
		buf[j++] = loadFileDataBlockSignature.signatureLength;
	}
	memcpy(buf+j, loadFileDataBlockSignature.signature, loadFileDataBlockSignature.signatureLength);
	j+=loadFileDataBlockSignature.signatureLength;
	LOG_END(_T("readLoadFileDataBlockSignature"), OPGP_ERROR_SUCCESS);
	return OPGP_ERROR_SUCCESS;
}

/**
 * \param cardContext OUT The returned POPGP_CARDCONTEXT.
 * \return OPGP_ERROR_SUCCESS if no error, error code else
 */
LONG establish_context(OPGP_CARDCONTEXT *cardContext) {
	LONG result;
	LOG_START(_T("establish_context"));
	result = SCardEstablishContext( SCARD_SCOPE_USER,
									NULL,
									NULL,
									cardContext);
	if ( SCARD_S_SUCCESS != result ) {
		goto end;
	}
	result = OPGP_ERROR_SUCCESS;
end:
	LOG_END(_T("establish_context"), result);
	return result;
}

/**
 * \param cardContext IN The valid OPGP_CARDCONTEXT returned by establish_context()
 * \return OPGP_ERROR_SUCCESS if no error, error code else
 */
LONG release_context(OPGP_CARDCONTEXT cardContext) {
	LONG result;
	LOG_START(_T("release_context"));
	result = SCardReleaseContext(cardContext);
	if ( SCARD_S_SUCCESS != result ) {
		goto end;
	}
	result = OPGP_ERROR_SUCCESS;
end:
	LOG_END(_T("release_context"), result);
	return result;
}

/**
 * \param cardContext IN The valid OPGP_CARDCONTEXT returned by establish_context()
 * \param readerNames OUT The reader names will be a multi-string and separated by a NULL character and ended by a double NULL.
 *  (ReaderA\\0ReaderB\\0\\0). If this value is NULL, list_readers ignores the buffer length supplied in
 *  readerNamesLength, writes the length of the multi-string that would have been returned if this parameter
 *  had not been NULL to readerNamesLength.
 * \param readerNamesLength INOUT The length of the multi-string including all trailing null characters.
 * \return OPGP_ERROR_SUCCESS if no error, error code else
 */
LONG list_readers(OPGP_CARDCONTEXT cardContext, OPGP_STRING readerNames, PDWORD readerNamesLength) {
	LONG result;
	DWORD readersSize = 0;
	OPGP_STRING readers = NULL;
	LOG_START(_T("list_readers"));
	result = SCardListReaders( cardContext, NULL, NULL, &readersSize );
	if ( SCARD_S_SUCCESS != result ) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("readerSize: %d"), readersSize);
#endif
	if (readerNames == NULL) {
		*readerNamesLength = readersSize;
		result = OPGP_ERROR_SUCCESS;
		goto end;
	}
	readers = (OPGP_STRING)malloc(sizeof(TCHAR)*readersSize);
	result = SCardListReaders( cardContext, NULL, readers, &readersSize);
	if ( SCARD_S_SUCCESS != result ) {
		goto end;
	}
	if (*readerNamesLength < readersSize) {
		_tcsncpy(readerNames, readers, (*readerNamesLength)-2);
		*(readerNames+(*readerNamesLength)-2) = _T('\0');
		*(readerNames+(*readerNamesLength)-1) = _T('\0');
		*readerNamesLength = readersSize;
	}
	else {
		memcpy(readerNames, readers, sizeof(TCHAR)*readersSize);
		*readerNamesLength = readersSize;
	}
	result = OPGP_ERROR_SUCCESS;
end:
	if (readers)
		free(readers);
	LOG_END(_T("list_readers"), result);
	return result;
}

/**
 * If something is not working, you may want to change the protocol type.
 * \param cardContext IN The valid OPGP_CARDCONTEXT returned by establish_context()
 * \param readerName IN The name of the reader to connect.
 * \param *cardInfo OUT The returned OPGP_CARD_INFO.
 * \param protocol IN The transmit protocol type to use. Can be OPGP_CARD_PROTOCOL_T0 or OPGP_CARD_PROTOCOL_T1 or both ORed.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG card_connect(OPGP_CARDCONTEXT cardContext, OPGP_CSTRING readerName, OPGP_CARD_INFO *cardInfo,
				  DWORD protocol) {
	LONG result;
	DWORD activeProtocol;
	DWORD readerNameLength;
	DWORD state;
	DWORD dummy;
	BYTE ATR[32];
	DWORD ATRLength=32;

	LOG_START(_T("card_connect"));
	result = SCardConnect( cardContext,
							readerName,
							SCARD_SHARE_EXCLUSIVE,
							protocol,
							&(cardInfo->cardHandle),
							&activeProtocol );
	if ( SCARD_S_SUCCESS != result ) {
		goto end;
	}
	readerNameLength = (DWORD)(_tcslen(readerName)*sizeof(TCHAR)+1);

	result = SCardStatus(cardInfo->cardHandle, (OPGP_STRING)readerName, &readerNameLength, &state, &dummy, ATR, &ATRLength);
	if ( SCARD_S_SUCCESS != result ) {
		goto end;
	}
	memcpy(cardInfo->ATR, ATR, 32);
	cardInfo->protocol = dummy;
	cardInfo->ATRLength = ATRLength;
	cardInfo->state = state;

	cardInfo->logicalChannel = 0;

	result = OPGP_ERROR_SUCCESS;
end:
	LOG_END(_T("card_connect"), result);
	return result;
}

/**
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG card_disconnect(OPGP_CARD_INFO cardInfo) {
	LONG result;
	LOG_START(_T("card_disconnect"));
	result = SCardDisconnect(cardInfo.cardHandle, SCARD_RESET_CARD);
	if ( SCARD_S_SUCCESS != result ) {
		goto end;
	}
	result = OPGP_ERROR_SUCCESS;
end:
	LOG_END(_T("card_disconnect"), result);
	return result;
}


/**
 * Converts a ISO 7816-4 Le Byte into its value.
 * \param b IN The Le BYTE.
 * \return Value of b.
 */
static DWORD convertByte(BYTE b) {
	return (b == 0) ? 256 : b;
}

/**
 * Wraps a APDU with the necessary security information according to secInfo.
 * The wrappedapduCommand must be a buffer with enough space for the potential added padding for the encryption
 * and the MAC. The maximum possible extra space to the apduCommandLength is 8 bytes for the MAC plus 7 bytes for padding
 * and one Lc byte in the encryption process.
 * \param apduCommand IN The command APDU.
 * \param apduCommandLength IN The length of the command APDU.
 * \param wrappedApduCommand OUT The buffer for the wrapped APDU command.
 * \param wrappedApduCommandLength INOUT The available and returned modified length of the wrappedApduCommand buffer.
 * \param *secInfo IN The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
static LONG wrap_command(PBYTE apduCommand, DWORD apduCommandLength, PBYTE wrappedApduCommand, PDWORD wrappedApduCommandLength, GP211_SECURITY_INFO *secInfo) {
	LONG result;
	BYTE lc;
	BYTE le;
	DWORD wrappedLength;
	unsigned char mac[8];
	unsigned char encryption[240];
	int encryptionLength = 240;
	DWORD caseAPDU;
	BYTE C_MAC_ICV[8];
	int C_MAC_ICVLength = 8;
//#ifdef DEBUG
//	DWORD i;
//#endif
	LOG_START(_T("wrap_command"));
	if (*wrappedApduCommandLength < apduCommandLength)
			{ result = OPGP_ERROR_INSUFFICIENT_BUFFER; goto end; }
	memcpy(wrappedApduCommand, apduCommand, apduCommandLength);

	// no security level defined, just return
	if (secInfo == NULL) {
		*wrappedApduCommandLength = apduCommandLength;
		{ result = OPGP_ERROR_SUCCESS; goto end; }
	}

	// trivial case, just return
	if (secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_NO_SECURE_MESSAGING || secInfo->securityLevel == GP211_SCP01_SECURITY_LEVEL_NO_SECURE_MESSAGING) {
		*wrappedApduCommandLength = apduCommandLength;
		{ result = OPGP_ERROR_SUCCESS; goto end; }
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
		if ((convertByte(lc) + 5) == apduCommandLength) {
		// Case 3 short
			wrappedLength = convertByte(lc) + 5;
			caseAPDU = 3;
		} else if ((convertByte(lc) + 5 + 1) == apduCommandLength) {
		// Case 4 short
			wrappedLength = convertByte(lc) + 5;
			caseAPDU = 4;

		le = apduCommand[apduCommandLength - 1];
		apduCommandLength--;
		} else {
			{ result = OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND; goto end; }
		}
	} // if (Determine which type of Exchange)

	if  (secInfo->securityLevel != GP211_SCP02_SECURITY_LEVEL_NO_SECURE_MESSAGING && secInfo->securityLevel != GP211_SCP01_SECURITY_LEVEL_NO_SECURE_MESSAGING) {
		if (secInfo->securityLevel == GP211_SCP01_SECURITY_LEVEL_C_DEC_C_MAC
			|| secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC
			|| secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC) {
			switch (caseAPDU) {
				case 3:
					if (apduCommandLength > 239 + 8 + 5) { result = OPGP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE; goto end; } // max apdu data size = 239 + 1 byte Lc
					break;
				case 4:
					if (apduCommandLength > 239 + 8 + 5 + 1) { result = OPGP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE; goto end; }
					break;
			}
		}
		if (secInfo->securityLevel == GP211_SCP01_SECURITY_LEVEL_C_MAC
			|| secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_C_MAC
			|| secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_C_MAC_R_MAC) {
			switch (caseAPDU) {
				case 3:
					if (apduCommandLength > 247 + 8 + 5) { result = OPGP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE; goto end; }
					break;
				case 4:
					if (apduCommandLength > 247 + 8 + 5 + 1) { result = OPGP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE; goto end; }
					break;
			}
		}
		/* C_MAC on modified APDU */
		if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i04
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i05
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i14
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i15
			|| secInfo->secureChannelProtocolImpl == GP211_SCP01_IMPL_i05
			|| secInfo->secureChannelProtocolImpl == GP211_SCP01_IMPL_i15) {

			switch (caseAPDU) {
				case 1:
				case 2: {
					if (*wrappedApduCommandLength < apduCommandLength + 8 + 1)
						{ result = OPGP_ERROR_INSUFFICIENT_BUFFER; goto end; }
					wrappedLength += 8 + 1;
					wrappedApduCommand[4] = 0x08;
					break;
				}
				case 3:
				case 4: {
					if (*wrappedApduCommandLength < apduCommandLength + 8) {
						{ result = OPGP_ERROR_INSUFFICIENT_BUFFER; goto end; }
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
				 || secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1B) {
					 result = calculate_enc_ecb_single_des(secInfo->C_MACSessionKey,
						 secInfo->lastC_MAC, 8,
						 C_MAC_ICV, &C_MAC_ICVLength);
					if (result != OPGP_ERROR_SUCCESS) {
						goto end;
					}
			}
			else {
				memcpy(C_MAC_ICV, secInfo->lastC_MAC, 8);
			}
		} else {
			if (secInfo->secureChannelProtocolImpl == GP211_SCP01_IMPL_i15) {
				result = calculate_enc_ecb_two_key_triple_des(secInfo->C_MACSessionKey,
					secInfo->lastC_MAC, 8,
						 C_MAC_ICV, &C_MAC_ICVLength);
				if (result != OPGP_ERROR_SUCCESS) {
					goto end;
				}
			}
			else {
				memcpy(C_MAC_ICV, secInfo->lastC_MAC, 8);
			}
		}
		if (secInfo->secureChannelProtocol == GP211_SCP02) {
			result = calculate_MAC_des_3des(secInfo->C_MACSessionKey, wrappedApduCommand, wrappedLength-8,
				C_MAC_ICV, mac);
			if (result != OPGP_ERROR_SUCCESS) {
				goto end;
			}
		}
		else {
			result = calculate_MAC(secInfo->C_MACSessionKey, wrappedApduCommand, wrappedLength-8,
				C_MAC_ICV, mac);
			if (result != OPGP_ERROR_SUCCESS) {
				goto end;
			}
		}
		memcpy(secInfo->lastC_MAC, mac, 8);
		memcpy(wrappedApduCommand+wrappedLength-8, mac, 8);

		/* C_MAC on unmodified APDU */
		if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0A
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0B
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1A
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1B) {

			switch (caseAPDU) {
				case 1:
				case 2: {
					if (*wrappedApduCommandLength < apduCommandLength + 8 + 1)
						{ result = OPGP_ERROR_INSUFFICIENT_BUFFER; goto end; }
					wrappedLength += 8 + 1;
					wrappedApduCommand[4] = 0x08;
					break;
				}
				case 3:
				case 4: {
					if (*wrappedApduCommandLength < apduCommandLength + 8) {
						{ result = OPGP_ERROR_INSUFFICIENT_BUFFER; goto end; }
					}
					wrappedLength += 8;
					wrappedApduCommand[4]+=8;
					break;
				}
			} // switch (caseAPDU)
			wrappedApduCommand[0] = apduCommand[0] | 0x04;
		}

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
						result = calculate_enc_cbc_SCP02(secInfo->encryptionSessionKey,
							wrappedApduCommand+5, wrappedLength-5-8, encryption, &encryptionLength);
						if (result != OPGP_ERROR_SUCCESS) {
							goto end;
						}
					}
					else {
						result = calculate_enc_cbc(secInfo->encryptionSessionKey,
							wrappedApduCommand+4, wrappedLength-4-8, encryption, &encryptionLength);
						if (result != OPGP_ERROR_SUCCESS) {
							goto end;
						}
					}
					break;
				case 2:
				case 4:
					if (secInfo->secureChannelProtocol == GP211_SCP02) {
						result = calculate_enc_cbc_SCP02(secInfo->encryptionSessionKey,
							wrappedApduCommand+5, wrappedLength-5-8-1, encryption, &encryptionLength);
						if (result != OPGP_ERROR_SUCCESS) {
							goto end;
						}
					}
					else {
						result = calculate_enc_cbc(secInfo->encryptionSessionKey,
							wrappedApduCommand+4, wrappedLength-4-8-1, encryption, &encryptionLength);
						if (result != OPGP_ERROR_SUCCESS) {
							goto end;
						}
					}
					break;
			}
			wrappedLength = encryptionLength + 4 + 1 + 8;
			if (*wrappedApduCommandLength < wrappedLength)
				{ result = OPGP_ERROR_INSUFFICIENT_BUFFER; goto end; }
			memcpy(wrappedApduCommand+5, encryption, encryptionLength);
			wrappedApduCommand[4] = encryptionLength + 8;
			memcpy(&wrappedApduCommand[encryptionLength + 5], mac, 8);
			if ((caseAPDU == 2) || (caseAPDU == 4)) {
				if (*wrappedApduCommandLength < wrappedLength+1)
					{ result = OPGP_ERROR_INSUFFICIENT_BUFFER; goto end; }
				wrappedApduCommand[wrappedLength] = le;
				wrappedLength++;
			}
		} // if (secInfo->securityLevel == GP211_SCP01_SECURITY_LEVEL_C_DEC_C_MAC || secInfo->securityLevel == GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC)
		*wrappedApduCommandLength = wrappedLength;
	} // if (secInfo->securityLevel != GP211_SCP02_SECURITY_LEVEL_NO_SECURE_MESSAGING && secInfo->securityLevel != GP211_SCP01_SECURITY_LEVEL_NO_SECURE_MESSAGING)
//#ifdef DEBUG
//	log_Log(_T("wrap_command: Data to send: "));
//	for (i=0; i<wrappedLength; i++) {
//		log_Log(_T(" 0x%02x"), wrappedApduCommand[i]);
//	}
//
//#endif

	result = OPGP_ERROR_SUCCESS;
end:
	LOG_END(_T("wrap_command"), result);
	return result;
}

/**
 * The secInfo pointer can also be null and so this function can be used for arbitrary cards.
 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param capdu IN The command APDU.
 * \param capduLength IN The length of the command APDU.
 * \param rapdu OUT The response APDU.
 * \param rapduLength INOUT The length of the the response APDU.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_send_APDU(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, PBYTE capdu, DWORD capduLength, PBYTE rapdu, PDWORD rapduLength) {
	return send_APDU(cardInfo, secInfo, capdu, capduLength, rapdu, rapduLength);
}

static LONG send_APDU(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, PBYTE capdu, DWORD capduLength, PBYTE rapdu, PDWORD rapduLength) {
	LONG result;
	// modified for managing all 4 cases with automatic APDU chaining

	// when necessary...

	BYTE apduCommand[261];
	DWORD caseAPDU;
	DWORD apduCommandLength = 261;
	BYTE lc;
	BYTE le;
	BYTE la;

	DWORD i;

	DWORD offset = 0;

	PBYTE responseData = NULL;
	DWORD responseDataLength = *rapduLength;

	LOG_START(_T("send_APDU"));
	responseData = (PBYTE)malloc(sizeof(BYTE)*responseDataLength);

	if (traceEnable) {
		_ftprintf(traceFile, _T("--> "));
		for (i=0; i<capduLength; i++) {
			_ftprintf(traceFile, _T("%02X"), capdu[i]);
		}
		_ftprintf(traceFile, _T("\n"));
	}

	// main transmission block

	// wrap command
	result = wrap_command(capdu, capduLength, apduCommand, &apduCommandLength, secInfo);
	if ( OPGP_ERROR_SUCCESS != result) {
		goto end;
	}

	apduCommand[0] |= cardInfo.logicalChannel;

	// if T=1 or else T=0
	if (cardInfo.protocol == OPGP_CARD_PROTOCOL_T1) {

		// T=1 transmition

		result = SCardTransmit(cardInfo.cardHandle,
				SCARD_PCI_T1,
				apduCommand,
				apduCommandLength,
				NULL,
				responseData,
				&responseDataLength
				);
		if ( SCARD_S_SUCCESS != result) {
			goto end;
		} // if ( SCARD_S_SUCCESS != result)
                offset += responseDataLength - 2;
	} else {
		// Determine which type of Exchange between the reader
		if (apduCommandLength == 4) {
		// Case 1 short

		caseAPDU = 1;
		} else if (apduCommandLength == 5) {
		// Case 2 short

		caseAPDU = 2;
		le = apduCommand[4];
		} else {
			lc = apduCommand[4];
			if ((convertByte(lc) + 5) == apduCommandLength) {
			// Case 3 short

			caseAPDU = 3;
			} else if ((convertByte(lc) + 5 + 1) == apduCommandLength) {
			// Case 4 short

			caseAPDU = 4;

			le = apduCommand[apduCommandLength - 1];
			apduCommandLength--;
			} else {
			{ result = OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND; goto end; }
			}
		} // if (Determine which type of Exchange)

		// T=0 transmition (first command)

		responseDataLength = *rapduLength;
		result = SCardTransmit(cardInfo.cardHandle,
				SCARD_PCI_T0,
				apduCommand,
				apduCommandLength,
				NULL,
				responseData,
				&responseDataLength
				);
		if ( SCARD_S_SUCCESS != result) {
			goto end;
		} // if ( SCARD_S_SUCCESS != result)
		offset += responseDataLength - 2;
		// main switch block for cases 2 and 4

		switch (caseAPDU) {
			case 2: {

				while ((responseData[responseDataLength + offset - 2] == 0x61)
					|| (responseData[responseDataLength + offset - 2] == 0x6c)) {

					//Le is not accepted by the card and the card indicates the available length La.
					//The response TPDU from the card indicates that the command is aborted due to
					//a wrong length and that the right length is La: (SW1='6C' and SW2 codes La).

					if (responseData[responseDataLength + offset - 2] == 0x6c) {

						la = responseData[responseDataLength + offset - 1];

						apduCommand[apduCommandLength-1] = la; // P3

						// T=0 transmition (command w/ La)

						responseDataLength = *rapduLength - offset;
						result = SCardTransmit(cardInfo.cardHandle,
								SCARD_PCI_T0,
								apduCommand,
								apduCommandLength,
								NULL,
								responseData+offset,
								&responseDataLength
								);
						if ( SCARD_S_SUCCESS != result) {
							goto end;
						}

						// If La is greater that Le, then the response TPDU is mapped
						// onto the response APDU by keeping only the first Le bytes
						// of the body and the status bytes SW1-SW2.

						if (convertByte(le) < convertByte(la)) {
							memmove(responseData+offset+convertByte(le), responseData+offset+responseDataLength-2, 2);
							offset += convertByte(le);
							break;
						} // if (convertByte(le) < convertByte(la))
						offset += responseDataLength - 2;
						le = la;
						continue;

					} // if (6C)

					// Java Card specific. Java Card RE Specification Chapter 9

					// if (61)

					if (responseData[responseDataLength + offset - 2] == 0x61) {

						// Lr < Le
						// 1. The card sends <0x61,Lr> completion status bytes
						// 2. The CAD sends GET RESPONSE command with Le = Lr.
						// 3. The card sends Lr bytes of output data using the standard T=0 <INS> or <~INS>
						// procedure byte mechanism.
						// 4. The card sends <SW1,SW2> completion status on completion of the
						// Applet.process method.

						// Lr > Le
						// 1. The card sends Le bytes of output data using the standard T=0 <INS> or
						// <~INS> procedure byte mechanism.
						// 2. The card sends <0x61,(Lr-Le)> completion status bytes
						// 3. The CAD sends GET RESPONSE command with new Le <= Lr.
						// 4. The card sends (new) Le bytes of output data using the standard T=0 <INS> or
						// <~INS> procedure byte mechanism.
						// 5. Repeat steps 2-4 as necessary to send the remaining output data bytes (Lr) as
						// required.
						// 6. The card sends <SW1,SW2> completion status on completion of the
						// Applet.process method.

						// These two cases behave the same way
						la = responseData[responseDataLength + offset - 1];

						apduCommand[0] = 0x00;;
						apduCommand[1] = 0xC0; // INS (Get Response)
						apduCommand[2] = 0x00; // P1
						apduCommand[3] = 0x00; // P2
						apduCommand[4] = la;
						apduCommandLength = 5;
						le = la;
						// T=0 transmition (command w/ La)

						responseDataLength = *rapduLength - offset;
						result = SCardTransmit(cardInfo.cardHandle,
								SCARD_PCI_T0,
								apduCommand,
								apduCommandLength,
								NULL,
								responseData+offset,
								&responseDataLength
								);
						if ( SCARD_S_SUCCESS != result) {
							goto end;
						} // if ( SCARD_S_SUCCESS != result)
						offset += responseDataLength - 2;
						continue;
					} // if (61)
				} // while (61) || (6c)
			break;
			} // case 2

			case 4: {

				/* Note: Some smartcard are not fully compatible
					with ISO normatives in case short 4.
					So when a card returns a 0x9000 to inform a good
					transfer of the APDU command then the terminal
					have to terminate the transaction and it shall
					return the sw1 sw2 to the user. In the case of
					fully ISO, the terminal sends a get response
					to extract the "le" bytes requested inside
					the APDU command. */

				// if 61 etc.

				if (responseData[responseDataLength + offset - 2] == 0x61
					|| responseData[responseDataLength + offset - 2] == 0x90
					|| responseData[responseDataLength + offset - 2] == 0x9F) {

					apduCommand[0] = 0x00;
					apduCommand[1] = 0xC0; // INS (Get Response)
					apduCommand[2] = 0x00; // P1
					apduCommand[3] = 0x00; // P2
					apduCommandLength = 5;

					// Default Case Le is requested in the get response

					apduCommand[4] = le; // P3

					// verify if we have La < Le in the case of sw2 = 0x61 or 0x9f

					if (responseData[responseDataLength + offset - 2] != 0x90) {
						if (convertByte(responseData[responseDataLength + offset - 1]) < convertByte(le)) {
						// La is requested in the get response

						apduCommand[4] = responseData[responseDataLength + offset - 1];
						le = responseData[responseDataLength + offset - 1];
						}
					}

					// T=0 transmission (command w/ Le or La)

					responseDataLength = *rapduLength - offset;
					result = SCardTransmit(cardInfo.cardHandle,
							SCARD_PCI_T0,
							apduCommand,
							apduCommandLength,
							NULL,
							responseData+offset,
							&responseDataLength
							);
					if ( SCARD_S_SUCCESS != result) {
						goto end;
					} // if ( SCARD_S_SUCCESS != result)
					offset += responseDataLength - 2;

				} // if (61 etc.)

				while ((responseData[responseDataLength + offset - 2] == 0x61)
					|| (responseData[responseDataLength + offset - 2] == 0x6c)
					|| (responseData[responseDataLength + offset - 2] == 0x9f)) {

					// if (6c)

					if (responseData[responseDataLength + offset - 2] == 0x6c) {

						la = responseData[responseDataLength + offset - 1];
						apduCommand[apduCommandLength -1] = la; // P3

						// T=0 transmition (command w/ La)

						responseDataLength = *rapduLength - offset;
						result = SCardTransmit(cardInfo.cardHandle,
								SCARD_PCI_T0,
								apduCommand,
								apduCommandLength,
								NULL,
								responseData+offset,
								&responseDataLength
								);
						if ( SCARD_S_SUCCESS != result) {
							goto end;
						}

						// If La is greater that Le, then the response TPDU is mapped
						// onto the response APDU by keeping only the first Le bytes
						// of the body and the status bytes SW1-SW2.

						if (convertByte(le) < convertByte(la)) {
							memmove(responseData+offset+convertByte(le), responseData+offset+responseDataLength-2, 2);
							offset += convertByte(le);
							break;
						} // if (convertByte(le) < convertByte(la))
						offset += responseDataLength - 2;
						le = la;
						continue;

					} // if (6c)

					// if (61) || (9f)

					if ((responseData[responseDataLength + offset - 2] == 0x61)
					|| (responseData[responseDataLength + offset - 2] == 0x9f)) {

						// Lr < Le
						// 1. The card sends <0x61,Lr> completion status bytes
						// 2. The CAD sends GET RESPONSE command with Le = Lr.
						// 3. The card sends Lr bytes of output data using the standard T=0 <INS> or <~INS>
						// procedure byte mechanism.
						// 4. The card sends <SW1,SW2> completion status on completion of the
						// Applet.process method.

						// Lr > Le
						// 1. The card sends Le bytes of output data using the standard T=0 <INS> or
						// <~INS> procedure byte mechanism.
						// 2. The card sends <0x61,(Lr-Le)> completion status bytes
						// 3. The CAD sends GET RESPONSE command with new Le <= Lr.
						// 4. The card sends (new) Le bytes of output data using the standard T=0 <INS> or
						// <~INS> procedure byte mechanism.
						// 5. Repeat steps 2-4 as necessary to send the remaining output data bytes (Lr) as
						// required.
						// 6. The card sends <SW1,SW2> completion status on completion of the
						// Applet.process method.

						la = responseData[responseDataLength + offset - 1];

						apduCommand[0] = 0x00;
						apduCommand[1] = 0xC0; // INS (Get Response)
						apduCommand[2] = 0x00; // P1
						apduCommand[3] = 0x00; // P2
						apduCommand[4] = la;
						apduCommandLength = 5;
						le = la;
						// T=0 transmition (command w/ La)

						responseDataLength = *rapduLength - offset;
						result = SCardTransmit(cardInfo.cardHandle,
								SCARD_PCI_T0,
								apduCommand,
								apduCommandLength,
								NULL,
								responseData+offset,
								&responseDataLength
								);
						if ( SCARD_S_SUCCESS != result) {
							goto end;
						}
						offset += responseDataLength - 2;
						continue;

					} // if (61) || (9f)

				} // while (61) || (6c) || (9f)

			break;
			} // case 4

		} // switch (main switch block for cases 2 and 4)

	} // if (if T=1 or else T=0)

	// if the case 3 command is actually a case 4 command and the cards wants to responds something.

	if (responseData[responseDataLength + offset - 2] == 0x61) {

		la = responseData[responseDataLength + offset - 1];

		apduCommand[0] = 0x00;;
		apduCommand[1] = 0xC0; // INS (Get Response)
		apduCommand[2] = 0x00; // P1
		apduCommand[3] = 0x00; // P2
		apduCommand[4] = la;
		apduCommandLength = 5;
		le = la;
		// T=0 transmition (command w/ La)

		responseDataLength = *rapduLength - offset;
		result = SCardTransmit(cardInfo.cardHandle,
				cardInfo.protocol == OPGP_CARD_PROTOCOL_T0 ? SCARD_PCI_T0 : SCARD_PCI_T1,
				apduCommand,
				apduCommandLength,
				NULL,
				responseData+offset,
				&responseDataLength
				);
		if ( SCARD_S_SUCCESS != result) {
			goto end;
		} // if ( SCARD_S_SUCCESS != result)
		offset += responseDataLength - 2;
	} // if (61)

	memcpy(rapdu, responseData, offset + 2);
	*rapduLength = offset + 2;

	if (traceEnable) {
		_ftprintf(traceFile, _T("<-- "));
		for (i=0; i<*rapduLength; i++) {
			_ftprintf(traceFile, _T("%02X"), rapdu[i]);
		}
		_ftprintf(traceFile, _T("\n"));
	}

	if (rapdu[*rapduLength-2] != 0x90 || rapdu[*rapduLength-1] != 0x00) {
		result = (OPGP_ISO7816_ERROR_PREFIX | (rapdu[*rapduLength-2] << 8)) | rapdu[*rapduLength-1];
		goto end;
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	if (responseData)
		free(responseData);
	LOG_END(_T("send_APDU"), result);
	return result;
}

/**
 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param AID IN The AID.
 * \param AIDLength IN The length of the AID.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG select_application(OPGP_CARD_INFO cardInfo, PBYTE AID, DWORD AIDLength) {
	LONG result;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[256];
	DWORD sendBufferLength=256;
	DWORD i=0;
	LOG_START(_T("select_application"));
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 0xA4;
	sendBuffer[i++] = 0x04;
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = (BYTE)AIDLength;
	memcpy(sendBuffer+i, AID, AIDLength);
	i+=AIDLength;
	sendBufferLength = i;
	/* Le */
	sendBuffer[i++] = 0x00;
#ifdef DEBUG
	log_Log(_T("select_application: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, NULL, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_SUCCESS != result) {
		switch (result) {
			case OPGP_ISO7816_ERROR_CONDITIONS_NOT_SATISFIED:
				{ result = OPGP_ISO7816_ERROR_NOT_MULTI_SELECTABLE; goto end; }
			case OPGP_ISO7816_ERROR_6999:
				{ result = OPGP_ISO7816_ERROR_SELECTION_REJECTED; goto end; }
			case OPGP_ISO7816_ERROR_FUNC_NOT_SUPPORTED:
				{ result = OPGP_ISO7816_ERROR_APPLET_NOT_SELECTABLE; goto end; }
			case OPGP_ISO7816_ERROR_FILE_NOT_FOUND:
				{ result = OPGP_ISO7816_ERROR_APPLET_NOT_FOUND; goto end; }
			case OPGP_ISO7816_ERROR_FILE_INVALIDATED:
				{ result = OPGP_ISO7816_WARNING_CM_LOCKED; goto end; }
			default:
				goto end;
		}
	}
#ifdef DEBUG
	log_Log(_T("select_application: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("select_application"), result);
	return result;
}

/**
 * A keySetVersion value of 0x00 adds a new key.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version a new key belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param keySetVersion IN An existing key set version.
 * \param keyIndex IN The position of the key in the key set version.
 * \param newKeySetVersion IN The new key set version.
 * \param PEMKeyFileName IN A PEM file name with the public RSA key.
 * \param *passPhrase IN The passphrase. Must be an ASCII string.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_put_rsa_key(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion,
				 OPGP_STRING PEMKeyFileName, char *passPhrase) {
	return put_rsa_key(cardInfo, secInfo, keySetVersion, keyIndex,
						 newKeySetVersion, PEMKeyFileName, passPhrase);
}

static LONG put_rsa_key(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion,
				 OPGP_STRING PEMKeyFileName, char *passPhrase) {
	LONG result;
	BYTE sendBuffer[261];
	DWORD sendBufferLength=261;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	DWORD i=0;
	EVP_PKEY *key;
	FILE *PEMKeyFile;
	BYTE rsa_modulus[128];
	unsigned long rsa_exponent;
	LOG_START(_T("put_rsa_key"));
	if (passPhrase == NULL)
		{ result = OPGP_ERROR_INVALID_PASSWORD; goto end; }

	if ((PEMKeyFileName == NULL) || (_tcslen(PEMKeyFileName) == 0))
		{ result = OPGP_ERROR_INVALID_FILENAME; goto end; }
	PEMKeyFile = _tfopen(PEMKeyFileName, _T("rb"));
	if (PEMKeyFile == NULL) {
		{ result = errno; goto end; }
	}
	key = EVP_PKEY_new();
	if (!PEM_read_PUBKEY(PEMKeyFile, &key, NULL, passPhrase)) {
		fclose(PEMKeyFile);
		EVP_PKEY_free(key);
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	};
	fclose(PEMKeyFile);
	rsa_exponent = key->pkey.rsa->e->d[0];
	memcpy(rsa_modulus, key->pkey.rsa->n->d, sizeof(unsigned long)*key->pkey.rsa->n->top);
	EVP_PKEY_free(key);
        /*
	if (keySetVersion > 0x7f)
		{ result = OPGP_ERROR_WRONG_KEY_VERSION; goto end; }
	if ((newKeySetVersion > 0x7f) || (newKeySetVersion < 0x01))
		{ result = OPGP_ERROR_WRONG_KEY_VERSION; goto end; }
	if (keyIndex > 0x7f)
		{ result = OPGP_ERROR_WRONG_KEY_INDEX; goto end; }
        */
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xD8;
	sendBuffer[i++] = keySetVersion;
	sendBuffer[i++] = keyIndex;
	sendBuffer[i++] = 0; // Lc later calculated
	sendBuffer[i++] = newKeySetVersion;
	sendBuffer[i++] = 0xA1; // alghoritm RSA
	sendBuffer[i++] = 0x80; // length of RSA modulus
	memcpy(sendBuffer+i, rsa_modulus, 128); // modulus
	i+=128;
	if (rsa_exponent == 3) {
		sendBuffer[i++] = 1; // length of public exponent
		sendBuffer[i++] = 3;
	}
	else if (rsa_exponent == 65537) {
		sendBuffer[i++] = 3; // length of public exponent
		sendBuffer[i++] = 0x01;
		sendBuffer[i++] = 0x00;
		sendBuffer[i++] = 0x01;
	}
	else {
		{ result = OPGP_ERROR_WRONG_EXPONENT; goto end; }
	}
	sendBuffer[4] = (BYTE)i-5;
	sendBuffer[i++] = 0x00; // Le
	sendBufferLength = i;
#ifdef DEBUG
	log_Log(_T("put_rsa_key: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("put_rsa_key: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("put_rsa_key"), result);
	return result;
}

/**
 * A keySetVersion value of 0x00 adds a new key.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version a new key belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param keySetVersion IN An existing key set version.
 * \param keyIndex IN The position of the key in the key set version.
 * \param newKeySetVersion IN The new key set version.
 * \param _3DESKey IN The new 3DES key.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_put_3des_key(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				  BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, BYTE _3DESKey[16]) {
	return put_3des_key(cardInfo, secInfo, keySetVersion, keyIndex, newKeySetVersion, _3DESKey);
}

static LONG put_3des_key(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				  BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, BYTE _3DESKey[16]) {
	LONG result;
	BYTE sendBuffer[29];
	DWORD sendBufferLength = 29;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE keyCheckValue[8];
	BYTE encrypted_3des_key[16];
	int encrypted_3des_key_length;
	int keyCheckValueLength;
	BYTE keyCheckTest[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	DWORD i=0;
	LOG_START(_T("put_3des_key"));
        /*
	if (keySetVersion > 0x7f)
		{ result = OPGP_ERROR_WRONG_KEY_VERSION; goto end; }
	if (newKeySetVersion > 0x7f)
		{ result = OPGP_ERROR_WRONG_KEY_VERSION; goto end; }
	if (keyIndex > 0x7f)
		{ result = OPGP_ERROR_WRONG_KEY_INDEX; goto end; }
        */
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xD8;
	sendBuffer[i++] = keySetVersion;
	sendBuffer[i++] = keyIndex;
	sendBuffer[i++] = 0x17;
	sendBuffer[i++] = newKeySetVersion;
	if (secInfo->secureChannelProtocol == GP211_SCP01) {
		sendBuffer[i++] = 0x81; // alghoritm 3DES
	}
	else {
		sendBuffer[i++] = 0x80; // alghoritm 3DES
	}

	sendBuffer[i++] = 0x10; // length of 3DES key
	if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0B
		|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1B) {
			result = calculate_enc_cbc_SCP02(secInfo->dataEncryptionSessionKey, _3DESKey, 16,
				encrypted_3des_key, &encrypted_3des_key_length);
		}
	else {
		result = calculate_enc_ecb_two_key_triple_des(secInfo->dataEncryptionSessionKey, _3DESKey,
			16, encrypted_3des_key, &encrypted_3des_key_length);
	}

	if ( OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
	memcpy(sendBuffer+i, encrypted_3des_key, 16); // key
	i+=16;
	sendBuffer[i++] = 0x03; // length of key check value
	result = calculate_enc_ecb_two_key_triple_des(_3DESKey, keyCheckTest, 8, keyCheckValue, &keyCheckValueLength);
	if ( OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
	memcpy(sendBuffer+i, keyCheckValue, 3);
	i+=3;
	sendBuffer[i] = 0x00; // Le
#ifdef DEBUG
	log_Log(_T("put_3des_key: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("put_3des_key: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
	if (memcmp(keyCheckValue, recvBuffer+1, 3) != 0)
		{ result = OPGP_ERROR_KEY_CHECK_VALUE; goto end; }
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("put_3des_key"), result);
	return result;
}

/**
 * A keySetVersion value of 0x00 adds a new secure channel key set.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version a the new secure channel keys belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * It depends on the supported protocol implementation by the card what keys must be passed as parameters.
 * baseKey must be NULL if the protocol uses 3 Secure Channel Keys
 * (Secure Channel Encryption Key, Secure Channel Message Authentication Code Key and
 * Data Encryption Key) and vice versa.
 * Details about the supported Secure Channel Protocol and its implementation can be
 * obtained by a call to the function get_secure_channel_protocol_details().
 * \param keySetVersion IN An existing key set version.
 * \param newKeySetVersion IN The new key set version.
 * \param newBaseKey IN The new Secure Channel base key.
 * \param newS_ENC IN The new S-ENC key.
 * \param newS_MAC IN The new S-MAC key.
 * \param newDEK IN The new DEK.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_put_secure_channel_keys(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
							 BYTE keySetVersion,
							 BYTE newKeySetVersion, BYTE newBaseKey[16],
							 BYTE newS_ENC[16],
							 BYTE newS_MAC[16], BYTE newDEK[16]) {
	return put_secure_channel_keys(cardInfo, secInfo,
							 keySetVersion,
							 newKeySetVersion, newBaseKey, newS_ENC,
							 newS_MAC, newDEK);
}

static LONG put_secure_channel_keys(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
							 BYTE keySetVersion,
							 BYTE newKeySetVersion, BYTE newBaseKey[16],
							 BYTE newS_ENC[16],
							 BYTE newS_MAC[16], BYTE newDEK[16]) {
	LONG result;
	BYTE sendBuffer[73];
	DWORD sendBufferLength=73;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE keyCheckValue1[8];
	BYTE keyCheckValue2[8];
	BYTE keyCheckValue3[8];
	BYTE encrypted_key[16];
	int encrypted_key_length;
	int keyCheckValueLength;
	BYTE keyCheckTest[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	DWORD i=0;
	LOG_START(_T("put_secure_channel_keys"));
        /*
	if (keySetVersion > 0x7f)
		{ result = OPGP_ERROR_WRONG_KEY_VERSION; goto end; }
	if (newKeySetVersion > 0x7f)
		{ result = OPGP_ERROR_WRONG_KEY_VERSION; goto end; }
        */
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xD8;
	sendBuffer[i++] = keySetVersion;
	sendBuffer[i++] = 0x81;
	sendBuffer[i++] = 0x43;

	sendBuffer[i++] = newKeySetVersion;
	/* Secure Channel base key */
	if (secInfo->secureChannelProtocol == GP211_SCP02 &&
		(secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i04
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i14
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0A
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1A)) {
		sendBuffer[i++] = 0x81; // alghoritm 3DES
		sendBuffer[i++] = 0x10; // length of 3DES key
		if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0A
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1A) {
				result = calculate_enc_cbc_SCP02(secInfo->dataEncryptionSessionKey, newBaseKey, 16, encrypted_key, &encrypted_key_length);
			}
		else {
			result = calculate_enc_ecb_two_key_triple_des(secInfo->dataEncryptionSessionKey, newBaseKey, 16, encrypted_key, &encrypted_key_length);
		}
		if ( OPGP_ERROR_SUCCESS != result) {
			goto end;
		}
		memcpy(sendBuffer+i, encrypted_key, 16); // key
		i+=16;
		sendBuffer[i++] = 0x03; // length of key check value
		result = calculate_enc_ecb_two_key_triple_des(newBaseKey, keyCheckTest, 8, keyCheckValue1, &keyCheckValueLength);
		if ( OPGP_ERROR_SUCCESS != result) {
			goto end;
		}
		memcpy(sendBuffer+i, keyCheckValue1, 3);
		i+=3;
	}
	else {
		// S-ENC key
		if (secInfo->secureChannelProtocol == GP211_SCP01) {
			sendBuffer[i++] = 0x81; // alghoritm 3DES
		}
		else {
			sendBuffer[i++] = 0x80; // alghoritm 3DES
		}
		sendBuffer[i++] = 0x10; // length of 3DES key
		if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0B
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1B) {
				result = calculate_enc_cbc_SCP02(secInfo->dataEncryptionSessionKey, newS_ENC, 16, encrypted_key, &encrypted_key_length);
			}
		else {
			result = calculate_enc_ecb_two_key_triple_des(secInfo->dataEncryptionSessionKey, newS_ENC, 16, encrypted_key, &encrypted_key_length);
		}

		if ( OPGP_ERROR_SUCCESS != result) {
			goto end;
		}
		memcpy(sendBuffer+i, encrypted_key, 16); // key
		i+=16;
		sendBuffer[i++] = 0x03; // length of key check value
		result = calculate_enc_ecb_two_key_triple_des(newS_ENC, keyCheckTest, 8, keyCheckValue1, &keyCheckValueLength);
		if ( OPGP_ERROR_SUCCESS != result) {
			goto end;
		}
		memcpy(sendBuffer+i, keyCheckValue1, 3);
		i+=3;
		// S-MAC key

		if (secInfo->secureChannelProtocol == GP211_SCP01) {
			sendBuffer[i++] = 0x81; // alghoritm 3DES
		}
		else {
			sendBuffer[i++] = 0x80; // alghoritm 3DES
		}

		sendBuffer[i++] = 0x10; // length of 3DES key
		if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0B
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1B) {
				result = calculate_enc_cbc_SCP02(secInfo->dataEncryptionSessionKey, newS_MAC, 16, encrypted_key, &encrypted_key_length);
			}
		else {
			result = calculate_enc_ecb_two_key_triple_des(secInfo->dataEncryptionSessionKey, newS_MAC, 16, encrypted_key, &encrypted_key_length);
		}
		if ( OPGP_ERROR_SUCCESS != result) {
			goto end;
		}
		memcpy(sendBuffer+i, encrypted_key, 16); // key
		i+=16;
		sendBuffer[i++] = 0x03; // length of key check value
		result = calculate_enc_ecb_two_key_triple_des(newS_MAC, keyCheckTest, 8, keyCheckValue2, &keyCheckValueLength);
		if ( OPGP_ERROR_SUCCESS != result) {
			goto end;
		}
		memcpy(sendBuffer+i, keyCheckValue2, 3);
		i+=3;
		// DEK

		if (secInfo->secureChannelProtocol == GP211_SCP01) {
			sendBuffer[i++] = 0x81; // alghoritm 3DES
		}
		else {
			sendBuffer[i++] = 0x80; // alghoritm 3DES
		}

		sendBuffer[i++] = 0x10; // length of 3DES key
		if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0B
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1B) {
				result = calculate_enc_cbc_SCP02(secInfo->dataEncryptionSessionKey, newDEK, 16, encrypted_key, &encrypted_key_length);
			}
		else {
			result = calculate_enc_ecb_two_key_triple_des(secInfo->dataEncryptionSessionKey, newDEK, 16, encrypted_key, &encrypted_key_length);
		}
		if ( OPGP_ERROR_SUCCESS != result) {
			goto end;
		}
		memcpy(sendBuffer+i, encrypted_key, 16); // key
		i+=16;
		sendBuffer[i++] = 0x03; // length of key check value
		result = calculate_enc_ecb_two_key_triple_des(newDEK, keyCheckTest, 8, keyCheckValue3, &keyCheckValueLength);
		if ( OPGP_ERROR_SUCCESS != result) {
			goto end;
		}
		memcpy(sendBuffer+i, keyCheckValue3, 3);
		i+=3;
	}
	// send the stuff

	sendBuffer[i++] = 0x00; // Le
	sendBufferLength = i;

#ifdef DEBUG
	log_Log(_T("put_secure_channel_keys: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("put_secure_channel_keys: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
	if (memcmp(keyCheckValue1, recvBuffer+1, 3) != 0)
		{ result = OPGP_ERROR_KEY_CHECK_VALUE; goto end; }
	if (memcmp(keyCheckValue2, recvBuffer+1+3, 3) != 0)
		{ result = OPGP_ERROR_KEY_CHECK_VALUE; goto end; }
	if (memcmp(keyCheckValue3, recvBuffer+1+6, 3) != 0)
		{ result = OPGP_ERROR_KEY_CHECK_VALUE; goto end; }
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("put_secure_channel_keys"), result);
	return result;
}

/**
 * A keySetVersion value of 0x00 adds a new secure channel key set.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version a the new secure channel keys belongs to.
 * This can be the same key version or a new not existing key set version.

 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param keySetVersion IN An existing key set version.
 * \param newKeySetVersion IN The new key set version.
 * \param PEMKeyFileName IN A PEM file name with the public RSA key.
 * \param *passPhrase IN The passphrase. Must be an ASCII string.
 * \param receiptKey IN The new Receipt Generation key.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_put_delegated_management_keys(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								   BYTE keySetVersion, BYTE newKeySetVersion,
								   OPGP_STRING PEMKeyFileName, char *passPhrase,
								   BYTE receiptKey[16]) {
	return put_delegated_management_keys(cardInfo, secInfo,
								   keySetVersion, newKeySetVersion,
								   PEMKeyFileName, passPhrase,
								   receiptKey);
}

static LONG put_delegated_management_keys(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								   BYTE keySetVersion, BYTE newKeySetVersion,
								   OPGP_STRING PEMKeyFileName, char *passPhrase,
								   BYTE receiptKey[16]) {
	LONG result;
	BYTE sendBuffer[261];
	DWORD sendBufferLength=261;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE keyCheckValue[8];
	BYTE encrypted_key[16];
	int encrypted_key_length;
	int keyCheckValueLength;
	BYTE keyCheckTest[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	DWORD i=0;
	EVP_PKEY *key;
	FILE *PEMKeyFile;
	BYTE token_verification_rsa_modulus[128];
	unsigned long token_verification_rsa_exponent;
	LOG_START(_T("put_delegated_management_keys"));
	if (passPhrase == NULL)
		{ result = OPGP_ERROR_INVALID_PASSWORD; goto end; }
	if ((PEMKeyFileName == NULL) || (_tcslen(PEMKeyFileName) == 0))
		{ result = OPGP_ERROR_INVALID_FILENAME; goto end; }
	PEMKeyFile = _tfopen(PEMKeyFileName, _T("rb"));
	if (PEMKeyFile == NULL) {
		{ result = errno; goto end; }
	}
	key = EVP_PKEY_new();
	if (!PEM_read_PUBKEY(PEMKeyFile, &key, NULL, passPhrase)) {
	fclose(PEMKeyFile);

		EVP_PKEY_free(key);
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	};
	fclose(PEMKeyFile);
	// only 3 and 65337 are supported
	token_verification_rsa_exponent = key->pkey.rsa->e->d[0];
	memcpy(token_verification_rsa_modulus, key->pkey.rsa->n->d, sizeof(unsigned long)*key->pkey.rsa->n->top);
	EVP_PKEY_free(key);
	/*
	if (keySetVersion > 0x7f)
		{ result = OPGP_ERROR_WRONG_KEY_VERSION; goto end; }
	if (newKeySetVersion > 0x7f)
		{ result = OPGP_ERROR_WRONG_KEY_VERSION; goto end; }
	*/
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xD8;
	sendBuffer[i++] = keySetVersion;
	sendBuffer[i++] = 0x81;
	sendBuffer[i++] = 0x00; // Lc later calculated

	sendBuffer[i++] = newKeySetVersion;
	// Token Verification Key

	sendBuffer[i++] = 0xA1; // alghoritm RSA
	sendBuffer[i++] = 0x80; // length of RSA modulus
	memcpy(sendBuffer+i, token_verification_rsa_modulus, 128); // modulus
	i+=128;
	if (token_verification_rsa_exponent == 3) {
		sendBuffer[i++] = 1; // length of public exponent
		sendBuffer[i++] = 3;
	}
	else if (token_verification_rsa_exponent == 65537) {
		sendBuffer[i++] = 3; // length of public exponent
		sendBuffer[i++] = 0x01;
		sendBuffer[i++] = 0x00;
		sendBuffer[i++] = 0x01;
	}
	else {
		{ result = OPGP_ERROR_WRONG_EXPONENT; goto end; }
	}

	// Receipt Generation Key

	if (secInfo->secureChannelProtocol == GP211_SCP01) {
		sendBuffer[i++] = 0x81; // alghoritm 3DES
	}
	else {
		sendBuffer[i++] = 0x80; // alghoritm 3DES
	}

	sendBuffer[i++] = 0x10; // length of 3DES key
	if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0B
		|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1B) {
			result = calculate_enc_cbc_SCP02(secInfo->dataEncryptionSessionKey,
		receiptKey, 16, encrypted_key, &encrypted_key_length);
		}
	else {
		result = calculate_enc_ecb_two_key_triple_des(secInfo->dataEncryptionSessionKey,
		receiptKey, 16, encrypted_key, &encrypted_key_length);
	}

	if ( OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
	memcpy(sendBuffer+i, encrypted_key, 16); // key
	i+=16;
	sendBuffer[i++] = 0x03; // length of key check value
	result = calculate_enc_ecb_two_key_triple_des(receiptKey, keyCheckTest, 8, keyCheckValue, &keyCheckValueLength);
	if ( OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
	memcpy(sendBuffer+i, keyCheckValue, 3);
	i+=3;
	// send the stuff

	sendBuffer[4] = (BYTE)i - 5;

	sendBuffer[i++] = 0x00; // Le
	sendBufferLength = i;

#ifdef DEBUG
	log_Log(_T("put_delegated_management_keys: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif

	result = send_APDU(cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("put_delegated_management_keys: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
	if (memcmp(keyCheckValue, recvBuffer+1, 3) != 0)
		{ result = OPGP_ERROR_KEY_CHECK_VALUE; goto end; }
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("put_delegated_management_keys"), result);
	return result;
}

/**
 * If keyIndex is 0x00 all keys within a keySetVersion are deleted.
 * If keySetVersion is 0x00 all keys with the specified keyIndex are deleted.

 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param keySetVersion IN An existing key set version.
 * \param keyIndex IN An existing key index.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_delete_key(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE keySetVersion, BYTE keyIndex) {
	return delete_key(cardInfo, secInfo, keySetVersion, keyIndex);
}

static LONG delete_key(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE keySetVersion, BYTE keyIndex) {
	LONG result;
	BYTE sendBuffer[255];
	DWORD sendBufferLength;
	DWORD recvBufferLength=3;
	BYTE recvBuffer[3];
	DWORD i=0;
	LOG_START(_T("delete_key"));
	if ((keySetVersion == 0x00) && (keyIndex == 0x00))
		{ result = OPGP_ERROR_INVALID_COMBINATION_KEY_SET_VERSION_KEY_INDEX; goto end; }
	//if (keySetVersion > 0x7f)
	//	{ result = OPGP_ERROR_WRONG_KEY_VERSION; goto end; }
	//if (keyIndex > 0x7f)
	//	{ result = OPGP_ERROR_WRONG_KEY_INDEX; goto end; }
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xE4;
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 0x00;
	if (keySetVersion == 0x00) {
		sendBuffer[i++] = 0x03;
		sendBuffer[i++] = 0xD0;
		sendBuffer[i++] = 0x01;
		sendBuffer[i++] = keyIndex;
	}
	else if (keyIndex == 0x00) {
		sendBuffer[i++] = 0x03;
		sendBuffer[i++] = 0xD2;
		sendBuffer[i++] = 0x01;
		sendBuffer[i++] = keySetVersion;
	}
	else {
		sendBuffer[i++] = 0x06;
		sendBuffer[i++] = 0xD0;
		sendBuffer[i++] = 0x01;
		sendBuffer[i++] = keyIndex;
		sendBuffer[i++] = 0xD2;
		sendBuffer[i++] = 0x01;
		sendBuffer[i++] = keySetVersion;
	}
	sendBuffer[i++] = 0x01;
	sendBufferLength = i;
#ifdef DEBUG
	log_Log(_T("delete_key: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("delete_key: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("delete_key"), result);
	return result;
}

/**

 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param AIDs IN A pointer to the an array of OPGP_AID structures describing the applications and load files to delete.
 * \param AIDsLength IN The number of OPGP_AID structures.
 * \param *receiptData OUT A GP211_RECEIPT_DATA array. If the deletion is performed by a
 * security domain with delegated management privilege
 * this structure contains the according data for each deleted application or package.
 * \param receiptDataLength INOUT A pointer to the length of the receiptData array.
 * If no receiptData is available this length is 0;
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_delete_application(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						OPGP_AID *AIDs, DWORD AIDsLength, GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataLength) {
	return delete_application(cardInfo, secInfo, AIDs, AIDsLength, receiptData, receiptDataLength);
}

static LONG delete_application(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				   OPGP_AID *AIDs, DWORD AIDsLength, GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataLength) {
	LONG result;
	DWORD count=0;
	BYTE sendBuffer[261];
	DWORD sendBufferLength;
	DWORD recvBufferLength=255;
	BYTE recvBuffer[255];
	DWORD j,i=0;
	LOG_START(_T("delete_application"));
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xE4;
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 0x00;
	for (j=0; j< AIDsLength; j++) {
		if (i + AIDs[j].AIDLength+2 > 260) {
			*receiptDataLength = 0;
			{ result = OPGP_ERROR_COMMAND_TOO_LARGE; goto end; }
		}
		sendBuffer[4] += AIDs[j].AIDLength+2;
		sendBuffer[i++] = 0x4F;
		sendBuffer[i++] = AIDs[j].AIDLength;
		memcpy(sendBuffer+i, AIDs[j].AID, AIDs[j].AIDLength);
		i+=AIDs[j].AIDLength;
	}
	sendBuffer[i++] = 0x00;
	sendBufferLength = i;
#ifdef DEBUG
	log_Log(_T("delete_application: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_SUCCESS != result) {
		*receiptDataLength = 0;
		goto end;
	}
	if (recvBufferLength-count > sizeof(GP211_RECEIPT_DATA)) { // assumption that a GP211_RECEIPT_DATA structure is returned in a delegated management deletion
		*receiptDataLength=0;
		while (recvBufferLength-count > sizeof(GP211_RECEIPT_DATA)) {
			count+=fillReceipt(recvBuffer, receiptData + *receiptDataLength++);
		}
	}
	else {
		*receiptDataLength = 0;
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("delete_application: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("delete_application"), result);
	return result;
}

/**
 * Puts a single card data object identified by identifier.
 * Some cards do not provide some data objects. Some possible identifiers are predefined.
 * See #GP211_GET_DATA_ISSUER_BIN. For details about the coding of the dataObject see the programmer's manual
 * of your card.

 * \param identifier IN Two byte buffer with high and low order tag value for identifying card data object.
 * \param dataObject IN The coded data object.
 * \param dataObjectLength IN The length of the data object.
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
				   LONG GP211_put_data(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE identifier[2], PBYTE dataObject, DWORD dataObjectLength) {
	return put_data(cardInfo, secInfo, identifier, dataObject, dataObjectLength);
}

static LONG put_data(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE identifier[2], PBYTE dataObject, DWORD dataObjectLength) {
	LONG result;
	BYTE sendBuffer[255];
	DWORD sendBufferLength;
	DWORD recvBufferLength=2;
	BYTE recvBuffer[2];
	DWORD i=0;
	LOG_START(_T("put_data"));
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xDA;
	sendBuffer[i++] = identifier[0];
	sendBuffer[i++] = identifier[1];
	sendBuffer[i++] = (BYTE)dataObjectLength;
	memcpy(sendBuffer+i, dataObject, dataObjectLength);
	i+=dataObjectLength;
	sendBufferLength = i;
#ifdef DEBUG
	log_Log(_T("put_data: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("put_data: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
#endif
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("put_data"), result);
	return result;
}

/**
 * Retrieves a single card data object from the card identified by identifier.
 * Some cards do not provide some data objects. Some possible identifiers are predefined.
 * See #GP211_GET_DATA_ISSUER_BIN and so on. For details about the coding of the response see the programmer's manual
 * of your card.
 * There is a convenience method get_key_information_templates() to get the key information template(s)
 * containing key set version, key index, key type and key length of the keys.
 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param identifier IN Two byte buffer with high and low order tag value for identifying card data object.
 * \param recvBuffer OUT The buffer for the card data object.
 * \param recvBufferLength INOUT The length of the received card data object.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_get_data(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
			  const BYTE identifier[2], PBYTE recvBuffer, PDWORD recvBufferLength) {
				  return get_data(cardInfo, secInfo, identifier, recvBuffer, recvBufferLength);
}

static LONG get_data(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
			  const BYTE identifier[2], PBYTE recvBuffer, PDWORD recvBufferLength) {
	LONG result;
	BYTE sendBuffer[5];
	DWORD sendBufferLength = 5;
	BYTE cardData[256];
	DWORD cardDataLength = 256;
	DWORD i=0;
	LOG_START(_T("get_data"));
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xCA;
	sendBuffer[i++] = identifier[0];
	sendBuffer[i++] = identifier[1];
	sendBuffer[i] = 0x00;
#ifdef DEBUG
	log_Log(_T("get_data: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, secInfo, sendBuffer, sendBufferLength, cardData, &cardDataLength);
	if ( OPGP_ERROR_SUCCESS != result) {
		*recvBufferLength = 0;
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("get_data: Data: "));
	for (i=0; i<*recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
	if (cardDataLength-2 > *recvBufferLength) {
		{ result = OPGP_ERROR_INSUFFICIENT_BUFFER; goto end; }
	}
	memcpy(recvBuffer, cardData, cardDataLength-2);
	*recvBufferLength = cardDataLength-2;
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("get_data"), result);
	return result;
}

/**
 * This command is useful to return the Card Data with identifier 0x0066 containing the
 * Card Recognition Data with tag 0x73 containing among others
 * the Secure Channel Protocol and the eventual implementations.
 * For getting the Secure Channel Protocol and Secure Channel Protocol implementation there is the
 * convenience function get_secure_channel_protocol_details().
 * See also data objects identified in ISO 7816-6.
 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param identifier IN Two byte buffer with high and low order tag value for identifying card data.
 * \param recvBuffer OUT The buffer for the card data.
 * \param recvBufferLength INOUT The length of the received card data.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_get_data_iso7816_4(OPGP_CARD_INFO cardInfo, const BYTE identifier[2], PBYTE recvBuffer,
						PDWORD recvBufferLength) {
	LONG result;
	BYTE sendBuffer[5];
	DWORD sendBufferLength = 5;
	BYTE cardData[256];
	DWORD cardDataLength = 256;
	DWORD i=0;
	LOG_START(_T("get_data_iso7816-4"));
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 0xCA;
	sendBuffer[i++] = identifier[0];
	sendBuffer[i++] = identifier[1];
	sendBuffer[i] = 0x00;
#ifdef DEBUG
	log_Log(_T("get_data_iso7816-4: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}
#endif
	result = send_APDU(cardInfo, NULL, sendBuffer, sendBufferLength, cardData, &cardDataLength);
	if ( OPGP_ERROR_SUCCESS != result) {
		*recvBufferLength = 0;
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("get_data_iso7816-4: Data: "));
	for (i=0; i<cardDataLength; i++) {
		log_Log(_T(" 0x%02x"), cardData[i]);
	}

#endif
	if (cardDataLength-2 > *recvBufferLength) {
		{ result = OPGP_ERROR_INSUFFICIENT_BUFFER; goto end; }
	}
	memcpy(recvBuffer, cardData, cardDataLength-2);
	*recvBufferLength = cardDataLength-2;
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("get_data_iso7816-4"), result);
	return result;
}

/**
 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secureChannelProtocol OUT A pointer to the Secure Channel Protocol to use.
 * \param *secureChannelProtocolImpl OUT A pointer to the implementation of the Secure Channel Protocol.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_get_secure_channel_protocol_details(OPGP_CARD_INFO cardInfo,
										 BYTE *secureChannelProtocol, BYTE *secureChannelProtocolImpl) {
	LONG result;
	BYTE recvBuffer[256];
	DWORD recvBufferLength = sizeof(recvBuffer);
	DWORD offset = 0;
	DWORD length = 0;
	DWORD totalLength = 0;
	BYTE OIDCardRecognitionData[256];
	DWORD OIDCardRecognitionDataLength;
	BYTE OIDCardManagementTypeAndVersion[256];
	DWORD OIDCardManagementTypeAndVersionLength;
	BYTE OIDCardIdentificationScheme[256];
	DWORD OIDCardIdentificationSchemeLength;
	BYTE OIDSecureChannelProtocol[256];
	DWORD OIDSecureChannelProtocolLength;
	BYTE CardConfigurationDetails[256];
	DWORD CardConfigurationDetailsLength;
	BYTE CardChipDetails[256];
	DWORD CardChipDetailsLength;
#ifdef DEBUG
	DWORD i;
#endif

	LOG_START(_T("get_secure_channel_protocol_details"));
	result = GP211_get_data_iso7816_4(cardInfo, GP211_GET_DATA_CARD_DATA, recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
	/* start parsing */
	/* skip 0x66 Card Data Tag and length */
	if (recvBuffer[0] == 0x66) {
		offset++;
		totalLength = recvBuffer[offset++];
		/* 0x73 Tag and Length for ‘Card Recognition Data’ */
		offset+=2;
	}
	else {
		/* 0x73 Tag and Length for ‘Card Recognition Data’ */
		offset++;
		totalLength = recvBuffer[offset++];
	}
	/* 0x06 Universal tag for “Object Identifier” (OID) and Length */
	offset++;
	length = recvBuffer[offset++];
	/* {globalPlatform 1} OID for Card Recognition Data */
	memcpy(OIDCardRecognitionData, recvBuffer+offset, length);
	OIDCardRecognitionDataLength = length;
#ifdef DEBUG
	log_Log(_T("OIDCardRecognitionData: "));
	for (i=offset; i<offset+length; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
#endif
	offset+=length;
	/* Application tag 0 and length */
	offset+=2;
	/* 0x06 Universal tag for “Object Identifier” (OID) and Length */
	offset++;
	length = recvBuffer[offset++];
	/* {globalPlatform 2 v} OID for Card Management Type and Version */
	memcpy(OIDCardManagementTypeAndVersion, recvBuffer+offset, length);
	OIDCardManagementTypeAndVersionLength = length;
#ifdef DEBUG
	log_Log(_T("OIDCardManagementTypeAndVersion: "));
	for (i=offset; i<offset+length; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
#endif
	offset+=length;
	/* Application tag 3 and length */
	offset+=2;
	/* 0x06 Universal tag for “Object Identifier” (OID) and Length */
	offset++;
	length = recvBuffer[offset++];
	/* {globalPlatform 3} OID for Card Identification Scheme */
	memcpy(OIDCardIdentificationScheme, recvBuffer+offset, length);
	OIDCardIdentificationSchemeLength = length;
#ifdef DEBUG
	log_Log(_T("OIDCardIdentificationScheme: "));
	for (i=offset; i<offset+length; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
#endif
	offset+=length;
	/* Application tag 4 and length */
	offset+=2;
	/* 0x06 Universal tag for “Object Identifier” (OID) and Length */
	offset++;
	length = recvBuffer[offset++];
	/* {globalPlatform 4 scp i} OID for Secure Channel Protocol of
	 * the Issuer Security Domain and its implementation options
	 */
	memcpy(OIDSecureChannelProtocol, recvBuffer+offset, length);
	OIDSecureChannelProtocolLength = length;
#ifdef DEBUG
	log_Log(_T("OIDSecureChannelProtocol: "));
	for (i=offset; i<offset+length; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
#endif
	offset+=length;
	*secureChannelProtocol = OIDSecureChannelProtocol[OIDSecureChannelProtocolLength-2];
	*secureChannelProtocolImpl = OIDSecureChannelProtocol[OIDSecureChannelProtocolLength-1];

	/* optional part */

	if (totalLength > offset) {
		/* Application tag 5 and length */
		offset++;
		length = recvBuffer[offset++];
		/* Card configuration details */
		memcpy(CardConfigurationDetails, recvBuffer+offset, length);
		CardConfigurationDetailsLength = length;
	#ifdef DEBUG
		log_Log(_T("CardConfigurationDetails: "));
		for (i=offset; i<offset+length; i++) {
			log_Log(_T(" 0x%02x"), recvBuffer[i]);
		}
	#endif
		offset+=length;
	}
	if (totalLength > offset) {
		/* Application tag 6 and length */
		offset++;
		length = recvBuffer[offset++];
		/* Card / chip details */
		memcpy(CardChipDetails, recvBuffer+offset, length);
		CardChipDetailsLength = length;
	#ifdef DEBUG
		log_Log(_T("CardChipDetails: "));
		for (i=offset; i<offset+length; i++) {
			log_Log(_T(" 0x%02x"), recvBuffer[i]);
		}
	#endif
		offset+=length;
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("get_secure_channel_protocol_details"), result);
	return result;
}

/**
 * The card must support the optional report of key information templates.

 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param keyInformationTemplate IN The number of the key information template.
 * \param *keyInformation OUT A pointer to an array of GP211_KEY_INFORMATION structures.
 * \param keyInformationLength INOUT The number of GP211_KEY_INFORMATION structures.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_get_key_information_templates(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								   BYTE keyInformationTemplate,
								   GP211_KEY_INFORMATION *keyInformation, PDWORD keyInformationLength) {
	return get_key_information_templates(cardInfo, secInfo,
								   keyInformationTemplate,
								   keyInformation, keyInformationLength);
}

static LONG get_key_information_templates(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								   BYTE keyInformationTemplate,
								   GP211_KEY_INFORMATION *keyInformation, PDWORD keyInformationLength) {
	LONG result;
	BYTE sendBuffer[5];
	DWORD sendBufferLength = 5;
	BYTE cardData[256];
	DWORD cardDataLength = 256;
	DWORD j,i=0;
	LOG_START(_T("get_key_information_templates"));
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xCA;
	sendBuffer[i++] = keyInformationTemplate;
	sendBuffer[i++] = 0xE0;
	sendBuffer[i] = 0x00;
#ifdef DEBUG
	log_Log(_T("get_key_information_templates: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, secInfo, sendBuffer, sendBufferLength, cardData, &cardDataLength);
	if ( OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("get_key_information_templates: Data: "));
	for (i=0; i<cardDataLength; i++) {
		log_Log(_T(" 0x%02x"), cardData[i]);
	}

#endif
	i=0;
	for (j=4; j<cardDataLength-2; j+=2) {
		if (*keyInformationLength <= i ) {
			{ result = OPGP_ERROR_MORE_KEY_INFORMATION_TEMPLATES; goto end; };
		}
		keyInformation[i].keyIndex = cardData[j++];
		keyInformation[i].keySetVersion = cardData[j++];
		keyInformation[i].keyType = cardData[j++];
		keyInformation[i].keyLength = cardData[j++];
		i++;
	}

	*keyInformationLength = i;
#ifdef DEBUG
	for (i=0; i<*keyInformationLength; i++) {
		log_Log(_T("Key index: 0x%02x\n"), keyInformation[i].keyIndex);
		log_Log(_T("Key set version: 0x%02x\n"), keyInformation[i].keySetVersion);
		log_Log(_T("Key type: 0x%02x\n"), keyInformation[i].keyType);
		log_Log(_T("Key length: 0x%02x\n"), keyInformation[i].keyLength);
	}
#endif

	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("get_key_information_templates"), result);
	return result;
}

/**
 *
 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param cardElement IN Identifier for Load Files, Applications or the Card Manager.
 * \param AID IN The AID.
 * \param AIDLength IN The length of the AID.
 * \param lifeCycleState IN The new life cycle state.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_set_status(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE cardElement, PBYTE AID, DWORD AIDLength, BYTE lifeCycleState) {
	return set_status(cardInfo, secInfo, cardElement, AID, AIDLength, lifeCycleState);
}

static LONG set_status(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE cardElement, PBYTE AID, DWORD AIDLength, BYTE lifeCycleState) {
	LONG result;
	DWORD sendBufferLength=5+AIDLength;
	DWORD recvBufferLength=2;
	BYTE recvBuffer[2];
	BYTE sendBuffer[5+16];
	DWORD i=0;
	LOG_START(_T("set_status"));
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xF0;
	sendBuffer[i++] = cardElement;
	sendBuffer[i++] = lifeCycleState;
	sendBuffer[i++] = (BYTE)AIDLength;
	memcpy(sendBuffer+i, AID, AIDLength);
	i+=AIDLength;
#ifdef DEBUG
	log_Log(_T("set_status: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, secInfo,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("set_status: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("set_status"), result);
	return result;
}

/**
 * It depends on the card element to retrieve if an array of GP211_APPLICATION_DATA structures
 * or an array of GP211_EXECUTABLE_MODULES_DATA structures must be passed to this function.
 * For the card element #GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES executableData must not
 * be NULL, else applData must not be NULL.

 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param cardElement IN Identifier to retrieve data for Load Files, Applications or the Card Manager.
 * See #GP_STATUS_APPLICATIONS and so on.
 * \param *applData OUT The GP211_APPLICATION_DATA structure.
 * \param *executableData OUT The GP211_APPLICATION_DATA structure.
 * \param dataLength INOUT The number of GP211_APPLICATION_DATA or GP211_EXECUTABLE_MODULES_DATA passed and returned.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_get_status(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE cardElement, GP211_APPLICATION_DATA *applData, GP211_EXECUTABLE_MODULES_DATA *executableData, PDWORD dataLength) {
	LONG result;
	DWORD sendBufferLength=8;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[8];
	BYTE numExecutableModules;
	DWORD j=0, k=0, i=0;
	LOG_START(_T("get_status"));
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xF2;
	sendBuffer[i++] = cardElement;
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 2;
	sendBuffer[i++] = 0x4F;
	sendBuffer[i++] = 0x00;
	sendBuffer[i] = 0x00;
	i=0;
	do {
		recvBufferLength=256;
#ifdef DEBUG
		log_Log(_T("get_status: Data to send: "));
		for (j=0; j<sendBufferLength; j++) {
			log_Log(_T(" 0x%02x"), sendBuffer[j]);
		}

#endif
		result = send_APDU(cardInfo, secInfo,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
		if ( (OPGP_ERROR_SUCCESS != result) && !(result == OPGP_ISO7816_ERROR_MORE_DATA_AVAILABLE)) {
			goto end;
		}
#ifdef DEBUG
	log_Log(_T("get_status: Data: "));
	for (j=0; j<recvBufferLength; j++) {
		log_Log(_T(" 0x%02x"), recvBuffer[j]);
	}

#endif
		for (j=0; j<recvBufferLength-2; ) {
			if (*dataLength <= i ) {
				{ result = GP211_ERROR_MORE_APPLICATION_DATA; goto end; }
			}
			if (cardElement == GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES) {
				/* Length of Executable Load File AID */
				executableData[i].AIDLength = recvBuffer[j++];
				/* Executable Load File AID */
				memcpy(executableData[i].AID, recvBuffer+j, executableData[i].AIDLength);
				j+=executableData[i].AIDLength;
				/* Executable Load File Life Cycle State */
				executableData[i].lifeCycleState = recvBuffer[j++];
				/* Ignore Application Privileges */
				j++;
				/* Number of associated Executable Modules */
				numExecutableModules = recvBuffer[j++];
				for (k=0; k<numExecutableModules; k++) {
					/* Length of Executable Module AID */
					executableData[i].executableModules[k].AIDLength = recvBuffer[j++];
					/* Executable Module AID */
					memcpy(executableData[i].executableModules[k].AID,
						recvBuffer+j, executableData[i].executableModules[k].AIDLength);
					j+=executableData[i].executableModules[k].AIDLength;
				}
			}
			else {
				applData[i].AIDLength = recvBuffer[j++];
				memcpy(applData[i].AID, recvBuffer+j, applData[i].AIDLength);
				j+=applData[i].AIDLength;
				applData[i].lifeCycleState = recvBuffer[j++];
				if (cardElement != GP211_STATUS_LOAD_FILES) {
					applData[i].privileges = recvBuffer[j++];
				}
				else {
					applData[i].privileges = 0x00;
					j++;
				}
			}
			i++;
		}
		sendBuffer[3]=0x01;
	} while (result == OPGP_ISO7816_ERROR_MORE_DATA_AVAILABLE);

	*dataLength = i;
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("get_status"), result);
	return result;
}

/**
 * An GP211_install_for_load() must precede.
 * The Load File Data Block Signature(s) must be the same block(s) and in the same order like in calculate_load_file_data_block_hash().
 * If no Load File Data Block Signatures are necessary the loadFileDataBlockSignature must be NULL and the loadFileDataBlockSignatureLength 0.

 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param *loadFileDataBlockSignature IN A pointer to GP211_DAP_BLOCK structure(s).
 * \param loadFileDataBlockSignatureLength IN The number of GP211_DAP_BLOCK structure(s).
 * \param executableLoadFileName IN The name of the Executable Load File to hash.
 * \param *receiptData OUT If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * Can be validated with validate_load_receipt().
 * \param receiptDataAvailable OUT 0 if no receiptData is availabe.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_load(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 GP211_DAP_BLOCK *loadFileDataBlockSignature, DWORD loadFileDataBlockSignatureLength,
				 OPGP_STRING executableLoadFileName,
				 GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable) {
	return load(cardInfo, secInfo,
				 loadFileDataBlockSignature, loadFileDataBlockSignatureLength,
				 executableLoadFileName,
				 receiptData, receiptDataAvailable);
}

static LONG load(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 GP211_DAP_BLOCK *loadFileDataBlockSignature, DWORD loadFileDataBlockSignatureLength,
				 OPGP_STRING executableLoadFileName,
				 GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable) {
	LONG result = 0;
	DWORD sendBufferLength;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[261];
	BYTE dapBuf[256];
	DWORD dapBufSize=sizeof(dapBuf);
	long fileSize;
	DWORD total=0;
	DWORD fileSizeSize;
	DWORD j,k,i=0;
	FILE *CAPFile = NULL;
	BYTE sequenceNumber=0x00;
	LOG_START(_T("load"));
	*receiptDataAvailable = 0;
	sendBuffer[0] = 0x80;
	sendBuffer[1] = 0xE8;
	if ((executableLoadFileName == NULL) || (_tcslen(executableLoadFileName) == 0))
		{ result = OPGP_ERROR_INVALID_FILENAME; goto end; }

	j=0;
	for (i=0; i<loadFileDataBlockSignatureLength; i++) {
		k = dapBufSize;
		result = readLoadFileDataBlockSignature(dapBuf, &k, loadFileDataBlockSignature[i]);
		if (result != OPGP_ERROR_SUCCESS) {
			goto end;
		}
		if (k > MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING) {
			result = OPGP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE;
			goto end;
		}
		if (j+k <= MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING) {
			memcpy(sendBuffer+5+j, dapBuf, k);
			j+=k;
		}
		else {
			sendBufferLength=5+j;
			sendBuffer[2] = 0x00;
			sendBuffer[3] = sequenceNumber++;
			sendBuffer[4]=(BYTE)j;
			//sendBufferLength++;
			//sendBuffer[sendBufferLength-1] = 0x00;
#ifdef DEBUG
			log_Log(_T("load: Data to send: "));
			for (i=0; i<sendBufferLength; i++) {
				log_Log(_T(" 0x%02x"), sendBuffer[i]);
			}

#endif
			result = send_APDU(cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
			if (OPGP_ERROR_SUCCESS != result) {
				goto end;
			}
#ifdef DEBUG
			log_Log(_T("load: Data: "));
			for (i=0; i<recvBufferLength; i++) {
				log_Log(_T(" 0x%02x"), recvBuffer[i]);
			}

#endif
			/* Next data block has size k */
			j=k;
		}
	}
	// send load file data block

	CAPFile = _tfopen(executableLoadFileName, _T("rb"));
	if (CAPFile == NULL) {
		{ result = errno; goto end; }
	}
#ifdef WIN32
	fileSize = _filelength(CAPFile->_file);
#else
	fileSize = fseek(CAPFile, 0, SEEK_END);
	if (fileSize == -1) {
		{ result = errno; goto end; }
	}
	fileSize = ftell(CAPFile);
    fseek(CAPFile, 0, SEEK_SET);
#endif
	if (fileSize == -1L) {
		{ result = errno; goto end; }
	}
	if (fileSize < 128L) {
		fileSizeSize=1;
	}
	else if (fileSize < 256L) {
		fileSizeSize=2;
	}
	else if (fileSize < 32536L) {
		fileSizeSize=3;
	}
	else {
		{ result = OPGP_ERROR_APPLICATION_TOO_BIG; goto end; }
	}
	// Enough space left to start load file data block

	if ((MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING-j) > fileSizeSize+1+1) { // At least one byte of the load file data block must be sent.
		sendBuffer[5+j++] = 0xC4;
		switch(fileSizeSize) {
			case 1: {
				sendBuffer[5+j++] = (BYTE)fileSize;
					}
			case 2: {
				sendBuffer[5+j++] = 0x81;
				sendBuffer[5+j++] = (BYTE)fileSize;
					}
			case 3: {
				sendBuffer[5+j++] = 0x82;
				sendBuffer[5+j++] = (BYTE)(fileSize >> 8);
				sendBuffer[5+j++] = (BYTE)(fileSize - (sendBuffer[5+j-1] << 8));
					}
		}
		total+=(DWORD)fread(sendBuffer+5+j, sizeof(unsigned char), MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING-j, CAPFile);
		j+=total;
		if(ferror(CAPFile)) {
			{ result = errno; goto end; }
		}
		sendBufferLength=5+j;
		sendBuffer[2] = 0x00;
		sendBuffer[3] = (BYTE)sequenceNumber++;
		sendBuffer[4]=(BYTE)j;
		if ((feof(CAPFile)) || (total == (DWORD)fileSize)) {
			sendBuffer[2]=0x80;
			sendBufferLength++;
			sendBuffer[sendBufferLength-1] = 0x00;
		}
		else {
			sendBuffer[2]=0x00;
			/* CyberFlex e-gate 32k cards do not behave standard conform and accept the Le field (?) */
			//sendBufferLength++;
			//sendBuffer[sendBufferLength-1] = 0x00;
		}

		recvBufferLength=256;

#ifdef DEBUG
	log_Log(_T("load: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif

		result = send_APDU(cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
		if (OPGP_ERROR_SUCCESS != result) {
			goto end;
		}
#ifdef DEBUG
	log_Log(_T("load: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
	}
	// Not enough space to start load file data block. First send data then start load file data block.

	else {
		sendBufferLength=5+j;
		sendBuffer[2] = 0x00;
		sendBuffer[3] = sequenceNumber++;
		sendBuffer[4]=(BYTE)j;
		recvBufferLength=256;
#ifdef DEBUG
	log_Log(_T("load: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
		result = send_APDU(cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
		if (OPGP_ERROR_SUCCESS != result) {
			goto end;
		}
#ifdef DEBUG
	log_Log(_T("load: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
		j=0;
		sendBuffer[5+j++] = 0xC4;
		switch(fileSizeSize) {
			case 1: {
				sendBuffer[5+j++] = (BYTE)fileSize;
					}
			case 2: {
				sendBuffer[5+j++] = 0x81;
				sendBuffer[5+j++] = (BYTE)fileSize;
					}
			case 3: {
				sendBuffer[5+j++] = 0x82;
				sendBuffer[5+j++] = (BYTE)(fileSize >> 8);
				sendBuffer[5+j++] = (BYTE)(fileSize - (sendBuffer[5+j-1] << 8));
					}
		}
		total+=(DWORD)fread(sendBuffer+5+j, sizeof(unsigned char), MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING-1-fileSizeSize, CAPFile);
		j+=total;
		if(ferror(CAPFile)) {
			{ result = errno; goto end; }
		}
		sendBufferLength=5+j;
		sendBuffer[2] = 0x00;
		sendBuffer[3] = sequenceNumber++;
		sendBuffer[4]=(BYTE)j;
		if ((feof(CAPFile)) || (total == (DWORD)fileSize) ) {
			sendBuffer[2]=0x80;
			sendBufferLength++;
			sendBuffer[sendBufferLength-1] = 0x00;
		}
		else {
			sendBuffer[2]=0x00;
			/* CyberFlex e-gate 32k cards do not behave standard conform and accept the Le field (?) */
			//sendBufferLength++;
			//sendBuffer[sendBufferLength-1] = 0x00;
		}

		recvBufferLength=256;
#ifdef DEBUG
	log_Log(_T("load: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
		result = send_APDU(cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
		if (OPGP_ERROR_SUCCESS != result) {
			goto end;
		}
#ifdef DEBUG
	log_Log(_T("load: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
	}
	// The rest of the load file data block

	while((feof(CAPFile) == 0) && !(total == (DWORD)fileSize)) {
		total += j = (DWORD)fread(sendBuffer+5, sizeof(unsigned char), MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING, CAPFile);
		if(ferror(CAPFile)) {
			{ result = errno; goto end; }
		}
		sendBufferLength=5+j;
		sendBuffer[3] = sequenceNumber++;
		sendBuffer[4] = (BYTE)j;
		if ((feof(CAPFile)) || (total == (DWORD)fileSize)) {
			sendBuffer[2]=0x80;
			sendBufferLength++;
			sendBuffer[sendBufferLength-1] = 0x00;
		}
		else {
			sendBuffer[2]=0x00;
			/* CyberFlex e-gate 32k cards do not behave standard conform and accept the Le field (?) */
			//sendBufferLength++;
			//sendBuffer[sendBufferLength-1] = 0x00;
		}
#ifdef DEBUG
		log_Log(_T("load: Data to send: "));
		for (i=0; i<sendBufferLength; i++) {
			log_Log(_T(" 0x%02x"), sendBuffer[i]);
		}

#endif
		recvBufferLength=256;
		result = send_APDU(cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
		if (OPGP_ERROR_SUCCESS != result) {
			goto end;
		}
#ifdef DEBUG
		if (!(feof(CAPFile)) && !(total == (DWORD)fileSize)) {
			log_Log(_T("load: Data: "));
			for (i=0; i<recvBufferLength; i++) {
				log_Log(_T(" 0x%02x"), recvBuffer[i]);
			}

		}
#endif
	}
	if (recvBufferLength > sizeof(GP211_RECEIPT_DATA)) { // assumption that a GP211_RECEIPT_DATA structure is returned in a delegated management deletion
		fillReceipt(recvBuffer, receiptData);
		*receiptDataAvailable = 1;
	}
#ifdef DEBUG
	log_Log(_T("load: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
#endif
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	if (CAPFile)
		fclose(CAPFile);
	LOG_END(_T("load"), result);
	return result;
}

/**
 * The function assumes that the Issuer Security Domain or Security Domain
 * uses an optional Load File Data Block Hash using the SHA-1 message digest algorithm.
 * The loadFileDataBlockHash can be calculated using calculate_load_file_data_block_hash() or must be NULL, if the card does not
 * need or support a Load File DAP in this situation, e.g. if you want to load a Executable Load File to the Card
 * Manager Security Domain.
 * In the case of delegated management a Load Token authorizing the INSTALL [for load] must be included.
 * Otherwise loadToken must be NULL. See calculate_load_token().
 * The term Executable Load File is equivalent to the GlobalPlatform term Load File Data Block.
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tags.

 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param executableLoadFileAID IN A buffer with AID of the Executable Load File to INSTALL [for load].
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param securityDomainAID IN A buffer containing the AID of the intended associated Security Domain.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \param loadFileDataBlockHash IN The Load File Data Block Hash of the Executable Load File to INSTALL [for load].
 * \param loadToken IN The Load Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param nonVolatileCodeSpaceLimit IN The minimum amount of space that must be available to store the package.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_install_for_load(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
					  PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
					  DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20], BYTE loadToken[128],
					  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
					  DWORD nonVolatileDataSpaceLimit) {
	return install_for_load(cardInfo, secInfo,
					  executableLoadFileAID, executableLoadFileAIDLength, securityDomainAID,
					  securityDomainAIDLength, loadFileDataBlockHash, loadToken,
					  nonVolatileCodeSpaceLimit, volatileDataSpaceLimit,
					  nonVolatileDataSpaceLimit);
}

static LONG install_for_load(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
					  PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
					  DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20], BYTE loadToken[128],
					  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
					  DWORD nonVolatileDataSpaceLimit)
{
	LONG result;
	DWORD sendBufferLength = 0;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[261];
	DWORD i=0;
	BYTE buf[256];
	DWORD bufLength = sizeof(buf);
	LOG_START(_T("install_for_load"));
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xE6;
	result = get_load_data(executableLoadFileAID, executableLoadFileAIDLength, securityDomainAID,
		securityDomainAIDLength, loadFileDataBlockHash, nonVolatileCodeSpaceLimit, volatileDataSpaceLimit,
		nonVolatileDataSpaceLimit, buf, &bufLength);
	if (OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
	memcpy(sendBuffer+2, buf, bufLength);
	i+=bufLength;
	if (loadToken != NULL) {
		sendBuffer[i++] = 0x80; // Length of load token
		memcpy(sendBuffer+i, loadToken, 128);
		i+=128;
	}
	else {
		sendBuffer[i++] = 0x00; // Length of load token
	}
	sendBuffer[4] = (BYTE)i-5; // Lc
	sendBuffer[i++] = 0x00; // Le
	sendBufferLength = i;
#ifdef DEBUG
	log_Log(_T("install_for_load: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, secInfo,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("install_for_load: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("install_for_load"), result);
	return result;
}


/**
 * In the case of delegated management an Install Token authorizing the INSTALL [for install] must be included.
 * Otherwise installToken must be NULL. See calculate_install_token().
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tag.
 * For Security domains look in your manual what parameters are necessary.
 * If the tag for application install parameters is mandatory for your card, but you have no install parameters
 * for the install() method of the application anyway you have to use at least a dummy parameter.
 * If executableModuleAID is NULL and executableModuleAIDLength is 0 applicationAID is assumed for executableModuleAID.
 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param executableLoadFileAID IN A buffer with AID of the Executable Load File to INSTALL [for install].
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param executableModuleAID IN The AID of the application class in the package.
 * \param executableModuleAIDLength IN The length of the executableModuleAID buffer.
 * \param applicationAID IN The AID of the installed application.
 * \param applicationAIDLength IN The length of the application instance AID.
 * \param applicationPrivileges IN The application privileges. Can be an OR of multiple privileges. See #GP211_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param installParameters IN Applet install parameters for the install() method of the application.
 * \param installParametersLength IN The length of the installParameters buffer.
 * \param installToken IN The Install Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param *receiptData OUT If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * \param receiptDataAvailable OUT 0 if no receiptData is availabe.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_install_for_install(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						 PBYTE executableModuleAID,
						 DWORD executableModuleAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE installParameters, DWORD installParametersLength,
						 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable) {
	return install_for_install(cardInfo, secInfo,
						 executableLoadFileAID, executableLoadFileAIDLength,
						 executableModuleAID,
						 executableModuleAIDLength, applicationAID,
						 applicationAIDLength, applicationPrivileges,
						 volatileDataSpaceLimit, nonVolatileDataSpaceLimit,
						 installParameters, installParametersLength,
						 installToken, receiptData, receiptDataAvailable);
}

static LONG install_for_install(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						 PBYTE executableModuleAID,
						 DWORD executableModuleAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE installParameters, DWORD installParametersLength,
						 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable) {
	LONG result;
	DWORD sendBufferLength = 0;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[261];
	DWORD i=0;
	BYTE buf[256];
	DWORD bufLength = sizeof(buf);
	LOG_START(_T("install_for_install"));
	*receiptDataAvailable = 0;
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xE6;
	result = get_install_data(0x04, executableLoadFileAID, executableLoadFileAIDLength, executableModuleAID,
		executableModuleAIDLength, applicationAID, applicationAIDLength, applicationPrivileges,
		volatileDataSpaceLimit,	nonVolatileDataSpaceLimit, installParameters,
		installParametersLength, buf, &bufLength);
	if (OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
	memcpy(sendBuffer+2, buf, bufLength);
	i+=bufLength;

	if (installToken != NULL) {
		sendBuffer[i++] = 0x80; // Length of install token
		memcpy(sendBuffer+i, installToken, 128);
		i+=128;
	}
	else {
		sendBuffer[i++] = 0x00; // Length of install token
	}
	sendBuffer[4] = (BYTE)i-5; // Lc
	sendBuffer[i++] = 0x00; // Le
	sendBufferLength = i;
#ifdef DEBUG
	log_Log(_T("install_for_install: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, secInfo,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
	if (recvBufferLength > sizeof(GP211_RECEIPT_DATA)) { // assumption that a GP211_RECEIPT_DATA structure is returned in a delegated management deletion
		fillReceipt(recvBuffer, receiptData);
		*receiptDataAvailable = 1;
	}
#ifdef DEBUG
	log_Log(_T("install_for_install: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("install_for_install"), result);
	return result;
}

/**
 * In the case of delegated management an Install Token authorizing the INSTALL [for install and make selectable] must be included.
 * Otherwise installToken must be NULL. See calculate_install_token().
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tag.
 * For Security domains look in your manual what parameters are necessary.
 * If the tag for application install parameters is mandatory for your card, but you have no install parameters
 * for the install() method of the application anyway you have to use at least a dummy parameter.
 * If executableModuleAID is NULL and executableModuleAIDLength is 0 applicationAID is assumed for executableModuleAID.

 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param executableLoadFileAID IN A buffer with AID of the Executable Load File to INSTALL [for install].
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param executableModuleAID IN The AID of the application class in the package.
 * \param executableModuleAIDLength IN The length of the executableModuleAID buffer.
 * \param applicationAID IN The AID of the installed application.
 * \param applicationAIDLength IN The length of the application instance AID.
 * \param applicationPrivileges IN The application privileges. Can be an OR of multiple privileges. See #GP211_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param installParameters IN Applet install parameters for the install() method of the application.
 * \param installParametersLength IN The length of the installParameters buffer.
 * \param installToken IN The Install Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param *receiptData OUT If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * \param receiptDataAvailable OUT 0 if no receiptData is availabe.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_install_for_install_and_make_selectable(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE executableModuleAID,
						 DWORD executableModuleAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE installParameters, DWORD installParametersLength,
						 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData,
						 PDWORD receiptDataAvailable) {
	return install_for_install_and_make_selectable(cardInfo, secInfo,
						 executableLoadFileAID, executableLoadFileAIDLength, executableModuleAID,
						 executableModuleAIDLength, applicationAID,
						 applicationAIDLength, applicationPrivileges,
						 volatileDataSpaceLimit, nonVolatileDataSpaceLimit,
						 installParameters, installParametersLength,
						 installToken, receiptData,
						 receiptDataAvailable);
}

static LONG install_for_install_and_make_selectable(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE executableModuleAID,
						 DWORD executableModuleAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE installParameters, DWORD installParametersLength,
						 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData,
						 PDWORD receiptDataAvailable) {
	LONG result;
	DWORD sendBufferLength=0;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[261];
	DWORD i=0;
	BYTE buf[256];
	DWORD bufLength = sizeof(buf);
	LOG_START(_T("install_for_install_and_make_selectable"));
	*receiptDataAvailable = 0;
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xE6;
	result = get_install_data(0x0C, executableLoadFileAID, executableLoadFileAIDLength, executableModuleAID,
		executableModuleAIDLength, applicationAID, applicationAIDLength, applicationPrivileges,
		volatileDataSpaceLimit,	nonVolatileDataSpaceLimit, installParameters,
		installParametersLength, buf, &bufLength);
	if (OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
	memcpy(sendBuffer+2, buf, bufLength);
	i+=bufLength;

	if (installToken != NULL) {
		sendBuffer[i++] = 0x80; // Length of install token
		memcpy(sendBuffer+i, installToken, 128);
		i+=128;
	}
	else {
		sendBuffer[i++] = 0x00; // Length of install token
	}
	sendBuffer[4] = (BYTE)i-5; // Lc
	sendBuffer[i++] = 0x00; // Le
	sendBufferLength = i;
#ifdef DEBUG
	log_Log(_T("install_for_install_and_make_selectable: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, secInfo,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
	if (recvBufferLength > sizeof(GP211_RECEIPT_DATA)) { // assumption that a GP211_RECEIPT_DATA structure is returned in a delegated management deletion
		fillReceipt(recvBuffer, receiptData);
		*receiptDataAvailable = 1;
	}
#ifdef DEBUG
	log_Log(_T("install_for_install_and_make_selectable: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("install_for_install_and_make_selectable"), result);
	return result;
}

/**
 * In the case of delegated management an Extradition Token authorizing the
 * INSTALL [for extradition] must be included.
 * Otherwise extraditionToken must be NULL. See calculate_install_token().
 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param securityDomainAID IN A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \param applicationAID IN The AID of the installed application.
 * \param applicationAIDLength IN The length of the application instance AID.
GP211_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param extraditionToken IN The Install Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param *receiptData OUT If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * \param receiptDataAvailable OUT 0 if no receiptData is availabe.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_install_for_extradition(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
							  PBYTE securityDomainAID,
						 DWORD securityDomainAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength,
						 BYTE extraditionToken[128], GP211_RECEIPT_DATA *receiptData,
						 PDWORD receiptDataAvailable) {
	LONG result;
	DWORD sendBufferLength=0;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[261];
	DWORD i=0;
	BYTE buf[256];
	DWORD bufLength = sizeof(buf);
	LOG_START(_T("install_for_extradition"));
	*receiptDataAvailable = 0;
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xE6;
	result = GP211_get_extradition_token_signature_data(securityDomainAID, securityDomainAIDLength,
		applicationAID, applicationAIDLength,
		buf, &bufLength);
	if (OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
	memcpy(sendBuffer+2, buf, bufLength);
	i+=bufLength;

	if (extraditionToken != NULL) {
		sendBuffer[i++] = 0x80; // Length of extradition token
		memcpy(sendBuffer+i, extraditionToken, 128);
		i+=128;
	}
	else {
		sendBuffer[i++] = 0x00; // Length of install token
	}
	sendBuffer[4] = (BYTE)i-5; // Lc
	sendBuffer[i++] = 0x00; // Le
	sendBufferLength = i;
#ifdef DEBUG
	log_Log(_T("install_for_extradition: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, secInfo,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
	if (recvBufferLength > sizeof(GP211_RECEIPT_DATA)) { // assumption that a GP211_RECEIPT_DATA structure is returned in a delegated management deletion
		fillReceipt(recvBuffer, receiptData);
		*receiptDataAvailable = 1;
	}
#ifdef DEBUG
	log_Log(_T("install_for_extradition: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("install_for_extradition"), result);
	return result;
}

/**

 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param applicationAID IN The AID of the installed application.
 * \param applicationAIDLength IN The length of the application instance AID.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_install_for_personalization( OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						 PBYTE applicationAID,
						 DWORD applicationAIDLength) {
	LONG result;
	DWORD sendBufferLength=0;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[261];
	DWORD i=0;

	LOG_START(_T("install_for_personalization"));
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xE6;
	sendBuffer[i++] = 0x20;
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 0x00; // Lc dummy
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 0x00;

	sendBuffer[i++] = (BYTE)applicationAIDLength;
	memcpy(sendBuffer+i, applicationAID, applicationAIDLength);
	i+=applicationAIDLength;

	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 0x00;

	sendBuffer[4] = (BYTE)i-5; // Lc
	sendBuffer[i++] = 0x00; // Le
	sendBufferLength = i;
#ifdef DEBUG
	log_Log(_T("install_for_personalization: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, secInfo,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("install_for_personalization: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("install_for_personalization"), result);
	return result;
}

/**
 * In the case of delegated management an Install Token authorizing the INSTALL [for make selectable] must be included.
 * Otherwise installToken must be NULL.
 * For Security domains look in your manual what parameters are necessary.

 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param applicationAID IN The AID of the installed application or security domain.
 * \param applicationAIDLength IN The length of the application instance AID.
 * \param applicationPrivileges IN The application privileges. Can be an OR of multiple privileges. See #GP211_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param installToken IN The Install Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param *receiptData OUT If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * \param receiptDataAvailable OUT 0 if no receiptData is availabe.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_install_for_make_selectable(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								 PBYTE applicationAID,
								 DWORD applicationAIDLength, BYTE applicationPrivileges,
								 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData,
								 PDWORD receiptDataAvailable) {
	return install_for_make_selectable(cardInfo, secInfo,
								 applicationAID,
								 applicationAIDLength, applicationPrivileges,
								 installToken, receiptData,
								 receiptDataAvailable);
}

static LONG install_for_make_selectable(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								 PBYTE applicationAID,
								 DWORD applicationAIDLength, BYTE applicationPrivileges,
								 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData,
								 PDWORD receiptDataAvailable) {
	LONG result;
	DWORD sendBufferLength=0;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[261];
	DWORD i=0;
	LOG_START(_T("install_for_make_selectable"));
	*receiptDataAvailable = 0;
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xE6;
	sendBuffer[i++] = 0x08;
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 0x00; // Lc dummy

	sendBuffer[i++] = 0x00; //  Executable Load File AID
	sendBuffer[i++] = 0x00; // application class AID

	sendBuffer[i++] = (BYTE)applicationAIDLength; // application instance AID
	memcpy(sendBuffer+i, applicationAID, applicationAIDLength);
	i+=applicationAIDLength;

	sendBuffer[i++] = 0x01;
	sendBuffer[i++] = applicationPrivileges; // application privileges

	sendBuffer[i++] = 0x00; // install parameter field length

	if (installToken != NULL) {
		sendBuffer[i++] = 0x80; // Length of install token
		memcpy(sendBuffer+i, installToken, 128);
		i+=128;
	}
	else {
		sendBuffer[i++] = 0x00; // Length of install token
	}
	sendBuffer[4] = (BYTE)i-5; // Lc
	sendBuffer[i++] = 0x00; // Le
	sendBufferLength = i;
#ifdef DEBUG
	log_Log(_T("install_for_make_selectable: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, secInfo,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
	if (recvBufferLength > sizeof(GP211_RECEIPT_DATA)) { // assumption that a GP211_RECEIPT_DATA structure is returned in a delegated management deletion
		fillReceipt(recvBuffer, receiptData);
		*receiptDataAvailable = 1;
	}
#ifdef DEBUG
	log_Log(_T("install_for_make_selectable: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("install_for_make_selectable"), result);
	return result;
}

/**
 * If you are not the Card Issuer and do not know the token verification private key send this data to the
 * Card Issuer and obtain the RSA signature of the data, i.e. the Install Token.
 * volatileDataSpaceLimit can be 0, if the card does not need or support this tag.
 * The parameters must match the parameters of a later GP211_install_for_install() and GP211_install_for_make_selectable() method.
 * \param P1 IN The parameter P1 in the APDU command.
 * <ul>
 * <li> 0x04 for a INSTALL [for install] command </li>
 * <li> 0x08 for an INSTALL [for make selectable] command </li>
 * <li> 0x0C for an INSTALL [for install and make selectable] </li>
 * </ul>
 * \param executableLoadFileAID IN A buffer with AID of the Executable Load File to INSTALL [for load].
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param executableModuleAID IN The AID of the application class in the package.
 * \param executableModuleAIDLength IN The length of the executableModuleAID buffer.
 * \param applicationAID IN The AID of the installed application.
 * \param applicationAIDLength IN The length of the application instance AID.
 * \param applicationPrivileges IN The application privileges. Can be an OR of multiple privileges. See #GP211_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param installParameters IN Applet install parameters for the install() method of the application.
 * \param installParametersLength IN The length of the installParameters buffer.
 * \param installTokenSignatureData OUT The data to sign in a Install Token.
 * \param installTokenSignatureDataLength INOUT The length of the installTokenSignatureData buffer.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_get_install_token_signature_data(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE executableModuleAID,
									  DWORD executableModuleAIDLength, PBYTE applicationAID,
									  DWORD applicationAIDLength, BYTE applicationPrivileges,
									  DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
									  PBYTE installParameters, DWORD installParametersLength,
									  PBYTE installTokenSignatureData, PDWORD installTokenSignatureDataLength) {
	return get_install_data(P1, executableLoadFileAID, executableLoadFileAIDLength, executableModuleAID,
									  executableModuleAIDLength, applicationAID,
									  applicationAIDLength, applicationPrivileges,
									  volatileDataSpaceLimit, nonVolatileDataSpaceLimit,
									  installParameters, installParametersLength,
									  installTokenSignatureData, installTokenSignatureDataLength);
}

static LONG get_install_data(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE executableModuleAID,
									  DWORD executableModuleAIDLength, PBYTE applicationAID,
									  DWORD applicationAIDLength, BYTE applicationPrivileges,
									  DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
									  PBYTE installParameters, DWORD installParametersLength,
									  PBYTE installData, PDWORD installDataLength) {
	unsigned char buf[256];
	DWORD i=0;
	DWORD hiByte, loByte;
	LONG result;

	LOG_START(_T("get_install_data"));
	buf[i++] = P1;
	buf[i++] = 0x00;
	buf[i++] = 0x00; // Lc dummy
	buf[i++] = (BYTE)executableLoadFileAIDLength; // Executable Load File AID
	memcpy(buf+i, executableLoadFileAID, executableLoadFileAIDLength);
	i+=executableLoadFileAIDLength;
	buf[i++] = (BYTE)executableModuleAIDLength; // application class AID
	memcpy(buf+i, executableModuleAID, executableModuleAIDLength);
	i+=executableModuleAIDLength;
	buf[i++] = (BYTE)applicationAIDLength; // application instance AID
	memcpy(buf+i, applicationAID, applicationAIDLength);
	i+=applicationAIDLength;

	buf[i++] = 0x01;
	buf[i++] = applicationPrivileges; // application privileges

	buf[i++] = 0x00; // install parameter field length
	if (installParametersLength > 0) {
		buf[i-1] += 2;
		buf[i-1] += (BYTE)installParametersLength;
	}

	if ((nonVolatileDataSpaceLimit > 0) || (volatileDataSpaceLimit > 0)) {
		buf[i-1] += 2; // 0xEF LL
	}
	if (nonVolatileDataSpaceLimit > 0) {
		buf[i-1] += 4;
	}
	if (volatileDataSpaceLimit > 0) {
		buf[i-1] += 4;
	}

	if (installParametersLength > 0) {
		buf[i++] = 0xC9; // application install parameters
		buf[i++] = (BYTE)installParametersLength;
		memcpy(buf+i, installParameters, installParametersLength);
		i+=installParametersLength;
	}

	if (nonVolatileDataSpaceLimit > 0) {
		if (volatileDataSpaceLimit != 0)
			buf[i-1] += 4;
		buf[i++] = 0xEF;
		buf[i++] = 0x04;
		if (volatileDataSpaceLimit != 0)
			buf[i-1] += 4;
		if (volatileDataSpaceLimit != 0) {
			buf[i++] = 0xC7;
			buf[i++] = 0x02;
			hiByte = volatileDataSpaceLimit >> 8;
			loByte = volatileDataSpaceLimit - (hiByte << 8);
			buf[i++] = (BYTE)hiByte;
			buf[i++] = (BYTE)loByte;
		}
		buf[i++] = 0xC8;
		buf[i++] = 0x02;
		hiByte = nonVolatileDataSpaceLimit >> 8;
		loByte = nonVolatileDataSpaceLimit - (hiByte << 8);
		buf[i++] = (BYTE)hiByte;
		buf[i++] = (BYTE)loByte;
	}

	buf[2] = (BYTE)i-3; // Lc
	if (i > *installDataLength)
		{ result = OPGP_ERROR_INSUFFICIENT_BUFFER; goto end; }
	memcpy(installData, buf, i);
	*installDataLength = i;
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("get_install_data"), result);
	return result;
}

/**
 * If you are not the Card Issuer and do not know the token verification private key send this data to the
 * Card Issuer and obtain the RSA signature of the data, i.e. the Extradition Token.
 * The parameters must match the parameters of a later GP211_install_for_extradition() method.
 * \param securityDomainAID IN A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \param applicationAID IN The AID of the installed application.
 * \param applicationAIDLength IN The length of the application instance AID.
 * \param extraditionTokenSignatureData OUT The data to sign in a Install Token.
 * \param extraditionTokenSignatureDataLength INOUT The length of the installTokenSignatureData buffer.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_get_extradition_token_signature_data(PBYTE securityDomainAID,
										  DWORD securityDomainAIDLength,
										  PBYTE applicationAID, DWORD applicationAIDLength,
										  PBYTE extraditionTokenSignatureData,
										  PDWORD extraditionTokenSignatureDataLength) {
	unsigned char buf[258];
	DWORD i=0;
	LONG result;

	LOG_START(_T("get_extradition_token_signature_data"));
	buf[i++] = 0x10;
	buf[i++] = 0x00;
	buf[i++] = 0x00; // Lc dummy
	buf[i++] = (BYTE)securityDomainAIDLength; // Security Domain AID
	memcpy(buf+i, securityDomainAID, securityDomainAIDLength);
	i+=securityDomainAIDLength;
	buf[i++] = 0x00;
	buf[i++] = (BYTE)applicationAIDLength; // application instance AID
	memcpy(buf+i, applicationAID, applicationAIDLength);
	i+=applicationAIDLength;

	buf[i++] = 0x00;
	buf[i++] = 0x00;

	buf[2] = (BYTE)i-3+128; // Lc (including 128 byte RSA signature length)
	if (i > *extraditionTokenSignatureDataLength)
		{ result = OPGP_ERROR_INSUFFICIENT_BUFFER; goto end; }
	memcpy(extraditionTokenSignatureData, buf, i);
	*extraditionTokenSignatureDataLength = i;
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("get_extradition_token_signature_data"), result);
	return result;
}

/**
 * The parameters must match the parameters of a later GP211_install_for_install(), GP211_install_for_make_selectable() and GP211_install_for_install_and_make_selectable() method.
 * \param P1 IN The parameter P1 in the APDU command.
 * <ul>
 * <li> 0x04 for a INSTALL [for install] command </li>
 * <li> 0x08 for an INSTALL [for make selectable] command </li>
 * <li> 0x0C for an INSTALL [for install and make selectable] </li>
 * <li> 0x10 for an INSTALL [for extradiction] </li>
 * </ul>
 * \param executableLoadFileAID IN A buffer with AID of the Executable Load File to INSTALL [for install].
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param executableModuleAID IN The AID of the application class in the package.
 * \param executableModuleAIDLength IN The length of the executableModuleAID buffer.
 * \param applicationAID IN The AID of the installed application.
 * \param applicationAIDLength IN The length of the application instance AID.
 * \param applicationPrivileges IN The application privileges. Can be an OR of multiple privileges. See #GP211_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param installParameters IN Applet install parameters for the install() method of the application.
 * \param installParametersLength IN The length of the installParameters buffer.
 * \param installToken OUT The calculated Install Token. A 1024 bit RSA signature.
 * \param PEMKeyFileName IN A PEM file name with the private RSA key.
 * \param *passPhrase IN The passphrase. Must be an ASCII string.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_calculate_install_token(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
							 PBYTE executableModuleAID,
							 DWORD executableModuleAIDLength, PBYTE applicationAID, DWORD applicationAIDLength,
							 BYTE applicationPrivileges, DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
							 PBYTE installParameters, DWORD installParametersLength,
							 BYTE installToken[128], OPGP_STRING PEMKeyFileName, char *passPhrase) {
	return calculate_install_token(P1, executableLoadFileAID, executableLoadFileAIDLength,
							 executableModuleAID,
							 executableModuleAIDLength, applicationAID, applicationAIDLength,
							 applicationPrivileges, volatileDataSpaceLimit, nonVolatileDataSpaceLimit,
							 installParameters, installParametersLength,
							 installToken, PEMKeyFileName, passPhrase);
}
static LONG calculate_install_token(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
							 PBYTE executableModuleAID,
							 DWORD executableModuleAIDLength, PBYTE applicationAID, DWORD applicationAIDLength,
							 BYTE applicationPrivileges, DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
							 PBYTE installParameters, DWORD installParametersLength,
							 BYTE installToken[128], OPGP_STRING PEMKeyFileName, char *passPhrase) {
	LONG result;
	BYTE installTokenSignatureData[256];
	DWORD installTokenSignatureDataLength = 256;
	LOG_START(_T("calculate_install_token"));
	result = get_install_data(P1, executableLoadFileAID, executableLoadFileAIDLength,
		executableModuleAID, executableModuleAIDLength, applicationAID,
		applicationAIDLength, applicationPrivileges, volatileDataSpaceLimit,
		nonVolatileDataSpaceLimit, installParameters,
		installParametersLength, installTokenSignatureData, &installTokenSignatureDataLength);
	if (result != OPGP_ERROR_SUCCESS) {
		goto end;
	}
	result = calculate_rsa_signature(installTokenSignatureData, installTokenSignatureDataLength, PEMKeyFileName,
									passPhrase, installToken);
	if (result != OPGP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("calculate_install_token"), result);
	return result;
}


/**
 * Calculates a RSA signature using SHA-1 and PKCS#1.
 * \param message IN The message to generate the signature for.
 * \param messageLength IN The length of the message buffer.
 * \param PEMKeyFileName IN A PEM file name with the private RSA key.
 * \param *passPhrase IN The passphrase. Must be an ASCII string.
 * \param signature The calculated signature.
 */
static LONG calculate_rsa_signature(PBYTE message, DWORD messageLength, OPGP_STRING PEMKeyFileName,
									char *passPhrase, BYTE signature[128]) {
	LONG result;
	EVP_PKEY *key = NULL;
	FILE *PEMKeyFile = NULL;
	EVP_MD_CTX mdctx;
	unsigned int signatureLength=0;
	LOG_START(_T("calculate_rsa_signature"));
	EVP_MD_CTX_init(&mdctx);
	if (passPhrase == NULL)
		{ result = OPGP_ERROR_INVALID_PASSWORD; goto end; }
	if ((PEMKeyFileName == NULL) || (_tcslen(PEMKeyFileName) == 0))
		{ result = OPGP_ERROR_INVALID_FILENAME; goto end; }
	PEMKeyFile = _tfopen(PEMKeyFileName, _T("rb"));
	if (PEMKeyFile == NULL) {
		{ result = errno; goto end; }
	}
	key = EVP_PKEY_new();
	if (!PEM_read_PrivateKey(PEMKeyFile, &key, NULL, passPhrase)) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	};
	result = EVP_SignInit_ex(&mdctx, EVP_sha1(), NULL);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	result = EVP_SignUpdate(&mdctx, message, messageLength);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	if (EVP_PKEY_size(key) > 128) {
		{ result = OPGP_ERROR_INSUFFICIENT_BUFFER; goto end; }
	}
	result = EVP_SignFinal(&mdctx, signature, &signatureLength, key);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	if (EVP_MD_CTX_cleanup(&mdctx) != 1) {
		{ result = OPGP_OPENSSL_ERROR; }
	}
	if (PEMKeyFile)
		fclose(PEMKeyFile);
	if (key)
		EVP_PKEY_free(key);
	LOG_END(_T("calculate_rsa_signature"), result);
	return result;
}

/**
 * If you are not the Card Issuer and do not know the token verification private key send this data to the
 * Card Issuer and obtain the RSA signature of the data, i.e. the Load Token.
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tags.
 * The parameters must match the parameters of a later GP211_install_for_load() command.
 * \param executableLoadFileAID IN A buffer containing the Executable Load File AID.
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param securityDomainAID IN A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \param loadFileDataBlockHash IN The Load File Data Block Hash. The same calculated as in GP211_install_for_load().
 * \param nonVolatileCodeSpaceLimit IN The minimum space required to store the application code.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param loadTokenSignatureData OUT The data to sign in a Load Token.
 * \param loadTokenSignatureDataLength INOUT The length of the loadTokenSignatureData buffer.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_get_load_token_signature_data(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
								   DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20],
								   DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
								   DWORD nonVolatileDataSpaceLimit, PBYTE loadTokenSignatureData,
								   PDWORD loadTokenSignatureDataLength) {
	unsigned char buf[258];
	DWORD i=0;
#ifdef DEBUG
	DWORD j=0;
#endif
	DWORD hiByte, loByte;
	DWORD staticSize;
	LONG result;
	LOG_START(_T("get_load_token_signature_data"));
	if (loadFileDataBlockHash == NULL) {
		result = GP211_ERROR_LOAD_FILE_DATA_BLOCK_HASH_NULL;
		goto end;
	}
	buf[i++] = 0x02;
	buf[i++] = 0x00;
	buf[i++] = 0x00; // Lc dummy
	buf[i++] = (BYTE)executableLoadFileAIDLength; // Executable Load File AID
	memcpy(buf+i, executableLoadFileAID, executableLoadFileAIDLength);
	i+=executableLoadFileAIDLength;
	buf[i++] = (BYTE)securityDomainAIDLength; // Security Domain AID
	memcpy(buf+i, securityDomainAID, securityDomainAIDLength);
	i+=securityDomainAIDLength;

	/* SHA-1 hash */
	buf[i++] = 0x14;
	memcpy(buf+i, loadFileDataBlockHash, 20);
	i+=20;

	if ((volatileDataSpaceLimit != 0) || (nonVolatileCodeSpaceLimit != 0) ||
(nonVolatileDataSpaceLimit != 0)) {
		buf[i++] = 0x02; // load parameter field
		if (volatileDataSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileDataSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileCodeSpaceLimit != 0)
			buf[i-1] += 4;
		buf[i++] = 0xEF;
		buf[i++] = 0x00;
		if (volatileDataSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileDataSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileCodeSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileCodeSpaceLimit != 0) {
			buf[i++] = 0xC6; // non-volatile code space limit.
			buf[i++] = 0x02; //
			staticSize = 8 - (nonVolatileCodeSpaceLimit % 8) + 8;
            nonVolatileCodeSpaceLimit += staticSize;
			hiByte = nonVolatileCodeSpaceLimit >> 8;
			loByte = nonVolatileCodeSpaceLimit - (hiByte << 8);
			buf[i++] = (BYTE)hiByte; // minimum amount
			buf[i++] = (BYTE)loByte; // of space needed
		}
		if (volatileDataSpaceLimit != 0) {
			buf[i++] = 0xC7;
			buf[i++] = 0x02;
			hiByte = volatileDataSpaceLimit >> 8;
			loByte = volatileDataSpaceLimit - (hiByte << 8);
			buf[i++] = (BYTE)hiByte;
			buf[i++] = (BYTE)loByte;
		}
		if (nonVolatileDataSpaceLimit != 0) {
			buf[i++] = 0xC8;
			buf[i++] = 0x02;
			hiByte = nonVolatileDataSpaceLimit >> 8;
			loByte = nonVolatileDataSpaceLimit - (hiByte << 8);
			buf[i++] = (BYTE)hiByte;
			buf[i++] = (BYTE)loByte;
		}
	}
	else buf[i++] = 0x00;

	/* Length of all following fields - minus 3 for P1, P2 and length field itself */
	buf[2] = (BYTE)i-3;
	if (i > *loadTokenSignatureDataLength)
		{ result = OPGP_ERROR_INSUFFICIENT_BUFFER; goto end; }
	memcpy(loadTokenSignatureData, buf, i);
	*loadTokenSignatureDataLength = i;
#ifdef DEBUG
	log_Log(_T("get_load_token_signature_data: Gathered data : "));
	log_Log(_T("Reference control parameter P1: 0x%02x"), loadTokenSignatureData[j++]);
	log_Log(_T("Reference control parameter P2: 0x%02x"), loadTokenSignatureData[j++]);
	log_Log(_T("Length of the following fields: 0x%02x"), loadTokenSignatureData[j++]);
	log_Log(_T("Load file AID length: 0x%02x"), loadTokenSignatureData[j++]);
	log_Log(_T("Load file AID:"));
	for (i=0; i<loadTokenSignatureData[j-1]; i++) {
		log_Log(_T(" 0x%02x"), loadTokenSignatureData[j+i]);
	}
	j+=loadTokenSignatureData[j-1];
	log_Log(_T("Security Domain AID length: 0x%02x"), loadTokenSignatureData[j++]);
	log_Log(_T("Security Domain AID:"));
	for (i=0; i<loadTokenSignatureData[j-1]; i++) {
		log_Log(_T(" 0x%02x"), loadTokenSignatureData[j+i]);
	}
	j+=loadTokenSignatureData[j-1];
	log_Log(_T("Length of the Load File Data Block Hash: 0x%02x"), loadTokenSignatureData[j++]);
	log_Log(_T("Load File Data Block Hash:"));
	for (i=0; i<loadTokenSignatureData[j-1]; i++) {
		log_Log(_T(" 0x%02x"), loadTokenSignatureData[j+i]);
	}
	j+=loadTokenSignatureData[j-1];

	log_Log(_T("Load parameters field length: 0x%02x"), loadTokenSignatureData[j++]);
	log_Log(_T("Load parameters field:"));
	for (i=0; i<loadTokenSignatureData[j-1]; i++) {
		log_Log(_T(" 0x%02x"), loadTokenSignatureData[j+i]);
	}
	j+=loadTokenSignatureData[j-1];

#endif
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("GPget_load_token_signature_data"), result);
	return result;
}

/**
 * Gets the data for a GP211_install_for_load() command.
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tags.
 * \param executableLoadFileAID IN A buffer containing the Executable Load File AID.
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param securityDomainAID IN A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \param loadFileDataBlockHash IN The Load File DAP.
 * \param nonVolatileCodeSpaceLimit IN The minimum space required to store the application code.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param loadData OUT The data to sign in a load data.
 * \param loadDataLength INOUT The length of the loadData buffer.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
static LONG get_load_data(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						  PBYTE securityDomainAID,
								   DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20],
								   DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
								   DWORD nonVolatileDataSpaceLimit, PBYTE loadData,
								   PDWORD loadDataLength) {
	unsigned char buf[258];
	DWORD i=0;
	DWORD hiByte, loByte;
	DWORD staticSize;
	LONG result;
	LOG_START(_T("get_load_data"));
	buf[i++] = 0x02;
	buf[i++] = 0x00;
	buf[i++] = 0x00; // Lc dummy
	buf[i++] = (BYTE)executableLoadFileAIDLength; // Executable Load File AID
	memcpy(buf+i, executableLoadFileAID, executableLoadFileAIDLength);
	i+=executableLoadFileAIDLength;
	buf[i++] = (BYTE)securityDomainAIDLength; // Security Domain AID
	memcpy(buf+i, securityDomainAID, securityDomainAIDLength);
	i+=securityDomainAIDLength;
	if (loadFileDataBlockHash != NULL) {
		buf[i++] = 0x14; // length of SHA-1 hash
		memcpy(buf+i, loadFileDataBlockHash, 20);
		i+=20;
	}
	else buf[i++] = 0x00;
	if ((volatileDataSpaceLimit != 0) || (nonVolatileCodeSpaceLimit != 0) ||
(nonVolatileDataSpaceLimit != 0)) {
		buf[i++] = 0x02; // load parameter field
		if (volatileDataSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileDataSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileCodeSpaceLimit != 0)
			buf[i-1] += 4;
		buf[i++] = 0xEF;
		buf[i++] = 0x00;
		if (volatileDataSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileDataSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileCodeSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileCodeSpaceLimit != 0) {
			buf[i++] = 0xC6; // non-volatile code space limit.
			buf[i++] = 0x02; //
			staticSize = 8 - (nonVolatileCodeSpaceLimit % 8) + 8;
            nonVolatileCodeSpaceLimit += staticSize;
			hiByte = nonVolatileCodeSpaceLimit >> 8;
			loByte = nonVolatileCodeSpaceLimit - (hiByte << 8);
			buf[i++] = (BYTE)hiByte; // minimum amount
			buf[i++] = (BYTE)loByte; // of space needed
		}
		if (volatileDataSpaceLimit != 0) {
			buf[i++] = 0xC7;
			buf[i++] = 0x02;
			hiByte = volatileDataSpaceLimit >> 8;
			loByte = volatileDataSpaceLimit - (hiByte << 8);
			buf[i++] = (BYTE)hiByte;
			buf[i++] = (BYTE)loByte;
		}
		if (nonVolatileDataSpaceLimit != 0) {
			buf[i++] = 0xC8;
			buf[i++] = 0x02;
			hiByte = nonVolatileDataSpaceLimit >> 8;
			loByte = nonVolatileDataSpaceLimit - (hiByte << 8);
			buf[i++] = (BYTE)hiByte;
			buf[i++] = (BYTE)loByte;
		}
	}
	else buf[i++] = 0x00;

	buf[2] = (BYTE)i-3+128; // Lc (including 128 byte RSA signature length)
	if (i > *loadDataLength)
		{ result = OPGP_ERROR_INSUFFICIENT_BUFFER; goto end; }
	memcpy(loadData, buf, i);
	*loadDataLength = i;
#ifdef DEBUG
	log_Log(_T("get_load_data: Gathered data : "));
	for (i=0; i<*loadDataLength; i++) {
		log_Log(_T(" 0x%02x"), loadData[i]);
	}
#endif
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("get_load_data"), result);
	return result;
}

/**
 * The parameters must match the parameters of a later GP211_install_for_load() method.
 * \param executableLoadFileAID IN A buffer containing the Executable Load File AID.
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param securityDomainAID IN A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \param loadFileDataBlockHash IN The Load File DAP. The same calculated as in GP211_install_for_load().
 * \param nonVolatileCodeSpaceLimit IN The minimum space required to store the package.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param loadToken OUT The calculated Load Token. A 1024 bit RSA signature.
 * \param PEMKeyFileName IN A PEM file name with the private RSA key.
 * \param *passPhrase IN The passphrase. Must be an ASCII string.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_calculate_load_token(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						  PBYTE securityDomainAID,
						  DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20],
						  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
						  DWORD nonVolatileDataSpaceLimit, BYTE loadToken[128],
						  OPGP_STRING PEMKeyFileName, char *passPhrase) {
	LONG result;
	BYTE loadTokenSignatureData[256];
	DWORD loadTokenSignatureDataLength = 256;
	LOG_START(_T("calculate_load_token"));
	result = GP211_get_load_token_signature_data(executableLoadFileAID, executableLoadFileAIDLength, securityDomainAID, securityDomainAIDLength,
		loadFileDataBlockHash, nonVolatileCodeSpaceLimit, volatileDataSpaceLimit, nonVolatileDataSpaceLimit, loadTokenSignatureData, &loadTokenSignatureDataLength);
	if (result != OPGP_ERROR_SUCCESS) {
		goto end;
	}
	result = calculate_rsa_signature(loadTokenSignatureData, loadTokenSignatureDataLength, PEMKeyFileName,
									passPhrase, loadToken);
	if (result != OPGP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("calculate_load_token"), result);
	return result;
}

/**
 * This is a hash of the Load File Data Block with SHA-1.
 * \param executableLoadFileName IN The name of the Executable Load File to hash.
 * \param hash OUT The hash value.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_calculate_load_file_data_block_hash(OPGP_STRING executableLoadFileName,
							 unsigned char hash[20]) {
	LONG result;
	int count;
	unsigned char buf[1024];
	PBYTE dapBuf = NULL;
	DWORD dapBufSize=0;
	FILE *CAPFile = NULL;
	long fileSize = 0;
	EVP_MD_CTX mdctx;
	LOG_START(_T("GPcalculate_load_file_data_block_hash"));
	EVP_MD_CTX_init(&mdctx);
	if ((executableLoadFileName == NULL) || (_tcslen(executableLoadFileName) == 0))
		{ result = OPGP_ERROR_INVALID_FILENAME; goto end; }
	result = EVP_DigestInit_ex(&mdctx, EVP_sha1(), NULL);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	CAPFile = _tfopen(executableLoadFileName, _T("rb"));
	if (CAPFile == NULL) {
		{ result = errno; goto end; }
	}

	while(feof(CAPFile) == 0) {
		count = (int)fread(buf, sizeof(unsigned char), sizeof(buf), CAPFile);
		if(ferror(CAPFile)) {
			{ result = errno; goto end; }
		}
		result = EVP_DigestUpdate(&mdctx, buf, count);
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
	}
	result = EVP_DigestFinal_ex(&mdctx, hash, NULL);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	if (EVP_MD_CTX_cleanup(&mdctx) != 1) {
		{ result = OPGP_OPENSSL_ERROR; }
	}
	if (CAPFile)
		fclose(CAPFile);
	LOG_END(_T("GPcalculate_load_file_data_block_hash"), result);
	return result;
}

/**
 * If a security domain has DAP verification privilege the security domain validates this DAP.
 * The loadFileDataBlockHash can be calculated using calculate_load_file_data_block_hash().
 * \param loadFileDataBlockHash IN The Load File Data Block Hash.
 * \param securityDomainAID IN A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \param DAPCalculationKey IN The key to calculate the DAP.
 * \param *loadFileDataBlockSignature OUT A pointer to the returned GP211_DAP_BLOCK structure.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_calculate_3des_DAP(BYTE loadFileDataBlockHash[20], PBYTE securityDomainAID,
						DWORD securityDomainAIDLength,
						BYTE DAPCalculationKey[16], GP211_DAP_BLOCK *loadFileDataBlockSignature)
{
	LONG result;

	calculate_MAC_des_3des(DAPCalculationKey, loadFileDataBlockHash, 20, icv,
		loadFileDataBlockSignature->signature);

	loadFileDataBlockSignature->signatureLength = 8;
	memcpy(loadFileDataBlockSignature->securityDomainAID, securityDomainAID, securityDomainAIDLength);
	loadFileDataBlockSignature->securityDomainAIDLength = (BYTE)securityDomainAIDLength;

	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("calculate_3des_DAP"), result);
	return result;

}

/**
 * If a security domain has DAP verification privilege the security domain validates this DAP.
 * The loadFileDataBlockHash can be calculated using calculate_load_file_data_block_hash().
 * \param loadFileDataBlockHash IN The Load File Data Block Hash.
 * \param securityDomainAID IN A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \param PEMKeyFileName IN A PEM file name with the DAP Verification private RSA key.
 * \param *passPhrase IN The passphrase. Must be an ASCII string.
 * \param *loadFileDataBlockSignature OUT A pointer to the returned GP211_DAP_BLOCK structure.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_calculate_rsa_DAP(BYTE loadFileDataBlockHash[20], PBYTE securityDomainAID,
					   DWORD securityDomainAIDLength,
					   OPGP_STRING PEMKeyFileName, char *passPhrase,
					   GP211_DAP_BLOCK *loadFileDataBlockSignature)
{
	LONG result;
	LOG_START(_T("calculate_rsa_DAP"));

	calculate_rsa_signature(loadFileDataBlockHash, 20, PEMKeyFileName, passPhrase,
		loadFileDataBlockSignature->signature);
	loadFileDataBlockSignature->signatureLength = 128;
	memcpy(loadFileDataBlockSignature->securityDomainAID, securityDomainAID, securityDomainAIDLength);
	loadFileDataBlockSignature->securityDomainAIDLength = (BYTE)securityDomainAIDLength;

	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("calculate_rsa_DAP"), result);
	return result;
}


/**
 * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
 * You may keep track of it. Returns OPGP_ERROR_SUCCESS if receipt is valid.
 * \param confirmationCounter IN The confirmation counter.
 * \param cardUniqueData IN The card unique data.
 * \param cardUniqueDataLength IN The length of the card unique data buffer.
 * \param receiptKey IN The 3DES key to generate the receipt.
 * \param receiptData IN The GP211_RECEIPT_DATA structure containing the receipt returned
 * from load() to verify.
 * \param executableLoadFileAID IN A buffer with AID of the Executable Load File which was INSTALL [for load].
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param securityDomainAID IN A buffer containing the AID of the associated Security Domain.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_validate_load_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
						   DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE securityDomainAID, DWORD securityDomainAIDLength) {
	return validate_load_receipt(confirmationCounter, cardUniqueData,
						   cardUniqueDataLength,
						   receiptKey, receiptData,
						   executableLoadFileAID, executableLoadFileAIDLength,
						   securityDomainAID, securityDomainAIDLength);
}

static LONG validate_load_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
						   DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE securityDomainAID, DWORD securityDomainAIDLength)
{
	LONG result;
	PBYTE validationData = NULL;
	DWORD validationDataLength;
	DWORD i=0;
	LOG_START(_T("validate_load_receipt"));
	validationDataLength = 1 + 2 + 1 + cardUniqueDataLength + 1 + executableLoadFileAIDLength + 1 + securityDomainAIDLength;
	validationData = (PBYTE)malloc(validationDataLength);
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
	result = validate_receipt(validationData, validationDataLength, receiptData.receipt, receiptKey);
	if (result != OPGP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	if (validationData)
		free(validationData);
	LOG_END(_T("validate_load_receipt"), result);
	return result;
}

/**
 * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
 * You may keep track of it. Returns OPGP_ERROR_SUCCESS if receipt is valid.
 * \param confirmationCounter IN The confirmation counter.
 * \param cardUniqueData IN The card unique data.
 * \param cardUniqueDataLength IN The length of the card unique data buffer.
 * \param receiptKey IN The 3DES key to generate the receipt.
 * \param receiptData IN The GP211_RECEIPT_DATA structure containing the receipt returned
 * from GP211_install_for_install() to verify.
 * \param executableLoadFileAID IN A buffer with AID of the Executable Load File which was INSTALL [for install].
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param applicationAID IN The AID of the installed application.
 * \param applicationAIDLength IN The length of the application instance AID.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_validate_install_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
							  DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE applicationAID, DWORD applicationAIDLength) {
	return validate_install_receipt(confirmationCounter, cardUniqueData,
							  cardUniqueDataLength,
						   receiptKey, receiptData,
						   executableLoadFileAID, executableLoadFileAIDLength,
						   applicationAID, applicationAIDLength);
}

static LONG validate_install_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
							  DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE applicationAID, DWORD applicationAIDLength)
{
	LONG result;
	DWORD i=0;
	PBYTE validationData;
	DWORD validationDataLength;
	LOG_START(_T("validate_install_receipt"));
	validationDataLength = 1 + 2 + 1 + cardUniqueDataLength + 1 + executableLoadFileAIDLength + 1 + applicationAIDLength;
	validationData = (PBYTE)malloc(validationDataLength);
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
	result = validate_receipt(validationData, validationDataLength, receiptData.receipt, receiptKey);
	if (result != OPGP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	if (validationData)
		free(validationData);
	LOG_END(_T("validate_install_receipt"), result);
	return result;
}

/**
 * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
 * You may keep track of it. Returns OPGP_ERROR_SUCCESS if receipt is valid.
 * \param confirmationCounter IN The confirmation counter.
 * \param cardUniqueData IN The card unique data.
 * \param cardUniqueDataLength IN The length of the card unique data buffer.
 * \param receiptKey IN The 3DES key to generate the receipt.
 * \param receiptData IN The GP211_RECEIPT_DATA structure containing the receipt returned
 * from delete_application() to verify.
 * \param AID IN A buffer with AID of the application which was deleted.
 * \param AIDLength IN The length of the AID.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_validate_delete_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
							 DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE AID, DWORD AIDLength) {
	return validate_delete_receipt(confirmationCounter, cardUniqueData,
							 cardUniqueDataLength,
						   receiptKey, receiptData,
						   AID, AIDLength);
}

static LONG validate_delete_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
							 DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE AID, DWORD AIDLength)
{
	LONG result;
	DWORD i=0;
	PBYTE validationData = NULL;
	DWORD validationDataLength;
	LOG_START(_T("validate_delete_receipt"));
	validationDataLength = 1 + 2 + 1 + cardUniqueDataLength + 1 + AIDLength;
	validationData = (PBYTE)malloc(validationDataLength);
	validationData[i++] = 2;
	validationData[i++] = (BYTE)((confirmationCounter & 0x0000FF00) >> 8);
	validationData[i++] = (BYTE)(confirmationCounter & 0x000000FF);
	validationData[i++] = (BYTE)cardUniqueDataLength;
	memcpy(validationData, cardUniqueData, cardUniqueDataLength);
	i+=cardUniqueDataLength;
	validationData[i++] = (BYTE)AIDLength;
	memcpy(validationData, AID, AIDLength);
	i+=AIDLength;
	result = validate_receipt(validationData, validationDataLength, receiptData.receipt, receiptKey);
	if (result != OPGP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	if (validationData)
		free(validationData);
	LOG_END(_T("validate_delete_receipt"), result);
	return result;
}

/**
 * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
 * You may keep track of it. Returns OPGP_ERROR_SUCCESS if receipt is valid.
 * \param confirmationCounter IN The confirmation counter.
 * \param cardUniqueData IN The card unique data.
 * \param cardUniqueDataLength IN The length of the card unique data buffer.
 * \param receiptKey IN The 3DES key to generate the receipt.
 * \param receiptData IN The GP211_RECEIPT_DATA structure containing the receipt returned
 * from GP211_install_for_extradition() to verify.
 * \param oldSecurityDomainAID IN The AID of the old associated Security Domain.
 * \param oldSecurityDomainAIDLength IN The length of the oldSecurityDomainAID buffer.
 * \param newSecurityDomainAID IN The AID of the new associated Security Domain.
 * \param newSecurityDomainAIDLength IN The length of the newSecurityDomainAID buffer.
 * \param applicationOrExecutableLoadFileAID IN A buffer with AID of the Executable Load File which was INSTALL [for install].
 * \param applicationOrExecutableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_validate_extradition_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
							  DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE oldSecurityDomainAID, DWORD oldSecurityDomainAIDLength,
						   PBYTE newSecurityDomainAID, DWORD newSecurityDomainAIDLength,
						   PBYTE applicationOrExecutableLoadFileAID,
						   DWORD applicationOrExecutableLoadFileAIDLength)
{
	LONG result;
	DWORD i=0;
	PBYTE validationData;
	DWORD validationDataLength;
	LOG_START(_T("validate_install_receipt"));
	validationDataLength = 1 + 2 + 1 + cardUniqueDataLength + 1
		+ oldSecurityDomainAIDLength + 1 + applicationOrExecutableLoadFileAIDLength +
		1 + newSecurityDomainAIDLength;
	validationData = (PBYTE)malloc(validationDataLength);
	validationData[i++] = 2;
	validationData[i++] = (BYTE)((confirmationCounter & 0x0000FF00) >> 8);
	validationData[i++] = (BYTE)(confirmationCounter & 0x000000FF);
	validationData[i++] = (BYTE)cardUniqueDataLength;
	memcpy(validationData, cardUniqueData, cardUniqueDataLength);
	i+=cardUniqueDataLength;
	validationData[i++] = (BYTE)oldSecurityDomainAIDLength;
	memcpy(validationData, oldSecurityDomainAID, oldSecurityDomainAIDLength);
	i+=oldSecurityDomainAIDLength;
	validationData[i++] = (BYTE)applicationOrExecutableLoadFileAIDLength;
	memcpy(validationData, applicationOrExecutableLoadFileAID, applicationOrExecutableLoadFileAIDLength);
	i+=applicationOrExecutableLoadFileAIDLength;
	validationData[i++] = (BYTE)newSecurityDomainAIDLength;
	memcpy(validationData, newSecurityDomainAID, newSecurityDomainAIDLength);
	i+=newSecurityDomainAIDLength;
	result = validate_receipt(validationData, validationDataLength, receiptData.receipt, receiptKey);
	if (result != OPGP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	if (validationData)
		free(validationData);
	LOG_END(_T("validate_install_receipt"), result);
	return result;
}


/**
 * GlobalPlatform2.1.1: Validates a Receipt.
 * Returns OPGP_ERROR_SUCCESS if the receipt is valid.
 * \param validationData IN The data used to validate the returned receipt.
 * \param validationDataLength IN The length of the validationData buffer.
 * \param receipt IN The receipt.
 * \param receiptKey IN The 3DES key to generate the receipt.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
static LONG validate_receipt(PBYTE validationData, DWORD validationDataLength,
							 BYTE receipt[16], BYTE receiptKey[16])
{
	LONG result;
	BYTE mac[8];
	LOG_START(_T("validate_receipt"));
	result = calculate_MAC_des_3des(receiptKey, validationData, validationDataLength, icv, mac);
	if (result != OPGP_ERROR_SUCCESS) {
		goto end;
	}
	if (memcmp(mac, receipt, 8) != 0) {
		{ result = OPGP_ERROR_VALIDATION_FAILED; goto end; }
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("validate_receipt"), result);
	return result;
}

/**
 * Calculates a message authentication code using the left half key of a two key 3DES key
 * and the the full key for the final operation.
 * Pads the message always with 0x80 and additional 0x00 until message length is a multiple of 8.
 * \param _3des_key[16] IN A 3DES key used to sign.
 * \param *message IN The message to authenticate.
 * \param messageLength IN The message length.
 * \param InitialICV[8] IN The initial chaining vector.
 * \param mac[8] OUT The calculated MAC.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
static LONG calculate_MAC_des_3des(unsigned char _3des_key[16], unsigned char *message, int messageLength,
						  unsigned char InitialICV[8], unsigned char mac[8]) {
	LONG result;
	int i,outl;
	EVP_CIPHER_CTX ctx;
	unsigned char des_key[8];
	LOG_START(_T("calculate_MAC_des_3des"));
	EVP_CIPHER_CTX_init(&ctx);
	/* If only one block */
	memcpy(mac, InitialICV, 8);
//  DES CBC mode
	memcpy(des_key, _3des_key, 8);
	result = EVP_EncryptInit_ex(&ctx, EVP_des_cbc(), NULL, des_key, InitialICV);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(&ctx, mac,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
	}
	result = EVP_EncryptFinal_ex(&ctx, mac,
		&outl);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	result = EVP_CIPHER_CTX_cleanup(&ctx);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
//  3DES mode
	EVP_CIPHER_CTX_init(&ctx);
	result = EVP_EncryptInit_ex(&ctx, EVP_des_ede_cbc(), NULL, _3des_key, mac);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, mac,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
	}
	result = EVP_EncryptUpdate(&ctx, mac,
		&outl, padding, 8 - (messageLength%8));
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	result = EVP_EncryptFinal_ex(&ctx, mac,
		&outl);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	LOG_END(_T("calculate_MAC_des_3des"), result);
	return result;
}

/**
 * Creates the session key for SCP01.
 * \param key[16] IN The Secure Channel Encryption Key or Secure Channel Message
 * Authentication Code Key for calculating the corresponding session key.
 * \param cardChallenge[8] IN The card challenge.
 * \param hostChallenge[8] IN The host challenge.
 * \param sessionKey[8] OUT The calculated 3DES session key.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
static LONG create_session_key_SCP01(unsigned char key[16], unsigned char cardChallenge[8],
							   unsigned char hostChallenge[8], unsigned char sessionKey[16]) {
	LONG result;
	unsigned char derivation_data[16];
	int outl;

	LOG_START(_T("create_session_key_SCP01"));
	memcpy(derivation_data, cardChallenge+4, 4);
	memcpy(derivation_data+4, hostChallenge, 4);
	memcpy(derivation_data+8, cardChallenge, 4);
	memcpy(derivation_data+12, hostChallenge+4, 4);

	result = calculate_enc_ecb_two_key_triple_des(key, derivation_data, 16, sessionKey, &outl);
	if (result != OPGP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("create_session_key_SCP01"), result);
	return result;
}

/**
 * Creates the session key for SCP02.
 * \param key[16] IN The Secure Channel Encryption Key or Secure Channel Message
 * Authentication Code Key or Data Encryption Key for calculating the corresponding session key.
 * \param constant[2] IN The constant for the corresponding session key.
 * \param sequenceCounter[2] IN The sequence counter.
 * \param sessionKey[8] OUT The calculated 3DES session key.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
static LONG create_session_key_SCP02(unsigned char key[16], unsigned char constant[2],
									unsigned char sequenceCounter[2], unsigned char sessionKey[16]) {
	LONG result;
	unsigned char derivation_data[16];
	int outl;
	int i;

	LOG_START(_T("create_session_key_SCP02"));
	memcpy(derivation_data, constant, 2);
	memcpy(derivation_data+2, sequenceCounter, 2);
	for (i=4; i< 16; i++) {
		derivation_data[i] = 0x00;
	}

	result = calculate_enc_cbc(key, derivation_data, 16, sessionKey, &outl);
	if (result != OPGP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("create_session_key_SCP02"), result);
	return result;
}

/**
 * Calculates the encryption of a message in ECB mode with two key triple DES.
 * Pads the message with 0x80 and additional 0x00 if message length is not a multiple of 8.
 * \param key[16] IN A 3DES key used to encrypt.
 * \param *message IN The message to encrypt.
 * \param messageLength IN The length of the message.
 * \param *encryption OUT The encryption.
 * \param *encryptionLength OUT The length of the encryption.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
static LONG calculate_enc_ecb_two_key_triple_des(unsigned char key[16], unsigned char *message, int messageLength,
							  unsigned char *encryption, int *encryptionLength) {
	LONG result;
	int i,outl;
	EVP_CIPHER_CTX ctx;
	LOG_START(_T("calculate_enc_ecb_two_key_triple_des"));
	EVP_CIPHER_CTX_init(&ctx);
	*encryptionLength = 0;

	result = EVP_EncryptInit_ex(&ctx, EVP_des_ede(), NULL, key, icv);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
		*encryptionLength+=outl;
	}
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
		*encryptionLength+=outl;

		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, padding, 8 - (messageLength%8));
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
		*encryptionLength+=outl;
	}
	result = EVP_EncryptFinal_ex(&ctx, encryption+*encryptionLength,
		&outl);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	*encryptionLength+=outl;
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	LOG_END(_T("calculate_enc_ecb_two_key_triple_des"), result);
	return result;
}

/**
 * Calculates the encryption of a message in ECB mode with single DES.
 * Pads the message with 0x80 and additional 0x00 if message length is not a multiple of 8.
 * \param key[8] IN A DES key used to encrypt.
 * \param *message IN The message to encrypt.
 * \param messageLength IN The length of the message.
 * \param *encryption OUT The encryption.
 * \param *encryptionLength OUT The length of the encryption.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
static LONG calculate_enc_ecb_single_des(unsigned char key[8], unsigned char *message, int messageLength,
							  unsigned char *encryption, int *encryptionLength) {
	LONG result;
	int i,outl;
	EVP_CIPHER_CTX ctx;
	LOG_START(_T("calculate_enc_ecb_single_des"));
	EVP_CIPHER_CTX_init(&ctx);
	*encryptionLength = 0;

	result = EVP_EncryptInit_ex(&ctx, EVP_des_ecb(), NULL, key, NULL);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
		*encryptionLength+=outl;
	}
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
		*encryptionLength+=outl;

		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, padding, 8 - (messageLength%8));
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
		*encryptionLength+=outl;
	}
	result = EVP_EncryptFinal_ex(&ctx, encryption+*encryptionLength,
		&outl);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	*encryptionLength+=outl;
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	LOG_END(_T("calculate_enc_ecb_single_des"), result);
	return result;
}

/**
 * Calculates a message authentication code.
 * Pads the message always with 0x80 and additional 0x00 until message length is a multiple of 8.
 * \param sessionKey[16] IN A 3DES key used to sign.
 * \param *message IN The message to authenticate.
 * \param messageLength IN The message length.
 * \param icv[8] IN The initial chaining vector.
 * \param mac[8] OUT The calculated MAC.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
static LONG calculate_MAC(unsigned char sessionKey[16], unsigned char *message, int messageLength,
						  unsigned char icv[8], unsigned char mac[8]) {
	LONG result;
	int i,outl;
	EVP_CIPHER_CTX ctx;
	LOG_START(_T("calculate_MAC"));
	EVP_CIPHER_CTX_init(&ctx);

	result = EVP_EncryptInit_ex(&ctx, EVP_des_ede_cbc(), NULL, sessionKey, icv);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(&ctx, mac,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
	}
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, mac,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
	}
	result = EVP_EncryptUpdate(&ctx, mac,
		&outl, padding, 8 - (messageLength%8));
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	result = EVP_EncryptFinal_ex(&ctx, mac,
		&outl);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	LOG_END(_T("calculate_MAC"), result);
	return result;
}

/**
 * Calculates the encryption of a message in CBC mode.
 * Pads the message with 0x80 and additional 0x00 if message length is not a multiple of 8.
 * \param key[16] IN A 3DES key used to encrypt.
 * \param *message IN The message to encrypt.
 * \param messageLength IN The length of the message.
 * \param *encryption OUT The encryption.
 * \param *encryptionLength OUT The length of the encryption.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
static LONG calculate_enc_cbc(unsigned char key[16], unsigned char *message, int messageLength,
							  unsigned char *encryption, int *encryptionLength) {
	LONG result;
	int i,outl;
	EVP_CIPHER_CTX ctx;
	LOG_START(_T("calculate_enc_cbc"));
	EVP_CIPHER_CTX_init(&ctx);
	*encryptionLength = 0;

	result = EVP_EncryptInit_ex(&ctx, EVP_des_ede_cbc(), NULL, key, icv);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
		*encryptionLength+=outl;
	}
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
		*encryptionLength+=outl;

		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, padding, 8 - (messageLength%8));
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
		*encryptionLength+=outl;
	}
	result = EVP_EncryptFinal_ex(&ctx, encryption+*encryptionLength,
		&outl);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	*encryptionLength+=outl;
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	LOG_END(_T("calculate_enc_cbc"), result);
	return result;
}

/**
 * Calculates the encryption of a message in CBC mode for SCP02.
 * Pads the message with 0x80 and additional 0x00 until message length is a multiple of 8.
 * \param key[16] IN A 3DES key used to encrypt.
 * \param *message IN The message to encrypt.
 * \param messageLength IN The length of the message.
 * \param *encryption OUT The encryption.
 * \param *encryptionLength OUT The length of the encryption.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
static LONG calculate_enc_cbc_SCP02(unsigned char key[16], unsigned char *message, int messageLength,
							  unsigned char *encryption, int *encryptionLength) {
	LONG result;
	int i,outl;
	EVP_CIPHER_CTX ctx;
	LOG_START(_T("calculate_enc_cbc_SCP02"));
	EVP_CIPHER_CTX_init(&ctx);
	*encryptionLength = 0;

	result = EVP_EncryptInit_ex(&ctx, EVP_des_ede_cbc(), NULL, key, icv);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
		*encryptionLength+=outl;
	}
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
		*encryptionLength+=outl;
	}
	result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
		&outl, padding, 8 - (messageLength%8));
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	*encryptionLength+=outl;
	result = EVP_EncryptFinal_ex(&ctx, encryption+*encryptionLength,
		&outl);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	*encryptionLength+=outl;
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	LOG_END(_T("calculate_enc_cbc_SCP02"), result);
	return result;
}

/**
 * Calculates the card cryptogram for SCP01.
 * \param S_ENCSessionKey[16] IN The S-ENC Session Key for calculating the card cryptogram.
 * \param cardChallenge[8] IN The card challenge.
 * \param hostChallenge[8] IN The host challenge.
 * \param cardCryptogram[8] OUT The calculated card cryptogram.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
static LONG calculate_card_cryptogram_SCP01(unsigned char S_ENCSessionKey[16], unsigned char cardChallenge[8],
									  unsigned char hostChallenge[8], unsigned char cardCryptogram[8]) {
	LONG result;
	unsigned char message[16];
	LOG_START(_T("calculate_card_cryptogram_SCP01"));
	memcpy(message, hostChallenge, 8);
	memcpy(message+8, cardChallenge, 8);
	result = calculate_MAC(S_ENCSessionKey, message, 16, icv, cardCryptogram);
	if (result != OPGP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("calculate_card_cryptogram_SCP01"), result);
	return result;
}

/**
 * Calculates the card cryptogram for SCP02.
 * \param S_ENCSessionKey[16] IN The S-ENC Session Key for calculating the card cryptogram.
 * \param sequenceCounter[2] IN The sequence counter.
 * \param cardChallenge[6] IN The card challenge.
 * \param hostChallenge[8] IN The host challenge.
 * \param cardCryptogram[8] OUT The calculated card cryptogram.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
static LONG calculate_card_cryptogram_SCP02(unsigned char S_ENCSessionKey[16],
											unsigned char sequenceCounter[2],
											unsigned char cardChallenge[6],
											unsigned char hostChallenge[8],
											unsigned char cardCryptogram[8]) {
	LONG result;
	unsigned char message[16];
	LOG_START(_T("calculate_card_cryptogram_SCP02"));
	memcpy(message, hostChallenge, 8);
	memcpy(message+8, sequenceCounter, 2);
	memcpy(message+10, cardChallenge, 6);
	result = calculate_MAC(S_ENCSessionKey, message, 16, icv, cardCryptogram);
	if (result != OPGP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("calculate_card_cryptogram_SCP02"), result);
	return result;
}

/**
 * Calculates the host cryptogram for SCP01.
 * \param S_ENCSessionKey[16] IN The S-ENC Session Key for calculating the card cryptogram.
 * \param cardChallenge[8] IN The card challenge.
 * \param hostChallenge[8] IN The host challenge.
 * \param cardCryptogram[8] OUT The calculated host cryptogram.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
static LONG calculate_host_cryptogram_SCP01(unsigned char S_ENCSessionKey[16],
											unsigned char cardChallenge[8],
											unsigned char hostChallenge[8],
											unsigned char hostCryptogram[8]) {
	LONG result;
	unsigned char message[16];
	LOG_START(_T("calculate_host_cryptogram_SCP01"));
	memcpy(message, cardChallenge, 8);
	memcpy(message+8, hostChallenge, 8);
	result = calculate_MAC(S_ENCSessionKey, message, 16, icv, hostCryptogram);
	if (result != OPGP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("calculate_host_cryptogram_SCP01"), result);
	return result;
}

/**
 * Calculates the host cryptogram for SCP02.
 * \param S_ENCSessionKey[16] IN The S-ENC Session Key for calculating the card cryptogram.
 * \param sequenceCounter[2] IN The sequence counter.
 * \param cardChallenge[6] IN The card challenge.
 * \param hostChallenge[8] IN The host challenge.
 * \param cardCryptogram[8] OUT The calculated host cryptogram.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
static LONG calculate_host_cryptogram_SCP02(unsigned char S_ENCSessionKey[16],
											unsigned char sequenceCounter[2],
											unsigned char cardChallenge[6],
											unsigned char hostChallenge[8],
											unsigned char hostCryptogram[8]) {
	LONG result;
	unsigned char message[16];
	LOG_START(_T("calculate_host_cryptogram_SCP02"));
	memcpy(message, sequenceCounter, 2);
	memcpy(message+2, cardChallenge, 6);
	memcpy(message+8, hostChallenge, 8);
	result = calculate_MAC(S_ENCSessionKey, message, 16, icv, hostCryptogram);
	if (result != OPGP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("calculate_host_cryptogram_SCP02"), result);
	return result;
}

/**
 * A keySetVersion and keyIndex of 0x00 selects the first available key set version and key index.
 * There a two Secure Channel Protocols defined be the GlobalPlatform specification. For SCP01 a secure channel
 * key set consist always of at least three keys, from which the Secure Channel Encryption Key and the Secure Channel
 * Message Authentication Code Key is needed for mutual authentication and the generation of session keys.
 * The Data Encryption Key is used when transmitting key sensitive data with a PUT KEY command.
 * For SCP02 a keyset can also have only one Secure Channel base key.
 * It depends on the supported protocol implementation by the card what keys must be passed as parameters.
 * baseKey must be NULL if the protocol uses 3 Secure Channel Keys
 * (Secure Channel Encryption Key, Secure Channel Message Authentication Code Key and
 * Data Encryption Key) and vice versa.
 * Details about the supported Secure Channel Protocol and its implementation can be
 * obtained by a call to the function get_secure_channel_protocol_details().
 * New cards usually use the VISA default key for all DES keys. See #GP211_VISA_DEFAULT_KEY.
 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param baseKey IN Secure Channel base key.
 * \param S_ENC IN Secure Channel Encryption Key.
 * \param S_MAC IN Secure Channel Message Authentication Code Key.
 * \param DEK IN Data Encryption Key.
 * \param keySetVersion IN The key set version on the card to use for mutual authentication.
 * \param keyIndex IN The key index of the encryption key in the key set version on the card to use for
 * mutual authentication.
 * \param secureChannelProtocol IN The Secure Channel Protocol.
 * \param secureChannelProtocolImpl IN The Secure Channel Protocol Implementation.
 * \param securityLevel IN The requested security level.
 * See #GP211_SCP01_SECURITY_LEVEL_C_DEC_C_MAC and so on.
 * \param *secInfo OUT The returned GP211_SECURITY_INFO structure.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_mutual_authentication(OPGP_CARD_INFO cardInfo, BYTE baseKey[16],
						   BYTE S_ENC[16], BYTE S_MAC[16],
						   BYTE DEK[16], BYTE keySetVersion,
						   BYTE keyIndex, BYTE secureChannelProtocol,
						   BYTE secureChannelProtocolImpl, BYTE securityLevel,
						   GP211_SECURITY_INFO *secInfo) {
	return mutual_authentication(cardInfo, baseKey,
						   S_ENC, S_MAC,
						   DEK, keySetVersion,
						   keyIndex, secureChannelProtocol,
						   secureChannelProtocolImpl, securityLevel,
						   secInfo);
}

static LONG mutual_authentication(OPGP_CARD_INFO cardInfo, BYTE baseKey[16],
						   BYTE S_ENC[16], BYTE S_MAC[16],
						   BYTE DEK[16], BYTE keySetVersion,
						   BYTE keyIndex, BYTE secureChannelProtocol,
						   BYTE secureChannelProtocolImpl, BYTE securityLevel,
						   GP211_SECURITY_INFO *secInfo) {
	LONG result;
	DWORD i=0;

	unsigned char hostChallenge[8];

	unsigned char key_diversification_data[10];
	unsigned char key_information_data[2];
	unsigned char sequenceCounter[2];
	unsigned char cardChallengeSCP02[6];
	unsigned char cardChallengeSCP01[8];
	unsigned char cardCryptogram[8];

	unsigned char card_cryptogram_ver[8];
	unsigned char hostCryptogram[8];
	unsigned char mac[8];

	DWORD sendBufferLength=256;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[256];
	// random for host challenge

	LOG_START(_T("mutual_authentication"));

	secInfo->secureChannelProtocol = secureChannelProtocol;
	secInfo->secureChannelProtocolImpl = secureChannelProtocolImpl;

#ifdef DEBUG
	log_Log(_T("Secure Channel Protocol: 0x%02X"), secureChannelProtocol);
	log_Log(_T("Secure Channel Protocol Implementation: 0x%02X"), secureChannelProtocolImpl);
#endif

	result = RAND_bytes(hostChallenge, 8);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}

#ifdef DEBUG
	log_Log(_T("Generated Host Challenge: "));
	for (i=0; i<8; i++) {
		log_Log(_T("0x%02x "), hostChallenge[i]);
	}
#endif

	// INITIALIZE UPDATE
	i=0;
	sendBufferLength = 14;
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0x50;
	sendBuffer[i++] = keySetVersion;
	sendBuffer[i++] = keyIndex;
	sendBuffer[i++] = 0x08;
	memcpy(sendBuffer+i, hostChallenge, 8);
	i+=8;
	sendBuffer[i] = 0x00;
#ifdef DEBUG
	log_Log(_T("mutual_authentication: INITIALIZE UPDATE Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, NULL, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("mutual_authentication: INITIALIZE UPDATE Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif

	// response of INITIALIZE UPDATE
	memcpy(key_diversification_data, recvBuffer, 10);
	memcpy(key_information_data, recvBuffer+10,2);
	if (secInfo->secureChannelProtocol == GP211_SCP02) {
		memcpy(sequenceCounter, recvBuffer+12, 2);
		memcpy(cardChallengeSCP02, recvBuffer+14, 6);
	}
	else {
		memcpy(cardChallengeSCP01, recvBuffer+12, 8);
	}
	memcpy(cardCryptogram, recvBuffer+20, 8);

	log_Log(_T("Key Diversification Data: "));
	for (i=0; i<10; i++) {
		log_Log(_T("0x%02x "), key_diversification_data[i]);
	}

	log_Log(_T("Key Information Data: "));
	for (i=0; i<2; i++) {
		log_Log(_T("0x%02x "), key_information_data[i]);
	}

#ifdef DEBUG
	if (secInfo->secureChannelProtocol == GP211_SCP02) {
		log_Log(_T("Sequence Counter: "));
		for (i=0; i<2; i++) {
			log_Log(_T("0x%02x "), sequenceCounter[i]);
		}
		log_Log(_T("Card Challenge: "));
		for (i=0; i<6; i++) {
			log_Log(_T("0x%02x "), cardChallengeSCP02[i]);
		}
	}
	else {
		log_Log(_T("Card Challenge: "));
		for (i=0; i<8; i++) {
			log_Log(_T("0x%02x "), cardChallengeSCP01[i]);
		}
	}

	log_Log(_T("Retrieved Card Cryptogram: "));
	for (i=0; i<8; i++) {
		log_Log(_T("0x%02x "), cardCryptogram[i]);
	}

#endif

	if (secInfo->secureChannelProtocol == GP211_SCP02) {
		/* Secure Channel base key */
		if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i04
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i14) {
			// calculation of encryption session key
				result = create_session_key_SCP02(baseKey, ENCDerivationConstant, sequenceCounter, secInfo->encryptionSessionKey);
			if (result != OPGP_ERROR_SUCCESS) {
				goto end;
			}

			// calculation of C-MAC session key
			result = create_session_key_SCP02(baseKey, C_MACDerivationConstant, sequenceCounter, secInfo->C_MACSessionKey);
			if (result != OPGP_ERROR_SUCCESS) {
				goto end;
			}

			// calculation of R-MAC session key
			result = create_session_key_SCP02(baseKey, R_MACDerivationConstant, sequenceCounter, secInfo->C_MACSessionKey);
			if (result != OPGP_ERROR_SUCCESS) {
				goto end;
			}

			// calculation of data encryption session key
			result = create_session_key_SCP02(baseKey, DEKDerivationConstant, sequenceCounter, secInfo->C_MACSessionKey);
			if (result != OPGP_ERROR_SUCCESS) {
				goto end;
			}

		}
		/* 3 Secure Channel Keys */
		else if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i05
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i15) {
			// calculation of encryption session key
			result = create_session_key_SCP02(S_ENC, ENCDerivationConstant, sequenceCounter, secInfo->encryptionSessionKey);
			if (result != OPGP_ERROR_SUCCESS) {
				goto end;
			}

			// calculation of C-MAC session key
			result = create_session_key_SCP02(S_MAC, C_MACDerivationConstant, sequenceCounter, secInfo->C_MACSessionKey);
			if (result != OPGP_ERROR_SUCCESS) {
				goto end;
			}

			// calculation of R-MAC session key
			result = create_session_key_SCP02(S_MAC, R_MACDerivationConstant, sequenceCounter, secInfo->R_MACSessionKey);
			if (result != OPGP_ERROR_SUCCESS) {
				goto end;
			}

			// calculation of data encryption session key
			result = create_session_key_SCP02(DEK, DEKDerivationConstant, sequenceCounter, secInfo->dataEncryptionSessionKey);
			if (result != OPGP_ERROR_SUCCESS) {
				goto end;
			}
		}
		else {
			result = GP211_ERROR_INVALID_SCP_IMPL;
			goto end;
		}
	}
	else if (secInfo->secureChannelProtocol = GP211_SCP01) {
		if (secInfo->secureChannelProtocolImpl == GP211_SCP01_IMPL_i05
			|| secInfo->secureChannelProtocolImpl == GP211_SCP01_IMPL_i15) {
			// calculation of ENC session key
			result = create_session_key_SCP01(S_ENC, cardChallengeSCP01, hostChallenge, secInfo->encryptionSessionKey);
			if (result != OPGP_ERROR_SUCCESS) {
				goto end;
			}

			// calculation of MAC session key
			result = create_session_key_SCP01(S_MAC, cardChallengeSCP01, hostChallenge, secInfo->C_MACSessionKey);
			if (result != OPGP_ERROR_SUCCESS) {
				goto end;
			}

			// DEK
			memcpy(secInfo->dataEncryptionSessionKey, DEK, 16);
		}
		else {
			result = GP211_ERROR_INVALID_SCP_IMPL;
			goto end;
		}
	}
	else {
		result = GP211_ERROR_INVALID_SCP;
		goto end;
	}

#ifdef DEBUG
	log_Log(_T("S-ENC Session Key: "));
	for (i=0; i<16; i++) {
		log_Log(_T("0x%02x "), secInfo->encryptionSessionKey[i]);
	}
#endif

#ifdef DEBUG
	log_Log(_T("C-MAC Session Key: "));
	for (i=0; i<16; i++) {
		log_Log(_T("0x%02x "), secInfo->C_MACSessionKey[i]);
	}
#endif

#ifdef DEBUG
	if (secInfo->secureChannelProtocol == GP211_SCP01) {
		log_Log(_T("Date Encryption Key: "));
		for (i=0; i<16; i++) {
			log_Log(_T("0x%02x "), secInfo->dataEncryptionSessionKey[i]);
		}
	}
#endif

#ifdef DEBUG
	if (secInfo->secureChannelProtocol == GP211_SCP02) {
		log_Log(_T("R-MAC Session Key: "));
		for (i=0; i<16; i++) {
			log_Log(_T("0x%02x "), secInfo->R_MACSessionKey[i]);
		}
	}
#endif

#ifdef DEBUG
	if (secInfo->secureChannelProtocol == GP211_SCP02) {
		log_Log(_T("DEK Session Key: "));
		for (i=0; i<16; i++) {
			log_Log(_T("0x%02x "), secInfo->dataEncryptionSessionKey[i]);
		}
	}
#endif

	// calculation of card cryptogram
	if (secInfo->secureChannelProtocol == GP211_SCP02) {
		result = calculate_card_cryptogram_SCP02(secInfo->encryptionSessionKey,
			sequenceCounter, cardChallengeSCP02, hostChallenge, card_cryptogram_ver);
		if (result != OPGP_ERROR_SUCCESS) {
			goto end;
		}
	}
	else {
		result = calculate_card_cryptogram_SCP01(secInfo->encryptionSessionKey,
			cardChallengeSCP01, hostChallenge, card_cryptogram_ver);
		if (result != OPGP_ERROR_SUCCESS) {
			goto end;
		}
	}

#ifdef DEBUG
	log_Log(_T("Card Cryptogram to compare: "));
	for (i=0; i<8; i++) {
		log_Log(_T("0x%02x "), card_cryptogram_ver[i]);
	}

#endif

	if (memcmp(cardCryptogram, card_cryptogram_ver, 8) != 0) {
		{ result = OPGP_ERROR_CARD_CRYPTOGRAM_VERIFICATION; goto end; }
	}

	// EXTERNAL AUTHENTICATE
	secInfo->securityLevel = securityLevel;
	if (secInfo->secureChannelProtocol == GP211_SCP02) {
		calculate_host_cryptogram_SCP02(secInfo->encryptionSessionKey, sequenceCounter,
			cardChallengeSCP02, hostChallenge, hostCryptogram);
	}
	else {
		calculate_host_cryptogram_SCP01(secInfo->encryptionSessionKey, cardChallengeSCP01, hostChallenge,
			hostCryptogram);
	}

	sendBufferLength = 21;
	i=0;
	sendBuffer[i++] = 0x84;
	sendBuffer[i++] = 0x82;
	sendBuffer[i++] = securityLevel;
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 0x10;
	memcpy(sendBuffer+i, hostCryptogram, 8);
	i+=8;

	if (secInfo->secureChannelProtocol == GP211_SCP02) {
		calculate_MAC_des_3des(secInfo->C_MACSessionKey, sendBuffer, sendBufferLength-8, icv, mac);
	}
	else {
		calculate_MAC(secInfo->C_MACSessionKey, sendBuffer, sendBufferLength-8, icv, mac);
	}
	memcpy(secInfo->lastC_MAC, mac, 8);
	memcpy(sendBuffer+i, mac, 8);
	i+=8;
#ifdef DEBUG
	log_Log(_T("mutual_authentication: EXTERNAL AUTHENTICATE Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, NULL, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_SUCCESS != result) {
		switch (result) {
			case OPGP_ISO7816_ERROR_6300:
				{ result = OPGP_ISO7816_ERROR_HOST_CRYPTOGRAM_VERIFICATION; goto end; }
			default:
				goto end;
		}
	}

#ifdef DEBUG
	log_Log(_T("mutual_authentication: EXTERNAL AUTHENTICATE Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
#endif

	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("mutual_authentication"), result);
	return result;
}

/**
 * It depends on the supported protocol implementation by the card what keys must be passed as parameters.
 * baseKey must be NULL if the protocol uses 3 Secure Channel Keys
 * (Secure Channel Encryption Key, Secure Channel Message Authentication Code Key and
 * Data Encryption Key) and vice versa.
 * Details about the supported Secure Channel Protocol and its implementation can be
 * obtained by a call to the function GP211_get_secure_channel_protocol_details().
 * New cards usually use the VISA default key for all DES keys. See #GP211_VISA_DEFAULT_KEY.
 * The current Sequence Counter can be obtained with a call to GP211_get_sequence_counter().
 * SCP02 is implicitly set and the security level is set to C-MAC only.
 * \param AID The AID needed for the calculation of the ICV.
 * \param AIDLength The length of the AID buffer.
 * \param baseKey IN Secure Channel base key.
 * \param S_ENC IN Secure Channel Encryption Key.
 * \param S_MAC IN Secure Channel Message Authentication Code Key.
 * \param DEK IN Data Encryption Key.
 * \param secureChannelProtocolImpl IN The Secure Channel Protocol Implementation.
 * \param sequenceCounter IN The sequence counter.
 * \param *secInfo OUT The returned GP211_SECURITY_INFO structure.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_init_implicit_secure_channel(PBYTE AID, DWORD AIDLength, BYTE baseKey[16],
								  BYTE S_ENC[16], BYTE S_MAC[16], BYTE DEK[16],
								  BYTE secureChannelProtocolImpl, BYTE sequenceCounter[2],
								  GP211_SECURITY_INFO *secInfo) {
	LONG result;

	LOG_START(_T("init_implicit_secure_channel"));

	secInfo->secureChannelProtocol = GP211_SCP02;
	secInfo->secureChannelProtocolImpl = secureChannelProtocolImpl;
	secInfo->securityLevel = GP211_SCP02_SECURITY_LEVEL_C_MAC;
		/* Secure Channel base key */
	if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1A
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1B) {
		// calculation of encryption session key
			result = create_session_key_SCP02(baseKey, ENCDerivationConstant, sequenceCounter, secInfo->encryptionSessionKey);
		if (result != OPGP_ERROR_SUCCESS) {
			goto end;
		}

		// calculation of C-MAC session key
		result = create_session_key_SCP02(baseKey, C_MACDerivationConstant, sequenceCounter, secInfo->C_MACSessionKey);
		if (result != OPGP_ERROR_SUCCESS) {
			goto end;
		}

		// calculation of R-MAC session key
		result = create_session_key_SCP02(baseKey, R_MACDerivationConstant, sequenceCounter, secInfo->C_MACSessionKey);
		if (result != OPGP_ERROR_SUCCESS) {
			goto end;
		}

		// calculation of data encryption session key
		result = create_session_key_SCP02(baseKey, DEKDerivationConstant, sequenceCounter, secInfo->C_MACSessionKey);
		if (result != OPGP_ERROR_SUCCESS) {
			goto end;
		}

	}
	/* 3 Secure Channel Keys */
	else if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0A
		|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0B) {
		// calculation of encryption session key
		result = create_session_key_SCP02(S_ENC, ENCDerivationConstant, sequenceCounter, secInfo->encryptionSessionKey);
		if (result != OPGP_ERROR_SUCCESS) {
			goto end;
		}

		// calculation of C-MAC session key
		result = create_session_key_SCP02(S_MAC, C_MACDerivationConstant, sequenceCounter, secInfo->C_MACSessionKey);
		if (result != OPGP_ERROR_SUCCESS) {
			goto end;
		}

		// calculation of R-MAC session key
		result = create_session_key_SCP02(S_MAC, R_MACDerivationConstant, sequenceCounter, secInfo->R_MACSessionKey);
		if (result != OPGP_ERROR_SUCCESS) {
			goto end;
		}

		// calculation of data encryption session key
		result = create_session_key_SCP02(DEK, DEKDerivationConstant, sequenceCounter, secInfo->dataEncryptionSessionKey);
		if (result != OPGP_ERROR_SUCCESS) {
			goto end;
		}
	}
	else {
		result = GP211_ERROR_INVALID_SCP_IMPL;
		goto end;
	}

	result = calculate_MAC_des_3des(secInfo->C_MACSessionKey, AID, AIDLength, icv, secInfo->lastC_MAC);
	if ( OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("init_implicit_secure_channel"), result);
	return result;
}

/**
 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param sequenceCounter OUT The sequence counter.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_get_sequence_counter(OPGP_CARD_INFO cardInfo,
						  BYTE sequenceCounter[2]) {
	LONG result;
	BYTE recvBuffer[256];
	DWORD recvBufferLength = sizeof(recvBuffer);

	LOG_START(_T("get_sequence_counter"));
	result = GP211_get_data_iso7816_4(cardInfo, GP211_GET_DATA_SEQUENCE_COUNTER_DEFAULT_KEY_VERSION,
		recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
	memcpy(sequenceCounter, recvBuffer, 2);
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("get_sequence_counter"), result);
	return result;
}

/**
 * \param *secInfo OUT The returned GP211_SECURITY_INFO structure.
 */
LONG close_implicit_secure_channel(GP211_SECURITY_INFO *secInfo) {
	LONG result;
	LOG_START(_T("close_implicit_secure_channel"));
	secInfo->securityLevel = GP211_SCP02_SECURITY_LEVEL_NO_SECURE_MESSAGING;
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("close_implicit_secure_channel"), result);
	return result;
}

/**
 * \return The last OpenSSL error code.
 */
unsigned long get_last_OpenSSL_error_code(void) {
	return ERR_get_error();
}


/**
 * The single numbers of the new PIN are encoded as single BYTEs in the newPIN buffer.
 * The tryLimit must be in the range of 0x03 and x0A.
 * The PIN must comprise at least 6 numbers and not exceeding 12 numbers.
 * To unblock the PIN use tryLimit with a value of 0x00. In this case newPIN buffer and newPINLength are ignored.
 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param tryLimit IN The try limit for the PIN.
 * \param newPIN IN The new PIN.
 * \param newPINLength IN The length of the new PIN.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_pin_change(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE tryLimit,
					  PBYTE newPIN, DWORD newPINLength) {
	return pin_change(cardInfo, secInfo, tryLimit, newPIN, newPINLength);
}

static LONG pin_change(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE tryLimit,
				PBYTE newPIN, DWORD newPINLength) {
	LONG result;
	DWORD sendBufferLength;
	DWORD recvBufferLength=2;
	BYTE recvBuffer[2];
	BYTE sendBuffer[13];
	BYTE PINFormat[8];
	BYTE encryption[8];
	int encryptionLength;
	DWORD j,i=0;
	LOG_START(_T("pin_change"));
	if ((tryLimit != 0) && !((tryLimit > 0x03) && (tryLimit <= 0x0a))) {
		{ result = OPGP_ERROR_WRONG_TRY_LIMIT; goto end; }
	}
	if ((newPINLength < 6) || (newPINLength > 12)) {
		{ result = OPGP_ERROR_WRONG_PIN_LENGTH; goto end; }
	}
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0x24;
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = tryLimit;
	if (tryLimit != 0) {
		sendBuffer[i++] = 0x08;
		PINFormat[0] = 0x20;
		PINFormat[0] |= newPINLength & 0x0f;
		for (j=0; j<newPINLength; j++) {
			PINFormat[1+j/2] |= (newPIN[j] & 0x0f) << 4*(1-j%2);
		}
		for (; j<12; j++) {
			PINFormat[1+j/2] |= (0x0f) << 4*(1-j%2);
		}
		PINFormat[7] = 0xFF;
		calculate_enc_ecb_two_key_triple_des(secInfo->dataEncryptionSessionKey, PINFormat, 8, encryption, &encryptionLength);
		memcpy(sendBuffer+i, encryption, 8);
		i+=8;
	}
	sendBufferLength = i;
#ifdef DEBUG
	log_Log(_T("pin_change: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(cardInfo, secInfo,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_SUCCESS != result) {
		if (result == OPGP_ISO7816_ERROR_WRONG_DATA)
			{ result = OPGP_ISO7816_ERROR_WRONG_GLOBAL_PIN_FORMAT; goto end; }
		if (result == OPGP_ISO7816_ERROR_INCORRECT_P1P2)
			{ result = OPGP_ISO7816_ERROR_WRONG_PIN_TRY_LIMIT; goto end; }
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("pin_change: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}

#endif
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("pin_change"), result);
	return result;
}

/**
 * If STORE DATA is used for personalizing an application, a GP211_install_for_personalization().

 * \param cardInfo IN The OPGP_CARD_INFO structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param *data IN Data to send to application or Security Domain.
 * \param dataLength IN The length of the data buffer.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG GP211_store_data(OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 PBYTE data, DWORD dataLength) {
	LONG result = 0;
	DWORD sendBufferLength;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[261];
	DWORD i=0;
	DWORD left, read;
	BYTE blockNumber=0x00;
	LOG_START(_T("store_data"));
	sendBuffer[0] = 0x80;
	sendBuffer[1] = 0xE2;

	read = 0;
	left = dataLength;
	while(left > 0) {
		if (left <= MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING) {
			sendBuffer[2] = 0x80;
			memcpy(sendBuffer+5, data+read, left);
			read+=left;
			left-=left;
			sendBufferLength=5+left;
			sendBuffer[4] = (BYTE)left;
		}
		else {
			sendBuffer[2] = 0x00;
			memcpy(sendBuffer+5, data+read, MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING);
			read+=MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING;
			left-=MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING;
			sendBufferLength=5+MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING;
			sendBuffer[4] = MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING;
		}
		sendBuffer[3] = blockNumber++;

#ifdef DEBUG
		log_Log(_T("store_data: Data to send: "));
		for (i=0; i<sendBufferLength; i++) {
			log_Log(_T(" 0x%02x"), sendBuffer[i]);
		}

#endif
		recvBufferLength=256;
		result = send_APDU(cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
		if (OPGP_ERROR_SUCCESS != result) {
			goto end;
		}
#ifdef DEBUG
		if (sendBuffer[2] != 0x80) {
			log_Log(_T("store_data: Data: "));
			for (i=0; i<recvBufferLength; i++) {
				log_Log(_T(" 0x%02x"), recvBuffer[i]);
			}
		}
#endif
	}
#ifdef DEBUG
	log_Log(_T("store_data: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
#endif
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("store_data"), result);
	return result;
}

/**
 * You must track on your won, what channels are open.
 * \param *cardInfo INOUT The OPGP_CARD_INFO structure returned by card_connect().
 * \param channelNumber IN The Logical Channel number to select.
 */
LONG select_channel(OPGP_CARD_INFO *cardInfo, BYTE channelNumber) {
	LONG result;
	LOG_START(_T("select_channel"));
	cardInfo->logicalChannel = channelNumber;
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("select_channel"), result);
	return result;
}

/**
 * For an OPEN command, the channelNumberToClose is ignored.
 * For an CLOSE command, the channelNumberOpened is returned.
 * After closing a Logical Channel the Basic Logical Channel is assumed for the next transmissions.
 * \param *secInfo INOUT The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param *cardInfo INOUT The OPGP_CARD_INFO structure returned by card_connect().
 * \param openClose IN Logical Channel should be opened or closed. See #BYTE GP211_MANAGE_CHANNEL_OPEN.
 * \param channelNumberToClose IN The Logical Channel number to close.
 * \param channelNumberOpened OUT The Logical Channel number opened.
 */
LONG manage_channel(GP211_SECURITY_INFO *secInfo,
					OPGP_CARD_INFO *cardInfo, BYTE openClose, BYTE channelNumberToClose,
					BYTE *channelNumberOpened) {

	LONG result;
	DWORD sendBufferLength;
	DWORD recvBufferLength=3;
	BYTE recvBuffer[3];
	BYTE sendBuffer[5];
	DWORD i=0;
	LOG_START(_T("manage_channel"));
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 0x70;
	sendBuffer[i++] = openClose;
	if (openClose == GP211_MANAGE_CHANNEL_CLOSE) {
		sendBuffer[i++] = channelNumberToClose;
	}
	else {
		sendBuffer[i++] = 0x00;
		sendBuffer[i++] = 0x00;
	}
	sendBufferLength = i;
#ifdef DEBUG
	log_Log(_T("manage_channel: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}

#endif
	result = send_APDU(*cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("manage_channel: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
#endif
	if (openClose == GP211_MANAGE_CHANNEL_OPEN) {
		*channelNumberOpened = recvBuffer[0];
		cardInfo->logicalChannel = recvBuffer[0];
#ifdef DEBUG
	log_Log(_T("Logical Channel number openend: %d"), *channelNumberOpened);
#endif
	}
	else {
		*channelNumberOpened = 0;
		cardInfo->logicalChannel = 0;
#ifdef DEBUG
	log_Log(_T("Logical Channel closed: %d"), channelNumberToClose);
#endif
	}

	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("manage_channel"), result);
	return result;
}

/**
 * \param errorCode IN The error code.
 * \return OPGP_STRING representation of the error code.
 */
OPGP_STRING stringify_error(DWORD errorCode) {
	static TCHAR strError[256];
	unsigned int strErrorSize = 256;
#ifdef _WIN32
#ifdef _UNICODE
	char str1[256];
	unsigned int str1Size = 256;
#endif
#endif
#ifdef _WIN32
	LPVOID lpMsgBuf;
#endif
	if (errorCode == OPGP_OPENSSL_ERROR) {
		ERR_load_crypto_strings();
#ifdef _WIN32
#ifdef _UNICODE
		ERR_error_string_n(ERR_get_error(), str1, str1Size);
		MultiByteToWideChar(CP_ACP, 0, str1, -1, strError, strErrorSize);
		return strError;
#endif
#else
		ERR_error_string_n(ERR_get_error(), strError, strErrorSize);
		return strError;
#endif
	}
	if (errorCode == OP201_ERROR_MORE_APPLICATION_DATA)
		return _T("More Card Manager, Executable Load File or application data is available.");
	if (errorCode == OP201_ERROR_LOAD_FILE_DAP_NULL)
		return _T("The Load File DAP is NULL.");
	if (errorCode == GP211_ERROR_LOAD_FILE_DATA_BLOCK_HASH_NULL)
		return _T("The Load File Data Block Hash is NULL.");
	if (errorCode == GP211_ERROR_INVALID_SCP)
		return _T("The Secure Channel Protocol is invalid.");
	if (errorCode == GP211_ERROR_INVALID_SCP_IMPL)
		return _T("The Secure Channel Protocol Implementation is invalid.");
	if (errorCode == OPGP_ERROR_COMMAND_TOO_LARGE)
		return _T("The command data is too large.");
	if (errorCode == OPGP_ERROR_UNRECOGNIZED_APDU_COMMAND)
		return _T("A APDU command can't be recognized as a valid T=0 protocol Case 1-4 ISO7816-4 APDU");
	if (errorCode == OPGP_ERROR_CARD_CRYPTOGRAM_VERIFICATION)
		return _T("The verification of the card cryptogram failed.");
	if (errorCode == OPGP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE)
		return _T("The command is too large for secure messaging.");
	if (errorCode == OPGP_ERROR_INSUFFICIENT_BUFFER)
		return _T("A used buffer is too small.");
	if (errorCode == GP211_ERROR_MORE_APPLICATION_DATA)
		return _T("More Issuer Security Domain, Executable Load File, Executable Load Files and Executable Modules or application data is available.");
	if (errorCode == OPGP_ERROR_WRONG_TRY_LIMIT)
		return _T("Wrong maximum try limit.");
	if (errorCode == OPGP_ERROR_WRONG_PIN_LENGTH)
		return _T("Wrong PIN length.");
	if (errorCode == OPGP_ERROR_WRONG_KEY_VERSION)
		return _T("Wrong key version.");
	if (errorCode == OPGP_ERROR_WRONG_KEY_INDEX)
		return _T("Wrong key index.");
	if (errorCode == OPGP_ERROR_WRONG_KEY_TYPE)
		return _T("Wrong key type.");
	if (errorCode == OPGP_ERROR_KEY_CHECK_VALUE)
		return _T("Key check value reported does not match.");
	if (errorCode == OPGP_ERROR_INVALID_COMBINATION_KEY_SET_VERSION_KEY_INDEX)
		return _T("The combination of key set version and key index is invalid.");
	if (errorCode == OPGP_ERROR_MORE_KEY_INFORMATION_TEMPLATES)
		return _T("More key information templates are available.");
	if (errorCode == OPGP_ERROR_APPLICATION_TOO_BIG)
		return _T("The application to load must be less than 32535 bytes.");
	if (errorCode == OPGP_ERROR_VALIDATION_FAILED)
		return _T("A validation has failed.");
	if (errorCode == OPGP_ERROR_INVALID_PASSWORD)
		return _T("A password is invalid.");
	if (errorCode == OPGP_ERROR_WRONG_EXPONENT)
		return _T("The exponent must be 3 or 65537.");
	if ((errorCode & ((DWORD)0xFFFFFF00L)) == OPGP_ISO7816_ERROR_CORRECT_LENGTH) {
        _sntprintf(strError, strErrorSize, _T("Wrong length Le: Exact length: 0x%02lX"),
					errorCode&0x000000ff);
		strError[strErrorSize-1] = _T('\0');
		return strError;
	}
	if ((errorCode & ((DWORD)0xFFFFFF00L)) == OPGP_ISO7816_ERROR_RESPONSE_LENGTH) {
        _sntprintf(strError, strErrorSize, _T("Number of response bytes still available: 0x%02lX"),
					errorCode&0x000000ff);
		strError[strErrorSize-1] = _T('\0');
		return strError;
	}
	if ((errorCode & ((DWORD)0xFFF00000L)) == ((DWORD)0x80200000L)) {
		switch(errorCode) {
// 0x63
			case OPGP_ISO7816_ERROR_HOST_CRYPTOGRAM_VERIFICATION:
				return _T("6300: Authentication of host cryptogram failed.");
			case OPGP_ISO7816_ERROR_MORE_DATA_AVAILABLE:
				return _T("6310: More data available.");
// 0x63

// 0x67
			case OPGP_ISO7816_ERROR_WRONG_LENGTH:
				return _T("6700: Wrong length.");
// 0x67
			case OPGP_ISO7816_ERROR_SECURE_MESSAGING_NOT_SUPPORTED:
				return _T("6882: Function not supported - Secure messaging not supported.");
// 0x69
			case OPGP_ISO7816_ERROR_CONDITIONS_NOT_SATISFIED:
				return _T("6985: Command not allowed - Conditions of use not satisfied.");
			case OPGP_ISO7816_ERROR_NOT_MULTI_SELECTABLE:
				return _T("6985: The application to be selected is not multi-selectable, but its context is already active.");
			case OPGP_ISO7816_ERROR_SELECTION_REJECTED:
				return _T("6999: The application to be selected rejects selection or throws an exception.");
			case OPGP_ISO7816_ERROR_SECURITY_STATUS_NOT_SATISFIED:
				return _T("6982: Command not allowed - Security status not satisfied.");

// 0x69

// 0x6a
			case OPGP_ISO7816_ERROR_WRONG_DATA:
				return _T("6A80: Wrong data / Incorrect values in command data.");
			case OPGP_ISO7816_ERROR_WRONG_GLOBAL_PIN_FORMAT:
				return _T("6A80: Wrong format for global PIN.");

			case OPGP_ISO7816_ERROR_FUNC_NOT_SUPPORTED:
				return _T("6A81: Function not supported.");
			case OPGP_ISO7816_ERROR_APPLET_NOT_SELECTABLE:
				return _T("6A81: Card is locked or selected application was not in a selectable state.");

			case OPGP_ISO7816_ERROR_NOT_ENOUGH_MEMORY:
				return _T("6A84: Not enough memory space.");
			case OPGP_ISO7816_ERROR_INCORRECT_P1P2:
				return _T("6A86: Incorrect parameters (P1, P2).");
			case OPGP_ISO7816_ERROR_WRONG_PIN_TRY_LIMIT:
				return _T("6A86: Wrong parameter P2 (PIN try limit).");
			case OPGP_ISO7816_ERROR_DATA_NOT_FOUND:
				return _T("6A88: Referenced data not found.");

			case OPGP_ISO7816_ERROR_FILE_NOT_FOUND:
				return _T("6A82: File not found.");
			case OPGP_ISO7816_ERROR_APPLET_NOT_FOUND:
				return _T("6A82: The application to be selected could not be found.");
// 0x6a
			case OPGP_ISO7816_ERROR_NOTHING_SPECIFIC:
				return _T("6400: No specific diagnostic.");
// 0x62
			case OPGP_ISO7816_ERROR_FILE_INVALIDATED:
				return _T("6283: Selected file invalidated.");
			case OPGP_ISO7816_WARNING_CM_LOCKED:
				return _T("6283: Card life cycle state is CM_LOCKED.");
			case OPGP_ISO7816_ERROR_FILE_TERMINATED:
				return _T("6285: SELECT FILE Warning: selected file is terminated.");
// 0x62
			case OPGP_ISO7816_ERROR_MEMORY_FAILURE:
				return _T("6581: Memory failure or EDC check failed.");
			case OPGP_ISO7816_ERROR_CHANNEL_NOT_SUPPORTED:
				return _T("6881: Function not supported - Logical channel not supported/open.");
			case OPGP_ISO7816_ERROR_ILLEGAL_PARAMETER:
				return _T("6F74: Illegal parameter.");
			case OPGP_ISO7816_ERROR_WRONG_CLA:
				return _T("6E00: Wrong CLA byte.");
			case OPGP_ISO7816_ERROR_INVALID_INS:
				return _T("6D00: Invalid instruction byte / Command not supported or invalid.");
			case OPGP_ISO7816_ERROR_WRONG_P1P2:
				return _T("6B00: Wrong parameters (P1, P2).");
// 0x94
			case OPGP_ISO7816_ERROR_ALGORITHM_NOT_SUPPORTED:
				return _T("9484: Algorithm not supported.");
			case OPGP_ISO7816_ERROR_INVALID_KEY_CHECK_VALUE:
				return _T("9485: Invalid key check value.");
// 0x94

			default:
                _sntprintf(strError, strErrorSize, _T("Unknown ISO7816 error: 0x%04lX"),
					errorCode&0x0000ffff);
				strError[strErrorSize-1] = _T('\0');
				return strError;
		} // switch(errorCode)
	} // if ((errorCode & ((DWORD)0xFFF00000L)) == ((DWORD)0x80200000L))
	else {
	#ifndef WIN32
		if ((errorCode & ((DWORD)0xFFF00000L)) == ((DWORD)0x80100000L)) {
			return (OPGP_STRING)pcsc_stringify_error((long)errorCode);
		}
	#endif
		switch (errorCode)
		{
			case OPGP_ERROR_SUCCESS:
	#ifdef _WIN32
			default:
				FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
					NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (OPGP_STRING) &lpMsgBuf, 0, NULL);
				if (_tcslen((OPGP_STRING)lpMsgBuf)+1 > strErrorSize ) {
					_tcsncpy(strError, (OPGP_STRING)lpMsgBuf, strErrorSize-1);
					strError[strErrorSize-1] = _T('\0');
				}
				else {
					_tcscpy(strError, (OPGP_STRING)lpMsgBuf);
				}
				LocalFree(lpMsgBuf);
				return strError;
	#else
				return _T("No error.");
			default:
				strerror_r(errorCode, strError, strErrorSize);
				return strError;
	#endif
		}
	}
}

/**
 * The secInfo pointer can also be null and so this function can be used for arbitrary cards.

 * \param capdu IN The command APDU.
 * \param capduLength IN The length of the command APDU.
 * \param rapdu OUT The response APDU.
 * \param rapduLength INOUT The length of the the response APDU.
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param *secInfo IN The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_send_APDU(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
					 PBYTE capdu, DWORD capduLength, PBYTE rapdu, PDWORD rapduLength) {
	LONG result;

	if (secInfo == NULL) {
	    result = send_APDU(cardInfo, NULL, capdu, capduLength, rapdu, rapduLength);
	} else {
	    GP211_SECURITY_INFO gp211secInfo;
	    mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	    result = send_APDU(cardInfo, &gp211secInfo, capdu, capduLength, rapdu, rapduLength);
	    mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	}

	return result;
}

/**
 * A keySetVersion value of 0x00 adds a new key.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version a new key belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param *secInfo INOUT The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param keySetVersion IN An existing key set version.
 * \param keyIndex IN The position of the key in the key set version.
 * \param newKeySetVersion IN The new key set version.
 * \param PEMKeyFileName IN A PEM file name with the public RSA key.
 * \param *passPhrase IN The passphrase. Must be an ASCII string.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_put_rsa_key(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				 BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion,
				 OPGP_STRING PEMKeyFileName, char *passPhrase) {
	LONG result;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	result = put_rsa_key(cardInfo, &gp211secInfo, keySetVersion, keyIndex, newKeySetVersion,
		PEMKeyFileName, passPhrase);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return result;
}

/**
 * A keySetVersion value of 0x00 adds a new key.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version a new key belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param *secInfo INOUT The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param keySetVersion IN An existing key set version.
 * \param keyIndex IN The position of the key in the key set version.
 * \param newKeySetVersion IN The new key set version.
 * \param _3desKey IN The new 3DES key.
 * \param KEK IN The key encryption key (KEK) to encrypt the _3desKey.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_put_3desKey(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				  BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, BYTE _3desKey[16],
				  BYTE KEK[16]) {
	LONG result;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	result = put_3des_key(cardInfo, &gp211secInfo, keySetVersion, keyIndex, newKeySetVersion, _3desKey);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return result;
}

/**
 * A keySetVersion value of 0x00 adds a new secure channel key set.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version a the new secure channel keys belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param *secInfo INOUT The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param keySetVersion IN An existing key set version.
 * \param newKeySetVersion IN The new key set version.
 * \param new_encKey IN The new Encryption key.
 * \param new_macKey IN The new MAC key.
 * \param new_KEK IN The new key encryption key.
 * \param KEK IN The key encryption key (KEK).
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
				  LONG OP201_put_secure_channel_keys(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo, BYTE keySetVersion, BYTE newKeySetVersion, BYTE new_encKey[16], BYTE new_macKey[16], BYTE new_KEK[16], BYTE KEK[16]) {
	LONG result;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	memcpy(gp211secInfo.dataEncryptionSessionKey, KEK, 16);
	result = put_secure_channel_keys(cardInfo, &gp211secInfo, keySetVersion, newKeySetVersion,
		NULL, new_encKey, new_macKey, new_KEK);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return result;
}

/**
 * A keySetVersion value of 0x00 adds a new secure channel key set.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version a the new secure channel keys belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param *secInfo INOUT The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param keySetVersion IN An existing key set version.
 * \param newKeySetVersion IN The new key set version.
 * \param PEMKeyFileName IN A PEM file name with the public RSA key.
 * \param *passPhrase IN The passphrase. Must be an ASCII string.
 * \param receiptGenerationKey IN The new Receipt Generation key.
 * \param KEK IN The key encryption key (KEK).
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_put_delegated_management_keys(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
								   BYTE keySetVersion, BYTE newKeySetVersion,
								   OPGP_STRING PEMKeyFileName, char *passPhrase,
								   BYTE receiptGenerationKey[16], BYTE KEK[16]) {
	LONG result;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	memcpy(gp211secInfo.dataEncryptionSessionKey, KEK, 16);
	result = put_delegated_management_keys(cardInfo, &gp211secInfo, keySetVersion, newKeySetVersion,
		PEMKeyFileName, passPhrase, receiptGenerationKey);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return result;
}

/**
 * If keyIndex is 0x00 all keys within a keySetVersion are deleted.
 * If keySetVersion is 0x00 all keys with the specified keyIndex are deleted.
 * \param *secInfo INOUT The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param keySetVersion IN An existing key set version.
 * \param keyIndex IN An existing key index.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_delete_key(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo, BYTE keySetVersion, BYTE keyIndex) {
	LONG result;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	result = delete_key(cardInfo, &gp211secInfo, keySetVersion, keyIndex);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return result;
}

/**
 * \param *secInfo INOUT The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param AIDs IN A pointer to the an array of OPGP_AID structures describing the applications and load files to delete.
 * \param AIDsLength IN The number of OPGP_AID structures.
 * \param *receiptData OUT A OP201_RECEIPT_DATA array. If the deletion is performed by a
 * security domain with delegated management privilege
 * this structure contains the according data for each deleted application or package.
 * \param receiptDataLength INOUT A pointer to the length of the receiptData array.
 * If no receiptData is available this length is 0;
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_delete_application(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
							  OPGP_AID *AIDs, DWORD AIDsLength, OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataLength) {
	LONG result;
	DWORD i;
	GP211_SECURITY_INFO gp211secInfo;
	GP211_RECEIPT_DATA *gp211receiptData;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	gp211receiptData =
		(GP211_RECEIPT_DATA *)malloc(sizeof(GP211_RECEIPT_DATA)* (*receiptDataLength));

	result = delete_application(cardInfo, &gp211secInfo, AIDs, AIDsLength,
		gp211receiptData, receiptDataLength);
	for (i=0; i<*receiptDataLength; i++) {
		mapGP211ToOP201ReceiptData(gp211receiptData[i], &(receiptData[i]));
	}
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	if (gp211receiptData)
		free(gp211receiptData);
	return result;
}

/**
 * Puts a single card data object identified by identifier.
 * Some cards do not provide some data objects. Some possible identifiers are predefined.
 * See OP201_GET_DATA_ISSUER_BIN. For details about the coding of the dataObject see the programmer's manual
 * of your card.
 * \param identifier IN Two byte buffer with high and low order tag value for identifying card data object.
 * \param dataObject IN The coded data object.
 * \param dataObjectLength IN The length of the data object.
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_put_data(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
					BYTE identifier[2], PBYTE dataObject, DWORD dataObjectLength) {
	LONG result;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	result = put_data(cardInfo, &gp211secInfo, identifier, dataObject, dataObjectLength);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return result;
}

/**
 * Retrieves a single card data object from the card identified by identifier.
 * Some cards do not provide some data objects. Some possible identifiers are predefined.
 * See OP201_GET_DATA_ISSUER_BIN and so on. For details about the coding of the response see the programmer's manual
 * of your card.
 * There is a convenience method get_key_information_templates() to get the key information template(s)
 * containing key set version, key index, key type and key length of the keys.
 * \param identifier IN Two byte buffer with high and low order tag value for identifying card data object.
 * \param recvBuffer IN The buffer for the card data object.
 * \param recvBufferLength IN The length of the received card data object.
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param *secInfo INOUT The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_get_data(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo, BYTE identifier[2], PBYTE recvBuffer, PDWORD recvBufferLength) {
	LONG result;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	result = get_data(cardInfo, &gp211secInfo, identifier, recvBuffer, recvBufferLength);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return result;
}

/**
 * The card must support the optional report of key information templates.
 * \param *secInfo INOUT The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param keyInformationTemplate IN The number of the key information template.
 * \param *keyInformation OUT A pointer to an array of OP201_KEY_INFORMATION structures.
 * \param keyInformationLength INOUT The number of OP201_KEY_INFORMATION structures.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_get_key_information_templates(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
								   BYTE keyInformationTemplate,
								   OP201_KEY_INFORMATION *keyInformation, PDWORD keyInformationLength) {
	LONG result;
	DWORD i;
	GP211_SECURITY_INFO gp211secInfo;
	GP211_KEY_INFORMATION *gp211keyInformation;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	gp211keyInformation =
		(GP211_KEY_INFORMATION *)malloc(sizeof(GP211_KEY_INFORMATION)* (*keyInformationLength));

	result = get_key_information_templates(cardInfo, &gp211secInfo, keyInformationTemplate,
		gp211keyInformation, keyInformationLength);
	for (i=0; i<*keyInformationLength; i++) {
		mapGP211ToOP201KeyInformation(gp211keyInformation[i], &(keyInformation[i]));
	}

	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	if (keyInformation)
		free(keyInformation);
	return result;
}

/**
 *
 * \param *secInfo INOUT The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param cardElement IN Identifier for Load Files, Applications or the Card Manager.
 * \param AID IN The AID.
 * \param AIDLength IN The length of the AID.
 * \param lifeCycleState IN The new life cycle state.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_set_status(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo, BYTE cardElement, PBYTE AID, DWORD AIDLength, BYTE lifeCycleState) {
	LONG result;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	result = set_status(cardInfo, &gp211secInfo, cardElement, AID, AIDLength, lifeCycleState);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return result;
}

/**
 * \param *secInfo INOUT The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param cardElement IN Identifier to retrieve data for Load Files, Applications or the Card Manager.
 * \param *applData OUT The OP201_APPLICATION_DATA structure containing AID, life cycle state and privileges.
 * \param applDataLength INOUT The number of OP201_APPLICATION_DATA passed and returned.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_get_status(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo, BYTE cardElement, OP201_APPLICATION_DATA *applData, PDWORD applDataLength) {
	LONG result;
	DWORD sendBufferLength=8;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[8];
	DWORD j,i=0;
	LOG_START(_T("get_status"));
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xF2;
	sendBuffer[i++] = cardElement;
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 2;
	sendBuffer[i++] = 0x4F;
	sendBuffer[i++] = 0x00;
	sendBuffer[i] = 0x00;
	i=0;
	do {
		recvBufferLength=256;
#ifdef DEBUG
	log_Log(_T("get_status: Data to send: "));
	for (j=0; j<sendBufferLength; j++) {
		log_Log(_T(" 0x%02x"), sendBuffer[j]);
	}

#endif
		result = OP201_send_APDU(cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
		if ( (OPGP_ERROR_SUCCESS != result) && !(result == OPGP_ISO7816_ERROR_MORE_DATA_AVAILABLE)) {
			goto end;
		}
#ifdef DEBUG
	log_Log(_T("get_status: Data: "));
	for (j=0; j<recvBufferLength; j++) {
		log_Log(_T(" 0x%02x"), recvBuffer[j]);
	}

#endif
		for (j=0; j<recvBufferLength-2; ) {
			if (*applDataLength <= i ) {
				{ result = OP201_ERROR_MORE_APPLICATION_DATA; goto end; }
			}
			applData[i].AIDLength = recvBuffer[j++];
			memcpy(applData[i].AID, recvBuffer+j, applData[i].AIDLength);
			j+=applData[i].AIDLength;
			applData[i].lifeCycleState = recvBuffer[j++];
			applData[i].privileges = recvBuffer[j++];
			i++;
		}
		sendBuffer[3]=0x01;
	} while (result == OPGP_ISO7816_ERROR_MORE_DATA_AVAILABLE);

	*applDataLength = i;
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("get_status"), result);
	return result;
}

/**
 * An install_for_load() must precede.
 * The Load File Data Block DAP block(s) must be the same block(s) and in the same order like in calculate_load_file_DAP().
 * If no Load File Data Block DAP blocks are necessary the dapBlock must be NULL and the dapBlockLength 0.
 * \param *secInfo INOUT The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param *dapBlock IN A pointer to OP201_DAP_BLOCK structure(s).
 * \param dapBlockLength IN The number of OP201_DAP_BLOCK structure(s).
 * \param executableLoadFileName IN The name of the CAP file to hash.
 * \param *receiptData OUT If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * Can be validated with validate_load_receipt().
 * \param receiptDataAvailable OUT 0 if no receiptData is availabe.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_load(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				 OP201_DAP_BLOCK *dapBlock, DWORD dapBlockLength, OPGP_STRING executableLoadFileName,
				 OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable) {
	LONG result;
	GP211_SECURITY_INFO gp211secInfo;
	GP211_RECEIPT_DATA gp211receiptData;
	GP211_DAP_BLOCK *gp211dapBlock = NULL;
	DWORD i;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	gp211dapBlock = (GP211_DAP_BLOCK *)malloc(sizeof(GP211_DAP_BLOCK)*dapBlockLength);
	for (i=0; i<dapBlockLength; i++) {
		mapOP201ToGP211DAPBlock(dapBlock[i], &(gp211dapBlock[i]));
	}
	result = load(cardInfo, &gp211secInfo, gp211dapBlock, dapBlockLength,
		executableLoadFileName, &gp211receiptData, receiptDataAvailable);
	if (*receiptDataAvailable)
		mapGP211ToOP201ReceiptData(gp211receiptData, receiptData);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	if (gp211dapBlock)
		free(gp211dapBlock);
	return result;
}

/**
 * The function assumes that the Card Manager or Security Domain
 * uses an optional load file DAP using the SHA-1 message digest algorithm.
 * The loadFileDAP can be calculated using calculate_load_file_DAP() or must be NULL, if the card does not
 * need or support a Load File DAP in this situation, e.g. if you want to load a Executable Load File to the Card
 * Manager Security Domain.
 * In the case of delegated management a Load Token authorizing the INSTALL [for load] must be included.
 * Otherwise loadToken must be NULL. See calculate_load_token().
 * The term Executable Load File is equivalent to the Open Platform term Load File Data Block.
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tags.
 * \param *secInfo INOUT The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param executableLoadFileAID IN A buffer with AID of the Executable Load File to INSTALL [for load].
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param securityDomainAID IN A buffer containing the AID of the intended associated Security Domain.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \param loadFileDAP IN The load file DAP of the Executable Load File to INSTALL [for load].
 * \param loadToken IN The Load Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param nonVolatileCodeSpaceLimit IN The minimum amount of space that must be available to store the package.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_install_for_load(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
					  PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
					  DWORD securityDomainAIDLength, BYTE loadFileDAP[20], BYTE loadToken[128],
					  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
					  DWORD nonVolatileDataSpaceLimit) {
	LONG result;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	result = install_for_load(cardInfo, &gp211secInfo, executableLoadFileAID,
		executableLoadFileAIDLength, securityDomainAID, securityDomainAIDLength,
		loadFileDAP, loadToken, nonVolatileCodeSpaceLimit,
		volatileDataSpaceLimit, nonVolatileDataSpaceLimit);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return result;
}

/**
 * In the case of delegated management an Install Token authorizing the INSTALL [for install] must be included.
 * Otherwise installToken must be NULL. See calculate_install_token().
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tag.
 * For Security domains look in your manual what parameters are necessary.
 * If the tag for application install parameters is mandatory for your card, but you have no install parameters
 * for the install() method of the application anyway you have to use at least a dummy parameter.
 * If AIDWithinLoadFileAID is NULL and AIDWithinLoadFileAIDLength is 0 applicationInstanceAID is assumed for AIDWithinLoadFileAID
 * \param *secInfo INOUT The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param executableLoadFileAID IN A buffer with AID of the Executable Load File to INSTALL [for install].
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param AIDWithinLoadFileAID IN The AID of the application class in the package.
 * \param AIDWithinLoadFileAIDLength IN The length of the AIDWithinLoadFileAID buffer.
 * \param applicationInstanceAID IN The AID of the installed application.
 * \param applicationInstanceAIDLength IN The length of the application instance AID.
 * \param applicationPrivileges IN The application privileges. Can be an OR of multiple privileges. See OP201_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param applicationInstallParameters IN Applet install parameters for the install() method of the application.
 * \param applicationInstallParametersLength IN The length of the applicationInstallParameters buffer.
 * \param installToken IN The Install Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param *receiptData OUT If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * \param receiptDataAvailable OUT 0 if no receiptData is availabe.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_install_for_install(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE AIDWithinLoadFileAID,
						 DWORD AIDWithinLoadFileAIDLength, PBYTE applicationInstanceAID,
						 DWORD applicationInstanceAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE applicationInstallParameters, DWORD applicationInstallParametersLength,
						 BYTE installToken[128], OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable) {
	LONG result;
	GP211_SECURITY_INFO gp211secInfo;
	GP211_RECEIPT_DATA gp211receiptData;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	result = install_for_install(cardInfo, &gp211secInfo, executableLoadFileAID,
		executableLoadFileAIDLength, AIDWithinLoadFileAID, AIDWithinLoadFileAIDLength,
		applicationInstanceAID, applicationInstanceAIDLength,
		applicationPrivileges, volatileDataSpaceLimit, nonVolatileDataSpaceLimit,
		applicationInstallParameters, applicationInstallParametersLength, installToken,
		&gp211receiptData, receiptDataAvailable);
	if (*receiptDataAvailable)
		mapGP211ToOP201ReceiptData(gp211receiptData, receiptData);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return result;
}

/**
 * In the case of delegated management an Install Token authorizing the INSTALL [for install and make selectable] must be included.
 * Otherwise installToken must be NULL. See calculate_install_token().
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tag.
 * For Security domains look in your manual what parameters are necessary.
 * If the tag for application install parameters is mandatory for your card, but you have no install parameters
 * for the install() method of the application anyway you have to use at least a dummy parameter.
 * If AIDWithinLoadFileAID is NULL and AIDWithinLoadFileAIDLength is 0 applicationInstanceAID is assumed for AIDWithinLoadFileAID.
 * \param *secInfo INOUT The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param executableLoadFileAID IN A buffer with AID of the Executable Load File to INSTALL [for install].
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param AIDWithinLoadFileAID IN The AID of the application class in the package.
 * \param AIDWithinLoadFileAIDLength IN The length of the AIDWithinLoadFileAID buffer.
 * \param applicationInstanceAID IN The AID of the installed application.
 * \param applicationInstanceAIDLength IN The length of the application instance AID.
 * \param applicationPrivileges IN The application privileges. Can be an OR of multiple privileges. See OP201_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param applicationInstallParameters IN Applet install parameters for the install() method of the application.
 * \param applicationInstallParametersLength IN The length of the applicationInstallParameters buffer.
 * \param installToken IN The Install Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param *receiptData OUT If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * \param receiptDataAvailable OUT 0 if no receiptData is availabe.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_install_for_install_and_make_selectable(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE AIDWithinLoadFileAID,
						 DWORD AIDWithinLoadFileAIDLength, PBYTE applicationInstanceAID,
						 DWORD applicationInstanceAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE applicationInstallParameters, DWORD applicationInstallParametersLength,
						 BYTE installToken[128], OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable) {
	LONG result;
	GP211_SECURITY_INFO gp211secInfo;
	GP211_RECEIPT_DATA gp211receiptData;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	result = install_for_install_and_make_selectable(cardInfo, &gp211secInfo, executableLoadFileAID,
		executableLoadFileAIDLength, AIDWithinLoadFileAID, AIDWithinLoadFileAIDLength,
		applicationInstanceAID, applicationInstanceAIDLength,
		applicationPrivileges, volatileDataSpaceLimit, nonVolatileDataSpaceLimit,
		applicationInstallParameters, applicationInstallParametersLength, installToken,
		&gp211receiptData, receiptDataAvailable);
	if (*receiptDataAvailable)
		mapGP211ToOP201ReceiptData(gp211receiptData, receiptData);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return result;
}

/**
 * In the case of delegated management an Install Token authorizing the INSTALL [for make selectable] must be included.
 * Otherwise installToken must be NULL.
 * For Security domains look in your manual what parameters are necessary.
 * \param *secInfo INOUT The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param applicationInstanceAID IN The AID of the installed application or security domain.
 * \param applicationInstanceAIDLength IN The length of the application instance AID.
 * \param applicationPrivileges IN The application privileges. Can be an OR of multiple privileges. See OP201_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param installToken IN The Install Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param *receiptData OUT If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * \param receiptDataAvailable OUT 0 if no receiptData is availabe.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_install_for_make_selectable(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
								 PBYTE applicationInstanceAID,
								 DWORD applicationInstanceAIDLength, BYTE applicationPrivileges,
								 BYTE installToken[128], OP201_RECEIPT_DATA *receiptData,
								 PDWORD receiptDataAvailable) {
	LONG result;
	GP211_SECURITY_INFO gp211secInfo;
	GP211_RECEIPT_DATA gp211receiptData;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	result = install_for_make_selectable(cardInfo, &gp211secInfo, applicationInstanceAID, applicationInstanceAIDLength, applicationPrivileges, installToken,
		&gp211receiptData, receiptDataAvailable);
	if (*receiptDataAvailable)
		mapGP211ToOP201ReceiptData(gp211receiptData, receiptData);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return result;
}

/**
 * If you are not the Card Issuer and do not know the token verification private key send this data to the
 * Card Issuer and obtain the RSA signature of the data, i.e. the Install Token.
 * volatileDataSpaceLimit can be 0, if the card does not need or support this tag.
 * The parameters must match the parameters of a later install_for_install() and install_for_make_selectable() method.
 * \param P1 IN The parameter P1 in the APDU command.
 * <ul>
 * <li> 0x04 for a INSTALL [for install] command </li>
 * <li> 0x08 for an INSTALL [for make selectable] command </li>
 * <li> 0x0C for an INSTALL [for install and make selectable] </li>
 * </ul>
 * \param executableLoadFileAID IN A buffer with AID of the Executable Load File to INSTALL [for load].
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param AIDWithinLoadFileAID IN The AID of the application class in the package.
 * \param AIDWithinLoadFileAIDLength IN The length of the AIDWithinLoadFileAID buffer.
 * \param applicationInstanceAID IN The AID of the installed application.
 * \param applicationInstanceAIDLength IN The length of the application instance AID.
 * \param applicationPrivileges IN The application privileges. Can be an OR of multiple privileges. See OP201_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param applicationInstallParameters IN Applet install parameters for the install() method of the application.
 * \param applicationInstallParametersLength IN The length of the applicationInstallParameters buffer.
 * \param installTokenSignatureData OUT The data to sign in a Install Token.
 * \param installTokenSignatureDataLength INOUT The length of the installTokenSignatureData buffer.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_get_install_token_signature_data(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE AIDWithinLoadFileAID,
									  DWORD AIDWithinLoadFileAIDLength, PBYTE applicationInstanceAID,
									  DWORD applicationInstanceAIDLength, BYTE applicationPrivileges,
									  DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
									  PBYTE applicationInstallParameters, DWORD applicationInstallParametersLength,
									  PBYTE installTokenSignatureData, PDWORD installTokenSignatureDataLength) {
	LONG result;
	result = get_install_data(P1, executableLoadFileAID, executableLoadFileAIDLength,
		AIDWithinLoadFileAID, AIDWithinLoadFileAIDLength, applicationInstanceAID,
		applicationInstanceAIDLength, applicationPrivileges, volatileDataSpaceLimit,
		nonVolatileDataSpaceLimit, applicationInstallParameters, applicationInstallParametersLength,
		installTokenSignatureData, installTokenSignatureDataLength);
	return result;
}

/**
 * The parameters must match the parameters of a later install_for_install(), install_for_make_selectable() and install_for_install_and_make_selectable() method.
 * \param P1 IN The parameter P1 in the APDU command.
 * <ul>
 * <li> 0x04 for a INSTALL [for install] command </li>
 * <li> 0x08 for an INSTALL [for make selectable] command </li>
 * <li> 0x0C for an INSTALL [for install and make selectable] </li>
 * </ul>
 * \param executableLoadFileAID IN A buffer with AID of the Executable Load File to INSTALL [for install].
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param AIDWithinLoadFileAID IN The AID of the application class in the package.
 * \param AIDWithinLoadFileAIDLength IN The length of the AIDWithinLoadFileAID buffer.
 * \param applicationInstanceAID IN The AID of the installed application.
 * \param applicationInstanceAIDLength IN The length of the application instance AID.
 * \param applicationPrivileges IN The application privileges. Can be an OR of multiple privileges. See OP201_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param applicationInstallParameters IN Applet install parameters for the install() method of the application.
 * \param applicationInstallParametersLength IN The length of the applicationInstallParameters buffer.
 * \param installToken OUT The calculated Install Token. A 1024 bit RSA signature.
 * \param PEMKeyFileName IN A PEM file name with the private RSA key.
 * \param *passPhrase IN The passphrase. Must be an ASCII string.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_calculate_install_token(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE AIDWithinLoadFileAID,
							 DWORD AIDWithinLoadFileAIDLength, PBYTE applicationInstanceAID, DWORD applicationInstanceAIDLength,
							 BYTE applicationPrivileges, DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
							 PBYTE applicationInstallParameters, DWORD applicationInstallParametersLength,
							 BYTE installToken[128], OPGP_STRING PEMKeyFileName, char *passPhrase) {
	LONG result;
	result = calculate_install_token(P1, executableLoadFileAID, executableLoadFileAIDLength,
		AIDWithinLoadFileAID, AIDWithinLoadFileAIDLength, applicationInstanceAID, applicationInstanceAIDLength,
		applicationPrivileges, volatileDataSpaceLimit, nonVolatileDataSpaceLimit,
		applicationInstallParameters, applicationInstallParametersLength, installToken,
		PEMKeyFileName, passPhrase);
	return result;
}

/**
 * If you are not the Card Issuer and do not know the token verification private key send this data to the
 * Card Issuer and obtain the RSA signature of the data, i.e. the Load Token.
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tags.
 * The parameters must match the parameters of a later install_for_load() command.
 * \param executableLoadFileAID IN A buffer containing the Executable Load File AID.
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param securityDomainAID IN A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \param loadFileDAP IN The Load File DAP. The same calculated as in install_for_load().
 * \param nonVolatileCodeSpaceLimit IN The minimum space required to store the application code.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param loadTokenSignatureData OUT The data to sign in a Load Token.
 * \param loadTokenSignatureDataLength INOUT The length of the loadTokenSignatureData buffer.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_get_load_token_signature_data(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
								   DWORD securityDomainAIDLength, BYTE loadFileDAP[20],
								   DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
								   DWORD nonVolatileDataSpaceLimit, PBYTE loadTokenSignatureData,
								   PDWORD loadTokenSignatureDataLength) {
	unsigned char buf[258];
	DWORD i=0;
#ifdef DEBUG
	DWORD j=0;
#endif
	DWORD hiByte, loByte;
	DWORD staticSize;
	LONG result;
	LOG_START(_T("get_load_token_signature_data"));
	if (loadFileDAP == NULL) {
		result = OP201_ERROR_LOAD_FILE_DAP_NULL;
		goto end;
	}
	buf[i++] = 0x02;
	buf[i++] = 0x00;
	buf[i++] = 0x00; // Lc dummy
	buf[i++] = (BYTE)executableLoadFileAIDLength; // Executable Load File AID
	memcpy(buf+i, executableLoadFileAID, executableLoadFileAIDLength);
	i+=executableLoadFileAIDLength;
	buf[i++] = (BYTE)securityDomainAIDLength; // Security Domain AID
	memcpy(buf+i, securityDomainAID, securityDomainAIDLength);
	i+=securityDomainAIDLength;
	if ((volatileDataSpaceLimit != 0) || (nonVolatileCodeSpaceLimit != 0) ||
(nonVolatileDataSpaceLimit != 0)) {
		buf[i++] = 0x02; // load parameter field
		if (volatileDataSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileDataSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileCodeSpaceLimit != 0)
			buf[i-1] += 4;
		buf[i++] = 0xEF;
		buf[i++] = 0x00;
		if (volatileDataSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileDataSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileCodeSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileCodeSpaceLimit != 0) {
			buf[i++] = 0xC6; // non-volatile code space limit.
			buf[i++] = 0x02; //
			staticSize = 8 - (nonVolatileCodeSpaceLimit % 8) + 8;
            nonVolatileCodeSpaceLimit += staticSize;
			hiByte = nonVolatileCodeSpaceLimit >> 8;
			loByte = nonVolatileCodeSpaceLimit - (hiByte << 8);
			buf[i++] = (BYTE)hiByte; // minimum amount
			buf[i++] = (BYTE)loByte; // of space needed
		}
		if (volatileDataSpaceLimit != 0) {
			buf[i++] = 0xC7;
			buf[i++] = 0x02;
			hiByte = volatileDataSpaceLimit >> 8;
			loByte = volatileDataSpaceLimit - (hiByte << 8);
			buf[i++] = (BYTE)hiByte;
			buf[i++] = (BYTE)loByte;
		}
		if (nonVolatileDataSpaceLimit != 0) {
			buf[i++] = 0xC8;
			buf[i++] = 0x02;
			hiByte = nonVolatileDataSpaceLimit >> 8;
			loByte = nonVolatileDataSpaceLimit - (hiByte << 8);
			buf[i++] = (BYTE)hiByte;
			buf[i++] = (BYTE)loByte;
		}
	}
	else buf[i++] = 0x00;

	/* SHA-1 hash */
	memcpy(buf+i, loadFileDAP, 20);
	i+=20;

	/* Lc - including 128 byte RSA signature length, one more byte for signature length field,
	   minus 3 for P1, P2 and Lc itself
	*/
	buf[2] = (BYTE)i-3+128+1;
	if (i > *loadTokenSignatureDataLength)
		{ result = OPGP_ERROR_INSUFFICIENT_BUFFER; goto end; }
	memcpy(loadTokenSignatureData, buf, i);
	*loadTokenSignatureDataLength = i;
#ifdef DEBUG
	log_Log(_T("get_load_token_signature_data: Gathered data : "));
	log_Log(_T("P1: 0x%02x"), loadTokenSignatureData[j++]);
	log_Log(_T("P2: 0x%02x"), loadTokenSignatureData[j++]);
	log_Log(_T("Lc: 0x%02x"), loadTokenSignatureData[j++]);
	log_Log(_T("Load file AID length indicator: 0x%02x"), loadTokenSignatureData[j++]);
	log_Log(_T("Load file AID:"));
	for (i=0; i<loadTokenSignatureData[j-1]; i++) {
		log_Log(_T(" 0x%02x"), loadTokenSignatureData[j+i]);
	}
	j+=loadTokenSignatureData[j-1];
	log_Log(_T("Security Domain AID length indicator: 0x%02x"), loadTokenSignatureData[j++]);
	log_Log(_T("Security Domain AID:"));
	for (i=0; i<loadTokenSignatureData[j-1]; i++) {
		log_Log(_T(" 0x%02x"), loadTokenSignatureData[j+i]);
	}
	j+=loadTokenSignatureData[j-1];
	log_Log(_T("Load parameters length indicator: 0x%02x"), loadTokenSignatureData[j++]);
	log_Log(_T("Load parameters:"));
	for (i=0; i<loadTokenSignatureData[j-1]; i++) {
		log_Log(_T(" 0x%02x"), loadTokenSignatureData[j+i]);
	}
	j+=loadTokenSignatureData[j-1];
	log_Log(_T("Hash of Load File:"));
	for (i=0; i<20; i++) {
		log_Log(_T(" 0x%02x"), loadTokenSignatureData[j+i]);
	}
	j+=loadTokenSignatureData[j-1];
#endif
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("get_load_token_signature_data"), result);
	return result;
}

/**
 * The parameters must match the parameters of a later install_for_load() method.
 * \param executableLoadFileAID IN A buffer containing the Executable Load File AID.
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param securityDomainAID IN A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \param loadFileDAP IN The Load File DAP. The same calculated as in install_for_load().
 * \param nonVolatileCodeSpaceLimit IN The minimum space required to store the package.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param loadToken OUT The calculated Load Token. A 1024 bit RSA signature.
 * \param PEMKeyFileName IN A PEM file name with the private RSA key.
 * \param *passPhrase IN The passphrase. Must be an ASCII string.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_calculate_load_token(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
						  DWORD securityDomainAIDLength, BYTE loadFileDAP[20],
						  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
						  DWORD nonVolatileDataSpaceLimit, BYTE loadToken[128],
						  OPGP_STRING PEMKeyFileName, char *passPhrase) {
	LONG result;
	BYTE loadTokenSignatureData[256];
	DWORD loadTokenSignatureDataLength = 256;
	LOG_START(_T("calculate_load_token"));
	result = OP201_get_load_token_signature_data(executableLoadFileAID, executableLoadFileAIDLength, securityDomainAID, securityDomainAIDLength,
		loadFileDAP, nonVolatileCodeSpaceLimit, volatileDataSpaceLimit, nonVolatileDataSpaceLimit, loadTokenSignatureData, &loadTokenSignatureDataLength);
	if (result != OPGP_ERROR_SUCCESS) {
		goto end;
	}
	result = calculate_rsa_signature(loadTokenSignatureData, loadTokenSignatureDataLength, PEMKeyFileName,
									passPhrase, loadToken);
	if (result != OPGP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("calculate_load_token"), result);
	return result;
}

/**
 * This is a hash of the Load File with SHA-1.
 * A Load File consists of 0 to n Load File Data Block DAP blocks and a mandatory
 * Load File Data Block, e.g. a CAP file.
 * If no Load File Data Block DAP blocks are necessary the dapBlock must be NULL and the dapBlockLength 0.
 * The dapBlock(s) can be calculated using calculate_3des_dap() or calculate_rsa_dap().
 * If the Load File Data Block DAP block(s) are already calculated they must be parsed into a OP201_DAP_BLOCK structure.
 * If the Load File Data Block DAP block(s) are already prefixing the CAPFile following the Open Platform Specification 2.0.1',
 * the whole CAPFile including the Load File Data Block DAP block(s) is sufficient, the dapBlock must be NULL and the dapBlockLength 0.
 * \param *dapBlock IN A pointer to OP201_DAP_BLOCK structure(s).
 * \param dapBlockLength IN The number of OP201_DAP_BLOCK structure(s).
 * \param executableLoadFileName IN The name of the CAP file to hash.
 * \param hash OUT The hash value.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_calculate_load_file_DAP(OP201_DAP_BLOCK *dapBlock, DWORD dapBlockLength, OPGP_STRING executableLoadFileName,
							 unsigned char hash[20])
{
	LONG result;
	int count;
	DWORD k,j,i;
	unsigned char buf[1024];
	BYTE dapBuf[256];
	DWORD dapBufSize=sizeof(dapBuf);
	FILE *CAPFile = NULL;
	long fileSize = 0;
	EVP_MD_CTX mdctx;
	LOG_START(_T("calculate_load_file_DAP"));
	EVP_MD_CTX_init(&mdctx);
	if ((executableLoadFileName == NULL) || (_tcslen(executableLoadFileName) == 0))
		{ result = OPGP_ERROR_INVALID_FILENAME; goto end; }
	result = EVP_DigestInit_ex(&mdctx, EVP_sha1(), NULL);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
#ifdef DEBUG
	else {
		log_Log(_T("No DAP blocks to hash."));
	}
#endif
	for (i=0; i<dapBlockLength; i++) {
#ifdef DEBUG
		log_Log(_T("Hashing DAP block %lu."), i);
#endif
		j=0;
		k = dapBufSize;
		result = readDAPBlock(dapBuf, &k, dapBlock[i]);
		if (OPGP_ERROR_SUCCESS != result) {
			goto end;
		}
		result = EVP_DigestUpdate(&mdctx, dapBuf, k);
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
	}
	CAPFile = _tfopen(executableLoadFileName, _T("rb"));
	if (CAPFile == NULL) {
		{ result = errno; goto end; }
	}
#ifdef WIN32
	fileSize = _filelength(CAPFile->_file);
#else
	fileSize = fseek(CAPFile, 0, SEEK_END);
	if (fileSize == -1) {
		{ result = errno; goto end; }
	}
	fileSize = ftell(CAPFile);
	fseek(CAPFile, 0, SEEK_SET);
#endif
	if (fileSize == -1L) {
		{ result = errno; goto end; }
	}
	if (fileSize < 128L) {
		buf[0] = 0xC4;
		buf[1] = (BYTE)fileSize;
		count=2;
	}
	else if (fileSize < 256L) {
		buf[0] = 0xC4;
		buf[1] = 0x81;
		buf[2] = (BYTE)fileSize;
		count=3;
	}
	else if (fileSize < 32536L) {
		buf[0] = 0xC4;
		buf[1] = 0x82;
		buf[2] = (BYTE)(fileSize >> 8);
		buf[3] = (BYTE)(fileSize - (buf[2] << 8));
		count=4;
	}
	else {
		{ result = OPGP_ERROR_APPLICATION_TOO_BIG; goto end; }
	}
	/* Hash tag and value field of Load File Data Block */
	result = EVP_DigestUpdate(&mdctx, buf, count);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}

	while(feof(CAPFile) == 0) {
		count = (int)fread(buf, sizeof(unsigned char), sizeof(buf), CAPFile);
		if(ferror(CAPFile)) {
			{ result = errno; goto end; }
		}
		result = EVP_DigestUpdate(&mdctx, buf, count);
		if (result != 1) {
			{ result = errno; goto end; }
		}
	}
	result = EVP_DigestFinal_ex(&mdctx, hash, NULL);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	if (EVP_MD_CTX_cleanup(&mdctx) != 1) {
		{ result = OPGP_OPENSSL_ERROR; }
	}
	if (CAPFile)
		fclose(CAPFile);
	LOG_END(_T("calculate_load_file_DAP"), result);
	return result;
}

/**
 * If a security domain has DAP verification privilege the security domain validates this DAP.
 * \param securityDomainAID IN A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \param executableLoadFileName IN The name of the CAP file to calculate the DAP for.
 * \param DAP_verification_key IN The key to calculate the DAP.
 * \param *dapBlock OUT A pointer to the returned OP201_DAP_BLOCK structure.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_calculate_3des_DAP(PBYTE securityDomainAID, DWORD securityDomainAIDLength, OPGP_STRING executableLoadFileName,
						BYTE DAP_verification_key[16], OP201_DAP_BLOCK *dapBlock)
{
	LONG result;
	int i, count, outl;
	long fileSize;
	unsigned char buf[1024];
	unsigned char des_key[8];
	FILE *CAPFile = NULL;
	EVP_CIPHER_CTX ctx;
	LOG_START(_T("calculate_3des_DAP"));
	EVP_CIPHER_CTX_init(&ctx);
	if ((executableLoadFileName == NULL) || (_tcslen(executableLoadFileName) == 0))
		{ result = OPGP_ERROR_INVALID_FILENAME; goto end; }
// DES CBC mode
	memcpy(des_key, DAP_verification_key+8, 8);
	result = EVP_EncryptInit_ex(&ctx, EVP_des_cbc(), NULL, des_key, icv);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	CAPFile = _tfopen(executableLoadFileName, _T("rb"));
	if (CAPFile == NULL) {
		{ result = errno; goto end; }
	}
#ifdef WIN32
	fileSize = _filelength(CAPFile->_file);
	if (fileSize == -1L) {
		{ result = errno; goto end; }
	}
#else
	fileSize = fseek(CAPFile, 0, SEEK_END);
	if (fileSize == -1) {
		{ result = errno; goto end; }
	}
	fileSize = ftell(CAPFile);
	fseek(CAPFile, 0, SEEK_SET);
#endif
	while(feof(CAPFile) == 0) {
		count = (int)fread(buf, sizeof(unsigned char), sizeof(buf), CAPFile);
		if(ferror(CAPFile)) {
			{ result = errno; goto end; }
		}
		for (i=0; i<count/8; i++) {
			result = EVP_EncryptUpdate(&ctx, dapBlock->signature,
				&outl, buf+i*8, 8);
			if (result != 1) {
				{ result = OPGP_OPENSSL_ERROR; goto end; }
			}
		}
	}
	result = EVP_EncryptFinal_ex(&ctx, dapBlock->signature, &outl);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}

	result = EVP_CIPHER_CTX_cleanup(&ctx);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	EVP_CIPHER_CTX_init(&ctx);
// 3DES CBC mode
	result = EVP_EncryptInit_ex(&ctx, EVP_des_ede_cbc(), NULL, DAP_verification_key, icv);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	if (count%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, dapBlock->signature,
			&outl, buf+i*8, count%8);
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
	}
	result = EVP_EncryptUpdate(&ctx, dapBlock->signature,
		&outl, padding, 8 - (fileSize%8));
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	result = EVP_EncryptFinal_ex(&ctx, dapBlock->signature,
		&outl);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	dapBlock->signatureLength = 8;
	memcpy(dapBlock->securityDomainAID, securityDomainAID, securityDomainAIDLength);
	dapBlock->securityDomainAIDLength = (BYTE)securityDomainAIDLength;

	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	if (EVP_CIPHER_CTX_cleanup(&ctx) != 1) {
		{ result = OPGP_OPENSSL_ERROR; }
	}
	if (CAPFile)
		fclose(CAPFile);
	LOG_END(_T("calculate_3des_DAP"), result);
	return result;
}

/**
 * If a security domain has DAP verification privilege the security domain validates this DAP.
 * \param securityDomainAID IN A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \param executableLoadFileName IN The name of the CAP file to calculate the DAP for.
 * \param PEMKeyFileName IN A PEM file name with the private RSA key.
 * \param *passPhrase IN The passphrase. Must be an ASCII string.
 * \param *dapBlock OUT A pointer to the returned OP201_DAP_BLOCK structure.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_calculate_rsa_DAP(PBYTE securityDomainAID, DWORD securityDomainAIDLength, OPGP_STRING executableLoadFileName,
					   OPGP_STRING PEMKeyFileName, char *passPhrase, OP201_DAP_BLOCK *dapBlock)
{
	LONG result;
	int count;
	unsigned char buf[1024];
	unsigned int signatureLength=0;
	FILE *CAPFile = NULL;
	EVP_PKEY *key = NULL;
	EVP_MD_CTX mdctx;
	FILE *PEMKeyFile = NULL;
	LOG_START(_T("calculate_rsa_DAP"));
	EVP_MD_CTX_init(&mdctx);
	if (passPhrase == NULL)
		{ result = OPGP_ERROR_INVALID_PASSWORD; goto end; }
	if ((executableLoadFileName == NULL) || (_tcslen(executableLoadFileName) == 0))
		{ result = OPGP_ERROR_INVALID_FILENAME; goto end; }
	if ((PEMKeyFileName == NULL) || (_tcslen(PEMKeyFileName) == 0))
		{ result = OPGP_ERROR_INVALID_FILENAME; goto end; }
	PEMKeyFile = _tfopen(PEMKeyFileName, _T("rb"));
	if (PEMKeyFile == NULL) {
		{ result = errno; goto end; }
	}

	key = EVP_PKEY_new();
	if (!PEM_read_PrivateKey(PEMKeyFile, &key, NULL, passPhrase)) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	result = EVP_SignInit_ex(&mdctx, EVP_sha1(), NULL);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}
	CAPFile = _tfopen(executableLoadFileName, _T("rb"));
	if (CAPFile == NULL) {
		{ result = errno; goto end; }
	}
	while(feof(CAPFile) == 0) {
		count = (int)fread(buf, sizeof(unsigned char), sizeof(buf), CAPFile);
		if(ferror(CAPFile)) {
			{ result = errno; goto end; }
		}
		result = EVP_SignUpdate(&mdctx, buf, count);
		if (result != 1) {
			{ result = OPGP_OPENSSL_ERROR; goto end; }
		}
	}

	if (EVP_PKEY_size(key) > 128) {
		{ result = OPGP_ERROR_INSUFFICIENT_BUFFER; goto end; }
	}
	result = EVP_SignFinal(&mdctx, dapBlock->signature, &signatureLength, key);
	if (result != 1) {
		{ result = OPGP_OPENSSL_ERROR; goto end; }
	}

	dapBlock->signatureLength = 128;
	memcpy(dapBlock->securityDomainAID, securityDomainAID, securityDomainAIDLength);
	dapBlock->securityDomainAIDLength = (BYTE)securityDomainAIDLength;

	{ result = OPGP_ERROR_SUCCESS; goto end; }
end:
	if (EVP_MD_CTX_cleanup(&mdctx) != 1) {
		{ result = OPGP_OPENSSL_ERROR; }
	}
	if (PEMKeyFile)
		fclose(PEMKeyFile);
	if (CAPFile)
		fclose(CAPFile);
	if (key)
		EVP_PKEY_free(key);
	LOG_END(_T("calculate_rsa_DAP"), result);
	return result;
}

/**
 * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
 * You may keep track of it. Returns OPGP_ERROR_SUCCESS if receipt is valid.
 * \param confirmationCounter IN The confirmation counter.
 * \param cardUniqueData IN The card unique data (?).
 * \param receiptGenerationKey IN The 3DES key to generate the receipt.
 * \param receiptData IN The OP201_RECEIPT_DATA structure containing the receipt returned
 * from load_application() to verify.
 * \param executableLoadFileAID IN A buffer with AID of the Executable Load File which was INSTALL [for load].
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param securityDomainAID IN A buffer containing the AID of the associated Security Domain.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_validate_load_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receiptGenerationKey[16], OP201_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE securityDomainAID, DWORD securityDomainAIDLength) {
	LONG result;
	GP211_RECEIPT_DATA gp211receiptData;
	mapOP201ToGP211ReceiptData(receiptData, &gp211receiptData);
	result = validate_load_receipt(confirmationCounter, cardUniqueData,
		10, receiptGenerationKey, gp211receiptData, executableLoadFileAID,
		executableLoadFileAIDLength, securityDomainAID, securityDomainAIDLength);
	return result;
}

/**
 * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
 * You may keep track of it. Returns OPGP_ERROR_SUCCESS if receipt is valid.
 * \param confirmationCounter IN The confirmation counter.
 * \param cardUniqueData IN The card unique data (?).
 * \param receiptGenerationKey IN The 3DES key to generate the receipt.
 * \param receiptData IN The OP201_RECEIPT_DATA structure containing the receipt returned
 * from install_for_install() to verify.
 * \param executableLoadFileAID IN A buffer with AID of the Executable Load File which was INSTALL [for install].
 * \param executableLoadFileAIDLength IN The length of the Executable Load File AID.
 * \param applicationInstanceAID IN The AID of the installed application.
 * \param applicationInstanceAIDLength IN The length of the application instance AID.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_validate_install_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receiptGenerationKey[16], OP201_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE applicationInstanceAID, DWORD applicationInstanceAIDLength) {
	LONG result;
	GP211_RECEIPT_DATA gp211receiptData;
	mapOP201ToGP211ReceiptData(receiptData, &gp211receiptData);
	result = validate_install_receipt(confirmationCounter, cardUniqueData,
		10, receiptGenerationKey, gp211receiptData, executableLoadFileAID,
		executableLoadFileAIDLength, applicationInstanceAID, applicationInstanceAIDLength);
	return result;
}

/**
 * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
 * You may keep track of it. Returns OPGP_ERROR_SUCCESS if receipt is valid.
 * \param confirmationCounter IN The confirmation counter.
 * \param cardUniqueData IN The card unique data (?).
 * \param receiptGenerationKey IN The 3DES key to generate the receipt.
 * \param receiptData IN The OP201_RECEIPT_DATA structure containing the receipt returned
 * from delete_application() to verify.
 * \param AID IN A buffer with AID of the application which was deleted.
 * \param AIDLength IN The length of the AID.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_validate_delete_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receiptGenerationKey[16], OP201_RECEIPT_DATA receiptData,
						   PBYTE AID, DWORD AIDLength) {
	LONG result;
	GP211_RECEIPT_DATA gp211receiptData;
	mapOP201ToGP211ReceiptData(receiptData, &gp211receiptData);
	result = validate_delete_receipt(confirmationCounter, cardUniqueData,
		10, receiptGenerationKey, gp211receiptData, AID, AIDLength);
	return result;
}

/**
 * The single numbers of the new PIN are encoded as single BYTEs in the newPIN buffer.
 * The tryLimit must be in the range of 0x03 and x0A.
 * The PIN must comprise at least 6 numbers and not exceeding 12 numbers.
 * To unblock the PIN use tryLimit with a value of 0x00. In this case newPIN buffer and newPINLength are ignored.
 * \param *secInfo INOUT The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param tryLimit IN The try limit for the PIN.
 * \param newPIN IN The new PIN.
 * \param newPINLength IN The length of the new PIN.
 * \param KEK IN The Key Encryption key (KEK).
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_pin_change(OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo, BYTE tryLimit,
				PBYTE newPIN, DWORD newPINLength, BYTE KEK[16]) {
	LONG result;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	memcpy(gp211secInfo.dataEncryptionSessionKey, KEK, 16);
	result = pin_change(cardInfo, &gp211secInfo, tryLimit, newPIN, newPINLength);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return result;
}

/**
 * Reads a DAP block and parses it to the buffer buf.
 * \param buf OUT The buffer.
 * \param bufLength INOUT The length of the buffer and the returned data.
 * \param dapBlock IN The Load File Data Block DAP block.
 * \return OPGP_ERROR_SUCCESS if no error, error code else
 */
static LONG readDAPBlock(PBYTE buf, PDWORD bufLength, OP201_DAP_BLOCK dapBlock) {
	LONG result;
	GP211_DAP_BLOCK gp211dapBlock;
	mapOP201ToGP211DAPBlock(dapBlock, &gp211dapBlock);
	result = readLoadFileDataBlockSignature(buf, bufLength, gp211dapBlock);
	return result;
}

/**
 * A keySetVersion and keyIndex of 0x00 selects the first available key set version and key index.
 * \param encKey IN The static encryption key.
 * \param macKey IN The static MAC key.
 * \param keySetVersion IN The key set version on the card to use for mutual authentication.
 * \param keyIndex IN The key index of the encryption key in the key set version on the card to use for mutual authentication.
 * \param cardInfo IN The OPGP_CARD_INFO cardInfo, structure returned by card_connect().
 * \param securityLevel IN The requested security level.
 * \param *secInfo OUT The returned OP201_SECURITY_INFO structure.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
LONG OP201_mutual_authentication(OPGP_CARD_INFO cardInfo, BYTE encKey[16], BYTE macKey[16],
								 BYTE keySetVersion,
								 BYTE keyIndex, BYTE securityLevel, OP201_SECURITY_INFO *secInfo) {
	LONG result;
	GP211_SECURITY_INFO gp211secInfo;
	result = mutual_authentication(cardInfo, NULL, encKey, macKey, macKey, keySetVersion,
		keyIndex, GP211_SCP01, GP211_SCP01_IMPL_i05, securityLevel, &gp211secInfo);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return result;
}

/**
 * \param enable Enables or disables the trace mode.
 * <ul>
 * <li>#OPGP_TRACE_MODE_ENABLE
 * <li>#OPGP_TRACE_MODE_DISABLE
 * </ul>
 * \param *out The pointer to to FILE to print result.
 */
void enableTraceMode(DWORD enable, FILE *out) {
    if (out == NULL)
 		traceFile = stdout;
    else
 		traceFile = out;
    traceEnable = enable;
}
