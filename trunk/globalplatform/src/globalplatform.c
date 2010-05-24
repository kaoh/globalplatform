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
 * want to use for the command is selected by OPGP_select_application().
 * </p>
 * <h2>Unicode support</h2>
 * <p>
 * Obey that this library supports Unicode. If you develop an application you should use Unicode
 * strings. OPGP_STRING and OPGP_CSTRING are wrapping this for you. Use the <code>LPTSTR</code>, <code>TCHAR</code> and the <code>_T()</code> macro,
 * use Unicode functions and compile your application with the switches UNICODE and _UNICODE in your own code. Under Unixes
 * only ASCII is supported for now but to be portable use the mappings in globalplatform/unicode.h
 * </p>
 *
 */
#ifdef WIN32
#include "stdafx.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include "globalplatform/globalplatform.h"
#ifndef WIN32
#include <sys/stat.h>
#include <string.h>
#endif
#include <errno.h>
#include "globalplatform/debug.h"
#include "unzip/unzip.h"
#include "unzip/zip.h"
#include "util.h"
#include "crypto.h"
#include "loadfile.h"

// 255 bytes minus 8 byte MAC minus 8 byte encryption padding
#define MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING 239

#ifndef MAX_PATH
#define MAX_PATH 257
#endif

static BYTE C_MACDerivationConstant[2] = {0x01, 0x01}; //!< Constant for C-MAC session key calculation.
static BYTE ENCDerivationConstant[2] = {0x01, 0x82};//!< Constant for encryption session key calculation.
static BYTE DEKDerivationConstant[2] = {0x01, 0x81};//!< Constant for data encryption session key calculation.
static BYTE R_MACDerivationConstant[2] = {0x01, 0x02};//!< Constant for R-MAC session key calculation.

OPGP_NO_API
OPGP_ERROR_STATUS calculate_install_token(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
							 PBYTE executableModuleAID,
							 DWORD executableModuleAIDLength, PBYTE applicationAID, DWORD applicationAIDLength,
							 BYTE applicationPrivileges, DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
							 PBYTE installParameters, DWORD installParametersLength,
							 BYTE installToken[128], OPGP_STRING PEMKeyFileName, char *passPhrase);

OPGP_NO_API
OPGP_ERROR_STATUS put_delegated_management_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								   BYTE keySetVersion, BYTE newKeySetVersion,
								   OPGP_STRING PEMKeyFileName, char *passPhrase,
								   BYTE receiptKey[16]);

OPGP_NO_API
OPGP_ERROR_STATUS put_3des_key(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				  BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, BYTE _3DESKey[16]);

OPGP_NO_API
OPGP_ERROR_STATUS put_rsa_key(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion,
				 OPGP_STRING PEMKeyFileName, char *passPhrase);

OPGP_NO_API
OPGP_ERROR_STATUS put_secure_channel_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
							 BYTE keySetVersion,
							 BYTE newKeySetVersion,
							 BYTE newBaseKey[16],
							 BYTE newS_ENC[16],
							 BYTE newS_MAC[16], BYTE newDEK[16]);

OPGP_NO_API
OPGP_ERROR_STATUS delete_key(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE keySetVersion, BYTE keyIndex);

OPGP_NO_API
OPGP_ERROR_STATUS delete_application(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				   OPGP_AID *AIDs, DWORD AIDsLength, GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataLength, DWORD mode);

OPGP_NO_API
OPGP_ERROR_STATUS get_data(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
			  BYTE identifier[2], PBYTE recvBuffer, PDWORD recvBufferLength);

OPGP_NO_API
OPGP_ERROR_STATUS put_data(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE identifier[2], PBYTE dataObject, DWORD dataObjectLength);

OPGP_NO_API
OPGP_ERROR_STATUS get_key_information_templates(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								   BYTE keyInformationTemplate,
								   GP211_KEY_INFORMATION *keyInformation, PDWORD keyInformationLength);

OPGP_NO_API
OPGP_ERROR_STATUS set_status(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE cardElement, PBYTE AID, DWORD AIDLength, BYTE lifeCycleState);

OPGP_NO_API
OPGP_ERROR_STATUS load(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 GP211_DAP_BLOCK *loadFileDataBlockSignature, DWORD loadFileDataBlockSignatureLength,
				 OPGP_STRING executableLoadFileName,
				 GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable, OPGP_PROGRESS_CALLBACK *callback);

OPGP_NO_API
OPGP_ERROR_STATUS install_for_install_and_make_selectable(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE executableModuleAID,
						 DWORD executableModuleAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE installParameters, DWORD installParametersLength,
						 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData,
						 PDWORD receiptDataAvailable);

OPGP_NO_API
OPGP_ERROR_STATUS install_for_load(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
					  PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
					  DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20], BYTE loadToken[128],
					  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
					  DWORD nonVolatileDataSpaceLimit);

OPGP_NO_API
OPGP_ERROR_STATUS install_for_install(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						 PBYTE executableModuleAID,
						 DWORD executableModuleAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE installParameters, DWORD installParametersLength,
						 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable);

OPGP_NO_API
OPGP_ERROR_STATUS install_for_make_selectable(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								 PBYTE applicationAID,
								 DWORD applicationAIDLength, BYTE applicationPrivileges,
								 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData,
								 PDWORD receiptDataAvailable);


OPGP_NO_API
OPGP_ERROR_STATUS pin_change(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE tryLimit,
				PBYTE newPIN, DWORD newPINLength);

OPGP_NO_API
OPGP_ERROR_STATUS mutual_authentication(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, BYTE baseKey[16],
						   BYTE S_ENC[16], BYTE S_MAC[16],
						   BYTE DEK[16], BYTE keySetVersion,
						   BYTE keyIndex, BYTE secureChannelProtocol,
						   BYTE secureChannelProtocolImpl, BYTE securityLevel,
						   BYTE derivationMethod,
						   GP211_SECURITY_INFO *secInfo);

OPGP_NO_API
OPGP_ERROR_STATUS get_install_data(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE executableModuleAID,
									  DWORD executableModuleAIDLength, PBYTE applicationAID,
									  DWORD applicationAIDLength, BYTE applicationPrivileges,
									  DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
									  PBYTE installParameters, DWORD installParametersLength,
									  PBYTE installData, PDWORD installDataLength);

OPGP_NO_API
OPGP_ERROR_STATUS load_from_buffer(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 GP211_DAP_BLOCK *loadFileDataBlockSignature, DWORD loadFileDataBlockSignatureLength,
				 PBYTE loadFileBuf, DWORD loadFileBufSize,
				 GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable, OPGP_PROGRESS_CALLBACK *callback);

OPGP_NO_API
OPGP_ERROR_STATUS VISA2_derive_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, BYTE baseKeyDiversificationData[10], BYTE masterKey[16],
							BYTE S_ENC[16], BYTE S_MAC[16], BYTE DEK[16]);

OPGP_NO_API
OPGP_ERROR_STATUS EMV_CPS11_derive_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, BYTE baseKeyDiversificationData[10], BYTE masterKey[16],
							BYTE S_ENC[16], BYTE S_MAC[16], BYTE DEK[16]);

/**
 * Macro to check for the status word 9000, otherwise the status is set to the error and a jump to the end mark takes place.
 */
#define CHECK_SW_9000(recvBuffer, recvBufferLength, status) if (recvBuffer[recvBufferLength-2] != 0x90 || recvBuffer[recvBufferLength-1] != 0x00) {\
	OPGP_ERROR_CREATE_ERROR(status, status.errorCode, OPGP_stringify_error(status.errorCode)); \
	goto end; \
}

/**
 * ATR for a broken JCOP21 to handle it correctly.
 */
static const BYTE JCOP21V22_ATR[14] = {0x3B, 0x79, 0x18, 0x00, 0x00, 0x4A, 0x43, 0x4F, 0x50, 0x32, 0x31, 0x56, 0x32, 0x32};

OPGP_NO_API
void mapOP201ToGP211SecurityInfo(OP201_SECURITY_INFO op201secInfo,
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
	/* Augusto: added two attributes for key information */
	gp211secInfo->keySetVersion = op201secInfo.keySetVersion;
	gp211secInfo->keyIndex = op201secInfo.keyIndex;
	/* end */

}

OPGP_NO_API
void mapGP211ToOP201SecurityInfo(GP211_SECURITY_INFO gp211secInfo,
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

	/* Augusto: added two attributes for key information */
	op201secInfo->keySetVersion = gp211secInfo.keySetVersion;
	op201secInfo->keyIndex = gp211secInfo.keyIndex;
	/* end */
}

OPGP_NO_API
void mapOP201ToGP211DAPBlock(OP201_DAP_BLOCK op201dapBlock,
										GP211_DAP_BLOCK *gp211dapBlock) {
	if (gp211dapBlock == NULL)
		return;
	gp211dapBlock->securityDomainAIDLength = op201dapBlock.securityDomainAIDLength;
	memcpy(gp211dapBlock->securityDomainAID, op201dapBlock.securityDomainAID, op201dapBlock.securityDomainAIDLength);
	gp211dapBlock->signatureLength = op201dapBlock.signatureLength;
	memcpy(gp211dapBlock->signature, op201dapBlock.signature, op201dapBlock.signatureLength);
}

OPGP_NO_API
void mapGP211ToOP201DAPBlock(GP211_DAP_BLOCK gp211dapBlock,
										OP201_DAP_BLOCK *op201dapBlock) {
	if (op201dapBlock == NULL)
		return;
	op201dapBlock->securityDomainAIDLength = gp211dapBlock.securityDomainAIDLength;
	memcpy(op201dapBlock->securityDomainAID, gp211dapBlock.securityDomainAID, gp211dapBlock.securityDomainAIDLength);
	op201dapBlock->signatureLength = gp211dapBlock.signatureLength;
	memcpy(op201dapBlock->signature, gp211dapBlock.signature, gp211dapBlock.signatureLength);
}

OPGP_NO_API
void mapOP201ToGP211ReceiptData(OP201_RECEIPT_DATA op201receiptData,
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

OPGP_NO_API
void mapGP211ToOP201ReceiptData(GP211_RECEIPT_DATA gp211receiptData,
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

OPGP_NO_API
void mapOP201ToGP211KeyInformation(OP201_KEY_INFORMATION op201keyInformation,
										  GP211_KEY_INFORMATION *gp211keyInformation) {
	if (gp211keyInformation == NULL)
		return;
	gp211keyInformation->keyIndex = op201keyInformation.keyIndex;
	gp211keyInformation->keyLength = op201keyInformation.keyLength;
	gp211keyInformation->keySetVersion = op201keyInformation.keySetVersion;
	gp211keyInformation->keyType = op201keyInformation.keyType;
}

OPGP_NO_API
void mapGP211ToOP201KeyInformation(GP211_KEY_INFORMATION gp211keyInformation,
										  OP201_KEY_INFORMATION *op201keyInformation) {
	if (op201keyInformation == NULL)
		return;
	op201keyInformation->keyIndex = gp211keyInformation.keyIndex;
	op201keyInformation->keyLength = gp211keyInformation.keyLength;
	op201keyInformation->keySetVersion = gp211keyInformation.keySetVersion;
	op201keyInformation->keyType = gp211keyInformation.keyType;
}

OPGP_NO_API
void mapOP201ToGP211ApplicationData(OP201_APPLICATION_DATA op201applData,
										  GP211_APPLICATION_DATA *gp211applData) {
	if (gp211applData == NULL)
		return;
	gp211applData->AIDLength = op201applData.AIDLength;
	memcpy(gp211applData->AID, op201applData.AID, op201applData.AIDLength);
	gp211applData->lifeCycleState = op201applData.lifeCycleState;
	gp211applData->privileges = op201applData.privileges;
}

OPGP_NO_API
void mapGP211ToOP201ApplicationData(GP211_APPLICATION_DATA gp211applData,
										   OP201_APPLICATION_DATA *op201applData) {
	if (op201applData == NULL)
		return;
	op201applData->AIDLength = gp211applData.AIDLength;
	memcpy(op201applData->AID, gp211applData.AID, gp211applData.AIDLength);
	op201applData->lifeCycleState = gp211applData.lifeCycleState;
	op201applData->privileges = gp211applData.privileges;
}

OPGP_NO_API
OPGP_ERROR_STATUS readDAPBlock(PBYTE buf, PDWORD bufLength, OP201_DAP_BLOCK dapBlock);

/**
 * Reads a valid buffer containing a (delete, load, install) receipt and parses it in a GP211_RECEIPT_DATA.
 * \param buf [in] The buffer to parse.
 * \param receiptData [out] The receipt data.
 * \return The number of bytes which were consumed while parsing the buffer.
 */
OPGP_NO_API
DWORD fillReceipt(PBYTE buf, GP211_RECEIPT_DATA *receiptData) {
	DWORD j = 0;
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
	return j;
}

/**
 * The secInfo pointer can also be null and so this function can be used for arbitrary cards.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param capdu [in] The command APDU.
 * \param capduLength [in] The length of the command APDU.
 * \param rapdu [out] The response APDU.
 * \param rapduLength [in, out] The length of the the response APDU.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_send_APDU(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, PBYTE capdu, DWORD capduLength, PBYTE rapdu, PDWORD rapduLength) {
	return OPGP_send_APDU(cardContext, cardInfo, secInfo, capdu, capduLength, rapdu, rapduLength);
}

/**
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param AID [in] The AID.
 * \param AIDLength [in] The length of the AID.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_select_application(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, PBYTE AID, DWORD AIDLength) {
	OPGP_ERROR_STATUS status;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[256];
	DWORD sendBufferLength=256;
	DWORD i=0;
	OPGP_LOG_START(_T("select_application"));
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
	status = OPGP_send_APDU(cardContext, cardInfo, NULL, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_CHECK(status) ) {
		goto end;
	}
	switch (status.errorCode) {
		case OPGP_ISO7816_ERROR_CONDITIONS_NOT_SATISFIED:
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ISO7816_ERROR_NOT_MULTI_SELECTABLE, OPGP_stringify_error(OPGP_ISO7816_ERROR_NOT_MULTI_SELECTABLE)); goto end; }
		case OPGP_ISO7816_ERROR_6999:
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ISO7816_ERROR_SELECTION_REJECTED, OPGP_stringify_error(OPGP_ISO7816_ERROR_SELECTION_REJECTED)); goto end; }
		case OPGP_ISO7816_ERROR_FUNC_NOT_SUPPORTED:
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ISO7816_ERROR_APPLET_NOT_SELECTABLE, OPGP_stringify_error(OPGP_ISO7816_ERROR_APPLET_NOT_SELECTABLE)); goto end; }
		case OPGP_ISO7816_ERROR_FILE_NOT_FOUND:
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ISO7816_ERROR_APPLET_NOT_FOUND, OPGP_stringify_error(OPGP_ISO7816_ERROR_APPLET_NOT_FOUND)); goto end; }
		case OPGP_ISO7816_ERROR_FILE_INVALIDATED:
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ISO7816_WARNING_CM_LOCKED, OPGP_stringify_error(OPGP_ISO7816_WARNING_CM_LOCKED)); goto end; }
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("select_application"), status);
	return status;
}

/**
 * A keySetVersion value of 0x00 adds a new key.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version a new key belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param keySetVersion [in] An existing key set version.
 * \param keyIndex [in] The position of the key in the key set version.
 * \param newKeySetVersion [in] The new key set version.
 * \param PEMKeyFileName [in] A PEM file name with the public RSA key.
 * \param *passPhrase [in] The passphrase. Must be an ASCII string.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_put_rsa_key(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion,
				 OPGP_STRING PEMKeyFileName, char *passPhrase) {
	OPGP_ERROR_STATUS status;
	status = put_rsa_key(cardContext, cardInfo, secInfo, keySetVersion, keyIndex,
						 newKeySetVersion, PEMKeyFileName, passPhrase);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	return status;
}

OPGP_ERROR_STATUS put_rsa_key(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion,
				 OPGP_STRING PEMKeyFileName, char *passPhrase) {
	OPGP_ERROR_STATUS status;
	BYTE sendBuffer[261];
	DWORD sendBufferLength=261;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	DWORD i=0;
	BYTE rsa_modulus[128];
	LONG rsa_exponent;
	OPGP_LOG_START(_T("put_rsa_key"));

	status = read_public_rsa_key(PEMKeyFileName, passPhrase, rsa_modulus, &rsa_exponent);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
        /*
	if (keySetVersion > 0x7f)
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_WRONG_KEY_VERSION, OPGP_stringify_error(OPGP_ERROR_WRONG_KEY_VERSION)); goto end; }
	if ((newKeySetVersion > 0x7f) || (newKeySetVersion < 0x01))
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_WRONG_KEY_VERSION, OPGP_stringify_error(OPGP_ERROR_WRONG_KEY_VERSION)); goto end; }
	if (keyIndex > 0x7f)
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_WRONG_KEY_INDEX, OPGP_stringify_error(OPGP_ERROR_WRONG_KEY_INDEX)); goto end; }
        */
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xD8;
	sendBuffer[i++] = keySetVersion;
	sendBuffer[i++] = keyIndex;
	sendBuffer[i++] = 0; // Lc later calculated
	sendBuffer[i++] = newKeySetVersion;
	// modulus
	sendBuffer[i++] = GP211_KEY_TYPE_RSA_PUB_N;
	sendBuffer[i++] = 0x80; // length of RSA modulus
	memcpy(sendBuffer+i, rsa_modulus, 128); // modulus
	i+=128;
	// key check value
	sendBuffer[i++] = 0;
	// exponent
	sendBuffer[i++] = GP211_KEY_TYPE_RSA_PUB_E;
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
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_WRONG_EXPONENT, OPGP_stringify_error(OPGP_ERROR_WRONG_EXPONENT)); goto end; }
	}
	// key check value
	sendBuffer[i++] = 0;
	sendBuffer[4] = (BYTE)i-5;
	sendBuffer[i++] = 0x00; // Le
	sendBufferLength = i;
	status = OPGP_send_APDU(cardContext, cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("put_rsa_key"), status);
	return status;
}

/**
 * A keySetVersion value of 0x00 adds a new key.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version a new key belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param keySetVersion [in] An existing key set version.
 * \param keyIndex [in] The position of the key in the key set version.
 * \param newKeySetVersion [in] The new key set version.
 * \param _3DESKey [in] The new 3DES key.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_put_3des_key(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				  BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, BYTE _3DESKey[16]) {
	OPGP_ERROR_STATUS status;
	status = put_3des_key(cardContext, cardInfo, secInfo, keySetVersion, keyIndex, newKeySetVersion, _3DESKey);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	return status;
}

OPGP_ERROR_STATUS put_3des_key(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				  BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, BYTE _3DESKey[16]) {
	OPGP_ERROR_STATUS status;
	BYTE sendBuffer[29];
	DWORD sendBufferLength = 29;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE keyCheckValue[3];
	BYTE keyDataField[22];
	DWORD keyDataFieldLength=22;
	DWORD i=0;
	BYTE keyType;
	OPGP_LOG_START(_T("put_3des_key"));
        /*
	if (keySetVersion > 0x7f)
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_WRONG_KEY_VERSION, OPGP_stringify_error(OPGP_ERROR_WRONG_KEY_VERSION)); goto end; }
	if (newKeySetVersion > 0x7f)
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_WRONG_KEY_VERSION, OPGP_stringify_error(OPGP_ERROR_WRONG_KEY_VERSION)); goto end; }
	if (keyIndex > 0x7f)
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_WRONG_KEY_INDEX, OPGP_stringify_error(OPGP_ERROR_WRONG_KEY_INDEX)); goto end; }
        */
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xD8;
	sendBuffer[i++] = keySetVersion;
	sendBuffer[i++] = keyIndex;
	sendBuffer[i++] = 0x17;
	sendBuffer[i++] = newKeySetVersion;

	if (cardInfo.specVersion == OP_201) {
		keyType = OP201_KEY_TYPE_DES_ECB;
	}
	else {
		keyType = GP211_KEY_TYPE_DES;
	}

	status = get_key_data_field(secInfo, _3DESKey, 16, keyType, 1, keyDataField, &keyDataFieldLength, keyCheckValue);
	if ( OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	memcpy(sendBuffer+i, keyDataField, keyDataFieldLength); // key
	i+=keyDataFieldLength;

	sendBuffer[i] = 0x00; // Le

	status = OPGP_send_APDU(cardContext, cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);
	if (memcmp(keyCheckValue, recvBuffer+1, 3) != 0)
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_KEY_CHECK_VALUE, OPGP_stringify_error(OPGP_ERROR_KEY_CHECK_VALUE)); goto end; }
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("put_3des_key"), status);
	return status;
}

OPGP_ERROR_STATUS put_delegated_management_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								   BYTE keySetVersion, BYTE newKeySetVersion,
								   OPGP_STRING PEMKeyFileName, char *passPhrase,
								   BYTE receiptKey[16]) {
	OPGP_ERROR_STATUS status;
	BYTE sendBuffer[261];
	DWORD sendBufferLength=261;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE keyCheckValue[8];

	BYTE keyDataField[22];
	DWORD keyDataFieldLength=22;

	DWORD i=0;
	BYTE token_verification_rsa_modulus[128];
	LONG token_verification_rsa_exponent;
	BYTE keyType;

	OPGP_LOG_START(_T("put_delegated_management_keys"));
	/*
	if (keySetVersion > 0x7f)
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_WRONG_KEY_VERSION, OPGP_stringify_error(OPGP_ERROR_WRONG_KEY_VERSION)); goto end; }
	if (newKeySetVersion > 0x7f)
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_WRONG_KEY_VERSION, OPGP_stringify_error(OPGP_ERROR_WRONG_KEY_VERSION)); goto end; }
	*/
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xD8;
	sendBuffer[i++] = keySetVersion;
	sendBuffer[i++] = 0x01; // put multiple keys starting at index 1
	sendBuffer[i++] = 0x00; // Lc later calculated

	sendBuffer[i++] = newKeySetVersion;

	// read public key
	status = read_public_rsa_key(PEMKeyFileName, passPhrase, token_verification_rsa_modulus, &token_verification_rsa_exponent);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	// Token Verification Key

	sendBuffer[i++] = GP211_KEY_TYPE_RSA_PUB_N; // alghoritm RSA modulus
	sendBuffer[i++] = 0x80; // length of RSA modulus
	memcpy(sendBuffer+i, token_verification_rsa_modulus, 128); // modulus
	i+=128;
	sendBuffer[i++] = 0x00; // no key check value
	sendBuffer[i++] = GP211_KEY_TYPE_RSA_PUB_E; // alghoritm RSA exponent
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
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_WRONG_EXPONENT, OPGP_stringify_error(OPGP_ERROR_WRONG_EXPONENT)); goto end; }
	}
	sendBuffer[i++] = 0x00; // no key check value

	// key type seems to be used different in OP201 and GP211
	if (cardInfo.specVersion == OP_201) {
		keyType = OP201_KEY_TYPE_DES_ECB;
	}
	else {
		keyType = GP211_KEY_TYPE_DES;
	}

	status = get_key_data_field(secInfo, receiptKey, 16, keyType, 1, keyDataField, &keyDataFieldLength, keyCheckValue);
	if ( OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	memcpy(sendBuffer+i, keyDataField, keyDataFieldLength); // key
	i+=keyDataFieldLength;

	// send the stuff

	sendBuffer[4] = (BYTE)i - 5;

	sendBuffer[i++] = 0x00; // Le
	sendBufferLength = i;

	status = OPGP_send_APDU(cardContext, cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);

	if (memcmp(keyCheckValue, recvBuffer+1, 3) != 0)
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_KEY_CHECK_VALUE, OPGP_stringify_error(OPGP_ERROR_KEY_CHECK_VALUE)); goto end; }
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("put_delegated_management_keys"), status);
	return status;
}

/**
 * A keySetVersion value of 0x00 adds a new secure channel key set.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version the new secure channel keys belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * It depends on the supported protocol implementation by the card what keys must be passed as parameters.
 * baseKey must be NULL if the protocol uses 3 Secure Channel Keys
 * (Secure Channel Encryption Key, Secure Channel Message Authentication Code Key and
 * Data Encryption Key) and vice versa.
 * Details about the supported Secure Channel Protocol and its implementation can be
 * obtained by a call to the function get_secure_channel_protocol_details().
 * \param keySetVersion [in] An existing key set version.
 * \param newKeySetVersion [in] The new key set version.
 * \param newBaseKey [in] The new Secure Channel base key.
 * \param newS_ENC [in] The new S-ENC key.
 * \param newS_MAC [in] The new S-MAC key.
 * \param newDEK [in] The new DEK.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_put_secure_channel_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
							 BYTE keySetVersion,
							 BYTE newKeySetVersion, BYTE newBaseKey[16],
							 BYTE newS_ENC[16],
							 BYTE newS_MAC[16], BYTE newDEK[16]) {
	return put_secure_channel_keys(cardContext, cardInfo, secInfo,
							 keySetVersion,
							 newKeySetVersion, newBaseKey, newS_ENC,
							 newS_MAC, newDEK);
}

OPGP_ERROR_STATUS put_secure_channel_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
							 BYTE keySetVersion,
							 BYTE newKeySetVersion, BYTE newBaseKey[16],
							 BYTE newS_ENC[16],
							 BYTE newS_MAC[16], BYTE newDEK[16]) {
	OPGP_ERROR_STATUS status;
	BYTE sendBuffer[73];
	DWORD sendBufferLength=73;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE keyDataField[22];
	DWORD keyDataFieldLength=22;
	BYTE keyCheckValue1[3];
	BYTE keyCheckValue2[3];
	BYTE keyCheckValue3[3];
	DWORD i=0;
	BYTE keyType;
	OPGP_LOG_START(_T("put_secure_channel_keys"));
        /*
	if (keySetVersion > 0x7f)
		{ status = OPGP_ERROR_WRONG_KEY_VERSION; goto end; }
	if (newKeySetVersion > 0x7f)
		{ status = OPGP_ERROR_WRONG_KEY_VERSION; goto end; }
        */
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xD8;
	sendBuffer[i++] = keySetVersion;
	sendBuffer[i++] = 0x81;
	sendBuffer[i++] = 0x43;

	sendBuffer[i++] = newKeySetVersion;
	if (cardInfo.specVersion == OP_201) {
		keyType = OP201_KEY_TYPE_DES_ECB;
	}
	else {
		keyType = GP211_KEY_TYPE_DES;
	}
	/* only Secure Channel base key */
	if (secInfo->secureChannelProtocol == GP211_SCP02 &&
		(secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i04
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i14
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0A
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1A
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i54
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i44)) {
		status = get_key_data_field(secInfo, newBaseKey, 16, keyType, 1, keyDataField, &keyDataFieldLength, keyCheckValue1);
		if ( OPGP_ERROR_CHECK(status) ) {
			goto end;
		}
		memcpy(sendBuffer+i, keyDataField, keyDataFieldLength); // key
		i+=keyDataFieldLength;
	}
	else {
		// S-ENC key
		status = get_key_data_field(secInfo, newS_ENC, 16, keyType, 1, keyDataField, &keyDataFieldLength, keyCheckValue1);
		if ( OPGP_ERROR_CHECK(status) ) {
			goto end;
		}
		memcpy(sendBuffer+i, keyDataField, keyDataFieldLength); // key
		i+=keyDataFieldLength;

		// S-MAC key
		status = get_key_data_field(secInfo, newS_MAC, 16, keyType, 1, keyDataField, &keyDataFieldLength, keyCheckValue2);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
		memcpy(sendBuffer+i, keyDataField, keyDataFieldLength); // key
		i+=keyDataFieldLength;

		// DEK
		status = get_key_data_field(secInfo, newDEK, 16, keyType, 1, keyDataField, &keyDataFieldLength, keyCheckValue3);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
		memcpy(sendBuffer+i, keyDataField, keyDataFieldLength); // key
		i+=keyDataFieldLength;
	}
	// send the stuff

	sendBuffer[i++] = 0x00; // Le
	sendBufferLength = i;

	status = OPGP_send_APDU(cardContext, cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);

	/* only Secure Channel base key, so check only first key check value */
	if (secInfo->secureChannelProtocol == GP211_SCP02 &&
		(secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i04
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i14
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0A
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1A
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i54
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i44)) {
		if (memcmp(keyCheckValue1, recvBuffer+1, 3) != 0)
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_KEY_CHECK_VALUE, OPGP_stringify_error(OPGP_ERROR_KEY_CHECK_VALUE)); goto end; }
	}
	else {
		if (memcmp(keyCheckValue1, recvBuffer+1, 3) != 0)
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_KEY_CHECK_VALUE, OPGP_stringify_error(OPGP_ERROR_KEY_CHECK_VALUE)); goto end; }
		if (memcmp(keyCheckValue2, recvBuffer+1+3, 3) != 0)
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_KEY_CHECK_VALUE, OPGP_stringify_error(OPGP_ERROR_KEY_CHECK_VALUE)); goto end; }
		if (memcmp(keyCheckValue3, recvBuffer+1+6, 3) != 0)
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_KEY_CHECK_VALUE, OPGP_stringify_error(OPGP_ERROR_KEY_CHECK_VALUE)); goto end; }
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("put_secure_channel_keys"), status);
	return status;
}

/**
 * A keySetVersion value of 0x00 adds a new secure channel key set.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version a the new secure channel keys belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param keySetVersion [in] An existing key set version.
 * \param newKeySetVersion [in] The new key set version.
 * \param PEMKeyFileName [in] A PEM file name with the public RSA key.
 * \param *passPhrase [in] The passphrase. Must be an ASCII string.
 * \param receiptKey [in] The new Receipt Generation key.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_put_delegated_management_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								   BYTE keySetVersion, BYTE newKeySetVersion,
								   OPGP_STRING PEMKeyFileName, char *passPhrase,
								   BYTE receiptKey[16]) {
	return put_delegated_management_keys(cardContext, cardInfo, secInfo,
								   keySetVersion, newKeySetVersion,
								   PEMKeyFileName, passPhrase,
								   receiptKey);
}

/**
 * If keyIndex is 0xFF (=-1) all keys within a keySetVersion are deleted.
 * If keySetVersion is 0x00 all keys with the specified keyIndex are deleted.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param keySetVersion [in] An existing key set version.
 * \param keyIndex [in] An existing key index.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_delete_key(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE keySetVersion, BYTE keyIndex) {
	return delete_key(cardContext, cardInfo, secInfo, keySetVersion, keyIndex);
}

OPGP_ERROR_STATUS delete_key(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE keySetVersion, BYTE keyIndex) {
	OPGP_ERROR_STATUS status;
	BYTE sendBuffer[255];
	DWORD sendBufferLength;
	DWORD recvBufferLength=3;
	BYTE recvBuffer[3];
	DWORD i=0;
	OPGP_LOG_START(_T("delete_key"));
	if ((keySetVersion == 0x00) && (keyIndex == 0x00))
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_COMBINATION_KEY_SET_VERSION_KEY_INDEX, OPGP_stringify_error(OPGP_ERROR_INVALID_COMBINATION_KEY_SET_VERSION_KEY_INDEX)); goto end; }
	//if (keySetVersion > 0x7f)
	//	{ status = OPGP_ERROR_WRONG_KEY_VERSION; goto end; }
	//if (keyIndex > 0x7f)
	//	{ status = OPGP_ERROR_WRONG_KEY_INDEX; goto end; }
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
	else if (keyIndex == 0xFF) {
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
	sendBuffer[i++] = 0x00; // Le
	sendBufferLength = i;

	status = OPGP_send_APDU(cardContext, cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("delete_key"), status);
	return status;
}

/**
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param AIDs [in] A pointer to the an array of OPGP_AID structures describing the applications and load files to delete.
 * \param AIDsLength [in] The number of OPGP_AID structures.
 * \param *receiptData [out] A GP211_RECEIPT_DATA array. If the deletion is performed by a
 * security domain with delegated management privilege
 * this structure contains the according data for each deleted application or package.
 * \param receiptDataLength [in, out] A pointer to the length of the receiptData array.
 * If no receiptData is available this length is 0;
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_delete_application(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						OPGP_AID *AIDs, DWORD AIDsLength, GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataLength) {
	return delete_application(cardContext, cardInfo, secInfo, AIDs, AIDsLength, receiptData, receiptDataLength, GP_211);
}

/**
* \param mode OpenPlatform 2.0.1' or GlobalPlatform 2.1.1 delete command.
*/
OPGP_ERROR_STATUS delete_application(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				   OPGP_AID *AIDs, DWORD AIDsLength, GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataLength, DWORD mode) {
	OPGP_ERROR_STATUS status;
	DWORD count=0;
	BYTE sendBuffer[261];
	DWORD sendBufferLength;
	DWORD recvBufferLength=255;
	BYTE recvBuffer[255];
	DWORD j,i=0;
	OPGP_LOG_START(_T("delete_application"));
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xE4;
	sendBuffer[i++] = 0x00;
	if (mode == OP_201)
		sendBuffer[i++] = 0x00;
	else
		sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0x00;
	for (j=0; j< AIDsLength; j++) {
		if (i + AIDs[j].AIDLength+2 > 260) {
			*receiptDataLength = 0;
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_COMMAND_TOO_LARGE, OPGP_stringify_error(OPGP_ERROR_COMMAND_TOO_LARGE)); goto end; }
		}
		OPGP_log_Hex(_T("delete_application: AID to delete: "), AIDs[j].AID, AIDs[j].AIDLength);
		sendBuffer[4] += AIDs[j].AIDLength+2;
		sendBuffer[i++] = 0x4F;
		sendBuffer[i++] = AIDs[j].AIDLength;
		memcpy(sendBuffer+i, AIDs[j].AID, AIDs[j].AIDLength);
		i+=AIDs[j].AIDLength;
	}
	sendBuffer[i++] = 0x00;
	sendBufferLength = i;

	status = OPGP_send_APDU(cardContext, cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_CHECK(status)) {
		*receiptDataLength = 0;
		goto end;
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);
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

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("delete_application"), status);
	return status;
}

/**
 * Puts a single card data object identified by identifier.
 * Some cards do not provide some data objects. Some possible identifiers are predefined.
 * See #GP211_GET_DATA_CPLC_WHOLE_CPLC. For details about the coding of the dataObject see the programmer's manual
 * of your card.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param identifier [in] Two byte buffer with high and low order tag value for identifying card data object.
 * \param dataObject [in] The coded data object.
 * \param dataObjectLength [in] The length of the data object.
  * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_put_data(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE identifier[2], PBYTE dataObject, DWORD dataObjectLength) {
	return put_data(cardContext, cardInfo, secInfo, identifier, dataObject, dataObjectLength);
}

OPGP_ERROR_STATUS put_data(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE identifier[2], PBYTE dataObject, DWORD dataObjectLength) {
	OPGP_ERROR_STATUS status;
	BYTE sendBuffer[255];
	DWORD sendBufferLength;
	DWORD recvBufferLength=2;
	BYTE recvBuffer[2];
	DWORD i=0;
	OPGP_LOG_START(_T("put_data"));
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xDA;
	sendBuffer[i++] = identifier[0];
	sendBuffer[i++] = identifier[1];
	sendBuffer[i++] = (BYTE)dataObjectLength;
	memcpy(sendBuffer+i, dataObject, dataObjectLength);
	i+=dataObjectLength;
	sendBufferLength = i;

	status = OPGP_send_APDU(cardContext, cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("put_data"), status);
	return status;
}

/**
 * Retrieves a single card data object from the card identified by identifier.
 * Some cards do not provide some data objects. Some possible identifiers are predefined.
 * See #GP211_GET_DATA_CPLC_WHOLE_CPLC and so on. For details about the coding of the response see the programmer's manual
 * of your card.
 * There is a convenience method get_key_information_templates() to get the key information template(s)
 * containing key set version, key index, key type and key length of the keys.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param identifier [in] Two byte buffer with high and low order tag value for identifying card data object.
 * \param recvBuffer [out] The buffer for the card data object.
 * \param recvBufferLength [in, out] The length of the received card data object.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_get_data(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
			  BYTE identifier[2], PBYTE recvBuffer, PDWORD recvBufferLength) {
				  return get_data(cardContext, cardInfo, secInfo, identifier, recvBuffer, recvBufferLength);
}


/**
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param securityLevel Level of security for all subsequent commands
 * <ul>
 * <li>GP211_SCP02_SECURITY_LEVEL_R_MAC - Each APDU response contains a R-MAC during the session.</li>
 * <li>GP211_SCP02_SECURITY_LEVEL_NO_SECURE_MESSAGING - Only the END R-MAC SESSION response message will contain a R-MAC.</li>
 * </ul>
 * \param data [in] Data for the BEGIN R-MAC SESSION command, e.g. extra challenge.
 * \param dataLength [in] Length of data.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_begin_R_MAC(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE securityLevel, PBYTE data, DWORD dataLength)
{
	OPGP_ERROR_STATUS status;
	BYTE sendBuffer[30];
	DWORD sendBufferLength = 30;
	DWORD i=0;
	DWORD recvBufferLength=2;
	BYTE recvBuffer[2];
	OPGP_LOG_START(_T("GP211_begin_R_MAC"));
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0x7A;
	sendBuffer[i++] = securityLevel;
	sendBuffer[i++] = 1;
	sendBuffer[i++] = (BYTE)(1+dataLength);
	sendBuffer[i++] = (BYTE)dataLength;
	if (dataLength > 24) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_COMMAND_TOO_LARGE, OPGP_stringify_error(OPGP_ERROR_COMMAND_TOO_LARGE));
		goto end;
	}
	memcpy(sendBuffer+i, data, dataLength);
	i+=dataLength;
	sendBufferLength=i;

	status = OPGP_send_APDU(cardContext, cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);
	secInfo->securityLevel |= securityLevel;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("GP211_begin_R_MAC"), status);
	return status;
}

/**
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_end_R_MAC(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo)
{
	OPGP_ERROR_STATUS status;
	BYTE sendBuffer[6];
	DWORD sendBufferLength = 6;
	DWORD i=0;
	DWORD recvBufferLength=2;
	BYTE recvBuffer[2];
	OPGP_LOG_START(_T("GP211_end_R_MAC"));
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0x78;
	sendBuffer[i++] = 0;
	sendBuffer[i++] = 3;
	sendBuffer[i++] = 0; // Le
	/* Switch on, if R-MAC is only applied to last command of session. */
	secInfo->securityLevel |= GP211_SCP02_SECURITY_LEVEL_R_MAC;

	status = OPGP_send_APDU(cardContext, cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);
	secInfo->securityLevel &= ~GP211_SCP02_SECURITY_LEVEL_R_MAC;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("GP211_end_R_MAC"), status);
	return status;
}

OPGP_ERROR_STATUS get_data(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
			  BYTE identifier[2], PBYTE recvBuffer, PDWORD recvBufferLength) {
	OPGP_ERROR_STATUS status;
	BYTE sendBuffer[5];
	DWORD sendBufferLength = 5;
	BYTE cardData[256];
	DWORD cardDataLength = 256;
	DWORD i=0;
	OPGP_LOG_START(_T("get_data"));
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xCA;
	sendBuffer[i++] = identifier[0];
	sendBuffer[i++] = identifier[1];
	sendBuffer[i] = 0x00;

	status = OPGP_send_APDU(cardContext, cardInfo, secInfo, sendBuffer, sendBufferLength, cardData, &cardDataLength);
	if (OPGP_ERROR_CHECK(status)) {
		*recvBufferLength = 0;
		goto end;
	}
	CHECK_SW_9000(cardData, cardDataLength, status);

	if (cardDataLength-2 > *recvBufferLength) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
	}
	memcpy(recvBuffer, cardData, cardDataLength-2);
	*recvBufferLength = cardDataLength-2;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("get_data"), status);
	return status;
}

/**
 * This command is useful to return the Card Data with identifier 0x0066 containing the
 * Card Recognition Data with tag 0x73 containing among others
 * the Secure Channel Protocol and the eventual implementations.
 * For getting the Secure Channel Protocol and Secure Channel Protocol implementation there is the
 * convenience function get_secure_channel_protocol_details().
 * See also data objects identified in ISO 7816-6.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param identifier [in] Two byte buffer with high and low order tag value for identifying card data.
 * \param recvBuffer [out] The buffer for the card data.
 * \param recvBufferLength [in, out] The length of the received card data.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_get_data_iso7816_4(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, BYTE identifier[2], PBYTE recvBuffer,
						PDWORD recvBufferLength) {
	OPGP_ERROR_STATUS status;
	BYTE sendBuffer[5];
	DWORD sendBufferLength = 5;
	BYTE cardData[256];
	DWORD cardDataLength = 256;
	DWORD i=0;
	OPGP_LOG_START(_T("get_data_iso7816-4"));
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 0xCA;
	sendBuffer[i++] = identifier[0];
	sendBuffer[i++] = identifier[1];
	sendBuffer[i] = 0x00;

	status = OPGP_send_APDU(cardContext, cardInfo, NULL, sendBuffer, sendBufferLength, cardData, &cardDataLength);
	if (OPGP_ERROR_CHECK(status)) {
		*recvBufferLength = 0;
		goto end;
	}
	CHECK_SW_9000(cardData, cardDataLength, status);

	if (cardDataLength-2 > *recvBufferLength) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
	}
	memcpy(recvBuffer, cardData, cardDataLength-2);
	*recvBufferLength = cardDataLength-2;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("get_data_iso7816-4"), status);
	return status;
}

/**
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secureChannelProtocol [out] A pointer to the Secure Channel Protocol to use.
 * \param *secureChannelProtocolImpl [out] A pointer to the implementation of the Secure Channel Protocol.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_get_secure_channel_protocol_details(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo,
										 BYTE *secureChannelProtocol, BYTE *secureChannelProtocolImpl) {
	OPGP_ERROR_STATUS status;
	LONG result;
	BYTE recvBuffer[256];
	DWORD recvBufferLength = sizeof(recvBuffer);
	DWORD offset = 0;
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
	TLV tlv1, tlv2, _73tlv;

	OPGP_LOG_START(_T("GP211_get_secure_channel_protocol_details"));
	status = GP211_get_data(cardContext, cardInfo, NULL, (PBYTE)GP211_GET_DATA_CARD_DATA, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	// read outer tag, should be one 0x66
	result = read_TLV(recvBuffer, recvBufferLength, &tlv1);
	if (result == -1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
		goto end;
	}
	// while tag 0x73 not found look into inner tlv objects
	while (tlv1.tag != 0x73) {
		result = read_TLV(tlv1.value, tlv1.length, &tlv2);
		if (result == -1) {
			OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
			goto end;
		}
		tlv1 = tlv2;
	}
	// 0x73 must be found, we parse in expected order
	_73tlv = tlv1;

	/* 0x06 Universal tag for Object Identifier (OID) and Length */
	result = read_TLV(_73tlv.value+offset, _73tlv.length-offset, &tlv1);
	if (result == -1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
		goto end;
	}
	offset += result;

	/* {globalPlatform 1} OID for Card Recognition Data */
	memcpy(OIDCardRecognitionData, tlv1.value, tlv1.length);
	OIDCardRecognitionDataLength = tlv1.length;
#ifdef DEBUG
	OPGP_log_Hex(_T("GP211_get_secure_channel_protocol_details: OIDCardRecognitionData: "), OIDCardRecognitionData, OIDCardRecognitionDataLength);
#endif

	/* Application tag 0 and length */
	result = read_TLV(_73tlv.value+offset, _73tlv.length-offset, &tlv1);
	if (result == -1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
		goto end;
	}
	offset += result;
	/* inner tag: 0x06 Universal tag for �Object Identifier� (OID) and Length */
	result = read_TLV(tlv1.value, tlv1.length, &tlv2);
	if (result == -1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
		goto end;
	}
	/* {globalPlatform 2 v} OID for Card Management Type and Version */
	memcpy(OIDCardManagementTypeAndVersion, tlv2.value, tlv2.length);
	OIDCardManagementTypeAndVersionLength = tlv2.length;
#ifdef DEBUG
	OPGP_log_Hex(_T("GP211_get_secure_channel_protocol_details: OIDCardManagementTypeAndVersion: "), OIDCardManagementTypeAndVersion, OIDCardManagementTypeAndVersionLength);

#endif

	/* Application tag 3 and length */
	result = read_TLV(_73tlv.value+offset, _73tlv.length-offset, &tlv1);
	if (result == -1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
		goto end;
	}
	offset += result;
	/* inner tag: 0x06 Universal tag for �Object Identifier� (OID) and Length */
	result = read_TLV(tlv1.value, tlv1.length, &tlv2);
	if (result == -1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
		goto end;
	}
	/* {globalPlatform 3} OID for Card Identification Scheme */
	memcpy(OIDCardIdentificationScheme, tlv2.value, tlv2.length);
	OIDCardIdentificationSchemeLength = tlv2.length;
#ifdef DEBUG
	OPGP_log_Hex(_T("GP211_get_secure_channel_protocol_details: OIDCardIdentificationScheme: "), OIDCardIdentificationScheme, OIDCardIdentificationSchemeLength);

#endif

	/* Application tag 4 and length */
	result = read_TLV(_73tlv.value+offset, _73tlv.length-offset, &tlv1);
	if (result == -1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
		goto end;
	}
	offset += result;
	/* inner tag: 0x06 Universal tag for �Object Identifier� (OID) and Length */
	result = read_TLV(tlv1.value, tlv1.length, &tlv2);
	if (result == -1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
		goto end;
	}
	/* {globalPlatform 4 scp i} OID for Secure Channel Protocol of
	* the Issuer Security Domain and its implementation options
	*/
	memcpy(OIDSecureChannelProtocol, tlv2.value, tlv2.length);
	OIDSecureChannelProtocolLength = tlv2.length;
#ifdef DEBUG
	OPGP_log_Hex(_T("GP211_get_secure_channel_protocol_details: OIDSecureChannelProtocol: "), OIDSecureChannelProtocol, OIDSecureChannelProtocolLength);

#endif
	*secureChannelProtocol = OIDSecureChannelProtocol[OIDSecureChannelProtocolLength-2];
	*secureChannelProtocolImpl = OIDSecureChannelProtocol[OIDSecureChannelProtocolLength-1];

	/* optional part */

	if (_73tlv.length > offset) {
		/* Application tag 5 and length */
		result = read_TLV(_73tlv.value+offset, _73tlv.length-offset, &tlv1);
		if (result == -1) {
			OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
			goto end;
		}
		offset += result;
		/* Card configuration details */
		memcpy(CardConfigurationDetails, tlv1.value, tlv1.length);
		CardConfigurationDetailsLength = tlv1.length;
#ifdef DEBUG
		OPGP_log_Hex(_T("GP211_get_secure_channel_protocol_details: CardConfigurationDetails: "), CardConfigurationDetails, CardConfigurationDetailsLength);
#endif
	}
	if (_73tlv.length > offset) {
		/* Application tag 6 and length */
		result = read_TLV(_73tlv.value+offset, _73tlv.length-offset, &tlv1);
		if (result == -1) {
			OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
			goto end;
		}
		offset += result;
		/* Card / chip details */
		memcpy(CardChipDetails, tlv1.value, tlv1.length);
		CardChipDetailsLength = tlv1.length;
#ifdef DEBUG
		OPGP_log_Hex(_T("GP211_get_secure_channel_protocol_details: CardChipDetails: "), CardChipDetails, CardChipDetailsLength);
#endif
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("GP211_get_secure_channel_protocol_details"), status);
	return status;
}

/**
 * The card must support the optional report of key information templates.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param keyInformationTemplate [in] The number of the key information template.
 * \param *keyInformation [out] A pointer to an array of GP211_KEY_INFORMATION structures.
 * \param keyInformationLength [in, out] The number of GP211_KEY_INFORMATION structures.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_get_key_information_templates(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								   BYTE keyInformationTemplate,
								   GP211_KEY_INFORMATION *keyInformation, PDWORD keyInformationLength) {
	return get_key_information_templates(cardContext, cardInfo, secInfo,
								   keyInformationTemplate,
								   keyInformation, keyInformationLength);
}

OPGP_ERROR_STATUS get_key_information_templates(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								   BYTE keyInformationTemplate,
								   GP211_KEY_INFORMATION *keyInformation, PDWORD keyInformationLength) {
	OPGP_ERROR_STATUS status;
	BYTE sendBuffer[5];
	DWORD sendBufferLength = 5;
	BYTE cardData[256];
	DWORD cardDataLength = 256;
	DWORD j,i=0;
	OPGP_LOG_START(_T("get_key_information_templates"));
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xCA;
	sendBuffer[i++] = keyInformationTemplate;
	sendBuffer[i++] = 0xE0;
	sendBuffer[i] = 0x00;

	status = OPGP_send_APDU(cardContext, cardInfo, secInfo, sendBuffer, sendBufferLength, cardData, &cardDataLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	CHECK_SW_9000(cardData, cardDataLength, status);

	i=0;
	for (j=4; j<cardDataLength-2; j+=2) {
		// our key information template is actually wrong, it should be able to
		// contain multiple key components
		// another key component follows
		while (cardData[j] != 0xC0 && j<cardDataLength-2) {
			if (*keyInformationLength <= i ) {
				{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_MORE_KEY_INFORMATION_TEMPLATES, OPGP_stringify_error(OPGP_ERROR_MORE_KEY_INFORMATION_TEMPLATES)); goto end; };
			}
			keyInformation[i].keyIndex = cardData[j++];
			keyInformation[i].keySetVersion = cardData[j++];
			keyInformation[i].keyType = cardData[j++];
			keyInformation[i].keyLength = cardData[j++];
			i++;
		}
	}

	*keyInformationLength = i;
#ifdef DEBUG
	for (i=0; i<*keyInformationLength; i++) {
		OPGP_log_Msg(_T("get_key_information_templates: Key index: 0x%02x\n"), keyInformation[i].keyIndex);
		OPGP_log_Msg(_T("get_key_information_templates: Key set version: 0x%02x\n"), keyInformation[i].keySetVersion);
		OPGP_log_Msg(_T("get_key_information_templates: Key type: 0x%02x\n"), keyInformation[i].keyType);
		OPGP_log_Msg(_T("get_key_information_templates: Key length: 0x%02x\n"), keyInformation[i].keyLength);
	}
#endif

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("get_key_information_templates"), status);
	return status;
}

/**
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param cardElement [in] Identifier for Load Files, Applications or the Card Manager.
 * \param AID [in] The AID.
 * \param AIDLength [in] The length of the AID.
 * \param lifeCycleState [in] The new life cycle state.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_set_status(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE cardElement, PBYTE AID, DWORD AIDLength, BYTE lifeCycleState) {
	return set_status(cardContext, cardInfo, secInfo, cardElement, AID, AIDLength, lifeCycleState);
}

OPGP_ERROR_STATUS set_status(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE cardElement, PBYTE AID, DWORD AIDLength, BYTE lifeCycleState) {
	OPGP_ERROR_STATUS status;
	DWORD sendBufferLength=5+AIDLength;
	DWORD recvBufferLength=2;
	BYTE recvBuffer[2];
	BYTE sendBuffer[5+16];
	DWORD i=0;
	OPGP_LOG_START(_T("set_status"));
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xF0;
	sendBuffer[i++] = cardElement;
	sendBuffer[i++] = lifeCycleState;
	sendBuffer[i++] = (BYTE)AIDLength;
	memcpy(sendBuffer+i, AID, AIDLength);
	i+=AIDLength;

	status = OPGP_send_APDU(cardContext, cardInfo, secInfo,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("set_status"), status);
	return status;
}

/**
 * It depends on the card element to retrieve if an array of GP211_APPLICATION_DATA structures
 * or an array of GP211_EXECUTABLE_MODULES_DATA structures must be passed to this function.
 * For the card element #GP211_EXECUTABLE_MODULES_DATA executableData must not
 * be NULL, else applData must not be NULL.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param cardElement [in] Identifier to retrieve data for Load Files, Applications or the Card Manager.
 * See #GP211_STATUS_APPLICATIONS and related.
 * \param *applData [out] The GP211_APPLICATION_DATA structure.
 * \param *executableData [out] The GP211_APPLICATION_DATA structure.
 * \param dataLength [in, out] The number of GP211_APPLICATION_DATA or GP211_EXECUTABLE_MODULES_DATA passed and returned.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_get_status(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE cardElement, GP211_APPLICATION_DATA *applData, GP211_EXECUTABLE_MODULES_DATA *executableData, PDWORD dataLength) {
	OPGP_ERROR_STATUS status;
	DWORD sendBufferLength=8;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[8];
	BYTE numExecutableModules;
	DWORD j=0, k=0, i=0;
	OPGP_LOG_START(_T("get_status"));
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

		status = OPGP_send_APDU(cardContext, cardInfo, secInfo,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
		if ( OPGP_ERROR_CHECK(status)) {
			goto end;
		}
		if (status.errorCode != OPGP_ISO7816_ERROR_MORE_DATA_AVAILABLE) {
			CHECK_SW_9000(recvBuffer, recvBufferLength, status);
		}
		for (j=0; j<recvBufferLength-2; ) {
			if (*dataLength <= i ) {
				{ OPGP_ERROR_CREATE_ERROR(status, GP211_ERROR_MORE_APPLICATION_DATA, OPGP_stringify_error(GP211_ERROR_MORE_APPLICATION_DATA)); goto end; }
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
				for (k=0; k<numExecutableModules && (j<recvBufferLength-2); k++) {
					/* Length of Executable Module AID */
					executableData[i].executableModules[k].AIDLength = recvBuffer[j++];
					/* Executable Module AID */
					memcpy(executableData[i].executableModules[k].AID,
						recvBuffer+j, executableData[i].executableModules[k].AIDLength);
					j+=executableData[i].executableModules[k].AIDLength;
				}
				executableData[i].numExecutableModules = numExecutableModules;
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
	} while (status.errorCode == OPGP_ISO7816_ERROR_MORE_DATA_AVAILABLE);

	*dataLength = i;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("get_status"), status);
	return status;
}

/**
 * If loadFileBuf is NULL the loadFileBufSize is ignored and the necessary buffer size
 * is returned in loadFileBufSize and the functions returns.
 * \param fileName [in] The name of the CAP file.
 * \param loadFileBuf [out] The destination buffer with the Executable Load File contents.
 * \param loadFileBufSize [in, out] The size of the loadFileBuf.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_extract_cap_file(OPGP_CSTRING fileName, PBYTE loadFileBuf, PDWORD loadFileBufSize) {
	return extract_cap_file(fileName, loadFileBuf, loadFileBufSize);
}

/**
 * \param capFileName [in] The name of the CAP file.
 * \param ijcFileName [in] The name of the destination IJC file.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_cap_to_ijc(OPGP_CSTRING capFileName, OPGP_STRING ijcFileName) {
	return cap_to_ijc(capFileName, ijcFileName);
}

/**
 * \param loadFileName [in] The load file name to parse.
 * \param *loadFileParams [out] The parsed parameters.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_read_executable_load_file_parameters(OPGP_STRING loadFileName, OPGP_LOAD_FILE_PARAMETERS *loadFileParams)  {
	return read_executable_load_file_parameters(loadFileName, loadFileParams);
}

/**
 * \param loadFileBuf [in] The load file buffer.
 * \param loadFileBufSize [in] The size of the load file buffer.
 * \param *loadFileParams [out] The parsed parameters.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_read_executable_load_file_parameters_from_buffer(PBYTE loadFileBuf, DWORD loadFileBufSize, OPGP_LOAD_FILE_PARAMETERS *loadFileParams) {
	return read_executable_load_file_parameters_from_buffer(loadFileBuf, loadFileBufSize, loadFileParams);
}

/**
 * An GP211_install_for_load() must precede.
 * The Load File Data Block Signature(s) must be the same block(s) and in the same order like in calculate_load_file_data_block_hash().
 * If no Load File Data Block Signatures are necessary the loadFileDataBlockSignature must be NULL and the loadFileDataBlockSignatureLength 0.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param *loadFileDataBlockSignature [in] A pointer to GP211_DAP_BLOCK structure(s).
 * \param loadFileDataBlockSignatureLength [in] The number of GP211_DAP_BLOCK structure(s).
 * \param executableLoadFileName [in] The name of the CAP or IJC file (Executable Load File) to load.
 * \param *receiptData [out] If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * Can be validated with validate_load_receipt().
 * \param receiptDataAvailable [out] 0 if no receiptData is available.
 * \param *callback [in] An optional callback for measuring the progress. Can be NULL if not needed.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_load(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 GP211_DAP_BLOCK *loadFileDataBlockSignature, DWORD loadFileDataBlockSignatureLength,
				 OPGP_STRING executableLoadFileName,
				 GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable, OPGP_PROGRESS_CALLBACK *callback) {
	return load(cardContext, cardInfo, secInfo,
				 loadFileDataBlockSignature, loadFileDataBlockSignatureLength,
				 executableLoadFileName,
				 receiptData, receiptDataAvailable, callback);
}

/**
 * An GP211_install_for_load() must precede.
 * The Load File Data Block Signature(s) must be the same block(s) and in the same order like in calculate_load_file_data_block_hash().
 * If no Load File Data Block Signatures are necessary the loadFileDataBlockSignature must be NULL and the loadFileDataBlockSignatureLength 0.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param *loadFileDataBlockSignature [in] A pointer to GP211_DAP_BLOCK structure(s).
 * \param loadFileDataBlockSignatureLength [in] The number of GP211_DAP_BLOCK structure(s).
 * \param loadFileBuf [in] buffer with the contents of a Executable Load File.
 * \param loadFileBufSize [in] size of loadFileBuf.
 * \param *receiptData [out] If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * Can be validated with validate_load_receipt().
 * \param receiptDataAvailable [out] 0 if no receiptData is available.
 * \param *callback [in] An optional callback for measuring the progress. Can be NULL if not needed.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_load_from_buffer(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 GP211_DAP_BLOCK *loadFileDataBlockSignature, DWORD loadFileDataBlockSignatureLength,
				 PBYTE loadFileBuf, DWORD loadFileBufSize,
				 GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable, OPGP_PROGRESS_CALLBACK *callback) {
	return load_from_buffer(cardContext, cardInfo, secInfo,
				 loadFileDataBlockSignature, loadFileDataBlockSignatureLength,
				 loadFileBuf, loadFileBufSize,
				 receiptData, receiptDataAvailable, callback);
}

OPGP_ERROR_STATUS load_from_buffer(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 GP211_DAP_BLOCK *loadFileDataBlockSignature, DWORD loadFileDataBlockSignatureLength,
				 PBYTE loadFileBuf, DWORD loadFileBufSize,
				 GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable, OPGP_PROGRESS_CALLBACK *callback) {
	OPGP_ERROR_STATUS status;
	DWORD sendBufferLength;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[261];
	BYTE dapBuf[256];
	DWORD dapBufSize=sizeof(dapBuf);

	DWORD total=0;
	DWORD fileSizeSize;
	DWORD j,k,i=0,count;
	OPGP_PROGRESS_CALLBACK_PARAMETERS callbackParameters;
	BYTE sequenceNumber=0x00;
    INIT_PROGRESS_CALLBACK_PARAMETERS(callbackParameters, callback);
	OPGP_LOG_START(_T("load_from_buffer"));

	*receiptDataAvailable = 0;
	sendBuffer[0] = 0x80;
	sendBuffer[1] = 0xE8;
	j=0;
	for (i=0; i<loadFileDataBlockSignatureLength; i++) {
		k = dapBufSize;
		status = read_load_file_data_block_signature(dapBuf, &k, loadFileDataBlockSignature[i]);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
		if (k > MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING) {
			OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE, OPGP_stringify_error(OPGP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE)); goto end;
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
			// CFlex behavior strange, so commented out
			//sendBufferLength++;
			//sendBuffer[sendBufferLength-1] = 0x00;

			status = OPGP_send_APDU(cardContext, cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
			if (OPGP_ERROR_CHECK(status)) {
				goto end;
			}
			CHECK_SW_9000(recvBuffer, recvBufferLength, status);

			/* Start with new APDU */
			j=0;
			// The current data block i is not sent so must be handled again
			i--;
		}
	}
	// send load file data block

	if (loadFileBufSize < 128L) {
		fileSizeSize=1;
	}
	else if (loadFileBufSize < 256L) {
		fileSizeSize=2;
	}
	else if (loadFileBufSize < 65536L) {
		fileSizeSize=3;
	}
	else {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_APPLICATION_TOO_BIG, OPGP_stringify_error(OPGP_ERROR_APPLICATION_TOO_BIG)); goto end; }
	}
	// load file can only have 256 blocks (minus the already sent blocks)
	// times the maximum APDU size minus the tag and length and the current position in the APDU
	if (((256-sequenceNumber) * MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING - j - 1 - fileSizeSize) < loadFileBufSize) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_APPLICATION_TOO_BIG, OPGP_stringify_error(OPGP_ERROR_APPLICATION_TOO_BIG)); goto end; }
	}

	// Enough space left to start load file data block

	if ((MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING-j) > fileSizeSize+1+1) { // At least one byte of the load file data block must be sent.
		sendBuffer[5+j++] = 0xC4;
		switch(fileSizeSize) {
			case 1: {
				sendBuffer[5+j++] = (BYTE)loadFileBufSize;
					}
			case 2: {
				sendBuffer[5+j++] = 0x81;
				sendBuffer[5+j++] = (BYTE)loadFileBufSize;
					}
			case 3: {
				sendBuffer[5+j++] = 0x82;
				sendBuffer[5+j++] = (BYTE)(loadFileBufSize >> 8);
				sendBuffer[5+j++] = (BYTE)(loadFileBufSize - (sendBuffer[5+j-1] << 8));
					}
		}
		if (loadFileBufSize > MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING-j) {
			count=MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING-j;
		}
		else {
			count=loadFileBufSize;
		}

		memcpy(sendBuffer+5+j, loadFileBuf, count);
		j+=count;
		total+=count;
		sendBufferLength=5+j;
		sendBuffer[2] = 0x00;
		sendBuffer[3] = (BYTE)sequenceNumber++;
		sendBuffer[4]=(BYTE)j;
		if (count == loadFileBufSize) {
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

		status = OPGP_send_APDU(cardContext, cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
		CHECK_SW_9000(recvBuffer, recvBufferLength, status);

		if(callback != NULL) {
			callbackParameters.currentWork = total;
			callbackParameters.totalWork = loadFileBufSize;
			((void(*)(OPGP_PROGRESS_CALLBACK_PARAMETERS))(callback->callback))(callbackParameters);
		}
	}
	// Not enough space to start load file data block. First send data then start load file data block.

	else {
		sendBufferLength=5+j;
		sendBuffer[2] = 0x00;
		sendBuffer[3] = sequenceNumber++;
		sendBuffer[4]=(BYTE)j;
		recvBufferLength=256;

		status = OPGP_send_APDU(cardContext, cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
		CHECK_SW_9000(recvBuffer, recvBufferLength, status);

		j=0;
		sendBuffer[5+j++] = 0xC4;
		switch(fileSizeSize) {
			case 1: {
				sendBuffer[5+j++] = (BYTE)loadFileBufSize;
				}
			case 2: {
				sendBuffer[5+j++] = 0x81;
				sendBuffer[5+j++] = (BYTE)loadFileBufSize;
				}
			case 3: {
				sendBuffer[5+j++] = 0x82;
				sendBuffer[5+j++] = (BYTE)(loadFileBufSize >> 8);
				sendBuffer[5+j++] = (BYTE)(loadFileBufSize - (sendBuffer[5+j-1] << 8));
				}
		}
		if (loadFileBufSize > MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING-1-fileSizeSize) {
			count=MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING-1-fileSizeSize;
		}
		else {
			count=loadFileBufSize;
		}

		memcpy(sendBuffer+5+j, loadFileBuf, count);
		j+=count;
		total+=count;

		sendBufferLength=5+j;
		sendBuffer[2] = 0x00;
		sendBuffer[3] = sequenceNumber++;
		sendBuffer[4]=(BYTE)j;
		if (total == loadFileBufSize) {
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

		status = OPGP_send_APDU(cardContext, cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
		CHECK_SW_9000(recvBuffer, recvBufferLength, status);

		if(callback != NULL) {
			callbackParameters.currentWork = total;
			callbackParameters.totalWork = loadFileBufSize;
			((void(*)(OPGP_PROGRESS_CALLBACK_PARAMETERS))(callback->callback))(callbackParameters);
		}
	}
	// The rest of the load file data block

	while(!(total == loadFileBufSize)) {
		j = 0;
#ifdef DEBUG
		OPGP_log_Msg(_T("load_from_buffer: left: %d"), loadFileBufSize-total);
#endif
		if (loadFileBufSize-total > MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING) {
			count=MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING;
		}
		else {
			count=loadFileBufSize-total;
		}

		memcpy(sendBuffer+5+j, loadFileBuf+total, count);
		j+=count;
		total+=count;

		sendBufferLength=5+j;
		sendBuffer[3] = sequenceNumber++;
		sendBuffer[4] = (BYTE)j;
		if (loadFileBufSize == total) {
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
		status = OPGP_send_APDU(cardContext, cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
		CHECK_SW_9000(recvBuffer, recvBufferLength, status);

		if(callback != NULL) {
			callbackParameters.currentWork = total;
			callbackParameters.totalWork = loadFileBufSize;
			((void(*)(OPGP_PROGRESS_CALLBACK_PARAMETERS))(callback->callback))(callbackParameters);
		}
	}
	if (recvBufferLength > sizeof(GP211_RECEIPT_DATA)) { // assumption that a GP211_RECEIPT_DATA structure is returned in a delegated management deletion
		fillReceipt(recvBuffer, receiptData);
		*receiptDataAvailable = 1;
	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if(callback != NULL) {
		callbackParameters.currentWork = total;
		callbackParameters.totalWork = loadFileBufSize;
		callbackParameters.finished = OPGP_TASK_FINISHED;
		((void(*)(OPGP_PROGRESS_CALLBACK_PARAMETERS))(callback->callback))(callbackParameters);
	}
	OPGP_LOG_END(_T("load_from_buffer"), status);
	return status;

}

OPGP_ERROR_STATUS load(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 GP211_DAP_BLOCK *loadFileDataBlockSignature, DWORD loadFileDataBlockSignatureLength,
				 OPGP_STRING executableLoadFileName,
				 GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable, OPGP_PROGRESS_CALLBACK *callback) {
	OPGP_ERROR_STATUS status;
	PBYTE loadFileBuf = NULL;
	DWORD loadFileBufSize;

	OPGP_LOG_START(_T("load"));

	if ((executableLoadFileName == NULL) || (_tcslen(executableLoadFileName) == 0))
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_FILENAME, OPGP_stringify_error(OPGP_ERROR_INVALID_FILENAME)); goto end; }


	status = handle_load_file((OPGP_CSTRING)executableLoadFileName, loadFileBuf, &loadFileBufSize);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	loadFileBuf = (PBYTE)malloc(sizeof(BYTE) * loadFileBufSize);
	if (loadFileBuf == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
		goto end;
	}
	status = handle_load_file((OPGP_CSTRING)executableLoadFileName, loadFileBuf, &loadFileBufSize);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	status = load_from_buffer(cardContext, cardInfo, secInfo, loadFileDataBlockSignature,
			loadFileDataBlockSignatureLength, loadFileBuf, loadFileBufSize, receiptData, receiptDataAvailable, callback);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if (loadFileBuf) {
		free(loadFileBuf);
	}
	OPGP_LOG_END(_T("load"), status);
	return status;
}

/**
 * The function assumes that the Issuer Security Domain or Security Domain
 * uses an optional Load File Data Block Hash using the SHA-1 message digest algorithm.
 * The loadFileDataBlockHash can be calculated using GP211_calculate_load_file_data_block_hash() or must be NULL, if the card does not
 * need or support a Load File DAP in this situation, e.g. if you want to load a Executable Load File to the Card
 * Manager Security Domain.
 * In the case of delegated management a Load Token authorizing the INSTALL [for load] must be included.
 * Otherwise loadToken must be NULL. See GP211_calculate_load_token().
 * The term Executable Load File is equivalent to the GlobalPlatform term Load File Data Block.
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tags.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param executableLoadFileAID [in] A buffer with AID of the Executable Load File to INSTALL [for load].
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param securityDomainAID [in] A buffer containing the AID of the intended associated Security Domain.
 * \param securityDomainAIDLength [in] The length of the Security Domain AID.
 * \param loadFileDataBlockHash [in] The Load File Data Block Hash of the Executable Load File to INSTALL [for load].
 * \param loadToken [in] The Load Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param nonVolatileCodeSpaceLimit [in] The minimum amount of space that must be available to store the package.
 * \param volatileDataSpaceLimit [in] The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit [in] The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_install_for_load(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
					  PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
					  DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20], BYTE loadToken[128],
					  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
					  DWORD nonVolatileDataSpaceLimit) {
	return install_for_load(cardContext, cardInfo, secInfo,
					  executableLoadFileAID, executableLoadFileAIDLength, securityDomainAID,
					  securityDomainAIDLength, loadFileDataBlockHash, loadToken,
					  nonVolatileCodeSpaceLimit, volatileDataSpaceLimit,
					  nonVolatileDataSpaceLimit);
}

OPGP_ERROR_STATUS install_for_load(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
					  PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
					  DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20], BYTE loadToken[128],
					  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
					  DWORD nonVolatileDataSpaceLimit)
{
	OPGP_ERROR_STATUS status;
	DWORD sendBufferLength = 0;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[261];
	DWORD i=0;
	BYTE buf[256];
	DWORD bufLength = sizeof(buf);
	OPGP_LOG_START(_T("install_for_load"));
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xE6;
	status = get_load_data(executableLoadFileAID, executableLoadFileAIDLength, securityDomainAID,
		securityDomainAIDLength, loadFileDataBlockHash, nonVolatileCodeSpaceLimit, volatileDataSpaceLimit,
		nonVolatileDataSpaceLimit, buf, &bufLength);
	if (OPGP_ERROR_CHECK(status)) {
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

	status = OPGP_send_APDU(cardContext, cardInfo, secInfo,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("install_for_load"), status);
	return status;
}


/**
 * In the case of delegated management an Install Token authorizing the INSTALL [for install] must be included.
 * Otherwise installToken must be NULL. See calculate_install_token().
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tag.
 * For Security domains look in your manual what parameters are necessary.
 * If the tag for application install parameters is mandatory for your card, but you have no install parameters
 * for the install() method of the application anyway you have to use at least a dummy parameter.
 * If executableModuleAID is NULL and executableModuleAIDLength is 0 applicationAID is assumed for executableModuleAID.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param executableLoadFileAID [in] A buffer with AID of the Executable Load File to INSTALL [for install].
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param executableModuleAID [in] The AID of the application class in the package.
 * \param executableModuleAIDLength [in] The length of the executableModuleAID buffer.
 * \param applicationAID [in] The AID of the installed application.
 * \param applicationAIDLength [in] The length of the application instance AID.
 * \param applicationPrivileges [in] The application privileges. Can be an OR of multiple privileges. See #GP211_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit [in] The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit [in] The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param installParameters [in] Applet install parameters for the install() method of the application.
 * \param installParametersLength [in] The length of the installParameters buffer.
 * \param installToken [in] The Install Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param *receiptData [out] If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * \param receiptDataAvailable [out] 0 if no receiptData is available.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_install_for_install(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						 PBYTE executableModuleAID,
						 DWORD executableModuleAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE installParameters, DWORD installParametersLength,
						 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable) {
	return install_for_install(cardContext, cardInfo, secInfo,
						 executableLoadFileAID, executableLoadFileAIDLength,
						 executableModuleAID,
						 executableModuleAIDLength, applicationAID,
						 applicationAIDLength, applicationPrivileges,
						 volatileDataSpaceLimit, nonVolatileDataSpaceLimit,
						 installParameters, installParametersLength,
						 installToken, receiptData, receiptDataAvailable);
}

OPGP_ERROR_STATUS install_for_install(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						 PBYTE executableModuleAID,
						 DWORD executableModuleAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE installParameters, DWORD installParametersLength,
						 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable) {
	OPGP_ERROR_STATUS status;
	DWORD sendBufferLength = 0;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[261];
	DWORD i=0;
	BYTE buf[256];
	DWORD bufLength = sizeof(buf);
	OPGP_LOG_START(_T("install_for_install"));
	*receiptDataAvailable = 0;
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xE6;
	status = get_install_data(0x04, executableLoadFileAID, executableLoadFileAIDLength, executableModuleAID,
		executableModuleAIDLength, applicationAID, applicationAIDLength, applicationPrivileges,
		volatileDataSpaceLimit,	nonVolatileDataSpaceLimit, installParameters,
		installParametersLength, buf, &bufLength);
	if (OPGP_ERROR_CHECK(status)) {
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

	status = OPGP_send_APDU(cardContext, cardInfo, secInfo,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);
	if (recvBufferLength > sizeof(GP211_RECEIPT_DATA)) { // assumption that a GP211_RECEIPT_DATA structure is returned in a delegated management deletion
		fillReceipt(recvBuffer, receiptData);
		*receiptDataAvailable = 1;
	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("install_for_install"), status);
	return status;
}

/**
 * In the case of delegated management an Install Token authorizing the INSTALL [for install and make selectable] must be included.
 * Otherwise installToken must be NULL. See calculate_install_token().
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tag.
 * For Security domains look in your manual what parameters are necessary.
 * If the tag for application install parameters is mandatory for your card, but you have no install parameters
 * for the install() method of the application anyway you have to use at least a dummy parameter.
 * If executableModuleAID is NULL and executableModuleAIDLength is 0 applicationAID is assumed for executableModuleAID.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param executableLoadFileAID [in] A buffer with AID of the Executable Load File to INSTALL [for install].
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param executableModuleAID [in] The AID of the application class in the package.
 * \param executableModuleAIDLength [in] The length of the executableModuleAID buffer.
 * \param applicationAID [in] The AID of the installed application.
 * \param applicationAIDLength [in] The length of the application instance AID.
 * \param applicationPrivileges [in] The application privileges. Can be an OR of multiple privileges. See #GP211_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit [in] The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit [in] The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param installParameters [in] Applet install parameters for the install() method of the application.
 * \param installParametersLength [in] The length of the installParameters buffer.
 * \param installToken [in] The Install Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param *receiptData [out] If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * \param receiptDataAvailable [out] 0 if no receiptData is available.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_install_for_install_and_make_selectable(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE executableModuleAID,
						 DWORD executableModuleAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE installParameters, DWORD installParametersLength,
						 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData,
						 PDWORD receiptDataAvailable) {
	return install_for_install_and_make_selectable(cardContext, cardInfo, secInfo,
						 executableLoadFileAID, executableLoadFileAIDLength, executableModuleAID,
						 executableModuleAIDLength, applicationAID,
						 applicationAIDLength, applicationPrivileges,
						 volatileDataSpaceLimit, nonVolatileDataSpaceLimit,
						 installParameters, installParametersLength,
						 installToken, receiptData,
						 receiptDataAvailable);
}

OPGP_ERROR_STATUS install_for_install_and_make_selectable(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE executableModuleAID,
						 DWORD executableModuleAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE installParameters, DWORD installParametersLength,
						 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData,
						 PDWORD receiptDataAvailable) {
	OPGP_ERROR_STATUS status;
	DWORD sendBufferLength=0;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[261];
	DWORD i=0;
	BYTE buf[256];
	DWORD bufLength = sizeof(buf);
	OPGP_LOG_START(_T("install_for_install_and_make_selectable"));
	*receiptDataAvailable = 0;
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xE6;
	status = get_install_data(0x0C, executableLoadFileAID, executableLoadFileAIDLength, executableModuleAID,
		executableModuleAIDLength, applicationAID, applicationAIDLength, applicationPrivileges,
		volatileDataSpaceLimit,	nonVolatileDataSpaceLimit, installParameters,
		installParametersLength, buf, &bufLength);
	if (OPGP_ERROR_CHECK(status)) {
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
	if (memcmp(JCOP21V22_ATR, cardInfo.ATR, max(cardInfo.ATRLength, sizeof(JCOP21V22_ATR))) != 0) {
		sendBuffer[i++] = 0x00; // Le
	}
	sendBufferLength = i;

	status = OPGP_send_APDU(cardContext, cardInfo, secInfo,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);
	if (recvBufferLength > sizeof(GP211_RECEIPT_DATA)) { // assumption that a GP211_RECEIPT_DATA structure is returned in a delegated management deletion
		fillReceipt(recvBuffer, receiptData);
		*receiptDataAvailable = 1;
	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("install_for_install_and_make_selectable"), status);
	return status;
}

/**
 * In the case of delegated management an Extradition Token authorizing the
 * INSTALL [for extradition] must be included.
 * Otherwise extraditionToken must be NULL. See calculate_install_token().
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param securityDomainAID [in] A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength [in] The length of the Security Domain AID.
 * \param applicationAID [in] The AID of the installed application.
 * \param applicationAIDLength [in] The length of the application instance AID.
GP211_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param extraditionToken [in] The Install Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param *receiptData [out] If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * \param receiptDataAvailable [out] 0 if no receiptData is available.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_install_for_extradition(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
							  PBYTE securityDomainAID,
						 DWORD securityDomainAIDLength, PBYTE applicationAID,
						 DWORD applicationAIDLength,
						 BYTE extraditionToken[128], GP211_RECEIPT_DATA *receiptData,
						 PDWORD receiptDataAvailable) {
	OPGP_ERROR_STATUS status;
	DWORD sendBufferLength=0;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[261];
	DWORD i=0;
	BYTE buf[256];
	DWORD bufLength = sizeof(buf);
	OPGP_LOG_START(_T("install_for_extradition"));
	*receiptDataAvailable = 0;
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xE6;
	status = GP211_get_extradition_token_signature_data(securityDomainAID, securityDomainAIDLength,
		applicationAID, applicationAIDLength,
		buf, &bufLength);
	if (OPGP_ERROR_CHECK(status)) {
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

	status = OPGP_send_APDU(cardContext, cardInfo, secInfo,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);
	if (recvBufferLength > sizeof(GP211_RECEIPT_DATA)) { // assumption that a GP211_RECEIPT_DATA structure is returned in a delegated management deletion
		fillReceipt(recvBuffer, receiptData);
		*receiptDataAvailable = 1;
	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("install_for_extradition"), status);
	return status;
}

/**
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param applicationAID [in] The AID of the installed application.
 * \param applicationAIDLength [in] The length of the application instance AID.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_install_for_personalization(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
						 PBYTE applicationAID,
						 DWORD applicationAIDLength) {
	OPGP_ERROR_STATUS status;
	DWORD sendBufferLength=0;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[261];
	DWORD i=0;

	OPGP_LOG_START(_T("install_for_personalization"));
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

	status = OPGP_send_APDU(cardContext, cardInfo, secInfo,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("install_for_personalization"), status);
	return status;
}

/**
 * In the case of delegated management an Install Token authorizing the INSTALL [for make selectable] must be included.
 * Otherwise installToken must be NULL.
 * For Security domains look in your manual what parameters are necessary.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param applicationAID [in] The AID of the installed application or security domain.
 * \param applicationAIDLength [in] The length of the application instance AID.
 * \param applicationPrivileges [in] The application privileges. Can be an OR of multiple privileges. See #GP211_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param installToken [in] The Install Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param *receiptData [out] If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * \param receiptDataAvailable [out] 0 if no receiptData is available.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_install_for_make_selectable(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								 PBYTE applicationAID,
								 DWORD applicationAIDLength, BYTE applicationPrivileges,
								 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData,
								 PDWORD receiptDataAvailable) {
	return install_for_make_selectable(cardContext, cardInfo, secInfo,
								 applicationAID,
								 applicationAIDLength, applicationPrivileges,
								 installToken, receiptData,
								 receiptDataAvailable);
}

OPGP_ERROR_STATUS install_for_make_selectable(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
								 PBYTE applicationAID,
								 DWORD applicationAIDLength, BYTE applicationPrivileges,
								 BYTE installToken[128], GP211_RECEIPT_DATA *receiptData,
								 PDWORD receiptDataAvailable) {
	OPGP_ERROR_STATUS status;
	DWORD sendBufferLength=0;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[261];
	DWORD i=0;
	OPGP_LOG_START(_T("install_for_make_selectable"));
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
	if (memcmp(JCOP21V22_ATR, cardInfo.ATR, max(cardInfo.ATRLength, sizeof(JCOP21V22_ATR))) != 0) {
		sendBuffer[i++] = 0x00; // Le
	}
	sendBufferLength = i;

	status = OPGP_send_APDU(cardContext, cardInfo, secInfo,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);
	if (recvBufferLength > sizeof(GP211_RECEIPT_DATA)) { // assumption that a GP211_RECEIPT_DATA structure is returned in a delegated management deletion
		fillReceipt(recvBuffer, receiptData);
		*receiptDataAvailable = 1;
	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("install_for_make_selectable"), status);
	return status;
}

/**
 * If you are not the Card Issuer and do not know the token verification private key send this data to the
 * Card Issuer and obtain the RSA signature of the data, i.e. the Install Token.
 * volatileDataSpaceLimit can be 0, if the card does not need or support this tag.
 * The parameters must match the parameters of a later GP211_install_for_install() and GP211_install_for_make_selectable() method.
 * \param P1 [in] The parameter P1 in the APDU command.
 * <ul>
 * <li> 0x04 for a INSTALL [for install] command </li>
 * <li> 0x08 for an INSTALL [for make selectable] command </li>
 * <li> 0x0C for an INSTALL [for install and make selectable] </li>
 * </ul>
 * \param executableLoadFileAID [in] A buffer with AID of the Executable Load File to INSTALL [for load].
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param executableModuleAID [in] The AID of the application class in the package.
 * \param executableModuleAIDLength [in] The length of the executableModuleAID buffer.
 * \param applicationAID [in] The AID of the installed application.
 * \param applicationAIDLength [in] The length of the application instance AID.
 * \param applicationPrivileges [in] The application privileges. Can be an OR of multiple privileges. See #GP211_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit [in] The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit [in] The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param installParameters [in] Applet install parameters for the install() method of the application.
 * \param installParametersLength [in] The length of the installParameters buffer.
 * \param installTokenSignatureData [out] The data to sign in a Install Token.
 * \param installTokenSignatureDataLength [in, out] The length of the installTokenSignatureData buffer.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_get_install_token_signature_data(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE executableModuleAID,
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

OPGP_ERROR_STATUS get_install_data(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE executableModuleAID,
									  DWORD executableModuleAIDLength, PBYTE applicationAID,
									  DWORD applicationAIDLength, BYTE applicationPrivileges,
									  DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
									  PBYTE installParameters, DWORD installParametersLength,
									  PBYTE installData, PDWORD installDataLength) {
	BYTE buf[256];
	DWORD i=0;
	DWORD hiByte, loByte;
	OPGP_ERROR_STATUS status;

	OPGP_LOG_START(_T("get_install_data"));
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

	buf[i++] = 0x02; // install parameter field length
	if (installParametersLength > 0) {
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

	buf[i++] = 0xC9; // application install parameters
	buf[i++] = 0;

    buf[i-1] = (BYTE)installParametersLength;
    memcpy(buf+i, installParameters, installParametersLength);
    i+=installParametersLength;

	if (nonVolatileDataSpaceLimit > 0) {
		buf[i++] = 0xEF;
		buf[i++] = 0x04;
		if (volatileDataSpaceLimit != 0) {
			buf[i-1] += 4; // bug fix from Adriaan De Haan
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
	if (i > *installDataLength) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
	}
	memcpy(installData, buf, i);
	*installDataLength = i;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("get_install_data"), status);
	return status;
}

/**
 * If you are not the Card Issuer and do not know the token verification private key send this data to the
 * Card Issuer and obtain the RSA signature of the data, i.e. the Extradition Token.
 * The parameters must match the parameters of a later GP211_install_for_extradition() method.
 * \param securityDomainAID [in] A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength [in] The length of the Security Domain AID.
 * \param applicationAID [in] The AID of the installed application.
 * \param applicationAIDLength [in] The length of the application instance AID.
 * \param extraditionTokenSignatureData [out] The data to sign in a Install Token.
 * \param extraditionTokenSignatureDataLength [in, out] The length of the installTokenSignatureData buffer.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_get_extradition_token_signature_data(PBYTE securityDomainAID,
										  DWORD securityDomainAIDLength,
										  PBYTE applicationAID, DWORD applicationAIDLength,
										  PBYTE extraditionTokenSignatureData,
										  PDWORD extraditionTokenSignatureDataLength) {
	BYTE buf[258];
	DWORD i=0;
	OPGP_ERROR_STATUS status;

	OPGP_LOG_START(_T("get_extradition_token_signature_data"));
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
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
	memcpy(extraditionTokenSignatureData, buf, i);
	*extraditionTokenSignatureDataLength = i;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("get_extradition_token_signature_data"), status);
	return status;
}

/**
 * The parameters must match the parameters of a later GP211_install_for_install(), GP211_install_for_make_selectable() and GP211_install_for_install_and_make_selectable() method.
 * \param P1 [in] The parameter P1 in the APDU command.
 * <ul>
 * <li> 0x04 for a INSTALL [for install] command </li>
 * <li> 0x08 for an INSTALL [for make selectable] command </li>
 * <li> 0x0C for an INSTALL [for install and make selectable] </li>
 * <li> 0x10 for an INSTALL [for extradiction] </li>
 * </ul>
 * \param executableLoadFileAID [in] A buffer with AID of the Executable Load File to INSTALL [for install].
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param executableModuleAID [in] The AID of the application class in the package.
 * \param executableModuleAIDLength [in] The length of the executableModuleAID buffer.
 * \param applicationAID [in] The AID of the installed application.
 * \param applicationAIDLength [in] The length of the application instance AID.
 * \param applicationPrivileges [in] The application privileges. Can be an OR of multiple privileges. See #GP211_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit [in] The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit [in] The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param installParameters [in] Applet install parameters for the install() method of the application.
 * \param installParametersLength [in] The length of the installParameters buffer.
 * \param installToken [out] The calculated Install Token. A 1024 bit RSA signature.
 * \param PEMKeyFileName [in] A PEM file name with the private RSA key.
 * \param *passPhrase [in] The passphrase. Must be an ASCII string.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_calculate_install_token(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
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

/**
 * If you are not the Card Issuer and do not know the token verification private key send this data to the
 * Card Issuer and obtain the RSA signature of the data, i.e. the Load Token.
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tags.
 * The parameters must match the parameters of a later GP211_install_for_load() command.
 * \param executableLoadFileAID [in] A buffer containing the Executable Load File AID.
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param securityDomainAID [in] A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength [in] The length of the Security Domain AID.
 * \param loadFileDataBlockHash [in] The Load File Data Block Hash. The same calculated as in GP211_install_for_load().
 * \param nonVolatileCodeSpaceLimit [in] The minimum space required to store the application code.
 * \param volatileDataSpaceLimit [in] The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit [in] The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param loadTokenSignatureData [out] The data to sign in a Load Token.
 * \param loadTokenSignatureDataLength [in, out] The length of the loadTokenSignatureData buffer.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_get_load_token_signature_data(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
								   DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20],
								   DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
								   DWORD nonVolatileDataSpaceLimit, PBYTE loadTokenSignatureData,
								   PDWORD loadTokenSignatureDataLength) {
	BYTE buf[258];
	DWORD i=0;
#ifdef DEBUG
	DWORD j=0;
#endif
	DWORD hiByte, loByte;
	DWORD staticSize;
	OPGP_ERROR_STATUS status;
	OPGP_LOG_START(_T("GP211_get_load_token_signature_data"));
	if (loadFileDataBlockHash == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, GP211_ERROR_LOAD_FILE_DATA_BLOCK_HASH_NULL, OPGP_stringify_error(GP211_ERROR_LOAD_FILE_DATA_BLOCK_HASH_NULL));
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
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
	memcpy(loadTokenSignatureData, buf, i);
	*loadTokenSignatureDataLength = i;
#ifdef DEBUG
	OPGP_log_Msg(_T("GP211_get_load_token_signature_data: Reference control parameter P1: 0x%02x"), loadTokenSignatureData[j++]);
	OPGP_log_Msg(_T("GP211_get_load_token_signature_data: Reference control parameter P2: 0x%02x"), loadTokenSignatureData[j++]);
	OPGP_log_Msg(_T("GP211_get_load_token_signature_data: Length of the following fields: 0x%02x"), loadTokenSignatureData[j++]);
	OPGP_log_Msg(_T("GP211_get_load_token_signature_data: Load file AID length: 0x%02x"), loadTokenSignatureData[j++]);
	OPGP_log_Hex(_T("GP211_get_load_token_signature_data: Load file AID: "), loadTokenSignatureData+(j-1), *loadTokenSignatureDataLength-(j-1));

	j+=loadTokenSignatureData[j-1];
	OPGP_log_Msg(_T("GP211_get_load_token_signature_data: Security Domain AID length: 0x%02x"), loadTokenSignatureData[j++]);
	OPGP_log_Hex(_T("GP211_get_load_token_signature_data: Security Domain AID: "), loadTokenSignatureData+(j-1), *loadTokenSignatureDataLength-(j-1));
	j+=loadTokenSignatureData[j-1];
	OPGP_log_Msg(_T("GP211_get_load_token_signature_data: Length of the Load File Data Block Hash: 0x%02x"), loadTokenSignatureData[j++]);
	OPGP_log_Hex(_T("GP211_get_load_token_signature_data: Load File Data Block Hash: "), loadTokenSignatureData+(j-1), *loadTokenSignatureDataLength-(j-1));
	j+=loadTokenSignatureData[j-1];

	OPGP_log_Msg(_T("GP211_get_load_token_signature_data: Load parameters field length: 0x%02x"), loadTokenSignatureData[j++]);
	OPGP_log_Hex(_T("GP211_get_load_token_signature_data: Load parameters field: "), loadTokenSignatureData+(j-1), *loadTokenSignatureDataLength-(j-1));
	j+=loadTokenSignatureData[j-1];

#endif
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("GP211_get_load_token_signature_data"), status);
	return status;
}


/**
 * The parameters must match the parameters of a later GP211_install_for_load() method.
 * \param executableLoadFileAID [in] A buffer containing the Executable Load File AID.
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param securityDomainAID [in] A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength [in] The length of the Security Domain AID.
 * \param loadFileDataBlockHash [in] The Load File DAP. The same calculated as in GP211_install_for_load().
 * \param nonVolatileCodeSpaceLimit [in] The minimum space required to store the package.
 * \param volatileDataSpaceLimit [in] The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit [in] The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param loadToken [out] The calculated Load Token. A 1024 bit RSA signature.
 * \param PEMKeyFileName [in] A PEM file name with the private RSA key.
 * \param *passPhrase [in] The passphrase. Must be an ASCII string.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_calculate_load_token(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						  PBYTE securityDomainAID,
						  DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20],
						  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
						  DWORD nonVolatileDataSpaceLimit, BYTE loadToken[128],
						  OPGP_STRING PEMKeyFileName, char *passPhrase) {
	OPGP_ERROR_STATUS status;
	BYTE loadTokenSignatureData[256];
	DWORD loadTokenSignatureDataLength = 256;
	OPGP_LOG_START(_T("GP211_calculate_load_token"));
	status = GP211_get_load_token_signature_data(executableLoadFileAID, executableLoadFileAIDLength, securityDomainAID, securityDomainAIDLength,
		loadFileDataBlockHash, nonVolatileCodeSpaceLimit, volatileDataSpaceLimit, nonVolatileDataSpaceLimit, loadTokenSignatureData, &loadTokenSignatureDataLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	status = calculate_rsa_signature(loadTokenSignatureData, loadTokenSignatureDataLength, PEMKeyFileName,
									passPhrase, loadToken);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("GP211_calculate_load_token"), status);
	return status;
}

/**
 * This is a hash of the Load File Data Block with SHA-1.
 * \param executableLoadFileName [in] The name of the Executable Load File to hash.
 * \param hash [out] The hash value.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_calculate_load_file_data_block_hash(OPGP_STRING executableLoadFileName,
							 BYTE hash[20]) {
	OPGP_ERROR_STATUS status;
	PBYTE loadFileBuf = NULL;
	DWORD loadFileBufSize;
	OPGP_LOG_START(_T("GP211_calculate_load_file_data_block_hash"));
	if ((executableLoadFileName == NULL) || (_tcslen(executableLoadFileName) == 0))
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_FILENAME, OPGP_stringify_error(OPGP_ERROR_INVALID_FILENAME)); goto end; }
	status = handle_load_file((OPGP_CSTRING)executableLoadFileName, loadFileBuf, &loadFileBufSize);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	loadFileBuf = (PBYTE)malloc(sizeof(BYTE) * loadFileBufSize);
	if (loadFileBuf == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
		goto end;
	}
	status = handle_load_file((OPGP_CSTRING)executableLoadFileName, loadFileBuf, &loadFileBufSize);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	status = calculate_sha1_hash(loadFileBuf, loadFileBufSize, hash);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if (loadFileBuf != NULL) {
		free(loadFileBuf);
	}
	OPGP_LOG_END(_T("GP211_calculate_load_file_data_block_hash"), status);
	return status;
}

/**
 * If a security domain has DAP verification privilege the security domain validates this DAP.
 * The loadFileDataBlockHash can be calculated using calculate_load_file_data_block_hash().
 * \param loadFileDataBlockHash [in] The Load File Data Block Hash.
 * \param securityDomainAID [in] A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength [in] The length of the Security Domain AID.
 * \param DAPCalculationKey [in] The key to calculate the DAP.
 * \param *loadFileDataBlockSignature [out] A pointer to the returned GP211_DAP_BLOCK structure.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_calculate_3des_DAP(BYTE loadFileDataBlockHash[20], PBYTE securityDomainAID,
						DWORD securityDomainAIDLength,
						BYTE DAPCalculationKey[16], GP211_DAP_BLOCK *loadFileDataBlockSignature)
{
	OPGP_ERROR_STATUS status;

	calculate_MAC_des_3des(DAPCalculationKey, loadFileDataBlockHash, 20, NULL,
		loadFileDataBlockSignature->signature);

	loadFileDataBlockSignature->signatureLength = 8;
	memcpy(loadFileDataBlockSignature->securityDomainAID, securityDomainAID, securityDomainAIDLength);
	loadFileDataBlockSignature->securityDomainAIDLength = (BYTE)securityDomainAIDLength;

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("calculate_3des_DAP"), status);
	return status;

}

/**
 * If a security domain has DAP verification privilege the security domain validates this DAP.
 * The loadFileDataBlockHash can be calculated using calculate_load_file_data_block_hash().
 * \param loadFileDataBlockHash [in] The Load File Data Block Hash.
 * \param securityDomainAID [in] A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength [in] The length of the Security Domain AID.
 * \param PEMKeyFileName [in] A PEM file name with the DAP Verification private RSA key.
 * \param *passPhrase [in] The passphrase. Must be an ASCII string.
 * \param *loadFileDataBlockSignature [out] A pointer to the returned GP211_DAP_BLOCK structure.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_calculate_rsa_DAP(BYTE loadFileDataBlockHash[20], PBYTE securityDomainAID,
					   DWORD securityDomainAIDLength,
					   OPGP_STRING PEMKeyFileName, char *passPhrase,
					   GP211_DAP_BLOCK *loadFileDataBlockSignature)
{
	OPGP_ERROR_STATUS status;
	OPGP_LOG_START(_T("calculate_rsa_DAP"));

	calculate_rsa_signature(loadFileDataBlockHash, 20, PEMKeyFileName, passPhrase,
		loadFileDataBlockSignature->signature);
	loadFileDataBlockSignature->signatureLength = 128;
	memcpy(loadFileDataBlockSignature->securityDomainAID, securityDomainAID, securityDomainAIDLength);
	loadFileDataBlockSignature->securityDomainAIDLength = (BYTE)securityDomainAIDLength;

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("calculate_rsa_DAP"), status);
	return status;
}


/**
 * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
 * You may keep track of it. Returns OPGP_ERROR_SUCCESS if receipt is valid.
 * \param confirmationCounter [in] The confirmation counter.
 * \param cardUniqueData [in] The card unique data.
 * \param cardUniqueDataLength [in] The length of the card unique data buffer.
 * \param receiptKey [in] The 3DES key to generate the receipt.
 * \param receiptData [in] The GP211_RECEIPT_DATA structure containing the receipt returned
 * from load() to verify.
 * \param executableLoadFileAID [in] A buffer with AID of the Executable Load File which was INSTALL [for load].
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param securityDomainAID [in] A buffer containing the AID of the associated Security Domain.
 * \param securityDomainAIDLength [in] The length of the Security Domain AID.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_validate_load_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
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


/**
 * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
 * You may keep track of it. Returns OPGP_ERROR_SUCCESS if receipt is valid.
 * \param confirmationCounter [in] The confirmation counter.
 * \param cardUniqueData [in] The card unique data.
 * \param cardUniqueDataLength [in] The length of the card unique data buffer.
 * \param receiptKey [in] The 3DES key to generate the receipt.
 * \param receiptData [in] The GP211_RECEIPT_DATA structure containing the receipt returned
 * from GP211_install_for_install() to verify.
 * \param executableLoadFileAID [in] A buffer with AID of the Executable Load File which was INSTALL [for install].
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param applicationAID [in] The AID of the installed application.
 * \param applicationAIDLength [in] The length of the application instance AID.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_validate_install_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
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


/**
 * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
 * You may keep track of it. Returns OPGP_ERROR_SUCCESS if receipt is valid.
 * \param confirmationCounter [in] The confirmation counter.
 * \param cardUniqueData [in] The card unique data.
 * \param cardUniqueDataLength [in] The length of the card unique data buffer.
 * \param receiptKey [in] The 3DES key to generate the receipt.
 * \param receiptData [in] The GP211_RECEIPT_DATA structure containing the receipt returned
 * from delete_application() to verify.
 * \param AID [in] A buffer with AID of the application which was deleted.
 * \param AIDLength [in] The length of the AID.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_validate_delete_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
							 DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE AID, DWORD AIDLength) {
	return validate_delete_receipt(confirmationCounter, cardUniqueData,
							 cardUniqueDataLength,
						   receiptKey, receiptData,
						   AID, AIDLength);
}

/**
 * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
 * You may keep track of it. Returns OPGP_ERROR_SUCCESS if receipt is valid.
 * \param confirmationCounter [in] The confirmation counter.
 * \param cardUniqueData [in] The card unique data.
 * \param cardUniqueDataLength [in] The length of the card unique data buffer.
 * \param receiptKey [in] The 3DES key to generate the receipt.
 * \param receiptData [in] The GP211_RECEIPT_DATA structure containing the receipt returned
 * from GP211_install_for_extradition() to verify.
 * \param oldSecurityDomainAID [in] The AID of the old associated Security Domain.
 * \param oldSecurityDomainAIDLength [in] The length of the oldSecurityDomainAID buffer.
 * \param newSecurityDomainAID [in] The AID of the new associated Security Domain.
 * \param newSecurityDomainAIDLength [in] The length of the newSecurityDomainAID buffer.
 * \param applicationOrExecutableLoadFileAID [in] A buffer with AID of the Executable Load File which was INSTALL [for install].
 * \param applicationOrExecutableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_validate_extradition_receipt(DWORD confirmationCounter, PBYTE cardUniqueData,
							  DWORD cardUniqueDataLength,
						   BYTE receiptKey[16], GP211_RECEIPT_DATA receiptData,
						   PBYTE oldSecurityDomainAID, DWORD oldSecurityDomainAIDLength,
						   PBYTE newSecurityDomainAID, DWORD newSecurityDomainAIDLength,
						   PBYTE applicationOrExecutableLoadFileAID,
						   DWORD applicationOrExecutableLoadFileAIDLength)
{
	OPGP_ERROR_STATUS status;
	DWORD i=0;
	PBYTE validationData;
	DWORD validationDataLength;
	OPGP_LOG_START(_T("validate_install_receipt"));
	validationDataLength = 1 + 2 + 1 + cardUniqueDataLength + 1
		+ oldSecurityDomainAIDLength + 1 + applicationOrExecutableLoadFileAIDLength +
		1 + newSecurityDomainAIDLength;
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
	validationData[i++] = (BYTE)oldSecurityDomainAIDLength;
	memcpy(validationData, oldSecurityDomainAID, oldSecurityDomainAIDLength);
	i+=oldSecurityDomainAIDLength;
	validationData[i++] = (BYTE)applicationOrExecutableLoadFileAIDLength;
	memcpy(validationData, applicationOrExecutableLoadFileAID, applicationOrExecutableLoadFileAIDLength);
	i+=applicationOrExecutableLoadFileAIDLength;
	validationData[i++] = (BYTE)newSecurityDomainAIDLength;
	memcpy(validationData, newSecurityDomainAID, newSecurityDomainAIDLength);
	i+=newSecurityDomainAIDLength;
	status = validate_receipt(validationData, validationDataLength, receiptData.receipt, receiptKey);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if (validationData)
		free(validationData);
	OPGP_LOG_END(_T("validate_install_receipt"), status);
	return status;
}

/**
  * E.g. GemXpresso cards, JCOP-10 cards or Palmera Protect V5 cards use this scheme.
  * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
  * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
  * \param AID [in] The AID of the Card Manager.
  * \param AIDLength [in] The length of the Card Manager AID / Issuer Security Domain AID.
  * \param masterKey [in] The master key.
  * \param S_ENC [out] The static Encryption key.
  * \param S_MAC [out] The static Message Authentication Code key.
  * \param DEK [out] The static Key Encryption Key.
  * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
  */
OPGP_ERROR_STATUS OPGP_VISA2_derive_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, PBYTE AID, DWORD AIDLength, BYTE masterKey[16],
							BYTE S_ENC[16], BYTE S_MAC[16], BYTE DEK[16]) {
	OPGP_ERROR_STATUS status;
	BYTE cardCPLCData[50];
	DWORD cplcDataLen = 50;
	BYTE keyDiversificationData[16];
	BYTE cardmanagerAID[16];
	DWORD cardmanagerAIDLength = 16;

	OPGP_LOG_START(_T("OPGP_VISA2_derive_keys"));

#ifdef DEBUG
	OPGP_log_Hex(_T("OPGP_VISA2_derive_keys: Card Manager AID: "), AID, AIDLength);
#endif

	status = OP201_get_data(cardContext, cardInfo, NULL, (PBYTE)OP201_GET_DATA_CPLC_WHOLE_CPLC,
		cardCPLCData, &cplcDataLen);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	// card manager first 2 AID bytes
	// does not work on GemXpresso cards
	//status = OP201_get_data(cardContext, cardInfo, NULL, (PBYTE)OP201_GET_DATA_CARD_MANAGER_AID,
	//	cardmanagerAID, &cardmanagerAIDLength);
	//if (OPGP_ERROR_CHECK(status)) {
	//	goto end;
	//}
	memcpy(cardmanagerAID, AID, AIDLength);
	cardmanagerAIDLength = AIDLength;

	keyDiversificationData[0] = cardmanagerAID[cardmanagerAIDLength-2];
	keyDiversificationData[1] = cardmanagerAID[cardmanagerAIDLength-1];
	// we are using 13 here because VISA2_Dertive_keys skips the first 2 bytes after the card manager AID
 	memcpy(keyDiversificationData+2, cardCPLCData+13, 8);

	status = VISA2_derive_keys(cardContext, cardInfo, keyDiversificationData, masterKey, S_ENC, S_MAC, DEK);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("OPGP_VISA2_derive_keys"), status);
	return status;
}

/**
  * E.g. GemXpresso cards, JCOP-10 cards or Palmera Protect V5 cards use this scheme.
  * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
  * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
  * \param baseKeyDiversificationData [in] The key diversification data. This is returned by INITIALIZE UPDATE or can be constructed.
  * \param S_ENC [out] The static Encryption key.
  * \param S_MAC [out] The static Message Authentication Code key.
  * \param DEK [out] The static Key Encryption Key.
  * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
  */
OPGP_ERROR_STATUS VISA2_derive_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, BYTE baseKeyDiversificationData[10], BYTE masterKey[16],
							BYTE S_ENC[16], BYTE S_MAC[16], BYTE DEK[16]) {
	OPGP_ERROR_STATUS status;
	int outl;
	BYTE keyDiversificationData[16];

	OPGP_LOG_START(_T("VISA2_derive_keys"));

#ifdef DEBUG
	OPGP_log_Hex(_T("VISA2_derive_keys: Base Key Diversification Data: "), baseKeyDiversificationData, 10);
#endif

	/* Key Diversification data
	KDCAUTH/ENC xxh xxh || IC serial number || F0h 01h ||xxh xxh || IC serial number
	||0Fh 01h
	KDCMAC xxh xxh || IC serial number || F0h 02h ||xxh xxh || IC serial number
	|| 0Fh 02h
	KDCKEK xxh xxh || IC serial number || F0h 03h || xxh xxh || IC serial number
	|| 0Fh 03h


	xxh xxh is the last (rightmost) two bytes of the Card Manager AID.
	IC Serial Number is taken from the CPLC data.
	*/

 	// left
 	memcpy(keyDiversificationData, baseKeyDiversificationData, 2);
 	memcpy(keyDiversificationData+2, baseKeyDiversificationData+4, 4);
 	keyDiversificationData[6] = 0xF0;
 	keyDiversificationData[7] = 0x01;
 	// right
 	memcpy(keyDiversificationData+8, baseKeyDiversificationData, 2);
 	memcpy(keyDiversificationData+10, baseKeyDiversificationData+4, 4);
 	keyDiversificationData[14] = 0x0F;
 	keyDiversificationData[15] = 0x01;

#ifdef DEBUG
	OPGP_log_Hex(_T("VISA2_derive_keys: Key Diversification Data: "), keyDiversificationData, 16);
#endif

	status = calculate_enc_ecb_two_key_triple_des(masterKey, keyDiversificationData, 16, S_ENC, &outl);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	// left for MAC
	keyDiversificationData[6] = 0xF0;
	keyDiversificationData[7] = 0x02;
	// right for MAC
	keyDiversificationData[14] = 0x0F;
	keyDiversificationData[15] = 0x02;

#ifdef DEBUG
	OPGP_log_Hex(_T("VISA2_derive_keys: Key Diversification Data: "), keyDiversificationData, 16);
#endif

	status = calculate_enc_ecb_two_key_triple_des(masterKey, keyDiversificationData, 16, S_MAC, &outl);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	// DEK

	// left for DEK
	keyDiversificationData[6] = 0xF0;
	keyDiversificationData[7] = 0x03;
	// right for DEK
	keyDiversificationData[14] = 0x0F;
	keyDiversificationData[15] = 0x03;

#ifdef DEBUG
	OPGP_log_Hex(_T("VISA2_derive_keys: Key Diversification Data: "), keyDiversificationData, 16);

#endif

	status = calculate_enc_ecb_two_key_triple_des(masterKey, keyDiversificationData, 16, DEK, &outl);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("VISA2_derive_keys"), status);
	return status;
}


/**
  * E.g. Sm@rtCafe Expert 3.0 cards use this scheme.
  * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
  * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
  * \param masterKey [in] The master key.
  * \param S_ENC [out] The static Encryption key.
  * \param S_MAC [out] The static Message Authentication Code key.
  * \param DEK [out] The static Key Encryption Key.
  * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
  */
OPGP_ERROR_STATUS OPGP_EMV_CPS11_derive_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, BYTE masterKey[16],
							BYTE S_ENC[16], BYTE S_MAC[16], BYTE DEK[16]) {
	OPGP_ERROR_STATUS status;
	BYTE diversificationData[50];
	DWORD diversificationDataLen = 50;

	OPGP_LOG_START(_T("OPGP_EMV_CPS11_derive_keys"));

	status = OP201_get_data(cardContext, cardInfo, NULL, (PBYTE)OP201_GET_DATA_DIVERSIFICATION_DATA,
		diversificationData, &diversificationDataLen);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	status = EMV_CPS11_derive_keys(cardContext, cardInfo, diversificationData + 2, masterKey, S_ENC, S_MAC, DEK);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("OPGP_EMV_CPS11_derive_keys"), status);
	return status;
}

/**
  * E.g. Sm@rtCafe Expert 3.0 cards use this scheme.
  * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
  * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
  * \param baseKeyDiversificationData [in] The key diversification data. This is returned by INITIALIZE UPDATE or can be constructed.
  * \param masterKey [in] The master key.
  * \param S_ENC [out] The static Encryption key.
  * \param S_MAC [out] The static Message Authentication Code key.
  * \param DEK [out] The static Key Encryption Key.
  * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
  */
OPGP_ERROR_STATUS EMV_CPS11_derive_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, BYTE baseKeyDiversificationData[10], BYTE masterKey[16],
							BYTE S_ENC[16], BYTE S_MAC[16], BYTE DEK[16]) {
	OPGP_ERROR_STATUS status;
	int outl;
	BYTE keyDiversificationData[16];

	OPGP_LOG_START(_T("EMV_CPS11_derive_keys"));

	/*
	The 6 byte KMCID (e.g. IIN right justified and left padded with 1111b per quartet)
	concatenated with the 4 byte CSN (least significant bytes) form the key
	diversification data that must be placed in tag ‘CF’. This same data must be used to
	form the response to the INITIALIZE UPDATE command.
	*/

	/* KEYDATA Key derivation data:
        - KMCID (6 bytes)
        - CSN (4 bytes)

        If the CSN does not ensure the uniqueness of KEYDATA across different batches of cards other unique data (e.g. 2
		right most bytes of IC serial number and 2 bytes of IC batch identifier) should be used instead.
    */

	/* KENC := DES3(KMC)[Six least
	significant bytes of the KEYDATA || ’F0’ || ‘01’ ]|| DES3(KMC)[ Six least
	significant bytes of the KEYDATA || ‘0F’ || ‘01’].
	*/


	/* KMAC := DES3(KMC)[ Six
	least significant bytes of the KEYDATA || ’F0’ || ‘02’ ]|| DES3(KMC)[ Six
	least significant bytes of the KEYDATA || ‘0F’ || ‘02’].
	*/

	/* KDEK := DES3(KMC)[ Six
	least significant bytes of the KEYDATA || ’F0’ || ‘03’ ]|| DES3(KMC)[ Six
	least significant bytes of the KEYDATA || ‘0F’ || ‘03’].
	*/

	// left
    memcpy(keyDiversificationData, baseKeyDiversificationData + 4, 6);
    keyDiversificationData[6] = 0xF0;
    keyDiversificationData[7] = 0x01;
    // right
    memcpy(keyDiversificationData+8, baseKeyDiversificationData + 4, 6);
    keyDiversificationData[14] = 0x0F;
    keyDiversificationData[15] = 0x01;

#ifdef DEBUG
	OPGP_log_Hex(_T("EMV_CPS11_derive_keys: Key Diversification Data: "), keyDiversificationData, 16);
#endif

	status = calculate_enc_ecb_two_key_triple_des(masterKey, keyDiversificationData, 16, S_ENC, &outl);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	// left for MAC
	keyDiversificationData[6] = 0xF0;
	keyDiversificationData[7] = 0x02;
	// right for MAC
	keyDiversificationData[14] = 0x0F;
	keyDiversificationData[15] = 0x02;

#ifdef DEBUG
	OPGP_log_Hex(_T("EMV_CPS11_derive_keys: Key Diversification Data: "), keyDiversificationData, 16);
#endif

	status = calculate_enc_ecb_two_key_triple_des(masterKey, keyDiversificationData, 16, S_MAC, &outl);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	// DEK

	// left for DEK
	keyDiversificationData[6] = 0xF0;
	keyDiversificationData[7] = 0x03;
	// right for DEK
	keyDiversificationData[14] = 0x0F;
	keyDiversificationData[15] = 0x03;

#ifdef DEBUG
	OPGP_log_Hex(_T("EMV_CPS11_derive_keys: Key Diversification Data: "), keyDiversificationData, 16);

#endif

	status = calculate_enc_ecb_two_key_triple_des(masterKey, keyDiversificationData, 16, DEK, &outl);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("EMV_CPS11_derive_keys"), status);
	return status;
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
 * New cards usually use the VISA default key for all DES keys. See #OPGP_VISA_DEFAULT_KEY.
 * If a derivation method is used the baseKey defines the master key.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param baseKey [in] Secure Channel base key or the master key for the key derivation.
 * \param S_ENC [in] Secure Channel Encryption Key.
 * \param S_MAC [in] Secure Channel Message Authentication Code Key.
 * \param DEK [in] Data Encryption Key.
 * \param keySetVersion [in] The key set version on the card to use for mutual authentication.
 * \param keyIndex [in] The key index of the encryption key in the key set version on the card to use for
 * mutual authentication.
 * \param secureChannelProtocol [in] The Secure Channel Protocol.
 * \param secureChannelProtocolImpl [in] The Secure Channel Protocol Implementation.
 * \param securityLevel [in] The requested security level.
 * \param derivationMethod [in] The derivation method to use for. See #OPGP_DERIVATION_METHOD_VISA2.
 * See security.h#GP211_SCP01_SECURITY_LEVEL_C_DEC_C_MAC and others.
 * \param *secInfo [out] The returned GP211_SECURITY_INFO structure.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_mutual_authentication(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, BYTE baseKey[16],
						   BYTE S_ENC[16], BYTE S_MAC[16],
						   BYTE DEK[16], BYTE keySetVersion,
						   BYTE keyIndex, BYTE secureChannelProtocol,
						   BYTE secureChannelProtocolImpl, BYTE securityLevel,
						   BYTE derivationMethod,
						   GP211_SECURITY_INFO *secInfo) {
	return mutual_authentication(cardContext, cardInfo, baseKey,
						   S_ENC, S_MAC,
						   DEK, keySetVersion,
						   keyIndex, secureChannelProtocol,
						   secureChannelProtocolImpl, securityLevel,
						   derivationMethod,
						   secInfo);
}

OPGP_ERROR_STATUS mutual_authentication(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, BYTE baseKey[16],
						   BYTE S_ENC[16], BYTE S_MAC[16],
						   BYTE DEK[16], BYTE keySetVersion,
						   BYTE keyIndex, BYTE secureChannelProtocol,
						   BYTE secureChannelProtocolImpl, BYTE securityLevel,
						   BYTE derivationMethod,
						   GP211_SECURITY_INFO *secInfo) {
	OPGP_ERROR_STATUS status;
	DWORD i=0;

	BYTE hostChallenge[8];

	BYTE key_diversification_data[10];
	BYTE key_information_data[2];
	BYTE sequenceCounter[2];
	BYTE cardChallengeSCP02[6];
	BYTE cardChallengeSCP01[8];
	BYTE cardCryptogram[8];

	BYTE card_cryptogram_ver[8];
	BYTE hostCryptogram[8];
	BYTE mac[8];

	BYTE sMac[16];
	BYTE sEnc[16];
	BYTE dek[16];

	DWORD sendBufferLength=256;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[256];
	// random for host challenge

	OPGP_LOG_START(_T("mutual_authentication"));

	// copy keys to internal buffer
	if (S_MAC != NULL) {
		memcpy(sMac, S_MAC, 16);
	}
	if (S_ENC != NULL) {
		memcpy(sEnc, S_ENC, 16);
	}
	if (DEK != NULL) {
		memcpy(dek, DEK, 16);
	}

	secInfo->secureChannelProtocol = secureChannelProtocol;
	secInfo->secureChannelProtocolImpl = secureChannelProtocolImpl;

#ifdef DEBUG
	OPGP_log_Msg(_T("mutual_authentication: Secure Channel Protocol: 0x%02X"), secureChannelProtocol);
	OPGP_log_Msg(_T("mutual_authentication: Secure Channel Protocol Implementation: 0x%02X"), secureChannelProtocolImpl);
#endif

	status = get_random(hostChallenge, 8);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

#ifdef DEBUG
	OPGP_log_Hex(_T("mutual_authentication: Generated Host Challenge: "), hostChallenge, 8);

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

	status = OPGP_send_APDU(cardContext, cardInfo, NULL, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);

	// check receive buffer length, including SW it must be 30 bytes
	if (recvBufferLength != 30) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_RESPONSE_DATA, OPGP_stringify_error(OPGP_ERROR_INVALID_RESPONSE_DATA));
		goto end;
	}

	// response of INITIALIZE UPDATE
	memcpy(key_diversification_data, recvBuffer, 10);
	memcpy(key_information_data, recvBuffer+10,2);

	/* Augusto: added key information data in secInfo */
	secInfo->keySetVersion = key_information_data[0];
	// the key index is only reported in OP201
	if (cardInfo.specVersion == OP_201) {
		secInfo->keyIndex = key_information_data[1];
	}
	else {
		// we set it to a dummy value
		secInfo->keyIndex = 0xFF;
	}
	/* end */

	if (secInfo->secureChannelProtocol == GP211_SCP02) {
		memcpy(sequenceCounter, recvBuffer+12, 2);
		memcpy(cardChallengeSCP02, recvBuffer+14, 6);
	}
	else {
		memcpy(cardChallengeSCP01, recvBuffer+12, 8);
	}
	memcpy(cardCryptogram, recvBuffer+20, 8);

	// test if reported SCP is consistent with passed SCP
	if (cardInfo.specVersion == GP_211) {
		if (secureChannelProtocol != key_information_data[1]) {
			OPGP_ERROR_CREATE_ERROR(status, GP211_ERROR_INCONSISTENT_SCP, OPGP_stringify_error(GP211_ERROR_INCONSISTENT_SCP));
			goto end;
		}
	}
#ifdef DEBUG
	OPGP_log_Hex(_T("mutual_authentication: Key Diversification Data: "), key_diversification_data, 10);

	OPGP_log_Hex(_T("mutual_authentication: Key Information Data: "), key_information_data, 2);

	if (secInfo->secureChannelProtocol == GP211_SCP02) {
		OPGP_log_Hex(_T("mutual_authentication: Sequence Counter: "), sequenceCounter, 2);
		OPGP_log_Hex(_T("mutual_authentication: Card Challenge: "), cardChallengeSCP02, 6);
	}
	else {
		OPGP_log_Hex(_T("mutual_authentication: Card Challenge: "), cardChallengeSCP01, 8);
	}

	OPGP_log_Hex(_T("mutual_authentication: Retrieved Card Cryptogram: "), cardCryptogram, 8);

#endif


	
	if (derivationMethod == OPGP_DERIVATION_METHOD_EMV_CPS11) {
		status = EMV_CPS11_derive_keys(cardContext, cardInfo, recvBuffer, baseKey, sEnc, sMac, dek);
		if ( OPGP_ERROR_CHECK(status)) {
			goto end;
		}
	}

	if (derivationMethod == OPGP_DERIVATION_METHOD_VISA2) {
		// first 10 bytes are the key diversification data
		status = VISA2_derive_keys(cardContext, cardInfo, recvBuffer, baseKey, sEnc, sMac, dek);
		if ( OPGP_ERROR_CHECK(status)) {
			goto end;
		}
	}

	if (secInfo->secureChannelProtocol == GP211_SCP02) {
		/* Secure Channel base key */
		if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i04
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i14
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i44
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i54) {
			// calculation of encryption session key
			status = create_session_key_SCP02(baseKey, ENCDerivationConstant, sequenceCounter, secInfo->encryptionSessionKey);
			if (OPGP_ERROR_CHECK(status)) {
				goto end;
			}

			// calculation of C-MAC session key
			status = create_session_key_SCP02(baseKey, C_MACDerivationConstant, sequenceCounter, secInfo->C_MACSessionKey);
			if (OPGP_ERROR_CHECK(status)) {
				goto end;
			}

			// calculation of R-MAC session key
			status = create_session_key_SCP02(baseKey, R_MACDerivationConstant, sequenceCounter, secInfo->C_MACSessionKey);
			if (OPGP_ERROR_CHECK(status)) {
				goto end;
			}

			// calculation of data encryption session key
			status = create_session_key_SCP02(baseKey, DEKDerivationConstant, sequenceCounter, secInfo->C_MACSessionKey);
			if (OPGP_ERROR_CHECK(status)) {
				goto end;
			}

		}
		/* 3 Secure Channel Keys */
		else if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i05
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i15
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i55
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i45) {
			// calculation of encryption session key
			status = create_session_key_SCP02(sEnc, ENCDerivationConstant, sequenceCounter, secInfo->encryptionSessionKey);
			if (OPGP_ERROR_CHECK(status)) {
				goto end;
			}

			// calculation of C-MAC session key
			status = create_session_key_SCP02(sMac, C_MACDerivationConstant, sequenceCounter, secInfo->C_MACSessionKey);
			if (OPGP_ERROR_CHECK(status)) {
				goto end;
			}

			// calculation of R-MAC session key
			status = create_session_key_SCP02(sMac, R_MACDerivationConstant, sequenceCounter, secInfo->R_MACSessionKey);
			if (OPGP_ERROR_CHECK(status)) {
				goto end;
			}

			// calculation of data encryption session key
			status = create_session_key_SCP02(dek, DEKDerivationConstant, sequenceCounter, secInfo->dataEncryptionSessionKey);
			if (OPGP_ERROR_CHECK(status)) {
				goto end;
			}
		}
		else {
			OPGP_ERROR_CREATE_ERROR(status, GP211_ERROR_INVALID_SCP_IMPL, OPGP_stringify_error(GP211_ERROR_INVALID_SCP_IMPL));
			goto end;
		}
	}
	else if (secInfo->secureChannelProtocol == GP211_SCP01) {
		if (secInfo->secureChannelProtocolImpl == GP211_SCP01_IMPL_i05
			|| secInfo->secureChannelProtocolImpl == GP211_SCP01_IMPL_i15) {
			// calculation of ENC session key
			status = create_session_key_SCP01(sEnc, cardChallengeSCP01, hostChallenge, secInfo->encryptionSessionKey);
			if (OPGP_ERROR_CHECK(status)) {
				goto end;
			}

			// calculation of MAC session key
			status = create_session_key_SCP01(sMac, cardChallengeSCP01, hostChallenge, secInfo->C_MACSessionKey);
			if (OPGP_ERROR_CHECK(status)) {
				goto end;
			}

			// DEK
			memcpy(secInfo->dataEncryptionSessionKey, dek, 16);
		}
		else {
			OPGP_ERROR_CREATE_ERROR(status, GP211_ERROR_INVALID_SCP_IMPL, OPGP_stringify_error(GP211_ERROR_INVALID_SCP_IMPL));
			goto end;
		}
	}
	else {
		OPGP_ERROR_CREATE_ERROR(status, GP211_ERROR_INVALID_SCP, OPGP_stringify_error(GP211_ERROR_INVALID_SCP));
		goto end;
	}

#ifdef DEBUG
	OPGP_log_Hex(_T("mutual_authentication: S-ENC Session Key: "), secInfo->encryptionSessionKey, 16);
#endif

#ifdef DEBUG
	OPGP_log_Msg(_T("mutual_authentication: S-MAC Session Key: "), secInfo->C_MACSessionKey, 16);
#endif

#ifdef DEBUG
	if (secInfo->secureChannelProtocol == GP211_SCP01) {
		OPGP_log_Hex(_T("mutual_authentication: Data Encryption Key: "), secInfo->dataEncryptionSessionKey, 16);
	}
#endif

#ifdef DEBUG
	if (secInfo->secureChannelProtocol == GP211_SCP02) {
		OPGP_log_Hex(_T("mutual_authentication: R-MAC Session Key: "), secInfo->R_MACSessionKey, 16);
	}
#endif

#ifdef DEBUG
	if (secInfo->secureChannelProtocol == GP211_SCP02) {
		OPGP_log_Hex(_T("mutual_authentication: DEK Session Key: "), secInfo->dataEncryptionSessionKey, 16);
	}
#endif

	// calculation of card cryptogram
	if (secInfo->secureChannelProtocol == GP211_SCP02) {
		status = calculate_card_cryptogram_SCP02(secInfo->encryptionSessionKey,
			sequenceCounter, cardChallengeSCP02, hostChallenge, card_cryptogram_ver);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
	}
	else {
		status = calculate_card_cryptogram_SCP01(secInfo->encryptionSessionKey,
			cardChallengeSCP01, hostChallenge, card_cryptogram_ver);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
	}

#ifdef DEBUG
	OPGP_log_Hex(_T("mutual_authentication: Card Cryptogram to compare: "), card_cryptogram_ver, 8);

#endif

	if (memcmp(cardCryptogram, card_cryptogram_ver, 8) != 0) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CARD_CRYPTOGRAM_VERIFICATION, OPGP_stringify_error(OPGP_ERROR_CARD_CRYPTOGRAM_VERIFICATION)); goto end; }
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
		status = calculate_MAC_des_3des(secInfo->C_MACSessionKey, sendBuffer, sendBufferLength-8, (PBYTE)icv, mac);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
	}
	else {
		calculate_MAC(secInfo->C_MACSessionKey, sendBuffer, sendBufferLength-8, (PBYTE)icv, mac);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
	}
	memcpy(secInfo->lastC_MAC, mac, 8);
	memcpy(sendBuffer+i, mac, 8);
	i+=8;

	status = OPGP_send_APDU(cardContext, cardInfo, NULL, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	switch (status.errorCode) {
		case OPGP_ISO7816_ERROR_6300:
			{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ISO7816_ERROR_HOST_CRYPTOGRAM_VERIFICATION, OPGP_stringify_error(OPGP_ISO7816_ERROR_HOST_CRYPTOGRAM_VERIFICATION)); goto end; }
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("mutual_authentication"), status);
	return status;
}

/**
 * It depends on the supported protocol implementation by the card what keys must be passed as parameters.
 * baseKey must be NULL if the protocol uses 3 Secure Channel Keys
 * (Secure Channel Encryption Key, Secure Channel Message Authentication Code Key and
 * Data Encryption Key) and vice versa.
 * Details about the supported Secure Channel Protocol and its implementation can be
 * obtained by a call to the function GP211_get_secure_channel_protocol_details().
 * New cards usually use the VISA default key for all DES keys. See #OPGP_VISA_DEFAULT_KEY.
 * The current Sequence Counter can be obtained with a call to GP211_get_sequence_counter().
 * SCP02 is implicitly set and the security level is set to C-MAC only.
 * \param AID The AID needed for the calculation of the ICV.
 * \param AIDLength The length of the AID buffer.
 * \param baseKey [in] Secure Channel base key.
 * \param S_ENC [in] Secure Channel Encryption Key.
 * \param S_MAC [in] Secure Channel Message Authentication Code Key.
 * \param DEK [in] Data Encryption Key.
 * \param secureChannelProtocolImpl [in] The Secure Channel Protocol Implementation.
 * \param sequenceCounter [in] The sequence counter.
 * \param *secInfo [out] The returned GP211_SECURITY_INFO structure.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_init_implicit_secure_channel(PBYTE AID, DWORD AIDLength, BYTE baseKey[16],
								  BYTE S_ENC[16], BYTE S_MAC[16], BYTE DEK[16],
								  BYTE secureChannelProtocolImpl, BYTE sequenceCounter[2],
								  GP211_SECURITY_INFO *secInfo) {
	OPGP_ERROR_STATUS status;

	OPGP_LOG_START(_T("init_implicit_secure_channel"));

	secInfo->secureChannelProtocol = GP211_SCP02;
	secInfo->secureChannelProtocolImpl = secureChannelProtocolImpl;
	secInfo->securityLevel = GP211_SCP02_SECURITY_LEVEL_C_MAC;
		/* Secure Channel base key */
	if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1A
			|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i1B) {
		// calculation of encryption session key
			status = create_session_key_SCP02(baseKey, ENCDerivationConstant, sequenceCounter, secInfo->encryptionSessionKey);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}

		// calculation of C-MAC session key
		status = create_session_key_SCP02(baseKey, C_MACDerivationConstant, sequenceCounter, secInfo->C_MACSessionKey);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}

		// calculation of R-MAC session key
		status = create_session_key_SCP02(baseKey, R_MACDerivationConstant, sequenceCounter, secInfo->C_MACSessionKey);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}

		// calculation of data encryption session key
		status = create_session_key_SCP02(baseKey, DEKDerivationConstant, sequenceCounter, secInfo->C_MACSessionKey);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}

	}
	/* 3 Secure Channel Keys */
	else if (secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0A
		|| secInfo->secureChannelProtocolImpl == GP211_SCP02_IMPL_i0B) {
		// calculation of encryption session key
		status = create_session_key_SCP02(S_ENC, ENCDerivationConstant, sequenceCounter, secInfo->encryptionSessionKey);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}

		// calculation of C-MAC session key
		status = create_session_key_SCP02(S_MAC, C_MACDerivationConstant, sequenceCounter, secInfo->C_MACSessionKey);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}

		// calculation of R-MAC session key
		status = create_session_key_SCP02(S_MAC, R_MACDerivationConstant, sequenceCounter, secInfo->R_MACSessionKey);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}

		// calculation of data encryption session key
		status = create_session_key_SCP02(DEK, DEKDerivationConstant, sequenceCounter, secInfo->dataEncryptionSessionKey);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
	}
	else {
		OPGP_ERROR_CREATE_ERROR(status, GP211_ERROR_INVALID_SCP_IMPL, OPGP_stringify_error(GP211_ERROR_INVALID_SCP_IMPL));
		goto end;
	}

	status = calculate_MAC_des_3des(secInfo->C_MACSessionKey, AID, AIDLength, (PBYTE)icv, secInfo->lastC_MAC);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("init_implicit_secure_channel"), status);
	return status;
}

/**
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param sequenceCounter [out] The sequence counter.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_get_sequence_counter(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo,
						  BYTE sequenceCounter[2]) {
	OPGP_ERROR_STATUS status;
	BYTE recvBuffer[256];
	DWORD recvBufferLength = sizeof(recvBuffer);

	OPGP_LOG_START(_T("get_sequence_counter"));
	status = GP211_get_data_iso7816_4(cardContext, cardInfo, (PBYTE)GP211_GET_DATA_SEQUENCE_COUNTER_DEFAULT_KEY_VERSION,
		recvBuffer, &recvBufferLength);
	if ( OPGP_ERROR_CHECK(status) ) {
		goto end;
	}
	memcpy(sequenceCounter, recvBuffer, 2);
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("get_sequence_counter"), status);
	return status;
}

/**
 * \param *secInfo [out] The returned GP211_SECURITY_INFO structure.
 */
OPGP_ERROR_STATUS GP211_close_implicit_secure_channel(GP211_SECURITY_INFO *secInfo) {
	OPGP_ERROR_STATUS status;
	OPGP_LOG_START(_T("close_implicit_secure_channel"));
	secInfo->securityLevel = GP211_SCP02_SECURITY_LEVEL_NO_SECURE_MESSAGING;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("close_implicit_secure_channel"), status);
	return status;
}

/**
 * The single numbers of the new PIN are encoded as single BYTEs in the newPIN buffer.
 * The tryLimit must be in the range of 0x03 and x0A.
 * The PIN must comprise at least 6 numbers and not exceeding 12 numbers.
 * To unblock the PIN use tryLimit with a value of 0x00. In this case newPIN buffer and newPINLength are ignored.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param tryLimit [in] The try limit for the PIN.
 * \param newPIN [in] The new PIN.
 * \param newPINLength [in] The length of the new PIN.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_pin_change(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE tryLimit,
					  PBYTE newPIN, DWORD newPINLength) {
	return pin_change(cardContext, cardInfo, secInfo, tryLimit, newPIN, newPINLength);
}

OPGP_ERROR_STATUS pin_change(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo, BYTE tryLimit,
				PBYTE newPIN, DWORD newPINLength) {
	OPGP_ERROR_STATUS status;
	DWORD sendBufferLength;
	DWORD recvBufferLength=2;
	BYTE recvBuffer[2];
	BYTE sendBuffer[13];
	BYTE PINFormat[8];
	BYTE encryption[8];
	int encryptionLength;
	DWORD j,i=0;
	OPGP_LOG_START(_T("pin_change"));
	if ((tryLimit != 0) && !((tryLimit >= 0x03) && (tryLimit <= 0x0a))) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_WRONG_TRY_LIMIT, OPGP_stringify_error(OPGP_ERROR_WRONG_TRY_LIMIT)); goto end; }
	}
	if ((newPINLength < 6) || (newPINLength > 12)) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_WRONG_PIN_LENGTH, OPGP_stringify_error(OPGP_ERROR_WRONG_PIN_LENGTH)); goto end; }
	}
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0x24;
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = tryLimit;
	if (tryLimit != 0) {
		sendBuffer[i++] = 0x08;
		memset ( PINFormat, 0, sizeof ( PINFormat ));
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

	status = OPGP_send_APDU(cardContext, cardInfo, secInfo,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	if (status.errorCode == OPGP_ISO7816_ERROR_WRONG_DATA)
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ISO7816_ERROR_WRONG_GLOBAL_PIN_FORMAT, OPGP_stringify_error(OPGP_ISO7816_ERROR_WRONG_GLOBAL_PIN_FORMAT)); goto end; }
	if (status.errorCode == OPGP_ISO7816_ERROR_INCORRECT_P1P2)
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ISO7816_ERROR_WRONG_PIN_TRY_LIMIT, OPGP_stringify_error(OPGP_ISO7816_ERROR_WRONG_PIN_TRY_LIMIT)); goto end; }
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("pin_change"), status);
	return status;
}

/**
 * If STORE DATA is used for personalizing an application, a GP211_install_for_personalization().
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param *data [in] Data to send to application or Security Domain.
 * \param dataLength [in] The length of the data buffer.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS GP211_store_data(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, GP211_SECURITY_INFO *secInfo,
				 PBYTE data, DWORD dataLength) {
	OPGP_ERROR_STATUS status;
	DWORD sendBufferLength;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[261];
	DWORD left, read;
	BYTE blockNumber=0x00;
	OPGP_LOG_START(_T("GP211_store_data"));
	sendBuffer[0] = 0x80;
	sendBuffer[1] = 0xE2;

	read = 0;
	left = dataLength;
	while(left > 0) {
		if (left <= MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING) {
			sendBuffer[2] = 0x80;
			memcpy(sendBuffer+5, data+read, left);
			read+=left;
			sendBufferLength=5+left;
			sendBuffer[4] = (BYTE)left;
			left-=left;
		}
		else {
			sendBuffer[2] = 0x00;
			memcpy(sendBuffer+5, data+read, MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING);
			read+=MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING;
			sendBufferLength=5+MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING;
			sendBuffer[4] = MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING;
			left-=MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING;
		}
		sendBuffer[3] = blockNumber++;

		recvBufferLength=256;
		status = OPGP_send_APDU(cardContext, cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
		CHECK_SW_9000(recvBuffer, recvBufferLength, status);

	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("GP211_store_data"), status);
	return status;
}

/**
 * You must track on your own, what channels are open.
 * \param *cardInfo [in, out] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param channelNumber [in] The Logical Channel number to select.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_select_channel(OPGP_CARD_INFO *cardInfo, BYTE channelNumber) {
	OPGP_ERROR_STATUS status;
	OPGP_LOG_START(_T("select_channel"));
	cardInfo->logicalChannel = channelNumber;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("select_channel"), status);
	return status;
}

/**
 * For an OPEN command, the channelNumberToClose is ignored.
 * For an CLOSE command, the channelNumberOpened is returned.
 * After closing a Logical Channel the Basic Logical Channel is assumed for the next transmissions.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param *cardInfo [in, out] The OPGP_CARD_INFO structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the GP211_SECURITY_INFO structure returned by GP211_mutual_authentication().
 * \param openClose [in] Logical Channel should be opened or closed. See #GP211_MANAGE_CHANNEL_OPEN.
 * \param channelNumberToClose [in] The Logical Channel number to close.
 * \param channelNumberOpened [out] The Logical Channel number opened.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OPGP_manage_channel(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO *cardInfo, GP211_SECURITY_INFO *secInfo,
					BYTE openClose, BYTE channelNumberToClose,
					BYTE *channelNumberOpened) {

	OPGP_ERROR_STATUS status;
	DWORD sendBufferLength;
	DWORD recvBufferLength=3;
	BYTE recvBuffer[3];
	BYTE sendBuffer[5];
	DWORD i=0;
	OPGP_LOG_START(_T("OPGP_manage_channel"));
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

	status = OPGP_send_APDU(cardContext, *cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	CHECK_SW_9000(recvBuffer, recvBufferLength, status);

	if (openClose == GP211_MANAGE_CHANNEL_OPEN) {
		*channelNumberOpened = recvBuffer[0];
		cardInfo->logicalChannel = recvBuffer[0];
#ifdef DEBUG
	OPGP_log_Msg(_T("OPGP_manage_channel: Logical Channel number opened: %d"), *channelNumberOpened);
#endif
	}
	else {
		*channelNumberOpened = 0;
		cardInfo->logicalChannel = 0;
#ifdef DEBUG
	OPGP_log_Msg(_T("OPGP_manage_channel: Logical Channel closed: %d"), channelNumberToClose);
#endif
	}

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("OPGP_manage_channel"), status);
	return status;
}

/**
 * The secInfo pointer can also be null and so this function can be used for arbitrary cards.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param *secInfo [in] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param capdu [in] The command APDU.
 * \param capduLength [in] The length of the command APDU.
 * \param rapdu [out] The response APDU.
 * \param rapduLength [in, out] The length of the the response APDU.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_send_APDU(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
					 PBYTE capdu, DWORD capduLength, PBYTE rapdu, PDWORD rapduLength) {
	OPGP_ERROR_STATUS status;

	if (secInfo == NULL) {
	    status = OPGP_send_APDU(cardContext, cardInfo, NULL, capdu, capduLength, rapdu, rapduLength);
	} else {
	    GP211_SECURITY_INFO gp211secInfo;
	    mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	    status = OPGP_send_APDU(cardContext, cardInfo, &gp211secInfo, capdu, capduLength, rapdu, rapduLength);
	    mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	}

	return status;
}

/**
 * A keySetVersion value of 0x00 adds a new key.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version a new key belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param keySetVersion [in] An existing key set version.
 * \param keyIndex [in] The position of the key in the key set version.
 * \param newKeySetVersion [in] The new key set version.
 * \param PEMKeyFileName [in] A PEM file name with the public RSA key.
 * \param *passPhrase [in] The passphrase. Must be an ASCII string.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_put_rsa_key(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				 BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion,
				 OPGP_STRING PEMKeyFileName, char *passPhrase) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	status = put_rsa_key(cardContext, cardInfo, &gp211secInfo, keySetVersion, keyIndex, newKeySetVersion,
		PEMKeyFileName, passPhrase);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return status;
}

/**
 * A keySetVersion value of 0x00 adds a new key.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version a new key belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param keySetVersion [in] An existing key set version.
 * \param keyIndex [in] The position of the key in the key set version.
 * \param newKeySetVersion [in] The new key set version.
 * \param _3desKey [in] The new 3DES key.
 * \param KEK [in] The key encryption key (KEK) to encrypt the _3desKey.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_put_3desKey(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				  BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, BYTE _3desKey[16],
				  BYTE KEK[16]) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	status = put_3des_key(cardContext, cardInfo, &gp211secInfo, keySetVersion, keyIndex, newKeySetVersion, _3desKey);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return status;
}

/**
 * A keySetVersion value of 0x00 adds a new secure channel key set.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version the new secure channel keys belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param keySetVersion [in] An existing key set version.
 * \param newKeySetVersion [in] The new key set version.
 * \param new_encKey [in] The new Encryption key.
 * \param new_macKey [in] The new MAC key.
 * \param new_KEK [in] The new key encryption key.
 * \param KEK [in] The key encryption key (KEK).
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_put_secure_channel_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo, BYTE keySetVersion, BYTE newKeySetVersion, BYTE new_encKey[16], BYTE new_macKey[16], BYTE new_KEK[16], BYTE KEK[16]) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	memcpy(gp211secInfo.dataEncryptionSessionKey, KEK, 16);
	status = put_secure_channel_keys(cardContext, cardInfo, &gp211secInfo, keySetVersion, newKeySetVersion,
		NULL, new_encKey, new_macKey, new_KEK);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return status;
}

/**
 * A keySetVersion value of 0x00 adds a new secure channel key set.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version a the new secure channel keys belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param keySetVersion [in] An existing key set version.
 * \param newKeySetVersion [in] The new key set version.
 * \param PEMKeyFileName [in] A PEM file name with the public RSA key.
 * \param *passPhrase [in] The passphrase. Must be an ASCII string.
 * \param receiptGenerationKey [in] The new Receipt Generation key.
 * \param KEK [in] The key encryption key (KEK).
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_put_delegated_management_keys(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
								   BYTE keySetVersion, BYTE newKeySetVersion,
								   OPGP_STRING PEMKeyFileName, char *passPhrase,
								   BYTE receiptGenerationKey[16], BYTE KEK[16]) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	memcpy(gp211secInfo.dataEncryptionSessionKey, KEK, 16);
	status = put_delegated_management_keys(cardContext, cardInfo, &gp211secInfo, keySetVersion, newKeySetVersion,
		PEMKeyFileName, passPhrase, receiptGenerationKey);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return status;
}

/**
 * If keyIndex is 0xFF (=-1) all keys within a keySetVersion are deleted.
 * If keySetVersion is 0x00 all keys with the specified keyIndex are deleted.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param keySetVersion [in] An existing key set version.
 * \param keyIndex [in] An existing key index.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_delete_key(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo, BYTE keySetVersion, BYTE keyIndex) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	status = delete_key(cardContext, cardInfo, &gp211secInfo, keySetVersion, keyIndex);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return status;
}

/**
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param AIDs [in] A pointer to the an array of OPGP_AID structures describing the applications and load files to delete.
 * \param AIDsLength [in] The number of OPGP_AID structures.
 * \param *receiptData [out] A OP201_RECEIPT_DATA array. If the deletion is performed by a
 * security domain with delegated management privilege
 * this structure contains the according data for each deleted application or package.
 * \param receiptDataLength [in, out] A pointer to the length of the receiptData array.
 * If no receiptData is available this length is 0;
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_delete_application(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
							  OPGP_AID *AIDs, DWORD AIDsLength, OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataLength) {
	OPGP_ERROR_STATUS status;
	DWORD i;
	GP211_SECURITY_INFO gp211secInfo;
	GP211_RECEIPT_DATA *gp211receiptData;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
    gp211receiptData = (*receiptDataLength == 0) ?
        NULL :
        (GP211_RECEIPT_DATA *)malloc(sizeof(GP211_RECEIPT_DATA)* (*receiptDataLength));

    if ((*receiptDataLength != 0) && (gp211receiptData == NULL)) {
        OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
        goto end;
    }

	status = delete_application(cardContext, cardInfo, &gp211secInfo, AIDs, AIDsLength,
		gp211receiptData, receiptDataLength, OP_201);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	for (i=0; i<*receiptDataLength; i++) {
		mapGP211ToOP201ReceiptData(gp211receiptData[i], &(receiptData[i]));
	}
end:
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	if (gp211receiptData) {
		free(gp211receiptData);
	}
	return status;
}

/**
 * Puts a single card data object identified by identifier.
 * Some cards do not provide some data objects. Some possible identifiers are predefined.
 * See #OP201_GET_DATA_ISSUER_BIN. For details about the coding of the dataObject see the programmer's manual
 * of your card.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param identifier [in] Two byte buffer with high and low order tag value for identifying card data object.
 * \param dataObject [in] The coded data object.
 * \param dataObjectLength [in] The length of the data object.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_put_data(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
					BYTE identifier[2], PBYTE dataObject, DWORD dataObjectLength) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	status = put_data(cardContext, cardInfo, &gp211secInfo, identifier, dataObject, dataObjectLength);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return status;
}

/**
 * Retrieves a single card data object from the card identified by identifier.
 * Some cards do not provide some data objects. Some possible identifiers are predefined.
 * See #OP201_GET_DATA_ISSUER_BIN and so on. For details about the coding of the response see the programmer's manual
 * of your card.
 * There is a convenience method get_key_information_templates() to get the key information template(s)
 * containing key set version, key index, key type and key length of the keys.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param identifier [in] Two byte buffer with high and low order tag value for identifying card data object.
 * \param recvBuffer [in] The buffer for the card data object.
 * \param recvBufferLength [in] The length of the received card data object.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_get_data(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo, BYTE identifier[2], PBYTE recvBuffer, PDWORD recvBufferLength) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO gp211secInfo;
	/* can be executed outside of a secret channel */
	if (secInfo != NULL) {
		mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
		status = get_data(cardContext, cardInfo, &gp211secInfo, identifier, recvBuffer, recvBufferLength);
	}
	else {
		status = get_data(cardContext, cardInfo, NULL, identifier, recvBuffer, recvBufferLength);
	}
	if (secInfo != NULL) {
		mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	}
	return status;
}

/**
 * The card must support the optional report of key information templates.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param keyInformationTemplate [in] The number of the key information template.
 * \param *keyInformation [out] A pointer to an array of OP201_KEY_INFORMATION structures.
 * \param keyInformationLength [in, out] The number of OP201_KEY_INFORMATION structures.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_get_key_information_templates(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
								   BYTE keyInformationTemplate,
								   OP201_KEY_INFORMATION *keyInformation, PDWORD keyInformationLength) {
	OPGP_ERROR_STATUS status;
	DWORD i;
	GP211_SECURITY_INFO gp211secInfo;
	GP211_KEY_INFORMATION *gp211keyInformation;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	gp211keyInformation =
		(GP211_KEY_INFORMATION *)malloc(sizeof(GP211_KEY_INFORMATION)* (*keyInformationLength));
	if (gp211keyInformation == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
		goto end;
	}

	status = get_key_information_templates(cardContext, cardInfo, &gp211secInfo, keyInformationTemplate,
		gp211keyInformation, keyInformationLength);
	for (i=0; i<*keyInformationLength; i++) {
		mapGP211ToOP201KeyInformation(gp211keyInformation[i], &(keyInformation[i]));
	}

	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
end:
	if (keyInformation)
		free(keyInformation);
	return status;
}

/**
 *
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardElement [in] Identifier for Load Files, Applications or the Card Manager.
 * \param AID [in] The AID.
 * \param AIDLength [in] The length of the AID.
 * \param lifeCycleState [in] The new life cycle state.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_set_status(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo, BYTE cardElement, PBYTE AID, DWORD AIDLength, BYTE lifeCycleState) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	status = set_status(cardContext, cardInfo, &gp211secInfo, cardElement, AID, AIDLength, lifeCycleState);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return status;
}

/**
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardElement [in] Identifier to retrieve data for Load Files, Applications or the Card Manager.
 * \param *applData [out] The OP201_APPLICATION_DATA structure containing AID, life cycle state and privileges.
 * \param applDataLength [in, out] The number of OP201_APPLICATION_DATA passed and returned.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_get_status(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo, BYTE cardElement, OP201_APPLICATION_DATA *applData, PDWORD applDataLength) {
	OPGP_ERROR_STATUS status;
	DWORD sendBufferLength=8;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[8];
	DWORD j,i=0;
	OPGP_LOG_START(_T("get_status"));
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

		status = OP201_send_APDU(cardContext, cardInfo, secInfo, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
		if (status.errorCode != OPGP_ISO7816_ERROR_MORE_DATA_AVAILABLE) {
			CHECK_SW_9000(recvBuffer, recvBufferLength, status);
		}

		for (j=0; j<recvBufferLength-2; ) {
			if (*applDataLength <= i ) {
				{ OPGP_ERROR_CREATE_ERROR(status, OP201_ERROR_MORE_APPLICATION_DATA, OPGP_stringify_error(OP201_ERROR_MORE_APPLICATION_DATA)); goto end; }
			}
			applData[i].AIDLength = recvBuffer[j++];
			memcpy(applData[i].AID, recvBuffer+j, applData[i].AIDLength);
			j+=applData[i].AIDLength;
			applData[i].lifeCycleState = recvBuffer[j++];
			applData[i].privileges = recvBuffer[j++];
			i++;
		}
		sendBuffer[3]=0x01;
	} while (status.errorCode == OPGP_ISO7816_ERROR_MORE_DATA_AVAILABLE);

	*applDataLength = i;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("get_status"), status);
	return status;
}

/**
 * An install_for_load() must precede.
 * The Load File Data Block DAP block(s) must be the same block(s) and in the same order like in calculate_load_file_DAP().
 * If no Load File Data Block DAP blocks are necessary the dapBlock must be NULL and the dapBlockLength 0.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param *dapBlock [in] A pointer to OP201_DAP_BLOCK structure(s).
 * \param dapBlockLength [in] The number of OP201_DAP_BLOCK structure(s).
 * \param executableLoadFileName [in] The name of the CAP or IJC file to load.
 * \param *receiptData [out] If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * Can be validated with validate_load_receipt().
 * \param receiptDataAvailable [out] 0 if no receiptData is available.
 * \param *callback [in] A pointer to a #OPGP_PROGRESS_CALLBACK defining the callback function and optional parameters for it.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_load(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				 OP201_DAP_BLOCK *dapBlock, DWORD dapBlockLength, OPGP_STRING executableLoadFileName,
				 OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable, OPGP_PROGRESS_CALLBACK *callback) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO gp211secInfo;
	GP211_RECEIPT_DATA gp211receiptData;
	GP211_DAP_BLOCK *gp211dapBlock = NULL;
	DWORD i;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	gp211dapBlock = (GP211_DAP_BLOCK *)malloc(sizeof(GP211_DAP_BLOCK)*dapBlockLength);
	if (gp211dapBlock == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
		goto end;
	}

	for (i=0; i<dapBlockLength; i++) {
		mapOP201ToGP211DAPBlock(dapBlock[i], &(gp211dapBlock[i]));
	}
	status = load(cardContext, cardInfo, &gp211secInfo, gp211dapBlock, dapBlockLength,
		executableLoadFileName, &gp211receiptData, receiptDataAvailable, callback);
	if (*receiptDataAvailable)
		mapGP211ToOP201ReceiptData(gp211receiptData, receiptData);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
end:
	if (gp211dapBlock)
		free(gp211dapBlock);
	return status;
}

/**
 * An install_for_load() must precede.
 * The Load File Data Block DAP block(s) must be the same block(s) and in the same order like in calculate_load_file_DAP().
 * If no Load File Data Block DAP blocks are necessary the dapBlock must be NULL and the dapBlockLength 0.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param *dapBlock [in] A pointer to OP201_DAP_BLOCK structure(s).
 * \param dapBlockLength [in] The number of OP201_DAP_BLOCK structure(s).
 * \param loadFileBuf [in] buffer with the contents of a Executable Load File.
 * \param loadFileBufSize [in] size of loadFileBuf.
 * \param *receiptData [out] If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * Can be validated with validate_load_receipt().
 * \param receiptDataAvailable [out] 0 if no receiptData is available.
 * \param *callback [in] A pointer to a #OPGP_PROGRESS_CALLBACK defining the callback function and optional parameters for it.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_load_from_buffer(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
				 OP201_DAP_BLOCK *dapBlock, DWORD dapBlockLength,
				 PBYTE loadFileBuf, DWORD loadFileBufSize,
				 OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable, OPGP_PROGRESS_CALLBACK *callback) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO gp211secInfo;
	GP211_RECEIPT_DATA gp211receiptData;
	GP211_DAP_BLOCK *gp211dapBlock = NULL;
	DWORD i;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	gp211dapBlock = (GP211_DAP_BLOCK *)malloc(sizeof(GP211_DAP_BLOCK)*dapBlockLength);
	if (gp211dapBlock == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
		goto end;
	}

	for (i=0; i<dapBlockLength; i++) {
		mapOP201ToGP211DAPBlock(dapBlock[i], &(gp211dapBlock[i]));
	}
	status = load_from_buffer(cardContext, cardInfo, &gp211secInfo, gp211dapBlock, dapBlockLength,
		loadFileBuf, loadFileBufSize, &gp211receiptData, receiptDataAvailable, callback);
	if (*receiptDataAvailable)
		mapGP211ToOP201ReceiptData(gp211receiptData, receiptData);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
end:
	if (gp211dapBlock)
		free(gp211dapBlock);
	return status;
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
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param executableLoadFileAID [in] A buffer with AID of the Executable Load File to INSTALL [for load].
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param securityDomainAID [in] A buffer containing the AID of the intended associated Security Domain.
 * \param securityDomainAIDLength [in] The length of the Security Domain AID.
 * \param loadFileDAP [in] The load file DAP of the Executable Load File to INSTALL [for load].
 * \param loadToken [in] The Load Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param nonVolatileCodeSpaceLimit [in] The minimum amount of space that must be available to store the package.
 * \param volatileDataSpaceLimit [in] The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit [in] The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_install_for_load(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
					  PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
					  DWORD securityDomainAIDLength, BYTE loadFileDAP[20], BYTE loadToken[128],
					  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
					  DWORD nonVolatileDataSpaceLimit) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	status = install_for_load(cardContext, cardInfo, &gp211secInfo, executableLoadFileAID,
		executableLoadFileAIDLength, securityDomainAID, securityDomainAIDLength,
		loadFileDAP, loadToken, nonVolatileCodeSpaceLimit,
		volatileDataSpaceLimit, nonVolatileDataSpaceLimit);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return status;
}

/**
 * In the case of delegated management an Install Token authorizing the INSTALL [for install] must be included.
 * Otherwise installToken must be NULL. See calculate_install_token().
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tag.
 * For Security domains look in your manual what parameters are necessary.
 * If the tag for application install parameters is mandatory for your card, but you have no install parameters
 * for the install() method of the application anyway you have to use at least a dummy parameter.
 * If AIDWithinLoadFileAID is NULL and AIDWithinLoadFileAIDLength is 0 applicationInstanceAID is assumed for AIDWithinLoadFileAID
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param executableLoadFileAID [in] A buffer with AID of the Executable Load File to INSTALL [for install].
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param AIDWithinLoadFileAID [in] The AID of the application class in the package.
 * \param AIDWithinLoadFileAIDLength [in] The length of the AIDWithinLoadFileAID buffer.
 * \param applicationInstanceAID [in] The AID of the installed application.
 * \param applicationInstanceAIDLength [in] The length of the application instance AID.
 * \param applicationPrivileges [in] The application privileges. Can be an OR of multiple privileges. See OP201_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit [in] The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit [in] The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param applicationInstallParameters [in] Applet install parameters for the install() method of the application.
 * \param applicationInstallParametersLength [in] The length of the applicationInstallParameters buffer.
 * \param installToken [in] The Install Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param *receiptData [out] If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * \param receiptDataAvailable [out] 0 if no receiptData is available.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_install_for_install(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE AIDWithinLoadFileAID,
						 DWORD AIDWithinLoadFileAIDLength, PBYTE applicationInstanceAID,
						 DWORD applicationInstanceAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE applicationInstallParameters, DWORD applicationInstallParametersLength,
						 BYTE installToken[128], OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO gp211secInfo;
	GP211_RECEIPT_DATA gp211receiptData;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	status = install_for_install(cardContext, cardInfo, &gp211secInfo, executableLoadFileAID,
		executableLoadFileAIDLength, AIDWithinLoadFileAID, AIDWithinLoadFileAIDLength,
		applicationInstanceAID, applicationInstanceAIDLength,
		applicationPrivileges, volatileDataSpaceLimit, nonVolatileDataSpaceLimit,
		applicationInstallParameters, applicationInstallParametersLength, installToken,
		&gp211receiptData, receiptDataAvailable);
	if (*receiptDataAvailable)
		mapGP211ToOP201ReceiptData(gp211receiptData, receiptData);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return status;
}

/**
 * In the case of delegated management an Install Token authorizing the INSTALL [for install and make selectable] must be included.
 * Otherwise installToken must be NULL. See calculate_install_token().
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tag.
 * For Security domains look in your manual what parameters are necessary.
 * If the tag for application install parameters is mandatory for your card, but you have no install parameters
 * for the install() method of the application anyway you have to use at least a dummy parameter.
 * If AIDWithinLoadFileAID is NULL and AIDWithinLoadFileAIDLength is 0 applicationInstanceAID is assumed for AIDWithinLoadFileAID.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param *secInfo [in, out] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param executableLoadFileAID [in] A buffer with AID of the Executable Load File to INSTALL [for install].
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param AIDWithinLoadFileAID [in] The AID of the application class in the package.
 * \param AIDWithinLoadFileAIDLength [in] The length of the AIDWithinLoadFileAID buffer.
 * \param applicationInstanceAID [in] The AID of the installed application.
 * \param applicationInstanceAIDLength [in] The length of the application instance AID.
 * \param applicationPrivileges [in] The application privileges. Can be an OR of multiple privileges. See OP201_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit [in] The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit [in] The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param applicationInstallParameters [in] Applet install parameters for the install() method of the application.
 * \param applicationInstallParametersLength [in] The length of the applicationInstallParameters buffer.
 * \param installToken [in] The Install Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param *receiptData [out] If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * \param receiptDataAvailable [out] 0 if no receiptData is available.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_install_for_install_and_make_selectable(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
						 PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE AIDWithinLoadFileAID,
						 DWORD AIDWithinLoadFileAIDLength, PBYTE applicationInstanceAID,
						 DWORD applicationInstanceAIDLength, BYTE applicationPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE applicationInstallParameters, DWORD applicationInstallParametersLength,
						 BYTE installToken[128], OP201_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO gp211secInfo;
	GP211_RECEIPT_DATA gp211receiptData;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	status = install_for_install_and_make_selectable(cardContext, cardInfo, &gp211secInfo, executableLoadFileAID,
		executableLoadFileAIDLength, AIDWithinLoadFileAID, AIDWithinLoadFileAIDLength,
		applicationInstanceAID, applicationInstanceAIDLength,
		applicationPrivileges, volatileDataSpaceLimit, nonVolatileDataSpaceLimit,
		applicationInstallParameters, applicationInstallParametersLength, installToken,
		&gp211receiptData, receiptDataAvailable);
	if (*receiptDataAvailable)
		mapGP211ToOP201ReceiptData(gp211receiptData, receiptData);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return status;
}

/**
 * In the case of delegated management an Install Token authorizing the INSTALL [for make selectable] must be included.
 * Otherwise installToken must be NULL.
 * For Security domains look in your manual what parameters are necessary.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param *secInfo [in, out] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param applicationInstanceAID [in] The AID of the installed application or security domain.
 * \param applicationInstanceAIDLength [in] The length of the application instance AID.
 * \param applicationPrivileges [in] The application privileges. Can be an OR of multiple privileges. See OP201_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param installToken [in] The Install Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param *receiptData [out] If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * \param receiptDataAvailable [out] 0 if no receiptData is available.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_install_for_make_selectable(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo,
								 PBYTE applicationInstanceAID,
								 DWORD applicationInstanceAIDLength, BYTE applicationPrivileges,
								 BYTE installToken[128], OP201_RECEIPT_DATA *receiptData,
								 PDWORD receiptDataAvailable) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO gp211secInfo;
	GP211_RECEIPT_DATA gp211receiptData;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	status = install_for_make_selectable(cardContext, cardInfo, &gp211secInfo, applicationInstanceAID, applicationInstanceAIDLength, applicationPrivileges, installToken,
		&gp211receiptData, receiptDataAvailable);
	if (*receiptDataAvailable)
		mapGP211ToOP201ReceiptData(gp211receiptData, receiptData);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return status;
}

/**
 * If you are not the Card Issuer and do not know the token verification private key send this data to the
 * Card Issuer and obtain the RSA signature of the data, i.e. the Install Token.
 * volatileDataSpaceLimit can be 0, if the card does not need or support this tag.
 * The parameters must match the parameters of a later install_for_install() and install_for_make_selectable() method.
 * \param P1 [in] The parameter P1 in the APDU command.
 * <ul>
 * <li> 0x04 for a INSTALL [for install] command </li>
 * <li> 0x08 for an INSTALL [for make selectable] command </li>
 * <li> 0x0C for an INSTALL [for install and make selectable] </li>
 * </ul>
 * \param executableLoadFileAID [in] A buffer with AID of the Executable Load File to INSTALL [for load].
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param AIDWithinLoadFileAID [in] The AID of the application class in the package.
 * \param AIDWithinLoadFileAIDLength [in] The length of the AIDWithinLoadFileAID buffer.
 * \param applicationInstanceAID [in] The AID of the installed application.
 * \param applicationInstanceAIDLength [in] The length of the application instance AID.
 * \param applicationPrivileges [in] The application privileges. Can be an OR of multiple privileges. See OP201_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit [in] The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit [in] The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param applicationInstallParameters [in] Applet install parameters for the install() method of the application.
 * \param applicationInstallParametersLength [in] The length of the applicationInstallParameters buffer.
 * \param installTokenSignatureData [out] The data to sign in a Install Token.
 * \param installTokenSignatureDataLength [in, out] The length of the installTokenSignatureData buffer.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_get_install_token_signature_data(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE AIDWithinLoadFileAID,
									  DWORD AIDWithinLoadFileAIDLength, PBYTE applicationInstanceAID,
									  DWORD applicationInstanceAIDLength, BYTE applicationPrivileges,
									  DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
									  PBYTE applicationInstallParameters, DWORD applicationInstallParametersLength,
									  PBYTE installTokenSignatureData, PDWORD installTokenSignatureDataLength) {
	OPGP_ERROR_STATUS status;
	status = get_install_data(P1, executableLoadFileAID, executableLoadFileAIDLength,
		AIDWithinLoadFileAID, AIDWithinLoadFileAIDLength, applicationInstanceAID,
		applicationInstanceAIDLength, applicationPrivileges, volatileDataSpaceLimit,
		nonVolatileDataSpaceLimit, applicationInstallParameters, applicationInstallParametersLength,
		installTokenSignatureData, installTokenSignatureDataLength);
	return status;
}

/**
 * The parameters must match the parameters of a later install_for_install(), install_for_make_selectable() and install_for_install_and_make_selectable() method.
 * \param P1 [in] The parameter P1 in the APDU command.
 * <ul>
 * <li> 0x04 for a INSTALL [for install] command </li>
 * <li> 0x08 for an INSTALL [for make selectable] command </li>
 * <li> 0x0C for an INSTALL [for install and make selectable] </li>
 * </ul>
 * \param executableLoadFileAID [in] A buffer with AID of the Executable Load File to INSTALL [for install].
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param AIDWithinLoadFileAID [in] The AID of the application class in the package.
 * \param AIDWithinLoadFileAIDLength [in] The length of the AIDWithinLoadFileAID buffer.
 * \param applicationInstanceAID [in] The AID of the installed application.
 * \param applicationInstanceAIDLength [in] The length of the application instance AID.
 * \param applicationPrivileges [in] The application privileges. Can be an OR of multiple privileges. See OP201_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit [in] The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit [in] The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param applicationInstallParameters [in] Applet install parameters for the install() method of the application.
 * \param applicationInstallParametersLength [in] The length of the applicationInstallParameters buffer.
 * \param installToken [out] The calculated Install Token. A 1024 bit RSA signature.
 * \param PEMKeyFileName [in] A PEM file name with the private RSA key.
 * \param *passPhrase [in] The passphrase. Must be an ASCII string.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_calculate_install_token(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE AIDWithinLoadFileAID,
							 DWORD AIDWithinLoadFileAIDLength, PBYTE applicationInstanceAID, DWORD applicationInstanceAIDLength,
							 BYTE applicationPrivileges, DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
							 PBYTE applicationInstallParameters, DWORD applicationInstallParametersLength,
							 BYTE installToken[128], OPGP_STRING PEMKeyFileName, char *passPhrase) {
	OPGP_ERROR_STATUS status;
	status = calculate_install_token(P1, executableLoadFileAID, executableLoadFileAIDLength,
		AIDWithinLoadFileAID, AIDWithinLoadFileAIDLength, applicationInstanceAID, applicationInstanceAIDLength,
		applicationPrivileges, volatileDataSpaceLimit, nonVolatileDataSpaceLimit,
		applicationInstallParameters, applicationInstallParametersLength, installToken,
		PEMKeyFileName, passPhrase);
	return status;
}

/**
 * If you are not the Card Issuer and do not know the token verification private key send this data to the
 * Card Issuer and obtain the RSA signature of the data, i.e. the Load Token.
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tags.
 * The parameters must match the parameters of a later install_for_load() command.
 * \param executableLoadFileAID [in] A buffer containing the Executable Load File AID.
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param securityDomainAID [in] A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength [in] The length of the Security Domain AID.
 * \param loadFileDAP [in] The Load File DAP. The same calculated as in install_for_load().
 * \param nonVolatileCodeSpaceLimit [in] The minimum space required to store the application code.
 * \param volatileDataSpaceLimit [in] The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit [in] The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param loadTokenSignatureData [out] The data to sign in a Load Token.
 * \param loadTokenSignatureDataLength [in, out] The length of the loadTokenSignatureData buffer.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_get_load_token_signature_data(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
								   DWORD securityDomainAIDLength, BYTE loadFileDAP[20],
								   DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
								   DWORD nonVolatileDataSpaceLimit, PBYTE loadTokenSignatureData,
								   PDWORD loadTokenSignatureDataLength) {
	BYTE buf[258];
	DWORD i=0;
#ifdef DEBUG
	DWORD j=0;
#endif
	DWORD hiByte, loByte;
	DWORD staticSize;
	OPGP_ERROR_STATUS status;
	OPGP_LOG_START(_T("OP201_get_load_token_signature_data"));
	if (loadFileDAP == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, OP201_ERROR_LOAD_FILE_DAP_NULL, OPGP_stringify_error(OP201_ERROR_LOAD_FILE_DAP_NULL));
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
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
	memcpy(loadTokenSignatureData, buf, i);
	*loadTokenSignatureDataLength = i;
#ifdef DEBUG
	OPGP_log_Msg(_T("OP201_get_load_token_signature_data: P1: 0x%02x"), loadTokenSignatureData[j++]);
	OPGP_log_Msg(_T("OP201_get_load_token_signature_data: P2: 0x%02x"), loadTokenSignatureData[j++]);
	OPGP_log_Msg(_T("OP201_get_load_token_signature_data: Lc: 0x%02x"), loadTokenSignatureData[j++]);
	OPGP_log_Msg(_T("OP201_get_load_token_signature_data: Load file AID length indicator: 0x%02x"), loadTokenSignatureData[j++]);
	OPGP_log_Hex(_T("OP201_get_load_token_signature_data: Load file AID: "), loadTokenSignatureData+(j-1), *loadTokenSignatureDataLength-(j-1));
	j+=loadTokenSignatureData[j-1];
	OPGP_log_Msg(_T("OP201_get_load_token_signature_data: Security Domain AID length indicator: 0x%02x"), loadTokenSignatureData[j++]);
	OPGP_log_Hex(_T("OP201_get_load_token_signature_data: Security Domain AID: "), loadTokenSignatureData+(j-1), *loadTokenSignatureDataLength-(j-1));
	j+=loadTokenSignatureData[j-1];
	OPGP_log_Msg(_T("OP201_get_load_token_signature_data: Load parameters length indicator: 0x%02x"), loadTokenSignatureData[j++]);
	OPGP_log_Hex(_T("OP201_get_load_token_signature_data: Load parameters: "), loadTokenSignatureData+(j-1), *loadTokenSignatureDataLength-(j-1));
	j+=loadTokenSignatureData[j-1];
	OPGP_log_Hex(_T("OP201_get_load_token_signature_data: Hash of Load File: "), loadTokenSignatureData+j, 20);
	j+=loadTokenSignatureData[j-1];
#endif
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("OP201_get_load_token_signature_data"), status);
	return status;
}

/**
 * The parameters must match the parameters of a later install_for_load() method.
 * \param executableLoadFileAID [in] A buffer containing the Executable Load File AID.
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param securityDomainAID [in] A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength [in] The length of the Security Domain AID.
 * \param loadFileDAP [in] The Load File DAP. The same calculated as in install_for_load().
 * \param nonVolatileCodeSpaceLimit [in] The minimum space required to store the package.
 * \param volatileDataSpaceLimit [in] The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit [in] The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param loadToken [out] The calculated Load Token. A 1024 bit RSA signature.
 * \param PEMKeyFileName [in] A PEM file name with the private RSA key.
 * \param *passPhrase [in] The passphrase. Must be an ASCII string.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_calculate_load_token(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength, PBYTE securityDomainAID,
						  DWORD securityDomainAIDLength, BYTE loadFileDAP[20],
						  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
						  DWORD nonVolatileDataSpaceLimit, BYTE loadToken[128],
						  OPGP_STRING PEMKeyFileName, char *passPhrase) {
	OPGP_ERROR_STATUS status;
	BYTE loadTokenSignatureData[256];
	DWORD loadTokenSignatureDataLength = 256;
	OPGP_LOG_START(_T("calculate_load_token"));
	status = OP201_get_load_token_signature_data(executableLoadFileAID, executableLoadFileAIDLength, securityDomainAID, securityDomainAIDLength,
		loadFileDAP, nonVolatileCodeSpaceLimit, volatileDataSpaceLimit, nonVolatileDataSpaceLimit, loadTokenSignatureData, &loadTokenSignatureDataLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	status = calculate_rsa_signature(loadTokenSignatureData, loadTokenSignatureDataLength, PEMKeyFileName,
									passPhrase, loadToken);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("calculate_load_token"), status);
	return status;
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
 * \param *dapBlock [in] A pointer to OP201_DAP_BLOCK structure(s).
 * \param dapBlockLength [in] The number of OP201_DAP_BLOCK structure(s).
 * \param executableLoadFileName [in] The name of the CAP or IJC file to hash.
 * \param hash [out] The hash value. This are 20 bytes.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_calculate_load_file_DAP(OP201_DAP_BLOCK *dapBlock, DWORD dapBlockLength, OPGP_STRING executableLoadFileName,
							 BYTE hash[20])
{
	OPGP_ERROR_STATUS status;
	int count;
	DWORD k,j,i;
	BYTE buf[4];

	BYTE dapBuf[256];
	DWORD dapBufSize=sizeof(dapBuf);

	PBYTE loadFileBuf = NULL;
	DWORD loadFileBufSize;

	PBYTE temp = NULL;
	DWORD tempSize = 0;

	OPGP_LOG_START(_T("OP201_calculate_load_file_DAP"));
	if ((executableLoadFileName == NULL) || (_tcslen(executableLoadFileName) == 0))
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_FILENAME, OPGP_stringify_error(OPGP_ERROR_INVALID_FILENAME)); goto end; }

	for (i=0; i<dapBlockLength; i++) {
#ifdef DEBUG
		OPGP_log_Msg(_T("OP201_calculate_load_file_DAP: Hashing DAP block %lu."), i);
#endif
		j=0;
		k = dapBufSize;
		status = readDAPBlock(dapBuf, &k, dapBlock[i]);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
		tempSize += k;
		temp = realloc(temp, tempSize);
		if (temp == NULL) {
			OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
			goto end;
		}
		memcpy(temp+tempSize-k, dapBuf, k);
	}

	status = handle_load_file((OPGP_CSTRING)executableLoadFileName, loadFileBuf, &loadFileBufSize);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	loadFileBuf = (PBYTE)malloc(sizeof(BYTE) * loadFileBufSize);
	if (loadFileBuf == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
		goto end;
	}
	status = handle_load_file((OPGP_CSTRING)executableLoadFileName, loadFileBuf, &loadFileBufSize);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	if (loadFileBufSize < 128L) {
		buf[0] = 0xC4;
		buf[1] = (BYTE)loadFileBufSize;
		count=2;
	}
	else if (loadFileBufSize < 256L) {
		buf[0] = 0xC4;
		buf[1] = 0x81;
		buf[2] = (BYTE)loadFileBufSize;
		count=3;
	}
	else if (loadFileBufSize < 32536L) {
		buf[0] = 0xC4;
		buf[1] = 0x82;
		buf[2] = (BYTE)(loadFileBufSize >> 8);
		buf[3] = (BYTE)(loadFileBufSize - (buf[2] << 8));
		count=4;
	}
	else {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_APPLICATION_TOO_BIG, OPGP_stringify_error(OPGP_ERROR_APPLICATION_TOO_BIG)); goto end; }
	}
	tempSize += count;
	temp = realloc(temp, tempSize);
	if (temp == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
		goto end;
	}
	memcpy(temp+tempSize-count, buf, count);

	tempSize += loadFileBufSize;
	temp = realloc(temp, tempSize);
	if (temp == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
		goto end;
	}
	memcpy(temp+tempSize-loadFileBufSize, loadFileBuf, loadFileBufSize);

	status = calculate_sha1_hash(temp, tempSize, hash);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if (loadFileBuf != NULL) {
		free(loadFileBuf);
	}
	if (temp != NULL) {
		free(temp);
	}
	OPGP_LOG_END(_T("calculate_load_file_DAP"), status);
	return status;
}

/**
 * If a security domain has DAP verification privilege the security domain validates this DAP.
 * \param securityDomainAID [in] A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength [in] The length of the Security Domain AID.
 * \param executableLoadFileName [in] The name of the CAP or IJC file to calculate the DAP for.
 * \param DAP_verification_key [in] The key to calculate the DAP.
 * \param *dapBlock [out] A pointer to the returned OP201_DAP_BLOCK structure.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_calculate_3des_DAP(PBYTE securityDomainAID, DWORD securityDomainAIDLength, OPGP_STRING executableLoadFileName,
						BYTE DAP_verification_key[16], OP201_DAP_BLOCK *dapBlock)
{
	OPGP_ERROR_STATUS status;
	PBYTE loadFileBuf = NULL;
	DWORD loadFileBufSize;
	OPGP_LOG_START(_T("calculate_3des_DAP"));
	if ((executableLoadFileName == NULL) || (_tcslen(executableLoadFileName) == 0))
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_FILENAME, OPGP_stringify_error(OPGP_ERROR_INVALID_FILENAME)); goto end; }

	status = handle_load_file((OPGP_CSTRING)executableLoadFileName, loadFileBuf, &loadFileBufSize);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	loadFileBuf = (PBYTE)malloc(sizeof(BYTE) * loadFileBufSize);
	if (loadFileBuf == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
		goto end;
	}
	status = handle_load_file((OPGP_CSTRING)executableLoadFileName, loadFileBuf, &loadFileBufSize);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	status = calculate_MAC_des_3des(DAP_verification_key, loadFileBuf, loadFileBufSize, NULL, dapBlock->signature);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	dapBlock->signatureLength = 8;
	memcpy(dapBlock->securityDomainAID, securityDomainAID, securityDomainAIDLength);
	dapBlock->securityDomainAIDLength = (BYTE)securityDomainAIDLength;

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if (loadFileBuf != NULL) {
		free(loadFileBuf);
	}
	OPGP_LOG_END(_T("calculate_3des_DAP"), status);
	return status;
}

/**
 * If a security domain has DAP verification privilege the security domain validates this DAP.
 * \param securityDomainAID [in] A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength [in] The length of the Security Domain AID.
 * \param executableLoadFileName [in] The name of the CAP or IJC file to calculate the DAP for.
 * \param PEMKeyFileName [in] A PEM file name with the private RSA key.
 * \param *passPhrase [in] The passphrase. Must be an ASCII string.
 * \param *dapBlock [out] A pointer to the returned OP201_DAP_BLOCK structure.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_calculate_rsa_DAP(PBYTE securityDomainAID, DWORD securityDomainAIDLength, OPGP_STRING executableLoadFileName,
					   OPGP_STRING PEMKeyFileName, char *passPhrase, OP201_DAP_BLOCK *dapBlock)
{
	OPGP_ERROR_STATUS status;
	PBYTE loadFileBuf = NULL;
	DWORD loadFileBufSize;

	OPGP_LOG_START(_T("calculate_rsa_DAP"));

	status = handle_load_file((OPGP_CSTRING)executableLoadFileName, loadFileBuf, &loadFileBufSize);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	loadFileBuf = (PBYTE)malloc(sizeof(BYTE) * loadFileBufSize);
	if (loadFileBuf == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
		goto end;
	}
	status = handle_load_file((OPGP_CSTRING)executableLoadFileName, loadFileBuf, &loadFileBufSize);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	status = calculate_rsa_signature(loadFileBuf, loadFileBufSize, PEMKeyFileName, passPhrase, dapBlock->signature);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}

	dapBlock->signatureLength = 128;
	memcpy(dapBlock->securityDomainAID, securityDomainAID, securityDomainAIDLength);
	dapBlock->securityDomainAIDLength = (BYTE)securityDomainAIDLength;

	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if (loadFileBuf != NULL) {
		free(loadFileBuf);
	}
	OPGP_LOG_END(_T("calculate_rsa_DAP"), status);
	return status;
}

/**
 * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
 * You may keep track of it. Returns OPGP_ERROR_SUCCESS if receipt is valid.
 * \param confirmationCounter [in] The confirmation counter.
 * \param cardUniqueData [in] The card unique data (?).
 * \param receiptGenerationKey [in] The 3DES key to generate the receipt.
 * \param receiptData [in] The OP201_RECEIPT_DATA structure containing the receipt returned
 * from load_application() to verify.
 * \param executableLoadFileAID [in] A buffer with AID of the Executable Load File which was INSTALL [for load].
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param securityDomainAID [in] A buffer containing the AID of the associated Security Domain.
 * \param securityDomainAIDLength [in] The length of the Security Domain AID.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_validate_load_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receiptGenerationKey[16], OP201_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE securityDomainAID, DWORD securityDomainAIDLength) {
	OPGP_ERROR_STATUS status;
	GP211_RECEIPT_DATA gp211receiptData;
	mapOP201ToGP211ReceiptData(receiptData, &gp211receiptData);
	status = validate_load_receipt(confirmationCounter, cardUniqueData,
		10, receiptGenerationKey, gp211receiptData, executableLoadFileAID,
		executableLoadFileAIDLength, securityDomainAID, securityDomainAIDLength);
	return status;
}

/**
 * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
 * You may keep track of it. Returns OPGP_ERROR_SUCCESS if receipt is valid.
 * \param confirmationCounter [in] The confirmation counter.
 * \param cardUniqueData [in] The card unique data (?).
 * \param receiptGenerationKey [in] The 3DES key to generate the receipt.
 * \param receiptData [in] The OP201_RECEIPT_DATA structure containing the receipt returned
 * from install_for_install() to verify.
 * \param executableLoadFileAID [in] A buffer with AID of the Executable Load File which was INSTALL [for install].
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param applicationInstanceAID [in] The AID of the installed application.
 * \param applicationInstanceAIDLength [in] The length of the application instance AID.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_validate_install_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receiptGenerationKey[16], OP201_RECEIPT_DATA receiptData,
						   PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						   PBYTE applicationInstanceAID, DWORD applicationInstanceAIDLength) {
	OPGP_ERROR_STATUS status;
	GP211_RECEIPT_DATA gp211receiptData;
	mapOP201ToGP211ReceiptData(receiptData, &gp211receiptData);
	status = validate_install_receipt(confirmationCounter, cardUniqueData,
		10, receiptGenerationKey, gp211receiptData, executableLoadFileAID,
		executableLoadFileAIDLength, applicationInstanceAID, applicationInstanceAIDLength);
	return status;
}

/**
 * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
 * You may keep track of it. Returns OPGP_ERROR_SUCCESS if receipt is valid.
 * \param confirmationCounter [in] The confirmation counter.
 * \param cardUniqueData [in] The card unique data (?).
 * \param receiptGenerationKey [in] The 3DES key to generate the receipt.
 * \param receiptData [in] The OP201_RECEIPT_DATA structure containing the receipt returned
 * from delete_application() to verify.
 * \param AID [in] A buffer with AID of the application which was deleted.
 * \param AIDLength [in] The length of the AID.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_validate_delete_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receiptGenerationKey[16], OP201_RECEIPT_DATA receiptData,
						   PBYTE AID, DWORD AIDLength) {
	OPGP_ERROR_STATUS status;
	GP211_RECEIPT_DATA gp211receiptData;
	mapOP201ToGP211ReceiptData(receiptData, &gp211receiptData);
	status = validate_delete_receipt(confirmationCounter, cardUniqueData,
		10, receiptGenerationKey, gp211receiptData, AID, AIDLength);
	return status;
}

/**
 * The single numbers of the new PIN are encoded as single BYTEs in the newPIN buffer.
 * The tryLimit must be in the range of 0x03 and x0A.
 * The PIN must comprise at least 6 numbers and not exceeding 12 numbers.
 * To unblock the PIN use tryLimit with a value of 0x00. In this case newPIN buffer and newPINLength are ignored.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param *secInfo [in, out] The pointer to the OP201_SECURITY_INFO structure returned by OP201_mutual_authentication().
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param tryLimit [in] The try limit for the PIN.
 * \param newPIN [in] The new PIN.
 * \param newPINLength [in] The length of the new PIN.
 * \param KEK [in] The Key Encryption key (KEK).
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_pin_change(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, OP201_SECURITY_INFO *secInfo, BYTE tryLimit,
				PBYTE newPIN, DWORD newPINLength, BYTE KEK[16]) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO gp211secInfo;
	mapOP201ToGP211SecurityInfo(*secInfo, &gp211secInfo);
	memcpy(gp211secInfo.dataEncryptionSessionKey, KEK, 16);
	status = pin_change(cardContext, cardInfo, &gp211secInfo, tryLimit, newPIN, newPINLength);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return status;
}

/**
 * Reads a DAP block and parses it to the buffer buf.
 * \param buf [out] The buffer.
 * \param bufLength [in, out] The length of the buffer and the returned data.
 * \param dapBlock [in] The Load File Data Block DAP block.
 * \return OPGP_ERROR_SUCCESS if no error, error code else
 */
OPGP_ERROR_STATUS readDAPBlock(PBYTE buf, PDWORD bufLength, OP201_DAP_BLOCK dapBlock) {
	OPGP_ERROR_STATUS status;
	GP211_DAP_BLOCK gp211dapBlock;
	mapOP201ToGP211DAPBlock(dapBlock, &gp211dapBlock);
	status = read_load_file_data_block_signature(buf, bufLength, gp211dapBlock);
	return status;
}

/**
 * A keySetVersion and keyIndex of 0x00 selects the first available key set version and key index.
 * If a derivation method is used the baseKey defines the master key.
 * \param cardContext [in] The valid OPGP_CARD_CONTEXT returned by OPGP_establish_context()
 * \param cardInfo [in] The OPGP_CARD_INFO cardInfo, structure returned by OPGP_card_connect().
 * \param baseKey [in] The master key used for the key derivation.
 * \param encKey [in] The static encryption key.
 * \param macKey [in] The static MAC key.
 * \param kekKey [in] The static Key Encryption key.
 * \param keySetVersion [in] The key set version on the card to use for mutual authentication.
 * \param keyIndex [in] The key index of the encryption key in the key set version on the card to use for mutual authentication.
 * \param securityLevel [in] The requested security level.
 * \param derivationMethod [in] The derivation method to use for. See #OPGP_DERIVATION_METHOD_VISA2.
 * \param *secInfo [out] The returned OP201_SECURITY_INFO structure.
 * \return OPGP_ERROR_STATUS struct with error status OPGP_ERROR_STATUS_SUCCESS if no error occurs, otherwise error code  and error message are contained in the OPGP_ERROR_STATUS struct
 */
OPGP_ERROR_STATUS OP201_mutual_authentication(OPGP_CARD_CONTEXT cardContext, OPGP_CARD_INFO cardInfo, BYTE baseKey[16], BYTE encKey[16], BYTE macKey[16],
								 BYTE kekKey[16],
								 BYTE keySetVersion,
								 BYTE keyIndex, BYTE securityLevel,
								 BYTE derivationMethod,
								 OP201_SECURITY_INFO *secInfo) {
	OPGP_ERROR_STATUS status;
	GP211_SECURITY_INFO gp211secInfo;
	status = mutual_authentication(cardContext, cardInfo, baseKey, encKey, macKey, kekKey, keySetVersion,
		keyIndex, GP211_SCP01, GP211_SCP01_IMPL_i05, securityLevel, derivationMethod, &gp211secInfo);
	mapGP211ToOP201SecurityInfo(gp211secInfo, secInfo);
	return status;
}

OPGP_ERROR_STATUS calculate_install_token(BYTE P1, PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
							 PBYTE executableModuleAID,
							 DWORD executableModuleAIDLength, PBYTE applicationAID, DWORD applicationAIDLength,
							 BYTE applicationPrivileges, DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
							 PBYTE installParameters, DWORD installParametersLength,
							 BYTE installToken[128], OPGP_STRING PEMKeyFileName, char *passPhrase) {
	OPGP_ERROR_STATUS status;
	BYTE installTokenSignatureData[256];
	DWORD installTokenSignatureDataLength = 256;
	OPGP_LOG_START(_T("calculate_install_token"));
	status = get_install_data(P1, executableLoadFileAID, executableLoadFileAIDLength,
		executableModuleAID, executableModuleAIDLength, applicationAID,
		applicationAIDLength, applicationPrivileges, volatileDataSpaceLimit,
		nonVolatileDataSpaceLimit, installParameters,
		installParametersLength, installTokenSignatureData, &installTokenSignatureDataLength);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	status = calculate_rsa_signature(installTokenSignatureData, installTokenSignatureDataLength, PEMKeyFileName,
									passPhrase, installToken);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:

	OPGP_LOG_END(_T("calculate_install_token"), status);
	return status;
}
