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

/*! \mainpage Open Platform Service Provider
 *
 * \author Karsten Ohme
 * \section intro_sec Introduction
 *
 * This library offers functions to manage a Open Platform 2.0.1' conforming card.
 *
 * The following terms are used different from the Open Platform 2.0.1' specification:
 * <ul>
 * <li>
 * The term CAP file is equivalent to the Open Platform term Load File Data Block and can be any
 * file format which is accepted by the underlying runtime environment. The CAP file format is used
 * by the Java Card Runtime Environment. Another popular formats also for the Java Card RE is the Interoperable
 * Java Card CAP format (IJC).
 * </li>
 * <li>
 * The term package is equivalent to the Open Platform term Load File and should be treated like this.
 * In contrast to the Open Platform specification this load file does not necessarily include DAP blocks.
 * They can be also be given separately to the according functions.
 * </li>
 * <li>
 * The term applet class has the meaning of the Open Platform term AID within Load File.
 * </li>
 * <li>
 * The term applet instance is equal to the the Open Platform application instance.
 * </li>
 * <li>
 * The term applet is also Java Card specific and is the same as a Open Platform application.
 * </li>
 * <p>
 * Before you call a card related command make sure that the Card Manager or Security Domain you 
 * want to use for the command is selected by select_application().
 * </p>
 * </ul>
 *
 */
#ifdef WIN32
#include "stdafx.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include "OpenPlatform.h"
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#ifndef WIN32
#include <sys/stat.h>
#endif
#include "debug.h"

#define MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING 239

static unsigned char padding[8] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //!< Applied padding pattern.
static unsigned char icv[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}; //!< First initial chaining vector.

static LONG get_capabilities(OPSP_CARDHANDLE cardHandle);

static LONG create_session_key(unsigned char key[16], unsigned char card_challenge[8],
							   unsigned char host_challenge[8], unsigned char session_key[16]);

static LONG calculate_rsa_signature(PBYTE message, DWORD messageLength, OPSP_STRING PEMKeyFileName,
									char *passPhrase, BYTE signature[128]);

static LONG calculate_MAC(unsigned char session_key[16], unsigned char *message, int messageLength,
						  unsigned char icv[8], unsigned char mac[8]);

static LONG calculate_card_cryptogram(unsigned char session_enc_key[16], unsigned char card_challenge[8],
									  unsigned char host_challenge[8], unsigned char card_cryptogram[8]);

static LONG calculate_host_cryptogram(unsigned char session_enc_key[16], unsigned char card_challenge[8],
									  unsigned char host_challenge[8], unsigned char host_cryptogram[8]);

static LONG wrap_command(PBYTE apduCommand, DWORD apduCommandLength, PBYTE wrappedApduCommand,
						 PDWORD wrappedApduCommandLength, OPSP_SECURITY_INFO *secInfo);

static LONG calculate_enc_cbc(unsigned char session_key[16], unsigned char *message, int messageLength,
							  unsigned char *encryption, int *encryptionLength);

static LONG calculate_enc_ecb(unsigned char key[16], unsigned char *message, int messageLength,
							  unsigned char *encryption, int *encryptionLength);

static LONG validate_receipt(PBYTE validationData, DWORD validationDataLength,
							 BYTE receipt[16], BYTE receipt_generation_key[16]);

static LONG calculate_MAC_des_3des(unsigned char _3des_key[16], unsigned char *message, int messageLength,
						  unsigned char icv[8], unsigned char mac[8]);

/**
 * Reads a valid buffer containing a (delete, load, install) receipt and parses it in a OPSP_RECEIPT_DATA.
 * \param buf IN The buffer to parse.
 * \param receiptData OUT The receipt data.
 * \return The number of bytes which were consumed while parsing the buffer.
 */
static DWORD fillReceipt(PBYTE buf, OPSP_RECEIPT_DATA *receiptData) {
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
 * \param dapBlock IN The Load File Data Block DAP block.
 * \return OPSP_ERROR_SUCCESS if no error, error code else
 */
static LONG readDAPBlock(PBYTE buf, PDWORD bufLength, OPSP_DAP_BLOCK dapBlock) {
	DWORD j=0;
	LOG_START(_T("readDAPBlock"));
	if ((DWORD)dapBlock.DAPBlockLength+1 > *bufLength) {
		return OPSP_ERROR_INSUFFICIENT_BUFFER;
	}
	buf[j++] = 0xE2; // Tag indicating a DAP block.
	buf[j++] = dapBlock.DAPBlockLength;
	buf[j++] = 0x4F; // Tag indicating a Security Domain AID.
	buf[j++] = dapBlock.securityDomainAIDLength;
	memcpy(buf+j, dapBlock.securityDomainAID, dapBlock.securityDomainAIDLength);
	j+=dapBlock.securityDomainAIDLength;
	buf[j++] = 0xC3; // The Tag indicating a signature
	buf[j++] = dapBlock.signatureLength;
	memcpy(buf+j, dapBlock.signature, dapBlock.signatureLength);
	j+=dapBlock.signatureLength;
	LOG_END(_T("readDAPBlock"), OPSP_ERROR_SUCCESS);
	return OPSP_ERROR_SUCCESS;
}

/**
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param cardInfo OUT The OPSP_CARD_INFO containing mechanical card state, protocol information and the ATR.
 * \return OPSP_ERROR_SUCCESS if no error, error code else
 */
LONG get_card_status(OPSP_CARDHANDLE cardHandle, OPSP_CARD_INFO *cardInfo) {
	LONG result;
	OPSP_STRING readerName;
	DWORD readerNameLength=100;
	DWORD state;
	DWORD protocol;
	BYTE ATR[32];
	DWORD ATRLength=32;
	LOG_START(_T("get_card_status"));
	readerName=(OPSP_STRING)malloc(sizeof(TCHAR)*readerNameLength);
	result = SCardStatus(cardHandle, readerName, &readerNameLength, &state, &protocol, ATR, &ATRLength);
	if ( SCARD_S_SUCCESS != result ) {
		goto end;
	}
	memcpy(cardInfo->ATR, ATR, 32);
	cardInfo->protocol = protocol;
	cardInfo->ATRLength = ATRLength;
	cardInfo->state = state;
	result = OPSP_ERROR_SUCCESS;
end:
	LOG_END(_T("get_card_status"), result);
	return result;
}

/**
 * \param cardContext OUT The returned POPSP_CARDCONTEXT.
 * \return OPSP_ERROR_SUCCESS if no error, error code else
 */
LONG establish_context(OPSP_CARDCONTEXT *cardContext) {
	LONG result;
	LOG_START(_T("establish_context"));
	result = SCardEstablishContext( SCARD_SCOPE_USER,
									NULL,
									NULL,
									cardContext);
	if ( SCARD_S_SUCCESS != result ) {
		goto end;
	}
	result = OPSP_ERROR_SUCCESS;
end:
	LOG_END(_T("establish_context"), result);
	return result;
}

/**
 * \param cardContext IN The valid OPSP_CARDCONTEXT returned by establish_context()
 * \return OPSP_ERROR_SUCCESS if no error, error code else
 */
LONG release_context(OPSP_CARDCONTEXT cardContext) {
	LONG result;
	LOG_START(_T("release_context"));
	result = SCardReleaseContext(cardContext);
	if ( SCARD_S_SUCCESS != result ) {
		goto end;
	}
	result = OPSP_ERROR_SUCCESS;
end:
	LOG_END(_T("release_context"), result);
	return result;
}

/**
 * \param cardContext IN The valid OPSP_CARDCONTEXT returned by establish_context()
 * \param readerNames OUT The reader names will be a multi-string and separated by a NULL character and ended by a double NULL.
 *  (ReaderA\\0ReaderB\\0\\0). If this value is NULL, list_readers ignores the buffer length supplied in
 *  readerNamesLength, writes the length of the multi-string that would have been returned if this parameter
 *  had not been NULL to readerNamesLength.
 * \param readerNamesLength INOUT The length of the multi-string including all trailing null characters.
 * \return OPSP_ERROR_SUCCESS if no error, error code else
 */
LONG list_readers(OPSP_CARDCONTEXT cardContext, OPSP_STRING readerNames, PDWORD readerNamesLength) {
	LONG result;
	DWORD readersSize;
	OPSP_STRING readers = NULL;
	LOG_START(_T("list_readers"));
	result = SCardListReaders( cardContext, NULL, NULL, &readersSize );
	if ( SCARD_S_SUCCESS != result ) {
		goto end;
	}
	if (readerNames == NULL) {
		*readerNamesLength = readersSize;
		result = OPSP_ERROR_SUCCESS;
		goto end;
	}
	readers = (OPSP_STRING)malloc(sizeof(TCHAR)*readersSize);
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
	result = OPSP_ERROR_SUCCESS;
end:
	if (readers)
		free(readers);
	LOG_END(_T("list_readers"), result);
	return result;
}

/**
 * If something is not working, you may want to change the protocol type.
 * \param cardContext IN The valid OPSP_CARDCONTEXT returned by establish_context()
 * \param readerName IN The name of the reader to connect.
 * \param *cardHandle OUT The returned reference to this card.
 * \param protocol IN The transmit protocol type to use. Can be OPSP_CARD_PROTOCOL_T0 or OPSP_CARD_PROTOCOL_T1 or both ORed.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG card_connect(OPSP_CARDCONTEXT cardContext, OPSP_CSTRING readerName, OPSP_CARDHANDLE *cardHandle, DWORD protocol) {
	LONG result;
	DWORD activeProtocol;
	LOG_START(_T("card_connect"));
	result = SCardConnect( cardContext,
							readerName,
							SCARD_SHARE_EXCLUSIVE,
							protocol,
							cardHandle,
							&activeProtocol );
	if ( SCARD_S_SUCCESS != result ) {
		goto end;
	}
	result = OPSP_ERROR_SUCCESS;
end:
	LOG_END(_T("card_connect"), result);
	return result;
}

/**
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG card_disconnect(OPSP_CARDHANDLE cardHandle) {
	LONG result;
	LOG_START(_T("card_disconnect"));
	result = SCardDisconnect(cardHandle, SCARD_RESET_CARD);
	if ( SCARD_S_SUCCESS != result ) {
		goto end;
	}
	result = OPSP_ERROR_SUCCESS;
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
 * \param *secInfo IN The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
static LONG wrap_command(PBYTE apduCommand, DWORD apduCommandLength, PBYTE wrappedApduCommand, PDWORD wrappedApduCommandLength, OPSP_SECURITY_INFO *secInfo) {
	LONG result;
	BYTE lc;
	BYTE le;
	DWORD wrappedLength;
	unsigned char mac[8];
	unsigned char encryption[240];
	int encryptionLength = 240;
	DWORD caseAPDU;
	LOG_START(_T("wrap_command"));
	if (*wrappedApduCommandLength < apduCommandLength)
			{ result = OPSP_ERROR_INSUFFICIENT_BUFFER; goto end; }
	memcpy(wrappedApduCommand, apduCommand, apduCommandLength);

	// no security level defined, just return
	if (secInfo == NULL) {
		*wrappedApduCommandLength = apduCommandLength;
		{ result = OPSP_ERROR_SUCCESS; goto end; }
	}

	// trivial case, just return
	if (secInfo->security_level == OPSP_SECURITY_LEVEL_PLAIN) {
		*wrappedApduCommandLength = apduCommandLength;
		{ result = OPSP_ERROR_SUCCESS; goto end; }
	}

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
			{ result = OPSP_ERROR_UNRECOGNIZED_APDU_COMMAND; goto end; }
		}
	} // if (Determine which type of Exchange)

	if  (secInfo->security_level != OPSP_SECURITY_LEVEL_PLAIN) {
		if (secInfo->security_level == OPSP_SECURITY_LEVEL_ENC_MAC) {
			switch (caseAPDU) {
				case 3:
					if (apduCommandLength > 239 + 8 + 5) { result = OPSP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE; goto end; } // max apdu data size = 239 + 1 byte Lc
					break;
				case 4:
					if (apduCommandLength > 239 + 8 + 5 + 1) { result = OPSP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE; goto end; }
					break;
			}
		}
		if (secInfo->security_level == OPSP_SECURITY_LEVEL_MAC) {
			switch (caseAPDU) {
				case 3:
					if (apduCommandLength > 247 + 8 + 5) { result = OPSP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE; goto end; }
					break;
				case 4:
					if (apduCommandLength > 247 + 8 + 5 + 1) { result = OPSP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE; goto end; }
					break;
			}
		}
		switch (caseAPDU) {
			case 1:
			case 2: {
				if (*wrappedApduCommandLength < apduCommandLength + 8 + 1)
					{ result = OPSP_ERROR_INSUFFICIENT_BUFFER; goto end; }
				wrappedLength = 4 + 8 + 1;
				wrappedApduCommand[4] = 0x08;
				break;
			}
			case 3:
			case 4: {
				if (*wrappedApduCommandLength < apduCommandLength + 8) {
					{ result = OPSP_ERROR_INSUFFICIENT_BUFFER; goto end; }
				}
				wrappedLength =  4 + 1 + convertByte(lc) + 8;
				wrappedApduCommand[4]+=8;
				break;
			}
		} // switch (caseAPDU)
		wrappedApduCommand[0] = apduCommand[0] | 0x04;
		result = calculate_MAC(secInfo->session_mac_key, wrappedApduCommand, wrappedLength-8, secInfo->last_mac, mac);
		if (result != OPSP_ERROR_SUCCESS) {
			goto end;
		}
		memcpy(secInfo->last_mac, mac, 8);
		memcpy(wrappedApduCommand+wrappedLength-8, mac, 8);
		if ((caseAPDU == 2) || (caseAPDU == 4)) {
			wrappedApduCommand[wrappedLength] = le;
			wrappedLength++;
		}

		if (secInfo->security_level == OPSP_SECURITY_LEVEL_ENC_MAC) {
			wrappedApduCommand[4] -= 8;
			switch (caseAPDU) {
				case 1:
				case 3:
					result = calculate_enc_cbc(secInfo->session_enc_key, wrappedApduCommand+4, wrappedLength-4-8, encryption, &encryptionLength);
					if (result != OPSP_ERROR_SUCCESS) {
						goto end;
					}
					break;
				case 2:
				case 4:
					result = calculate_enc_cbc(secInfo->session_enc_key, wrappedApduCommand+4, wrappedLength-4-8-1, encryption, &encryptionLength);
					if (result != OPSP_ERROR_SUCCESS) {
						goto end;
					}
					break;
			}
			wrappedLength = encryptionLength + 4 + 1 + 8;
			if (*wrappedApduCommandLength < wrappedLength)
				{ result = OPSP_ERROR_INSUFFICIENT_BUFFER; goto end; }
			memcpy(wrappedApduCommand+5, encryption, encryptionLength);
			wrappedApduCommand[4] = encryptionLength + 8;
			memcpy(&wrappedApduCommand[encryptionLength + 5], mac, 8);
			if ((caseAPDU == 2) || (caseAPDU ==4)) {
				if (*wrappedApduCommandLength < wrappedLength+1)
					{ result = OPSP_ERROR_INSUFFICIENT_BUFFER; goto end; }
				wrappedApduCommand[wrappedLength] = le;
				wrappedLength++;
			}
		} // if (secInfo.security_level == OPSP_SECURITY_LEVEL_ENC_MAC)
		*wrappedApduCommandLength = wrappedLength;
	} // if (secInfo.security_level == OPSP_SECURITY_LEVEL_PLAIN) ... else
	result = OPSP_ERROR_SUCCESS;
end:
	LOG_END(_T("wrap_command"), result);
	return result;
}

/**
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param capdu IN The command APDU.
 * \param capduLength IN The length of the command APDU.
 * \param rapdu OUT The response APDU.
 * \param rapduLength INOUT The length of the the response APDU.
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param *secInfo IN The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG send_APDU(OPSP_CARDHANDLE cardHandle, PBYTE capdu, DWORD capduLength, PBYTE rapdu, PDWORD rapduLength, OPSP_CARD_INFO cardInfo, OPSP_SECURITY_INFO *secInfo) {
	LONG result;
	// modified for managing all 4 cases with automatic APDU chaining

	// when necessary...

	BYTE apduCommand[261];
	DWORD caseAPDU;
	DWORD apduCommandLength = 261;
	BYTE lc;
	BYTE le;
	BYTE la;

	DWORD offset = 0;

	PBYTE responseData = NULL;
	DWORD responseDataLength = *rapduLength;

	LOG_START(_T("send_APDU"));
	responseData = (PBYTE)malloc(sizeof(BYTE)*responseDataLength);

	// main transmition block

	// wrap command
	result = wrap_command(capdu, capduLength, apduCommand, &apduCommandLength, secInfo);
	if ( OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
	// if T=1 or else T=0

	if (cardInfo.protocol == OPSP_CARD_PROTOCOL_T1) {

		// T=1 transmition

		result = SCardTransmit( cardHandle,
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
			{ result = OPSP_ERROR_UNRECOGNIZED_APDU_COMMAND; goto end; }
			}
		} // if (Determine which type of Exchange)

		// T=0 transmition (first command)

		responseDataLength = *rapduLength;
		result = SCardTransmit( cardHandle,
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
						result = SCardTransmit( cardHandle,
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
						result = SCardTransmit( cardHandle,
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

					// T=0 transmition (command w/ Le or La)

					responseDataLength = *rapduLength - offset;
					result = SCardTransmit( cardHandle,
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
						result = SCardTransmit( cardHandle,
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
						result = SCardTransmit( cardHandle,
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
		result = SCardTransmit( cardHandle,
				cardInfo.protocol == OPSP_CARD_PROTOCOL_T0 ? SCARD_PCI_T0 : SCARD_PCI_T1,
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

	if (rapdu[*rapduLength-2] != 0x90 || rapdu[*rapduLength-1] != 0x00) {
		result = (OPSP_ISO7816_ERROR_PREFIX | (rapdu[*rapduLength-2] << 8)) | rapdu[*rapduLength-1];
	}
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	if (responseData)
		free(responseData);
	LOG_END(_T("send_APDU"), result);
	return result;
}

/**
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param AID IN The AID.
 * \param AIDLength IN The length of the AID.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG select_application(OPSP_CARDHANDLE cardHandle, OPSP_CARD_INFO cardInfo, PBYTE AID, DWORD AIDLength) {
	LONG result;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	PBYTE sendBuffer;
	DWORD sendBufferLength;
	DWORD i=0;
	LOG_START(_T("select_application"));
	sendBufferLength = 5 + AIDLength;
	sendBuffer = (PBYTE)malloc(sizeof(BYTE)*sendBufferLength);
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 0xA4;
	sendBuffer[i++] = 0x04;
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = (BYTE)AIDLength;
	memcpy(sendBuffer+i, AID, AIDLength);
	i+=AIDLength;
#ifdef DEBUG
	log_Log(_T("select_application: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}
	
#endif
	result = send_APDU(cardHandle, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, NULL);
	if ( OPSP_ERROR_SUCCESS != result) {
		switch (result) {
			case OPSP_ISO7816_ERROR_CONDITIONS_NOT_SATISFIED:
				{ result = OPSP_ISO7816_ERROR_NOT_MULTI_SELECTABLE; goto end; }
			case OPSP_ISO7816_ERROR_6999:
				{ result = OPSP_ISO7816_ERROR_SELECTION_REJECTED; goto end; }
			case OPSP_ISO7816_ERROR_FUNC_NOT_SUPPORTED:
				{ result = OPSP_ISO7816_ERROR_APPLET_NOT_SELECTABLE; goto end; }
			case OPSP_ISO7816_ERROR_FILE_NOT_FOUND:
				{ result = OPSP_ISO7816_ERROR_APPLET_NOT_FOUND; goto end; }
			case OPSP_ISO7816_ERROR_FILE_INVALIDATED:
				{ result = OPSP_ISO7816_WARNING_CM_LOCKED; goto end; }
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
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("select_application"), result);
	return result;
}

/**
 * A keySetVersion value of 0x00 adds a new key.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version a new key belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param *secInfo INOUT The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param keySetVersion IN An existing key set version.
 * \param keyIndex IN The position of the key in the key set version.
 * \param newKeySetVersion IN The new key set version.
 * \param PEMKeyFileName IN A PEM file name with the public RSA key.
 * \param *passPhrase IN The passphrase. Must be an ASCII string.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG put_rsa_key(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo,
				 BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion,
				 OPSP_STRING PEMKeyFileName, char *passPhrase) {
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
		{ result = OPSP_ERROR_INVALID_PASSWORD; goto end; }

	if ((PEMKeyFileName == NULL) || (_tcslen(PEMKeyFileName) == 0))
		{ result = OPSP_ERROR_INVALID_FILENAME; goto end; }
	PEMKeyFile = _tfopen(PEMKeyFileName, _T("rb"));
	if (PEMKeyFile == NULL) {
		{ result = OPSP_ERROR_FILE_NOT_FOUND; goto end; }
	}
	key = EVP_PKEY_new();
	if (!PEM_read_PUBKEY(PEMKeyFile, &key, NULL, passPhrase)) {
		fclose(PEMKeyFile);
		EVP_PKEY_free(key);
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	};
	fclose(PEMKeyFile);
	rsa_exponent = key->pkey.rsa->e->d[0];
	memcpy(rsa_modulus, key->pkey.rsa->n->d, sizeof(unsigned long)*key->pkey.rsa->n->top);
	EVP_PKEY_free(key);

	if (keySetVersion > 0x7f)
		{ result = OPSP_ERROR_WRONG_KEY_VERSION; goto end; }
	if ((newKeySetVersion > 0x7f) || (newKeySetVersion < 0x01))
		{ result = OPSP_ERROR_WRONG_KEY_VERSION; goto end; }
	if (keyIndex > 0x7f)
		{ result = OPSP_ERROR_WRONG_KEY_INDEX; goto end; }
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
		{ result = OPSP_ERROR_WRONG_EXPONENT; goto end; }
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
	result = send_APDU(cardHandle, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
	if ( OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("put_rsa_key: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
	
#endif
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("put_rsa_key"), result);
	return result;
}

/**
 * A keySetVersion value of 0x00 adds a new key.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version a new key belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param *secInfo INOUT The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param keySetVersion IN An existing key set version.
 * \param keyIndex IN The position of the key in the key set version.
 * \param newKeySetVersion IN The new key set version.
 * \param _3des_key IN The new 3DES key.
 * \param kek_key IN The key encryption key (KEK) to encrypt the _3des_key.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG put_3des_key(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo,
				  BYTE keySetVersion, BYTE keyIndex, BYTE newKeySetVersion, BYTE _3des_key[16],
				  BYTE kek_key[16]) {
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
	if (keySetVersion > 0x7f)
		{ result = OPSP_ERROR_WRONG_KEY_VERSION; goto end; }
	if (newKeySetVersion > 0x7f)
		{ result = OPSP_ERROR_WRONG_KEY_VERSION; goto end; }
	if (keyIndex > 0x7f)
		{ result = OPSP_ERROR_WRONG_KEY_INDEX; goto end; }
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xD8;
	sendBuffer[i++] = keySetVersion;
	sendBuffer[i++] = keyIndex;
	sendBuffer[i++] = 0x17;
	sendBuffer[i++] = newKeySetVersion;
	sendBuffer[i++] = 0x81; // alghoritm 3DES
	sendBuffer[i++] = 0x10; // length of 3DES key
	result = calculate_enc_ecb(kek_key, _3des_key, 16, encrypted_3des_key, &encrypted_3des_key_length);
	if ( OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
	memcpy(sendBuffer+i, encrypted_3des_key, 16); // key
	i+=16;
	sendBuffer[i++] = 0x03; // length of key check value
	result = calculate_enc_ecb(_3des_key, keyCheckTest, 8, keyCheckValue, &keyCheckValueLength);
	if ( OPSP_ERROR_SUCCESS != result) {
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
	result = send_APDU(cardHandle, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
	if ( OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("put_3des_key: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
	
#endif
	if (memcmp(keyCheckValue, recvBuffer+1, 3) != 0)
		{ result = OPSP_ERROR_KEY_CHECK_VALUE; goto end; }
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("put_3des_key"), result);
	return result;
}

/**
 * A keySetVersion value of 0x00 adds a new secure channel key set.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version a the new secure channel keys belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param *secInfo INOUT The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param keySetVersion IN An existing key set version.
 * \param newKeySetVersion IN The new key set version.
 * \param new_enc_key IN The new Encryption key.
 * \param new_mac_key IN The new MAC key.
 * \param new_kek_key IN The new key encryption key.
 * \param kek_key IN The key encryption key (KEK).
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG put_secure_channel_keys(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo, BYTE keySetVersion, BYTE newKeySetVersion, BYTE new_enc_key[16], BYTE new_mac_key[16], BYTE new_kek_key[16], BYTE kek_key[16]) {
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
	if (keySetVersion > 0x7f)
		{ result = OPSP_ERROR_WRONG_KEY_VERSION; goto end; }
	if (newKeySetVersion > 0x7f)
		{ result = OPSP_ERROR_WRONG_KEY_VERSION; goto end; }
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xD8;
	sendBuffer[i++] = keySetVersion;
	sendBuffer[i++] = 0x81;
	sendBuffer[i++] = 0x43;

	sendBuffer[i++] = newKeySetVersion;
	// Encryption key

	sendBuffer[i++] = 0x81; // alghoritm 3DES
	sendBuffer[i++] = 0x10; // length of 3DES key
	result = calculate_enc_ecb(kek_key, new_enc_key, 16, encrypted_key, &encrypted_key_length);
	if ( OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
	memcpy(sendBuffer+i, encrypted_key, 16); // key
	i+=16;
	sendBuffer[i++] = 0x03; // length of key check value
	result = calculate_enc_ecb(new_enc_key, keyCheckTest, 8, keyCheckValue1, &keyCheckValueLength);
	if ( OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
	memcpy(sendBuffer+i, keyCheckValue1, 3);
	i+=3;
	// MAC key

	sendBuffer[i++] = 0x81; // alghoritm 3DES
	sendBuffer[i++] = 0x10; // length of 3DES key
	result = calculate_enc_ecb(kek_key, new_mac_key, 16, encrypted_key, &encrypted_key_length);
	if ( OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
	memcpy(sendBuffer+i, encrypted_key, 16); // key
	i+=16;
	sendBuffer[i++] = 0x03; // length of key check value
	result = calculate_enc_ecb(new_mac_key, keyCheckTest, 8, keyCheckValue2, &keyCheckValueLength);
	if ( OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
	memcpy(sendBuffer+i, keyCheckValue2, 3);
	i+=3;
	// KEK

	sendBuffer[i++] = 0x81; // alghoritm 3DES
	sendBuffer[i++] = 0x10; // length of 3DES key
	result = calculate_enc_ecb(kek_key, new_kek_key, 16, encrypted_key, &encrypted_key_length);
	if ( OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
	memcpy(sendBuffer+i, encrypted_key, 16); // key
	i+=16;
	sendBuffer[i++] = 0x03; // length of key check value
	result = calculate_enc_ecb(new_kek_key, keyCheckTest, 8, keyCheckValue3, &keyCheckValueLength);
	if ( OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
	memcpy(sendBuffer+i, keyCheckValue3, 3);
	i+=3;
	// send the stuff

	sendBuffer[i++] = 0x00; // Le
	sendBufferLength = i;

#ifdef DEBUG
	log_Log(_T("put_secure_channel_keys: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}
	
#endif
	result = send_APDU(cardHandle, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
	if ( OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("put_secure_channel_keys: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
	
#endif
	if (memcmp(keyCheckValue1, recvBuffer+1, 3) != 0)
		{ result = OPSP_ERROR_KEY_CHECK_VALUE; goto end; }
	if (memcmp(keyCheckValue2, recvBuffer+1+3, 3) != 0)
		{ result = OPSP_ERROR_KEY_CHECK_VALUE; goto end; }
	if (memcmp(keyCheckValue3, recvBuffer+1+6, 3) != 0)
		{ result = OPSP_ERROR_KEY_CHECK_VALUE; goto end; }
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("put_secure_channel_keys"), result);
	return result;
}

/**
 * A keySetVersion value of 0x00 adds a new secure channel key set.
 * Any other value between 0x01 and 0x7f must match an existing key set version.
 * The new key set version defines the key set version a the new secure channel keys belongs to.
 * This can be the same key version or a new not existing key set version.
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param *secInfo INOUT The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param keySetVersion IN An existing key set version.
 * \param newKeySetVersion IN The new key set version.
 * \param PEMKeyFileName IN A PEM file name with the public RSA key.
 * \param *passPhrase IN The passphrase. Must be an ASCII string.
 * \param receipt_generation_key IN The new Receipt Generation key.
 * \param kek_key IN The key encryption key (KEK).
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG put_delegated_management_keys(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo,
								   OPSP_CARD_INFO cardInfo, BYTE keySetVersion, BYTE newKeySetVersion,
								   OPSP_STRING PEMKeyFileName, char *passPhrase,
								   BYTE receipt_generation_key[16], BYTE kek_key[16]) {
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
		{ result = OPSP_ERROR_INVALID_PASSWORD; goto end; }
	if ((PEMKeyFileName == NULL) || (_tcslen(PEMKeyFileName) == 0))
		{ result = OPSP_ERROR_INVALID_FILENAME; goto end; }
	PEMKeyFile = _tfopen(PEMKeyFileName, _T("rb"));
	if (PEMKeyFile == NULL) {
		{ result = OPSP_ERROR_FILE_NOT_FOUND; goto end; }
	}
	key = EVP_PKEY_new();
	if (!PEM_read_PUBKEY(PEMKeyFile, &key, NULL, passPhrase)) {
	fclose(PEMKeyFile);

		EVP_PKEY_free(key);
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	};
	fclose(PEMKeyFile);
	// only 3 and 65337 are supported
	token_verification_rsa_exponent = key->pkey.rsa->e->d[0];
	memcpy(token_verification_rsa_modulus, key->pkey.rsa->n->d, sizeof(unsigned long)*key->pkey.rsa->n->top);
	EVP_PKEY_free(key);

	if (keySetVersion > 0x7f)
		{ result = OPSP_ERROR_WRONG_KEY_VERSION; goto end; }
	if (newKeySetVersion > 0x7f)
		{ result = OPSP_ERROR_WRONG_KEY_VERSION; goto end; }
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
		{ result = OPSP_ERROR_WRONG_EXPONENT; goto end; }
	}

	// Receipt Generation Key

	sendBuffer[i++] = 0x81; // alghoritm 3DES
	sendBuffer[i++] = 0x10; // length of 3DES key
	result = calculate_enc_ecb(kek_key, receipt_generation_key, 16, encrypted_key, &encrypted_key_length);
	if ( OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
	memcpy(sendBuffer+i, encrypted_key, 16); // key
	i+=16;
	sendBuffer[i++] = 0x03; // length of key check value
	result = calculate_enc_ecb(receipt_generation_key, keyCheckTest, 8, keyCheckValue, &keyCheckValueLength);
	if ( OPSP_ERROR_SUCCESS != result) {
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

	result = send_APDU(cardHandle, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
	if ( OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("put_delegated_management_keys: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
	
#endif
	if (memcmp(keyCheckValue, recvBuffer+1, 3) != 0)
		{ result = OPSP_ERROR_KEY_CHECK_VALUE; goto end; }
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("put_delegated_management_keys"), result);
	return result;
}

/**
 * If keyIndex is 0x00 all keys within a keySetVersion are deleted.
 * If keySetVersion is 0x00 all keys with the specified keyIndex are deleted.
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param *secInfo INOUT The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param keySetVersion IN An existing key set version.
 * \param keyIndex IN An existing key index.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG delete_key(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo, BYTE keySetVersion, BYTE keyIndex) {
	LONG result;
	BYTE sendBuffer[255];
	DWORD sendBufferLength;
	DWORD recvBufferLength=3;
	BYTE recvBuffer[3];
	DWORD i=0;
	LOG_START(_T("delete_key"));
	if ((keySetVersion == 0x00) && (keyIndex == 0x00))
		{ result = OPSP_ERROR_INVALID_COMBINATION_KEY_SET_VERSION_KEY_INDEX; goto end; }
	if (keySetVersion > 0x7f)
		{ result = OPSP_ERROR_WRONG_KEY_VERSION; goto end; }
	if (keyIndex > 0x7f)
		{ result = OPSP_ERROR_WRONG_KEY_INDEX; goto end; }
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
	result = send_APDU(cardHandle, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
	if ( OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("delete_key: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
	
#endif
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("delete_key"), result);
	return result;
}

/**
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param *secInfo INOUT The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param AIDs IN A pointer to the an array of OPSP_AID structures describing the applications and load files to delete.
 * \param AIDsLength IN The number of OPSP_AID structures.
 * \param **receiptData OUT A pointer to an OPSP_RECEIPT_DATA array. If the deletion is performed by a
 * security domain with delegated management privilege
 * this structure contains the according data for each deleted applet or package.
 * \param receiptDataLength INOUT A pointer to the length of the receiptData array.
 * If no receiptData is available this length is 0;
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG delete_applet(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo,
				   OPSP_AID *AIDs, DWORD AIDsLength, OPSP_RECEIPT_DATA **receiptData, PDWORD receiptDataLength) {
	LONG result;
	DWORD count=0;
	BYTE sendBuffer[261];
	DWORD sendBufferLength;
	DWORD recvBufferLength=255;
	BYTE recvBuffer[255];
	DWORD j,i=0;
	LOG_START(_T("delete_applet"));
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0xE4;
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 0x00;
	for (j=0; j< AIDsLength; j++) {
		if (i + AIDs[j].AIDLength+2 > 260) {
			*receiptDataLength = 0;
			{ result = OPSP_ERROR_COMMAND_TOO_LARGE; goto end; }
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
	result = send_APDU(cardHandle, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
	if ( OPSP_ERROR_SUCCESS != result) {
		*receiptDataLength = 0;
		goto end;
	}
	if (recvBufferLength-count > sizeof(OPSP_RECEIPT_DATA)) { // assumption that a OPSP_RECEIPT_DATA structure is returned in a delegated management deletion
		*receiptDataLength=0;
		while (recvBufferLength-count > sizeof(OPSP_RECEIPT_DATA)) {
			count+=fillReceipt(recvBuffer, *receiptData + *receiptDataLength++);
		}
	}
	else {
		*receiptDataLength = 0;
	}
#ifdef DEBUG
	log_Log(_T("delete_application: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
	
#endif
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("delete_applet"), result);
	return result;
}

/**
 * Puts a single card data object identified by identifier.
 * Some cards do not provide some data objects. Some possible identifiers are predefined.
 * See OPSP_GET_DATA_ISSUER_BIN. For details about the coding of the dataObject see the programmer's manual
 * of your card.
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param identifier IN Two byte buffer with high and low order tag value for identifying card data object.
 * \param dataObject IN The coded data object.
 * \param dataObjectLength IN The length of the data object.
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param *secInfo INOUT The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG put_data(OPSP_CARDHANDLE cardHandle, BYTE identifier[2], PBYTE dataObject, DWORD dataObjectLength, OPSP_CARD_INFO cardInfo, OPSP_SECURITY_INFO *secInfo) {
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
	result = send_APDU(cardHandle, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
	if ( OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("put_data: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}	
#endif
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("put_data"), result);
	return result;
}

/**
 * Retrieves a single card data object from the card identified by identifier.
 * Some cards do not provide some data objects. Some possible identifiers are predefined.
 * See OPSP_GET_DATA_ISSUER_BIN and so on. For details about the coding of the response see the programmer's manual
 * of your card.
 * There is a convenience method get_key_information_templates() to get the key information template(s)
 * containing key set version, key index, key type and key length of the keys.
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param identifier IN Two byte buffer with high and low order tag value for identifying card data object.
 * \param recvBuffer IN The buffer for the card data object.
 * \param recvBufferLength IN The length of the received card data object.
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param *secInfo INOUT The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG get_data(OPSP_CARDHANDLE cardHandle, BYTE identifier[2], PBYTE recvBuffer, PDWORD recvBufferLength,
			  OPSP_CARD_INFO cardInfo, OPSP_SECURITY_INFO *secInfo) {
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
	result = send_APDU(cardHandle, sendBuffer, sendBufferLength, cardData, &cardDataLength, cardInfo, secInfo);
	if ( OPSP_ERROR_SUCCESS != result) {
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
		{ result = OPSP_ERROR_INSUFFICIENT_BUFFER; goto end; }
	}
	memcpy(recvBuffer, cardData, cardDataLength-2);
	*recvBufferLength = cardDataLength-2;
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("get_data"), result);
	return result;
}

/**
 * The card must support the optional report of key information templates.
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param *secInfo INOUT The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param keyInformationTemplate IN The number of the key information template.
 * \param *keyInformation OUT A pointer to an array of OPSP_KEY_INFORMATION structures.
 * \param keyInformationLength INOUT The number of OPSP_KEY_INFORMATION structures.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG get_key_information_templates(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo,
								   OPSP_CARD_INFO cardInfo, BYTE keyInformationTemplate,
								   OPSP_KEY_INFORMATION *keyInformation, PDWORD keyInformationLength) {
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
	result = send_APDU(cardHandle, sendBuffer, sendBufferLength, cardData, &cardDataLength, cardInfo, secInfo);
	if ( OPSP_ERROR_SUCCESS != result) {
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
			{ result = OPSP_ERROR_MORE_KEY_INFORMATION_TEMPLATES; goto end; };
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

	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("get_key_information_templates"), result);
	return result;
}

/**
 *
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param *secInfo INOUT The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param cardElement IN Identifier for Load Files, Applications or the Card Manager.
 * \param AID IN The AID.
 * \param AIDLength IN The length of the AID.
 * \param lifeCycleState IN The new life cycle state.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG set_status(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo, BYTE cardElement, PBYTE AID, DWORD AIDLength, BYTE lifeCycleState) {
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
	result = send_APDU(cardHandle,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
	if (OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("set_status: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
	
#endif
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("set_status"), result);
	return result;
}

/**
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param *secInfo INOUT The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param cardElement IN Identifier to retrieve data for Load Files, Applications or the Card Manager.
 * \param *applData OUT The OPSP_APPLICATION_DATA structure containing AID, life cycle state and privileges.
 * \param applDataLength INOUT The number of OPSP_APPLICATION_DATA passed and returned.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG get_status(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo, BYTE cardElement, OPSP_APPLICATION_DATA *applData, PDWORD applDataLength) {
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
		result = send_APDU(cardHandle,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
		if ( (OPSP_ERROR_SUCCESS != result) && !(result == OPSP_ISO7816_ERROR_MORE_DATA_AVAILABLE)) {
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
				{ result = OPSP_ERROR_MORE_APPLICATION_DATA; goto end; }
			}
			applData[i].AIDLength = recvBuffer[j++];
			memcpy(applData[i].AID, recvBuffer+j, applData[i].AIDLength);
			j+=applData[i].AIDLength;
			applData[i].lifeCycleState = recvBuffer[j++];
			applData[i].privileges = recvBuffer[j++];
			i++;
		}
		sendBuffer[3]=0x01;
	} while (result == OPSP_ISO7816_ERROR_MORE_DATA_AVAILABLE);

	*applDataLength = i;
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("get_status"), result);
	return result;
}

/**
 * An install_for_load() must precede.
 * The Load File Data Block DAP block(s) must be the same block(s) and in the same order like in calculate_load_file_DAP().
 * If no Load File Data Block DAP blocks are necessary the dapBlock must be NULL and the dapBlockLength 0.
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param *secInfo INOUT The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param *dapBlock IN A pointer to OPSP_DAP_BLOCK structure(s).
 * \param dapBlockLength IN The number of OPSP_DAP_BLOCK structure(s).
 * \param CAPFileName IN The name of the CAP file to hash.
 * \param *receiptData OUT If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * Can be validated with validate_load_receipt().
 * \param receiptDataAvailable OUT 0 if no receiptData is availabe.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG load_applet(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo,
				 OPSP_DAP_BLOCK *dapBlock, DWORD dapBlockLength, OPSP_STRING CAPFileName,
				 OPSP_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable) {
	LONG result = 0;
	DWORD sendBufferLength;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	BYTE sendBuffer[261];
	PBYTE dapBuf = NULL;
	DWORD maxDAPBufSize=0;
	long fileSize;
	DWORD total=0;
	DWORD fileSizeSize;
	DWORD j,k,i=0;
	FILE *CAPFile = NULL;
	BYTE sequenceNumber=0x00;
	LOG_START(_T("load_applet"));
	*receiptDataAvailable = 0;
	sendBuffer[0] = 0x80;
	sendBuffer[1] = 0xE8;
	if ((CAPFileName == NULL) || (_tcslen(CAPFileName) == 0))
		{ result = OPSP_ERROR_INVALID_FILENAME; goto end; }

	for (i=0; i<dapBlockLength; i++) {
		maxDAPBufSize = max(maxDAPBufSize, (DWORD)dapBlock[i].DAPBlockLength + 1);
	}
	if (dapBlockLength > 0) {
		dapBuf = (PBYTE)malloc(sizeof(BYTE)*maxDAPBufSize);
	}
	j=0;
	for (i=0; i<dapBlockLength; i++) {
		k = maxDAPBufSize;
		result = readDAPBlock(dapBuf, &k, dapBlock[i]);
		if (result != OPSP_ERROR_SUCCESS) {
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
	log_Log(_T("load_applet: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}
	
#endif
			result = send_APDU(cardHandle, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
			if (OPSP_ERROR_SUCCESS != result) {
				goto end;
			}
#ifdef DEBUG
	log_Log(_T("load_applet: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
	
#endif
			j=k;
		}
	}
	// send load file data block

	CAPFile = _tfopen(CAPFileName, _T("rb"));
	if (CAPFile == NULL) {
		{ result = OPSP_ERROR_FILE_NOT_FOUND; goto end; }
	}
#ifdef WIN32
	fileSize = _filelength(CAPFile->_file);
#else
	fileSize = fseek(CAPFile, 0, SEEK_END);
	if (fileSize == -1) {		
		{ result = OPSP_ERROR_BAD_FILE_DESCRIPTOR; goto end; }
	}
	fileSize = ftell(CAPFile);
#endif
	if (fileSize == -1L) {
		{ result = OPSP_ERROR_BAD_FILE_DESCRIPTOR; goto end; }
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
		{ result = OPSP_ERROR_APPLICATION_TOO_BIG; goto end; }
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
			{ result = OPSP_ERROR_READ; goto end; }
		}
		sendBufferLength=5+j;
		sendBuffer[2] = 0x00;
		sendBuffer[3] = (BYTE)sequenceNumber++;
		sendBuffer[4]=(BYTE)j;
		//sendBufferLength++;
		//sendBuffer[sendBufferLength-1] = 0x00;
		if ((feof(CAPFile)) || (total == (DWORD)fileSize)) {
			sendBuffer[2]=0x80;
			sendBufferLength++;
			sendBuffer[sendBufferLength-1] = 0x00;
		}
		else
			sendBuffer[2]=0x00;

		recvBufferLength=256;

#ifdef DEBUG
	log_Log(_T("load_applet: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}
	
#endif

		result = send_APDU(cardHandle, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
		if (OPSP_ERROR_SUCCESS != result) {
			goto end;
		}
#ifdef DEBUG
	log_Log(_T("load_applet: Data: "));
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
//		sendBufferLength++;
//		sendBuffer[sendBufferLength-1] = 0x00;
#ifdef DEBUG
	log_Log(_T("load_applet: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}
	
#endif
		result = send_APDU(cardHandle, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
		if (OPSP_ERROR_SUCCESS != result) {
			goto end;
		}
#ifdef DEBUG
	log_Log(_T("load_applet: Data: "));
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
			{ result = OPSP_ERROR_READ; goto end; }
		}
		sendBufferLength=5+j;
		sendBuffer[2] = 0x00;
		sendBuffer[3] = sequenceNumber++;
		sendBuffer[4]=(BYTE)j;
//		sendBufferLength++;
//		sendBuffer[sendBufferLength-1] = 0x00;
		if ((feof(CAPFile)) || (total == (DWORD)fileSize) ) {
			sendBuffer[2]=0x80;
			sendBufferLength++;
			sendBuffer[sendBufferLength-1] = 0x00;
		}
		else
			sendBuffer[2]=0x00;

		recvBufferLength=256;
#ifdef DEBUG
	log_Log(_T("load_applet: Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}
	
#endif
		result = send_APDU(cardHandle, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
		if (OPSP_ERROR_SUCCESS != result) {
			goto end;
		}
#ifdef DEBUG
	log_Log(_T("load_applet: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
	
#endif
	}
	// The rest of the load file data block

	while((feof(CAPFile) == 0) && !(total == (DWORD)fileSize)) {
		total += j = (DWORD)fread(sendBuffer+5, sizeof(unsigned char), MAX_APDU_DATA_SIZE_FOR_SECURE_MESSAGING, CAPFile);
		if(ferror(CAPFile)) {
			{ result = OPSP_ERROR_READ; goto end; }
		}
		sendBufferLength=5+j;
		sendBuffer[3] = sequenceNumber++;
		sendBuffer[4] = (BYTE)j;
		//sendBufferLength++;
		//sendBuffer[sendBufferLength-1] = 0x00;
		if ((feof(CAPFile)) || (total == (DWORD)fileSize)) {
			sendBuffer[2]=0x80;
			sendBufferLength++;
			sendBuffer[sendBufferLength-1] = 0x00;
		}
		else
			sendBuffer[2]=0x00;
#ifdef DEBUG
		log_Log(_T("load_applet: Data to send: "));
		for (i=0; i<sendBufferLength; i++) {
			log_Log(_T(" 0x%02x"), sendBuffer[i]);
		}
		
#endif
		recvBufferLength=256;
		result = send_APDU(cardHandle, sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
		if (OPSP_ERROR_SUCCESS != result) {
			goto end;
		}
#ifdef DEBUG
		if (!(feof(CAPFile)) && !(total == (DWORD)fileSize)) {
			log_Log(_T("load_applet: Data: "));
			for (i=0; i<recvBufferLength; i++) {
				log_Log(_T(" 0x%02x"), recvBuffer[i]);
			}
			
		}
#endif
	}
	if (recvBufferLength > sizeof(OPSP_RECEIPT_DATA)) { // assumption that a OPSP_RECEIPT_DATA structure is returned in a delegated management deletion
		fillReceipt(recvBuffer, receiptData);
		*receiptDataAvailable = 1;
	}
#ifdef DEBUG
	log_Log(_T("load_applet: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
#endif
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	if (dapBuf)
		free(dapBuf);
	if (CAPFile)
		fclose(CAPFile);
	LOG_END(_T("load_applet"), result);
	return result;
}

/**
 * The function assumes that the Card Manager or Security Domain
 * uses an optional load file DAP using the SHA-1 message digest algorithm.
 * The loadFileDAP can be calculated using calculate_load_file_DAP() or must be NULL, if the card does not 
 * need or support a Load File DAP in this situation, e.g. if you want to load a package to the Card 
 * Manager Security Domain.
 * In the case of delegated management a Load Token authorizing the INSTALL [for load] must be included.
 * Otherwise loadToken must be NULL. See calculate_load_token().
 * The term package is equivalent to the Open Platform term Load File Data Block.
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tags.
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param *secInfo INOUT The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param packageAID IN A buffer with AID of the package to INSTALL [for load].
 * \param packageAIDLength IN The length of the package AID.
 * \param securityDomainAID IN A buffer containing the AID of the intended associated Security Domain.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \param loadFileDAP IN The load file DAP of the package to INSTALL [for load].
 * \param loadToken IN The Load Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param nonVolatileCodeSpaceLimit IN The minimum amount of space that must be available to store the package.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the applet, i.e. the data allocated in its lifetime.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG install_for_load(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo,
					  PBYTE packageAID, DWORD packageAIDLength, PBYTE securityDomainAID,
					  DWORD securityDomainAIDLength, BYTE loadFileDAP[20], BYTE loadToken[128],
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
	result = get_load_token_signature_data(packageAID, packageAIDLength, securityDomainAID,
		securityDomainAIDLength, loadFileDAP, nonVolatileCodeSpaceLimit, volatileDataSpaceLimit,
		nonVolatileDataSpaceLimit, buf, &bufLength);
	if (OPSP_ERROR_SUCCESS != result) {
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
	result = send_APDU(cardHandle,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
	if (OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("install_for_load: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
	
#endif
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("install_for_load"), result);
	return result;
}


/**
 * In the case of delegated management an Install Token authorizing the INSTALL [for install] must be included.
 * Otherwise installToken must be NULL. See calculate_install_token().
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tag.
 * For Security domains look in your manual what parameters are necessary.
 * If the tag for applet install parameters is mandatory for your card, but you have no install parameters
 * for the install() method of the applet anyway you have to use at least a dummy parameter.
 * If appletClassAID is NULL and appletClassAIDLength is 0 appletInstanceAID is assumed for appletClassAID.
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param *secInfo INOUT The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param packageAID IN A buffer with AID of the package to INSTALL [for install].
 * \param packageAIDLength IN The length of the package AID.
 * \param appletClassAID IN The AID of the applet class in the package.
 * \param appletClassAIDLength IN The length of the appletClassAID buffer.
 * \param appletInstanceAID IN The AID of the installed applet.
 * \param appletInstanceAIDLength IN The length of the applet instance AID.
 * \param appletPrivileges IN The applet privileges. Can be an OR of multiple privileges. See OPSP_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the applet, i.e. the data allocated in its lifetime.
 * \param appletInstallParameters IN Applet install parameters for the install() method of the applet.
 * \param appletInstallParametersLength IN The length of the appletInstallParameters buffer.
 * \param installToken IN The Install Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param *receiptData OUT If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * \param receiptDataAvailable OUT 0 if no receiptData is availabe.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG install_for_install(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo,
						 PBYTE packageAID, DWORD packageAIDLength, PBYTE appletClassAID,
						 DWORD appletClassAIDLength, PBYTE appletInstanceAID,
						 DWORD appletInstanceAIDLength, BYTE appletPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE appletInstallParameters, DWORD appletInstallParametersLength,
						 BYTE installToken[128], OPSP_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable) {
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
	result = get_install_token_signature_data(0x04, packageAID, packageAIDLength, appletClassAID,
		appletClassAIDLength, appletInstanceAID, appletInstanceAIDLength, appletPrivileges,
		volatileDataSpaceLimit,	nonVolatileDataSpaceLimit, appletInstallParameters,
		appletInstallParametersLength, buf, &bufLength);
	if (OPSP_ERROR_SUCCESS != result) {
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
	result = send_APDU(cardHandle,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
	if (OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
	if (recvBufferLength > sizeof(OPSP_RECEIPT_DATA)) { // assumption that a OPSP_RECEIPT_DATA structure is returned in a delegated management deletion
		fillReceipt(recvBuffer, receiptData);
		*receiptDataAvailable = 1;
	}
#ifdef DEBUG
	log_Log(_T("install_for_install: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
	
#endif
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("install_for_install"), result);
	return result;
}

/**
 * In the case of delegated management an Install Token authorizing the INSTALL [for install and make selectable] must be included.
 * Otherwise installToken must be NULL. See calculate_install_token().
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tag.
 * For Security domains look in your manual what parameters are necessary.
 * If the tag for applet install parameters is mandatory for your card, but you have no install parameters
 * for the install() method of the applet anyway you have to use at least a dummy parameter.
 * If appletClassAID is NULL and appletClassAIDLength is 0 appletInstanceAID is assumed for appletClassAID.
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param *secInfo INOUT The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param packageAID IN A buffer with AID of the package to INSTALL [for install].
 * \param packageAIDLength IN The length of the package AID.
 * \param appletClassAID IN The AID of the applet class in the package.
 * \param appletClassAIDLength IN The length of the appletClassAID buffer.
 * \param appletInstanceAID IN The AID of the installed applet.
 * \param appletInstanceAIDLength IN The length of the applet instance AID.
 * \param appletPrivileges IN The applet privileges. Can be an OR of multiple privileges. See OPSP_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the applet, i.e. the data allocated in its lifetime.
 * \param appletInstallParameters IN Applet install parameters for the install() method of the applet.
 * \param appletInstallParametersLength IN The length of the appletInstallParameters buffer.
 * \param installToken IN The Install Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param *receiptData OUT If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * \param receiptDataAvailable OUT 0 if no receiptData is availabe.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG install_for_install_and_make_selectable(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo,
						 PBYTE packageAID, DWORD packageAIDLength, PBYTE appletClassAID,
						 DWORD appletClassAIDLength, PBYTE appletInstanceAID,
						 DWORD appletInstanceAIDLength, BYTE appletPrivileges,
						 DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
						 PBYTE appletInstallParameters, DWORD appletInstallParametersLength,
						 BYTE installToken[128], OPSP_RECEIPT_DATA *receiptData, PDWORD receiptDataAvailable) {
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
	result = get_install_token_signature_data(0x0C, packageAID, packageAIDLength, appletClassAID,
		appletClassAIDLength, appletInstanceAID, appletInstanceAIDLength, appletPrivileges,
		volatileDataSpaceLimit,	nonVolatileDataSpaceLimit, appletInstallParameters,
		appletInstallParametersLength, buf, &bufLength);
	if (OPSP_ERROR_SUCCESS != result) {
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
	result = send_APDU(cardHandle,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
	if (OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
	if (recvBufferLength > sizeof(OPSP_RECEIPT_DATA)) { // assumption that a OPSP_RECEIPT_DATA structure is returned in a delegated management deletion
		fillReceipt(recvBuffer, receiptData);
		*receiptDataAvailable = 1;
	}
#ifdef DEBUG
	log_Log(_T("install_for_install_and_make_selectable: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
	
#endif
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("install_for_install_and_make_selectable"), result);
	return result;
}

/**
 * In the case of delegated management an Install Token authorizing the INSTALL [for make selectable] must be included.
 * Otherwise installToken must be NULL.
 * For Security domains look in your manual what parameters are necessary.
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param *secInfo INOUT The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param appletInstanceAID IN The AID of the installed applet or security domain.
 * \param appletInstanceAIDLength IN The length of the applet instance AID.
 * \param appletPrivileges IN The applet privileges. Can be an OR of multiple privileges. See OPSP_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param installToken IN The Install Token. This is a 1024 bit (=128 byte) RSA Signature.
 * \param *receiptData OUT If the deletion is performed by a security domain with delegated management privilege
 * this structure contains the according data.
 * \param receiptDataAvailable OUT 0 if no receiptData is availabe.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG install_for_make_selectable(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo,
								 PBYTE appletInstanceAID,
								 DWORD appletInstanceAIDLength, BYTE appletPrivileges,
								 BYTE installToken[128], OPSP_RECEIPT_DATA *receiptData,
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

	sendBuffer[i++] = 0x00; //  package AID
	sendBuffer[i++] = 0x00; // applet class AID

	sendBuffer[i++] = (BYTE)appletInstanceAIDLength; // applet instance AID
	memcpy(sendBuffer+i, appletInstanceAID, appletInstanceAIDLength);
	i+=appletInstanceAIDLength;

	sendBuffer[i++] = 0x01;
	sendBuffer[i++] = appletPrivileges; // applet privileges

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
	result = send_APDU(cardHandle,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
	if (OPSP_ERROR_SUCCESS != result) {
		goto end;
	}
	if (recvBufferLength > sizeof(OPSP_RECEIPT_DATA)) { // assumption that a OPSP_RECEIPT_DATA structure is returned in a delegated management deletion
		fillReceipt(recvBuffer, receiptData);
		*receiptDataAvailable = 1;
	}
#ifdef DEBUG
	log_Log(_T("install_for_make_selectable: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
	
#endif
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("install_for_make_selectable"), result);
	return result;
}

/**
 * If you are not the Card Issuer and do not know the token verification private key send this data to the
 * Card Issuer and obtain the RSA signature of the data, i.e. the Install Token.
 * volatileDataSpaceLimit can be NULL, if the card does not need or support this tag.
 * The parameters must match the parameters of a later install_for_install() and install_for_make_selectable() method.
 * \param P1 IN The parameter P1 in the APDU command.
 * <ul>
 * <li> 0x04 for a INSTALL [for install] command </li>
 * <li> 0x08 for an INSTALL [for make selectable] command </li>
 * <li> 0x0C for an INSTALL [for install and make selectable] </li>
 * </ul>
 * \param packageAID IN A buffer with AID of the package to INSTALL [for load].
 * \param packageAIDLength IN The length of the package AID.
 * \param appletClassAID IN The AID of the applet class in the package.
 * \param appletClassAIDLength IN The length of the appletClassAID buffer.
 * \param appletInstanceAID IN The AID of the installed applet.
 * \param appletInstanceAIDLength IN The length of the applet instance AID.
 * \param appletPrivileges IN The applet privileges. Can be an OR of multiple privileges. See OPSP_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the applet, i.e. the data allocated in its lifetime.
 * \param appletInstallParameters IN Applet install parameters for the install() method of the applet.
 * \param appletInstallParametersLength IN The length of the appletInstallParameters buffer.
 * \param installTokenSignatureData OUT The data to sign in a Install Token.
 * \param installTokenSignatureDataLength INOUT The length of the installTokenSignatureData buffer.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG get_install_token_signature_data(BYTE P1, PBYTE packageAID, DWORD packageAIDLength, PBYTE appletClassAID,
									  DWORD appletClassAIDLength, PBYTE appletInstanceAID,
									  DWORD appletInstanceAIDLength, BYTE appletPrivileges,
									  DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
									  PBYTE appletInstallParameters, DWORD appletInstallParametersLength,
									  PBYTE installTokenSignatureData, PDWORD installTokenSignatureDataLength) {
	unsigned char buf[258];
	DWORD i=0;
	DWORD hiByte, loByte;
	LONG result;

	LOG_START(_T("get_install_token_signature_data"));
	buf[i++] = P1;
	buf[i++] = 0x00;
	buf[i++] = 0x00; // Lc dummy
	buf[i++] = (BYTE)packageAIDLength; // package AID
	memcpy(buf+i, packageAID, packageAIDLength);
	i+=packageAIDLength;
	buf[i++] = (BYTE)appletClassAIDLength; // applet class AID
	memcpy(buf+i, appletClassAID, appletClassAIDLength);
	i+=appletClassAIDLength;
	buf[i++] = (BYTE)appletInstanceAIDLength; // applet instance AID
	memcpy(buf+i, appletInstanceAID, appletInstanceAIDLength);
	i+=appletInstanceAIDLength;

	buf[i++] = 0x01;
	buf[i++] = appletPrivileges; // applet privileges

	buf[i++] = 0x00; // install parameter field length
	if (appletInstallParametersLength > 0) {
		buf[i-1] += 2;
		buf[i-1] += (BYTE)appletInstallParametersLength;
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

	if (appletInstallParametersLength > 0) {
		buf[i++] = 0xC9; // applet install parameters
		buf[i++] = (BYTE)appletInstallParametersLength;
		memcpy(buf+i, appletInstallParameters, appletInstallParametersLength);
		i+=appletInstallParametersLength;
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

	buf[2] = (BYTE)i-3+128; // Lc (including 128 byte RSA signature length)
	if (i > *installTokenSignatureDataLength)
		{ result = OPSP_ERROR_INSUFFICIENT_BUFFER; goto end; }
	memcpy(installTokenSignatureData, buf, i);
	*installTokenSignatureDataLength = i;
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("get_install_token_signature_data"), result);
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
 * \param packageAID IN A buffer with AID of the package to INSTALL [for install].
 * \param packageAIDLength IN The length of the package AID.
 * \param appletClassAID IN The AID of the applet class in the package.
 * \param appletClassAIDLength IN The length of the appletClassAID buffer.
 * \param appletInstanceAID IN The AID of the installed applet.
 * \param appletInstanceAIDLength IN The length of the applet instance AID.
 * \param appletPrivileges IN The applet privileges. Can be an OR of multiple privileges. See OPSP_APPLICATION_PRIVILEGE_SECURITY_DOMAIN.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the applet, i.e. the data allocated in its lifetime.
 * \param appletInstallParameters IN Applet install parameters for the install() method of the applet.
 * \param appletInstallParametersLength IN The length of the appletInstallParameters buffer.
 * \param installToken OUT The calculated Install Token. A 1024 bit RSA signature.
 * \param PEMKeyFileName IN A PEM file name with the private RSA key.
 * \param *passPhrase IN The passphrase. Must be an ASCII string.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG calculate_install_token(BYTE P1, PBYTE packageAID, DWORD packageAIDLength, PBYTE appletClassAID,
							 DWORD appletClassAIDLength, PBYTE appletInstanceAID, DWORD appletInstanceAIDLength,
							 BYTE appletPrivileges, DWORD volatileDataSpaceLimit, DWORD nonVolatileDataSpaceLimit,
							 PBYTE appletInstallParameters, DWORD appletInstallParametersLength,
							 BYTE installToken[128], OPSP_STRING PEMKeyFileName, char *passPhrase) {
	LONG result;
	BYTE installTokenSignatureData[256];
	DWORD installTokenSignatureDataLength = 256;
	LOG_START(_T("calculate_install_token"));
	result = get_install_token_signature_data(P1, packageAID, packageAIDLength,
		appletClassAID, appletClassAIDLength, appletInstanceAID,
		appletInstanceAIDLength, appletPrivileges, volatileDataSpaceLimit,
		nonVolatileDataSpaceLimit, appletInstallParameters,
		appletInstallParametersLength, installTokenSignatureData, &installTokenSignatureDataLength);
	if (result != OPSP_ERROR_SUCCESS) {
		goto end;
	}
	result = calculate_rsa_signature(installTokenSignatureData, installTokenSignatureDataLength, PEMKeyFileName,
									passPhrase, installToken);
	if (result != OPSP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPSP_ERROR_SUCCESS; goto end; }
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
static LONG calculate_rsa_signature(PBYTE message, DWORD messageLength, OPSP_STRING PEMKeyFileName,
									char *passPhrase, BYTE signature[128]) {
	LONG result;
	EVP_PKEY *key = NULL;
	FILE *PEMKeyFile = NULL;
	EVP_MD_CTX mdctx;
	unsigned int signatureLength=0;
	LOG_START(_T("calculate_rsa_signature"));
	EVP_MD_CTX_init(&mdctx);
	if (passPhrase == NULL)
		{ result = OPSP_ERROR_INVALID_PASSWORD; goto end; }
	if ((PEMKeyFileName == NULL) || (_tcslen(PEMKeyFileName) == 0))
		{ result = OPSP_ERROR_INVALID_FILENAME; goto end; }
	PEMKeyFile = _tfopen(PEMKeyFileName, _T("rb"));
	if (PEMKeyFile == NULL) {
		{ result = OPSP_ERROR_FILE_NOT_FOUND; goto end; }
	}
	key = EVP_PKEY_new();
	if (!PEM_read_PrivateKey(PEMKeyFile, &key, NULL, passPhrase)) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	};
	result = EVP_SignInit_ex(&mdctx, EVP_sha1(), NULL);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	result = EVP_SignUpdate(&mdctx, message, messageLength);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	if (EVP_PKEY_size(key) > 128) {
		{ result = OPSP_ERROR_INSUFFICIENT_BUFFER; goto end; }
	}
	result = EVP_SignFinal(&mdctx, signature, &signatureLength, key);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	result = EVP_MD_CTX_cleanup(&mdctx);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; }
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
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be NULL, if the card does not need or support this tags.
 * The parameters must match the parameters of a later install_for_load() method.
 * \param packageAID IN A buffer containing the package AID.
 * \param packageAIDLength IN The length of the package AID.
 * \param securityDomainAID IN A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \param loadFileDAP IN The Load File DAP. The same calculated as in install_for_load().
 * \param nonVolatileCodeSpaceLimit IN The minimum space required to store the applet code.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the applet, i.e. the data allocated in its lifetime.
 * \param loadTokenSignatureData OUT The data to sign in a Load Token.
 * \param loadTokenSignatureDataLength INOUT The length of the loadTokenSignatureData buffer.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG get_load_token_signature_data(PBYTE packageAID, DWORD packageAIDLength, PBYTE securityDomainAID,
								   DWORD securityDomainAIDLength, BYTE loadFileDAP[20],
								   DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
								   DWORD nonVolatileDataSpaceLimit, PBYTE loadTokenSignatureData,
								   PDWORD loadTokenSignatureDataLength) {
	unsigned char buf[258];
	DWORD i=0;
	DWORD hiByte, loByte;
	DWORD staticSize;
	LONG result;
	LOG_START(_T("get_load_token_signature_data"));
	buf[i++] = 0x02;
	buf[i++] = 0x00;
	buf[i++] = 0x00; // Lc dummy
	buf[i++] = (BYTE)packageAIDLength; // package AID
	memcpy(buf+i, packageAID, packageAIDLength);
	i+=packageAIDLength;
	buf[i++] = (BYTE)securityDomainAIDLength; // Security Domain AID
	memcpy(buf+i, securityDomainAID, securityDomainAIDLength);
	i+=securityDomainAIDLength;
	if (loadFileDAP != NULL) {
		buf[i++] = 0x14; // length of SHA-1 hash
		memcpy(buf+i, loadFileDAP, 20);
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
	if (i > *loadTokenSignatureDataLength)
		{ result = OPSP_ERROR_INSUFFICIENT_BUFFER; goto end; }
	memcpy(loadTokenSignatureData, buf, i);
	*loadTokenSignatureDataLength = i;
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("get_load_token_signature_data"), result);
	return result;
}

/**
 * The parameters must match the parameters of a later install_for_load() method.
 * \param packageAID IN A buffer containing the package AID.
 * \param packageAIDLength IN The length of the package AID.
 * \param securityDomainAID IN A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \param loadFileDAP IN The Load File DAP. The same calculated as in install_for_load().
 * \param nonVolatileCodeSpaceLimit IN The minimum space required to store the package.
 * \param volatileDataSpaceLimit IN The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit IN The minimum amount of space for objects of the applet, i.e. the data allocated in its lifetime.
 * \param loadToken OUT The calculated Load Token. A 1024 bit RSA signature.
 * \param PEMKeyFileName IN A PEM file name with the private RSA key.
 * \param *passPhrase IN The passphrase. Must be an ASCII string.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG calculate_load_token(PBYTE packageAID, DWORD packageAIDLength, PBYTE securityDomainAID,
						  DWORD securityDomainAIDLength, BYTE loadFileDAP[20],
						  DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
						  DWORD nonVolatileDataSpaceLimit, BYTE loadToken[128],
						  OPSP_STRING PEMKeyFileName, char *passPhrase) {
	LONG result;
	BYTE loadTokenSignatureData[256];
	DWORD loadTokenSignatureDataLength = 256;
	LOG_START(_T("calculate_load_token"));
	result = get_load_token_signature_data(packageAID, packageAIDLength, securityDomainAID, securityDomainAIDLength,
		loadFileDAP, nonVolatileCodeSpaceLimit, volatileDataSpaceLimit, nonVolatileDataSpaceLimit, loadTokenSignatureData, &loadTokenSignatureDataLength);
	if (result != OPSP_ERROR_SUCCESS) {
		goto end;
	}
	result = calculate_rsa_signature(loadTokenSignatureData, loadTokenSignatureDataLength, PEMKeyFileName,
									passPhrase, loadToken);
	if (result != OPSP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("calculate_load_token"), result);
	return result;
}

/**
 * This is a hash of the load file with SHA-1.
 * A load file consists of 0 to n Load File Data Block DAP blocks and a mandatory
 * load file data block, e.g. a CAP file.
 * If no Load File Data Block DAP blocks are necessary the dapBlock must be NULL and the dapBlockLength 0.
 * The dapBlock(s) can be calculated using calculate_3des_dap() or calculate_rsa_dap().
 * If the Load File Data Block DAP block(s) are already calculated they must be parsed into a OPSP_DAP_BLOCK structure.
 * If the Load File Data Block DAP block(s) are already prefixing the CAPFile following the Open Platform Specification 2.0.1',
 * the whole CAPFile including the Load File Data Block DAP block(s) is sufficient, the dapBlock must be NULL and the dapBlockLength 0.
 * \param *dapBlock IN A pointer to OPSP_DAP_BLOCK structure(s).
 * \param dapBlockLength IN The number of OPSP_DAP_BLOCK structure(s).
 * \param CAPFileName IN The name of the CAP file to hash.
 * \param hash OUT The hash value.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG calculate_load_file_DAP(OPSP_DAP_BLOCK *dapBlock, DWORD dapBlockLength, OPSP_STRING CAPFileName,
							 unsigned char hash[20])
{
	LONG result;
	int count;
	DWORD k,j,i;
	unsigned char buf[1024];
	PBYTE dapBuf = NULL;
	DWORD dapBufSize=0;
	FILE *CAPFile = NULL;
	EVP_MD_CTX mdctx;
	LOG_START(_T("calculate_load_file_DAP"));
	EVP_MD_CTX_init(&mdctx);
	if ((CAPFileName == NULL) || (_tcslen(CAPFileName) == 0))
		{ result = OPSP_ERROR_INVALID_FILENAME; goto end; }
	result = EVP_DigestInit_ex(&mdctx, EVP_sha1(), NULL);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	for (i=0; i<dapBlockLength; i++) {
		dapBufSize += dapBlock[i].DAPBlockLength + 1;
	}
	if (dapBlockLength > 0) {
		dapBuf = (PBYTE)malloc(sizeof(BYTE)*dapBufSize);
	}
	for (i=0; i<dapBlockLength; i++) {
		j=0;
		k = dapBufSize;
		result = readDAPBlock(dapBuf, &k, dapBlock[i]);
		if (OPSP_ERROR_SUCCESS != result) {
			goto end;
		}
		result = EVP_DigestUpdate(&mdctx, dapBuf, k);
		if (result != 1) {
			{ result = OPSP_OPENSSL_ERROR; goto end; }
		}
	}
	CAPFile = _tfopen(CAPFileName, _T("rb"));
	if (CAPFile == NULL) {
		{ result = OPSP_ERROR_FILE_NOT_FOUND; goto end; }
	}
	while(feof(CAPFile) == 0) {
		count = (int)fread(buf, sizeof(unsigned char), sizeof(buf), CAPFile);
		if(ferror(CAPFile)) {
			{ result = OPSP_ERROR_READ; goto end; }
		}
		result = EVP_DigestUpdate(&mdctx, buf, count);
		if (result != 1) {
			{ result = OPSP_OPENSSL_ERROR; goto end; }
		}
	}
	result = EVP_DigestFinal_ex(&mdctx, hash, NULL);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	result = EVP_MD_CTX_cleanup(&mdctx);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; }
	}
	if (CAPFile)
		fclose(CAPFile);
	if (dapBuf)
		free(dapBuf);
	LOG_END(_T("calculate_load_file_DAP"), result);
	return result;
}

/**
 * If a security domain has DAP verification privilege the security domain validates this DAP.
 * \param securityDomainAID IN A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \param CAPFileName IN The name of the CAP file to calculate the DAP for.
 * \param DAP_verification_key IN The key to calculate the DAP.
 * \param *dapBlock OUT A pointer to the returned OPSP_DAP_BLOCK structure.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG calculate_3des_DAP(PBYTE securityDomainAID, DWORD securityDomainAIDLength, OPSP_STRING CAPFileName,
						BYTE DAP_verification_key[16], OPSP_DAP_BLOCK *dapBlock)
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
	if ((CAPFileName == NULL) || (_tcslen(CAPFileName) == 0))
		{ result = OPSP_ERROR_INVALID_FILENAME; goto end; }
// DES CBC mode
	memcpy(des_key, DAP_verification_key+8, 8);
	result = EVP_EncryptInit_ex(&ctx, EVP_des_cbc(), NULL, des_key, icv);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	CAPFile = _tfopen(CAPFileName, _T("rb"));
	if (CAPFile == NULL) {
		{ result = OPSP_ERROR_FILE_NOT_FOUND; goto end; }
	}
#ifdef WIN32
	fileSize = _filelength(CAPFile->_file);
	if (fileSize == -1L) {
		{ result = OPSP_ERROR_BAD_FILE_DESCRIPTOR; goto end; }
	}
#else
	fileSize = fseek(CAPFile, 0, SEEK_END);
	if (fileSize == -1) {
		{ result = OPSP_ERROR_BAD_FILE_DESCRIPTOR; goto end; }
	}
	fileSize = ftell(CAPFile);
#endif
	while(feof(CAPFile) == 0) {
		count = (int)fread(buf, sizeof(unsigned char), sizeof(buf), CAPFile);
		if(ferror(CAPFile)) {
			{ result = OPSP_ERROR_READ; goto end; }
		}
		for (i=0; i<count/8; i++) {
			result = EVP_EncryptUpdate(&ctx, dapBlock->signature,
				&outl, buf+i*8, 8);
			if (result != 1) {
				{ result = OPSP_OPENSSL_ERROR; goto end; }
			}
		}
	}
	result = EVP_EncryptFinal_ex(&ctx, dapBlock->signature, &outl);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}

	result = EVP_CIPHER_CTX_cleanup(&ctx);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	EVP_CIPHER_CTX_init(&ctx);
// 3DES CBC mode
	result = EVP_EncryptInit_ex(&ctx, EVP_des_ede_cbc(), NULL, DAP_verification_key, icv);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	if (count%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, dapBlock->signature,
			&outl, buf+i*8, count%8);
		if (result != 1) {
			{ result = OPSP_OPENSSL_ERROR; goto end; }
		}
	}
	result = EVP_EncryptUpdate(&ctx, dapBlock->signature,
		&outl, padding, 8 - (fileSize%8));
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	result = EVP_EncryptFinal_ex(&ctx, dapBlock->signature,
		&outl);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	dapBlock->signatureLength = 8;
	memcpy(dapBlock->securityDomainAID, securityDomainAID, securityDomainAIDLength);
	dapBlock->securityDomainAIDLength = (BYTE)securityDomainAIDLength;
	dapBlock->DAPBlockLength = (BYTE)securityDomainAIDLength+8+4;
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	result = EVP_CIPHER_CTX_cleanup(&ctx);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; }
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
 * \param CAPFileName IN The name of the CAP file to calculate the DAP for.
 * \param PEMKeyFileName IN A PEM file name with the private RSA key.
 * \param *passPhrase IN The passphrase. Must be an ASCII string.
 * \param *dapBlock OUT A pointer to the returned OPSP_DAP_BLOCK structure.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG calculate_rsa_DAP(PBYTE securityDomainAID, DWORD securityDomainAIDLength, OPSP_STRING CAPFileName,
					   OPSP_STRING PEMKeyFileName, char *passPhrase, OPSP_DAP_BLOCK *dapBlock)
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
		{ result = OPSP_ERROR_INVALID_PASSWORD; goto end; }
	if ((CAPFileName == NULL) || (_tcslen(CAPFileName) == 0))
		{ result = OPSP_ERROR_INVALID_FILENAME; goto end; }
	if ((PEMKeyFileName == NULL) || (_tcslen(PEMKeyFileName) == 0))
		{ result = OPSP_ERROR_INVALID_FILENAME; goto end; }
	PEMKeyFile = _tfopen(PEMKeyFileName, _T("rb"));
	if (PEMKeyFile == NULL) {
		{ result = OPSP_ERROR_FILE_NOT_FOUND; goto end; }
	}
	
	key = EVP_PKEY_new();
	if (!PEM_read_PrivateKey(PEMKeyFile, &key, NULL, passPhrase)) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	result = EVP_SignInit_ex(&mdctx, EVP_sha1(), NULL);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	CAPFile = _tfopen(CAPFileName, _T("rb"));
	if (CAPFile == NULL) {
		{ result = OPSP_ERROR_FILE_NOT_FOUND; goto end; }
	}
	while(feof(CAPFile) == 0) {
		count = (int)fread(buf, sizeof(unsigned char), sizeof(buf), CAPFile);
		if(ferror(CAPFile)) {
			{ result = OPSP_ERROR_READ; goto end; }
		}
		result = EVP_SignUpdate(&mdctx, buf, count);
		if (result != 1) {
			{ result = OPSP_OPENSSL_ERROR; goto end; }
		}
	}

	if (EVP_PKEY_size(key) > 128) {
		{ result = OPSP_ERROR_INSUFFICIENT_BUFFER; goto end; }
	}
	result = EVP_SignFinal(&mdctx, dapBlock->signature, &signatureLength, key);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	result = EVP_MD_CTX_cleanup(&mdctx);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}

	dapBlock->signatureLength = 128;
	memcpy(dapBlock->securityDomainAID, securityDomainAID, securityDomainAIDLength);
	dapBlock->securityDomainAIDLength = (BYTE)securityDomainAIDLength;
	dapBlock->DAPBlockLength = (BYTE)securityDomainAIDLength+128+4;
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	result = EVP_MD_CTX_cleanup(&mdctx);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; }
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
 * You may keep track of it. Returns OPSP_ERROR_SUCCESS if receipt is valid.
 * \param confirmationCounter IN The confirmation counter.
 * \param cardUniqueData IN The card unique data (?).
 * \param receipt_generation_key IN The 3DES key to generate the receipt.
 * \param receiptData IN The OPSP_RECEIPT_DATA structure containing the receipt returned
 * from load_applet() to verify.
 * \param packageAID IN A buffer with AID of the package which was INSTALL [for load].
 * \param packageAIDLength IN The length of the package AID.
 * \param securityDomainAID IN A buffer containing the AID of the associated Security Domain.
 * \param securityDomainAIDLength IN The length of the Security Domain AID.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG validate_load_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receipt_generation_key[16], OPSP_RECEIPT_DATA receiptData,
						   PBYTE packageAID, DWORD packageAIDLength,
						   PBYTE securityDomainAID, DWORD securityDomainAIDLength)
{
	LONG result;
	PBYTE validationData = NULL;
	DWORD validationDataLength;
	LOG_START(_T("validate_load_receipt"));
	validationDataLength = 1 + 2 + 1 + 10 + 1 + packageAIDLength + 1 + securityDomainAIDLength;
	validationData = (PBYTE)malloc(validationDataLength);
	validationData[0] = 2;
	validationData[1] = (BYTE)((confirmationCounter & 0x0000FF00) >> 8);
	validationData[2] = (BYTE)(confirmationCounter & 0x000000FF);
	validationData[3] = 10;
	memcpy(validationData, cardUniqueData, 10);
	validationData[13] = (BYTE)packageAIDLength;
	memcpy(validationData, packageAID, packageAIDLength);
	validationData[13+1+packageAIDLength] = (BYTE)securityDomainAIDLength;
	memcpy(validationData, securityDomainAID, securityDomainAIDLength);
	result = validate_receipt(validationData, validationDataLength, receiptData.receipt, receipt_generation_key);
	if (result != OPSP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	if (validationData)
		free(validationData);
	LOG_END(_T("validate_load_receipt"), result);
	return result;
}

/**
 * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
 * You may keep track of it. Returns OPSP_ERROR_SUCCESS if receipt is valid.
 * \param confirmationCounter IN The confirmation counter.
 * \param cardUniqueData IN The card unique data (?).
 * \param receipt_generation_key IN The 3DES key to generate the receipt.
 * \param receiptData IN The OPSP_RECEIPT_DATA structure containing the receipt returned
 * from install_for_install() to verify.
 * \param packageAID IN A buffer with AID of the package which was INSTALL [for install].
 * \param packageAIDLength IN The length of the package AID.
 * \param appletInstanceAID IN The AID of the installed applet.
 * \param appletInstanceAIDLength IN The length of the applet instance AID.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG validate_install_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receipt_generation_key[16], OPSP_RECEIPT_DATA receiptData,
						   PBYTE packageAID, DWORD packageAIDLength,
						   PBYTE appletInstanceAID, DWORD appletInstanceAIDLength)
{
	LONG result;
	PBYTE validationData;
	DWORD validationDataLength;
	LOG_START(_T("validate_install_receipt"));
	validationDataLength = 1 + 2 + 1 + 10 + 1 + packageAIDLength + 1 + appletInstanceAIDLength;
	validationData = (PBYTE)malloc(validationDataLength);
	validationData[0] = 2;
	validationData[1] = (BYTE)((confirmationCounter & 0x0000FF00) >> 8);
	validationData[2] = (BYTE)(confirmationCounter & 0x000000FF);
	validationData[3] = 10;
	memcpy(validationData, cardUniqueData, 10);
	validationData[13] = (BYTE)packageAIDLength;
	memcpy(validationData, packageAID, packageAIDLength);
	validationData[13+1+packageAIDLength] = (BYTE)appletInstanceAIDLength;
	memcpy(validationData, appletInstanceAID, appletInstanceAIDLength);
	result = validate_receipt(validationData, validationDataLength, receiptData.receipt, receipt_generation_key);
	free(validationData);
	if (result != OPSP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("validate_install_receipt"), result);
	return result;
}

/**
 * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
 * You may keep track of it. Returns OPSP_ERROR_SUCCESS if receipt is valid.
 * \param confirmationCounter IN The confirmation counter.
 * \param cardUniqueData IN The card unique data (?).
 * \param receipt_generation_key IN The 3DES key to generate the receipt.
 * \param receiptData IN The OPSP_RECEIPT_DATA structure containing the receipt returned
 * from delete_applet() to verify.
 * \param AID IN A buffer with AID of the application which was deleted.
 * \param AIDLength IN The length of the AID.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG validate_delete_receipt(DWORD confirmationCounter, BYTE cardUniqueData[10],
						   BYTE receipt_generation_key[16], OPSP_RECEIPT_DATA receiptData,
						   PBYTE AID, DWORD AIDLength)
{
	LONG result;
	PBYTE validationData = NULL;
	DWORD validationDataLength;
	LOG_START(_T("validate_delete_receipt"));
	validationDataLength = 1 + 2 + 1 + 10 + 1 + AIDLength;
	validationData = (PBYTE)malloc(validationDataLength);
	validationData[0] = 2;
	validationData[1] = (BYTE)((confirmationCounter & 0x0000FF00) >> 8);
	validationData[2] = (BYTE)(confirmationCounter & 0x000000FF);
	validationData[3] = 10;
	memcpy(validationData, cardUniqueData, 10);
	validationData[13] = (BYTE)AIDLength;
	memcpy(validationData, AID, AIDLength);
	result = validate_receipt(validationData, validationDataLength, receiptData.receipt, receipt_generation_key);
	if (result != OPSP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	if (validationData)
		free(validationData);
	LOG_END(_T("validate_delete_receipt"), result);
	return result;
}

/**
 * Open Platform: Validates a Receipt.
 * Returns OPSP_ERROR_SUCCESS if the receipt is valid.
 * \param validationData IN The data used to validate the returned receipt.
 * \param validationDataLength IN The length of the validationData buffer.
 * \param receipt IN The receipt.
 * \param receipt_generation_key IN The 3DES key to generate the receipt.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
static LONG validate_receipt(PBYTE validationData, DWORD validationDataLength,
							 BYTE receipt[16], BYTE receipt_generation_key[16])
{
	LONG result;
	BYTE mac[8];
	LOG_START(_T("validate_receipt"));
	result = calculate_MAC_des_3des(receipt_generation_key, validationData, validationDataLength, icv, mac);
	if (result != OPSP_ERROR_SUCCESS) {
		goto end;
	}
	if (memcmp(mac, receipt, 8) != 0) {
		{ result = OPSP_ERROR_VALIDATION_FAILED; goto end; }
	}
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("validate_receipt"), result);
	return result;
}

/**
 * Calculates a message authentication code using the left half key of a two key 3DES key
 and the the full key for the final operation.
 * \param _3des_key[16] IN A 3DES key used to sign.
 * \param *message IN The message to authenticate.
 * \param messageLength IN The message length.
 * \param icv[8] IN The initial chaining vector.
 * \param mac[8] OUT The calculated MAC.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
static LONG calculate_MAC_des_3des(unsigned char _3des_key[16], unsigned char *message, int messageLength,
						  unsigned char icv[8], unsigned char mac[8]) {
	LONG result;
	int i,outl;
	EVP_CIPHER_CTX ctx;
	unsigned char des_key[8];
	LOG_START(_T("calculate_MAC_des_3des"));
	EVP_CIPHER_CTX_init(&ctx);
// DES CBC mode
	memcpy(des_key, _3des_key+8, 8);
	result = EVP_EncryptInit_ex(&ctx, EVP_des_cbc(), NULL, des_key, icv);
	if (result != 1) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(&ctx, mac,
			&outl, message+i*8, 8);
		if (result != 1) {
			EVP_CIPHER_CTX_cleanup(&ctx);
			{ result = OPSP_OPENSSL_ERROR; goto end; }
		}
	}
	result = EVP_EncryptFinal_ex(&ctx, mac,
		&outl);
	if (result != 1) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	result = EVP_CIPHER_CTX_cleanup(&ctx);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
// 3DES CBC mode
	result = EVP_EncryptInit_ex(&ctx, EVP_des_ede_cbc(), NULL, _3des_key, icv);
	if (result != 1) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, mac,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			EVP_CIPHER_CTX_cleanup(&ctx);
			{ result = OPSP_OPENSSL_ERROR; goto end; }
		}
	}
	result = EVP_EncryptUpdate(&ctx, mac,
		&outl, padding, 8 - (messageLength%8));
	if (result != 1) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	result = EVP_EncryptFinal_ex(&ctx, mac,
		&outl);
	if (result != 1) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	result = EVP_CIPHER_CTX_cleanup(&ctx);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("calculate_MAC_des_3des"), result);
	return result;
}

/**
 * Creates the session key.
 * \param key[16] IN The static 3DES ENC/AUTH key or static 3DES MAC key for calculating the corresponding session key.
 * \param card_challenge[8] IN The card challenge.
 * \param host_challenge[8] IN The host challenge.
 * \param session_key[8] OUT The calculated 3DES session key.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
static LONG create_session_key(unsigned char key[16], unsigned char card_challenge[8],
							   unsigned char host_challenge[8], unsigned char session_key[16]) {
	LONG result;
	unsigned char derivation_data[16];
	int outl;

	LOG_START(_T("create_session_key"));
	memcpy(derivation_data, card_challenge+4, 4);
	memcpy(derivation_data+4, host_challenge, 4);
	memcpy(derivation_data+8, card_challenge, 4);
	memcpy(derivation_data+12, host_challenge+4, 4);

	result = calculate_enc_ecb(key, derivation_data, 16, session_key, &outl);
	if (result != OPSP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("create_session_key"), result);
	return result;
}

/**
 * Calculates the encryption of a message in ECB mode.
 * \param key[16] IN A 3DES key used to encrypt.
 * \param *message IN The message to encrypt.
 * \param messageLength IN The length of the message.
 * \param *encryption OUT The encryption.
 * \param *encryptionLength OUT The length of the encryption.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
static LONG calculate_enc_ecb(unsigned char key[16], unsigned char *message, int messageLength,
							  unsigned char *encryption, int *encryptionLength) {
	LONG result;
	int i,outl;
	EVP_CIPHER_CTX ctx;
	LOG_START(_T("calculate_enc_ecb"));
	EVP_CIPHER_CTX_init(&ctx);
	*encryptionLength = 0;

	result = EVP_EncryptInit_ex(&ctx, EVP_des_ede(), NULL, key, icv);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, 8);
		if (result != 1) {
			{ result = OPSP_OPENSSL_ERROR; goto end; }
		}
		*encryptionLength+=outl;
	}
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			{ result = OPSP_OPENSSL_ERROR; goto end; }
		}
		*encryptionLength+=outl;

		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, padding, 8 - (messageLength%8));
		if (result != 1) {
			{ result = OPSP_OPENSSL_ERROR; goto end; }
		}
		*encryptionLength+=outl;
	}
	result = EVP_EncryptFinal_ex(&ctx, encryption+*encryptionLength,
		&outl);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	*encryptionLength+=outl;
	result = EVP_CIPHER_CTX_cleanup(&ctx);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("calculate_enc_ecb"), result);
	return result;
}

/**
 * Calculates a message authentication code.
 * \param session_key[16] IN A 3DES key used to sign.
 * \param *message IN The message to authenticate.
 * \param messageLength IN The message length.
 * \param icv[8] IN The initial chaining vector.
 * \param mac[8] OUT The calculated MAC.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
static LONG calculate_MAC(unsigned char session_key[16], unsigned char *message, int messageLength,
						  unsigned char icv[8], unsigned char mac[8]) {
	LONG result;
	int i,outl;
	EVP_CIPHER_CTX ctx;
	LOG_START(_T("calculate_MAC"));
	EVP_CIPHER_CTX_init(&ctx);

	result = EVP_EncryptInit_ex(&ctx, EVP_des_ede_cbc(), NULL, session_key, icv);
	if (result != 1) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(&ctx, mac,
			&outl, message+i*8, 8);
		if (result != 1) {
			EVP_CIPHER_CTX_cleanup(&ctx);
			{ result = OPSP_OPENSSL_ERROR; goto end; }
		}
	}
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, mac,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			EVP_CIPHER_CTX_cleanup(&ctx);
			{ result = OPSP_OPENSSL_ERROR; goto end; }
		}
	}
	result = EVP_EncryptUpdate(&ctx, mac,
		&outl, padding, 8 - (messageLength%8));
	if (result != 1) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	result = EVP_EncryptFinal_ex(&ctx, mac,
		&outl);
	if (result != 1) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	result = EVP_CIPHER_CTX_cleanup(&ctx);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("calculate_MAC"), result);
	return result;
}

/**
 * Calculates the encryption of a message in CBC mode.
 * \param session_key[16] IN A 3DES key used to encrypt.
 * \param *message IN The message to encrypt.
 * \param messageLength IN The length of the message.
 * \param *encryption OUT The encryption.
 * \param *encryptionLength OUT The length of the encryption.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
static LONG calculate_enc_cbc(unsigned char session_key[16], unsigned char *message, int messageLength,
							  unsigned char *encryption, int *encryptionLength) {
	LONG result;
	int i,outl;
	EVP_CIPHER_CTX ctx;
	LOG_START(_T("calculate_enc_cbc"));
	EVP_CIPHER_CTX_init(&ctx);
	*encryptionLength = 0;

	result = EVP_EncryptInit_ex(&ctx, EVP_des_ede_cbc(), NULL, session_key, icv);
	if (result != 1) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	for (i=0; i<messageLength/8; i++) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, 8);
		if (result != 1) {
			EVP_CIPHER_CTX_cleanup(&ctx);
			{ result = OPSP_OPENSSL_ERROR; goto end; }
		}
		*encryptionLength+=outl;
	}
	if (messageLength%8 != 0) {
		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, message+i*8, messageLength%8);
		if (result != 1) {
			EVP_CIPHER_CTX_cleanup(&ctx);
			{ result = OPSP_OPENSSL_ERROR; goto end; }
		}
		*encryptionLength+=outl;

		result = EVP_EncryptUpdate(&ctx, encryption+*encryptionLength,
			&outl, padding, 8 - (messageLength%8));
		if (result != 1) {
			EVP_CIPHER_CTX_cleanup(&ctx);
			{ result = OPSP_OPENSSL_ERROR; goto end; }
		}
		*encryptionLength+=outl;
	}
	result = EVP_EncryptFinal_ex(&ctx, encryption+*encryptionLength,
		&outl);
	if (result != 1) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	*encryptionLength+=outl;
	result = EVP_CIPHER_CTX_cleanup(&ctx);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("calculate_enc_cbc"), result);
	return result;
}

/**
 * Calculates the card cryptogram.
 * \param session_enc_key[16] IN The 3DES session ENC key for calculating the card cryptogram.
 * \param card_challenge[8] IN The card challenge.
 * \param host_challenge[8] IN The host challenge.
 * \param card_cryptogram[8] OUT The calculated card cryptogram.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
static LONG calculate_card_cryptogram(unsigned char session_enc_key[16], unsigned char card_challenge[8],
									  unsigned char host_challenge[8], unsigned char card_cryptogram[8]) {
	LONG result;
	unsigned char message[16];
	LOG_START(_T("calculate_card_cryptogram"));
	memcpy(message, host_challenge, 8);
	memcpy(message+8, card_challenge, 8);
	result = calculate_MAC(session_enc_key, message, 16, icv, card_cryptogram);
	if (result != OPSP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("calculate_card_cryptogram"), result);
	return result;
}

/**
 * Calculates the host cryptogram.
 * \param session_enc_key[16] IN The 3DES session ENC key for calculating the host cryptogram.
 * \param card_challenge[8] IN The card challenge.
 * \param host_challenge[8] IN The host challenge.
 * \param card_cryptogram[8] OUT The calculated host cryptogram.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
static LONG calculate_host_cryptogram(unsigned char session_enc_key[16], unsigned char card_challenge[8],
									  unsigned char host_challenge[8], unsigned char host_cryptogram[8]) {
	LONG result;
	unsigned char message[16];
	LOG_START(_T("calculate_host_cryptogram"));
	memcpy(message, card_challenge, 8);
	memcpy(message+8, host_challenge, 8);
	result = calculate_MAC(session_enc_key, message, 16, icv, host_cryptogram);
	if (result != OPSP_ERROR_SUCCESS) {
		goto end;
	}
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("calculate_host_cryptogram"), result);
	return result;
}

/**
 * A keySetVersion and keyIndex of 0x00 selects the first available key set version and key index.
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param enc_key IN The static encryption key.
 * \param mac_key IN The static MAC key.
 * \param keySetVersion IN The key set version on the card to use for mutual authentication.
 * \param keyIndex IN The key index of the encryption key in the key set version on the card to use for mutual authentication.
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param securityLevel IN The requested security level.
 * \param *secInfo OUT The returned OPSP_SECURITY_INFO structure.
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG mutual_authentication(OPSP_CARDHANDLE cardHandle, BYTE enc_key[16], BYTE mac_key[16], BYTE keySetVersion,
						   BYTE keyIndex, OPSP_CARD_INFO cardInfo, BYTE securityLevel, OPSP_SECURITY_INFO *secInfo) {
	LONG result;
	DWORD i=0;

	unsigned char host_challenge[8];

	unsigned char key_diversification_data[10];
	unsigned char key_information_data[2];
	unsigned char card_challenge[8];
	unsigned char card_cryptogram[8];

	unsigned char card_cryptogram_ver[8];
	unsigned char host_cryptogram[8];
	unsigned char mac[8];

	DWORD sendBufferLength;
	DWORD recvBufferLength=256;
	BYTE recvBuffer[256];
	PBYTE sendBuffer = NULL;
	// random for host challenge

	LOG_START(_T("mutual_authentication"));
	result = RAND_bytes(host_challenge, 8);
	if (result != 1) {
		{ result = OPSP_OPENSSL_ERROR; goto end; }
	}

	// INITIALIZE UPDATE
	sendBufferLength = 14;
	sendBuffer = (PBYTE)malloc(sizeof(BYTE)*sendBufferLength);
	sendBuffer[i++] = 0x80;
	sendBuffer[i++] = 0x50;
	sendBuffer[i++] = keySetVersion;
	sendBuffer[i++] = keyIndex;
	sendBuffer[i++] = 0x08;
	memcpy(sendBuffer+i, host_challenge, 8);
	i+=8;
	sendBuffer[i] = 0x00;
#ifdef DEBUG
	log_Log(_T("mutual_authentication: INITIALIZE UPDATE Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}
	
#endif
	result = send_APDU(cardHandle,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, NULL);
	if ( OPSP_ERROR_SUCCESS != result) {
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
	memcpy(card_challenge, recvBuffer+12, 8);
	memcpy(card_cryptogram, recvBuffer+20, 8);

#ifdef DEBUG
	log_Log(_T("mutual_authentication: card_challenge: "));
	for (i=0; i<8; i++) {
		log_Log(_T("0x%02x "), card_challenge[i]);
	}
	

	log_Log(_T("mutual_authentication: host_challenge: "));
	for (i=0; i<8; i++) {
		log_Log(_T("0x%02x "), host_challenge[i]);
	}
	

	log_Log(_T("mutual_authentication: card_cryptogram: "));
	for (i=0; i<8; i++) {
		log_Log(_T("0x%02x "), card_cryptogram[i]);
	}
	
#endif

	// calculation of ENC session key
	result = create_session_key(enc_key, card_challenge, host_challenge, secInfo->session_enc_key);
	if (result != OPSP_ERROR_SUCCESS) {
		goto end;
	}

#ifdef DEBUG
	log_Log(_T("mutual_authentication: session_enc_key: "));
	for (i=0; i<16; i++) {
		log_Log(_T("0x%02x "), secInfo->session_enc_key[i]);
	}
	
#endif

	// calculation of MAC session key
	result = create_session_key(mac_key, card_challenge, host_challenge, secInfo->session_mac_key);
	if (result != OPSP_ERROR_SUCCESS) {
		goto end;
	}
	// calculation of card cryptogram
	result = calculate_card_cryptogram(secInfo->session_enc_key, card_challenge, host_challenge, card_cryptogram_ver);
	if (result != OPSP_ERROR_SUCCESS) {
		goto end;
	}

#ifdef DEBUG
	log_Log(_T("card_cryptogram_ver: "));
	for (i=0; i<8; i++) {
		log_Log(_T("0x%02x "), card_cryptogram_ver[i]);
	}
	
#endif

	if (memcmp(card_cryptogram, card_cryptogram_ver, 8) != 0) {
		{ result = OPSP_ERROR_CARD_CRYPTOGRAM_VERIFICATION; goto end; }
	}

	// EXTERNAL AUTHENTICATE
	secInfo->security_level = securityLevel;
	calculate_host_cryptogram(secInfo->session_enc_key, card_challenge, host_challenge, host_cryptogram);
	sendBufferLength = 21;
	sendBuffer = (PBYTE)malloc(sizeof(BYTE)*sendBufferLength);
	i=0;
	sendBuffer[i++] = 0x84;
	sendBuffer[i++] = 0x82;
	sendBuffer[i++] = securityLevel;
	sendBuffer[i++] = 0x00;
	sendBuffer[i++] = 0x10;
	memcpy(sendBuffer+i, host_cryptogram, 8);
	i+=8;
	calculate_MAC(secInfo->session_mac_key, sendBuffer, sendBufferLength-8, icv, mac);
	memcpy(secInfo->last_mac, mac, 8);
	memcpy(sendBuffer+i, mac, 8);
	i+=8;
#ifdef DEBUG
	log_Log(_T("mutual_authentication: EXTERNAL AUTHENTICATE Data to send: "));
	for (i=0; i<sendBufferLength; i++) {
		log_Log(_T(" 0x%02x"), sendBuffer[i]);
	}
	
#endif
	result = send_APDU(cardHandle,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, NULL);
	if ( OPSP_ERROR_SUCCESS != result) {
		switch (result) {
			case OPSP_ISO7816_ERROR_6300:
				{ result = OPSP_ISO7816_ERROR_HOST_CRYPTOGRAM_VERIFICATION; goto end; }
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
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	if (sendBuffer)
		free(sendBuffer);
	LOG_END(_T("mutual_authentication"), result);
	return result;
}


/**
 * \return The last OpenSSL error code.
 */
unsigned long get_last_OpenSSL_error_code(void) {
	return ERR_get_error();
}

///**
// * \return The last NSS error code.
// */
//unsigned long get_last_NSS_error_code(void) {
//	return PR_GetError();
//}


/**
 * The single numbers of the new PIN are encoded as single BYTEs in the newPIN buffer.
 * The tryLimit must be in the range of 0x03 and x0A.
 * The PIN must comprise at least 6 numbers and not exceeding 12 numbers.
 * To unblock the PIN use tryLimit with a value of 0x00. In this case newPIN buffer and newPINLength are ignored.
 * \param cardHandle IN The reference OPSP_CARDHANDLE obtained by card_connect().
 * \param *secInfo INOUT The pointer to the OPSP_SECURITY_INFO structure returned by mutual_authentication().
 * \param cardInfo IN The OPSP_CARD_INFO structure returned by get_card_status().
 * \param tryLimit IN The try limit for the PIN.
 * \param newPIN IN The new PIN.
 * \param newPINLength IN The length of the new PIN.
 * \param kek_key IN The Key Encryption key (KEK).
 * \return OPSP_ERROR_SUCCESS if no error, error code else.
 */
LONG pin_change(OPSP_CARDHANDLE cardHandle, OPSP_SECURITY_INFO *secInfo, OPSP_CARD_INFO cardInfo, BYTE tryLimit,
				PBYTE newPIN, DWORD newPINLength, BYTE kek_key[16]) {
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
		{ result = OPSP_ERROR_WRONG_TRY_LIMIT; goto end; }
	}
	if ((newPINLength < 6) || (newPINLength > 12)) {
		{ result = OPSP_ERROR_WRONG_PIN_LENGTH; goto end; }
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
		calculate_enc_ecb(kek_key, PINFormat, 8, encryption, &encryptionLength);
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
	result = send_APDU(cardHandle,sendBuffer, sendBufferLength, recvBuffer, &recvBufferLength, cardInfo, secInfo);
	if (OPSP_ERROR_SUCCESS != result) {
		if (result == OPSP_ISO7816_ERROR_WRONG_DATA)
			{ result = OPSP_ISO7816_ERROR_WRONG_GLOBAL_PIN_FORMAT; goto end; }
		if (result == OPSP_ISO7816_ERROR_INCORRECT_P1P2)
			{ result = OPSP_ISO7816_ERROR_WRONG_PIN_TRY_LIMIT; goto end; }
		goto end;
	}
#ifdef DEBUG
	log_Log(_T("pin_change: Data: "));
	for (i=0; i<recvBufferLength; i++) {
		log_Log(_T(" 0x%02x"), recvBuffer[i]);
	}
	
#endif
	{ result = OPSP_ERROR_SUCCESS; goto end; }
end:
	LOG_END(_T("pin_change"), result);
	return result;
}

/**
 * \param errorCode IN The error code.
 * \return OPSP_STRING representation of the error code.
 */
OPSP_STRING stringify_error(DWORD errorCode) {
	OPSP_STRING code;
	OPSP_STRING prefix;
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
	if (errorCode == OPSP_OPENSSL_ERROR) {
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
	if (errorCode == OPSP_ERROR_COMMAND_TOO_LARGE)
		return _T("The command data is too large.");
	if (errorCode == OPSP_ERROR_UNRECOGNIZED_APDU_COMMAND)
		return _T("A APDU command can't be recognized as a valid T=0 protocol Case 1-4 ISO7816-4 APDU");
	if (errorCode == OPSP_ERROR_CARD_CRYPTOGRAM_VERIFICATION)
		return _T("The verification of the card cryptogram failed.");
	if (errorCode == OPSP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE)
		return _T("The command is too large for secure messaging.");
	if (errorCode == OPSP_ERROR_INSUFFICIENT_BUFFER)
		return _T("A used buffer is too small.");
	if (errorCode == OPSP_ERROR_MORE_APPLICATION_DATA)
		return _T("More Card Manager, package or application data is available.");
	if (errorCode == OPSP_ERROR_WRONG_TRY_LIMIT)
		return _T("Wrong maximum try limit.");
	if (errorCode == OPSP_ERROR_WRONG_PIN_LENGTH)
		return _T("Wrong PIN length.");
	if (errorCode == OPSP_ERROR_WRONG_KEY_VERSION)
		return _T("Wrong key version.");
	if (errorCode == OPSP_ERROR_WRONG_KEY_INDEX)
		return _T("Wrong key index.");
	if (errorCode == OPSP_ERROR_WRONG_KEY_TYPE)
		return _T("Wrong key type.");
	if (errorCode == OPSP_ERROR_KEY_CHECK_VALUE)
		return _T("Key check value reported does not match.");
	if (errorCode == OPSP_ERROR_INVALID_COMBINATION_KEY_SET_VERSION_KEY_INDEX)
		return _T("The combination of key set version and key index is invalid.");
	if (errorCode == OPSP_ERROR_MORE_KEY_INFORMATION_TEMPLATES)
		return _T("More key information templates are available.");
	if (errorCode == OPSP_ERROR_APPLICATION_TOO_BIG)
		return _T("The application to load must be less than 32535 bytes.");
	if (errorCode == OPSP_ERROR_VALIDATION_FAILED)
		return _T("A validation has failed.");
	if (errorCode == OPSP_ERROR_INVALID_FILENAME)
		return _T("A file name is invalid.");
	if (errorCode == OPSP_ERROR_INVALID_PASSWORD)
		return _T("A password is invalid.");
	if (errorCode == OPSP_ERROR_FILE_NOT_FOUND)
		return _T("A file is not found.");		
	if (errorCode == OPSP_ERROR_WRONG_EXPONENT)
		return _T("The exponent must be 3 or 65537.");
	if (errorCode == OPSP_ERROR_BAD_FILE_DESCRIPTOR)
		return _T("Problems reading the file.");
	if ((errorCode & ((DWORD)0xFFFFFF00L)) == OPSP_ISO7816_ERROR_CORRECT_LENGTH) {
		code = (OPSP_STRING)malloc(sizeof(TCHAR)*3);
		#ifdef WIN32
		_ultot(errorCode&0x000000ff, code, 16);
		#else
		sprintf(code, "%lx", errorCode&0x000000ff);
		#endif
		prefix = (OPSP_STRING)malloc(sizeof(TCHAR)*(_tcslen(_T("Wrong length Le: Exact length: 0x"))+1));
		_tcscpy(prefix, _T("Wrong length Le: Exact length: 0x"));
		if (_tcslen(prefix)+_tcslen(code)+1 > strErrorSize ) {
			_tcsncpy(strError, prefix, strErrorSize-_tcslen(code)-1);
			_tcscpy(&strError[strErrorSize-_tcslen(code)-1], code);
		}
		else {
			_tcscpy(strError, prefix);
			_tcscpy(&strError[_tcslen(prefix)], code);
		}
		free(code);
		free(prefix);
		return strError;
	} // if ((errorCode & ((DWORD)0xFFFFFF00L)) == OPSP_ISO7816_ERROR_CORRECT_LENGTH)
	if ((errorCode & ((DWORD)0xFFFFFF00L)) == OPSP_ISO7816_ERROR_RESPONSE_LENGTH) {
		code = (OPSP_STRING)malloc(sizeof(TCHAR)*3);
		#ifdef WIN32
		_ultot(errorCode&0x000000ff, code, 16);
		#else
		sprintf(code, "%lx", errorCode&0x000000ff);
		#endif
		prefix = (OPSP_STRING)malloc(sizeof(TCHAR)*(_tcslen(_T("Number of response bytes still available: 0x"))+1));
		_tcscpy(prefix, _T("Number of response bytes still available: 0x"));
		if (_tcslen(prefix)+_tcslen(code)+1 > strErrorSize ) {
			_tcsncpy(strError, prefix, strErrorSize-_tcslen(code)-1);
			_tcscpy(&strError[strErrorSize-_tcslen(code)-1], code);
		}
		else {
			_tcscpy(strError, prefix);
			_tcscpy(&strError[_tcslen(prefix)], code);
		}
		free(code);
		free(prefix);
		return strError;
	}
	if ((errorCode & ((DWORD)0xFFF00000L)) == ((DWORD)0x80200000L)) {
		switch(errorCode) {
// 0x63
			case OPSP_ISO7816_ERROR_HOST_CRYPTOGRAM_VERIFICATION:
				return _T("6300: Authentication of host cryptogram failed.");
			case OPSP_ISO7816_ERROR_MORE_DATA_AVAILABLE:
				return _T("6310: More data available.");
// 0x63

// 0x67
			case OPSP_ISO7816_ERROR_WRONG_LENGTH:
				return _T("6700: Wrong length.");
// 0x67
			case OPSP_ISO7816_ERROR_SECURE_MESSAGING_NOT_SUPPORTED:
				return _T("6882: Function not supported - Secure messaging not supported.");
// 0x69
			case OPSP_ISO7816_ERROR_CONDITIONS_NOT_SATISFIED:
				return _T("6985: Command not allowed - Conditions of use not satisfied.");
			case OPSP_ISO7816_ERROR_NOT_MULTI_SELECTABLE:
				return _T("6985: The applet to be selected is not multi-selectable, but its context is already active.");
			case OPSP_ISO7816_ERROR_SELECTION_REJECTED:
				return _T("6999: The applet to be selected rejects selection or throws an exception.");
// 0x69

// 0x6a
			case OPSP_ISO7816_ERROR_WRONG_DATA:
				return _T("6A80: Wrong data / Incorrect values in command data.");
			case OPSP_ISO7816_ERROR_WRONG_GLOBAL_PIN_FORMAT:
				return _T("6A80: Wrong format for global PIN.");

			case OPSP_ISO7816_ERROR_FUNC_NOT_SUPPORTED:
				return _T("6A81: Function not supported.");
			case OPSP_ISO7816_ERROR_APPLET_NOT_SELECTABLE:
				return _T("6A81: Card life cycle is CM_LOCKED or selected application was not in a selectable state.");

			case OPSP_ISO7816_ERROR_NOT_ENOUGH_MEMORY:
				return _T("6A84: Not enough memory space.");
			case OPSP_ISO7816_ERROR_INCORRECT_P1P2:
				return _T("6A86: Incorrect parameters (P1, P2).");
			case OPSP_ISO7816_ERROR_WRONG_PIN_TRY_LIMIT:
				return _T("6A86: Wrong parameter P2 (PIN try limit).");
			case OPSP_ISO7816_ERROR_DATA_NOT_FOUND:
				return _T("6A88: Referenced data not found.");

			case OPSP_ISO7816_ERROR_FILE_NOT_FOUND:
				return _T("6A82: File not found.");
			case OPSP_ISO7816_ERROR_APPLET_NOT_FOUND:
				return _T("6A82: The applet to be selected could not be found.");
// 0x6a
			case OPSP_ISO7816_ERROR_NOTHING_SPECIFIC:
				return _T("6400: No specific diagnostic.");
			case OPSP_ISO7816_ERROR_SECURITY_STATUS_NOT_SATISFIED:
				return _T("6982: Command not allowed - Security status not satisfied.");
// 0x62
			case OPSP_ISO7816_ERROR_FILE_INVALIDATED:
				return _T("6283: Selected file invalidated.");
			case OPSP_ISO7816_WARNING_CM_LOCKED:
				return _T("6283: Card life cycle state is CM_LOCKED.");
// 0x62
			case OPSP_ISO7816_ERROR_FILE_TERMINATED:
				return _T("6285: SELECT FILE Warning: selected file is terminated.");
			case OPSP_ISO7816_ERROR_MEMORY_FAILURE:
				return _T("6581: Memory failure or EDC check failed.");
			case OPSP_ISO7816_ERROR_CHANNEL_NOT_SUPPORTED:
				return _T("6881: Function not supported - Logical channel not supported/open.");
			case OPSP_ISO7816_ERROR_ILLEGAL_PARAMETER:
				return _T("6F74: Illegal parameter.");
			case OPSP_ISO7816_ERROR_WRONG_CLA:
				return _T("6E00: Wrong CLA byte.");
			case OPSP_ISO7816_ERROR_INVALID_INS:
				return _T("6D00: Invalid instruction byte / Command not supported or invalid.");
			case OPSP_ISO7816_ERROR_WRONG_P1P2:
				return _T("6B00: Wrong parameters (P1, P2).");
// 0x94
			case OPSP_ISO7816_ERROR_ALGORITHM_NOT_SUPPORTED:
				return _T("9484: Algorithm not supported.");
			case OPSP_ISO7816_ERROR_INVALID_KEY_CHECK_VALUE:
				return _T("9485: Invalid key check value.");
// 0x94

			default:
				code = (OPSP_STRING)malloc(sizeof(TCHAR)*9);
				#ifdef WIN32
				_ultot(errorCode, code, 16);
				#else
				sprintf(code, "%lx", errorCode&0x000000ff);
				#endif
				prefix = (OPSP_STRING)malloc(sizeof(TCHAR)*(_tcslen(_T("Unknown ISO7816 error: 0x"))+1));
				_tcscpy(prefix, _T("Unknown ISO7816 error: 0x"));
				if (_tcslen(prefix)+_tcslen(code+4)+1 > strErrorSize ) {
					_tcsncpy(strError, prefix, strErrorSize-_tcslen(code+4)-1);
					_tcscpy(&strError[strErrorSize-_tcslen(code+4)-1], code+4);
				}
				else {
					_tcscpy(strError, prefix);
					_tcscpy(&strError[_tcslen(prefix)], code+4);
				}
				free(code);
				free(prefix);
				return strError;
		} // switch(errorCode)
	} // if ((errorCode & ((DWORD)0xFFF00000L)) == ((DWORD)0x80200000L))
	else {
	#ifndef WIN32
		if ((errorCode & ((DWORD)0xFFF00000L)) == ((DWORD)0x80100000L)) {
			return (OPSP_STRING)pcsc_stringify_error((long)errorCode);
		}
	#endif
		switch (errorCode)
		{
			case OPSP_ERROR_SUCCESS:
	#ifdef _WIN32
			default:
				FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
					NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (OPSP_STRING) &lpMsgBuf, 0, NULL);
				if (_tcslen((OPSP_STRING)lpMsgBuf)+1 > strErrorSize ) {
					_tcsncpy(strError, (OPSP_STRING)lpMsgBuf, strErrorSize-1);
					strError[strErrorSize-1] = _T('\0');
				}
				else {
					_tcscpy(strError, (OPSP_STRING)lpMsgBuf);
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
