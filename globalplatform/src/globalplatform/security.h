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
 * This file contains security related definitions.
  */

#ifndef SECURITY_H_
#define SECURITY_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "types.h"

#define OP_201 201 //!< OpenPlatform specification 2.0.1' mode
#define GP_211 211 //!< GlobalPlatform specification 2.1.1 mode

/* Secure Channel stuff */

#define GP211_SCP01 0x01 //!< Secure Channel Protocol '01'
#define GP211_SCP02 0x02 //!< Secure Channel Protocol '02'
#define GP211_SCP03 0x03 //!< Secure Channel Protocol '03'

/** Secure Channel Protocol '01': "i" '05': Initiation mode explicit, C-MAC on modified APDU,
  * ICV set to zero, no ICV encryption, 3 Secure Channel Keys
  */
#define GP211_SCP01_IMPL_i05 0x05
/** Secure Channel Protocol '01': "i" '15': Initiation mode explicit, C-MAC on modified APDU,
  * ICV set to zero, ICV encryption, 3 Secure Channel Keys
  */
#define GP211_SCP01_IMPL_i15 0x15

/** Secure Channel Protocol '02': "i" = '44': Initiation mode explicit, C-MAC on modified APDU,
  * ICV set to zero, no ICV encryption, 1 Secure Channel base key,
  * well-known pseudo-random algorithm (card challenge),
  */
#define GP211_SCP02_IMPL_i44 0x44
/** Secure Channel Protocol '02': "i" = '45': Initiation mode explicit, C-MAC on modified APDU,
  * ICV set to zero, no ICV encryption, 3 Secure Channel Keys,
  * well-known pseudo-random algorithm (card challenge),
  */

#define GP211_SCP02_IMPL_i45 0x45
/** Secure Channel Protocol '02': "i" = '54': Initiation mode explicit, C-MAC on modified APDU,
  * ICV set to zero, ICV encryption for C-MAC session, 1 Secure Channel base key,
  * well-known pseudo-random algorithm (card challenge),
  */
#define GP211_SCP02_IMPL_i54 0x54
/** Secure Channel Protocol '02': "i" = '55': Initiation mode explicit, C-MAC on modified APDU,
  * ICV set to zero, ICV encryption for C-MAC session, 3 Secure Channel Keys,
  * well-known pseudo-random algorithm (card challenge).�
  */
#define GP211_SCP02_IMPL_i55 0x55
/** Secure Channel Protocol '02': "i" '04': Initiation mode explicit, C-MAC on modified APDU,
  * ICV set to zero, no ICV encryption, 1 Secure Channel base key, unspecified card challenge generation method
  */
#define GP211_SCP02_IMPL_i04 0x04
/** Secure Channel Protocol '02': "i" '05': Initiation mode explicit, C-MAC on modified APDU,
  * ICV set to zero, no ICV encryption, 3 Secure Channel Keys, unspecified card challenge generation method
  */
#define GP211_SCP02_IMPL_i05 0x05
/** Secure Channel Protocol '02': "i" '0A': Initiation mode implicit, C-MAC on unmodified APDU,
  * ICV set to MAC over AID, no ICV encryption, 1 Secure Channel base key
  */
#define GP211_SCP02_IMPL_i0A 0x0A
/** Secure Channel Protocol '02': "i" '0B': Initiation mode implicit, C-MAC on unmodified APDU,
  * ICV set to MAC over AID, no ICV encryption, 3 Secure Channel Keys
  */
#define GP211_SCP02_IMPL_i0B 0x0B
/** Secure Channel Protocol '02': "i" '14': Initiation mode explicit, C-MAC on modified APDU,
  * ICV set to zero, ICV encryption for CMAC session, 1 Secure Channel base key,
  * unspecified card challenge generation method
  */
#define GP211_SCP02_IMPL_i14 0x14
/** Secure Channel Protocol '02': "i" '15': Initiation mode explicit, C-MAC on modified APDU,
  * ICV set to zero, ICV encryption for CMAC session, 3 Secure Channel Keys,
  * unspecified card challenge generation method
  */
#define GP211_SCP02_IMPL_i15 0x15
/** Secure Channel Protocol '02': "i" '1A': Initiation mode implicit, C-MAC on unmodified APDU,
  * ICV set to MAC over AID, ICV encryption for C-MAC session, 1 Secure Channel base key
  */
#define GP211_SCP02_IMPL_i1A 0x1A
/** Secure Channel Protocol '02': "i" '1B': Initiation mode implicit, C-MAC on unmodified APDU,
  * ICV set to MAC over AID, ICV encryption for C-MAC session, 3 Secure Channel Keys
  */
#define GP211_SCP02_IMPL_i1B 0x1B

/** Secure Channel Protocol '03': "i" '00': No R-MAC, no R-ENCRYPTION, no Pseudo-random cryptogram
  */
#define GP211_SCP03_IMPL_i00 0x00
	/**
	* Secure Channel Protocol '03': "i" '10': Pseudo-random card challenge, no R-MAC support, no R-ENCRYPTION support.
	*/
#define GP211_SCP03_IMPL_i10 0x10

	/**
	* Secure Channel Protocol '03': "i" '30': Pseudo-random card challenge, R-MAC support, no R-ENCRYPTION support.
	*/
#define GP211_SCP03_IMPL_i30 0x30

	/**
	* Secure Channel Protocol '03': "i" '20': Random card challenge, R-MAC support, no R-ENCRYPTION support.
	*/
#define GP211_SCP03_IMPL_i20 0x20

	/**
	* Secure Channel Protocol '03': "i" '60': Random card challenge, R-MAC support, R-ENCRYPTION support.
	*/
#define GP211_SCP03_IMPL_i60 0x60

	/**
	* Secure Channel Protocol '03': "i" '70': Pseudo-random card challenge, R_MAC, support, R-ENCRYPTION support.
	*/
#define GP211_SCP03_IMPL_i70 0x70

#define GP211_SCP01_SECURITY_LEVEL_C_DEC_C_MAC 0x03 //!< Secure Channel Protocol '01': C-DECRYPTION and C-MAC
#define GP211_SCP01_SECURITY_LEVEL_C_MAC 0x01 //!< Secure Channel Protocol '01': C-MAC
#define GP211_SCP01_SECURITY_LEVEL_NO_SECURE_MESSAGING 0x00 //!< Secure Channel Protocol '01': No secure messaging expected.

#define GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC_R_MAC 0x13 //!< Secure Channel Protocol '02': C-DECRYPTION, C-MAC and R-MAC
#define GP211_SCP02_SECURITY_LEVEL_C_MAC_R_MAC 0x11 //!< Secure Channel Protocol '02': C-MAC and R-MAC
#define GP211_SCP02_SECURITY_LEVEL_R_MAC 0x10 //!< Secure Channel Protocol '02': R-MAC
#define GP211_SCP02_SECURITY_LEVEL_C_DEC_C_MAC 0x03 //!< Secure Channel Protocol '02': C-DECRYPTION and C-MAC
#define GP211_SCP02_SECURITY_LEVEL_C_MAC 0x01 //!< Secure Channel Protocol '02': C-MAC
#define GP211_SCP02_SECURITY_LEVEL_NO_SECURE_MESSAGING 0x00 //!< Secure Channel Protocol '02': No secure messaging expected.

// Philip Wendland: added SCP03 security level identifiers
#define GP211_SCP03_SECURITY_LEVEL_C_DEC_C_MAC 0x03 //!< Secure Channel Protocol '03': C-Decryption and C-MAC
#define GP211_SCP03_SECURITY_LEVEL_C_MAC 0x01 //!< Secure Channel Protocol '03': C-MAC
#define GP211_SCP03_SECURITY_LEVEL_NO_SECURE_MESSAGING 0x00 //!< Secure Channel Protocol '03': No secure messaging expected.
#define GP211_SCP03_SECURITY_LEVEL_C_DEC_R_ENC_C_MAC_R_MAC 0x33 //!< Secure Channel Protocol '03': C-Decryption, C-MAC, R-Mac and R-Encryption
#define GP211_SCP03_SECURITY_LEVEL_C_DECRYPTION_C_MAC_R_MAC 0x13 //!< Secure Channel Protocol '03': C-Decryption, C-MAC and R-Mac
#define GP211_SCP03_SECURITY_LEVEL_C_MAC_R_MAC 0x11 //!< Secure Channel Protocol '03': C-MAC and R-Mac

#define GP211_KEY_TYPE_RSA_PUB_N 0xA1 //!< 'A1' RSA Public Key - modulus N component (clear text).
#define GP211_KEY_TYPE_RSA_PUB_E 0xA0 //!< 'A0' RSA Public Key - public exponent e component (clear text)
#define GP211_KEY_TYPE_RSA_PRIV_N 0xA2 //!< ''A2' RSA Private Key - modulus N component
#define GP211_KEY_TYPE_RSA_PRIV_D 0xA3 //!< ''A3' RSA Private Key - private exponent d component
#define GP211_KEY_TYPE_RSA_PRIV_P 0xA4 //!< ''A4' RSA Private Key - Chinese Remainder P component
#define GP211_KEY_TYPE_RSA_PRIV_Q 0xA5 //!< ''A5' RSA Private Key - Chinese Remainder Q component
#define GP211_KEY_TYPE_RSA_PRIV_PQ 0xA6 //!< ''A6' RSA Private Key - Chinese Remainder PQ component
#define GP211_KEY_TYPE_RSA_PRIV_DP1 0xA7 //!< ''A7' RSA Private Key - Chinese Remainder DP1 component
#define GP211_KEY_TYPE_RSA_PRIV_DQ1 0xA8 //!< ''A8' RSA Private Key - Chinese Remainder DQ1 component


#define GP211_KEY_TYPE_3DES 0x81 //!< Reserved (triple DES).
#define GP211_KEY_TYPE_DES 0x80 //!< '80' DES mode (EBC/CBC) implicitly known.
#define GP211_KEY_TYPE_3DES_CBC 0x82 //!<'82' Triple DES in CBC mode.
#define GP211_KEY_TYPE_DES_ECB 0x83 //!<'83' DES in ECB mode.
#define GP211_KEY_TYPE_DES_CBC 0x84 //!<'84' DES in CBC mode.

#define OP201_SECURITY_LEVEL_ENC_MAC 0x03 //!< Command messages are signed and encrypted.
#define OP201_SECURITY_LEVEL_MAC 0x01 //!< Command messages are signed.
#define OP201_SECURITY_LEVEL_PLAIN 0x00 //!< Command messages are plaintext.

#define OP201_KEY_TYPE_RSA_PUP_N 0xA1 //!< 'A1' RSA Public Key - modulus N component (clear text).
#define OP201_KEY_TYPE_RSA_PUP_E 0xA0 //!< 'A0' RSA Public Key - public exponent e component (clear text)
#define OP201_KEY_TYPE_DES 0x80 //!< DES (ECB/CBC) key.
#define OP201_KEY_TYPE_DES_ECB 0x81 //!< DES ECB.
#define OP201_KEY_TYPE_DES_CBC 0x82 //!< DES CBC.

/**
 * The security information negotiated at mutual_authentication().
 */
typedef struct {
	BYTE securityLevel; //!< The security level.
	BYTE sessionMacKey[16]; //!< The MAC session key.
	BYTE sessionEncKey[16]; //!< The ENC session key.
	BYTE lastMac[8]; //!< The last computed mac
	/* Augusto: added two more attributes for key information */
	BYTE keySetVersion; //!< The keyset version used in the secure channel
	BYTE keyIndex; //!< The key index used in the secure channel
	/* end */
} OP201_SECURITY_INFO;


/**
 * The security information negotiated at GP211_mutual_authentication().
 */
typedef struct {
	BYTE securityLevel; //!< The security level.
	BYTE secureChannelProtocol; //!< The Secure Channel Protocol.
	BYTE secureChannelProtocolImpl; //!< The Secure Channel Protocol implementation.
	BYTE C_MACSessionKey[16]; //!< The Secure Channel C-MAC session key.
	BYTE R_MACSessionKey[16]; //!< The Secure Channel R-MAC session key.
	BYTE encryptionSessionKey[16]; //!< The Secure Channel encryption session key.
	BYTE dataEncryptionSessionKey[16]; //!< Secure Channel data encryption key.
    /* 
     * Philip Wendland: lastC_MAC must be 16 Bytes for SCP03 because the MAC chaining value 
     * for MAC code generation is 16 Bytes (according to GP 2.2 Amendment D), not 8.
     * TODO This probably affects R_MAC too.
     */ 
    BYTE lastC_MAC[16]; //!< The last computed C-MAC. Only 8 byte used for SCP01 and SCP02.
	BYTE lastR_MAC[8]; //!< The last computed R-MAC.
	/* Augusto: added two more attributes for key information */
	BYTE keySetVersion; //!< The keyset version used in secure channel
	BYTE keyIndex; //!< The key index used in secured channel
	BYTE invokingAid[16]; //!< The invoking AID used for the mutual authentication.
	DWORD invokingAidLength; //!< The length of the invoking AID buffer.
} GP211_SECURITY_INFO;

/**
 * A structure describing a Load File Data Block DAP block according to the Open Platform specification 2.0.1'.
 * The structure comprises 3 Tag Length Value (TLV) fields after the ASN.1 specification.
 * The outer tag 0xE2 contains the two inner tags.
 */
typedef struct {
	BYTE securityDomainAIDLength; //!< The length of the Security Domain.
	BYTE securityDomainAID[16]; //!< The AID of the Security Domain.
	BYTE signatureLength; //!< The length of the signature. Can be 8 for a 3DES signature or 128 for a RSA signature.
	BYTE signature[128]; //!< The signature.
} OP201_DAP_BLOCK, OP201_RSA_DAP_BLOCK, OP201_3DES_DAP_BLOCK;



/**
 * A structure returned in DELETE, LOAD, INSTALL[for load], INSTALL[for install] with delegated management.
 */
typedef struct {
	BYTE receiptLength; //!< The length of the receipt DAP.
	BYTE receipt[8]; //!< The receipt DAP.
	BYTE confirmationCounterLength; //!< Length of the confirmation counter buffer.
	BYTE confirmationCounter[2]; //!< The confirmation counter buffer.
	BYTE cardUniqueDataLength; //!< The length of the card unique data buffer.
	BYTE cardUniqueData[10]; //!< Card unique data buffer.
} OP201_RECEIPT_DATA;




/**
 * A structure containing key information. Key set version, key index, key type and key length.
 */
typedef struct {
	BYTE keySetVersion; //!< The key set version.
	BYTE keyIndex; //!< The key index.
	BYTE keyType; //!< The key type.
	BYTE keyLength; //!< The key length.
} OP201_KEY_INFORMATION;

/**
 * A structure describing a Load File Data Block Signature according to the GlobalPlatform
 * specification 2.1.1.
 */
typedef struct {
	BYTE securityDomainAIDLength; //!< The length of the Security Domain.
	BYTE securityDomainAID[16]; //!< The AID of the Security Domain.
	BYTE signatureLength; //!< The length of the signature. Can be 8 for a 3DES signature or 128 for a RSA signature.
	BYTE signature[128]; //!< The signature.
} GP211_DAP_BLOCK, GP211_RSA_DAP_BLOCK, GP211_3DES_DAP_BLOCK;


/**
 * A structure returned in DELETE, LOAD, INSTALL[for load], INSTALL[for install] with delegated management.
 */
typedef struct {
	BYTE receiptLength; //!< The length of the receipt DAP.
	BYTE receipt[8]; //!< The receipt DAP.
	BYTE confirmationCounterLength; //!< Length of the confirmation counter buffer.
	BYTE confirmationCounter[2]; //!< The confirmation counter buffer.
	BYTE cardUniqueDataLength; //!< The length of the card unique data buffer.
	BYTE cardUniqueData[10]; //!< Card unique data buffer.
} GP211_RECEIPT_DATA;


/**
 * A structure containing key information. Key set version, key index, key type and key length.
 */
typedef struct {
	BYTE keySetVersion; //!< The key set version.
	BYTE keyIndex; //!< The key index.
	BYTE keyType; //!< The key type.
	BYTE keyLength; //!< The key length.
} GP211_KEY_INFORMATION;



#ifdef __cplusplus
}
#endif
#endif /* SECURITY_H_ */
