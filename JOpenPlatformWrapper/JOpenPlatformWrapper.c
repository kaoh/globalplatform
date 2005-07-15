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

#include <jni.h>
#include "org_dyndns_widerstand_OpenPlatform_OPSPWrapper.h"
#ifdef WIN32
#include "stdafx.h"
#endif
#include <malloc.h>
#include <OpenPlatform.h>

static void parsejcardInfo(JNIEnv *, jobject, OPSP_CARD_INFO *);
static void parsejsecInfo(JNIEnv *, jobject, OPSP_SECURITY_INFO *);
static void setjsecInfo(JNIEnv *, jobject, OPSP_SECURITY_INFO);
static void parsejbyteArray(JNIEnv *, jbyteArray, PBYTE, PDWORD);
static jbyteArray getjbyteArray(JNIEnv *, PBYTE, DWORD);
static int throwOPSPException(JNIEnv *env, OPSP_CSTRING, LONG);
static int throwException(JNIEnv *env, OPSP_CSTRING);
static void parsejOPSPDAPBlock(JNIEnv *, jobject, OPSP_DAP_BLOCK *);
static jobject getOPSPReceiptData(JNIEnv *, OPSP_RECEIPT_DATA);
static jobject getOPSPDAPBlock(JNIEnv *, OPSP_DAP_BLOCK);
static void parsejOPSPReceiptData(JNIEnv *, jobject, OPSP_RECEIPT_DATA *);

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    getLastOpenSSLErrorCode
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_getLastOpenSSLErrorCode
(JNIEnv *env, jclass cls) {
	return get_last_OpenSSL_error_code();
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    establishContext
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_establishContext
(JNIEnv *env, jclass cls) {
	LONG result;
	OPSP_CARDCONTEXT cardContext;
	result = establish_context(&cardContext);
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("establishContext"), result);
	}
	return cardContext;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    releaseContext
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_releaseContext
(JNIEnv *env, jclass cls, jlong cardContext) {
	LONG result;
	result = release_context((OPSP_CARDCONTEXT)cardContext);
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("releaseContext"), result);
	}
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    listReaders
 * Signature: (J)[Ljava/lang/String;
 */
JNIEXPORT jobjectArray JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_listReaders
(JNIEnv *env, jclass cls, jlong cardContext) {
	LONG result;
	DWORD i, numReaders, j;
	OPSP_STRING readerList;
	DWORD readerListLength;
	jobjectArray jreaderNamesArray = NULL;
	result = list_readers((OPSP_CARDCONTEXT)cardContext, NULL, &readerListLength);
	if ( OPSP_ERROR_SUCCESS != result ) {
		throwOPSPException(env, _T("listReaders"), result);
	}
	readerList = (OPSP_STRING)malloc(sizeof(TCHAR)*(readerListLength));
	result = list_readers((OPSP_CARDCONTEXT)cardContext, readerList, &readerListLength);
	if ( SCARD_S_SUCCESS != result ) {
		free(readerList);
		throwOPSPException(env, _T("listReaders"), result);
	}
	for (i=0, numReaders=0; i<readerListLength;) {
	    numReaders++;
		i += (DWORD)_tcslen(&readerList[i])+1;
		if (_tcslen(&readerList[i]) == 0)
			i++;
	}
	if (numReaders == 0) return NULL;
	jreaderNamesArray = (*env)->NewObjectArray(env, numReaders,(*env)->FindClass(env, "java/lang/String"),NULL);
	if ((*env)->ExceptionOccurred(env) != NULL) {
  		free(readerList);
		throwException(env, _T("listReaders"));
		return NULL;
	}
	for (i=0, j=0; j<numReaders; j++) {
		OPSP_STRING name;
		jstring jname;

		name = &readerList[i];
#ifdef _UNICODE
		jname = (*env)->NewString(env, name, (jsize)_tcslen(name));
#else
		jname = (*env)->NewStringUTF(env, name);
#endif
		if ((*env)->ExceptionOccurred(env) != NULL) {
  			free(readerList);
			throwException(env, _T("listReaders"));
			return NULL;
		}
		(*env)->SetObjectArrayElement(env, jreaderNamesArray, j, jname);
		if ((*env)->ExceptionOccurred(env) != NULL) {
  			free(readerList);
			throwException(env, _T("listReaders"));
			return NULL;
		}
		i += (DWORD)_tcslen(name)+1;
	}
	free(readerList);
	return jreaderNamesArray;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    cardConnect
 * Signature: (JLjava/lang/String;J)J
 */
JNIEXPORT jlong JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_cardConnect
(JNIEnv *env, jclass cls, jlong cardContext, jstring readerJavaName, jlong protocol) {
	LONG result;
	OPSP_CARDHANDLE cardHandle;
	OPSP_CSTRING readerName;
#ifdef _UNICODE
	readerName = (OPSP_STRING)(*env)->GetStringChars(env, readerJavaName, 0);
#else
	readerName = (*env)->GetStringUTFChars(env, readerJavaName, 0);
#endif
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("cardConnect"));
		return -1;
	}
	result = card_connect((OPSP_CARDCONTEXT)cardContext, readerName, &cardHandle, (DWORD)protocol);
#ifdef _UNICODE
	(*env)->ReleaseStringChars(env, readerJavaName, readerName);
#else
	(*env)->ReleaseStringUTFChars(env, readerJavaName, readerName);
#endif
	if ( OPSP_ERROR_SUCCESS != result ) {
		throwOPSPException(env, _T("cardConnect"), result);
		return -1;
	}
	return cardHandle;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    cardDisconnect
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_cardDisconnect
(JNIEnv *env, jclass cls, jlong cardHandle) {
	LONG result;
	result = card_disconnect((OPSP_CARDHANDLE)cardHandle);
	if ( OPSP_ERROR_SUCCESS != result ) {
		throwOPSPException(env, _T("cardDisconnect"), result);
	}
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    selectApplication
 * Signature: (JLorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;[B)V
 */
JNIEXPORT void JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_selectApplication
(JNIEnv *env, jclass cls, jlong cardHandle, jobject jcardInfo, jbyteArray jAID) {
	LONG result;
	OPSP_CARD_INFO cardInfo;
	PBYTE AID;
	DWORD AIDLength;
	AIDLength = (*env)->GetArrayLength(env, jAID);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("selectApplication"));
		return;
	}
	AID = (PBYTE)malloc(sizeof(BYTE)*AIDLength);
	(*env)->GetByteArrayRegion(env, jAID, 0, (*env)->GetArrayLength(env, jAID), (jbyte *)AID);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		free(AID);
		throwException(env, _T("selectApplication"));
		return;
	}
	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		free(AID);
		throwException(env, _T("selectApplication"));
		return;
	}
	result = select_application((OPSP_CARDHANDLE)cardHandle, cardInfo, AID, AIDLength);
	if (result != OPSP_ERROR_SUCCESS) {
		free(AID);
		throwOPSPException(env, _T("selectApplication"), result);
		return;
	}
	free(AID);
}

/*
 * Parses a Java OPSPCardConnectionInfo into a OPSP_CARD_INFO.
 * \param *env JNI interface pointer.
 * \param jcardInfo The Java OPSPCardConnectionInfo object.
 * \param method The method name of the calling method.
 * \param cardInfo The returned OPSP_CARD_INFO.
 */
static void parsejcardInfo(JNIEnv *env, jobject jcardInfo, OPSP_CARD_INFO *cardInfo) {
	jclass cardConnectionInfoClass;
	jfieldID fieldID;
	jmethodID methodID;
	jbyteArray ATR;
	OPSP_CSTRING empty = _T("");
	cardConnectionInfoClass = (*env)->FindClass(env, "org/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	fieldID = (*env)->GetFieldID(env, cardConnectionInfoClass, "protocol", "J");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	cardInfo->protocol = (DWORD)(*env)->GetLongField(env, jcardInfo, fieldID);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	fieldID = (*env)->GetFieldID(env, cardConnectionInfoClass, "state", "J");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	cardInfo->state = (DWORD)(*env)->GetLongField(env, jcardInfo, fieldID);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	methodID = (*env)->GetMethodID(env, cardConnectionInfoClass, "getATR", "()[B");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	ATR = (jbyteArray)(*env)->CallObjectMethod(env, jcardInfo, methodID);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	cardInfo->ATRLength = (*env)->GetArrayLength(env, ATR);
	(*env)->GetByteArrayRegion(env, ATR, 0, (*env)->GetArrayLength(env, ATR), (jbyte *)cardInfo->ATR);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
}

/*
 * Parses a Java OPSPSecurityInfo into a OPSP_SECURITY_INFO.
 * \param *env JNI interface pointer.
 * \param jsecInfo The Java OPSPSecurityInfo object.
 * \param secInfo The returned OPSP_SECURITY_INFO.
 */
static void parsejsecInfo(JNIEnv *env, jobject jsecInfo, OPSP_SECURITY_INFO *secInfo) {
	jclass securityInfoClass;
	jmethodID methodID;
	jfieldID fieldID;
	jbyteArray lastMac, sessionMacKey, sessionEncKey;
	OPSP_CSTRING empty = _T("");
	securityInfoClass = (*env)->FindClass(env, "org/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
// last MAC

	methodID = (*env)->GetMethodID(env, securityInfoClass, "getLastMac", "()[B");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	lastMac = (jbyteArray)(*env)->CallObjectMethod(env, jsecInfo, methodID);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	(*env)->GetByteArrayRegion(env, lastMac, 0, 8, (jbyte *)secInfo->last_mac);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
// session MAC key

	methodID = (*env)->GetMethodID(env, securityInfoClass, "getSessionMacKey", "()[B");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	sessionMacKey = (jbyteArray)(*env)->CallObjectMethod(env, jsecInfo, methodID);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	(*env)->GetByteArrayRegion(env, sessionMacKey, 0, 16, (jbyte *)secInfo->session_mac_key);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
// session ENC key

	methodID = (*env)->GetMethodID(env, securityInfoClass, "getSessionEncKey", "()[B");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	sessionEncKey = (jbyteArray)(*env)->CallObjectMethod(env, jsecInfo, methodID);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	(*env)->GetByteArrayRegion(env, sessionEncKey, 0, 16, (jbyte *)secInfo->session_enc_key);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
// security level

	fieldID = (*env)->GetFieldID(env, securityInfoClass, "securityLevel", "B");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	secInfo->security_level = (BYTE)(*env)->GetByteField(env, jsecInfo, fieldID);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}

}

/*
 * Sets the fields of a Java OPSPSecurityInfo according to an OPSP_SECURITY_INFO.
 * \param *env JNI interface pointer.
 * \param jsecInfo The returned Java OPSPSecurityInfo object.
 * \param secInfo The OPSP_SECURITY_INFO.
 */
static void setjsecInfo(JNIEnv *env, jobject jsecInfo, OPSP_SECURITY_INFO secInfo) {
	jclass OPSPsecurityInfoClass;
	jmethodID methodID;
	jfieldID fieldID;
	jbyteArray lastMac, sessionMacKey, sessionEncKey;
	OPSP_CSTRING empty = _T("");
	OPSPsecurityInfoClass = (*env)->FindClass(env, "org/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
// last MAC

	methodID = (*env)->GetMethodID(env, OPSPsecurityInfoClass, "setLastMac", "([B)V");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	lastMac = (*env)->NewByteArray(env, 8);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	(*env)->SetByteArrayRegion(env, lastMac, 0, 8, (jbyte *)secInfo.last_mac);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	(jbyteArray)(*env)->CallObjectMethod(env, jsecInfo, methodID, lastMac);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
// session MAC key

	methodID = (*env)->GetMethodID(env, OPSPsecurityInfoClass, "setSessionMacKey", "([B)V");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	sessionMacKey = (*env)->NewByteArray(env, 16);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	(*env)->SetByteArrayRegion(env, sessionMacKey, 0, 16, (jbyte *)secInfo.session_mac_key);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	(jbyteArray)(*env)->CallObjectMethod(env, jsecInfo, methodID, sessionMacKey);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
// session ENC key

	methodID = (*env)->GetMethodID(env, OPSPsecurityInfoClass, "setSessionEncKey", "([B)V");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	sessionEncKey = (*env)->NewByteArray(env, 16);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	(*env)->SetByteArrayRegion(env, sessionEncKey, 0, 16, (jbyte *)secInfo.session_enc_key);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	(jbyteArray)(*env)->CallObjectMethod(env, jsecInfo, methodID, sessionEncKey);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
// security level

	fieldID = (*env)->GetFieldID(env, OPSPsecurityInfoClass, "securityLevel", "B");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	(*env)->SetByteField(env, jsecInfo, fieldID, secInfo.security_level);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    getStatus
 * Signature: (JLorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;Lorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;B)[Lorg/dyndns/widerstand/OpenPlatform/OPSPApplicationData;
 */
JNIEXPORT jobjectArray JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_getStatus
(JNIEnv *env, jclass cls, jlong cardHandle, jobject jsecInfo, jobject jcardInfo, jbyte cardElement) {
	LONG result;
	OPSP_APPLICATION_DATA applData[100];
	DWORD applDataLength = 100;
	jobjectArray jappDataArray = NULL;
	jobject jappData;
	DWORD i;
	jmethodID methodID;
	jclass OPSPApplicationDataClass;
	jbyteArray jAID;
	OPSP_SECURITY_INFO secInfo;
	OPSP_CARD_INFO cardInfo;
	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getStatus"));
		return NULL;
	}
	parsejsecInfo(env, jsecInfo, &secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getStatus"));
		return NULL;
	}
	result = get_status((OPSP_CARDHANDLE)cardHandle, &secInfo, cardInfo, cardElement,
		applData, &applDataLength);
	setjsecInfo(env, jsecInfo, secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getStatus"));
		return NULL;
	}
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("getStatus"), result);
		return NULL;
	}

	OPSPApplicationDataClass = (*env)->FindClass(env, "org/dyndns/widerstand/OpenPlatform/OPSPApplicationData");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getStatus"));
		return NULL;
	}
	jappDataArray = (*env)->NewObjectArray(env, applDataLength, OPSPApplicationDataClass, NULL);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getStatus"));
		return NULL;
	}
	for (i=0; i<applDataLength; i++) {
		methodID = (*env)->GetMethodID(env, OPSPApplicationDataClass, "<init>", "([BBB)V");
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("getStatus"));
			return NULL;
		}
		jAID = (*env)->NewByteArray(env, (jsize)applData[i].AIDLength);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("getStatus"));
			return NULL;
		}
		(*env)->SetByteArrayRegion(env, jAID, 0, (jsize)applData[i].AIDLength, (jbyte *)applData[i].AID);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("getStatus"));
			return NULL;
		}
		jappData = (*env)->NewObject(env, OPSPApplicationDataClass, methodID,
			jAID,
			applData[i].lifeCycleState,
			applData[i].privileges);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("getStatus"));
			return NULL;
		}
		(*env)->SetObjectArrayElement(env, jappDataArray, i, jappData);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("getStatus"));
			return NULL;
		}
	}
	return jappDataArray;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    setStatus
 * Signature: (JLorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;Lorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;B[BB)V
 */
JNIEXPORT void JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_setStatus
(JNIEnv *env, jclass cls, jlong cardHandle, jobject jsecInfo, jobject jcardInfo, jbyte cardElement,
 jbyteArray jAID, jbyte lifeCycleState)
{
	LONG result;
	PBYTE AID;
	DWORD AIDLength;
	OPSP_CARD_INFO cardInfo;
	OPSP_SECURITY_INFO secInfo;
	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("setStatus"));
		return;
	}
	parsejsecInfo(env, jsecInfo, &secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("setStatus"));
		return;
	}
	AIDLength = (DWORD)(*env)->GetArrayLength(env, jAID);
	AID = (PBYTE)malloc(sizeof(BYTE)*AIDLength);
	if (jAID == NULL) {
		AID = NULL;
		AIDLength = 0;
	}
	else {
		parsejbyteArray(env, jAID, AID, &AIDLength);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("setStatus"));
			return;
		}
	}
	result = set_status((OPSP_CARDHANDLE)cardHandle, &secInfo, cardInfo, (BYTE)cardElement,
		AID, AIDLength, (BYTE)lifeCycleState);
	setjsecInfo(env, jsecInfo, secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("setStatus"));
		return;
	}
	if (result != OPSP_ERROR_SUCCESS) {
		free(AID);
		throwOPSPException(env, _T("setStatus"), result);
		return;
	}
	free(AID);
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    stringifyError
 * Signature: (I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_stringifyError
(JNIEnv *env, jclass cls, jint errorCode) {
	OPSP_STRING errorMsg;
	errorMsg = stringify_error((DWORD)errorCode);
#ifdef _UNICODE
	return (*env)->NewString(env, errorMsg, (jsize)_tcslen(errorMsg));
#else
	return (*env)->NewStringUTF(env, errorMsg);
#endif
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("stringifyError"));
		return NULL;
	}
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    getReaderCapabilities
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_getReaderCapabilities
(JNIEnv *env, jclass cls, jlong cardHandle, jlong attributeID) {
	LONG result;
	PBYTE attribute;
	DWORD attributeLength = 256;
	jbyteArray jattribute = NULL;
	attribute = (PBYTE)malloc(sizeof(BYTE)*attributeLength);
	result = get_reader_capabilities((OPSP_CARDHANDLE)cardHandle, (DWORD)attributeID,
		attribute, &attributeLength);
	if (result != OPSP_ERROR_SUCCESS) {
		free(attribute);
		throwOPSPException(env, _T("getReaderCapabilities"), result);
		return NULL;
	}
	jattribute = getjbyteArray(env, attribute, attributeLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		free(attribute);
		throwException(env, _T("getReaderCapabilities"));
		return NULL;
	}
	free(attribute);
	return jattribute;
}

/*
 * Returns a Java byte array from a native byte buffer.
 * \param *env JNI interface pointer.
 * \param array The native byte buffer.
 * \param arrayLength The length of the native buffer.
 * \return The Java byte array.
 */
static jbyteArray getjbyteArray(JNIEnv *env, PBYTE array, DWORD arrayLength) {
	jbyteArray jarray;
	OPSP_CSTRING empty = _T("");
	if (arrayLength == 0) {
		return NULL;
	}
	jarray = (*env)->NewByteArray(env, arrayLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return NULL;
	}
	(*env)->SetByteArrayRegion(env, jarray, 0, (jsize)arrayLength, (jbyte *)array);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return NULL;
	}
	return jarray;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    getCardStatus
 * Signature: (J)Lorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;
 */
JNIEXPORT jobject JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_getCardStatus
(JNIEnv *env, jclass cls, jlong cardHandle) {
	LONG result;
    jclass      cardConnectionInfoClass;
    jobject     cardConnectionInfoInstance = NULL;
	jbyteArray  ATR;
    jmethodID   constructorID;
	OPSP_CARD_INFO cardInfo;
	result = get_card_status((OPSP_CARDHANDLE)cardHandle, &cardInfo);
	if ( OPSP_ERROR_SUCCESS != result ) {
		throwOPSPException(env, _T("getCardStatus"), result);
	}
	cardConnectionInfoClass = (*env)->FindClass(env, "org/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getCardStatus"));
		return NULL;
	}
	constructorID = (*env)->GetMethodID(env, cardConnectionInfoClass,
			    "<init>", "([BJJ)V");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getCardStatus"));
		return NULL;
	}
	ATR = (*env)->NewByteArray(env, cardInfo.ATRLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getCardStatus"));
		return NULL;
	}
	(*env)->SetByteArrayRegion(env, ATR, 0, cardInfo.ATRLength, (jbyte *)cardInfo.ATR);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getCardStatus"));
		return NULL;
	}
	cardConnectionInfoInstance = (*env)->NewObject(env, cardConnectionInfoClass,
	constructorID, ATR, cardInfo.protocol, cardInfo.state);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getCardStatus3"));
		return NULL;
	}
	return cardConnectionInfoInstance;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    mutualAuthentication
 * Signature: (J[B[BBBLorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;B)Lorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;
 */
JNIEXPORT jobject JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_mutualAuthentication
(JNIEnv *env, jclass cls, jlong cardHandle, jbyteArray jencKey, jbyteArray jmacKey, jbyte keySetVersion,
 jbyte keyIndex, jobject jcardInfo, jbyte securityLevel) {
	LONG result;
	OPSP_CARD_INFO cardInfo;
	OPSP_SECURITY_INFO secInfo;
	jobject jsecInfo;
	BYTE enc_key[16];
	DWORD dummy = 16;
	BYTE mac_key[16];
	jclass OPSPSecurityInfoClass = NULL;
	jmethodID constructorID;
	jbyteArray lastMac, sessionMacKey, sessionEncKey;
	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("mutualAuthentication"));
		return NULL;
	}
	parsejbyteArray(env, jencKey, enc_key, &dummy);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("mutualAuthentication"));
		return NULL;
	}
	dummy = 16;
	parsejbyteArray(env, jmacKey, mac_key, &dummy);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("mutualAuthentication"));
		return NULL;
	}
	result = mutual_authentication((OPSP_CARDHANDLE)cardHandle, enc_key, mac_key,
		(BYTE)keySetVersion, (BYTE)keyIndex, cardInfo, (BYTE)securityLevel, &secInfo);
	if ( OPSP_ERROR_SUCCESS != result ) {
		throwOPSPException(env, _T("mutual_authentication"), result);
	}
	OPSPSecurityInfoClass = (*env)->FindClass(env, "org/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("mutualAuthentication"));
		return NULL;
	}
	constructorID = (*env)->GetMethodID(env, OPSPSecurityInfoClass, "<init>", "([B[B[BB)V");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("mutualAuthentication"));
		return NULL;
	}
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("mutualAuthentication"));
		return NULL;
	}
// last MAC
	lastMac = (*env)->NewByteArray(env, 8);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("mutualAuthentication"));
		return NULL;
	}
	(*env)->SetByteArrayRegion(env, lastMac, 0, 8, (jbyte *)secInfo.last_mac);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("mutualAuthentication"));
		return NULL;
	}
// session MAC key
	sessionMacKey = (*env)->NewByteArray(env, 16);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("mutualAuthentication"));
		return NULL;
	}
	(*env)->SetByteArrayRegion(env, sessionMacKey, 0, 16, (jbyte *)secInfo.session_mac_key);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("mutualAuthentication"));
		return NULL;
	}
// session ENC key
	sessionEncKey = (*env)->NewByteArray(env, 16);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("mutualAuthentication"));
		return NULL;
	}
	(*env)->SetByteArrayRegion(env, sessionEncKey, 0, 16, (jbyte *)secInfo.session_enc_key);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("mutualAuthentication"));
		return NULL;
	}
	jsecInfo = (*env)->NewObject(env, OPSPSecurityInfoClass, constructorID, sessionMacKey, sessionEncKey,
		lastMac, securityLevel);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("mutualAuthentication"));
		return NULL;
	}
	return jsecInfo;
 }

/*
 * Parses a Java byte array into a native byte buffer.
 * \param *env JNI interface pointer.
 * \param jarray The Java byte array.
 * \param array The native byte buffer.
 * \param arrayLength The length of the native buffer.
 */
 static void parsejbyteArray(JNIEnv *env, jbyteArray jarray, PBYTE array, PDWORD arrayLength) {
	OPSP_CSTRING empty = _T("");
	DWORD jarrayLength;
	if (jarray == NULL) {
		*arrayLength = 0;
		return;
	}
	jarrayLength = (*env)->GetArrayLength(env, jarray);
	if ((DWORD)jarrayLength > *arrayLength) {
		throwOPSPException(env, empty, OPSP_ERROR_INSUFFICIENT_BUFFER);
		return;
	}
	*arrayLength = (DWORD)jarrayLength;
	(*env)->GetByteArrayRegion(env, jarray, 0, (*env)->GetArrayLength(env, jarray), (jbyte *)array);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
 }


/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    getData
 * Signature: (J[BLorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;Lorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_getData
(JNIEnv *env, jclass cls, jlong cardHandle, jbyteArray jidentifier, jobject jcardInfo, jobject jsecInfo) {
	LONG result;
	BYTE identifier[2];
	DWORD identifierLength=2;
	BYTE recvBuffer[256];
	DWORD recvBufferLength=256;
	OPSP_SECURITY_INFO secInfo;
	OPSP_CARD_INFO cardInfo;
	jbyteArray cardData = NULL;
		parsejbyteArray(env, jidentifier, identifier, &identifierLength);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("getData"));
			return NULL;
		}

	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getData"));
		return NULL;
	}
	parsejsecInfo(env, jsecInfo, &secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getData"));
		return NULL;
	}
	result = get_data((OPSP_CARDHANDLE)cardHandle, identifier,
		recvBuffer, &recvBufferLength, cardInfo, &secInfo);
	setjsecInfo(env, jsecInfo, secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getData"));
		return NULL;
	}
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("getData"), result);
		return NULL;
	}
	cardData = getjbyteArray(env, recvBuffer, recvBufferLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getData"));
		return NULL;
	}
	return cardData;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    putData
 * Signature: (J[B[BLorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;Lorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;)V
 */
JNIEXPORT void JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_putData
(JNIEnv *env, jclass cls, jlong cardHandle, jbyteArray jidentifier, jbyteArray jcardObject,
 jobject jcardInfo, jobject jsecInfo)
{
	LONG result;
	BYTE identifier[2];
	DWORD identifierLength=2;
	BYTE cardObject[255];
	DWORD cardObjectLength=255;
	OPSP_SECURITY_INFO secInfo;
	OPSP_CARD_INFO cardInfo;
		parsejbyteArray(env, jcardObject, cardObject, &cardObjectLength);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("putData"));
			return;
		}

		parsejbyteArray(env, jidentifier, identifier, &identifierLength);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("putData"));
			return;
		}

	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("putData"));
		return;
	}
	parsejsecInfo(env, jsecInfo, &secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("putData"));
		return;
	}
	result = put_data((OPSP_CARDHANDLE)cardHandle, identifier, cardObject, cardObjectLength, cardInfo, &secInfo);
	setjsecInfo(env, jsecInfo, secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getData"));
		return;
	}
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("putData"), result);
		return;
	}
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    pinChange
 * Signature: (JLorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;Lorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;B[B[B)V
 */
JNIEXPORT void JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_pinChange
(JNIEnv *env, jclass cls, jlong cardHandle, jobject jsecInfo, jobject jcardInfo,
 jbyte tryLimit, jbyteArray jnewPIN, jbyteArray jkekKey) {
	LONG result;
	BYTE newPIN[12];
	DWORD newPINLength=12;
	BYTE kek_key[16];
	DWORD kek_key_length = 16;
	OPSP_SECURITY_INFO secInfo;
	OPSP_CARD_INFO cardInfo;
	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("pinChange"));
		return;
	}
	parsejsecInfo(env, jsecInfo, &secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("pinChange"));
		return;
	}
		parsejbyteArray(env, jkekKey, kek_key, &kek_key_length);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("pinChange"));
			return;
		}

		parsejbyteArray(env, jnewPIN, newPIN, &newPINLength);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("pinChange"));
			return;
		}

	result = pin_change((OPSP_CARDHANDLE)cardHandle, &secInfo, cardInfo, (BYTE)tryLimit,
		newPIN, newPINLength, kek_key);
	setjsecInfo(env, jsecInfo, secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("pinChange"));
		return;
	}
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("pinChange"), result);
		return;
	}
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    put3desKey
 * Signature: (JLorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;Lorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;BBB[B[B)V
 */
JNIEXPORT void JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_put3desKey
(JNIEnv *env, jclass cls, jlong cardHandle, jobject jsecInfo, jobject jcardInfo,
 jbyte keySetVersion, jbyte keyIndex, jbyte newKeySetVersion, jbyteArray j3desKey, jbyteArray jkekKey)
{
	LONG result;
	BYTE _3des_key[16];
	DWORD _3des_key_length=16;
	BYTE kek_key[16];
	DWORD kek_key_length = 16;
	OPSP_SECURITY_INFO secInfo;
	OPSP_CARD_INFO cardInfo;
	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("put3desKey"));
		return;
	}
	parsejsecInfo(env, jsecInfo, &secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("put3desKey"));
		return;
	}
	parsejbyteArray(env, jkekKey, kek_key, &kek_key_length);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("put3desKey"));
		return;
	}
	parsejbyteArray(env, j3desKey, _3des_key, &_3des_key_length);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("put3desKey"));
		return;
	}
	result = put_3des_key((OPSP_CARDHANDLE)cardHandle, &secInfo, cardInfo, (BYTE)keySetVersion,
		(BYTE)keyIndex, (BYTE)newKeySetVersion, _3des_key, kek_key);
	setjsecInfo(env, jsecInfo, secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("put3desKey"));
		return;
	}
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("put3desKey"), result);
		return;
	}
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    putRsaKey
 * Signature: (JLorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;Lorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;BBBLjava/lang/String;Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_putRsaKey
(JNIEnv *env, jclass cls, jlong cardHandle, jobject jsecInfo, jobject jcardInfo,
 jbyte keySetVersion, jbyte keyIndex, jbyte newKeySetVersion, jstring jPEMKeyFileName, jstring jpassPhrase)
{
	LONG result;
	OPSP_SECURITY_INFO secInfo;
	OPSP_CARD_INFO cardInfo;
	const char *passPhrase;
	OPSP_CSTRING PEMKeyFileName;
	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("putRsaKey"));
		return;
	}
	parsejsecInfo(env, jsecInfo, &secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("putRsaKey"));
		return;
	}
	if (jpassPhrase == NULL) {
		passPhrase = NULL;
	}
	else {
		passPhrase = (*env)->GetStringUTFChars(env, jpassPhrase, 0);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("putRsaKey"));
			return;
		}
	}
	if (jPEMKeyFileName == NULL) {
		PEMKeyFileName = NULL;
	}
	else {
#ifdef _UNICODE
	PEMKeyFileName = (OPSP_STRING)(*env)->GetStringChars(env, jPEMKeyFileName, 0);
#else
	PEMKeyFileName = (*env)->GetStringUTFChars(env, jPEMKeyFileName, 0);
#endif
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("putRsaKey"));
			return;
		}
	}

	result = put_rsa_key((OPSP_CARDHANDLE)cardHandle, &secInfo, cardInfo, (BYTE)keySetVersion,
		(BYTE)keyIndex, (BYTE)newKeySetVersion, (OPSP_STRING)PEMKeyFileName, (char *)passPhrase);
	setjsecInfo(env, jsecInfo, secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("putRsaKey"));
		return;
	}
	if (PEMKeyFileName != NULL) {
#ifdef _UNICODE
	(*env)->ReleaseStringChars(env, jPEMKeyFileName, PEMKeyFileName);
#else
	(*env)->ReleaseStringUTFChars(env, jPEMKeyFileName, PEMKeyFileName);
#endif
	}
	if (jpassPhrase != NULL) {
		(*env)->ReleaseStringUTFChars(env, jpassPhrase, passPhrase);
	}

	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("putRsaKey"), result);
		return;
	}
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    putSecureChannelKeys
 * Signature: (JLorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;Lorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;BB[B[B[B[B)V
 */
JNIEXPORT void JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_putSecureChannelKeys
(JNIEnv *env, jclass cls, jlong cardHandle, jobject jsecInfo, jobject jcardInfo, jbyte keySetVersion,
 jbyte newKeySetVersion, jbyteArray jnewEncKey, jbyteArray jnewMacKey, jbyteArray jnewKekKey, jbyteArray jkekKey) {
	LONG result;
	BYTE new_enc_key[16];
	BYTE new_mac_key[16];
	BYTE new_kek_key[16];
	BYTE kek_key[16];
	DWORD dummy=16;
	OPSP_SECURITY_INFO secInfo;
	OPSP_CARD_INFO cardInfo;
	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("putSecureChannelKeys"));
		return;
	}
	parsejsecInfo(env, jsecInfo, &secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("putSecureChannelKeys"));
		return;
	}
	parsejbyteArray(env, jnewEncKey, new_enc_key, &dummy);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("putSecureChannelKeys"));
		return;
	}
	dummy = 16;
	parsejbyteArray(env, jnewMacKey, new_mac_key, &dummy);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("putSecureChannelKeys"));
		return;
	}
	dummy = 16;
	parsejbyteArray(env, jnewKekKey, new_kek_key, &dummy);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("putSecureChannelKeys"));
		return;
	}
	dummy = 16;
	parsejbyteArray(env, jkekKey, kek_key, &dummy);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("putSecureChannelKeys"));
		return;
	}
	result = put_secure_channel_keys((OPSP_CARDHANDLE)cardHandle, &secInfo, cardInfo, (BYTE)keySetVersion,
		(BYTE)newKeySetVersion, new_enc_key, new_mac_key, new_kek_key, kek_key);
	setjsecInfo(env, jsecInfo, secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("putSecureChannelKeys"));
		return;
	}
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("putSecureChannelKeys"), result);
		return;
	}
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    deleteKey
 * Signature: (JLorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;Lorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;BB)V
 */
JNIEXPORT void JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_deleteKey
(JNIEnv *env, jclass cls, jlong cardHandle, jobject jsecInfo, jobject jcardInfo, jbyte keySetVersion,
 jbyte keyIndex)
{
	LONG result;
	OPSP_SECURITY_INFO secInfo;
	OPSP_CARD_INFO cardInfo;
	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("deleteKey"));
		return;
	}
	parsejsecInfo(env, jsecInfo, &secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("deleteKey"));
		return;
	}
	result = delete_key((OPSP_CARDHANDLE)cardHandle, &secInfo, cardInfo, (BYTE)keySetVersion, (BYTE)keyIndex);
	setjsecInfo(env, jsecInfo, secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("deleteKey"));
		return;
	}
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("deleteKey"), result);
		return;
	}
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    getKeyInformationTemplates
 * Signature: (JLorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;Lorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;B)[Lorg/dyndns/widerstand/OpenPlatform/OPSPKeyInformation;
 */
JNIEXPORT jobjectArray JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_getKeyInformationTemplates
(JNIEnv *env, jclass cls, jlong cardHandle, jobject jsecInfo, jobject jcardInfo, jbyte keyInformationTemplate) {
	LONG result;
	jclass OPSPKeyInformationClass;
	jobject OPSPKeyInformationInstance;
	jmethodID constructorID;
	OPSP_SECURITY_INFO secInfo;
	OPSP_CARD_INFO cardInfo;
	OPSP_KEY_INFORMATION keyInformation[50];
	DWORD i,keyInformationLength=50;
	jobjectArray jkeyInformationArray = NULL;
	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getKeyInformationTemplates"));
		return NULL;
	}
	parsejsecInfo(env, jsecInfo, &secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getKeyInformationTemplates"));
		return NULL;
	}
	result = get_key_information_templates((OPSP_CARDHANDLE)cardHandle, &secInfo, cardInfo,
		(BYTE)keyInformationTemplate, keyInformation, &keyInformationLength);
	setjsecInfo(env, jsecInfo, secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getKeyInformationTemplates"));
		return NULL;
	}
	if ((result != OPSP_ERROR_SUCCESS) &&  (result != OPSP_ERROR_MORE_KEY_INFORMATION_TEMPLATES)) {
		throwOPSPException(env, _T("getKeyInformationTemplates"), result);
		return NULL;
	}
	OPSPKeyInformationClass = (*env)->FindClass(env, "org/dyndns/widerstand/OpenPlatform/OPSPKeyInformation");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getKeyInformationTemplates"));
		return NULL;
	}
	jkeyInformationArray = (*env)->NewObjectArray(env, (jsize)keyInformationLength, OPSPKeyInformationClass, NULL);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getKeyInformationTemplates"));
		return NULL;
	}
	constructorID = (*env)->GetMethodID(env, OPSPKeyInformationClass, "<init>", "(BBBB)V");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getKeyInformationTemplates"));
		return NULL;
	}
	for (i=0; i<keyInformationLength; i++) {
		OPSPKeyInformationInstance = (*env)->NewObject(env, OPSPKeyInformationClass, constructorID,
			keyInformation[i].keySetVersion, keyInformation[i].keyIndex,
			keyInformation[i].keyType, keyInformation[i].keyLength);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("getKeyInformationTemplates"));
			return NULL;
		}
		(*env)->SetObjectArrayElement(env, jkeyInformationArray, (jsize)i, OPSPKeyInformationInstance);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("getKeyInformationTemplates"));
			return NULL;
		}
	}
	if (result == OPSP_ERROR_MORE_KEY_INFORMATION_TEMPLATES) {
		throwOPSPException(env, _T("getKeyInformationTemplates"), result);
		return jkeyInformationArray;
	}
	return jkeyInformationArray;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    deleteApplet
 * Signature: (JLorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;Lorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;[[B[Lorg/dyndns/widerstand/OpenPlatform/OPSPReceipt;)[Lorg/dyndns/widerstand/OpenPlatform/OPSPReceipt;
 */
JNIEXPORT jobjectArray JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_deleteApplet
(JNIEnv *env, jclass cls, jlong cardHandle, jobject jsecInfo, jobject jcardInfo, jobjectArray jAIDs) {
	LONG result;
	jclass OPSPReceiptDataClass;
	jobject OPSPReceiptDataInstance;
	OPSP_SECURITY_INFO secInfo;
	OPSP_CARD_INFO cardInfo;
	OPSP_AID *AIDs;
	DWORD AIDsLength;
	OPSP_RECEIPT_DATA **receiptData;
	DWORD receiptDataLength;
	DWORD i;
	jbyteArray jAID;
	jobjectArray jreceiptDataArray = NULL;

// parse AIDs
	AIDsLength = (*env)->GetArrayLength(env, jAIDs);
	AIDs = (OPSP_AID *)malloc(sizeof(OPSP_AID)*AIDsLength);
	for (i=0; i<AIDsLength; i++) {
		jAID = (jbyteArray)(*env)->GetObjectArrayElement(env, jAIDs, i);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("deleteApplet"));
			free(AIDs);
			return NULL;
		}
		AIDs[i].AIDLength = 16;
		parsejbyteArray(env, jAID, AIDs[i].AID, (PDWORD)&(AIDs[i].AIDLength));
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("deleteApplet"));
			free(AIDs);
			return NULL;
		}
	}

	receiptDataLength = AIDsLength;
	receiptData = (OPSP_RECEIPT_DATA **)malloc(sizeof(OPSP_RECEIPT_DATA *));
	*receiptData = (OPSP_RECEIPT_DATA *)malloc(sizeof(OPSP_RECEIPT_DATA)*receiptDataLength);

	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("deleteApplet"));
		free(AIDs);
		free(*receiptData);
		free(receiptData);
		return NULL;
	}
	parsejsecInfo(env, jsecInfo, &secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("deleteApplet"));
		free(AIDs);
		free(*receiptData);
		free(receiptData);
		return NULL;
	}
	result = delete_applet((OPSP_CARDHANDLE)cardHandle, &secInfo, cardInfo,
				   AIDs, AIDsLength, receiptData, &receiptDataLength);
	free(AIDs);
	setjsecInfo(env, jsecInfo, secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		free(*receiptData);
		free(receiptData);
		throwException(env, _T("deleteApplet"));
		return NULL;
	}
	if (result != OPSP_ERROR_SUCCESS) {
		free(*receiptData);
		free(receiptData);
		throwOPSPException(env, _T("deleteApplet"), result);
		return NULL;
	}
	OPSPReceiptDataClass = (*env)->FindClass(env, "org/dyndns/widerstand/OpenPlatform/OPSPReceiptData");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		free(*receiptData);
		free(receiptData);
		throwException(env, _T("deleteApplet"));
		return NULL;
	}
	jreceiptDataArray = (*env)->NewObjectArray(env, (jsize)receiptDataLength, OPSPReceiptDataClass, NULL);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		free(*receiptData);
		free(receiptData);
		throwException(env, _T("deleteApplet"));
		return NULL;
	}
	for (i=0; i<receiptDataLength; i++) {
		OPSPReceiptDataInstance = getOPSPReceiptData(env, (*receiptData)[i]);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			free(*receiptData);
			free(receiptData);
			throwException(env, _T("deleteApplet"));
			return NULL;
		}
		(*env)->SetObjectArrayElement(env, jreceiptDataArray, i, OPSPReceiptDataInstance);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			free(*receiptData);
			free(receiptData);
			throwException(env, _T("deleteApplet"));
			return NULL;
		}
	}
	free(*receiptData);
	free(receiptData);
	return jreceiptDataArray;
}

static jobject getOPSPReceiptData(JNIEnv *env, OPSP_RECEIPT_DATA receiptData) {
	jclass OPSPReceiptDataClass;
	jobject OPSPReceiptDataInstance;
	jmethodID constructorID;
	OPSP_STRING empty = _T("");
	jbyteArray jreceipt, jcardUniqueData, jconfirmationCounter;
	OPSPReceiptDataClass = (*env)->FindClass(env, "org/dyndns/widerstand/OpenPlatform/OPSPReceiptData");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return NULL;
	}
	constructorID = (*env)->GetMethodID(env, OPSPReceiptDataClass, "<init>", "([B[B[B)V");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return NULL;
	}
	jreceipt = getjbyteArray(env, receiptData.receipt, 8);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return NULL;
	}
	jconfirmationCounter = getjbyteArray(env, receiptData.confirmationCounter, receiptData.confirmationCounterLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return NULL;
	}
	jcardUniqueData = getjbyteArray(env, receiptData.cardUniqueData, receiptData.cardUniqueDataLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return NULL;
	}
	OPSPReceiptDataInstance = (*env)->NewObject(env, OPSPReceiptDataClass, constructorID,
		jreceipt, jconfirmationCounter, jcardUniqueData);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return NULL;
	}
	return OPSPReceiptDataInstance;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    installForLoad
 * Signature: (JLorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;Lorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;[B[B[B[BJJJ)V
 */
JNIEXPORT void JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_installForLoad
  (JNIEnv *env, jclass cls, jlong cardHandle, jobject jsecInfo, jobject jcardInfo,
  jbyteArray jpackageAID, jbyteArray jsecurityDomainAID, jbyteArray jloadFileDAP,
  jbyteArray jloadToken, jlong nonVolatileCodeSpaceLimit, jlong volatileDataSpaceLimit,
  jlong nonVolatileDataSpaceLimit)
{
	LONG result;
	BYTE packageAID[16];
	DWORD packageAIDLength = 16;
	BYTE securityDomainAID[16];
	DWORD securityDomainAIDLength = 16;
	BYTE loadFileDAP[20];
	DWORD loadFileDAPLength=20;
	BYTE loadToken[128];
	DWORD loadTokenLength=128;
	OPSP_SECURITY_INFO secInfo;
	OPSP_CARD_INFO cardInfo;
	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForLoad"));
		return;
	}
	parsejsecInfo(env, jsecInfo, &secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForLoad"));
		return;
	}
	parsejbyteArray(env, jpackageAID, packageAID, &packageAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForLoad"));
		return;
	}

	parsejbyteArray(env, jsecurityDomainAID, securityDomainAID, &securityDomainAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForLoad"));
		return;
	}

	parsejbyteArray(env, jloadToken, loadToken, &loadTokenLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForLoad"));
		return;
	}

	parsejbyteArray(env, jloadFileDAP, loadFileDAP, &loadFileDAPLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForLoad"));
		return;
	}

	result = install_for_load((OPSP_CARDHANDLE)cardHandle, &secInfo, cardInfo,
		packageAID, packageAIDLength, securityDomainAID,
		securityDomainAIDLength, jloadFileDAP == NULL ? NULL : loadFileDAP,
		jloadToken == NULL ? NULL : loadToken,
		(DWORD)nonVolatileCodeSpaceLimit, (DWORD)volatileDataSpaceLimit,
		(DWORD)nonVolatileDataSpaceLimit);
	setjsecInfo(env, jsecInfo, secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForLoad"));
		return;
	}
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("installForLoad"), result);
		return;
	}
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    getLoadTokenSignatureData
 * Signature: ([B[B[BJJJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_getLoadTokenSignatureData
  (JNIEnv *env, jclass cls, jbyteArray jpackageAID, jbyteArray jsecurityDomainAID, jbyteArray jloadFileDAP,
  jlong nonVolatileCodeSpaceLimit, jlong volatileDataSpaceLimit, jlong nonVolatileDataSpaceLimit)
{
	LONG result;
	BYTE packageAID[16];
	DWORD packageAIDLength = 16;
	BYTE securityDomainAID[16];
	DWORD securityDomainAIDLength = 16;
	BYTE loadFileDAP[20];
	DWORD loadFileDAPLength=20;
	BYTE loadTokenSignatureData[256];
	DWORD loadTokenSignatureDataLength=256;
	jbyteArray jloadTokenSignatureData = NULL;
	parsejbyteArray(env, jpackageAID, packageAID, &packageAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getLoadTokenSignatureData"));
		return NULL;
	}
	parsejbyteArray(env, jsecurityDomainAID, securityDomainAID, &securityDomainAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getLoadTokenSignatureData"));
		return NULL;
	}
	parsejbyteArray(env, jloadFileDAP, loadFileDAP, &loadFileDAPLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getLoadTokenSignatureData"));
		return NULL;
	}
	result = get_load_token_signature_data(packageAID, packageAIDLength,
		securityDomainAID, securityDomainAIDLength,
		jloadFileDAP == NULL ? NULL : loadFileDAP,
		(DWORD)nonVolatileCodeSpaceLimit, (DWORD)volatileDataSpaceLimit, (DWORD)nonVolatileDataSpaceLimit,
		loadTokenSignatureData, &loadTokenSignatureDataLength);
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("getLoadTokenSignatureData"), result);
		return NULL;
	}
	jloadTokenSignatureData = getjbyteArray(env, loadTokenSignatureData, loadTokenSignatureDataLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getLoadTokenSignatureData"));
		return NULL;
	}
	return jloadTokenSignatureData;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    getInstallTokenSignatureData
 * Signature: (B[B[B[BBJJ[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_getInstallTokenSignatureData
  (JNIEnv *env, jclass cls, jbyte P1, jbyteArray jpackageAID, jbyteArray jappletClassAID,
  jbyteArray jappletInstanceAID, jbyte appletPrivileges, jlong volatileDataSpaceLimit,
  jlong nonVolatileDataSpaceLimit, jbyteArray jappletInstallParameters)
{
	LONG result;
	BYTE packageAID[16];
	DWORD packageAIDLength = 16;
	BYTE appletClassAID[16];
	DWORD appletClassAIDLength = 16;
	BYTE appletInstanceAID[16];
	DWORD appletInstanceAIDLength=16;
	BYTE appletInstallParameters[32];
	DWORD appletInstallParametersLength=32;
	BYTE installTokenSignatureData[256];
	DWORD installTokenSignatureDataLength=256;
	jbyteArray jinstallTokenSignatureData = NULL;
	parsejbyteArray(env, jpackageAID, packageAID, &packageAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getInstallTokenSignatureData"));
		return NULL;
	}

	parsejbyteArray(env, jappletClassAID, appletClassAID, &appletClassAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getInstallTokenSignatureData"));
		return NULL;
	}

	parsejbyteArray(env, jappletInstanceAID, appletInstanceAID, &appletInstanceAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getLoadTokenSignatureData"));
		return NULL;
	}
	parsejbyteArray(env, jappletInstallParameters, appletInstallParameters, &appletInstallParametersLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getLoadTokenSignatureData"));
		return NULL;
	}

	result = get_install_token_signature_data(P1, packageAID, packageAIDLength,
		appletClassAID, appletClassAIDLength, appletInstanceAID, appletInstanceAIDLength,
		(BYTE)appletPrivileges, (DWORD)volatileDataSpaceLimit, (DWORD)nonVolatileDataSpaceLimit,
		appletInstallParameters, appletInstallParametersLength,
		installTokenSignatureData,
		&installTokenSignatureDataLength);
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("getLoadTokenSignatureData"), result);
		return NULL;
	}
	jinstallTokenSignatureData = getjbyteArray(env, installTokenSignatureData, installTokenSignatureDataLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("getLoadTokenSignatureData"));
		return NULL;
	}
	return jinstallTokenSignatureData;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    calculateLoadToken
 * Signature: ([B[B[BJJJLjava/lang/String;Ljava/lang/String;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_calculateLoadToken
  (JNIEnv *env, jclass cls, jbyteArray jpackageAID,
  jbyteArray jsecurityDomainAID, jbyteArray jloadFileDAP, jlong nonVolatileCodeSpaceLimit,
  jlong volatileDataSpaceLimit, jlong nonVolatileDataSpaceLimit,
  jstring jPEMKeyFileName, jstring jpassPhrase)
{
	LONG result;
	BYTE packageAID[16];
	DWORD packageAIDLength = 16;
	BYTE securityDomainAID[16];
	DWORD securityDomainAIDLength = 16;
	BYTE loadFileDAP[20];
	DWORD loadFileDAPLength=20;
	jbyteArray jloadToken = NULL;
	BYTE loadToken[128];
	DWORD loadTokenLength=128;
	const char *passPhrase;
	OPSP_CSTRING PEMKeyFileName;
	parsejbyteArray(env, jpackageAID, packageAID, &packageAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("calculateLoadToken"));
		return NULL;
	}
	parsejbyteArray(env, jsecurityDomainAID, securityDomainAID, &securityDomainAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("calculateLoadToken"));
		return NULL;
	}
	parsejbyteArray(env, jloadFileDAP, loadFileDAP, &loadFileDAPLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("calculateLoadToken"));
		return NULL;
	}
	if (jpassPhrase == NULL) {
		passPhrase = NULL;
	}
	else {
		passPhrase = (*env)->GetStringUTFChars(env, jpassPhrase, 0);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("calculateLoadToken"));
			return NULL;
		}
	}
	if (jPEMKeyFileName == NULL) {
		PEMKeyFileName = NULL;
	}
	else {
#ifdef _UNICODE
	PEMKeyFileName = (OPSP_STRING)(*env)->GetStringChars(env, jPEMKeyFileName, 0);
#else
	PEMKeyFileName = (*env)->GetStringUTFChars(env, jPEMKeyFileName, 0);
#endif
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("calculateLoadToken"));
			return NULL;
		}
	}
	result = calculate_load_token(packageAID, packageAIDLength, securityDomainAID,
						  securityDomainAIDLength,
						  jloadFileDAP == NULL ? NULL : loadFileDAP,
						  (DWORD)nonVolatileCodeSpaceLimit, (DWORD)volatileDataSpaceLimit,
						  (DWORD)nonVolatileDataSpaceLimit, loadToken,
						  (OPSP_STRING)PEMKeyFileName, (char *)passPhrase);
	if (jpassPhrase != NULL) {
		(*env)->ReleaseStringUTFChars(env, jpassPhrase, passPhrase);
	}
	if (PEMKeyFileName != NULL) {
#ifdef _UNICODE
	(*env)->ReleaseStringChars(env, jPEMKeyFileName, PEMKeyFileName);
#else
	(*env)->ReleaseStringUTFChars(env, jPEMKeyFileName, PEMKeyFileName);
#endif
	}
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("installForLoad"), result);
		return NULL;
	}
	jloadToken = getjbyteArray(env, loadToken, loadTokenLength);
	return jloadToken;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    calculateInstallToken
 * Signature: (B[B[B[BBJJ[BLjava/lang/String;Ljava/lang/String;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_calculateInstallToken
  (JNIEnv *env, jclass cls, jbyte P1, jbyteArray jpackageAID, jbyteArray jappletClassAID,
  jbyteArray jappletInstanceAID, jbyte appletPrivileges, jlong volatileDataSpaceLimit,
  jlong nonVolatileDataSpaceLimit, jbyteArray jappletInstallParameters,
  jstring jPEMKeyFileName, jstring jpassPhrase)
{
	LONG result;
	BYTE packageAID[16];
	DWORD packageAIDLength = 16;
	BYTE appletClassAID[16];
	DWORD appletClassAIDLength = 16;
	BYTE appletInstanceAID[16];
	DWORD appletInstanceAIDLength=16;
	BYTE appletInstallParameters[32];
	DWORD appletInstallParametersLength=32;
	jbyteArray jinstallToken = NULL;
	BYTE installToken[128];
	DWORD installTokenLength=128;
	const char *passPhrase;
	OPSP_CSTRING PEMKeyFileName;
	parsejbyteArray(env, jpackageAID, packageAID, &packageAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("calculateInstallToken"));
		return NULL;
	}

	parsejbyteArray(env, jappletInstallParameters, appletInstallParameters, &appletInstallParametersLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("calculateInstallToken"));
		return NULL;
	}
	parsejbyteArray(env, jappletClassAID, appletClassAID, &appletClassAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("calculateInstallToken"));
		return NULL;
	}
	parsejbyteArray(env, jappletInstanceAID, appletInstanceAID, &appletInstanceAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("calculateInstallToken"));
		return NULL;
	}
	if (jpassPhrase == NULL) {
		passPhrase = NULL;
	}
	else {
		passPhrase = (*env)->GetStringUTFChars(env, jpassPhrase, 0);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("calculateInstallToken"));
			return NULL;
		}
	}
	if (jPEMKeyFileName == NULL) {
		PEMKeyFileName = NULL;
	}
	else {
#ifdef _UNICODE
	PEMKeyFileName = (OPSP_STRING)(*env)->GetStringChars(env, jPEMKeyFileName, 0);
#else
	PEMKeyFileName = (*env)->GetStringUTFChars(env, jPEMKeyFileName, 0);
#endif
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("calculateInstallToken"));
			return NULL;
		}
	}
	result = calculate_install_token(P1, packageAID, packageAIDLength, appletClassAID,
		appletClassAIDLength, appletInstanceAID, appletInstanceAIDLength, (BYTE)appletPrivileges,
		(DWORD)volatileDataSpaceLimit, (DWORD)nonVolatileDataSpaceLimit,
		appletInstallParameters, (DWORD)appletInstallParametersLength,
		installToken, (OPSP_STRING)PEMKeyFileName, (char *)passPhrase);
	if (jpassPhrase != NULL) {
		(*env)->ReleaseStringUTFChars(env, jpassPhrase, passPhrase);
	}
	if (jPEMKeyFileName != NULL) {
#ifdef _UNICODE
	(*env)->ReleaseStringChars(env, jPEMKeyFileName, PEMKeyFileName);
#else
	(*env)->ReleaseStringUTFChars(env, jPEMKeyFileName, PEMKeyFileName);
#endif
	}
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("calculateInstallToken"), result);
		return NULL;
	}
	jinstallToken = getjbyteArray(env, installToken, installTokenLength);
	return jinstallToken;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    calculateLoadFileDAP
 * Signature: ([Lorg/dyndns/widerstand/OpenPlatform/OPSPDAPBlock;Ljava/lang/String;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_calculateLoadFileDAP
  (JNIEnv *env, jclass cls, jobjectArray jdapBlock, jstring jCAPFileName)
{
	LONG result;
	OPSP_DAP_BLOCK *dapBlock;
	DWORD dapBlockLength;
	OPSP_CSTRING CAPFileName;
	BYTE hash[20];
	jbyteArray jhash = NULL;
	DWORD i;
	jobject jdapBlockInstance;
	dapBlockLength = (DWORD)(*env)->GetArrayLength(env, jdapBlock);
	dapBlock = (OPSP_DAP_BLOCK *)malloc(sizeof(OPSP_DAP_BLOCK)*dapBlockLength);
	for (i=0; i<dapBlockLength; i++) {
		jdapBlockInstance = (*env)->GetObjectArrayElement(env, jdapBlock, i);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			free(dapBlock);
			throwException(env, _T("calculateLoadFileDAP"));
			return NULL;
		}
		parsejOPSPDAPBlock(env, jdapBlockInstance, &(dapBlock[i]));
		if ((*env)->ExceptionOccurred(env) != NULL) {
			free(dapBlock);
			throwException(env, _T("calculateLoadFileDAP"));
			return NULL;
		}
	}
#ifdef _UNICODE
	CAPFileName = (*env)->GetStringChars(env, jCAPFileName, 0);
#else
	CAPFileName = (*env)->GetStringUTFChars(env, jCAPFileName, 0);
#endif
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("calculateLoadFileDAP"));
		return NULL;
	}
	result = calculate_load_file_DAP(dapBlock, dapBlockLength,
							 (OPSP_STRING)CAPFileName, hash);
	free(dapBlock);
#ifdef _UNICODE
	(*env)->ReleaseStringChars(env, jCAPFileName, CAPFileName);
#else
	(*env)->ReleaseStringUTFChars(env, jCAPFileName, CAPFileName);
#endif
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("calculateInstallToken"), result);
		return NULL;
	}
	jhash = getjbyteArray(env, hash, 20);
	return jhash;
}

/*
 * Parses a OPSPDAPBlock into a OPSP_DAP_BLOCK.
 * \param *env JNI interface pointer.
 * \param jdapBlockInstance OPSPDAPBlock object.
 * \param *dapBlock The returned OPSP_DAP_BLOCK.
 */
static void parsejOPSPDAPBlock(JNIEnv *env, jobject jdapBlockInstance,
							   OPSP_DAP_BLOCK *dapBlock)
{
	jmethodID methodID1, methodID2;
	jclass dapBlockClass;
	jbyteArray jsignature, jsecurityDomainAID;
	OPSP_STRING empty = _T("");
	dapBlockClass = (*env)->FindClass(env, "org/dyndns/widerstand/OpenPlatform/OPSPDAPBlock");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	methodID1 = (*env)->GetMethodID(env, dapBlockClass, "getSecurityDomainAID", "()[B");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	methodID2 = (*env)->GetMethodID(env, dapBlockClass, "getSignature", "()[B");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	jsecurityDomainAID = (jbyteArray)(*env)->CallObjectMethod(env, jdapBlockInstance, methodID1);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	jsignature = (jbyteArray)(*env)->CallObjectMethod(env, jdapBlockInstance, methodID2);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	dapBlock->securityDomainAIDLength = 16;
	parsejbyteArray(env, jsecurityDomainAID, dapBlock->securityDomainAID,
		(PDWORD)&(dapBlock->securityDomainAIDLength));
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	dapBlock->signatureLength = 16;
	parsejbyteArray(env, jsignature, dapBlock->signature,
		(PDWORD)&(dapBlock->signatureLength));
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	dapBlock->DAPBlockLength = 1 + 1 + dapBlock->securityDomainAIDLength
		+ 1 + 1 +dapBlock->signatureLength;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    loadApplet
 * Signature: (JLorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;Lorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;[Lorg/dyndns/widerstand/OpenPlatform/OPSPDAPBlock;Ljava/lang/String;)Lorg/dyndns/widerstand/OpenPlatform/OPSPReceiptData;
 */
JNIEXPORT jobject JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_loadApplet
  (JNIEnv *env, jclass cls, jlong cardHandle, jobject jsecInfo, jobject jcardInfo,
  jobjectArray jdapBlock, jstring jCAPFileName)
{
	LONG result;
	OPSP_DAP_BLOCK *dapBlock;
	DWORD dapBlockLength;
	OPSP_CSTRING CAPFileName;
	DWORD i;
	jobject jdapBlockInstance;
	OPSP_RECEIPT_DATA receiptData;
	OPSP_SECURITY_INFO secInfo;
	OPSP_CARD_INFO cardInfo;
	jobject jreceiptData = NULL;
	DWORD receiptDataAvailable;
	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("loadApplet"));
		return NULL;
	}
	parsejsecInfo(env, jsecInfo, &secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("loadApplet"));
		return NULL;
	}
	if (jdapBlock != NULL) {
		dapBlockLength = (DWORD)(*env)->GetArrayLength(env, jdapBlock);
		dapBlock = (OPSP_DAP_BLOCK *)malloc(sizeof(OPSP_DAP_BLOCK)*dapBlockLength);
	}
	else {
		dapBlockLength = 0;
		dapBlock = NULL;
	}
	for (i=0; i<dapBlockLength; i++) {
		jdapBlockInstance = (*env)->GetObjectArrayElement(env, jdapBlock, i);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			free(dapBlock);
			throwException(env, _T("loadApplet"));
			return NULL;
		}
		parsejOPSPDAPBlock(env, jdapBlockInstance, &(dapBlock[i]));
		if ((*env)->ExceptionOccurred(env) != NULL) {
			free(dapBlock);
			throwException(env, _T("loadApplet"));
			return NULL;
		}
	}
#ifdef _UNICODE
	CAPFileName = (*env)->GetStringChars(env, jCAPFileName, 0);
#else
	CAPFileName = (*env)->GetStringUTFChars(env, jCAPFileName, 0);
#endif
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("loadApplet"));
		return NULL;
	}
	result = load_applet((OPSP_CARDHANDLE)cardHandle, &secInfo, cardInfo,
		dapBlock, (DWORD)dapBlockLength, (OPSP_STRING)CAPFileName, &receiptData,
		&receiptDataAvailable);
	if (jdapBlock != NULL) {
		free(dapBlock);
	}
#ifdef _UNICODE
	(*env)->ReleaseStringChars(env, jCAPFileName, CAPFileName);
#else
	(*env)->ReleaseStringUTFChars(env, jCAPFileName, CAPFileName);
#endif
	setjsecInfo(env, jsecInfo, secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("loadApplet"));
		return NULL;
	}
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("loadApplet"), result);
		return NULL;
	}
	if (receiptDataAvailable) {
		jreceiptData = getOPSPReceiptData(env, receiptData);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("loadApplet"));
			return NULL;
		}
	}
	return jreceiptData;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    installForInstall
 * Signature: (JLorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;Lorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;[B[B[BBJJ[B[B)Lorg/dyndns/widerstand/OpenPlatform/OPSPReceipt;
 */
JNIEXPORT jobject JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_installForInstall
  (JNIEnv *env, jclass cls, jlong cardHandle, jobject jsecInfo, jobject jcardInfo,
  jbyteArray jpackageAID, jbyteArray jappletClassAID, jbyteArray jappletInstanceAID,
  jbyte appletPrivileges, jlong volatileDataSpaceLimit,
  jlong nonVolatileDataSpaceLimit, jbyteArray jappletInstallParameters, jbyteArray jinstallToken)
{
	LONG result;
	OPSP_RECEIPT_DATA receiptData;
	OPSP_SECURITY_INFO secInfo;
	OPSP_CARD_INFO cardInfo;
	jobject jreceiptData = NULL;
	BYTE packageAID[16];
	DWORD packageAIDLength = 16;
	BYTE installToken[128];
	DWORD installTokenLength = 128;
	BYTE appletClassAID[16];
	DWORD appletClassAIDLength = 16;
	BYTE appletInstanceAID[16];
	DWORD appletInstanceAIDLength=16;
	BYTE appletInstallParameters[32];
	DWORD appletInstallParametersLength=32;
	DWORD receiptDataAvailable;
	parsejbyteArray(env, jpackageAID, packageAID, &packageAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForInstall"));
		return NULL;
	}

	parsejbyteArray(env, jappletClassAID, appletClassAID, &appletClassAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForInstall"));
		return NULL;
	}

	parsejbyteArray(env, jappletInstanceAID, appletInstanceAID, &appletInstanceAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForInstall"));
		return NULL;
	}

	parsejbyteArray(env, jappletInstallParameters, appletInstallParameters, &appletInstallParametersLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForInstall"));
		return NULL;
	}
	parsejbyteArray(env, jinstallToken, installToken, &installTokenLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForInstall"));
		return NULL;
	}

	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForInstall"));
		return NULL;
	}
	parsejsecInfo(env, jsecInfo, &secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForInstall"));
		return NULL;
	}
	result = install_for_install((OPSP_CARDHANDLE)cardHandle, &secInfo, cardInfo,
		packageAID, packageAIDLength, appletClassAID, appletClassAIDLength,
		appletInstanceAID, appletInstanceAIDLength, (BYTE)appletPrivileges,
		(DWORD)volatileDataSpaceLimit, (DWORD)nonVolatileDataSpaceLimit,
		appletInstallParameters, (DWORD)appletInstallParametersLength,
		jinstallToken == NULL ? NULL : installToken, &receiptData, &receiptDataAvailable);
	setjsecInfo(env, jsecInfo, secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForInstall"));
		return NULL;
	}
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("installForInstall"), result);
		return NULL;
	}
	if (receiptDataAvailable) {
		jreceiptData = getOPSPReceiptData(env, receiptData);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("installForInstall"));
			return NULL;
		}
	}
	return jreceiptData;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    installForInstallAndMakeSelectable
 * Signature: (JLorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;Lorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;[B[B[BBJJ[B[B)Lorg/dyndns/widerstand/OpenPlatform/OPSPReceipt;
 */
JNIEXPORT jobject JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_installForInstallAndMakeSelectable
  (JNIEnv *env, jclass cls, jlong cardHandle, jobject jsecInfo, jobject jcardInfo,
  jbyteArray jpackageAID, jbyteArray jappletClassAID, jbyteArray jappletInstanceAID,
  jbyte appletPrivileges, jlong volatileDataSpaceLimit,
  jlong nonVolatileDataSpaceLimit, jbyteArray jappletInstallParameters, jbyteArray jinstallToken)
{
	LONG result;
	OPSP_RECEIPT_DATA receiptData;
	OPSP_SECURITY_INFO secInfo;
	OPSP_CARD_INFO cardInfo;
	jobject jreceiptData = NULL;
	BYTE packageAID[16];
	DWORD packageAIDLength = 16;
	BYTE installToken[128];
	DWORD installTokenLength = 128;
	BYTE appletClassAID[16];
	DWORD appletClassAIDLength = 16;
	BYTE appletInstanceAID[16];
	DWORD appletInstanceAIDLength=16;
	BYTE appletInstallParameters[32];
	DWORD appletInstallParametersLength=32;
	DWORD receiptDataAvailable;
	parsejbyteArray(env, jpackageAID, packageAID, &packageAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForInstallAndMakeSelectable"));
		return NULL;
	}

	parsejbyteArray(env, jappletClassAID, appletClassAID, &appletClassAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForInstallAndMakeSelectable"));
		return NULL;
	}

	parsejbyteArray(env, jappletInstanceAID, appletInstanceAID, &appletInstanceAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForInstallAndMakeSelectable"));
		return NULL;
	}

	parsejbyteArray(env, jappletInstallParameters, appletInstallParameters, &appletInstallParametersLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForInstallAndMakeSelectable"));
		return NULL;
	}
	parsejbyteArray(env, jinstallToken, installToken, &installTokenLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForInstallAndMakeSelectable"));
		return NULL;
	}

	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForInstallAndMakeSelectable"));
		return NULL;
	}
	parsejsecInfo(env, jsecInfo, &secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForInstallAndMakeSelectable"));
		return NULL;
	}
	result = install_for_install_and_make_selectable((OPSP_CARDHANDLE)cardHandle, &secInfo, cardInfo,
		packageAID, packageAIDLength, appletClassAID, appletClassAIDLength,
		appletInstanceAID, appletInstanceAIDLength, (BYTE)appletPrivileges,
		(DWORD)volatileDataSpaceLimit, (DWORD)nonVolatileDataSpaceLimit,
		appletInstallParameters, (DWORD)appletInstallParametersLength,
		jinstallToken == NULL ? NULL : installToken, &receiptData, &receiptDataAvailable);
	setjsecInfo(env, jsecInfo, secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForInstallAndMakeSelectable"));
		return NULL;
	}
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("installForInstallAndMakeSelectable"), result);
		return NULL;
	}
	if (receiptDataAvailable) {
		jreceiptData = getOPSPReceiptData(env, receiptData);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("installForInstallAndMakeSelectable"));
			return NULL;
		}
	}
	return jreceiptData;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    installForMakeSelectable
 * Signature: (JLorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;Lorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;[BB[B)Lorg/dyndns/widerstand/OpenPlatform/OPSPReceipt;
 */
JNIEXPORT jobject JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_installForMakeSelectable
  (JNIEnv *env, jclass cls, jlong cardHandle, jobject jsecInfo, jobject jcardInfo,
  jbyteArray jappletInstanceAID, jbyte appletPrivileges,
  jbyteArray jinstallToken)
{
	LONG result;
	OPSP_RECEIPT_DATA receiptData;
	OPSP_SECURITY_INFO secInfo;
	OPSP_CARD_INFO cardInfo;
	jobject jreceiptData = NULL;
	BYTE installToken[128];
	DWORD installTokenLength = 128;
	BYTE appletInstanceAID[16];
	DWORD appletInstanceAIDLength=16;
	DWORD receiptDataAvailable;
	parsejbyteArray(env, jappletInstanceAID, appletInstanceAID, &appletInstanceAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForMakeSelectable"));
		return NULL;
	}
	parsejbyteArray(env, jinstallToken, installToken, &installTokenLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForMakeSelectable"));
		return NULL;
	}

	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForMakeSelectable"));
		return NULL;
	}
	parsejsecInfo(env, jsecInfo, &secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForMakeSelectable"));
		return NULL;
	}
	result = install_for_make_selectable((OPSP_CARDHANDLE)cardHandle, &secInfo,
		cardInfo, appletInstanceAID,
		(DWORD)appletInstanceAIDLength, (BYTE)appletPrivileges,
		jinstallToken == NULL ? NULL : installToken, &receiptData,
		&receiptDataAvailable);
	setjsecInfo(env, jsecInfo, secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("installForMakeSelectable"));
		return NULL;
	}
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("installForMakeSelectable"), result);
		return NULL;
	}
	if (receiptDataAvailable) {
		jreceiptData = getOPSPReceiptData(env, receiptData);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("installForMakeSelectable"));
			return NULL;
		}
	}
	return jreceiptData;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    putDelegatedManagementKeys
 * Signature: (JLorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;Lorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;BBLjava/lang/String;Ljava/lang/String;[B[B)V
 */
JNIEXPORT void JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_putDelegatedManagementKeys
  (JNIEnv *env, jclass cls, jlong cardHandle, jobject jsecInfo, jobject jcardInfo,
  jbyte keySetVersion, jbyte newKeySetVersion, jstring jPEMKeyFileName, jstring jpassPhrase,
  jbyteArray jreceiptGenerationKey,
  jbyteArray jkekKey)
{
	LONG result;
	BYTE receipt_generation_key[16];
	DWORD token_verification_rsa_exponent_length=128;
	BYTE kek_key[16];
	DWORD dummy=16;
	OPSP_SECURITY_INFO secInfo;
	OPSP_CARD_INFO cardInfo;
	OPSP_CSTRING PEMKeyFileName;
	const char *passPhrase;
	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("putDelegatedManagementKeys"));
		return;
	}
	parsejsecInfo(env, jsecInfo, &secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("putDelegatedManagementKeys"));
		return;
	}
	if (jPEMKeyFileName == NULL) {
		PEMKeyFileName = NULL;
	}
	else {
#ifdef _UNICODE
	PEMKeyFileName = (OPSP_STRING)(*env)->GetStringChars(env, jPEMKeyFileName, 0);
#else
	PEMKeyFileName = (*env)->GetStringUTFChars(env, jPEMKeyFileName, 0);
#endif
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("putDelegatedManagementKeys"));
			return;
		}
	}
	if (jpassPhrase == NULL) {
		passPhrase = NULL;
	}
	else {
		passPhrase = (*env)->GetStringUTFChars(env, jpassPhrase, 0);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("putDelegatedManagementKeys"));
			return;
		}
}

	parsejbyteArray(env, jreceiptGenerationKey, receipt_generation_key, &dummy);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("putDelegatedManagementKeys"));
		return;
	}
	dummy=16;
	parsejbyteArray(env, jkekKey, kek_key, &dummy);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("putDelegatedManagementKeys"));
		return;
	}

	result = put_delegated_management_keys((OPSP_CARDHANDLE)cardHandle, &secInfo, cardInfo,
		(BYTE)keySetVersion, (BYTE)newKeySetVersion, (OPSP_STRING)PEMKeyFileName, (char *)passPhrase,
		receipt_generation_key, kek_key);
	setjsecInfo(env, jsecInfo, secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("putDelegatedManagementKeys"));
		return;
	}
	if (jPEMKeyFileName != NULL) {
#ifdef _UNICODE
	(*env)->ReleaseStringChars(env, jPEMKeyFileName, PEMKeyFileName);
#else
	(*env)->ReleaseStringUTFChars(env, jPEMKeyFileName, PEMKeyFileName);
#endif
	}
	if (jpassPhrase != NULL) {
		(*env)->ReleaseStringUTFChars(env, jpassPhrase, passPhrase);
	}

	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("putDelegatedManagementKeys"), result);
		return;
	}
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    sendAPDU
 * Signature: (J[BLorg/dyndns/widerstand/OpenPlatform/OPSPCardConnectionInfo;Lorg/dyndns/widerstand/OpenPlatform/OPSPSecurityInfo;)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_sendAPDU
  (JNIEnv *env, jclass cls, jlong cardHandle, jbyteArray jcapdu, jobject jcardInfo, jobject jsecInfo)
{
	LONG result;
	BYTE capdu[261];
	DWORD capduLength=261;
	BYTE rapdu[258];
	DWORD rapduLength=258;
	OPSP_SECURITY_INFO secInfo;
	OPSP_CARD_INFO cardInfo;
	jbyteArray jrapdu = NULL;
	parsejcardInfo(env, jcardInfo, &cardInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("sendAPDU"));
		return NULL;
	}
	if (jsecInfo != NULL) {
		parsejsecInfo(env, jsecInfo, &secInfo);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("sendAPDU"));
			return NULL;
		}
	}
		parsejbyteArray(env, jcapdu, capdu, &capduLength);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("sendAPDU"));
			return NULL;
		}

	if (jsecInfo == NULL) {
		result = send_APDU((OPSP_CARDHANDLE)cardHandle, capdu, capduLength, rapdu, &rapduLength,
			cardInfo, NULL);
	}
	else {
		result = send_APDU((OPSP_CARDHANDLE)cardHandle, capdu, capduLength, rapdu, &rapduLength,
			cardInfo, &secInfo);
	}
	setjsecInfo(env, jsecInfo, secInfo);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("sendAPDU"));
		return NULL;
	}
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("sendAPDU"), result);
		return NULL;
	}
	jrapdu = getjbyteArray(env, rapdu, rapduLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("sendAPDU"));
		return NULL;
	}
	return jrapdu;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    calculate3desDAP
 * Signature: ([BLjava/lang/String;[B)Lorg/dyndns/widerstand/OpenPlatform/OPSPDAPBlock;
 */
JNIEXPORT jobject JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_calculate3desDAP
  (JNIEnv *env, jclass cls, jbyteArray jsecurityDomainAID, jstring jCAPFileName, jbyteArray jDAPVerificationKey)
{
	LONG result;
	BYTE securityDomainAID[16];
	DWORD securityDomainAIDLength = 16;
	OPSP_CSTRING CAPFileName;
	OPSP_DAP_BLOCK dapBlock;
	BYTE DAP_verification_key[16];
	DWORD DAP_verification_key_length = 16;
	jobject OPSPDAPBlockInstance = NULL;
		parsejbyteArray(env, jsecurityDomainAID, securityDomainAID,
			&securityDomainAIDLength);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("calculate3desDAP"));
			return NULL;
		}
		parsejbyteArray(env, jDAPVerificationKey, DAP_verification_key,
			&DAP_verification_key_length);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("calculate3desDAP"));
			return NULL;
		}

#ifdef _UNICODE
	CAPFileName = (OPSP_STRING)(*env)->GetStringChars(env, jCAPFileName, 0);
#else
	CAPFileName = (*env)->GetStringUTFChars(env, jCAPFileName, 0);
#endif
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("calculate3desDAP"));
		return NULL;
	}
	result = calculate_3des_DAP(securityDomainAID, securityDomainAIDLength, (OPSP_STRING)CAPFileName,
		DAP_verification_key, &dapBlock);
#ifdef _UNICODE
	(*env)->ReleaseStringChars(env, jCAPFileName, 0);
#else
	(*env)->ReleaseStringUTFChars(env, jCAPFileName, 0);
#endif
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("calculate3desDAP"), result);
		return NULL;
	}
	OPSPDAPBlockInstance = getOPSPDAPBlock(env, dapBlock);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("calculate3desDAP"));
		return NULL;
	}
	return OPSPDAPBlockInstance;
}


/**
 * Parses a OPSP_DAP_BLOCK into a OPSPDAPBlock.
 * \param *env JNI interface pointer.
 * \param dapBlock The OPSP_DAP_BLOCK.
 * \return an jobject of class OPSPDAPBlock
 */
static jobject getOPSPDAPBlock(JNIEnv *env, OPSP_DAP_BLOCK dapBlock) {
	OPSP_STRING empty = _T("");
	jclass OPSPDAPBlockClass;
	jobject OPSPDAPBlockInstance = NULL;
	jmethodID constructorID;
	jbyteArray jsecurityDomainAID, jsignature;
	OPSPDAPBlockClass = (*env)->FindClass(env, "org/dyndns/widerstand/OpenPlatform/OPSPDAPBlock");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return NULL;
	}
	constructorID = (*env)->GetMethodID(env, OPSPDAPBlockClass, "<init>", "([B[B)V");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return NULL;
	}
	jsecurityDomainAID = getjbyteArray(env, dapBlock.securityDomainAID, dapBlock.securityDomainAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return NULL;
	}
	jsignature = getjbyteArray(env, dapBlock.signature, dapBlock.signatureLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return NULL;
	}
	OPSPDAPBlockInstance = (*env)->NewObject(env, OPSPDAPBlockClass, constructorID, jsecurityDomainAID, jsignature);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return NULL;
	}
	return OPSPDAPBlockInstance;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    calculateRsaDAP
 * Signature: ([BLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lorg/dyndns/widerstand/OpenPlatform/OPSPDAPBlock;
 */
JNIEXPORT jobject JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_calculateRsaDAP
  (JNIEnv *env, jclass cls, jbyteArray jsecurityDomainAID, jstring jCAPFileName,
  jstring jPEMKeyFileName, jstring jpassPhrase)
{
	LONG result;
	BYTE securityDomainAID[16];
	DWORD securityDomainAIDLength = 16;
	OPSP_CSTRING CAPFileName;
	OPSP_CSTRING PEMKeyFileName;
	const char *passPhrase;
	OPSP_DAP_BLOCK dapBlock;
	jobject OPSPDAPBlockInstance = NULL;
	parsejbyteArray(env, jsecurityDomainAID, securityDomainAID,
		&securityDomainAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("calculateRsaDAP"));
		return NULL;
	}
	if (jCAPFileName == NULL) {
		CAPFileName = NULL;
	}
	else {
#ifdef _UNICODE
	CAPFileName = (*env)->GetStringChars(env, jCAPFileName, 0);
#else
	CAPFileName = (*env)->GetStringUTFChars(env, jCAPFileName, 0);
#endif
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("calculateRsaDAP"));
			return NULL;
		}
	}
	if (jPEMKeyFileName == NULL) {
		PEMKeyFileName = NULL;
	}
	else {
#ifdef _UNICODE
	PEMKeyFileName = (*env)->GetStringChars(env, jPEMKeyFileName, 0);
#else
	PEMKeyFileName = (*env)->GetStringUTFChars(env, jPEMKeyFileName, 0);
#endif
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("calculateRsaDAP"));
			return NULL;
		}
	}
	if (jpassPhrase == NULL) {
		passPhrase = NULL;
	}
	else {
		passPhrase = (char *)(*env)->GetStringUTFChars(env, jpassPhrase, 0);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			throwException(env, _T("calculateRsaDAP"));
			return NULL;
		}
	}
	result = calculate_rsa_DAP(securityDomainAID, securityDomainAIDLength, (OPSP_STRING)CAPFileName,
		(OPSP_STRING)PEMKeyFileName, (char *)passPhrase, &dapBlock);
	if (jPEMKeyFileName != NULL) {
#ifdef _UNICODE
	(*env)->ReleaseStringChars(env, jPEMKeyFileName, PEMKeyFileName);
#else
	(*env)->ReleaseStringUTFChars(env, jPEMKeyFileName, PEMKeyFileName);
#endif
	}
	if (jCAPFileName != NULL) {
#ifdef _UNICODE
	(*env)->ReleaseStringChars(env, jCAPFileName, CAPFileName);
#else
	(*env)->ReleaseStringUTFChars(env, jCAPFileName, CAPFileName);
#endif
	}
	if (jpassPhrase != NULL) {
		(*env)->ReleaseStringUTFChars(env, jpassPhrase, passPhrase);
	}
	if (result != OPSP_ERROR_SUCCESS) {
		throwOPSPException(env, _T("calculateRsaDAP"), result);
		return NULL;
	}
	OPSPDAPBlockInstance = getOPSPDAPBlock(env, dapBlock);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("calculateRsaDAP"));
		return NULL;
	}
	return OPSPDAPBlockInstance;
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    validateDeleteReceipt
 * Signature: (J[B[BLorg/dyndns/widerstand/OpenPlatform/OPSPReceiptData;[B)Z
 */
JNIEXPORT jboolean JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_validateDeleteReceipt
  (JNIEnv *env, jclass cls, jlong confirmationCounter, jbyteArray jcardUniqueData,
  jbyteArray jreceiptGenerationKey, jobject jreceiptData, jbyteArray jAID)
{
	LONG result;
	BYTE cardUniqueData[10];
	DWORD cardUniqueDataLength = 10;
	BYTE receipt_generation_key[16];
	DWORD receipt_generation_key_length = 16;
	BYTE AID[16];
	DWORD AIDLength = 16;
	OPSP_RECEIPT_DATA receiptData;
	jobject OPSPDAPBlockInstance = NULL;
	parsejbyteArray(env, jcardUniqueData, cardUniqueData, &cardUniqueDataLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("validateDeleteReceipt"));
		return JNI_FALSE;
	}
	parsejbyteArray(env, jreceiptGenerationKey, receipt_generation_key, &receipt_generation_key_length);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("validateDeleteReceipt"));
		return JNI_FALSE;
	}
	parsejbyteArray(env, jAID, AID, &AIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("validateDeleteReceipt"));
		return JNI_FALSE;
	}
	parsejOPSPReceiptData(env, jreceiptData, &receiptData);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("validateDeleteReceipt"));
		return JNI_FALSE;
	}
	result = validate_delete_receipt((DWORD)confirmationCounter, cardUniqueData,
		receipt_generation_key, receiptData,
		AID, AIDLength);
	if ((result != OPSP_ERROR_SUCCESS) && (result != OPSP_ERROR_VALIDATION_FAILED)) {
		throwOPSPException(env, _T("validateDeleteReceipt"), result);
		return JNI_FALSE;
	}
	if (OPSP_ERROR_VALIDATION_FAILED) {
		return JNI_FALSE;
	}
	else {
		return JNI_TRUE;
	}
}

static void parsejOPSPReceiptData(JNIEnv *env, jobject jreceiptData, OPSP_RECEIPT_DATA *receiptData)
{
	jclass OPSPReceiptDataClass;
	jmethodID methodID1, methodID2, methodID3;
	OPSP_STRING empty = _T("");
	DWORD dummy;
	jbyteArray jcardUniqueData, jconfirmationCounter, jreceipt;
	OPSPReceiptDataClass = (*env)->FindClass(env, "org/dyndns/widerstand/OpenPlatform/OPSPReceiptData");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	methodID1 = (*env)->GetMethodID(env, OPSPReceiptDataClass, "getConfirmationCounter", "()[B");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	methodID2 = (*env)->GetMethodID(env, OPSPReceiptDataClass, "getReceipt", "()[B");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	methodID3 =	(*env)->GetMethodID(env, OPSPReceiptDataClass, "getCardUniqueData", "()[B");
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	jconfirmationCounter = (jbyteArray)(*env)->CallObjectMethod(env, jreceiptData, methodID1);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	jreceipt = (jbyteArray)(*env)->CallObjectMethod(env, jreceiptData, methodID2);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	jcardUniqueData = (jbyteArray)(*env)->CallObjectMethod(env, jreceiptData, methodID3);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	receiptData->confirmationCounterLength = 2;
	parsejbyteArray(env, jconfirmationCounter, receiptData->confirmationCounter,
		(PDWORD)&(receiptData->confirmationCounterLength));
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	receiptData->cardUniqueDataLength = 10;
	parsejbyteArray(env, jcardUniqueData, receiptData->cardUniqueData,
		(PDWORD)&(receiptData->cardUniqueDataLength));
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
	dummy = 8;
	parsejbyteArray(env, jreceipt, receiptData->receipt, &dummy);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, empty);
		return;
	}
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    validateInstallReceipt
 * Signature: (J[B[BLorg/dyndns/widerstand/OpenPlatform/OPSPReceiptData;[B[B)Z
 */
JNIEXPORT jboolean JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_validateInstallReceipt
  (JNIEnv *env, jclass cls, jlong confirmationCounter, jbyteArray jcardUniqueData,
  jbyteArray jreceiptGenerationKey, jobject jreceiptData,
  jbyteArray jpackageAID, jbyteArray jappletInstanceAID)
{
	LONG result;
	BYTE cardUniqueData[10];
	DWORD cardUniqueDataLength = 10;
    BYTE receipt_generation_key[16];
	DWORD receipt_generation_key_length = 16;
	BYTE packageAID[16];
	DWORD packageAIDLength = 16;
	BYTE appletInstanceAID[16];
	DWORD appletInstanceAIDLength = 16;
	OPSP_RECEIPT_DATA receiptData;
	jobject OPSPDAPBlockInstance = NULL;
	parsejbyteArray(env, jcardUniqueData, cardUniqueData, &cardUniqueDataLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("validateInstallReceipt"));
		return JNI_FALSE;
	}
	parsejbyteArray(env, jreceiptGenerationKey, receipt_generation_key, &receipt_generation_key_length);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("validateInstallReceipt"));
		return JNI_FALSE;
	}
	parsejbyteArray(env, jpackageAID, packageAID, &packageAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("validateInstallReceipt"));
		return JNI_FALSE;
	}
	parsejbyteArray(env, jappletInstanceAID, appletInstanceAID, &appletInstanceAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("validateInstallReceipt"));
		return JNI_FALSE;
	}
	parsejOPSPReceiptData(env, jreceiptData, &receiptData);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("validateInstallReceipt"));
		return JNI_FALSE;
	}
	result = validate_install_receipt((DWORD)confirmationCounter, cardUniqueData,
		receipt_generation_key, receiptData, packageAID, packageAIDLength,
		appletInstanceAID, appletInstanceAIDLength);
	if ((result != OPSP_ERROR_SUCCESS) && (result != OPSP_ERROR_VALIDATION_FAILED)) {
		throwOPSPException(env, _T("validateInstallReceipt"), result);
		return JNI_FALSE;
	}
	if (OPSP_ERROR_VALIDATION_FAILED) {
		return JNI_FALSE;
	}
	else {
		return JNI_TRUE;
	}
}

/*
 * Class:     org_dyndns_widerstand_OpenPlatform_OPSPWrapper
 * Method:    validateLoadReceipt
 * Signature: (J[B[BLorg/dyndns/widerstand/OpenPlatform/OPSPReceiptData;[B[B)Z
 */
JNIEXPORT jboolean JNICALL Java_org_dyndns_widerstand_OpenPlatform_OPSPWrapper_validateLoadReceipt
  (JNIEnv *env, jclass cls, jlong confirmationCounter, jbyteArray jcardUniqueData,
  jbyteArray jreceiptGenerationKey, jobject jreceiptData,
  jbyteArray jpackageAID, jbyteArray jsecurityDomainAID)
{
	LONG result;
	BYTE cardUniqueData[10];
	DWORD cardUniqueDataLength = 10;
    BYTE receipt_generation_key[16];
	DWORD receipt_generation_key_length = 16;
	BYTE packageAID[16];
	DWORD packageAIDLength = 16;
	BYTE securityDomainAID[16];
	DWORD securityDomainAIDLength = 16;
	OPSP_RECEIPT_DATA receiptData;
	jobject OPSPDAPBlockInstance = NULL;
	parsejbyteArray(env, jcardUniqueData, cardUniqueData, &cardUniqueDataLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("validateLoadReceipt"));
		return JNI_FALSE;
	}
	parsejbyteArray(env, jreceiptGenerationKey, receipt_generation_key, &receipt_generation_key_length);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("validateLoadReceipt"));
		return JNI_FALSE;
	}
	parsejbyteArray(env, jpackageAID, packageAID, &packageAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("validateLoadReceipt"));
		return JNI_FALSE;
	}
	parsejbyteArray(env, jsecurityDomainAID, securityDomainAID, &securityDomainAIDLength);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("validateLoadReceipt"));
		return JNI_FALSE;
	}
	parsejOPSPReceiptData(env, jreceiptData, &receiptData);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		throwException(env, _T("validateLoadReceipt"));
		return JNI_FALSE;
	}
	result = validate_load_receipt((DWORD)confirmationCounter, cardUniqueData,
		receipt_generation_key, receiptData, packageAID, packageAIDLength,
		securityDomainAID, securityDomainAIDLength);
	if ((result != OPSP_ERROR_SUCCESS) && (result != OPSP_ERROR_VALIDATION_FAILED)) {
		throwOPSPException(env, _T("validateLoadReceipt"), result);
		return JNI_FALSE;
	}
	if (OPSP_ERROR_VALIDATION_FAILED) {
		return JNI_FALSE;
	}
	else {
		return JNI_TRUE;
	}
}

/*
 * Throws the actual pending exception.
 * \param *env JNI interface pointer.
 * \param method The name of the method in which the exception is thrown.
 * \return 0 for success, else -1.
 */
static int throwException(JNIEnv *env, OPSP_CSTRING method) {

    jstring     exceptionMsg;
    jclass      exceptionClass;
    jobject     exceptionInstance;
    jmethodID   constructorID;
	jmethodID   methodID;
	jthrowable  pendingException;
	jstring		originalJavaMsg;

	OPSP_CSTRING originalMsg;
	OPSP_STRING completeMsg;

	pendingException = (*env)->ExceptionOccurred(env);
	exceptionClass = (*env)->GetObjectClass(env, pendingException);
	if (exceptionClass == NULL) /* Unable to find the new exception class. */
		return -1;
    constructorID = (*env)->GetMethodID(env, exceptionClass,
			    "<init>", "(Ljava/lang/String)V");
    if (constructorID == NULL)
		return -1;
	methodID = (*env)->GetMethodID(env, exceptionClass,
			    "toString", "()Ljava/lang/String");
    if (methodID == NULL)
		return -1;

	originalJavaMsg = (jstring)(*env)->CallObjectMethod(env, pendingException, methodID);
#ifdef _UNICODE
	originalMsg = (*env)->GetStringChars(env, originalJavaMsg, 0);
#else
	originalMsg = (*env)->GetStringUTFChars(env, originalJavaMsg, 0);
#endif
    completeMsg = (OPSP_STRING)malloc((_tcslen(method)+_tcslen(originalMsg)+1)*sizeof(TCHAR));
    _stprintf(completeMsg, _T("%s: %s\n"), method, originalMsg);
#ifdef _UNICODE
	(*env)->ReleaseStringChars(env, originalJavaMsg, originalMsg);
#else
	(*env)->ReleaseStringUTFChars(env, originalJavaMsg, originalMsg);
#endif

#ifdef _UNICODE
	if ((exceptionMsg = (*env)->NewString(env, completeMsg, (jsize)_tcslen(completeMsg))) == NULL) {
		return -1;
    }
#else
	if ((exceptionMsg = (*env)->NewStringUTF(env, completeMsg)) == NULL) {
		return -1;
    }
#endif

	(*env)->ExceptionClear(env);

    exceptionInstance = (*env)->NewObject(env, exceptionClass, constructorID, exceptionMsg);
    if (exceptionInstance == NULL)
	return -1;

	if ((*env)->Throw(env, (jthrowable)exceptionInstance))
	return -1;

    return 0;
}

/*
 * Throws an OPSPException with the return code of the OPSP library.
 * \param *env JNI interface pointer.
 * \param method The name of the method in which the exception is thrown.
 * \param errorCode the OPSP error code.
 * \return 0 for success, else -1.
 */
static int throwOPSPException(JNIEnv *env, OPSP_CSTRING method, LONG errorCode) {

    jstring     exceptionMsg;
    jclass      exceptionClass;
    jobject     exceptionInstance;
    jmethodID   constructorID;
	exceptionClass = (*env)->FindClass(env, "org/dyndns/widerstand/OpenPlatform/OPSPException");
	if (exceptionClass == NULL) { /* Unable to find the new exception class. */
		return -1;
	}
    constructorID = (*env)->GetMethodID(env, exceptionClass,
			    "<init>", "(Ljava/lang/String;I)V");
    if (constructorID == NULL)
	return -1;

#ifdef _UNICODE
    if ((exceptionMsg = (*env)->NewString(env, method, (jsize)_tcslen(method))) == NULL) {
		return -1;
    }
#else
    if ((exceptionMsg = (*env)->NewStringUTF(env, method)) == NULL) {
		return -1;
    }
#endif

    exceptionInstance = (*env)->NewObject(env, exceptionClass, constructorID, exceptionMsg, errorCode);
    if (exceptionInstance == NULL)
	return -1;

	if ((*env)->Throw(env, (jthrowable)exceptionInstance))
	return -1;

	return 0;
}
