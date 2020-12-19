/**
 *  Copyright (c) 2013, Snit Mo, Karsten Ohme
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
#ifdef WIN32
#include "stdafx.h"
#else
#include <stdlib.h>
#define _snprintf snprintf
#endif
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef WIN32
#include <sys/time.h>
#endif

#include <globalplatform/globalplatform.h>

#ifndef WIN32
#define _snprintf snprintf
#define _fgetts fgets
#define _tcscmp strcmp
#define _tcstok strtok
#define _stscanf sscanf
#define _tcsstr strstr
#define _tcschr strchr
#define _tstoi atoi
#define _tgetenv getenv
#define _tcsnccmp strncmp
#define _tcstol strtol
#endif

/* Constants */
#define BUFLEN 1024
#define FILENAMELEN 256
#define READERNAMELEN 256
#define AIDLEN 16
#define DATALEN 4096
#define INSTPARAMLEN 128
#define DELIMITER _T(" \t\r\n,")
#define KEY_LEN 32
#define PLATFORM_MODE_OP_201 OP_201
#define PLATFORM_MODE_GP_211 GP_211
#define PASSPHRASELEN 64
#define AUTOREADER -1

#define CHECK_TOKEN(token, option) token = parseToken(NULL);\
if (token == NULL)\
{\
    _tprintf(_T("Error: option %s not followed by data\n"), option);\
    rv = EXIT_FAILURE;\
    goto end;\
}

/* Data Structures */
typedef struct _OptionStr
{
    BYTE keyIndex;
    BYTE keySetVersion;
    BYTE newKeySetVersion;
    BYTE key[KEY_LEN];
    BYTE mac_key[KEY_LEN];
    BYTE enc_key[KEY_LEN];
    BYTE kek_key[KEY_LEN];
    BYTE securityLevel;
    BYTE keyLength;
    BYTE AID[AIDLEN+1];
    DWORD AIDLen;
    BYTE sdAID[AIDLEN+1];
    DWORD sdAIDLen;
    BYTE pkgAID[AIDLEN+1];
    DWORD pkgAIDLen;
    BYTE instAID[AIDLEN+1];
    DWORD instAIDLen;
    BYTE APDU[APDU_COMMAND_LEN+1];
    DWORD APDULen;
    BYTE secureChannel;
    TCHAR reader[READERNAMELEN+1];
    DWORD readerNumber;
    DWORD protocol;
    DWORD nvCodeLimit;
    DWORD nvDataLimit;
    DWORD vDataLimit;
    TCHAR file[FILENAMELEN+1];
    char passPhrase[PASSPHRASELEN+1];
    BYTE instParam[INSTPARAMLEN+1];
    DWORD instParamLen;
    BYTE element; //!< GET STATUS element (application, security domains, executable load files) to get
    BYTE format; //!< GET STATUS format
	BYTE dataFormat; //!< data format of STORE DATA
	BYTE responseDataExpected; //!< 1 if STORE DATA expects response data.
    BYTE keyTemplate; //!< The key template index to return.
    BYTE privilege;
    BYTE scp;
    BYTE scpImpl;
    BYTE identifier[2];
    BYTE keyDerivation;
	BYTE dataEncryption; //!< STORE DATA encryption flag
	BYTE data[DATALEN+1];
	DWORD dataLen;
	BYTE noStop; //!< Does not stop in case of an error.
} OptionStr;

/* Global Variables */
static OPGP_CARD_CONTEXT cardContext;
static OPGP_CARD_INFO cardInfo;
static OP201_SECURITY_INFO securityInfo201;
static GP211_SECURITY_INFO securityInfo211;
static int gemXpressoPro = 0;
static int platform_mode = OP_201;
static int timer = 0;
static BYTE selectedAID[AIDLEN+1];
static DWORD selectedAIDLength = 0;
static BYTE scp = 0;
static BYTE scpImpl = 0;

static unsigned int GetTime()
{
#if WIN32
    return GetTickCount();
#else
    struct timeval t;
    gettimeofday(&t, NULL);
    return (t.tv_sec*1000) + (t.tv_usec/1000);
#endif
}

LPCTSTR EMPTY_STRING = _T("");

typedef struct {
	TCHAR privilege[32];
} PRIVILEGES_STRING;

/* Functions */
static void convertTCharToChar(char* pszDest, const TCHAR* pszSrc)
{
    unsigned int i;

    for (i = 0; i < _tcslen(pszSrc); i++)
        pszDest[i] = (char) pszSrc[i];

    pszDest[_tcslen(pszSrc)] = '\0';
}

static int convertStringToByteArray(TCHAR *src, int destLength, BYTE *dest)
{
    TCHAR *dummy;
    unsigned int temp, i = 0;
	dummy = malloc(destLength*2*sizeof(TCHAR) + sizeof(TCHAR));
    _tcsncpy(dummy, src, destLength*2+1);
    dummy[destLength*2] = _T('\0');
    while (_stscanf(&(dummy[i*2]), _T("%02x"), &temp) > 0)
    {
        dest[i] = (BYTE)temp;
        i++;
    }
	free(dummy);
    return i;
}

static void convertByteArrayToString(BYTE *src, int srcLength, int destLength, TCHAR *dest)
{
	int j;
	dest[destLength-1] =  _T('\0');
	for (j=0; j<srcLength && j*2 < destLength-1 ; j++)
	{
		// use 3 to have space for null terminator
		_sntprintf(dest+j*2, 3, _T("%02x"), src[j]);
	}
	// if string is empty add null terminator
	if (destLength-1 > j*2) {
		dest[j*2] =  _T('\0');
	}
}

// You must free the result if result is non-NULL.
TCHAR * strReplace(TCHAR *orig, TCHAR *rep, TCHAR *with) {
	TCHAR *result; // the return string
	TCHAR *ins;    // the next insert point
	TCHAR *tmp;    // varies
    int len_rep;  // length of rep (the string to remove)
    int len_with; // length of with (the string to replace rep with)
    int len_front; // distance between rep and end of last rep
    int count;    // number of replacements

    // sanity checks and initialization
    if (!orig || !rep)
        return NULL;
    len_rep = _tcslen(rep);
    if (len_rep == 0)
        return NULL; // empty rep causes infinite loop during count
    if (!with) {
        with = "";
    }
    len_with = _tcslen(with);

    // count the number of replacements needed
    ins = orig;
    for (count = 0; (tmp = _tcsstr(ins, rep)); ++count) {
        ins = tmp + len_rep;
    }

    tmp = result = malloc(_tcslen(orig) + (len_with - len_rep) * count + 1);

    if (!result) {
        return NULL;
    }

    // first time through the loop, all the variable are set correctly
    // from here on,
    //    tmp points to the end of the result string
    //    ins points to the next occurrence of rep in orig
    //    orig points to the remainder of orig after "end of rep"
    while (count--) {
        ins = _tcsstr(orig, rep);
        len_front = ins - orig;
        tmp = _tcsncpy(tmp, orig, len_front) + len_front;
        tmp = _tcscpy(tmp, with) + len_with;
        orig += len_front + len_rep; // move to next "end of rep"
    }
    _tcscpy(tmp, orig);
    return result;
}


/**
 * Parses the next token.
 *
 * The tokens are separated by a whitespace.
 * Comments starting with // or # are recognized and <code>NULL</code> is returned.
 * This function also handles quoted strings and parses them correctly ignoring contained whitespace here (but the string cannot contain itself a quote).
 * Environment variables are processed using the syntax ${VAR}. No support for escaping ${ is supported.
 * \param *buf [IN] The input buffer containing the token.
 * \return the found token. <code>NULL</code> if none is found.
 */
static TCHAR *parseToken(TCHAR *buf)
{
    TCHAR *token;
    static TCHAR dummy[BUFLEN];
    int avail = BUFLEN;
    int size = 0, read = 0;

    token = _tcstok(buf, DELIMITER);

    if (token == NULL || _tcslen(token) == 0) {
        return NULL;
    }

    /* Check for quoted string */
    if (token[0] == _T('"'))
    {
        size = _sntprintf(dummy, avail, _T("%s"), token + 1);
        avail -= size;
        read += size;
        token = _tcstok(buf, _T("\""));
        if (token == NULL) {
            return NULL;
        }
        if (size > 0)
        {
            _sntprintf(dummy+read, avail, _T(" %s"), token);
        }
        dummy[BUFLEN-1] = _T('\0');
        token = dummy;
    }
    else if (_tcscmp(token, _T("//")) == 0 || _tcscmp(token, _T("#")) == 0)
    {
        return NULL;
    }
	 /* Check for env variable */
    TCHAR * envVarStart = NULL;
    TCHAR * replace = NULL;
    TCHAR * currentPos = token;
	while ((envVarStart = _tcsstr(currentPos, _T("${"))) != NULL)
	{
		TCHAR * envVarEnd = NULL;
		if ((envVarEnd = _tcschr(envVarStart, _T('}'))) != NULL) {
			TCHAR * envString = NULL;
			TCHAR * envVar = NULL;
			// minus }
			int endPosVar = (int)((envVarEnd - envVarStart + 1)/sizeof(TCHAR));
			// get env string + null terminator
			envString = malloc(sizeof(TCHAR)* endPosVar - 3 + 1);
			_tcsncpy(envString, envVarStart+2, endPosVar - 3);
			envString[endPosVar - 3] = _T('\0');
			// replace var
			if ((envVar = _tgetenv(envString)) != NULL) {
				TCHAR * newToken = NULL;
				replace = malloc(endPosVar + 1);
				replace[endPosVar] = _T('\0');
				_tcsncpy(replace, envVarStart, endPosVar);
				newToken = strReplace(token, replace, envVar);
				if (newToken) {
					_tcsncpy(dummy, newToken, BUFLEN);
					dummy[BUFLEN-1] = _T('\0');
					free(newToken);
					token = dummy;
				}
				free(replace);
			}
			free(envString);
		}
		else {
			// unclosed var
			return NULL;
		}
		// increment to prevent endless loop if not env var is found
		currentPos += 2;
    }
	return token;
}

static void displayCardRecognitionData(GP211_CARD_RECOGNITION_DATA cardData) {
	DWORD i=0;
	TCHAR temp[128];
	if (cardData.version > 0) {
		_tprintf(_T("Version: %04x\n"), (unsigned int)cardData.version);
	}
	for (i=0; i<cardData.scpLength; i++) {
		_tprintf(_T("SCP: %d SCP Impl: %02x\n"), cardData.scp[i], cardData.scpImpl[i]);
	}
	if (cardData.cardChipDetailsLength > 0) {
		convertByteArrayToString(cardData.cardChipDetails, cardData.cardChipDetailsLength, sizeof(temp)/sizeof(TCHAR), temp);
		_tprintf(_T("Card Chip Details: %s\n"), temp);
	}
	if (cardData.cardConfigurationDetailsLength > 0) {
		convertByteArrayToString(cardData.cardConfigurationDetails, cardData.cardConfigurationDetailsLength, sizeof(temp)/sizeof(TCHAR), temp);
		_tprintf(_T("Card Configuration Details: %s\n"), temp);
	}
	if (cardData.issuerSecurityDomainsTrustPointCertificateInformationLength > 0) {
		convertByteArrayToString(cardData.issuerSecurityDomainsTrustPointCertificateInformation,
				cardData.issuerSecurityDomainsTrustPointCertificateInformationLength, sizeof(temp)/sizeof(TCHAR), temp);
		_tprintf(_T("Issuer Security Domains Trust Point Certificate Information: %s\n"), temp);
	}
	if (cardData.issuerSecurityDomainCertificateInformationLength > 0) {
		convertByteArrayToString(cardData.issuerSecurityDomainCertificateInformation, cardData.issuerSecurityDomainCertificateInformationLength, sizeof(temp)/sizeof(TCHAR), temp);
		_tprintf(_T("Issuer Security Domain Certificate Information: %s\n"), temp);
	}
}

static LPTSTR lifeCycleToString(BYTE lifeCycle, BYTE element) {
	LPCTSTR lcLoaded = _T("Loaded");
	LPCTSTR lcInstalled = _T("Installed");
	LPCTSTR lcSelectable = _T("Selectable");
	LPCTSTR lcLocked = _T("Locked");
	LPCTSTR lcPersonalized = _T("Personalized");
	LPCTSTR lcOpReady = _T("OP Ready");
	LPCTSTR lcInitialized = _T("Initialized");
	LPCTSTR lcSecured = _T("Secured");
	LPCTSTR lcCardLocked = _T("Card Locked");
	LPCTSTR lcTerminated = _T("Terminated");

	static LPTSTR lifeCycleState;

	switch (element) {
		case GP211_STATUS_LOAD_FILES:
		case GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES:
			if ((lifeCycle & GP211_LIFE_CYCLE_LOAD_FILE_LOADED) == GP211_LIFE_CYCLE_LOAD_FILE_LOADED) {
				lifeCycleState = (LPTSTR)lcLoaded;
			}
			break;
		case GP211_STATUS_APPLICATIONS:
			if ((lifeCycle & GP211_LIFE_CYCLE_APPLICATION_INSTALLED) == GP211_LIFE_CYCLE_APPLICATION_INSTALLED) {
				lifeCycleState = (LPTSTR)lcInstalled;
			}
			if ((lifeCycle & GP211_LIFE_CYCLE_APPLICATION_SELECTABLE) == GP211_LIFE_CYCLE_APPLICATION_SELECTABLE) {
				lifeCycleState = (LPTSTR)lcSelectable;
			}
			if ((lifeCycle & GP211_LIFE_CYCLE_SECURITY_DOMAIN_PERSONALIZED)  == GP211_LIFE_CYCLE_SECURITY_DOMAIN_PERSONALIZED) {
				lifeCycleState = (LPTSTR)lcPersonalized;
			}
			if ((lifeCycle & GP211_LIFE_CYCLE_APPLICATION_LOCKED) == GP211_LIFE_CYCLE_APPLICATION_LOCKED) {
				lifeCycleState = (LPTSTR)lcLocked;
			}
			break;
		case GP211_STATUS_ISSUER_SECURITY_DOMAIN:
			if ((lifeCycle & GP211_LIFE_CYCLE_CARD_OP_READY) == GP211_LIFE_CYCLE_CARD_OP_READY) {
				lifeCycleState = (LPTSTR)lcOpReady;
			}
			if ((lifeCycle & GP211_LIFE_CYCLE_CARD_INITIALIZED) == GP211_LIFE_CYCLE_CARD_INITIALIZED) {
				lifeCycleState = (LPTSTR)lcInitialized;
			}
			if ((lifeCycle & GP211_LIFE_CYCLE_CARD_SECURED)  == GP211_LIFE_CYCLE_CARD_SECURED) {
				lifeCycleState = (LPTSTR)lcSecured;
			}
			if ((lifeCycle & GP211_LIFE_CYCLE_CARD_LOCKED) == GP211_LIFE_CYCLE_CARD_LOCKED) {
				lifeCycleState = (LPTSTR)lcCardLocked;
			}
			if ((lifeCycle & GP211_LIFE_CYCLE_CARD_TERMINATED) == GP211_LIFE_CYCLE_CARD_TERMINATED) {
				lifeCycleState = (LPTSTR)lcTerminated;
			}
			break;
	}

	return lifeCycleState;
}

static void privilegesToString(DWORD privileges, PRIVILEGES_STRING privilegesStrings[20]) {
	int i;
	LPCTSTR lcSd = _T("Security Domain");
	LPCTSTR lcDapVerfification = _T("DAP Verification");
	LPCTSTR lcDelegatedManagement = _T("Delegated Management");
	LPCTSTR lcCardLock = _T("Card Lock");
	LPCTSTR lcCardTerminate = _T("Card Terminate");
	LPCTSTR lcCardReset = _T("Default Selected / Card Reset");
	LPCTSTR lcCVMManagement = _T("CVM Management");
	LPCTSTR lcMandatedDapVerification = _T("Mandated DAP Verification");
	LPCTSTR lcTrustedPath = _T("Trusted Path");
	LPCTSTR lcAuthManagement = _T("Authorized Management");
	LPCTSTR lcTokenManagement = _T("Token Management");
	LPCTSTR lcGlobalDelete = _T("Global Delete");
	LPCTSTR lcGlobalLock = _T("Global Lock");
	LPCTSTR lcGlobalRegistry = _T("Global Registry");
	LPCTSTR lcFinalApplication = _T("Final Application");
	LPCTSTR lcGlobalService = _T("Global Service");

	LPCTSTR lcReceiptGeneration = _T("Receipt Generation");
	LPCTSTR lcCipheredLoadFileDataBlock = _T("Ciphered Load File Data Block");
	LPCTSTR lcContactlessActivation = _T("Contactless Activation");
	LPCTSTR lcContactlessSelfActivation = _T("Contactless Self-Activation");
	// null all
	for (i = 0; i<20; i++) {
		_tcscpy(privilegesStrings[i].privilege, EMPTY_STRING);
	}
	i=0;
	if ((privileges & GP211_SECURITY_DOMAIN) == GP211_SECURITY_DOMAIN) {
		_tcscpy(privilegesStrings[i++].privilege, lcSd);
	}
	if ((privileges & GP211_DAP_VERIFICATION) == GP211_DAP_VERIFICATION) {
		_tcscpy(privilegesStrings[i++].privilege, lcDapVerfification);
	}
	if ((privileges & GP211_DELEGATED_MANAGEMENT) == GP211_DELEGATED_MANAGEMENT) {
		_tcscpy(privilegesStrings[i++].privilege, lcDelegatedManagement);
	}
	if ((privileges & GP211_CARD_MANAGER_LOCK_PRIVILEGE) == GP211_CARD_MANAGER_LOCK_PRIVILEGE) {
		_tcscpy(privilegesStrings[i++].privilege, lcCardLock);
	}
	if ((privileges & GP211_CARD_MANAGER_TERMINATE_PRIVILEGE) == GP211_CARD_MANAGER_TERMINATE_PRIVILEGE) {
		_tcscpy(privilegesStrings[i++].privilege, lcCardTerminate);
	}
	if ((privileges & GP211_DEFAULT_SELECTED_CARD_RESET_PRIVILEGE) == GP211_DEFAULT_SELECTED_CARD_RESET_PRIVILEGE) {
		_tcscpy(privilegesStrings[i++].privilege, lcCardReset);
	}
	if ((privileges & GP211_PIN_CHANGE_PRIVILEGE) == GP211_PIN_CHANGE_PRIVILEGE) {
		_tcscpy(privilegesStrings[i++].privilege, lcCVMManagement);
	}
	if ((privileges & GP211_MANDATED_DAP_VERIFICATION) == GP211_MANDATED_DAP_VERIFICATION) {
		_tcscpy(privilegesStrings[i++].privilege, lcMandatedDapVerification);
	}
	if ((privileges & GP211_TRUSTED_PATH) == GP211_TRUSTED_PATH) {
		_tcscpy(privilegesStrings[i++].privilege, lcTrustedPath);
	}
	if ((privileges & GP211_AUTHORIZED_MANAGEMENT) == GP211_AUTHORIZED_MANAGEMENT) {
		_tcscpy(privilegesStrings[i++].privilege, lcAuthManagement);
	}
	if ((privileges & GP211_TOKEN_VERIFICATION) == GP211_TOKEN_VERIFICATION) {
		_tcscpy(privilegesStrings[i++].privilege, lcTokenManagement);
	}
	if ((privileges & GP211_GLOBAL_DELETE) == GP211_GLOBAL_DELETE) {
		_tcscpy(privilegesStrings[i++].privilege, lcGlobalDelete);
	}
	if ((privileges & GP211_GLOBAL_LOCK) == GP211_GLOBAL_LOCK) {
		_tcscpy(privilegesStrings[i++].privilege, lcGlobalLock);
	}
	if ((privileges & GP211_GLOBAL_REGISTRY) == GP211_GLOBAL_REGISTRY) {
		_tcscpy(privilegesStrings[i++].privilege, lcGlobalRegistry);
	}
	if ((privileges & GP211_GLOBAL_SERVICE) == GP211_GLOBAL_SERVICE) {
		_tcscpy(privilegesStrings[i++].privilege, lcGlobalService);
	}
	if ((privileges & GP211_FINAL_APPLICATION) == GP211_FINAL_APPLICATION) {
		_tcscpy(privilegesStrings[i++].privilege, lcFinalApplication);
	}
	if ((privileges & GP211_RECEIPT_GENERATION) == GP211_RECEIPT_GENERATION) {
		_tcscpy(privilegesStrings[i++].privilege, lcReceiptGeneration);
	}
	if ((privileges & GP211_CIPHERED_LOAD_FILE_DATA_BLOCK) == GP211_CIPHERED_LOAD_FILE_DATA_BLOCK) {
		_tcscpy(privilegesStrings[i++].privilege, lcCipheredLoadFileDataBlock);
	}
	if ((privileges & GP211_CONTACTLESS_ACTIVATION) == GP211_CONTACTLESS_ACTIVATION) {
		_tcscpy(privilegesStrings[i++].privilege, lcContactlessActivation);
	}
	if ((privileges & GP211_CONTACTLESS_SELF_ACTIVATION) == GP211_CONTACTLESS_SELF_ACTIVATION) {
		_tcscpy(privilegesStrings[i++].privilege, lcContactlessSelfActivation);
	}
}

static void displayLoadFilesAndModulesGp211(GP211_EXECUTABLE_MODULES_DATA *executables, int count) {
	LPCTSTR format;
	TCHAR aidStr[33];
	TCHAR moduleAidStr[33];
	TCHAR sdAidStr[33];
	TCHAR versionStr[5];
	LPTSTR lifeCycleState;
	int i,j;
	format = _T("%-32s | %-12s | %-7s | %-32s | %-32s\n");
	_tprintf(format, _T("Load File AID"), _T("State"), _T("Version"), _T("Module AID"), _T("Linked Security Domain"));
	for (i=0; i<count; i++) {
		_tprintf(format, _T("--"), _T("--"), _T("--"), _T("--"), _T("--"));
		convertByteArrayToString(executables[i].aid.AID, executables[i].aid.AIDLength, sizeof(aidStr)/sizeof(TCHAR), aidStr);
		convertByteArrayToString(executables[i].associatedSecurityDomainAID.AID, executables[i].associatedSecurityDomainAID.AIDLength, sizeof(sdAidStr) / sizeof(TCHAR), sdAidStr);
		convertByteArrayToString(executables[i].versionNumber, sizeof(executables[i].versionNumber), sizeof(versionStr) / sizeof(TCHAR), versionStr);
		lifeCycleState = lifeCycleToString(executables[i].lifeCycleState, GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES);
		_tprintf(format, aidStr, lifeCycleState, versionStr, EMPTY_STRING, sdAidStr);
		_tprintf(format, aidStr, lifeCycleState, versionStr, EMPTY_STRING, EMPTY_STRING);
		for (j=0; j<executables[i].numExecutableModules; j++) {
			convertByteArrayToString(executables[i].executableModules[j].AID, executables[i].executableModules[j].AIDLength, sizeof(moduleAidStr) / sizeof(TCHAR), moduleAidStr);
			_tprintf(format, EMPTY_STRING, EMPTY_STRING, EMPTY_STRING, moduleAidStr, EMPTY_STRING);
		}
	}
}

static void displayLoadApplicationsGp211(GP211_APPLICATION_DATA *applications, int count, BYTE element) {
	LPCTSTR format;
	TCHAR aidStr[33];
	TCHAR sdAidStr[33];
	TCHAR versionStr[5];
	LPTSTR lifeCycleState;
	PRIVILEGES_STRING privileges[20];
	int i,j;
	format = _T("%-32s | %-12s | %-30s | %-7s | %-32s\n");
	_tprintf(format, _T("AID"), _T("State"), _T("Privileges"), _T("Version"), _T("Linked Security Domain"));
	for (i=0; i<count; i++) {
		_tprintf(format, _T("--"), _T("--"), _T("--"), _T("--"), _T("--"));
		convertByteArrayToString(applications[i].aid.AID, applications[i].aid.AIDLength, sizeof(aidStr) / sizeof(TCHAR), aidStr);
		convertByteArrayToString(applications[i].associatedSecurityDomainAID.AID, applications[i].associatedSecurityDomainAID.AIDLength, sizeof(sdAidStr) / sizeof(TCHAR), sdAidStr);
		convertByteArrayToString(applications[i].versionNumber, sizeof(applications[i].versionNumber), sizeof(versionStr) / sizeof(TCHAR), versionStr);
		lifeCycleState = lifeCycleToString(applications[i].lifeCycleState, element);
		_tprintf(format, aidStr, lifeCycleState, EMPTY_STRING, versionStr, sdAidStr);
		privilegesToString(applications[i].privileges, privileges);
		for (j=0; j<20; j++) {
			if (_tcslen(privileges[j].privilege) > 0) {
				_tprintf(format, EMPTY_STRING, EMPTY_STRING, privileges[j].privilege, EMPTY_STRING, EMPTY_STRING);
			}
		}
	}
}

static void displayApplicationsOp201(OP201_APPLICATION_DATA *applications, int count, BYTE element) {
	LPCTSTR format;
	TCHAR aidStr[33];
	LPTSTR lifeCycleState;
	PRIVILEGES_STRING privileges[20];
	int i,j;
	format = _T("%-32s | %-12s | %-30s\n");
	_tprintf(format, _T("AID"), _T("State"), _T("Privileges"));
	for (i=0; i<count; i++) {
		_tprintf(format, _T("--"), _T("--"), _T("--"));
		convertByteArrayToString(applications[i].aid.AID, applications[i].aid.AIDLength, sizeof(aidStr) / sizeof(TCHAR), aidStr);
		lifeCycleState = lifeCycleToString(applications[i].lifeCycleState, element);
		_tprintf(format, aidStr, lifeCycleState, EMPTY_STRING);
		privilegesToString(applications[i].privileges << 16, privileges);
		for (j=0; j<20; j++) {
			if (_tcslen(privileges[j].privilege) > 0) {
				_tprintf(format, EMPTY_STRING, EMPTY_STRING, privileges[j].privilege, EMPTY_STRING, EMPTY_STRING);
			}
		}
	}
}

static void displayExtCardResorcesInfo(OPGP_EXTENDED_CARD_RESOURCE_INFORMATION extCardResorcesInfo) {
	LPCTSTR format1, format2;
	format1 = _T("%-16s | %-21s | %-17s \n");
	_tprintf(format1, _T("Num Applications"), _T("Free non volatile mem"), _T("Free volatile mem"));
	format2 = _T("%-16d | %-21d | %-17d \n");
	_tprintf(format1, _T("--"), _T("--"), _T("--"));
	_tprintf(format2, extCardResorcesInfo.numInstalledApplications, extCardResorcesInfo.freeNonVolatileMemory,
			extCardResorcesInfo.freeVolatileMemory);
}

static void displayGpKeyInformation(GP211_KEY_INFORMATION *keyInformation, int count) {
	LPCTSTR format1, format2;
	int i;
	format1 = _T("%-3s | %-7s | %-6s | %-6s | %-5s | %-6s \n");
	_tprintf(format1, _T("ID"), _T("Version"), _T("Type"), _T("Length"), _T("Usage"), _T("Access"));
	format2 = _T("%-3d | %-7d | %-6.2x | %-6d | %-5.2x | %-6.2x \n");
	for (i=0; i<count; i++) {
		_tprintf(format1, _T("--"), _T("--"), _T("--"), _T("--"), _T("--"), _T("--"));
		_tprintf(format2, keyInformation[i].keyIndex, keyInformation[i].keySetVersion,
				keyInformation[i].keyType, keyInformation[i].keyLength,
				keyInformation[i].keyUsage, keyInformation[i].keyAccess);
	}
}

static void displayOpKeyInformation(OP201_KEY_INFORMATION *keyInformation, int count) {
	LPCTSTR format;
	int i;
	format = _T("%-3d | %-7d | %-4.2x | %-6%d \n");
	_tprintf(format, _T("ID"), _T("Version"), _T("Type"), _T("Length"));
	for (i=0; i<count; i++) {
		_tprintf(format, _T("--"), _T("--"), _T("--"), _T("--"));
		_tprintf(format, keyInformation[i].keyIndex, keyInformation[i].keySetVersion, keyInformation[i].keyType, keyInformation[i].keyLength);
	}
}

static int handleOptions(OptionStr *pOptionStr)
{
    int rv = EXIT_SUCCESS;
    TCHAR *token;

    //handle default for delete_key
    pOptionStr->keyIndex = pOptionStr->keyIndex != 0xFF ? 0 : 0xFF;
    pOptionStr->keySetVersion = 0;
    pOptionStr->newKeySetVersion = 0;
    pOptionStr->securityLevel = 0;
    pOptionStr->AIDLen = 0;
    pOptionStr->sdAIDLen = 0;
    pOptionStr->pkgAIDLen = 0;
    pOptionStr->instAIDLen = 0;
    pOptionStr->APDULen = 0;
    pOptionStr->secureChannel = 0;
    pOptionStr->reader[0] = _T('\0');
    pOptionStr->readerNumber = AUTOREADER;
    pOptionStr->file[0] = _T('\0');
    pOptionStr->passPhrase[0] = _T('\0');
    pOptionStr->protocol = OPGP_CARD_PROTOCOL_T0 | OPGP_CARD_PROTOCOL_T1;
    pOptionStr->nvCodeLimit = 0;
    pOptionStr->nvDataLimit = 0;
    pOptionStr->vDataLimit = 0;
    pOptionStr->instParam[0] = '\0';
    pOptionStr->instParamLen = 0;
    pOptionStr->element = 0;
    pOptionStr->format = 2;
    pOptionStr->privilege = 0;
    pOptionStr->scp = scp;
    pOptionStr->scpImpl = scpImpl;
	pOptionStr->identifier[0] = 0;
	pOptionStr->identifier[1] = 0;
	pOptionStr->keyDerivation = OPGP_DERIVATION_METHOD_NONE;
	pOptionStr->keyTemplate = 0;
	pOptionStr->dataFormat = 2;
	pOptionStr->dataLen = 0;
	pOptionStr->data[0] = '\0';
	pOptionStr->dataEncryption = 0;
	pOptionStr->responseDataExpected = 0;
	pOptionStr->noStop = 0;
	// use by default 3DES / AES-128 keys
	pOptionStr->keyLength = 16;

    token = parseToken(NULL);

    while (token != NULL)
    {
        if (_tcscmp(token, _T("-identifier")) == 0)
        {
        	CHECK_TOKEN(token, _T("-identifier"));
			BYTE temp;
			convertStringToByteArray(token, 2, pOptionStr->identifier);
			if (_tcslen(token) == 2) {
				temp = pOptionStr->identifier[0];
				pOptionStr->identifier[0] = pOptionStr->identifier[1];
				pOptionStr->identifier[1] = temp;
			}
        }
        else if (_tcscmp(token, _T("-keyTemplate")) == 0)
		{
			CHECK_TOKEN(token, _T("-keyTemplate"));
			pOptionStr->keyTemplate = _tstoi(token);
		}
        else if (_tcscmp(token, _T("-noStop")) == 0)
		{
			pOptionStr->noStop = 1;
		}
        else if (_tcscmp(token, _T("-keyind")) == 0)
        {
        	CHECK_TOKEN(token, _T("-keyind"));
            pOptionStr->keyIndex = _tstoi(token);
        }
        else if (_tcscmp(token, _T("-keyver")) == 0)
        {
        	CHECK_TOKEN(token, _T("-keyver"));
            pOptionStr->keySetVersion = _tstoi(token);
        }
        else if (_tcscmp(token, _T("-newkeyver")) == 0)
        {
        	CHECK_TOKEN(token, _T("-newkeyver"));
            pOptionStr->newKeySetVersion = _tstoi(token);
        }
        else if (_tcscmp(token, _T("-sc")) == 0)
        {
        	int sc;
        	CHECK_TOKEN(token, _T("-sc"));
        	sc = _tstoi(token);
			if (sc == 0) {
				pOptionStr->secureChannel = 0;
			}
			else if (sc == 1) {
				pOptionStr->secureChannel = 1;
			}
			else
			{
				_tprintf(_T("Error: option -sc not followed 0 (secure channel off) or 1 (secure channel on)\n"));
				rv = EXIT_FAILURE;
				goto end;
			}
        }
        else if (_tcscmp(token, _T("-security")) == 0)
        {
        	CHECK_TOKEN(token, _T("-security"));
        	pOptionStr->securityLevel = _tstoi(token);
        }
        else if (_tcscmp(token, _T("-readerNumber")) == 0)
        {
        	CHECK_TOKEN(token, _T("-readerNumber"));
        	int readerNumber = _tstoi(token)-1;
			if (readerNumber < 0)
			{
				_tprintf(_T("Error: option -readerNumber must be followed by number > 0\n"));
				rv = EXIT_FAILURE;
				goto end;
			}
			pOptionStr->readerNumber = readerNumber;
        }
        else if (_tcscmp(token, _T("-reader")) == 0)
        {
        	CHECK_TOKEN(token, _T("-reader"));
            _tcsncpy(pOptionStr->reader, token, READERNAMELEN);
#ifdef DEBUG
            _tprintf ( _T("reader name %s\n"), pOptionStr->reader);
#endif
        }
        else if (_tcscmp(token, _T("-file")) == 0)
        {
        	CHECK_TOKEN(token, _T("-file"));
            _tcsncpy(pOptionStr->file, token, FILENAMELEN);
#ifdef DEBUG
            _tprintf ( _T("file name %s\n"), pOptionStr->file);
#endif
        }
        else if (_tcscmp(token, _T("-pass")) == 0)
        {
        	CHECK_TOKEN(token, _T("-pass"));
            convertTCharToChar(pOptionStr->passPhrase, token);
            pOptionStr->passPhrase[PASSPHRASELEN] = '\0';
        }
        else if (_tcscmp(token, _T("-key")) == 0)
        {
        	CHECK_TOKEN(token, _T("-key"));
        	pOptionStr->keyLength = convertStringToByteArray(token, KEY_LEN, pOptionStr->key);
        }
        else if (_tcscmp(token, _T("-mac_key")) == 0)
        {
        	CHECK_TOKEN(token, _T("-mac_key"));
        	pOptionStr->keyLength = convertStringToByteArray(token, KEY_LEN, pOptionStr->mac_key);
        }
        else if (_tcscmp(token, _T("-enc_key")) == 0)
        {
        	CHECK_TOKEN(token, _T("-enc_key"));
        	pOptionStr->keyLength = convertStringToByteArray(token, KEY_LEN, pOptionStr->enc_key);
        }
        else if (_tcscmp(token, _T("-kek_key")) == 0)
        {
        	CHECK_TOKEN(token, _T("-kek_key"));
        	pOptionStr->keyLength = convertStringToByteArray(token, KEY_LEN, pOptionStr->kek_key);
        }
        else if (_tcscmp(token, _T("-AID")) == 0)
        {
        	CHECK_TOKEN(token, _T("-AID"));
            pOptionStr->AIDLen = convertStringToByteArray(token, AIDLEN, pOptionStr->AID);
        }
        else if (_tcscmp(token, _T("-sdAID")) == 0)
        {
        	CHECK_TOKEN(token, _T("-sdAID"));
            pOptionStr->sdAIDLen = convertStringToByteArray(token, AIDLEN, pOptionStr->sdAID);
        }
        else if (_tcscmp(token, _T("-pkgAID")) == 0)
        {
        	CHECK_TOKEN(token, _T("-pkgAID"));
            pOptionStr->pkgAIDLen = convertStringToByteArray(token, AIDLEN, pOptionStr->pkgAID);
        }
        else if (_tcscmp(token, _T("-instAID")) == 0)
        {
        	CHECK_TOKEN(token, _T("-instAID"));
            pOptionStr->instAIDLen = convertStringToByteArray(token, AIDLEN, pOptionStr->instAID);
        }
        else if (_tcscmp(token, _T("-APDU")) == 0)
        {
        	CHECK_TOKEN(token, _T("-APDU"));
            pOptionStr->APDULen = convertStringToByteArray(token, APDU_COMMAND_LEN, pOptionStr->APDU);
        }
        else if (_tcscmp(token, _T("-protocol")) == 0)
        {
        	DWORD protocol;
        	CHECK_TOKEN(token, _T("-protocol"));
        	protocol = _tstoi(token);
			if (protocol == 0)
			{
				pOptionStr->protocol = OPGP_CARD_PROTOCOL_T0;
			}
			else if (protocol == 1)
			{
				pOptionStr->protocol = OPGP_CARD_PROTOCOL_T1;
			}
			else
			{
				_tprintf(_T("Unknown protocol type %s\n"), token);
				rv = EXIT_FAILURE;
				goto end;
			}
        }
        else if (_tcscmp(token, _T("-nvCodeLimit")) == 0)
        {
        	CHECK_TOKEN(token, _T("-nvCodeLimit"));
            pOptionStr->nvCodeLimit = _tstoi(token);
        }
        else if (_tcscmp(token, _T("-nvDataLimit")) == 0)
        {
        	CHECK_TOKEN(token, _T("-nvDataLimit"));
            pOptionStr->nvDataLimit = _tstoi(token);
        }
        else if (_tcscmp(token, _T("-vDataLimit")) == 0)
        {
        	CHECK_TOKEN(token, _T("-vDataLimit"));
            pOptionStr->vDataLimit = _tstoi(token);
        }
        else if (_tcscmp(token, _T("-instParam")) == 0)
        {
        	CHECK_TOKEN(token, _T("-instParam"));
            pOptionStr->instParamLen = convertStringToByteArray(token, INSTPARAMLEN, pOptionStr->instParam);
        }
        else if (_tcscmp(token, _T("-element")) == 0)
        {
            unsigned int element;
            CHECK_TOKEN(token, _T("-element"));
            if (_stscanf (token, _T("%02x"), &element) <= 0)
            {
                _tprintf(_T("Error: option -element followed by an illegal string %s\n"),
                        token);
                rv = EXIT_FAILURE;
                goto end;
            }
            pOptionStr->element = element;
        }
        else if (_tcscmp(token, _T("-format")) == 0)
		{
        	int format;
        	CHECK_TOKEN(token, _T("-format"));
        	format = _tstoi(token);
        	if (format != 0 && format != 2)
			{
				_tprintf(_T("Error: option -format followed by an unsupported format %s\n"), token);
				rv = EXIT_FAILURE;
				goto end;
			}
			pOptionStr->format = format;
		}
		else if (_tcscmp(token, _T("-dataFormat")) == 0)
		{
			int dataFormat;
			CHECK_TOKEN(token, _T("-dataFormat"));
			dataFormat = (int)_tcstol(token, NULL, 0);
			pOptionStr->dataFormat = dataFormat;
		}
		else if (_tcscmp(token, _T("-dataEncryption")) == 0)
		{
			int dataEncryption;
			CHECK_TOKEN(token, _T("-dataEncryption"));
			dataEncryption = (int)_tcstol(token, NULL, 0);
			pOptionStr->dataEncryption = dataEncryption;
		}
		else if (_tcscmp(token, _T("-responseDataExpected")) == 0)
		{
			int responseDataExpected;
			CHECK_TOKEN(token, _T("-responseDataExpected"));
			responseDataExpected = _tstoi(token);
			pOptionStr->responseDataExpected = responseDataExpected;
		}
		else if (_tcscmp(token, _T("-data")) == 0)
		{
			CHECK_TOKEN(token, _T("-data"));
			pOptionStr->dataLen = convertStringToByteArray(token, DATALEN, pOptionStr->data);
		}
        else if (_tcscmp(token, _T("-priv")) == 0)
        {
        	CHECK_TOKEN(token, _T("-priv"));
            pOptionStr->privilege = _tstoi(token);
        }
        else if (_tcscmp(token, _T("-scp")) == 0)
        {
        	CHECK_TOKEN(token, _T("-scp"));
            pOptionStr->scp = (int)_tcstol(token, NULL, 0);
        }
        else if (_tcscmp(token, _T("-scpimpl")) == 0)
        {
        	CHECK_TOKEN(token, _T("-scpimpl"));
            pOptionStr->scpImpl = (int)_tcstol(token, NULL, 0);
        }
        else if (_tcscmp(token, _T("-keyDerivation")) == 0)
        {
        	CHECK_TOKEN(token, _T("-keyDerivation"));
            if (_tcscmp(token, _T("none")) == 0) {
            	pOptionStr->keyDerivation = OPGP_DERIVATION_METHOD_NONE;
            }
            else if (_tcscmp(token, _T("visa2")) == 0) {
            	pOptionStr->keyDerivation = OPGP_DERIVATION_METHOD_VISA2;
            }
			else if (_tcscmp(token, _T("visa1")) == 0) {
            	pOptionStr->keyDerivation = OPGP_DERIVATION_METHOD_VISA1;
            }
            else if (_tcscmp(token, _T("emvcps11")) == 0) {
            	pOptionStr->keyDerivation = OPGP_DERIVATION_METHOD_EMV_CPS11;
            }
            else
            {
                _tprintf(_T("Error: Unknown key derivation method %s\n"), token);
                rv = EXIT_FAILURE;
                goto end;
            }
        }
        else
        {
            // unknown option
            _tprintf(_T("Error: unknown option %s\n"), token);
            rv = EXIT_FAILURE;
            goto end;
        }

        token = parseToken(NULL);
    }
end:
    return rv;
}

static int handleCommands(FILE *fd)
{
    TCHAR buf[BUFLEN + 1], commandLine[BUFLEN + 1];
    int rv = EXIT_SUCCESS;
    unsigned int it=0, ft=0;
    OPGP_ERROR_STATUS status;
    TCHAR *token;
    OptionStr optionStr;
    OPGP_ERROR_CREATE_NO_ERROR(status);

	memset(&optionStr, 0, sizeof(optionStr));
	nostop:
    while (_fgetts (buf, BUFLEN, fd) != NULL)
    {

        // copy command line for printing it out later
        _tcsncpy (commandLine, buf, BUFLEN);

        token = parseToken(buf);
        while (token != NULL)
        {
            if (token[0] == _T('#') || _tcsnccmp(token, _T("//"), 2) == 0)
                break;

            // get the initial time
            if (timer)
            {
                it = GetTime();
            }

            // print command line
            _tprintf(_T("%s"), commandLine);

            if (_tcscmp(token, _T("establish_context")) == 0)
            {
                // Establish context
                _tcsncpy(cardContext.libraryName, _T("gppcscconnectionplugin"),
                         _tcslen(_T("gppcscconnectionplugin"))+1);
                status = OPGP_establish_context(&cardContext);
                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("establish_context failed with error 0x%08X (%s)\n"), (unsigned int)status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
                goto timer;
            }
            else if (_tcscmp(token, _T("release_context")) == 0)
            {
                // Release context
                status = OPGP_release_context(&cardContext);
                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("release_context failed with error 0x%08X (%s)\n"), (unsigned int)status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
                goto timer;
            }
            else if (_tcscmp(token, _T("card_connect")) == 0)
            {
                DWORD readerStrLen = BUFLEN;
                int readerFound = 0;
                // open reader
                rv = handleOptions(&optionStr);
                if (rv != EXIT_SUCCESS)
                {
                    goto end;
                }
                if (_tcslen(optionStr.reader) == 0)
                {
                    int j=0;
                    int k=0;

                    // get all readers
                    status = OPGP_list_readers (cardContext, buf, &readerStrLen);
                    if (OPGP_ERROR_CHECK(status))
                    {
                        _tprintf(_T("list_readers failed with error 0x%08X (%s)\n"), (unsigned int)status.errorCode, status.errorMessage);
                        rv = EXIT_FAILURE;
                        goto end;
                    }

                    for (j=0; j<(int)readerStrLen;)
                    {
                        // Check for end of readers
                        if (buf[j] == _T('\0'))
                            break;
                        _tcsncpy(optionStr.reader, buf+j, READERNAMELEN);

#ifdef DEBUG
						_tprintf ( _T("* reader name %s\n"), optionStr.reader);
#endif
                        // if auto reader, connect now
                        if (optionStr.readerNumber == AUTOREADER)
                        {
                            status = OPGP_card_connect(cardContext, optionStr.reader, &cardInfo, optionStr.protocol);
                            readerFound = 1;
                            if (!OPGP_ERROR_CHECK(status))
                            {
                                break;
                            }
                        }
                        else if (k == optionStr.readerNumber)
                        {
                        	// connect the this reader number
                        	status = OPGP_card_connect (cardContext, optionStr.reader, &cardInfo, optionStr.protocol);
                        	readerFound = 1;
                            break;
                        }

                        k++;
                        j+=(int)_tcslen(buf+j)+1;
                    }
                    if (!readerFound) {
                    	_tprintf (_T("Could not connect to reader number %d\n"), (int)(optionStr.readerNumber+1));
						rv = EXIT_FAILURE;
						goto end;
                    }

                }
                else {
                    status = OPGP_card_connect (cardContext, optionStr.reader, &cardInfo, optionStr.protocol);
                }

                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("card_connect() returns 0x%08X (%s)\n"), (unsigned int)status.errorCode, status.errorMessage);
					rv = EXIT_FAILURE;
                    goto end;
                }
                // set mode for internal use of library
                cardInfo.specVersion = platform_mode;
                goto timer;
            }
			else if (_tcscmp(token, _T("get_secure_channel_protocol_details")) == 0)
			{
				// select instance
				rv = handleOptions(&optionStr);
				if (rv != EXIT_SUCCESS)
				{
					goto end;
				}
				status = GP211_get_secure_channel_protocol_details(cardContext, cardInfo,
					&scp,
					&scpImpl);
				if (OPGP_ERROR_CHECK(status))
				{
					_tprintf(_T("get_secure_channel_protocol_details() returns 0x%08X (%s)\n"),
						(unsigned int)status.errorCode, status.errorMessage);
					rv = EXIT_FAILURE;
					goto end;
				}
				_tprintf(_T("SCP: 0x%02x\n"), scp);
				_tprintf(_T("SCP Impl: 0x%02x\n"), scpImpl);
				goto timer;
			}
            else if (_tcscmp(token, _T("open_sc")) == 0)
            {
                // open secure channel
                rv = handleOptions(&optionStr);
                if (rv != EXIT_SUCCESS)
                {
                    goto end;
                }
                if (gemXpressoPro) {
                        optionStr.keyDerivation = OPGP_DERIVATION_METHOD_VISA2;
                }
                if (platform_mode == PLATFORM_MODE_OP_201)
                {
                    status = OP201_mutual_authentication(cardContext, cardInfo,
                                                     optionStr.key,
                                                     optionStr.enc_key,
                                                     optionStr.mac_key,
                                                     optionStr.kek_key,
                                                     optionStr.keySetVersion,
                                                     optionStr.keyIndex,
                                                     optionStr.securityLevel,
                                                     optionStr.keyDerivation,
                                                     &securityInfo201);
                }
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
                    if (optionStr.scp == 0 || optionStr.scpImpl == 0)
                    {
                        status = GP211_get_secure_channel_protocol_details(cardContext, cardInfo,
                                &optionStr.scp,
                                &optionStr.scpImpl);
                        if (OPGP_ERROR_CHECK(status))
                        {
                            _tprintf (_T("get_secure_channel_protocol_details() returns 0x%08X (%s)\n"),
                                      (unsigned int)status.errorCode, status.errorMessage);
                            rv = EXIT_FAILURE;
                            goto end;
                        }
                    }
                    if (selectedAIDLength > 0) {
                    	memcpy(securityInfo211.invokingAid, selectedAID, selectedAIDLength);
                    	securityInfo211.invokingAidLength = selectedAIDLength;
                    }
                    status = GP211_mutual_authentication(cardContext, cardInfo,
                                                     optionStr.key,
                                                     optionStr.enc_key,
                                                     optionStr.mac_key,
                                                     optionStr.kek_key,
													 optionStr.keyLength,
                                                     optionStr.keySetVersion,
                                                     optionStr.keyIndex,
                                                     optionStr.scp,
                                                     optionStr.scpImpl,
                                                     optionStr.securityLevel,
                                                     optionStr.keyDerivation,
                                                     &securityInfo211);

                }
                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("mutual_authentication() returns 0x%08X (%s)\n"),
                              (unsigned int)status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
                goto timer;
            }
			else if (_tcscmp(token, _T("install_for_personalization")) == 0)
			{
				rv = handleOptions(&optionStr);
				if (rv != EXIT_SUCCESS)
				{
					goto end;
				}
				// only supported in GP211+
				if (platform_mode == PLATFORM_MODE_GP_211)
				{
					status = GP211_install_for_personalization(cardContext, cardInfo,
						&securityInfo211,
						optionStr.AID, optionStr.AIDLen);
				}
				if (OPGP_ERROR_CHECK(status))
				{
					_tprintf(_T("install_for_personalization() returns 0x%08X (%s)\n"),
						(unsigned int)status.errorCode, status.errorMessage);
					rv = EXIT_FAILURE;
					goto end;
				}
				goto timer;
			}
			else if (_tcscmp(token, _T("store_data")) == 0)
			{
				rv = handleOptions(&optionStr);
				if (rv != EXIT_SUCCESS)
				{
					goto end;
				}
				// only supported in GP211+
				if (platform_mode == PLATFORM_MODE_GP_211)
				{
					status = GP211_store_data(cardContext, cardInfo,
						&securityInfo211,
						optionStr.dataEncryption,
						optionStr.dataFormat,
						optionStr.responseDataExpected,
						optionStr.data, optionStr.dataLen);
				}
				if (OPGP_ERROR_CHECK(status))
				{
					_tprintf(_T("store_data() returns 0x%08X (%s)\n"),
						(unsigned int)status.errorCode, status.errorMessage);
					rv = EXIT_FAILURE;
					goto end;
				}
				goto timer;
			}
            else if (_tcscmp(token, _T("get_key_information_templates")) == 0)
            {
            	GP211_KEY_INFORMATION gpKeyInformation[64];
            	OP201_KEY_INFORMATION opKeyInformation[64];
            	DWORD keyInformationLength = 64;
            	rv = handleOptions(&optionStr);
                if (rv != EXIT_SUCCESS)
                {
                    goto end;
                }
                if (platform_mode == PLATFORM_MODE_OP_201)
                {
                    status = OP201_get_key_information_templates(cardContext, cardInfo,
                                                     &securityInfo201,
													 optionStr.keyTemplate,
													 opKeyInformation, &keyInformationLength);
                }
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
                    status = GP211_get_key_information_templates(cardContext, cardInfo,
                    		&securityInfo211,
							optionStr.keyTemplate,
							gpKeyInformation, &keyInformationLength);
                }
                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("get_key_information_templates() returns 0x%08X (%s)\n"),
                              (unsigned int)status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
                if (platform_mode == PLATFORM_MODE_OP_201) {
                	displayOpKeyInformation(opKeyInformation, keyInformationLength);
                }
                else {
                	displayGpKeyInformation(gpKeyInformation, keyInformationLength);
                }
                goto timer;
            }
            else if (_tcscmp(token, _T("get_extended_card_resources_information")) == 0)
			  {
				OPGP_EXTENDED_CARD_RESOURCE_INFORMATION extendedCardResourcesInfo;
				rv = handleOptions(&optionStr);
				  if (rv != EXIT_SUCCESS)
				  {
					  goto end;
				  }
				  status = OPGP_get_extended_card_resources_information(cardContext, cardInfo, &securityInfo211, &extendedCardResourcesInfo);
				  if (OPGP_ERROR_CHECK(status))
				  {
					  _tprintf (_T("get_extended_card_resources_information() returns 0x%08X (%s)\n"),
								(unsigned int)status.errorCode, status.errorMessage);
					  rv = EXIT_FAILURE;
					  goto end;
				  }
				  displayExtCardResorcesInfo(extendedCardResourcesInfo);
				  goto timer;
			  }
            else if (_tcscmp(token, _T("select")) == 0)
            {
                // select instance
                rv = handleOptions(&optionStr);
                if (rv != EXIT_SUCCESS)
                {
                    goto end;
                }
                status = OPGP_select_application (cardContext, cardInfo,
                                              (PBYTE)optionStr.AID, optionStr.AIDLen);
                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("select_application() returns 0x%08X (%s)\n"),
                              (unsigned int)status.errorCode, status.errorMessage);
                    /* 6283 is warning we want to continue and unlock */
                    if (status.errorCode != OPGP_ISO7816_WARNING_CM_LOCKED)
                    {
                        rv = EXIT_FAILURE;
                        goto end;
                    }
                    status.errorStatus =  OPGP_ERROR_STATUS_SUCCESS;

                }
                memcpy(selectedAID, optionStr.AID, optionStr.AIDLen);
                selectedAIDLength = optionStr.AIDLen;
                goto timer;
            }
            else if (_tcscmp(token, _T("get_data")) == 0)
            {
                // Get Data
                BYTE data[256];
                DWORD dataLen = 256;
                DWORD i=0;
                rv = handleOptions(&optionStr);
                if (rv != EXIT_SUCCESS)
                {
                    goto end;
                }
                if (platform_mode == PLATFORM_MODE_OP_201)
                {
                    status = OP201_get_data(cardContext, cardInfo, &securityInfo201,
                                    optionStr.identifier,
                                    data, &dataLen);
                }
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
                    status = GP211_get_data(cardContext, cardInfo, &securityInfo211,
                                    optionStr.identifier,
                                    data, &dataLen);
                }

                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("get_data() returns 0x%08X (%s)\n"),
                              (unsigned int)status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
				for (i=0; i<dataLen; i++) {
					_tprintf (_T("%02X"), data[i]);
				}
				_tprintf (_T("\n"));
                goto timer;
            }
            else if (_tcscmp(token, _T("load")) == 0)
            {
                // Load Applet
                DWORD receiptDataLen = 0;
                rv = handleOptions(&optionStr);
                if (rv != EXIT_SUCCESS)
                {
                    goto end;
                }
                if (platform_mode == PLATFORM_MODE_OP_201)
                {
                    status = OP201_load(cardContext, cardInfo, &securityInfo201,
                                    NULL, 0,
                                    optionStr.file,
                                    NULL, &receiptDataLen, NULL);
                }
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
                    status = GP211_load(cardContext, cardInfo, &securityInfo211,
                                    NULL, 0,
                                    optionStr.file,
                                    NULL, &receiptDataLen, NULL);
                }

                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("load() returns 0x%08X (%s)\n"),
                              (unsigned int)status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
                goto timer;
            }
            else if (_tcscmp(token, _T("delete")) == 0)
            {
                // Delete Applet
                OPGP_AID AIDs[1];

                DWORD receiptLen = 10;

                rv = handleOptions(&optionStr);
                if (rv != EXIT_SUCCESS)
                {
                    goto end;
                }
                memcpy (AIDs[0].AID, optionStr.AID, optionStr.AIDLen);
                AIDs[0].AIDLength = (BYTE)optionStr.AIDLen;

                if (platform_mode == PLATFORM_MODE_OP_201)
                {
                    OP201_RECEIPT_DATA receipt[10];
                    status = OP201_delete_application(cardContext, cardInfo, &securityInfo201,
                                                  AIDs, 1,
                                                  (OP201_RECEIPT_DATA *)receipt,
                                                  &receiptLen);
                }
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
                    GP211_RECEIPT_DATA receipt[10];
                    status = GP211_delete_application(cardContext, cardInfo, &securityInfo211,
                                                  AIDs, 1,
                                                  (GP211_RECEIPT_DATA *)receipt,
                                                  &receiptLen);

                }
                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("delete() returns 0x%08X (%s)\n"),
                              (unsigned int)status.errorCode, status.errorMessage);
                }
                goto timer;
            }
            /* Augusto: added delete_key command support */
            else if (_tcscmp(token, _T("delete_key")) == 0)
            {
            	// 0xFF means that all key index for a key set version are deleted
            	optionStr.keyIndex = 0xFF;
                rv = handleOptions(&optionStr);
                if (rv != EXIT_SUCCESS)
                {
                    goto end;
                }

                if (platform_mode == PLATFORM_MODE_OP_201)
                {
                    status = OP201_delete_key
                         (
                             cardContext,
                             cardInfo,
                             &securityInfo201,
                             optionStr.keySetVersion,
                             optionStr.keyIndex
                         );
                }
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
                    status = GP211_delete_key
                         ( cardContext, cardInfo,
                           &securityInfo211, optionStr.keySetVersion, optionStr.keyIndex
                         );
                }

                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("delete_key() return 0x%08X (%s)\n"),
                              (unsigned int)status.errorCode, status.errorMessage);
                }
                goto timer;
            }
            else if (_tcscmp(token, _T("install")) == 0)
            {
                // One step install
                OPGP_LOAD_FILE_PARAMETERS loadFileParams;
                DWORD receiptDataAvailable = 0;
                DWORD receiptDataLen = 0;
                rv = handleOptions(&optionStr);
                if (rv != EXIT_SUCCESS)
                {
                    goto end;
                }
                status = OPGP_read_executable_load_file_parameters(optionStr.file, &loadFileParams);
                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("read_executable_load_file_parameters() returns 0x%08X (%s)\n"),
                              (unsigned int)status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
                if (optionStr.pkgAIDLen == 0)
                {
                    optionStr.pkgAIDLen = loadFileParams.loadFileAID.AIDLength;
                    memcpy(optionStr.pkgAID, loadFileParams.loadFileAID.AID, optionStr.pkgAIDLen);
                }
                if (optionStr.nvCodeLimit == 0)
                {
                    optionStr.nvCodeLimit = loadFileParams.loadFileSize;
                }
                if (platform_mode == PLATFORM_MODE_OP_201)
                {
                    if (optionStr.sdAIDLen == 0)
                    {
                        if (selectedAIDLength != 0)
                        {
                            optionStr.sdAIDLen = selectedAIDLength;
                            memcpy(optionStr.sdAID, selectedAID, selectedAIDLength);
                        }
                        else
                        {
                            optionStr.sdAIDLen = sizeof(OP201_CARD_MANAGER_AID);
                            memcpy(optionStr.sdAID, OP201_CARD_MANAGER_AID, optionStr.sdAIDLen);
                        }
                    }
                    status = OP201_install_for_load(cardContext, cardInfo, &securityInfo201,
                                                (PBYTE)optionStr.pkgAID, optionStr.pkgAIDLen,
                                                (PBYTE)optionStr.sdAID, optionStr.sdAIDLen,
                                                NULL, NULL,
                                                optionStr.nvCodeLimit,
                                                optionStr.vDataLimit,  // jvictor
                                                0); // jvictor, k_o_: we also use 0, e.g. a Cyberflex refuses to install an applet if something else is given.
                }
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
                    if (optionStr.sdAIDLen == 0)
                    {
                        if (selectedAIDLength != 0)
                        {
                            optionStr.sdAIDLen = selectedAIDLength;
                            memcpy(optionStr.sdAID, selectedAID, selectedAIDLength);
                        }
                        else
                        {
                            optionStr.sdAIDLen = sizeof(GP211_CARD_MANAGER_AID);
                            memcpy(optionStr.sdAID, GP211_CARD_MANAGER_AID, optionStr.sdAIDLen);
                        }
                    }
                    status = GP211_install_for_load(cardContext, cardInfo, &securityInfo211,
                                                (PBYTE)optionStr.pkgAID, optionStr.pkgAIDLen,
                                                (PBYTE)optionStr.sdAID, optionStr.sdAIDLen,
                                                NULL, NULL,
                                                optionStr.nvCodeLimit,
                                                optionStr.vDataLimit,          // jvictor
                                                optionStr.nvDataLimit);        // jvictor
                }

                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("install_for_load() returns 0x%08X (%s)\n"),
                              (unsigned int)status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
                if (platform_mode == PLATFORM_MODE_OP_201)
                {
                    status = OP201_load(cardContext, cardInfo, &securityInfo201,
                                    NULL, 0,
                                    optionStr.file,
                                    NULL, &receiptDataLen, NULL);
                }
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
                    status = GP211_load(cardContext, cardInfo, &securityInfo211,
                                    NULL, 0,
                                    optionStr.file,
                                    NULL, &receiptDataLen, NULL);
                }

                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("load() returns 0x%08X (%s)\n"),
                              (unsigned int)status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }

                if (platform_mode == PLATFORM_MODE_OP_201)
                {
					int i;
                    OP201_RECEIPT_DATA receipt;

					if (optionStr.AIDLen || optionStr.instAIDLen)
					{
						if (optionStr.AIDLen == 0)
						{
							optionStr.AIDLen = loadFileParams.appletAIDs[0].AIDLength;
							memcpy(optionStr.AID, loadFileParams.appletAIDs[0].AID, optionStr.AIDLen);
						}
						if (optionStr.instAIDLen == 0)
						{
							optionStr.instAIDLen = optionStr.AIDLen;
							memcpy(optionStr.instAID, optionStr.AID, optionStr.instAIDLen);
						}
						status = OP201_install_for_install_and_make_selectable(
							cardContext, cardInfo, &securityInfo201,
							(PBYTE)optionStr.pkgAID, optionStr.pkgAIDLen,
							(PBYTE)optionStr.AID, optionStr.AIDLen,
							(PBYTE)optionStr.instAID, optionStr.instAIDLen,
							optionStr.privilege,
							optionStr.vDataLimit,
							optionStr.nvDataLimit,
							(PBYTE)optionStr.instParam,
							optionStr.instParamLen,
							NULL, // No install token
							&receipt,
							&receiptDataAvailable);
					}
					else
					{
						for (i = 0; loadFileParams.appletAIDs[i].AIDLength; i++)
						{
							status = OP201_install_for_install_and_make_selectable(
								cardContext, cardInfo, &securityInfo201,
								(PBYTE)optionStr.pkgAID, optionStr.pkgAIDLen,
								(PBYTE)loadFileParams.appletAIDs[i].AID,
								loadFileParams.appletAIDs[i].AIDLength,
								(PBYTE)loadFileParams.appletAIDs[i].AID,
								loadFileParams.appletAIDs[i].AIDLength,
								optionStr.privilege,
								optionStr.vDataLimit,
								optionStr.nvDataLimit,
								(PBYTE)optionStr.instParam,
								optionStr.instParamLen,
								NULL, // No install token
								&receipt,
								&receiptDataAvailable);
						}
					}
                }
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
					int i;
                    GP211_RECEIPT_DATA receipt;

					if (optionStr.AIDLen || optionStr.instAIDLen)
					{
						if (optionStr.AIDLen == 0)
						{
							optionStr.AIDLen = loadFileParams.appletAIDs[0].AIDLength;
							memcpy(optionStr.AID, loadFileParams.appletAIDs[0].AID, optionStr.AIDLen);
						}
						if (optionStr.instAIDLen == 0)
						{
							optionStr.instAIDLen = optionStr.AIDLen;
							memcpy(optionStr.instAID, optionStr.AID, optionStr.instAIDLen);
						}
						status = GP211_install_for_install_and_make_selectable(
							cardContext, cardInfo, &securityInfo211,
							(PBYTE)optionStr.pkgAID, optionStr.pkgAIDLen,
							(PBYTE)optionStr.AID, optionStr.AIDLen,
							(PBYTE)optionStr.instAID, optionStr.instAIDLen,
							optionStr.privilege,
							optionStr.vDataLimit,
							optionStr.nvDataLimit,
							(PBYTE)optionStr.instParam,
							optionStr.instParamLen,
							NULL, // No install token
							&receipt,
							&receiptDataAvailable);
					}
					else
					{
						for (i = 0; loadFileParams.appletAIDs[i].AIDLength; i++)
						{
							status = GP211_install_for_install_and_make_selectable(
								cardContext, cardInfo, &securityInfo211,
								(PBYTE)optionStr.pkgAID, optionStr.pkgAIDLen,
								(PBYTE)loadFileParams.appletAIDs[i].AID,
								loadFileParams.appletAIDs[i].AIDLength,
								(PBYTE)loadFileParams.appletAIDs[i].AID,
								loadFileParams.appletAIDs[i].AIDLength,
								optionStr.privilege,
								optionStr.vDataLimit,
								optionStr.nvDataLimit,
								(PBYTE)optionStr.instParam,
								optionStr.instParamLen,
								NULL, // No install token
								&receipt,
								&receiptDataAvailable);
						}
					}
                }

                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("install_for_install_and_make_selectable() returns 0x%08X (%s)\n"),
                              (unsigned int)status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
                goto timer;
            }
            else if (_tcscmp(token, _T("install_for_load")) == 0)
            {
                // Install for Load
                rv = handleOptions(&optionStr);
                if (rv != EXIT_SUCCESS)
                {
                    goto end;
                }
                if (platform_mode == PLATFORM_MODE_OP_201)
                {
                    if (optionStr.sdAIDLen == 0)
                    {
                        if (selectedAIDLength != 0)
                        {
                            optionStr.sdAIDLen = selectedAIDLength;
                            memcpy(optionStr.sdAID, selectedAID, selectedAIDLength);
                        }
                        else
                        {
                            optionStr.sdAIDLen = sizeof(OP201_CARD_MANAGER_AID);
                            memcpy(optionStr.sdAID, OP201_CARD_MANAGER_AID, optionStr.sdAIDLen);
                        }
                    }
                    status = OP201_install_for_load(cardContext, cardInfo, &securityInfo201,
                                                (PBYTE)optionStr.pkgAID, optionStr.pkgAIDLen,
                                                (PBYTE)optionStr.sdAID, optionStr.sdAIDLen,
                                                NULL, NULL,
                                                optionStr.nvCodeLimit,
                                                optionStr.vDataLimit,  // jvictor
                                                optionStr.nvDataLimit);// jvictor
                }
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
                    if (optionStr.sdAIDLen == 0)
                    {
                        if (selectedAIDLength != 0)
                        {
                            optionStr.sdAIDLen = selectedAIDLength;
                            memcpy(optionStr.sdAID, selectedAID, selectedAIDLength);
                        }
                        else
                        {
                            optionStr.sdAIDLen = sizeof(GP211_CARD_MANAGER_AID);
                            memcpy(optionStr.sdAID, GP211_CARD_MANAGER_AID, optionStr.sdAIDLen);
                        }
                    }
                    status = GP211_install_for_load(cardContext, cardInfo, &securityInfo211,
                                                (PBYTE)optionStr.pkgAID, optionStr.pkgAIDLen,
                                                (PBYTE)optionStr.sdAID, optionStr.sdAIDLen,
                                                NULL, NULL,
                                                optionStr.nvCodeLimit,
                                                optionStr.vDataLimit,   // jvictor
                                                optionStr.nvDataLimit); // jvictor
                }

                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("install_for_load() returns 0x%08X (%s)\n"),
                              (unsigned int)status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
            }
            else if (_tcscmp(token, _T("install_for_install")) == 0)
            {

                DWORD receiptDataAvailable = 0;
                // Install for Install
                rv = handleOptions(&optionStr);
                if (rv != EXIT_SUCCESS)
                {
                    goto end;
                }
                if (platform_mode == PLATFORM_MODE_OP_201)
                {
                    OP201_RECEIPT_DATA receipt;
                    status = OP201_install_for_install_and_make_selectable(
                             cardContext, cardInfo, &securityInfo201,
                             (PBYTE)optionStr.pkgAID, optionStr.pkgAIDLen,
                             (PBYTE)optionStr.AID, optionStr.AIDLen,
                             (PBYTE)optionStr.instAID, optionStr.instAIDLen,
                             optionStr.privilege,
                             optionStr.vDataLimit,
                             optionStr.nvDataLimit,
                             (PBYTE)optionStr.instParam,
                             optionStr.instParamLen,
                             NULL, // No install token
                             &receipt,
                             &receiptDataAvailable);
                }
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
                    GP211_RECEIPT_DATA receipt;

                    status = GP211_install_for_install_and_make_selectable(
                             cardContext, cardInfo, &securityInfo211,
                             (PBYTE)optionStr.pkgAID, optionStr.pkgAIDLen,
                             (PBYTE)optionStr.AID, optionStr.AIDLen,
                             (PBYTE)optionStr.instAID, optionStr.instAIDLen,
                             optionStr.privilege,
                             optionStr.vDataLimit,
                             optionStr.nvDataLimit,
                             (PBYTE)optionStr.instParam,
                             optionStr.instParamLen,
                             NULL, // No install token
                             &receipt,
                             &receiptDataAvailable);
                }

                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("install_for_install_and_make_selectable() returns 0x%08X (%s)\n"),
                              (unsigned int)status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
                goto timer;
            }
            else if (_tcscmp(token, _T("card_disconnect")) == 0)
            {
                // disconnect card
                status = OPGP_card_disconnect(cardContext, &cardInfo);
                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("card_disconnect() returns 0x%08X (%s)\n"),
                              (unsigned int)status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
                goto timer;
            }
            else if (_tcscmp(token, _T("put_sc_key")) == 0)
            {
                rv = handleOptions(&optionStr);
                if (rv != EXIT_SUCCESS)
                {
                    goto end;
                }
                if (platform_mode == PLATFORM_MODE_OP_201)
                {
                    if (optionStr.keyDerivation == OPGP_DERIVATION_METHOD_EMV_CPS11) {
                        status = OP201_EMV_CPS11_derive_keys(cardContext, cardInfo, &securityInfo201, optionStr.key, optionStr.enc_key, optionStr.mac_key, optionStr.kek_key);
                        if (OPGP_ERROR_CHECK(status))
                        {
                            _tprintf (_T("EMV_CPS11_derive_keys() returns 0x%08X (%s)\n"),
                                        (unsigned int)status.errorCode, status.errorMessage);
                            rv = EXIT_FAILURE;
                            goto end;
                        }
                    }
                    else if (optionStr.keyDerivation == OPGP_DERIVATION_METHOD_VISA2) {
						optionStr.APDULen = APDU_COMMAND_LEN;
						OP201_get_data(cardContext, cardInfo, &securityInfo201, (PBYTE)OP201_GET_DATA_CARD_MANAGER_AID, optionStr.APDU, &(optionStr.APDULen));
						if (OPGP_ERROR_CHECK(status))
						{
							_tprintf (_T("VISA2_derive_keys() returns 0x%08X (%s)\n"),
										(unsigned int)status.errorCode, status.errorMessage);
							rv = EXIT_FAILURE;
							goto end;
						}
						// offset should be 3 where the Card Manager AID starts
						status = OP201_VISA2_derive_keys(cardContext, cardInfo, &securityInfo201, optionStr.APDU+3, optionStr.APDULen-3, optionStr.key, optionStr.enc_key, optionStr.mac_key, optionStr.kek_key);
						if (OPGP_ERROR_CHECK(status))
						{
							_tprintf (_T("VISA2_derive_keys() returns 0x%08X (%s)\n"),
										(unsigned int)status.errorCode, status.errorMessage);
							rv = EXIT_FAILURE;
							goto end;
						}
                    }
					else if (optionStr.keyDerivation == OPGP_DERIVATION_METHOD_VISA1) {
						status = OP201_VISA1_derive_keys(cardContext, cardInfo, &securityInfo201, optionStr.key, optionStr.enc_key, optionStr.mac_key, optionStr.kek_key);
						if (OPGP_ERROR_CHECK(status))
						{
							_tprintf (_T("VISA1_derive_keys() returns 0x%08X (%s)\n"),
										(unsigned int)status.errorCode, status.errorMessage);
							rv = EXIT_FAILURE;
							goto end;
						}
                    }
                    status = OP201_put_secure_channel_keys(cardContext, cardInfo, &securityInfo201,
                                                       optionStr.keySetVersion,
                                                       optionStr.newKeySetVersion,
                                                       optionStr.enc_key,
                                                       optionStr.mac_key,
                                                       optionStr.kek_key);
                }
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
                    if (optionStr.keyDerivation == OPGP_DERIVATION_METHOD_EMV_CPS11) {
                        status = GP211_EMV_CPS11_derive_keys(cardContext, cardInfo, &securityInfo211, optionStr.key, optionStr.enc_key, optionStr.mac_key, optionStr.kek_key);
                        if (OPGP_ERROR_CHECK(status))
                        {
                            _tprintf (_T("EMV_CPS11_derive_keys() returns 0x%08X (%s)\n"),
                                      (unsigned int)status.errorCode, status.errorMessage);
                            rv = EXIT_FAILURE;
                            goto end;
                        }
                    }
                    else if (optionStr.keyDerivation == OPGP_DERIVATION_METHOD_VISA2) {
                        optionStr.APDULen = APDU_COMMAND_LEN;
                        GP211_get_data(cardContext, cardInfo, &securityInfo211, (PBYTE)GP211_GET_DATA_ISSUER_SECURITY_DOMAIN_AID, optionStr.APDU, &(optionStr.APDULen));
                        if (OPGP_ERROR_CHECK(status))
                        {
                            _tprintf (_T("VISA2_derive_keys() returns 0x%08X (%s)\n"),
                                      (unsigned int)status.errorCode, status.errorMessage);
                            rv = EXIT_FAILURE;
                            goto end;
                        }
                        // offset should be 3 where the Card Manager AID starts
                        status = GP211_VISA2_derive_keys(cardContext, cardInfo, &securityInfo211, optionStr.APDU+3, optionStr.APDULen-3, optionStr.key, optionStr.enc_key, optionStr.mac_key, optionStr.kek_key);
                        if (OPGP_ERROR_CHECK(status))
                        {
                            _tprintf (_T("VISA2_derive_keys() returns 0x%08X (%s)\n"),
                                      (unsigned int)status.errorCode, status.errorMessage);
                            rv = EXIT_FAILURE;
                            goto end;
                        }
                    }
					else if (optionStr.keyDerivation == OPGP_DERIVATION_METHOD_VISA1) {
                        status = GP211_VISA1_derive_keys(cardContext, cardInfo, &securityInfo211, optionStr.key, optionStr.enc_key, optionStr.mac_key, optionStr.kek_key);
                        if (OPGP_ERROR_CHECK(status))
                        {
                            _tprintf (_T("VISA1_derive_keys() returns 0x%08X (%s)\n"),
                                      (unsigned int)status.errorCode, status.errorMessage);
                            rv = EXIT_FAILURE;
                            goto end;
                        }
                    }
                    status = GP211_put_secure_channel_keys(cardContext, cardInfo,
                                                       &securityInfo211,
                                                       optionStr.keySetVersion,
                                                       optionStr.newKeySetVersion,
                                                       NULL,
                                                       optionStr.enc_key,
                                                       optionStr.mac_key,
                                                       optionStr.kek_key,
													   optionStr.keyLength);
                }

                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("put_secure_channel_keys() returns 0x%08X (%s)\n"),
                              (unsigned int)status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
                goto timer;
            }
            else if (_tcscmp(token, _T("put_dm_keys")) == 0)
            {
                rv = handleOptions(&optionStr);
                if (rv != EXIT_SUCCESS)
                {
                    goto end;
                }
                if (platform_mode == PLATFORM_MODE_OP_201)
                {
                    status = OP201_put_delegated_management_keys(cardContext, cardInfo, &securityInfo201,
                            optionStr.keySetVersion,
                            optionStr.newKeySetVersion,
                            optionStr.file,
                            optionStr.passPhrase,
                            optionStr.key);
                }
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
                    status = GP211_put_delegated_management_keys(cardContext, cardInfo,
                            &securityInfo211,
                            optionStr.keySetVersion,
                            optionStr.newKeySetVersion,
                            optionStr.file,
                            optionStr.passPhrase,
                            optionStr.key,
							optionStr.keyLength);
                }

                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("put_delegated_management_keys() returns 0x%08X (%s)\n"),
                              (unsigned int)status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
                goto timer;
            }
            else if (_tcscmp(token, _T("get_card_recognition_data")) == 0)
			{
            	GP211_CARD_RECOGNITION_DATA cardData;
				rv = handleOptions(&optionStr);
				if (rv != EXIT_SUCCESS)
				{
					goto end;
				}
				status = GP211_get_card_recognition_data(cardContext, cardInfo, &cardData);

				if (OPGP_ERROR_CHECK(status))
				{
					_tprintf (_T("get_card_recognition_data() returns 0x%08X (%s)\n"),
							  (unsigned int)status.errorCode, status.errorMessage);
					rv = EXIT_FAILURE;
					goto end;
				}
				displayCardRecognitionData(cardData);
			}
            else if (_tcscmp(token, _T("get_status")) == 0)
            {
#define NUM_APPLICATIONS 64
                DWORD numData = NUM_APPLICATIONS;

                rv = handleOptions(&optionStr);
                if (rv != EXIT_SUCCESS)
                {
                    goto end;
                }
                if (platform_mode == PLATFORM_MODE_OP_201)
                {
                    OP201_APPLICATION_DATA data[NUM_APPLICATIONS];
                    status = OP201_get_status(cardContext, cardInfo, &securityInfo201,
                                          optionStr.element,
                                          data,
                                          &numData);

                    if (OPGP_ERROR_CHECK(status))
                    {
                        _tprintf (_T("get_status() returns 0x%08X (%s)\n"),
                                  (unsigned int)status.errorCode, status.errorMessage);
                        rv = EXIT_FAILURE;
                        goto end;
                    }
                    displayApplicationsOp201(data, numData, optionStr.element);
                }
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
                    GP211_APPLICATION_DATA appData[NUM_APPLICATIONS];
                    GP211_EXECUTABLE_MODULES_DATA execData[NUM_APPLICATIONS];
                    status = GP211_get_status(cardContext, cardInfo, &securityInfo211,
                                          optionStr.element,
										  optionStr.format,
                                          appData,
                                          execData,
                                          &numData);

                    if (OPGP_ERROR_CHECK(status))
                    {
                        _tprintf (_T("get_status() returns 0x%08X (%s)\n"),
                                  (unsigned int)status.errorCode, status.errorMessage);
                        rv = EXIT_FAILURE;
                        goto end;
                    }

                    if (optionStr.element == GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES)
                    {
                    	displayLoadFilesAndModulesGp211(execData, numData);
                    }
                    else
                    {
                    	displayLoadApplicationsGp211(appData, numData, optionStr.element);
                    }
                }
                goto timer;
            }
            else if (_tcscmp(token, _T("send_apdu")) == 0 || _tcscmp(token, _T("send_apdu_nostop")) == 0)
            {
                BYTE recvAPDU[258];
                DWORD recvAPDULen = 258;
                // Install for Load
                rv = handleOptions(&optionStr);
                if (rv != EXIT_SUCCESS)
                {
                    goto end;
                }

                if (platform_mode == PLATFORM_MODE_OP_201)
                {
                    status = OP201_send_APDU(cardContext, cardInfo,
                                         (optionStr.secureChannel == 0 ? NULL : &securityInfo201),
                                         (PBYTE)(optionStr.APDU), optionStr.APDULen,
                                         recvAPDU, &recvAPDULen);
                }
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
                    status = GP211_send_APDU(cardContext, cardInfo,
                                         (optionStr.secureChannel == 0 ? NULL : &securityInfo211),
                                         (PBYTE)(optionStr.APDU), optionStr.APDULen,
                                         recvAPDU, &recvAPDULen);
                }
				_tprintf (_T("send_APDU() returns 0x%08X (%s)\n"),
						  (unsigned int)status.errorCode, status.errorMessage);
                if (OPGP_ERROR_CHECK(status))
                {

                    // if the command was nostop, don't quit
                    if (_tcscmp(token, _T("send_apdu_nostop")) != 0)
                    {
                        rv = EXIT_FAILURE;
                        goto end;
                    }
                }
                goto timer;
            }
            else if (_tcscmp(token, _T("mode_201")) == 0)
            {
                platform_mode = PLATFORM_MODE_OP_201;
                break;
            }
            else if (_tcscmp(token, _T("mode_211")) == 0)
            {
                platform_mode = PLATFORM_MODE_GP_211;
                break;
            }
            else if (_tcscmp(token, _T("enable_trace")) == 0)
            {
                OPGP_enable_trace_mode(OPGP_TRACE_MODE_ENABLE, NULL);
                break;
            }
			// for backward combatibility
			else if (_tcscmp(token, _T("gemXpressoPro")) == 0)
			{
				gemXpressoPro = 1;
				break;
			}
            else if (_tcscmp(token, _T("enable_timer")) == 0)
            {
                timer = 1;
                break;
            }
			else if (_tcscmp(token, _T("exit")) == 0)
            {
                rv = EXIT_SUCCESS;
                goto end;
            }
			else if (_tcscmp(token, _T("list_readers")) == 0)
            {
                DWORD readerStrLen = BUFLEN;
                int j=0;
                int k=0;

                // get all readers
                status = OPGP_list_readers (cardContext, buf, &readerStrLen);
                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf(_T("list_readers failed with error 0x%08X (%s)\n"), (unsigned int)status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }

                for (j=0; j<(int)readerStrLen;)
                {
                    // Check for end of readers
                    if (buf[j] == _T('\0'))
                        break;
                    _tcsncpy(optionStr.reader, buf+j, READERNAMELEN);
					_tprintf ( _T("* reader name %s\n"), optionStr.reader);
                    k++;
                    j+=(int)_tcslen(buf+j)+1;
                }
                break;
            }
            else
            {
                _tprintf(_T("Unknown command %s\n"), token);
                break;
            }
timer:
			// get the final time and calculate the total time of the command
			if (timer)
			{
				ft = GetTime();
				_tprintf(_T("command time: %u ms\n"), (ft - it));
			}
			break;
        }
    }
end:
	if (optionStr.noStop) {
		goto nostop;
	}
    return rv;
}

int _tmain(int argc, TCHAR* argv[])
{
    FILE *fd = NULL;
    int rv = EXIT_SUCCESS;

    // take care of input argument
    if (argc == 1)
    {
        // read input from stdin
        fd = stdin;
    }
    else if (argc == 2)
    {
        // read input from script file
    	// fix for MAC eclipse bug using single quotes: https://bugs.eclipse.org/bugs/show_bug.cgi?id=516027
        if (argv[1][0] == _T('\'')) {
        	argv[1]++;
        	argv[1][_tcslen(argv[1])-1] = _T('\0');
        }
    	fd = _tfopen(argv[1], _T("r"));
        // error
        if (fd == NULL)
        {
            _ftprintf(stderr, _T("Could not open scriptfile !\n"));
            rv = EXIT_FAILURE;
            goto end;
        }
    }
    else
    {
        // error
        _ftprintf (stderr, _T("Usage: gpshell [scriptfile]\n"));
        rv = EXIT_FAILURE;
        goto end;
    }

    // launch the command interpreter
    rv = handleCommands(fd);
end:
    return rv;
}
