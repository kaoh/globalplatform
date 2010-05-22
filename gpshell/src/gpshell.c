/**
 *  Copyright (c) 2007, Snit Mo, Karsten Ohme
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

#include "globalplatform/globalplatform.h"

#ifndef WIN32
#define _snprintf snprintf
#define _fgetts fgets
#define _tcscmp strcmp
#define _tcstok strtok
#define _stscanf sscanf
#define _tstoi atoi
#define _tcsnccmp strncmp
#define _tcstol strtol
#endif

/* Constants */
#define BUFLEN 1024
#define FILENAMELEN 256
#define READERNAMELEN 256
#define AIDLEN 16
#define APDULEN 261
#define INSTPARAMLEN 32
#define DELIMITER _T(" \t\n,")
#define DDES_KEY_LEN 16
#define PLATFORM_MODE_OP_201 OP_201
#define PLATFORM_MODE_GP_211 GP_211
#define PASSPHRASELEN 64
#define AUTOREADER -1

/* Data Structures */
typedef struct _OptionStr
{
    BYTE keyIndex;
    BYTE keySetVersion;
    BYTE newKeySetVersion;
    BYTE key[DDES_KEY_LEN];
    BYTE mac_key[DDES_KEY_LEN];
    BYTE enc_key[DDES_KEY_LEN];
    BYTE kek_key[DDES_KEY_LEN];
    BYTE current_kek[DDES_KEY_LEN];
    BYTE securityLevel;
    BYTE AID[AIDLEN+1];
    DWORD AIDLen;
    BYTE sdAID[AIDLEN+1];
    DWORD sdAIDLen;
    BYTE pkgAID[AIDLEN+1];
    DWORD pkgAIDLen;
    BYTE instAID[AIDLEN+1];
    DWORD instAIDLen;
    BYTE APDU[APDULEN+1];
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
    BYTE element;
    BYTE privilege;
    BYTE scp;
    BYTE scpImpl;
    BYTE identifier[2];
    BYTE keyDerivation;
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

/* Functions */
static void ConvertTToC(char* pszDest, const TCHAR* pszSrc)
{
    unsigned int i;

    for (i = 0; i < _tcslen(pszSrc); i++)
        pszDest[i] = (char) pszSrc[i];

    pszDest[_tcslen(pszSrc)] = '\0';
}

static int ConvertStringToByteArray(TCHAR *src, int maxLength, BYTE *dest)
{
    TCHAR dummy[BUFLEN+1];
    int temp, i = 0;
    _tcsncpy(dummy, src, maxLength*2+1);
    dummy[maxLength*2] = _T('\0');
    while (_stscanf(&(dummy[i*2]), _T("%02x"), &temp) > 0)
    {
        dest[i] = temp;
        i++;
    }
    return i;
}

static TCHAR *strtokCheckComment(TCHAR *buf)
{
    TCHAR *token;
    TCHAR dummy[BUFLEN];
    int avail = sizeof(dummy);
    int size = 0, read = 0;

    token = _tcstok(buf, DELIMITER);

    if (token == NULL)
        return NULL;

    /* Check for quoted string */
    if (token[0] == _T('"'))
    {
        size = _sntprintf(dummy, avail, _T("%s"), token+1);
        avail -= size;
        read += size;
        token = _tcstok(buf, _T("\""));
        if (token == NULL)
            return NULL;
        if (size > 0)
        {
            _sntprintf(dummy+read, avail, _T(" %s"), token);
        }
        dummy[sizeof(dummy)-1] = _T('\0');

        /* Skip next delimiter */
        token = _tcstok(buf, DELIMITER);

        token = dummy;
        return token;
    }

    if (_tcscmp(token, _T("//")) == 0 || _tcscmp(token, _T("#")) == 0)
    {
        return NULL;
    }
    else
    {
        return token;
    }
}


static int handleOptions(OptionStr *pOptionStr)
{
    int rv = EXIT_SUCCESS;
    TCHAR *token;

    pOptionStr->keyIndex = 0;
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
    pOptionStr->privilege = 0;
    pOptionStr->scp = 0;
    pOptionStr->scpImpl = 0;
	pOptionStr->identifier[0] = 0;
	pOptionStr->identifier[1] = 0;
	pOptionStr->keyDerivation = OPGP_DERIVATION_METHOD_NONE;

        	printf("YYYYYYYYYYYYYYY Hier\n");

    token = strtokCheckComment(NULL);

    while (token != NULL)
    {

        if (_tcscmp(token, _T("-identifier")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -identifier not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
            	BYTE temp;
            	ConvertStringToByteArray(token, 2, pOptionStr->identifier);
            	if (_tcslen(token) == 2) {
					temp = pOptionStr->identifier[0];
					pOptionStr->identifier[0] = pOptionStr->identifier[1];
					pOptionStr->identifier[1] = temp;
            	}
            }
        }
        else if (_tcscmp(token, _T("-keyind")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -keyind not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                pOptionStr->keyIndex = _tstoi(token);
            }
        }
        else if (_tcscmp(token, _T("-keyver")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -keyver not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                pOptionStr->keySetVersion = _tstoi(token);
            }
        }
        else if (_tcscmp(token, _T("-newkeyver")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -newkeyver not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                pOptionStr->newKeySetVersion = _tstoi(token);
            }
        }
        else if (_tcscmp(token, _T("-sc")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -sc not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                if (_tstoi(token) == 0)
                    pOptionStr->secureChannel = 0;
                else if (_tstoi(token) == 1)
                    pOptionStr->secureChannel = 1;
                else
                {
                    _tprintf(_T("Error: option -sc not followed 0 (secure channel off) or 1 (secure channel on)\n"));
                    rv = EXIT_FAILURE;
                    goto end;
                }
            }
        }
        else if (_tcscmp(token, _T("-security")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -security not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                pOptionStr->securityLevel = _tstoi(token);
            }
        }
        else if (_tcscmp(token, _T("-readerNumber")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -readerNumber not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                if (_tcscmp(token,_T("0")) == 0)
                {
                    _tprintf(_T("Error: option -readerNumber must be followed by number > 0\n"));
                    rv = EXIT_FAILURE;
                    goto end;
                }
                pOptionStr->readerNumber = _tstoi(token)-1;
            }
        }
        else if (_tcscmp(token, _T("-reader")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -reader not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                _tcsncpy(pOptionStr->reader, token, READERNAMELEN+1);
#ifdef DEBUG
                _tprintf ( _T("reader name %s\n"), pOptionStr->reader);
#endif
            }
        }
        else if (_tcscmp(token, _T("-file")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -file not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                _tcsncpy(pOptionStr->file, token, FILENAMELEN+1);
#ifdef DEBUG
                _tprintf ( _T("file name %s\n"), pOptionStr->file);
#endif
            }
        }
        else if (_tcscmp(token, _T("-pass")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -pass not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                ConvertTToC(pOptionStr->passPhrase, token);
                pOptionStr->passPhrase[PASSPHRASELEN] = '\0';
            }
        }
        else if (_tcscmp(token, _T("-key")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -key not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {

                ConvertStringToByteArray(token, DDES_KEY_LEN, pOptionStr->key);
            }
        }
        else if (_tcscmp(token, _T("-mac_key")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -key not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                ConvertStringToByteArray(token, DDES_KEY_LEN, pOptionStr->mac_key);
            }
        }
        else if (_tcscmp(token, _T("-enc_key")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -enc_key not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                ConvertStringToByteArray(token, DDES_KEY_LEN, pOptionStr->enc_key);
            }
        }
        else if (_tcscmp(token, _T("-kek_key")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -kek_key not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {

                ConvertStringToByteArray(token, DDES_KEY_LEN, pOptionStr->kek_key);
            }
        }
        else if (_tcscmp(token, _T("-current_kek")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -current_kek not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {

                ConvertStringToByteArray(token, DDES_KEY_LEN, pOptionStr->current_kek);
            }
        }
        else if (_tcscmp(token, _T("-AID")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -AID not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                pOptionStr->AIDLen = ConvertStringToByteArray(token, AIDLEN, pOptionStr->AID);
            }
        }
        else if (_tcscmp(token, _T("-sdAID")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -sdAID not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                pOptionStr->sdAIDLen = ConvertStringToByteArray(token, AIDLEN, pOptionStr->sdAID);
            }
        }
        else if (_tcscmp(token, _T("-pkgAID")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -pkgAID not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                pOptionStr->pkgAIDLen = ConvertStringToByteArray(token, AIDLEN, pOptionStr->pkgAID);
            }
        }
        else if (_tcscmp(token, _T("-instAID")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -instAID not followed by data\n"));
                exit (EXIT_FAILURE);
            }
            else
            {
                pOptionStr->instAIDLen = ConvertStringToByteArray(token, AIDLEN, pOptionStr->instAID);
            }
        }
        else if (_tcscmp(token, _T("-APDU")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -APDU not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                pOptionStr->APDULen = ConvertStringToByteArray(token, APDULEN, pOptionStr->APDU);
            }
        }
        else if (_tcscmp(token, _T("-protocol")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -protocol not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                if (_tstoi(token) == 0)
                {
                    pOptionStr->protocol = OPGP_CARD_PROTOCOL_T0;
                }
                else if (_tstoi(token) == 1)
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
        }
        else if (_tcscmp(token, _T("-nvCodeLimit")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -nvCodeLimit not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                pOptionStr->nvCodeLimit = _tstoi(token);
            }
        }
        else if (_tcscmp(token, _T("-nvDataLimit")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -nvDataLimit not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                pOptionStr->nvDataLimit = _tstoi(token);
            }
        }
        else if (_tcscmp(token, _T("-vDataLimit")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -vDataLimit not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                pOptionStr->vDataLimit = _tstoi(token);
            }
        }
        else if (_tcscmp(token, _T("-instParam")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -instParam not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                pOptionStr->instParamLen = ConvertStringToByteArray(token, INSTPARAMLEN, pOptionStr->instParam);
            }
        }
        else if (_tcscmp(token, _T("-element")) == 0)
        {
            int temp;
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -element not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }

            if (_stscanf (token, _T("%02x"), &temp) <= 0)
            {
                _tprintf(_T("Error: option -element followed by an illegal string %s\n"),
                        token);
                rv = EXIT_FAILURE;
                goto end;
            }
            pOptionStr->element = temp;
        }
        else if (_tcscmp(token, _T("-priv")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -priv not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                pOptionStr->privilege = _tstoi(token);
            }
        }
        else if (_tcscmp(token, _T("-scp")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -scp not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                pOptionStr->scp = _tstoi(token);
            }
        }
        else if (_tcscmp(token, _T("-scpimpl")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -scpimpl not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                pOptionStr->scpImpl = (int)_tcstol(token, NULL, 0);
            }
        }
        else if (_tcscmp(token, _T("-keyDerivation")) == 0)
        {
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -keyDerivation not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            if (_tcscmp(token, _T("none")) == 0) {
            	pOptionStr->keyDerivation = OPGP_DERIVATION_METHOD_NONE;
            }
            else if (_tcscmp(token, _T("visa2")) == 0) {
            	pOptionStr->keyDerivation = OPGP_DERIVATION_METHOD_VISA2;
            }
            else if (_tcscmp(token, _T("emvcps11")) == 0) {
            	pOptionStr->keyDerivation = OPGP_DERIVATION_METHOD_EMV_CPS11;
            }
            else
            {
                _tprintf(_T("Error: Unknown key derivation method\n"));
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

        token = strtokCheckComment(NULL);
    }
end:
    return rv;
}

static int handleCommands(FILE *fd)
{
    TCHAR buf[BUFLEN + 1], commandLine[BUFLEN + 1];
    int rv = EXIT_SUCCESS, i;
	unsigned int it=0, ft=0;
    OPGP_ERROR_STATUS status;
    TCHAR *token;
    OptionStr optionStr;
    OPGP_ERROR_CREATE_NO_ERROR(status);

    while (_fgetts (buf, BUFLEN, fd) != NULL)
    {

        // copy command line for printing it out later
        _tcsncpy (commandLine, buf, BUFLEN);

        token = strtokCheckComment(buf);
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
                         _tcslen(_T("gppcscconnectionplugin")));
                _tcsncpy(cardContext.libraryVersion, _T("1.0.0"),
                         _tcslen( _T("1.0.0")));
                status = OPGP_establish_context(&cardContext);
                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("establish_context failed with error 0x%08lX (%s)\n"), status.errorCode, status.errorMessage);
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
                    _tprintf (_T("release_context failed with error 0x%08lX (%s)\n"), status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
                goto timer;
            }
            else if (_tcscmp(token, _T("card_connect")) == 0)
            {
                TCHAR buf[BUFLEN + 1];
                DWORD readerStrLen = BUFLEN;
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
                        _tprintf(_T("list_readers failed with error 0x%08lX (%s)\n"), status.errorCode, status.errorMessage);
                        rv = EXIT_FAILURE;
                        goto end;
                    }

                    for (j=0; j<(int)readerStrLen;)
                    {
                        // Check for end of readers
                        if (buf[j] == _T('\0'))
                            break;
                        _tcsncpy(optionStr.reader, buf+j, READERNAMELEN+1);


                        // if auto reader, connect now
                        if (optionStr.readerNumber == AUTOREADER)
                        {
                            status = OPGP_card_connect(cardContext, optionStr.reader, &cardInfo, optionStr.protocol);
                            if (!OPGP_ERROR_CHECK(status))
                            {
                                break;
                            }
                        }
                        else if (k == optionStr.readerNumber)
                        {
                        	// connect the this reader number
                        	status = OPGP_card_connect (cardContext, optionStr.reader, &cardInfo, optionStr.protocol);
                            break;
                        }

                        k++;
                        j+=(int)_tcslen(buf+j)+1;
                    }
                    optionStr.reader[READERNAMELEN] = _T('\0');

#ifdef DEBUG
                    _tprintf ( _T("* reader name %s\n"), optionStr.reader);
#endif
                }
                else {
                    status = OPGP_card_connect (cardContext, optionStr.reader, &cardInfo, optionStr.protocol);
                }

                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("card_connect() returns 0x%08lX (%s)\n"), status.errorCode, status.errorMessage);
					rv = EXIT_FAILURE;
                    goto end;
                }
                // set mode for internal use of library
                cardInfo.specVersion = platform_mode;
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

printf("key: %02X",optionStr.key[0]);
				if (gemXpressoPro) {
					optionStr.keyDerivation = OPGP_DERIVATION_METHOD_VISA2;
				}
                if (platform_mode == PLATFORM_MODE_OP_201)
                {
                	printf("key: %02X",optionStr.key[0]);
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
                /*
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
                    if (optionStr.scp == 0 || optionStr.scpImpl == 0)
                    {
                        status = GP211_get_secure_channel_protocol_details(cardContext, cardInfo,
                                &optionStr.scp,
                                &optionStr.scpImpl);
                        if (OPGP_ERROR_CHECK(status))
                        {
                            _tprintf (_T("GP211_get_secure_channel_protocol_details() returns 0x%08lX (%s)\n"),
                                      status.errorCode, status.errorMessage);
                            rv = EXIT_FAILURE;
                            goto end;
                        }
                    }

                    status = GP211_mutual_authentication(cardContext, cardInfo,
                                                     optionStr.key,
                                                     optionStr.enc_key,
                                                     optionStr.mac_key,
                                                     optionStr.kek_key,
                                                     optionStr.keySetVersion,
                                                     optionStr.keyIndex,
                                                     optionStr.scp,
                                                     optionStr.scpImpl,
                                                     optionStr.securityLevel,
                                                     optionStr.keyDerivation,
                                                     &securityInfo211);

                }
*/
                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("mutual_authentication() returns 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
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
                    _tprintf (_T("select_application() returns 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
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
                    _tprintf (_T("get_data() returns 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
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
                    _tprintf (_T("load() returns 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
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
                    _tprintf (_T("delete() returns 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
                }
                goto timer;
            }
            /* Augusto: added delete_key command support */
            else if (_tcscmp(token, _T("delete_key")) == 0)
            {

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
                    _tprintf (_T("delete_key() return 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
                }
                goto timer;
            }
            else if (_tcscmp(token, _T("install")) == 0)
            {
                // One step install
                OPGP_LOAD_FILE_PARAMETERS loadFileParams;
                DWORD receiptDataAvailable = 0;
                DWORD receiptDataLen = 0;
                char installParam[1];
                installParam[0] = 0;

                rv = handleOptions(&optionStr);
                if (rv != EXIT_SUCCESS)
                {
                    goto end;
                }
                status = OPGP_read_executable_load_file_parameters(optionStr.file, &loadFileParams);
                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("read_executable_load_file_parameters() returns 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
                if (optionStr.pkgAIDLen == 0)
                {
                    optionStr.pkgAIDLen = loadFileParams.loadFileAID.AIDLength;
                    memcpy(optionStr.pkgAID, loadFileParams.loadFileAID.AID, optionStr.pkgAIDLen);
                }
                if (optionStr.AIDLen == 0)
                {
                    optionStr.AIDLen = loadFileParams.appletAIDs[0].AIDLength;
                    memcpy(optionStr.AID, loadFileParams.appletAIDs[0].AID, optionStr.AIDLen);
                }
                if (optionStr.instAIDLen == 0)
                {
                    optionStr.instAIDLen = loadFileParams.appletAIDs[0].AIDLength;
                    memcpy(optionStr.instAID, loadFileParams.appletAIDs[0].AID, optionStr.instAIDLen);
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
                                                0); // jvictor, k_o_: we also use 0, e.g. y Cyberflex refuses to install an applet if something else is given.
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
                    _tprintf (_T("install_for_load() returns 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
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
                    _tprintf (_T("load() returns 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
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
                    _tprintf (_T("install_for_install_and_make_selectable() returns 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
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
                    _tprintf (_T("install_for_load() returns 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
            }
            else if (_tcscmp(token, _T("install_for_install")) == 0)
            {


                DWORD receiptDataAvailable = 0;
                char installParam[1];
                installParam[0] = 0;

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
                    _tprintf (_T("install_for_install_and_make_selectable() returns 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
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
                    _tprintf (_T("card_disconnect() returns 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
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
                    status = OP201_put_secure_channel_keys(cardContext, cardInfo, &securityInfo201,
                                                       optionStr.keySetVersion,
                                                       optionStr.newKeySetVersion,
                                                       optionStr.enc_key,
                                                       optionStr.mac_key,
                                                       optionStr.kek_key,
                                                       optionStr.current_kek);
                }
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
                    status = GP211_put_secure_channel_keys(cardContext, cardInfo,
                                                       &securityInfo211,
                                                       optionStr.keySetVersion,
                                                       optionStr.newKeySetVersion,
                                                       NULL,
                                                       optionStr.enc_key,
                                                       optionStr.mac_key,
                                                       optionStr.kek_key);
                }

                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("put_secure_channel_keys() returns 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
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
                            optionStr.key,
                            optionStr.current_kek);
                }
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
                    status = GP211_put_delegated_management_keys(cardContext, cardInfo,
                            &securityInfo211,
                            optionStr.keySetVersion,
                            optionStr.newKeySetVersion,
                            optionStr.file,
                            optionStr.passPhrase,
                            optionStr.key);
                }

                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("put_delegated_management_keys() returns 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
                goto timer;
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
                        _tprintf (_T("get_status() returns 0x%08lX (%s)\n"),
                                  status.errorCode, status.errorMessage);
                        rv = EXIT_FAILURE;
                        goto end;
                    }

                    _tprintf(_T("\nList of applets (AID state privileges)\n"));
                    for (i=0; i<(int)numData; i++)
                    {
                        int j;

                        for (j=0; j<data[i].AIDLength; j++)
                        {
                            _tprintf(_T("%02x"), data[i].AID[j]);
                        }

                        _tprintf(_T("\t%x"), data[i].lifeCycleState);
                        _tprintf(_T("\t%x\n"), data[i].privileges);
                    }
                }
                else if (platform_mode == PLATFORM_MODE_GP_211)
                {
                    GP211_APPLICATION_DATA appData[NUM_APPLICATIONS];
                    GP211_EXECUTABLE_MODULES_DATA execData[NUM_APPLICATIONS];
                    status = GP211_get_status(cardContext, cardInfo, &securityInfo211,
                                          optionStr.element,
                                          appData,
                                          execData,
                                          &numData);

                    if (OPGP_ERROR_CHECK(status))
                    {
                        _tprintf (_T("get_status() returns 0x%08lX (%s)\n"),
                                  status.errorCode, status.errorMessage);
                        rv = EXIT_FAILURE;
                        goto end;
                    }

                    if (optionStr.element == GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES)
                    {
                        _tprintf(_T("\nList of Ex. Load File (AID state Ex. Module AIDs)\n"));
                    }
                    else
                    {
                        _tprintf(_T("\nList of elements (AID state privileges)\n"));
                    }
                    for (i=0; i<(int)numData; i++)
                    {
                        int j;
                        int k;

                        if (optionStr.element == GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES)
                        {
                            for (j=0; j<execData[i].AIDLength; j++)
                            {
                                _tprintf(_T("%02x"), execData[i].AID[j]);
                            }
                            _tprintf(_T("\t%x\n"), execData[i].lifeCycleState);
                            for (k=0; k<execData[i].numExecutableModules; k++)
                            {
                                int h;
                                printf("\t");
                                for (h=0; h<execData[i].executableModules[k].AIDLength; h++)
                                {
                                    _tprintf(_T("%02x"), execData[i].executableModules[k].AID[h]);
                                }
                            }
                            _tprintf(_T("\n"));
                        }
                        else
                        {
                            for (j=0; j<appData[i].AIDLength; j++)
                            {
                                _tprintf(_T("%02x"), appData[i].AID[j]);
                            }

                            _tprintf(_T("\t%x"), appData[i].lifeCycleState);
                            _tprintf(_T("\t%x\n"), appData[i].privileges);
                        }
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
				_tprintf (_T("send_APDU() returns 0x%08lX (%s)\n"),
						  status.errorCode, status.errorMessage);
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
            else
            {
                _tprintf(_T("Unknown command %s\n"), token);
                rv = EXIT_FAILURE;
                goto end;
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
    return rv;
}

int main(int argc, char* argv[])
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
        fd = fopen (argv[1], "r");
        // error
        if (fd == NULL)
        {
            fprintf(stderr, "Could not open scriptfile !\n");
            rv = EXIT_FAILURE;
            goto end;
        }
    }
    else
    {
        // error
        fprintf (stderr, "Usage: gpshell [scriptfile]\n");
        rv = EXIT_FAILURE;
        goto end;
    }

    // launch the command interpreter
    rv = handleCommands(fd);
end:
    return rv;
}
