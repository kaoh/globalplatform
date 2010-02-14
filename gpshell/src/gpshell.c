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

#include "globalplatform/globalplatform.h"

#ifndef WIN32
#define _snprintf snprintf
#define _fgetts fgets
#define _tcscmp strcmp
#endif

/* Constants */
#define BUFLEN 1024
#define FILENAMELEN 256
#define READERNAMELEN 256
#define AIDLEN 16
#define APDULEN 261
#define INSTPARAMLEN 32
#define DELIMITER " \t\n,"
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
    unsigned char key[DDES_KEY_LEN];
    unsigned char mac_key[DDES_KEY_LEN];
    unsigned char enc_key[DDES_KEY_LEN];
    unsigned char kek_key[DDES_KEY_LEN];
    unsigned char current_kek[DDES_KEY_LEN];
    BYTE securityLevel;
    char AID[AIDLEN+1];
    int AIDLen;
    char sdAID[AIDLEN+1];
    int sdAIDLen;
    char pkgAID[AIDLEN+1];
    int pkgAIDLen;
    char instAID[AIDLEN+1];
    int instAIDLen;
    char APDU[APDULEN+1];
    int APDULen;
    int secureChannel;
    TCHAR reader[READERNAMELEN+1];
    int readerNumber;
    int protocol;
    int nvCodeLimit;
    int nvDataLimit;
    int vDataLimit;
    TCHAR file[FILENAMELEN+1];
    char passPhrase[PASSPHRASELEN+1];
    char instParam[INSTPARAMLEN+1];
    int instParamLen;
    BYTE element;
    BYTE privilege;
    BYTE scp;
    BYTE scpImpl;
} OptionStr;

/* Global Variables */
static OPGP_CARD_CONTEXT cardContext;
static OPGP_CARD_INFO cardInfo;
static OP201_SECURITY_INFO securityInfo201;
static GP211_SECURITY_INFO securityInfo211;
static int platform_mode = OP_201;
static int visaKeyDerivation = 0;
static int timer = 0;
static char selectedAID[AIDLEN+1];
static int selectedAIDLength = 0;

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

static void ConvertCToT(TCHAR* pszDest, const char* pszSrc)
{
    unsigned int i;

    for (i = 0; i < strlen(pszSrc); i++)
    {
        pszDest[i] = (TCHAR) pszSrc[i];
    }

    pszDest[strlen(pszSrc)] = _T('\0');
}

static int ConvertStringToByteArray(char *src, int maxLength, char *dest)
{
    char dummy[BUFLEN+1];
    int temp, i = 0;
    strncpy(dummy, src, maxLength*2+1);
    dummy[maxLength*2] = '\0';
    while (sscanf (&(dummy[i*2]), "%02x", &temp) > 0)
    {
        dest[i] = temp;
        i++;
    }
    return i;
}

static char *strtokCheckComment(char *buf)
{
    char *token;
    char dummy[BUFLEN];
    int avail = sizeof(dummy);
    int size = 0, read = 0;

    token = strtok (buf, DELIMITER);

    if (token == NULL)
        return NULL;

    /* Check for quoted string */
    if (token[0] == '"')
    {
        size = _snprintf(dummy, avail, "%s", token+1);
        avail -= size;
        read += size;
        token = strtok (buf, "\"");
        if (token == NULL)
            return NULL;
        if (size > 0)
        {
            _snprintf(dummy+read, avail, " %s", token);
        }
        dummy[sizeof(dummy)-1] = '\0';

        /* Skip next delimiter */
        token = strtok (buf, DELIMITER);

        token = dummy;
        return token;
    }

    if (strcmp(token, "//") == 0 || strcmp(token, "#") == 0)
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
    char *token;
    char dummy[BUFLEN+1];

    pOptionStr->keyIndex = 0;
    pOptionStr->keySetVersion = 0;
    pOptionStr->newKeySetVersion = 0;
    pOptionStr->securityLevel = 0;
    pOptionStr->AID[0] = '\0';
    pOptionStr->AIDLen = 0;
    pOptionStr->sdAID[0] = '\0';
    pOptionStr->sdAIDLen = 0;
    pOptionStr->pkgAID[0] = '\0';
    pOptionStr->pkgAIDLen = 0;
    pOptionStr->instAID[0] = '\0';
    pOptionStr->instAIDLen = 0;
    pOptionStr->APDU[0] = '\0';
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

    token = strtokCheckComment(NULL);

    while (token != NULL)
    {
        if (_tcscmp(token, _T("-keyind")) == 0)
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
                pOptionStr->keyIndex = atoi(token);
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
                pOptionStr->keySetVersion = atoi(token);
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
                pOptionStr->newKeySetVersion = atoi(token);
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
                if (atoi(token) == 0)
                    pOptionStr->secureChannel = 0;
                else if (atoi(token) == 1)
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
                pOptionStr->securityLevel = atoi(token);
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
                if (_tcscmp(token,"0") == 0)
                {
                    _tprintf(_T("Error: option -readerNumber must be followed by number > 0\n"));
                    rv = EXIT_FAILURE;
                    goto end;
                }
                pOptionStr->readerNumber = atoi(token)-1;
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
                strncpy(dummy, token, READERNAMELEN+1);
                dummy[READERNAMELEN] = '\0';
                ConvertCToT (pOptionStr->reader, dummy);
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
                strncpy(dummy, token, FILENAMELEN+1);
                dummy[FILENAMELEN] = '\0';
                ConvertCToT (pOptionStr->file, dummy);
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
                strncpy(pOptionStr->passPhrase, token, PASSPHRASELEN+1);
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
                if (atoi(token) == 0)
                {
                    pOptionStr->protocol = OPGP_CARD_PROTOCOL_T0;
                }
                else if (atoi(token) == 1)
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
                pOptionStr->nvCodeLimit = atoi(token);
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
                pOptionStr->nvDataLimit = atoi(token);
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
                pOptionStr->vDataLimit = atoi(token);
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

            if (sscanf (token, "%02x", &temp) <= 0)
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
                pOptionStr->privilege = atoi(token);
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
                pOptionStr->scp = atoi(token);
            }
        }
        else if (_tcscmp(token, _T("-scpimpl")) == 0)
        {
            char **dummy = NULL;
            token = strtokCheckComment(NULL);
            if (token == NULL)
            {
                _tprintf(_T("Error: option -scpimpl not followed by data\n"));
                rv = EXIT_FAILURE;
                goto end;
            }
            else
            {
                pOptionStr->scpImpl = (int)strtol(token, dummy, 0);
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
	unsigned int it, ft;
    OPGP_ERROR_STATUS status;
    TCHAR *token;
    OptionStr optionStr;

    while (_fgetts (buf, BUFLEN, fd) != NULL)
    {

        // copy command line for printing it out later
        strncpy (commandLine, buf, BUFLEN);

        token = strtokCheckComment(buf);
        while (token != NULL)
        {
            if (token[0] == _T('#') || strncmp (token, _T("//"), 2) == 0)
                break;

            // get the initial time
            if (timer)
            {
                it = GetTime();
            }

            // print command line
            printf("%s", commandLine);

            if (_tcscmp(token, "establish_context") == 0)
            {
                // Establish context
                _tcsncpy(cardContext.libraryName, _T("gppcscconnectionplugin"),
                         sizeof(cardContext.libraryName));
                _tcsncpy(cardContext.libraryVersion, _T("1.0.0"),
                         sizeof(cardContext.libraryVersion));
                status = OPGP_establish_context(&cardContext);
                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("establish_context failed with error 0x%08lX (%s)\n"), status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }
                break;
            }
            else if (_tcscmp(token, "release_context") == 0)
            {
                // Release context
                status = OPGP_release_context(&cardContext);
                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("release_context failed with error 0x%08lX (%s)\n"), status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }

                break;
            }
            else if (_tcscmp(token, "card_connect") == 0)
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


                        // if auto reader, connects now
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

                if (optionStr.readerNumber != AUTOREADER)
                {
                    status = OPGP_card_connect (cardContext, optionStr.reader, &cardInfo, optionStr.protocol);
                }

                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("card_connect() returns 0x%08lX (%s)\n"), status.errorCode, status.errorMessage);
                }
                // set mode for internal use of library
                cardInfo.specVersion = platform_mode;
                break;
            }
            if (_tcscmp(token, "open_sc") == 0)
            {
                // open secure channel
                rv = handleOptions(&optionStr);
                if (rv != EXIT_SUCCESS)
                {
                    goto end;
                }
                if (visaKeyDerivation)
                {
                    status = OPGP_VISA2_derive_keys(cardContext, cardInfo, selectedAID, selectedAIDLength, optionStr.key,
                                                optionStr.enc_key, optionStr.mac_key, optionStr.kek_key);
                    if (OPGP_ERROR_CHECK(status))
                    {
                        _tprintf (_T("OPGP_VISA2_derive_keys() returns 0x%08lX (%s)\n"),
                                  status.errorCode, status.errorMessage);
                        rv = EXIT_FAILURE;
                        goto end;
                    }
                }

                if (platform_mode == PLATFORM_MODE_OP_201)
                {
                    status = OP201_mutual_authentication(cardContext, cardInfo,
                                                     optionStr.enc_key,
                                                     optionStr.mac_key,
                                                     optionStr.kek_key,
                                                     optionStr.keySetVersion,
                                                     optionStr.keyIndex,
                                                     optionStr.securityLevel,
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
                                                     &securityInfo211);

                }

                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("mutual_authentication() returns 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }

                break;
            }
            else if (_tcscmp(token, "select") == 0)
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
                break;
            }
            else if (_tcscmp(token, "get_data") == 0)
            {
                // Get Data
                rv = handleOptions(&optionStr);
                if (rv != EXIT_SUCCESS)
                {
                    goto end;
                }
                // TODO: get data
                break;
            }
            else if (_tcscmp(token, "load") == 0)
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
                    _tprintf (_T("load_applet() returns 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
                    rv = EXIT_FAILURE;
                    goto end;
                }

                break;
            }
            else if (_tcscmp(token, "delete") == 0)
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
                AIDs[0].AIDLength = optionStr.AIDLen;

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
                    _tprintf (_T("delete_applet() returns 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
                }
                break;
                /* Augusto: added delete_key command support */
            }
            else if (_tcscmp(token, "delete_key") == 0)
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
                break;
                /* end */
            }
            else if (_tcscmp(token, "install") == 0)
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
                if (rv != EXIT_SUCCESS)
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
                                                optionStr.nvDataLimit); // jvictor
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
                    _tprintf (_T("load_applet() returns 0x%08lX (%s)\n"),
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
                break;
            }
            else if (_tcscmp(token, "install_for_load") == 0)
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
                break;
            }
            else if (_tcscmp(token, "install_for_install") == 0)
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

                break;
            }
            else if (_tcscmp(token, "card_disconnect") == 0)
            {
                // disconnect card
                OPGP_card_disconnect(cardContext, &cardInfo);

                break;
            }
            else if (_tcscmp(token, "put_sc_key") == 0)
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
                break;
            }
            else if (_tcscmp(token, "put_dm_keys") == 0)
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
                break;
            }
            else if (_tcscmp(token, "get_status") == 0)
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

                break;
            }
            else if (_tcscmp(token, "send_apdu") == 0 || _tcscmp(token, "send_apdu_nostop") == 0)
            {
                unsigned char recvAPDU[258];
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
                if (OPGP_ERROR_CHECK(status))
                {
                    _tprintf (_T("send_APDU() returns 0x%08lX (%s)\n"),
                              status.errorCode, status.errorMessage);
                    // if the command was nostop, don't quit
                    if (_tcscmp(token, "send_apdu_nostop") != 0)
                    {
                        rv = EXIT_FAILURE;
                        goto end;
                    }
                }

                break;
            }
            else if (_tcscmp(token, "mode_201") == 0)
            {
                platform_mode = PLATFORM_MODE_OP_201;
                break;
            }
            else if (_tcscmp(token, "mode_211") == 0)
            {
                platform_mode = PLATFORM_MODE_GP_211;
                break;
            }
            else if (_tcscmp(token, "enable_trace") == 0)
            {
                OPGP_enable_trace_mode(OPGP_TRACE_MODE_ENABLE, NULL);
                break;
                // gemXpressoPro and visa_key_derivation are the same, gemXpressoPro is for backward compatibility
            }
            else if (_tcscmp(token, "gemXpressoPro") == 0)
            {
                visaKeyDerivation = 1;
                break;
            }
            else if (_tcscmp(token, "visa_key_derivation") == 0)
            {
                visaKeyDerivation = 1;
                break;
            }
            else if (_tcscmp(token, "enable_timer") == 0)
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

			// get the final time and calculate the total time of the command
			if (timer)
			{
				ft = GetTime();
				_tprintf(_T("command time: %u ms\n"), (ft - it));
			}

            token = strtokCheckComment(NULL);
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
