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
/* GPShell.c */
/* TODO: make Unicode conform */
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

#include "GlobalPlatform/GlobalPlatform.h"

#ifndef WIN32
#define _snprintf snprintf
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
typedef struct _OptionStr {
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
	int apduTime;
} OptionStr;

/* Global Variables */
static OPGP_CARDCONTEXT cardContext;
static OPGP_CARD_INFO cardInfo;
static OP201_SECURITY_INFO securityInfo201;
static GP211_SECURITY_INFO securityInfo211;
static int platform_mode = PLATFORM_MODE_OP_201;
static int gemXpressoPro = 0;
static char selectedAID[AIDLEN+1];
static int selectedAIDLength = 0;

static unsigned int GetTime() {
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

    for(i = 0; i < _tcslen(pszSrc); i++)
	pszDest[i] = (char) pszSrc[i];

    pszDest[_tcslen(pszSrc)] = '\0';
}

static void ConvertCToT(TCHAR* pszDest, const char* pszSrc)
{
    unsigned int i;

	for(i = 0; i < strlen(pszSrc); i++) {
		pszDest[i] = (TCHAR) pszSrc[i];
	}

    pszDest[strlen(pszSrc)] = _T('\0');
}

static int ConvertStringToByteArray(char *src, int maxLength, char *dest) {
	char dummy[BUFLEN+1];
	int temp, i = 0;
	strncpy(dummy, src, maxLength*2+1);
	dummy[maxLength*2] = '\0';
	while (sscanf (&(dummy[i*2]), "%02x", &temp) > 0) {
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
	if (token[0] == '"') {
		size = _snprintf(dummy, avail, "%s", token+1);
		avail -= size;
		read += size;
		token = strtok (buf, "\"");
		if (token == NULL)
			return NULL;
		if (size > 0) {
			_snprintf(dummy+read, avail, " %s", token);
		}
		dummy[sizeof(dummy)-1] = '\0';

		/* Skip next delimiter */
		token = strtok (buf, DELIMITER);

		token = dummy;
		return token;
	}

    if (strcmp(token, "//") == 0 || strcmp(token, "#") == 0) {
	return NULL;
    } else {
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
	pOptionStr->apduTime = 0;

    token = strtokCheckComment(NULL);

    while (token != NULL) {
	if (strcmp(token, "-keyind") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -keyind not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
		pOptionStr->keyIndex = atoi(token);
	    }
	} else if (strcmp(token, "-keyver") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -keyver not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
		} else {
		pOptionStr->keySetVersion = atoi(token);
	    }
	} else if (strcmp(token, "-newkeyver") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -newkeyver not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
		pOptionStr->newKeySetVersion = atoi(token);
	    }
	} else if (strcmp(token, "-sc") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -sc not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
		if (atoi(token) == 0)
		    pOptionStr->secureChannel = 0;
		else if (atoi(token) == 1)
		    pOptionStr->secureChannel = 1;
		else {
		    printf ("Error: option -sc not followed 0 (secure channel off) or 1 (secure channel on)\n");
			rv = EXIT_FAILURE;
			goto end;
		}
	    }
	} else if (strcmp(token, "-security") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -security not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
			pOptionStr->securityLevel = atoi(token);
	    }
	} else if (strcmp(token, "-readerNumber") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -readerNumber not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
			if (strcmp(token,"0") == 0) {
		    	printf("Error: option -readerNumber must be followed by number > 0\n");
				rv = EXIT_FAILURE;
				goto end;
			}
			pOptionStr->readerNumber = atoi(token)-1;
	    }
	} else if (strcmp(token, "-reader") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -reader not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
			strncpy(dummy, token, READERNAMELEN+1);
			dummy[READERNAMELEN] = '\0';
			ConvertCToT (pOptionStr->reader, dummy);
#ifdef DEBUG
		_tprintf ( _T("reader name %s\n"), pOptionStr->reader);
#endif
	    }
	} else if (strcmp(token, "-file") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -file not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
			strncpy(dummy, token, FILENAMELEN+1);
			dummy[FILENAMELEN] = '\0';
			ConvertCToT (pOptionStr->file, dummy);
#ifdef DEBUG
		_tprintf ( _T("file name %s\n"), pOptionStr->file);
#endif
	    }
	} else if (strcmp(token, "-pass") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -pass not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
			strncpy(pOptionStr->passPhrase, token, PASSPHRASELEN+1);
			pOptionStr->passPhrase[PASSPHRASELEN] = '\0';
#ifdef DEBUG
		printf ( "file name %s\n", pOptionStr->passPhrase[PASSPHRASELEN]);
#endif
	    }
	} else if (strcmp(token, "-key") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -key not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {

		ConvertStringToByteArray(token, DDES_KEY_LEN, pOptionStr->key);
	    }
	} else if (strcmp(token, "-mac_key") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -key not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {

		ConvertStringToByteArray(token, DDES_KEY_LEN, pOptionStr->mac_key);
	    }
	} else if (strcmp(token, "-enc_key") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -enc_key not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {

		ConvertStringToByteArray(token, DDES_KEY_LEN, pOptionStr->enc_key);
	    }
	} else if (strcmp(token, "-kek_key") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -kek_key not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {

		ConvertStringToByteArray(token, DDES_KEY_LEN, pOptionStr->kek_key);
	    }
	} else if (strcmp(token, "-current_kek") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -current_kek not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {

		ConvertStringToByteArray(token, DDES_KEY_LEN, pOptionStr->current_kek);
		}
	} else if (strcmp(token, "-AID") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -AID not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
			pOptionStr->AIDLen = ConvertStringToByteArray(token, AIDLEN, pOptionStr->AID);
	    }
	} else if (strcmp(token, "-sdAID") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -sdAID not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
			pOptionStr->sdAIDLen = ConvertStringToByteArray(token, AIDLEN, pOptionStr->sdAID);
	    }
	} else if (strcmp(token, "-pkgAID") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -pkgAID not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
			pOptionStr->pkgAIDLen = ConvertStringToByteArray(token, AIDLEN, pOptionStr->pkgAID);
	    }
	} else if (strcmp(token, "-instAID") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -instAID not followed by data\n");
		exit (EXIT_FAILURE);
	    } else {
			pOptionStr->instAIDLen = ConvertStringToByteArray(token, AIDLEN, pOptionStr->instAID);
	    }
	} else if (strcmp(token, "-APDU") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -APDU not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
			pOptionStr->APDULen = ConvertStringToByteArray(token, APDULEN, pOptionStr->APDU);
	    }
	} else if (strcmp(token, "-protocol") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -protocol not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
		if (atoi(token) == 0) {
		    pOptionStr->protocol = OPGP_CARD_PROTOCOL_T0;
		} else if (atoi(token) == 1) {
		    pOptionStr->protocol = OPGP_CARD_PROTOCOL_T1;
		} else {
		    printf ("Unknown protocol type %s\n", token);
			rv = EXIT_FAILURE;
			goto end;
		}
	    }
	} else if (strcmp(token, "-nvCodeLimit") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -nvCodeLimit not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
		pOptionStr->nvCodeLimit = atoi(token);
	    }
	} else if (strcmp(token, "-nvDataLimit") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -nvDataLimit not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
		pOptionStr->nvDataLimit = atoi(token);
	    }
	} else if (strcmp(token, "-vDataLimit") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -vDataLimit not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
		pOptionStr->vDataLimit = atoi(token);
	    }
	} else if (strcmp(token, "-instParam") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -instParam not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
			pOptionStr->instParamLen = ConvertStringToByteArray(token, INSTPARAMLEN, pOptionStr->instParam);
	    }
	} else if (strcmp(token, "-element") == 0) {
		int temp;
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -element not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    }

		if (sscanf (token, "%02x", &temp) <= 0) {
			printf ("Error: option -element followed by an illegal string %s\n",
			token);
			rv = EXIT_FAILURE;
			goto end;
	    }
		pOptionStr->element = temp;
	} else if (strcmp(token, "-priv") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -priv not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
		pOptionStr->privilege = atoi(token);
	    }
	} else if (strcmp(token, "-scp") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -scp not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
		pOptionStr->scp = atoi(token);
	    }
	} else if (strcmp(token, "-scpimpl") == 0) {
          char **dummy = NULL;
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
			printf ("Error: option -scpimpl not followed by data\n");
			rv = EXIT_FAILURE;
			goto end;
	    } else {
              pOptionStr->scpImpl = (int)strtol(token, dummy, 0);
	    }
	} else if (strcmp(token, "-time") == 0) {
		pOptionStr->apduTime = 1;
	} else {
	    // unknown option
	    printf ("Error: unknown option %s\n", token);
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
    char buf[BUFLEN + 1], commandLine[BUFLEN + 1];
    int rv = EXIT_SUCCESS, i;
    char *token;
    OptionStr optionStr;

    while (fgets (buf, BUFLEN, fd) != NULL) {

	// copy command line for printing it out later
	strncpy (commandLine, buf, BUFLEN);

	token = strtokCheckComment(buf);
	while (token != NULL) {
	    if (token[0] == '#' || strncmp (token, "//", 2) == 0)
		break;

	    // print command line
	    printf ("%s", commandLine);

	    if (strcmp(token, "establish_context") == 0) {
		// Establish context
		rv = establish_context(&cardContext);
		if (rv != OPGP_ERROR_SUCCESS) {
		    printf ("establish_context failed with error 0x%08X (%s)\n", rv, stringify_error(rv));
			rv = EXIT_FAILURE;
			goto end;
		}
		break;
	    } else if (strcmp(token, "release_context") == 0) {
		// Release context
		rv = release_context(cardContext);
		if (rv != OPGP_ERROR_SUCCESS) {
		    printf ("release_context failed with error 0x%08X (%s)\n", rv, stringify_error(rv));
			rv = EXIT_FAILURE;
			goto end;
		}

		break;
	    } else if (strcmp(token, "card_connect") == 0) {
		TCHAR buf[BUFLEN + 1];
		DWORD readerStrLen = BUFLEN;
		// open reader
		rv = handleOptions(&optionStr);
		if (rv != EXIT_SUCCESS) {
			goto end;
		}
		if (_tcslen(optionStr.reader) == 0) {
			int j=0;
			int k=0;

			// get all readers
		    rv = list_readers (cardContext, buf, &readerStrLen);
			if (rv != OPGP_ERROR_SUCCESS) {
				printf ("list_readers failed with error 0x%08X (%s)\n", rv, stringify_error(rv));
				rv = EXIT_FAILURE;
				goto end;
			}

			for (j=0; j<(int)readerStrLen;) {
				// Check for end of readers
				if (buf[j] == _T('\0'))
					break;
				_tcsncpy(optionStr.reader, buf+j, READERNAMELEN+1);


				// if auto reader, connects now
				if (optionStr.readerNumber == AUTOREADER) {
	        		rv = card_connect(cardContext, optionStr.reader, &cardInfo, optionStr.protocol);
					if (rv == 0) {
						break;
					}
				} 
				else if (k == optionStr.readerNumber) {
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

		if (optionStr.readerNumber != AUTOREADER) {
		   	rv = card_connect (cardContext, optionStr.reader, &cardInfo, optionStr.protocol);
		}

		if (rv != 0) {
		    _tprintf (_T("card_connect() returns 0x%08X (%s)\n"), rv,
			      stringify_error(rv));
		}
		// set mode for internal use of library
		cardInfo.specVersion = platform_mode;
		break;
	    } if (strcmp(token, "open_sc") == 0) {
		// open secure channel
		rv = handleOptions(&optionStr);
		if (rv != EXIT_SUCCESS) {
			goto end;
		}
		if (gemXpressoPro) {
			rv = GemXpressoPro_create_daughter_keys(cardInfo, selectedAID, selectedAIDLength, optionStr.key,
				optionStr.enc_key, optionStr.mac_key, optionStr.kek_key);
			if (rv != 0) {
				_tprintf (_T("GemXpressoPro_create_daughter_keys() returns 0x%08X (%s)\n"),
					rv, stringify_error(rv));
				rv = EXIT_FAILURE;
				goto end;
			}
		}

		if (platform_mode == PLATFORM_MODE_OP_201) {
		    rv = OP201_mutual_authentication(cardInfo,
						     optionStr.enc_key,
						     optionStr.mac_key,
							 optionStr.kek_key,
						     optionStr.keySetVersion,
						     optionStr.keyIndex,
						     optionStr.securityLevel,
						     &securityInfo201);
		} else if (platform_mode == PLATFORM_MODE_GP_211) {
			if (optionStr.scp == 0 || optionStr.scpImpl == 0) {
				rv = GP211_get_secure_channel_protocol_details(cardInfo,
					&optionStr.scp,
					&optionStr.scpImpl);
				if (rv != 0) {
					_tprintf (_T("GP211_get_secure_channel_protocol_details() returns 0x%08X (%s)\n"),
						rv, stringify_error(rv));
					rv = EXIT_FAILURE;
					goto end;
				}
			}

		    rv = GP211_mutual_authentication(cardInfo,
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

		if (rv != 0) {
		    _tprintf (_T("mutual_authentication() returns 0x%08X (%s)\n"),
			      rv, stringify_error(rv));
			rv = EXIT_FAILURE;
			goto end;
		}

		break;
	    } else if (strcmp(token, "select") == 0) {
		// select instance
		rv = handleOptions(&optionStr);
		if (rv != EXIT_SUCCESS) {
			goto end;
		}
		rv = select_application (cardInfo,
                                         (PBYTE)optionStr.AID, optionStr.AIDLen);
		if (rv != 0) {
		    _tprintf (_T("select_application() returns 0x%08X (%s)\n"),
			      rv, stringify_error(rv));
			rv = EXIT_FAILURE;
			goto end;
		}
		memcpy(selectedAID, optionStr.AID, optionStr.AIDLen);
		selectedAIDLength = optionStr.AIDLen;
		break;
	    } else if (strcmp(token, "getdata") == 0) {
		// Get Data
		rv = handleOptions(&optionStr);
		if (rv != EXIT_SUCCESS) {
			goto end;
		}
		// TODO: get data
		break;
	    } else if (strcmp(token, "load") == 0) {
		// Load Applet
		DWORD receiptDataLen = 0;
		rv = handleOptions(&optionStr);
		if (rv != EXIT_SUCCESS) {
			goto end;
		}
		if (platform_mode == PLATFORM_MODE_OP_201) {
		    rv = OP201_load(cardInfo, &securityInfo201,
				    NULL, 0,
				    optionStr.file,
				    NULL, &receiptDataLen);
		} else if (platform_mode == PLATFORM_MODE_GP_211) {
		    rv = GP211_load(cardInfo, &securityInfo211,
				    NULL, 0,
				    optionStr.file,
				    NULL, &receiptDataLen);
		}

		if (rv != 0) {
		    _tprintf (_T("load_applet() returns 0x%08X (%s)\n"),
			      rv, stringify_error(rv));
			rv = EXIT_FAILURE;
			goto end;
		}

		break;
	    }  else if (strcmp(token, "delete") == 0) {
		// Delete Applet
		OPGP_AID AIDs[1];

		DWORD receiptLen = 10;

		rv = handleOptions(&optionStr);
		if (rv != EXIT_SUCCESS) {
			goto end;
		}
		memcpy (AIDs[0].AID, optionStr.AID, optionStr.AIDLen);
		AIDs[0].AIDLength = optionStr.AIDLen;

		if (platform_mode == PLATFORM_MODE_OP_201) {
		    OP201_RECEIPT_DATA receipt[10];
		    rv = OP201_delete_application(cardInfo, &securityInfo201,
					      AIDs, 1,
					      (OP201_RECEIPT_DATA *)receipt,
					      &receiptLen);
		} else if (platform_mode == PLATFORM_MODE_GP_211) {
		    GP211_RECEIPT_DATA receipt[10];
		    rv = GP211_delete_application(cardInfo, &securityInfo211,
						  AIDs, 1,
						  (GP211_RECEIPT_DATA *)receipt,
						  &receiptLen);

		}

		if (rv != 0) {
		    _tprintf (_T("delete_applet() returns 0x%08X (%s)\n"),
			      rv, stringify_error(rv));
		}
		break;
		/* Augusto: added delete_key command support */
	    } else if (strcmp(token, "delete_key") == 0) {

			rv = handleOptions(&optionStr);
			if(rv != EXIT_SUCCESS) {
				goto end;
			}

			if(platform_mode == PLATFORM_MODE_OP_201) {
				rv = OP201_delete_key
				(
					cardInfo,
					&securityInfo201,
					optionStr.keySetVersion,
					optionStr.keyIndex
				);
			} else if (platform_mode == PLATFORM_MODE_GP_211) {
				rv = GP211_delete_key
				(
					cardInfo,
					&securityInfo211,
					optionStr.keySetVersion,
					optionStr.keyIndex
				);
			}

			if(rv != 0) {
				_tprintf (_T("delete_key() return 0x%08x (%s)\n"),
					rv, stringify_error(rv));
			}
			break;
		/* end */
		} else if (strcmp(token, "install") == 0) {
			// One step install
			OPGP_LOAD_FILE_PARAMETERS loadFileParams;
			DWORD receiptDataAvailable = 0;
			DWORD receiptDataLen = 0;
			char installParam[1];
			installParam[0] = 0;

			rv = handleOptions(&optionStr);
			if (rv != EXIT_SUCCESS) {
				goto end;
			}
			rv = read_executable_load_file_parameters(optionStr.file, &loadFileParams);
			if (rv != EXIT_SUCCESS) {
				_tprintf (_T("read_executable_load_file_parameters() returns 0x%08X (%s)\n"),
					rv, stringify_error(rv));
				rv = EXIT_FAILURE;
				goto end;
			}
			if (optionStr.pkgAIDLen == 0) {
				optionStr.pkgAIDLen = loadFileParams.loadFileAID.AIDLength;
				memcpy(optionStr.pkgAID, loadFileParams.loadFileAID.AID, optionStr.pkgAIDLen);
			}
			if (optionStr.AIDLen == 0) {
				optionStr.AIDLen = loadFileParams.appletAIDs[0].AIDLength;
				memcpy(optionStr.AID, loadFileParams.appletAIDs[0].AID, optionStr.AIDLen);
			}
			if (optionStr.instAIDLen == 0) {
				optionStr.instAIDLen = loadFileParams.appletAIDs[0].AIDLength;
				memcpy(optionStr.instAID, loadFileParams.appletAIDs[0].AID, optionStr.instAIDLen);
			}
			if (optionStr.nvCodeLimit == 0) {
				optionStr.nvCodeLimit = loadFileParams.loadFileSize;
			}
			if (platform_mode == PLATFORM_MODE_OP_201) {
				if (optionStr.sdAIDLen == 0) {
					if (selectedAIDLength != 0) {
						optionStr.sdAIDLen = selectedAIDLength;
						memcpy(optionStr.sdAID, selectedAID, selectedAIDLength);
					}
					else {
						optionStr.sdAIDLen = sizeof(OP201_CARD_MANAGER_AID);
						memcpy(optionStr.sdAID, OP201_CARD_MANAGER_AID, optionStr.sdAIDLen);
					}
				}
				rv = OP201_install_for_load(cardInfo, &securityInfo201,
							(PBYTE)optionStr.pkgAID, optionStr.pkgAIDLen,
							(PBYTE)optionStr.sdAID, optionStr.sdAIDLen,
						NULL, NULL,
						optionStr.nvCodeLimit,
						optionStr.vDataLimit,  // jvictor
						optionStr.nvDataLimit); // jvictor
			} else if (platform_mode == PLATFORM_MODE_GP_211) {
				if (optionStr.sdAIDLen == 0) {
					if (selectedAIDLength != 0) {
						optionStr.sdAIDLen = selectedAIDLength;
						memcpy(optionStr.sdAID, selectedAID, selectedAIDLength);
					}
					else {
						optionStr.sdAIDLen = sizeof(GP211_CARD_MANAGER_AID);
						memcpy(optionStr.sdAID, GP211_CARD_MANAGER_AID, optionStr.sdAIDLen);
					}
				}
				rv = GP211_install_for_load(cardInfo, &securityInfo211,
							(PBYTE)optionStr.pkgAID, optionStr.pkgAIDLen,
							(PBYTE)optionStr.sdAID, optionStr.sdAIDLen,
							NULL, NULL,
							optionStr.nvCodeLimit,
							optionStr.vDataLimit,          // jvictor
							optionStr.nvDataLimit);        // jvictor
			}

			if (rv != 0) {
				_tprintf (_T("install_for_load() returns 0x%08X (%s)\n"),
					rv, stringify_error(rv));
				rv = EXIT_FAILURE;
				goto end;
			}
			if (platform_mode == PLATFORM_MODE_OP_201) {
				rv = OP201_load(cardInfo, &securityInfo201,
						NULL, 0,
						optionStr.file,
						NULL, &receiptDataLen);
			} else if (platform_mode == PLATFORM_MODE_GP_211) {
				rv = GP211_load(cardInfo, &securityInfo211,
						NULL, 0,
						optionStr.file,
						NULL, &receiptDataLen);
			}

			if (rv != 0) {
				_tprintf (_T("load_applet() returns 0x%08X (%s)\n"),
					rv, stringify_error(rv));
				rv = EXIT_FAILURE;
				goto end;
			}

			if (platform_mode == PLATFORM_MODE_OP_201) {
				OP201_RECEIPT_DATA receipt;
				rv = OP201_install_for_install_and_make_selectable(
							cardInfo, &securityInfo201,
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
			} else if (platform_mode == PLATFORM_MODE_GP_211) {
				GP211_RECEIPT_DATA receipt;

				rv = GP211_install_for_install_and_make_selectable(
						cardInfo, &securityInfo211,
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

			if (rv != 0) {
				_tprintf (_T("install_for_install_and_make_selectable() returns 0x%08X (%s)\n"),
					rv, stringify_error(rv));
				rv = EXIT_FAILURE;
				goto end;
			}
			break;
		}
	    else if (strcmp(token, "install_for_load") == 0) {
		// Install for Load
		rv = handleOptions(&optionStr);
		if (rv != EXIT_SUCCESS) {
			goto end;
		}
		if (platform_mode == PLATFORM_MODE_OP_201) {
			if (optionStr.sdAIDLen == 0) {
				if (selectedAIDLength != 0) {
					optionStr.sdAIDLen = selectedAIDLength;
					memcpy(optionStr.sdAID, selectedAID, selectedAIDLength);
				}
				else {
					optionStr.sdAIDLen = sizeof(OP201_CARD_MANAGER_AID);
					memcpy(optionStr.sdAID, OP201_CARD_MANAGER_AID, optionStr.sdAIDLen);
				}
			}
			rv = OP201_install_for_load(cardInfo, &securityInfo201,
                        (PBYTE)optionStr.pkgAID, optionStr.pkgAIDLen,
                        (PBYTE)optionStr.sdAID, optionStr.sdAIDLen,
				      NULL, NULL,
				      optionStr.nvCodeLimit,
				      optionStr.vDataLimit,  // jvictor
				      optionStr.nvDataLimit);// jvictor
		} else if (platform_mode == PLATFORM_MODE_GP_211) {
			if (optionStr.sdAIDLen == 0) {
				if (selectedAIDLength != 0) {
					optionStr.sdAIDLen = selectedAIDLength;
					memcpy(optionStr.sdAID, selectedAID, selectedAIDLength);
				}
				else {
					optionStr.sdAIDLen = sizeof(GP211_CARD_MANAGER_AID);
					memcpy(optionStr.sdAID, GP211_CARD_MANAGER_AID, optionStr.sdAIDLen);
				}
			}
			rv = GP211_install_for_load(cardInfo, &securityInfo211,
                        (PBYTE)optionStr.pkgAID, optionStr.pkgAIDLen,
                        (PBYTE)optionStr.sdAID, optionStr.sdAIDLen,
					    NULL, NULL,
					    optionStr.nvCodeLimit,
					    optionStr.vDataLimit,   // jvictor
					    optionStr.nvDataLimit); // jvictor
		}

		if (rv != 0) {
		    _tprintf (_T("install_for_load() returns 0x%08X (%s)\n"),
			      rv, stringify_error(rv));
			rv = EXIT_FAILURE;
			goto end;
		}
		break;
	    } else if (strcmp(token, "install_for_install") == 0) {


		DWORD receiptDataAvailable = 0;
		char installParam[1];
		installParam[0] = 0;

		// Install for Install
		rv = handleOptions(&optionStr);
		if (rv != EXIT_SUCCESS) {
			goto end;
		}
		if (platform_mode == PLATFORM_MODE_OP_201) {
		    OP201_RECEIPT_DATA receipt;
		    rv = OP201_install_for_install_and_make_selectable(
				         cardInfo, &securityInfo201,
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
		} else if (platform_mode == PLATFORM_MODE_GP_211) {
		    GP211_RECEIPT_DATA receipt;

		    rv = GP211_install_for_install_and_make_selectable(
					cardInfo, &securityInfo211,
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

		if (rv != 0) {
		    _tprintf (_T("install_for_install_and_make_selectable() returns 0x%08X (%s)\n"),
			      rv, stringify_error(rv));
			rv = EXIT_FAILURE;
			goto end;
		}

		break;
	    } else if (strcmp(token, "card_disconnect") == 0) {
		// disconnect card
		card_disconnect(cardInfo);

		break;
	    } else if (strcmp(token, "put_sc_key") == 0) {
		rv = handleOptions(&optionStr);
		if (rv != EXIT_SUCCESS) {
			goto end;
		}
		if (platform_mode == PLATFORM_MODE_OP_201) {
		    rv = OP201_put_secure_channel_keys(cardInfo, &securityInfo201,
						       optionStr.keySetVersion,
						       optionStr.newKeySetVersion,
						       optionStr.enc_key,
						       optionStr.mac_key,
						       optionStr.kek_key,
						       optionStr.current_kek);
		} else if (platform_mode == PLATFORM_MODE_GP_211) {
		    rv = GP211_put_secure_channel_keys(cardInfo,
						       &securityInfo211,
						       optionStr.keySetVersion,
						       optionStr.newKeySetVersion,
						       NULL,
						       optionStr.enc_key,
						       optionStr.mac_key,
						       optionStr.kek_key);
		}

		if (rv != 0) {
		    _tprintf (_T("put_secure_channel_keys() returns 0x%08X (%s)\n"),
			      rv, stringify_error(rv));
			rv = EXIT_FAILURE;
			goto end;
		}
		break;
	    } else if (strcmp(token, "put_dm_keys") == 0) {
		rv = handleOptions(&optionStr);
		if (rv != EXIT_SUCCESS) {
			goto end;
		}
		if (platform_mode == PLATFORM_MODE_OP_201) {
		    rv = OP201_put_delegated_management_keys(cardInfo, &securityInfo201,
						       optionStr.keySetVersion,
						       optionStr.newKeySetVersion,
						       optionStr.file,
							   optionStr.passPhrase,
						       optionStr.key,
						       optionStr.current_kek);
		} else if (platform_mode == PLATFORM_MODE_GP_211) {
		    rv = GP211_put_delegated_management_keys(cardInfo,
						       &securityInfo211,
						       optionStr.keySetVersion,
						       optionStr.newKeySetVersion,
						       optionStr.file,
							   optionStr.passPhrase,
						       optionStr.key);
		}

		if (rv != 0) {
		    _tprintf (_T("put_delegated_management_keys() returns 0x%08X (%s)\n"),
			      rv, stringify_error(rv));
			rv = EXIT_FAILURE;
			goto end;
		}
		break;
		} else if (strcmp(token, "get_status") == 0) {
#define NUM_APPLICATIONS 64
		DWORD numData = NUM_APPLICATIONS;

		rv = handleOptions(&optionStr);
		if (rv != EXIT_SUCCESS) {
			goto end;
		}
		if (platform_mode == PLATFORM_MODE_OP_201) {
		    OP201_APPLICATION_DATA data[NUM_APPLICATIONS];
		    rv = OP201_get_status(cardInfo, &securityInfo201,
				      optionStr.element,
				      data,
				      &numData);

		    if (rv != 0) {
			_tprintf (_T("OP201_get_status() returns 0x%08X (%s)\n"),
				  rv, stringify_error(rv));
				rv = EXIT_FAILURE;
				goto end;
		    }
#ifdef DEBUG
		    printf ("OP201_get_status() returned %d items\n", numData);
#endif
		    printf ("\nList of applets (AID state privileges)\n");
		    for (i=0; i<(int)numData; i++) {
			int j;

			for (j=0; j<data[i].AIDLength; j++) {
			    printf ("%02x", data[i].AID[j]);
			}

			printf ("\t%x", data[i].lifeCycleState);
			printf ("\t%x\n", data[i].privileges);
		    }
		} else if (platform_mode == PLATFORM_MODE_GP_211) {
                  GP211_APPLICATION_DATA appData[NUM_APPLICATIONS];
                  GP211_EXECUTABLE_MODULES_DATA execData[NUM_APPLICATIONS];
		    rv = GP211_get_status(cardInfo, &securityInfo211,
                                          optionStr.element,
					  appData,
					  execData,
					  &numData);

		    if (rv != 0) {
				_tprintf (_T("GP211_get_status() returns 0x%08X (%s)\n"),
				  rv, stringify_error(rv));
				rv = EXIT_FAILURE;
				goto end;
		    }
#ifdef DEBUG
		    printf ("GP211_get_status() returned %d items\n", numData);
#endif
			if (optionStr.element == GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES) {
				printf ("\nList of Ex. Load File (AID state Ex. Module AIDs)\n");
			}
			else {
				printf ("\nList of elements (AID state privileges)\n");
			}
		    for (i=0; i<(int)numData; i++) {
				int j;
				int k;

				if (optionStr.element == GP211_STATUS_LOAD_FILES_AND_EXECUTABLE_MODULES) {
					for (j=0; j<execData[i].AIDLength; j++) {
						printf ("%02x", execData[i].AID[j]);
					}
					printf ("\t%x\n", execData[i].lifeCycleState);
					for (k=0; k<execData[i].numExecutableModules; k++) {
						int h;
						printf("\t");
						for (h=0; h<execData[i].executableModules[k].AIDLength; h++) {
							printf ("%02x", execData[i].executableModules[k].AID[h]);
						}
					}
					printf("\n");
				}
				else {
					for (j=0; j<appData[i].AIDLength; j++) {
						printf ("%02x", appData[i].AID[j]);
					}

					printf ("\t%x", appData[i].lifeCycleState);
					printf ("\t%x\n", appData[i].privileges);
				}
			}
		}
		if (rv != 0) {
		    _tprintf (_T("get_status() returns 0x%08X (%s)\n"),
			      rv, stringify_error(rv));
			rv = EXIT_FAILURE;
			goto end;
		}


		break;
	    } else if (strcmp(token, "send_apdu") == 0 || strcmp(token, "send_apdu_nostop") == 0) {
		unsigned char recvAPDU[258];
                DWORD recvAPDULen = 258;
				unsigned int it, ft;
        //        int i;
		// Install for Load
		rv = handleOptions(&optionStr);
		if (rv != EXIT_SUCCESS) {
			goto end;
		}
		//printf ("Send APDU: ");
		//for (i=0; i<optionStr.APDULen; i++)
		//    printf ("%02X ", optionStr.APDU[i] & 0xFF);
		//printf ("\n");

		// get the initial time
		if (optionStr.apduTime) {
			it = GetTime();
		}

		if (platform_mode == PLATFORM_MODE_OP_201) {
		    rv = OP201_send_APDU(cardInfo,
				     (optionStr.secureChannel == 0 ? NULL : &securityInfo201),
				     (PBYTE)(optionStr.APDU), optionStr.APDULen,
				     recvAPDU, &recvAPDULen);
		} else if (platform_mode == PLATFORM_MODE_GP_211) {
		    rv = GP211_send_APDU(cardInfo,
				     (optionStr.secureChannel == 0 ? NULL : &securityInfo211),
					 (PBYTE)(optionStr.APDU), optionStr.APDULen,
				     recvAPDU, &recvAPDULen);
		}
		if (rv != 0) {
		    _tprintf (_T("send_APDU() returns 0x%08X (%s)\n"),
			      rv, stringify_error(rv));
		    // if the command was nostop, don't quit
		    if (strcmp(token, "send_apdu_nostop") != 0) {
			rv = EXIT_FAILURE;
			goto end;
		    }
		}

		// get the final time and calculate the total time of the command
		if (optionStr.apduTime) {
			ft = GetTime();
			_tprintf(_T("command time: %u ms\n"), (ft - it));
		}

		//printf ("Recv APDU: ");
		//for (i=0; i<(int)recvAPDULen; i++)
		//    printf ("%02x ", recvAPDU[i]);
		//printf ("\n");

		break;
	    } else if (strcmp(token, "mode_201") == 0) {
			platform_mode = PLATFORM_MODE_OP_201;
	    } else if (strcmp(token, "mode_211") == 0) {
			platform_mode = PLATFORM_MODE_GP_211;
	    } else if (strcmp(token, "enable_trace") == 0) {
			enableTraceMode(OPGP_TRACE_MODE_ENABLE, NULL);
	    } else if (strcmp(token, "gemXpressoPro") == 0) {
			gemXpressoPro = 1;
	    }

	    else {
			printf ("Unknown command %s\n", token);
			rv = EXIT_FAILURE;
			goto end;
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
    if (argc == 1) {
	// read input from stdin
	fd = stdin;
    } else if (argc == 2) {
	// read input from script file
	fd = fopen (argv[1], "r");
        // error
        if (fd == NULL) {
            fprintf(stderr, "Could not open scriptfile !\n");
			rv = EXIT_FAILURE;
			goto end;
        }
    } else {
	// error
		fprintf (stderr, "Usage: GPShell [scriptfile]\n");
		rv = EXIT_FAILURE;
		goto end;
    }

    // launch the command interpreter
    rv = handleCommands(fd);
end:
    return rv;
}
