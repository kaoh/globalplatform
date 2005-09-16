/* GPShell.c */

#ifdef WIN32
#include "stdafx.h"
#endif
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "GlobalPlatform/GlobalPlatform.h"

/* Constants */
#define BUFLEN 256
#define DELIMITER " \t\n,"
#define DDES_KEY_LEN 16
#define PLATFORM_MODE_OP_201 201
#define PLATFORM_MODE_GP_211 211

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
    char *appletFile;
    char *AID;
    int AIDLen;
    char *sdAID;
    int sdAIDLen;
    char *pkgAID;
    int pkgAIDLen;
    char *instAID;
    int instAIDLen;
    unsigned char *APDU;
    int APDULen;
    int secureChannel;
    TCHAR *reader;
    int protocol;
    int nvCodeLimit;
    int nvDataLimit;
    int vDataLimit;
    TCHAR *file;
    char *instParam;
    int instParamLen;
    BYTE element;
    BYTE privilege;
    BYTE scp;
    BYTE scpImpl;
} OptionStr;

/* Global Variables */
OPGP_CARDCONTEXT cardContext;
OPGP_CARD_INFO cardInfo;
OP201_SECURITY_INFO securityInfo201;
GP211_SECURITY_INFO securityInfo211;
int platform_mode = PLATFORM_MODE_OP_201;;

/* Functions */
void ConvertTToC(char* pszDest, const TCHAR* pszSrc)
{
    unsigned int i;
    
    for(i = 0; i < _tcslen(pszSrc); i++)
	pszDest[i] = (char) pszSrc[i];

    pszDest[_tcslen(pszSrc)] = '\0';
}

void ConvertCToT(TCHAR* pszDest, const char* pszSrc)
{
    unsigned int i;
    
    for(i = 0; i < strlen(pszSrc); i++)
	pszDest[i] = (TCHAR) pszSrc[i];

    pszDest[strlen(pszSrc)] = _T('\0');
}
char *strtokCheckComment(char *buf)
{
    char *token;
    
    token = strtok (buf, DELIMITER);

    if (token == NULL)
	return NULL;
    
    if (strcmp(token, "//") == 0 || strcmp(token, "#") == 0) {
	return NULL;
    } else {
	return token;
    }
}

int handleOptions(OptionStr *pOptionStr)
{
    char *token;

    pOptionStr->keyIndex = 0;
    pOptionStr->keySetVersion = 0;
    pOptionStr->newKeySetVersion = 0;
    pOptionStr->securityLevel = 0;
    pOptionStr->appletFile = NULL;
    pOptionStr->AID = NULL;
    pOptionStr->AIDLen = 0;
    pOptionStr->sdAID = NULL;
    pOptionStr->sdAIDLen = 0;
    pOptionStr->pkgAID = NULL;
    pOptionStr->pkgAIDLen = 0;
    pOptionStr->instAID = NULL;
    pOptionStr->instAIDLen = 0;
    pOptionStr->APDU = NULL;
    pOptionStr->APDULen = 0;
    pOptionStr->secureChannel = 0;
    pOptionStr->reader = NULL;
    pOptionStr->protocol = OPGP_CARD_PROTOCOL_T0;
    pOptionStr->nvCodeLimit = 0;
    pOptionStr->nvDataLimit = 0;
    pOptionStr->vDataLimit = 0;
    pOptionStr->instParam = NULL;
    pOptionStr->instParamLen = 0;
    pOptionStr->element = 0;
    pOptionStr->privilege = 0;
    pOptionStr->scp = 1;
    pOptionStr->scpImpl = 5;    
  
    token = strtokCheckComment(NULL);

    while (token != NULL) {
	if (strcmp(token, "-keyind") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -keyind not followed by data\n");
		exit (1);
	    } else {
		pOptionStr->keyIndex = atoi(token);
	    }
	} else if (strcmp(token, "-keyver") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -keyver not followed by data\n");
		exit (1);
	    } else {
		pOptionStr->keySetVersion = atoi(token);
	    }
	} else if (strcmp(token, "-newkeyver") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -newkeyver not followed by data\n");
		exit (1);
	    } else {
		pOptionStr->newKeySetVersion = atoi(token);
	    }
	} else if (strcmp(token, "-sc") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -sc not followed by data\n");
		exit (1);
	    } else {
		if (atoi(token) == 0)
		    pOptionStr->secureChannel = 0;
		else if (atoi(token) == 1)
		    pOptionStr->secureChannel = 1;
		else {
		    printf ("Error: option -sc not followed 0 (secure channel off) or 1 (secure channel on)\n");
		    exit (1);
		}		    
	    }
	} else if (strcmp(token, "-security") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -security not followed by data\n");
		exit (1);
	    } else {
		pOptionStr->securityLevel = atoi(token);
	    }
	} else if (strcmp(token, "-appletfile") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -appletfile not followed by data\n");
		exit (1);
	    } else {
		pOptionStr->appletFile = (char *)malloc(sizeof(char) * (strlen (token) + 1));
		if (pOptionStr->appletFile == NULL) {
		    printf ("Error: memory allocation\n");
		    exit (1);
		}
		strcpy (pOptionStr->appletFile, token);
	    } 
	} else if (strcmp(token, "-reader") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -reader not followed by data\n");
		exit (1);
	    } else {
		pOptionStr->reader = (TCHAR *)malloc(sizeof(TCHAR) * (strlen (token) + 1));
		if (pOptionStr->reader == NULL) {
		    printf ("Error: memory allocation\n");
		    exit (1);
		}
		ConvertCToT (pOptionStr->reader, token);
#ifdef DEBUG
		_tprintf ( _T("reader name %s\n"), pOptionStr->reader);
#endif
	    } 
	} else if (strcmp(token, "-file") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -file not followed by data\n");
		exit (1);
	    } else {
		pOptionStr->file = (TCHAR *)malloc(sizeof(TCHAR) * (strlen (token) + 1));
		if (pOptionStr->file == NULL) {
		    printf ("Error: memory allocation\n");
		    exit (1);
		}
		
		ConvertCToT (pOptionStr->file, token);
		/*#ifdef DEBUG
		_tprintf ( _T("file name %s\n"), pOptionStr->file);
		#endif*/
	    } 
	} else if (strcmp(token, "-key") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -key not followed by data\n");
		exit (1);
	    } else {
		int i;
		
		for (i=0; i<DDES_KEY_LEN; i++) {
		    sscanf (token, "%02x", &(pOptionStr->key[i]));
		    token += 2;
		}
	    } 
	} else if (strcmp(token, "-mac_key") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -key not followed by data\n");
		exit (1);
	    } else {
		int i;
		
		for (i=0; i<DDES_KEY_LEN; i++) {
		    sscanf (token, "%02x", &(pOptionStr->mac_key[i]));
		    token += 2;
		}
	    } 
	} else if (strcmp(token, "-enc_key") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -enc_key not followed by data\n");
		exit (1);
	    } else {
		int i;
		
		for (i=0; i<DDES_KEY_LEN; i++) {
		    sscanf (token, "%02x", &(pOptionStr->enc_key[i]));
		    token += 2;
		}
	    } 
	} else if (strcmp(token, "-kek_key") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -kek_key not followed by data\n");
		exit (1);
	    } else {
		int i;
		
		for (i=0; i<DDES_KEY_LEN; i++) {
		    sscanf (token, "%02x", &(pOptionStr->kek_key[i]));
		    token += 2;
		}
	    } 
	} else if (strcmp(token, "-current_kek") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -current_kek not followed by data\n");
		exit (1);
	    } else {
		int i;
		
		for (i=0; i<DDES_KEY_LEN; i++) {
		    sscanf (token, "%02x", &(pOptionStr->current_kek[i]));
		    token += 2;
		}
	    } 
	} else if (strcmp(token, "-AID") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -AID not followed by data\n");
		exit (1);
	    } else {
		int i = 0;

		pOptionStr->AID = (char *)malloc(sizeof(char) * (strlen (token) + 1));
		while (sscanf (token, "%02x", &(pOptionStr->AID[i])) > 0) {
		    i++;
		    token += 2;
		}
		pOptionStr->AIDLen = i;
		pOptionStr->AID = (char *)realloc (pOptionStr->AID, i);
	    } 
	} else if (strcmp(token, "-sdAID") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -sdAID not followed by data\n");
		exit (1);
	    } else {
		int i = 0;
		
		pOptionStr->sdAID = (char *)malloc(sizeof(char) * (strlen (token) + 1));
		while (sscanf (token, "%02x", &(pOptionStr->sdAID[i])) > 0) {
		    i++;
		    token += 2;
		}
		pOptionStr->sdAIDLen = i;
		pOptionStr->sdAID = (char *)realloc (pOptionStr->sdAID, i);
	    } 
	} else if (strcmp(token, "-pkgAID") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -pkgAID not followed by data\n");
		exit (1);
	    } else {
		int i = 0;
		
		pOptionStr->pkgAID = (char *)malloc(sizeof(char) * (strlen (token) + 1));
		while (sscanf (token, "%02x", &(pOptionStr->pkgAID[i])) > 0) {
		    i++;
		    token += 2;
		}
		pOptionStr->pkgAIDLen = i;
		pOptionStr->pkgAID = (char *)realloc (pOptionStr->pkgAID, i);
	    } 
	} else if (strcmp(token, "-instAID") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -instAID not followed by data\n");
		exit (1);
	    } else {
		int i = 0;
		
		pOptionStr->instAID = (char *)malloc(sizeof(char) * (strlen (token) + 1));
		while (sscanf (token, "%02x", &(pOptionStr->instAID[i])) > 0) {
		    i++;
		    token += 2;
		}
		pOptionStr->instAIDLen = i;
		pOptionStr->instAID = (char *)realloc (pOptionStr->instAID, i);
	    } 
	} else if (strcmp(token, "-APDU") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -APDU not followed by data\n");
		exit (1);
	    } else {
		int i = 0;

		pOptionStr->APDU = (char *)malloc(sizeof(char) * (strlen (token) + 1));
		while (sscanf (token, "%02x", &(pOptionStr->APDU[i])) > 0) {
		    i++;
		    token += 2;
		}
		pOptionStr->APDULen = i;
		pOptionStr->APDU = (char *)realloc (pOptionStr->APDU, i);
	    } 
	} else if (strcmp(token, "-protocol") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -protocol not followed by data\n");
		exit (1);
	    } else {
		if (atoi(token) == 0) {
		    pOptionStr->protocol = OPGP_CARD_PROTOCOL_T0;
		} else if (atoi(token) == 1) {
		    pOptionStr->protocol = OPGP_CARD_PROTOCOL_T1;
		} else {
		    printf ("Unknown protocol type %s\n", token);
		    exit (1);
		}
	    }
	} else if (strcmp(token, "-nvCodeLimit") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -nvCodeLimit not followed by data\n");
		exit (1);
	    } else {
		pOptionStr->nvCodeLimit = atoi(token);
	    }
	} else if (strcmp(token, "-nvDataLimit") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -nvDataLimit not followed by data\n");
		exit (1);
	    } else {
		pOptionStr->nvDataLimit = atoi(token);
	    }
	} else if (strcmp(token, "-vDataLimit") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -vDataLimit not followed by data\n");
		exit (1);
	    } else {
		pOptionStr->vDataLimit = atoi(token);
	    }
	} else if (strcmp(token, "-instParam") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -instParam not followed by data\n");
		exit (1);
	    } else {
		unsigned int i = 0;

		pOptionStr->instParam = (char *)malloc(sizeof(char) * (strlen (token) + 1));
		while (sscanf (token, "%02x", &(pOptionStr->instParam[i])) > 0) {
		    i++;
		    token += 2;
		}
		pOptionStr->instParamLen = i;
		pOptionStr->instParam =
		    (char *)realloc (pOptionStr->instParam, i);
	    }
	} else if (strcmp(token, "-element") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -element not followed by data\n");
		exit (1);
	    }
	    
	    if (sscanf (token, "%02x", &(pOptionStr->element)) <= 0) {
		printf ("Error: option -element followed by an illegal string %s\n",
			token);
		exit (1);
	    }	    
	} else if (strcmp(token, "-priv") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -priv not followed by data\n");
		exit (1);
	    } else {
		pOptionStr->privilege = atoi(token);
	    }
	} else if (strcmp(token, "-scp") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -scp not followed by data\n");
		exit (1);
	    } else {
		pOptionStr->scp = atoi(token);
	    }
	} else if (strcmp(token, "-scpimpl") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -scpimpl not followed by data\n");
		exit (1);
	    } else {
		pOptionStr->scpImpl = atoi(token);
	    }
	} else {
	    // unknown option
	    printf ("Error: unknown option %s\n", token);
	    exit (1);
	}

	token = strtokCheckComment(NULL);
    } 
    return 0;
}

int handleCommands(FILE *fd)
{
    BYTE buf[BUFLEN + 1], commandLine[BUFLEN + 1];
    int rv = -1, i;
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
		    printf ("establish_context failed with error %d\n", rv);
		    exit (1);
		}
		break;
	    } else if (strcmp(token, "release_context") == 0) {
		// Release context
		rv = release_context(cardContext);
		if (rv != OPGP_ERROR_SUCCESS) {
		    printf ("release_context failed with error %d\n", rv);
		    exit (1);
		}

		break;
	    } else if (strcmp(token, "card_connect") == 0) {
		TCHAR buf[BUFLEN + 1];
		DWORD readerStrLen = BUFLEN;
		// open reader
		handleOptions(&optionStr);
		/*#ifdef DEBUG
		printf ("optionStr.reader %d\n", optionStr.reader);
		#endif*/
		if (optionStr.reader == NULL) {	
		    // get the first reader
		    rv = list_readers (cardContext, buf, &readerStrLen);

		    optionStr.reader = buf;
#ifdef DEBUG
		    _tprintf ( _T("* reader name %s\n"), optionStr.reader);
#endif
		}
		
		rv = card_connect (cardContext, optionStr.reader,
				   &cardInfo, optionStr.protocol);

		if (rv != 0) {
		    _tprintf (_T("card_connect() returns %d (%s)\n"), rv,
			      stringify_error(rv));
		}

		break;
	    } if (strcmp(token, "open_sc") == 0) {
		// open secure channel
		handleOptions(&optionStr);
		
		if (platform_mode == PLATFORM_MODE_OP_201) {
		    rv = OP201_mutual_authentication(cardInfo,
						     optionStr.enc_key,
						     optionStr.mac_key,
						     optionStr.keySetVersion,
						     optionStr.keyIndex,
						     optionStr.securityLevel,
						     &securityInfo201);
		} else if (platform_mode == PLATFORM_MODE_GP_211) {
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
		    _tprintf (_T("mutual_authentication() returns %d (%s)\n"),
			      rv, stringify_error(rv));
		    exit (1);
		}

		break;
	    } else if (strcmp(token, "select") == 0) {
		// select instance
		handleOptions(&optionStr);
		rv = select_application (cardInfo,
					 optionStr.AID, optionStr.AIDLen);
		if (rv != 0) {
		    _tprintf (_T("select_application() returns %d (%s)\n"),
			      rv, stringify_error(rv));
		    exit (1);
		}
		break;
	    } else if (strcmp(token, "getdata") == 0) {
		// Get Data
		handleOptions(&optionStr);
		// TODO: get data
		break;
	    } else if (strcmp(token, "load") == 0) {
		// Load Applet
		DWORD receiptDataLen = 0;
		handleOptions(&optionStr);

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
		    _tprintf (_T("load_applet() returns %d (%s)\n"),
			      rv, stringify_error(rv));
		    exit (1);
		}

		break;
	    }  else if (strcmp(token, "delete") == 0) {
		// Delete Applet
		OPGP_AID AIDs[1];
		
		DWORD receiptLen = 10;
		    
		handleOptions(&optionStr);
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
		    _tprintf (_T("delete_applet() returns %d (%s)\n"),
			      rv, stringify_error(rv));
		}
		break;
	    }
    
	    else if (strcmp(token, "install_for_load") == 0) {
		// Install for Load
		handleOptions(&optionStr);

		if (platform_mode == platform_mode == PLATFORM_MODE_OP_201) {
		    rv = OP201_install_for_load(cardInfo, &securityInfo201,
				      optionStr.AID, optionStr.AIDLen,
				      optionStr.sdAID, optionStr.sdAIDLen,
				      NULL, NULL,
				      optionStr.nvCodeLimit,
				      optionStr.nvDataLimit,
				      optionStr.vDataLimit);
		} else if (platform_mode == PLATFORM_MODE_GP_211) {
		    rv = GP211_install_for_load(cardInfo, &securityInfo211,
					    optionStr.AID, optionStr.AIDLen,
					    optionStr.sdAID, optionStr.sdAIDLen,
					    NULL, NULL,
					    optionStr.nvCodeLimit,
					    optionStr.nvDataLimit,
					    optionStr.vDataLimit);
		}
		
		if (rv != 0) {
		    _tprintf (_T("install_for_load() returns %d (%s)\n"),
			      rv, stringify_error(rv));
		    exit (1);
		}
		break;
	    } else if (strcmp(token, "install_for_install") == 0) {
		

		DWORD receiptDataAvailable = 0;
		char installParam[1];
		installParam[0] = 0;

		// Install for Install
		handleOptions(&optionStr);

		if (platform_mode == PLATFORM_MODE_OP_201) {
		    OP201_RECEIPT_DATA receipt;
		    rv = OP201_install_for_install_and_make_selectable(
				         cardInfo, &securityInfo201,
					 optionStr.pkgAID, optionStr.pkgAIDLen,
					 optionStr.AID, optionStr.AIDLen,
					 optionStr.instAID, optionStr.instAIDLen,
					 optionStr.privilege, 
					 optionStr.vDataLimit,
					 optionStr.nvDataLimit,
					 optionStr.instParam,
					 optionStr.instParamLen, 
					 NULL, // No install token
					 &receipt,
					 &receiptDataAvailable);
		} else if (platform_mode == PLATFORM_MODE_GP_211) {
		    GP211_RECEIPT_DATA receipt;
		    
		    rv = GP211_install_for_install_and_make_selectable(
					cardInfo, &securityInfo211,
					optionStr.pkgAID, optionStr.pkgAIDLen,
					optionStr.AID, optionStr.AIDLen,
					optionStr.instAID, optionStr.instAIDLen,
					optionStr.privilege,
					optionStr.vDataLimit,
					optionStr.nvDataLimit,
					optionStr.instParam,
					optionStr.instParamLen,
					NULL, // No install token
					&receipt,
					&receiptDataAvailable);
		}
		
		if (rv != 0) {
		    _tprintf (_T("install_for_install_and_make_selectable() returns %d (%s)\n"),
			      rv, stringify_error(rv));
		    exit (1);
		}
		
		break;
	    } else if (strcmp(token, "card_disconnect") == 0) {
		// disconnect card
		card_disconnect(cardInfo);

		break;
	    } else if (strcmp(token, "put_sc_key") == 0) {
		handleOptions(&optionStr);

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
		    _tprintf (_T("put_secure_channel_keys() returns %d (%s)\n"),
			      rv, stringify_error(rv));
		    exit (1);
		}
		break;
	    } else if (strcmp(token, "get_status") == 0) {
#define NUM_APPLICATIONS 64
		DWORD numData = NUM_APPLICATIONS;

		handleOptions(&optionStr);

		if (platform_mode == PLATFORM_MODE_OP_201) {
		    OP201_APPLICATION_DATA data[NUM_APPLICATIONS];
		    rv = OP201_get_status(cardInfo, &securityInfo201,
				      optionStr.element,
				      data,
				      &numData);

		    if (rv != 0) {
			_tprintf (_T("OP201_get_status() returns %d (%s)\n"),
				  rv, stringify_error(rv));
			exit (1);
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
		    GP211_APPLICATION_DATA appData[NUM_APPLICATIONS],
			execData[NUM_APPLICATIONS];
		    rv = GP211_get_status(cardInfo, &securityInfo211,
					  optionStr.element,
					  appData,
					  execData,
					  &numData);

		    if (rv != 0) {
			_tprintf (_T("GP211_get_status() returns %d (%s)\n"),
				  rv, stringify_error(rv));
			exit (1);
		    }
#ifdef DEBUG
		    printf ("GP211_get_status() returned %d items\n", numData);
#endif
		    printf ("\nList of applets (AID state privileges)\n");
		    for (i=0; i<(int)numData; i++) {
			int j;
			
			for (j=0; j<appData[i].AIDLength; j++) {
			    printf ("%02x", appData[i].AID[j]);
			}
			
			printf ("\t%x", appData[i].lifeCycleState);
			printf ("\t%x\n", appData[i].privileges);
		    }
		}
		if (rv != 0) {
		    _tprintf (_T("get_status() returns %d (%s)\n"),
			      rv, stringify_error(rv));
		    exit (1);
		}

		
		break;
	    } else if (strcmp(token, "send_apdu") == 0) {
		unsigned char recvAPDU[257];
		int recvAPDULen = 257, i;
		// Install for Load
		handleOptions(&optionStr);

		printf ("Send APDU: ");
		for (i=0; i<optionStr.APDULen; i++)
		    printf ("%02x ", optionStr.APDU[i]);
		printf ("\n");

		if (platform_mode == PLATFORM_MODE_OP_201) {
		    rv = OP201_send_APDU(cardInfo,
				     (optionStr.secureChannel == 0 ? NULL : &securityInfo201),
				     optionStr.APDU, optionStr.APDULen, 
				     recvAPDU, &recvAPDULen);
		} else if (platform_mode == PLATFORM_MODE_GP_211) {
		    rv = GP211_send_APDU(cardInfo,
				     (optionStr.secureChannel == 0 ? NULL : &securityInfo211),
				     optionStr.APDU, optionStr.APDULen, 
				     recvAPDU, &recvAPDULen);
		}
		if (rv != 0) {
		    _tprintf (_T("send_APDU() returns %d (%s)\n"),
			      rv, stringify_error(rv));
		    exit (1);
		}

		printf ("Recv APDU: ");
		for (i=0; i<recvAPDULen; i++)
		    printf ("%02x ", recvAPDU[i]);
		printf ("\n");
		
		break;
	    } else if (strcmp(token, "mode_201") == 0) {
		platform_mode = PLATFORM_MODE_OP_201;
	    } else if (strcmp(token, "mode_211") == 0) {
		platform_mode = PLATFORM_MODE_GP_211;
	    } else if (strcmp(token, "enable_trace") == 0) {
		enableTraceMode(OPGP_TRACE_MODE_ENABLE, NULL);
	    }
	    
	    else {
		printf ("Unknown command %s\n", token);
		exit (1);
	    }

	    token = strtokCheckComment(NULL);
	}
    }

    return rv;
}

int main(int argc, char* argv[])
{
    FILE *fd = NULL;
    int rv;

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
          return 1;
        }
    } else {
	// error
	fprintf (stderr, "Usage: GPShell [scriptfile]\n");
	return 1;
    }
      
    // launch the command interpreter
    rv = handleCommands(fd);

    return 0;
}

