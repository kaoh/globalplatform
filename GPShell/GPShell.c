/* GPShell.c */

#ifdef WIN32
#include "stdafx.h"
#endif
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "OpenPlatform/OpenPlatform.h"

/* Constants */
#define BUFLEN 256
#define DELIMITER " \t\n,"
#define DDES_KEY_LEN 16

/* Data Structures */
typedef struct _OptionStr {
    int keyIndex;
    int keySetVersion;
    unsigned char key[DDES_KEY_LEN];
    unsigned char mac_key[DDES_KEY_LEN];
    unsigned char enc_key[DDES_KEY_LEN];
    unsigned char kek_key[DDES_KEY_LEN];
    int securityLevel;
    char *appletFile;
    char *AID;
    int AIDLen;
    char *sdAID;
    int sdAIDLen;
    char *pkgAID;
    int pkgAIDLen;
    char *instAID;
    int instAIDLen;
    TCHAR *reader;
    int protocol;
    int nvCodeLimit;
    int nvDataLimit;
    int vDataLimit;
    TCHAR *file;
    char *instParam;
    int instParamLen;
    int element;
} OptionStr;

/* Global Variables */
OPSP_CARDCONTEXT cardContext;
OPSP_CARDHANDLE cardHandle;
OPSP_CARD_INFO cardInfo;
OPSP_SECURITY_INFO securityInfo;

/* Functions */
void ConvertTToC(char* pszDest, const TCHAR* pszSrc)
{
    int i;
    
    for(i = 0; i < _tcslen(pszSrc); i++)
	pszDest[i] = (char) pszSrc[i];

    pszDest[_tcslen(pszSrc)] = '\0';
}

void ConvertCToT(TCHAR* pszDest, const char* pszSrc)
{
    int i;
    
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
    pOptionStr->reader = NULL;
    pOptionStr->protocol = OPSP_CARD_PROTOCOL_T0;
    pOptionStr->nvCodeLimit = 0;
    pOptionStr->nvDataLimit = 0;
    pOptionStr->vDataLimit = 0;
    pOptionStr->instParam = NULL;
    pOptionStr->instParamLen = 0;
    pOptionStr->element = 0;
	
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
	} else if (strcmp(token, "-security") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -security not followed by data\n");
		exit (1);
	    } else {
		pOptionStr->securityLevel = atoi(token);
	    }
	}  else if (strcmp(token, "-appletfile") == 0) {
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
#ifdef DEBUG
		_tprintf ( _T("file name %s\n"), pOptionStr->file);
#endif
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
	} else if (strcmp(token, "-protocol") == 0) {
	    token = strtokCheckComment(NULL);
	    if (token == NULL) {
		printf ("Error: option -protocol not followed by data\n");
		exit (1);
	    } else {
		if (atoi(token) == 0) {
		    pOptionStr->protocol = OPSP_CARD_PROTOCOL_T0;
		} else if (atoi(token) == 1) {
		    pOptionStr->protocol = OPSP_CARD_PROTOCOL_T1;
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
		int i = 0;

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
    BYTE buf[BUFLEN + 1];
    int rv = 0, i;
    char *token;
    OptionStr optionStr;

    while (fgets (buf, BUFLEN, fd) != NULL) {	
	token = strtokCheckComment(buf);
	while (token != NULL) {
	    if (token[0] == '#' || strncmp (token, "//", 2) == 0)
		break;
	    if (strcmp(token, "establish_context") == 0) {
		// Establish context
		rv = establish_context(&cardContext);
		if (rv != OPSP_ERROR_SUCCESS) {
		    printf ("establish_context failed with error %d\n", rv);
		    exit (1);
		}
		break;
	    } else if (strcmp(token, "release_context") == 0) {
		// Release context
		rv = release_context(cardContext);
		if (rv != OPSP_ERROR_SUCCESS) {
		    printf ("release_context failed with error %d\n", rv);
		    exit (1);
		}

		break;
	    } else if (strcmp(token, "card_connect") == 0) {
		TCHAR buf[BUFLEN + 1];
		DWORD readerStrLen = BUFLEN;
		// open reader
		handleOptions(&optionStr);
#ifdef DEBUG
		printf ("optionStr.reader %d\n", optionStr.reader);
#endif
		if (optionStr.reader == NULL) {	
		    // get the first reader
		    rv = list_readers (cardContext, buf, &readerStrLen);

		    optionStr.reader = buf;
#ifdef DEBUG
		    _tprintf ( _T("reader name %s\n"), optionStr.reader);
#endif
		}
		
		rv = card_connect (cardContext, optionStr.reader,
				   &cardHandle, optionStr.protocol);

		if (rv != 0) {
		    _tprintf (_T("card_connect() returns %d (%s)\n"), rv,
			      stringify_error(rv));
		}

		rv = get_card_status (cardHandle, &cardInfo);
		if (rv != 0) {
		    _tprintf (_T("get_card_status() returns %d (%s)\n"), rv,
			      stringify_error(rv));
		    exit (1);
		}
		
		break;
	    } if (strcmp(token, "open_sc") == 0) {
		// open secure channel
		handleOptions(&optionStr);
		/*for (i=0; i<TDES_KEY_LEN; i++) {
		  printf ("%02x ", optionStr.key[i]);
		  }*/
		rv = mutual_authentication(cardHandle,
					   optionStr.enc_key,
					   optionStr.mac_key,
					   optionStr.keySetVersion,
					   optionStr.keyIndex,
					   cardInfo,
					   optionStr.securityLevel,
					   &securityInfo);
		if (rv != 0) {
		    _tprintf (_T("mutual_authentication() returns %d (%s)\n"),
			      rv, stringify_error(rv));
		    exit (1);
		}
					       
		break;
	    } else if (strcmp(token, "select") == 0) {
		// select instance
		handleOptions(&optionStr);
		rv = select_application (cardHandle, cardInfo,
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

		rv = load_applet(cardHandle, &securityInfo, cardInfo,
				 NULL, 0, optionStr.file,
				 NULL, &receiptDataLen);
		if (rv != 0) {
		    _tprintf (_T("load_applet() returns %d (%s)\n"),
			      rv, stringify_error(rv));
		    exit (1);
		}

		break;
	    }  else if (strcmp(token, "delete") == 0) {
		// Delete Applet
		OPSP_AID AIDs[1];
		OPSP_RECEIPT_DATA receipt[10];
		DWORD receiptLen = 10;
		    
		handleOptions(&optionStr);
		memcpy (AIDs[0].AID, optionStr.AID, optionStr.AIDLen);
		AIDs[0].AIDLength = optionStr.AIDLen;

		rv = delete_applet(cardHandle, &securityInfo,
				   cardInfo,
				   AIDs, 1,
                                   (OPSP_RECEIPT_DATA **)&receipt, &receiptLen);

		if (rv != 0) {
		    _tprintf (_T("delete_applet() returns %d (%s)\n"),
			      rv, stringify_error(rv));
		}
		break;
	    }
    
	    else if (strcmp(token, "install_for_load") == 0) {
		// Install for Load
		handleOptions(&optionStr);

		rv = install_for_load(cardHandle, &securityInfo,
				      cardInfo,
				      optionStr.AID, optionStr.AIDLen,
				      optionStr.sdAID, optionStr.sdAIDLen,
				      NULL, NULL,
				      optionStr.nvCodeLimit,
				      optionStr.nvDataLimit,
				      optionStr.vDataLimit);
				      
		if (rv != 0) {
		    _tprintf (_T("install_for_load() returns %d (%s)\n"),
			      rv, stringify_error(rv));
		    exit (1);
		}
		break;
	    } else if (strcmp(token, "install_for_install") == 0) {
		OPSP_RECEIPT_DATA receipt;
		DWORD receiptDataAvailable = 0;
		char installParam[1];
		installParam[0] = 0;

		// Install for Install
		handleOptions(&optionStr);
		
		rv = install_for_install_and_make_selectable(
					 cardHandle, &securityInfo,
					 cardInfo,
					 optionStr.pkgAID, optionStr.pkgAIDLen,
					 optionStr.AID, optionStr.AIDLen,
					 optionStr.instAID, optionStr.instAIDLen,
					 OPSP_APPLICATION_PRIVILEGE_PIN_CHANGE_PRIVILEGE, // 
					 optionStr.vDataLimit,
					 optionStr.nvDataLimit,
					 optionStr.instParam,
					 optionStr.instParamLen, 
					 NULL, // No install token
					 &receipt,
					 &receiptDataAvailable);

		if (rv != 0) {
		    _tprintf (_T("install_for_install_and_make_selectable() returns %d (%s)\n"),
			      rv, stringify_error(rv));
		    exit (1);
		}
		break;
	    } else if (strcmp(token, "card_disconnect") == 0) {
		// disconnect card
		card_disconnect(cardHandle);

		break;
	    } else if (strcmp(token, "putkey") == 0) {
		// TODO: put key
		printf ("TODO: put key\n");
		break;
	    } else if (strcmp(token, "get_status") == 0) {
#define NUM_APPLICATIONS 64
		OPSP_APPLICATION_DATA data[NUM_APPLICATIONS];
		DWORD numData = NUM_APPLICATIONS;

		handleOptions(&optionStr);
		
		rv = get_status(cardHandle, &securityInfo, cardInfo,
				optionStr.element,
				data,
				&numData);
		if (rv != 0) {
		    _tprintf (_T("get_status() returns %d (%s)\n"),
			      rv, stringify_error(rv));
		    exit (1);
		}
#ifdef DEBUG
		printf ("get_status() returned %d items\n", numData);
#endif
		printf ("\nList of applets (AID state privileges)\n");
		for (i=0; i<numData; i++) {
		    int j;
		    
		    for (j=0; j<data[i].AIDLength; j++) {
			printf ("%02x", data[i].AID[j]);
		    }

		    printf ("\t%x", data[i].lifeCycleState);
		    printf ("\t%x\n", data[i].privileges);
		}
		
		break;
	    } else {
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

