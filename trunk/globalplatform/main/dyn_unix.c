/*  Copyright (c) 2008, Karsten Ohme
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

/*
 * Based on a implementation from the Muscle MUSCLE SmartCard Development ( http://www.linuxnet.com ) by David Corcoran <corcoran@linuxnet.com>
 */
/**
 * @file
 * @brief This abstracts dynamic library loading functions and timing.
 */

#include <stdio.h>
#include <string.h>
#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#include <stdlib.h>

#include "GlobalPlatform/debug.h"
#include "GlobalPlatform/error.h"
#include "dyn_generic.h"

#define MAX_LIBRARY_NAME_SIZE 64
#define LIBRARY_NAME_PREFIX _T("lib")
#define LIBRARY_NAME_EXTENSION _T(".so")

OPGP_ERROR_STATUS DYN_LoadLibrary(PVOID *libraryHandle, LPCTSTR libraryName)
{
	OPGP_ERROR_STATUS errorStatus;
	*libraryHandle = NULL;
	TCHAR internalLibraryName[MAX_LIBRARY_NAME_SIZE];
	OPGP_LOG_START(_T("DYN_LoadLibrary"));

	_tcsncpy(internalLibraryName, LIBRARY_NAME_PREFIX, MAX_LIBRARY_NAME_SIZE);
	_tcsncpy(internalLibraryName + _tcslen(LIBRARY_NAME_PREFIX), libraryName, MAX_LIBRARY_NAME_SIZE - _tcslen(LIBRARY_NAME_PREFIX));
	_tcsncpy(internalLibraryName + _tcslen(LIBRARY_NAME_PREFIX) + _tcslen(libraryName), LIBRARY_NAME_EXTENSION, MAX_LIBRARY_NAME_SIZE - (_tcslen(LIBRARY_NAME_PREFIX) + _tcslen(libraryName)));
	internalLibraryName[MAX_LIBRARY_NAME_SIZE-1] = _T('\0');
	*libraryHandle = dlopen(internalLibraryName, RTLD_LAZY);

	if (*libraryHandle == NULL)
	{
		OPGP_ERROR_CREATE_ERROR(errorStatus, -1, dlerror());
		goto end;
	}
	OPGP_ERROR_CREATE_NO_ERROR(errorStatus);

end:
	OPGP_LOG_END(_T("DYN_LoadLibrary"), errorStatus);
	return errorStatus;
}

OPGP_ERROR_STATUS DYN_CloseLibrary(PVOID *libraryHandle)
{
	int ret;
	OPGP_ERROR_STATUS errorStatus;

	OPGP_LOG_START(_T("DYN_CloseLibrary"));
	ret = dlclose(*libraryHandle);
	*libraryHandle = NULL;

	if (ret != 0)
	{
		OPGP_ERROR_CREATE_ERROR(errorStatus, -1, dlerror());
		goto end;
	}
	OPGP_ERROR_CREATE_NO_ERROR(errorStatus);
end:
	OPGP_LOG_END(_T("DYN_CloseLibrary"), errorStatus);
	return errorStatus;
}

OPGP_ERROR_STATUS DYN_GetAddress(PVOID libraryHandle, PVOID *functionHandle, LPCTSTR functionName)
{
	OPGP_ERROR_STATUS errorStatus;

	OPGP_LOG_START(_T("DYN_GetAddress"));

	char pcFunctionName[256];
	int rv;

	/* Some platforms might need a leading underscore for the symbol */
	snprintf(pcFunctionName, sizeof(pcFunctionName), "_%s", functionName);

	*functionHandle = NULL;
	*functionHandle = dlsym(libraryHandle, pcFunctionName);

	/* Failed? Try again without the leading underscore */
	if (*functionHandle == NULL)
		*functionHandle = dlsym(libraryHandle, functionName);

	if (*functionHandle == NULL)
	{
		OPGP_ERROR_CREATE_ERROR(errorStatus, -1, dlerror());
		goto end;
	}
	OPGP_ERROR_CREATE_NO_ERROR(errorStatus);
end:
	OPGP_LOG_END(_T("DYN_GetAddress"), errorStatus);
	return errorStatus;
}

#endif	// HAVE_DLFCN_H
