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

#include "globalplatform/debug.h"
#include "globalplatform/error.h"
#include "dyn_generic.h"

#define MAX_LIBRARY_NAME_SIZE 64
#define LIBRARY_NAME_PREFIX _T("lib")
#define LIBRARY_NAME_EXTENSION _T(".so")
#define LIBRARY_NAME_VERSION_SEPARATOR _T(".")

/**
 * \param libraryHandle [out] The returned library handle
 * \param libraryName [in] The length of the Security Domain AID.
 * \param version [in] The version of the library to use.
 * \return The error status.
 */
OPGP_ERROR_STATUS DYN_LoadLibrary(PVOID *libraryHandle, LPCTSTR libraryName, LPCTSTR version)
{
	OPGP_ERROR_STATUS errorStatus;
	int offset = 0;
	*libraryHandle = NULL;
	TCHAR internalLibraryName[MAX_LIBRARY_NAME_SIZE];
	OPGP_LOG_START(_T("DYN_LoadLibrary"));

	OPGP_log_Msg(_T("DYN_LoadLibrary: Using library name \"%s\" and version \"%s\"."), libraryName, version);

	_tcsncpy(internalLibraryName, LIBRARY_NAME_PREFIX, MAX_LIBRARY_NAME_SIZE);
	offset += _tcslen(LIBRARY_NAME_PREFIX);
	_tcsncpy(internalLibraryName + offset, libraryName, MAX_LIBRARY_NAME_SIZE - offset);
	offset +=  _tcslen(libraryName);
	_tcsncpy(internalLibraryName + offset, LIBRARY_NAME_EXTENSION, MAX_LIBRARY_NAME_SIZE - offset);
	offset += _tcslen(LIBRARY_NAME_EXTENSION);
	if (version != NULL) {
		_tcsncpy(internalLibraryName + offset, LIBRARY_NAME_VERSION_SEPARATOR, MAX_LIBRARY_NAME_SIZE - offset);
		offset += _tcslen(LIBRARY_NAME_VERSION_SEPARATOR);
		_tcsncpy(internalLibraryName + offset, version, MAX_LIBRARY_NAME_SIZE - offset);
		offset += _tcslen(version);
	}
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

/**
 * \param libraryHandle [in] The library handle
 * \return The error status.
 */
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

/**
 * \param libraryHandle [in] The returned library handle
 * \param functionHandle [out] The returned function handle.
 * \param functionName [in] The function name to search.
 * \return The error status.
 */
OPGP_ERROR_STATUS DYN_GetAddress(PVOID libraryHandle, PVOID *functionHandle, LPCTSTR functionName)
{
	OPGP_ERROR_STATUS errorStatus;

	OPGP_LOG_START(_T("DYN_GetAddress"));

	char pcFunctionName[256];

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
