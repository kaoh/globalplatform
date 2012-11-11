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
 * @brief This abstracts dynamic library loading functions.
 */

#ifdef WIN32
#include <string.h>

#include <windows.h>
#include <winscard.h>
#include "dyn_generic.h"
#include "globalplatform/debug.h"
#include "globalplatform/stringify.h"

static void ConvertTToC(char* pszDest, const TCHAR* pszSrc, unsigned int maxSize)
{
    unsigned int i;

    for (i = 0; i < _tcslen(pszSrc); i++)
        pszDest[i] = (char) pszSrc[i];

    pszDest[min(_tcslen(pszSrc), maxSize)] = '\0';
}

/**
 * \param libraryHandle [out] The returned library handle
 * \param libraryName [in] The length of the Security Domain AID.
 * \param version [in] The version of the library to use.
 * \return The error status.
 */
OPGP_ERROR_STATUS DYN_LoadLibrary(PVOID *libraryHandle, LPCTSTR libraryName, LPCTSTR version)
{
	OPGP_ERROR_STATUS errorStatus;

	OPGP_LOG_START(_T("DYN_LoadLibrary"));
	*libraryHandle = LoadLibrary(libraryName);

	if (*libraryHandle == NULL)
	{
		DWORD errorCode = GetLastError();
		OPGP_ERROR_CREATE_ERROR(errorStatus, errorCode, OPGP_stringify_error(errorCode));
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

	ret = FreeLibrary(*libraryHandle);
	*libraryHandle = NULL;

	/* If the function fails, the return value is zero. To get extended error
	 * information, call GetLastError. */
	if (ret == 0)
	{
		DWORD errorCode = GetLastError();
		OPGP_ERROR_CREATE_ERROR(errorStatus, errorCode, OPGP_stringify_error(errorCode));
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
	CHAR functionAsciiName[256];

	OPGP_LOG_START(_T("DYN_GetAddress"));

	OPGP_LOG_MSG(_T("DYN_GetAddress: Getting address for function \"%s\""), functionName);

	// convert to ascii
	ConvertTToC(functionAsciiName, functionName, 255);

	*functionHandle = NULL;
	*functionHandle = GetProcAddress(libraryHandle, (LPCSTR)functionAsciiName);

	if (*functionHandle == NULL)
	{
		DWORD errorCode = GetLastError();
		OPGP_ERROR_CREATE_ERROR(errorStatus, errorCode, OPGP_stringify_error(errorCode));
		goto end;
	}
	OPGP_ERROR_CREATE_NO_ERROR(errorStatus);
end:
	OPGP_LOG_END(_T("DYN_GetAddress"), errorStatus);
	return errorStatus;
}

#endif	/* WIN32 */

