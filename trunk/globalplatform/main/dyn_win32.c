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
#include "GlobalPlatform/debug.h"
#include "GlobalPlatform/stringify.h"

/**
 * \param libraryHandle OUT The returned library handle
 * \param libraryName IN The length of the Security Domain AID.
 * \return The error status.
 */
OPGP_ERROR_STATUS DYN_LoadLibrary(PVOID *libraryHandle, LPCTSTR libraryName)
{
	*libraryHandle = NULL;
	OPGP_ERROR_STATUS errorStatus;

	OPGP_LOG_START(_T("DYN_LoadLibrary"));
	*libraryHandle = LoadLibrary(libraryName);

	if (*libraryHandle == NULL)
	{
		DWORD errorCode = GetLastError();
		OPGP_ERROR_CREATE_ERROR(errorStatus, errorCode, stringify_error(errorCode));
		goto end;
	}
	OPGP_ERROR_CREATE_NO_ERROR(errorStatus);
end:
	OPGP_LOG_END(_T("DYN_LoadLibrary"), errorStatus);
	return errorStatus;
}

/**
 * \param libraryHandle IN The library handle
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
		OPGP_ERROR_CREATE_ERROR(errorStatus, errorCode, stringify_error(errorCode));
		goto end;
	}
	OPGP_ERROR_CREATE_NO_ERROR(errorStatus);
end:
	OPGP_LOG_END(_T("DYN_CloseLibrary"), errorStatus);
	return errorStatus;
}

/**
 * \param libraryHandle IN The returned library handle
 * \param functionHandle OUT The returned function handle.
 * \param functionName IN The function name to search.
 * \return The error status.
 */
OPGP_ERROR_STATUS DYN_GetAddress(PVOID libraryHandle, PVOID *functionHandle, LPCTSTR functionName)
{
	OPGP_ERROR_STATUS errorStatus;

	OPGP_LOG_START(_T("DYN_GetAddress"));

	*functionHandle = NULL;
	*functionHandle = GetProcAddress(libraryHandle, functionName);

	if (*functionHandle == NULL)
	{
		DWORD errorCode = GetLastError();
		OPGP_ERROR_CREATE_ERROR(errorStatus, errorCode, stringify_error(errorCode));
		goto end;
	}
	OPGP_ERROR_CREATE_NO_ERROR(errorStatus);
end:
	OPGP_LOG_END(_T("DYN_GetAddress"), errorStatus);
	return errorStatus;
}

#endif	/* WIN32 */

