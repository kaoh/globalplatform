/*
 *  Copyright (c) 2005-2026, Karsten Ohme
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
 *  along with GlobalPlatform.  If not, see <https://www.gnu.org/licenses/>.
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
	(void)version; // unused on Windows in your current design

	OPGP_ERROR_STATUS errorStatus;
	*libraryHandle = NULL;

	OPGP_LOG_START(_T("DYN_LoadLibrary"));

	// Copy name so we can append .dll if needed
	TCHAR dllName[MAX_LIBRARY_NAME_SIZE];
	_tcsncpy_s(dllName, MAX_LIBRARY_NAME_SIZE, libraryName, _TRUNCATE);
	ensure_dll_extension(dllName, MAX_LIBRARY_NAME_SIZE);

	// 1) Try OPGP_PLUGIN_PATH first
	{
		const TCHAR *plugin_path = _tgetenv(_T("OPGP_PLUGIN_PATH"));
		if (plugin_path && plugin_path[0] != _T('\0')) {
			TCHAR fullpath[PATH_MAX];
			if (join_path(fullpath, sizeof(fullpath)/sizeof(fullpath[0]), plugin_path, dllName)) {
				*libraryHandle = (PVOID)LoadLibrary(fullpath);
			}
		}
	}

	// 2) Try relative to this module (globalplatform.dll)
	if (*libraryHandle == NULL) {
		TCHAR selfDir[MAX_PATH];
		if (get_self_module_dir(selfDir, sizeof(selfDir)/sizeof(selfDir[0]))) {
			TCHAR fullpath[MAX_PATH];
			if (join_path(fullpath, sizeof(fullpath)/sizeof(fullpath[0]), selfDir, dllName)) {
				*libraryHandle = (PVOID)LoadLibrary(fullpath);
			}
		}
	}

	// 3) Fallback: default search (note: can be affected by DLL search path rules)
	if (*libraryHandle == NULL) {
		*libraryHandle = (PVOID)LoadLibrary(dllName);
	}

	if (*libraryHandle == NULL) {
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

