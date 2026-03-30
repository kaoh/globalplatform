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
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU Lesser General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.
 */

/*! \file
 * This file contains type definitions.
*/

#ifndef OPGP_TYPES_H
#define OPGP_TYPES_H

#ifndef _WIN32
#include <wintypes.h>

#ifndef LPTSTR
typedef char *LPTSTR;
#endif
#ifndef LPCTSTR
typedef const char *LPCTSTR;
#endif

#else
#include <windows.h>
#endif

typedef void *PVOID; //!< Pointer definition.
#ifdef _WIN32
typedef LPTSTR OPGP_STRING; //!< A Microsoft/Muscle LPTSTR.
typedef LPCTSTR OPGP_CSTRING; //!< A Microsoft/Muscle LPCTSTR.
typedef LPBYTE PBYTE; //!< A Microsoft/Muscle LPBYTE, pointer to unsigned char.
typedef LPDWORD PDWORD; //!< A Microsoft LPDWORD/Muscle pointer to a double word, pointer to unsigned long.
#else
#ifndef NULL
#define NULL 0
#endif
typedef char *OPGP_STRING; //!< A Microsoft/Muscle LPTSTR.
typedef const char *OPGP_CSTRING; //!< A Microsoft/Muscle LPCTSTR.
typedef unsigned char *PBYTE; //!< A Microsoft/Muscle LPBYTE, pointer to unsigned char.
#if !defined(__wintypes_h__)
typedef unsigned long *PDWORD; //!< A Microsoft LPDWORD/Muscle pointer to a DWORD.
typedef unsigned char BYTE; //!< A Microsoft/Muscle BYTE definition.
typedef unsigned long DWORD; //!< A Microsoft/Muscle DWORD definition.
typedef long LONG; //!< A long value.
#endif

#endif

#endif
