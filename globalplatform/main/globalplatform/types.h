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

/*! \file
 * This file contains type definitions.
*/

#ifndef OPGP_TYPES_H
#define OPGP_TYPES_H

#ifndef _WIN32
#include <PCSC/wintypes.h>
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
typedef char *PBYTE; //!< A Microsoft/Muscle LPBYTE, pointer to unsigned char.
#if !defined(__wintypes_h__)
typedef unsigned long *PDWORD; //!< A Microsoft LPDWORD/Muscle pointer to a DWORD.
typedef char BYTE; //!< A Microsoft/Muscle BYTE definition.
typedef unsigned long DWORD; //!< A Microsoft/Muscle DWORD definition.
#endif
typedef long LONG; //!< A long value.
#endif

#endif

