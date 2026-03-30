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

/*! @file
 * Contains mappings for Unicode functions.
 */

#ifndef OPGP_UNICODE_H
#define OPGP_UNICODE_H

#ifdef WIN32
#include <tchar.h>
#endif

#ifndef WIN32
#define _tmain main
#define _TCHAR char
#define TCHAR char
#define _T(arg) arg
#define _tcsncpy strncpy
#define _tcscpy strcpy
#define _tcscmp strcmp
#define _tcslen strlen
#define _tprintf printf
#define _tfopen fopen
#define _stprintf sprintf
#define _tgetenv getenv
#define _ftprintf fprintf
#define _sntprintf snprintf
#define _fputts fputs
#define _vftprintf vfprintf
#define _tcserror_s strerror_r
#endif

#endif
