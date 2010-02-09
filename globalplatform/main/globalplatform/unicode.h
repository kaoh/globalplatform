/*  Copyright (c) 2007, Karsten Ohme
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

/*! @file
 * Contains mappings for Unicode functions.
 */

#ifndef OPGP_UNICODE_H
#define OPGP_UNICODE_H

#ifndef WIN32
#define _tmain main
#define _TCHAR char
#define TCHAR char
#if !defined(__wintypes_h__)
#define LPTSTR char *
#define LPCTSTR const char *
#endif
#define _T(arg) arg
#define _tcsncpy strncpy
#define _tcscpy strcpy
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
