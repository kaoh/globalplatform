/*  Copyright (c) 2009, Karsten Ohme
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
 * This file contains debug functions.
*/

#ifndef OPGP_DEBUG_H
#define OPGP_DEBUG_H

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef WIN32
#include "stdafx.h"
#endif

#include "types.h"
#include "library.h"
#include "unicode.h"
#include "error.h"

#ifdef WIN32
#define OPGP_LOG_FILENAME _T("C:\\TEMP\\GlobalPlatform.log")
#else
#define OPGP_LOG_FILENAME _T("/tmp/GlobalPlatform.log")
#endif

#ifdef OPGP_DEBUG
#define OPGP_LOG_START(msg)        OPGP_log_Start(msg, _T(__FILE__), __LINE__)
#define OPGP_LOG_MSG(...)	OPGP_log_Msg(__VA_ARGS__)
#define OPGP_LOG_END(msg, status)       OPGP_log_End(msg, _T(__FILE__), __LINE__, status)
#define OPGP_LOG_HEX(msg, buffer, bufferLength) OPGP_log_Hex(msg, buffer, bufferLength)
#else
#define OPGP_LOG_START(msg)
#define OPGP_LOG_END(msg,rv)
#define OPGP_LOG_HEX(msg, buffer, bufferLength)
#define OPGP_LOG_MSG(...)
#endif

//! \brief Logs something to a file or the syslog.
OPGP_API
void OPGP_log_Msg(OPGP_STRING msg, ...);

//! \brief Logs the end of a function and its return code.
OPGP_API
void OPGP_log_End(OPGP_STRING func, OPGP_STRING file, int line, OPGP_ERROR_STATUS status);

//! \brief Logs the start of a function
OPGP_API
void OPGP_log_Start(OPGP_STRING func, OPGP_STRING file, int line);

//! \brief Logs a buffer as hex string.
OPGP_API
void OPGP_log_Hex(OPGP_STRING msg, PBYTE buffer, DWORD bufferLength);

#ifdef __cplusplus
}
#endif
#endif
