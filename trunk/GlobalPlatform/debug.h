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

#ifdef WIN32
#include "stdafx.h"
#endif

#include "GlobalPlatform/unicode.h"

#ifdef WIN32
#define LOG_FILENAME _T("C:\\TEMP\\GlobalPlatform.log")
#else
#define LOG_FILENAME _T("/tmp/GlobalPlatform.log")
#define LONG long
#endif

#ifdef DEBUG
#define LOG_START(x)        log_Start(x, _T(__FILE__), __LINE__)
#define LOG_END(x,rv)       log_End(x, _T(__FILE__), __LINE__, rv)
#else
#define LOG_START(x)
#define LOG_END(x,rv)
#endif

//! \brief Logs something to a file or the syslog.
void log_Log(LPTSTR msg, ...);

//! \brief Logs the end of a function and its return code.
void log_End(LPTSTR func, LPTSTR file, int line, LONG rv);

//! \brief Logs the start of a function
void log_Start(LPTSTR func, LPTSTR file, int line);
