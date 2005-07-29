/*
 * Copyright (c) 2005, Karsten Ohme
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef WIN32
#include "stdafx.h"
#endif

#ifdef WIN32
#define LOG_FILENAME _T("C:\\TEMP\\OpenPlatform.log")
#else
#define LOG_FILENAME _T("/tmp/OpenPlatform.log")
#define LPTSTR *char
#define LONG long
#define _tgetenv getenv
#define _ftprintf fprintf
#define _sntprintf snprintf
#define _fputts fputs
#define _vftprintf vfprintf
#endif

#ifdef DEBUG
#define LOG_START(x)        log_Start(x, _T(__FILE__), __LINE__)
#define LOG_END(x,rv)       log_End(x, _T(__FILE__), __LINE__, rv)
#else
#define LOG_START(x)
#define LOG_END(x,rv)
#endif

//! \brief Logs something to a file or the syslog. */
void log_Log(LPTSTR msg, ...);

//! \brief Logs the end of a function and its return code. */
void log_End(LPTSTR func, LPTSTR file, int line, LONG rv);

//! \brief Logs the start of a function */
void log_Start(LPTSTR func, LPTSTR file, int line);
