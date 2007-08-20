/*
 * Copyright (c) 2007, Karsten Ohme
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

/*
 * Based on a logging file by Chris Osgood <oznet@mac.com>.
 */

#ifdef WIN32
#include "stdafx.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include "debug.h"

#ifdef HAVE_VSYSLOG
#include <syslog.h>
#endif

/**
* The call is redirected to log_Log().
* \param func The function name
*/
void log_Start(LPTSTR func, LPTSTR file, int line)
{
    log_Log(_T("+%s in %s at line %d : start"), func, file, line);
}

/**
* The call is redirected to log_Log().
* \param func The function name
* \param rv The return value of the function
*/
void log_End(LPTSTR func, LPTSTR file, int line, LONG rv)
{
    log_Log(_T(" -%s in %s at line %d : end RV(0x%X)"), func, file, line, rv);
}

/**
* In Unix systems which have a syslog facility the msg is stored there.
* The environment varibale <code>GLOBALPLATFORM_DEBUG</code> must be set to enable the logging.
* With the environment varibale <code>GLOBALPLATFORM_LOGFILE</code> an explicit log file name can
* be set. If a no log file name has been set impilictly <code>/tmp/GlobalPlatform.log</code>
* or <code>C:\TEMP\GlobalPlatform.log</code> under Windows will be used. If a log file name
* is given the syslog if available will not be used.
* \param msg The formatted message which will be stored.
* \prama ... Variable argument list
*/
void log_Log(LPTSTR msg, ...)
{
    va_list args;
    FILE *fp;
    time_t t;
    struct tm *time_s;
    TCHAR format[256];

    if (_tgetenv(_T("GLOBALPLATFORM_DEBUG")))
    {
    #ifdef HAVE_VSYSLOG
    if (getenv("GLOBALPLATFORM_LOGFILE")) {
	goto filelog;
    }
    else {
		va_start(args, msg);
		vsyslog(LOG_USER | LOG_DEBUG, msg, args);
		va_end(args);
		return;
    }
filelog:
    #endif // HAVE_VSYSLOG
    if (_tgetenv(_T("GLOBALPLATFORM_LOGFILE")))
        fp = _tfopen(_tgetenv(_T("GLOBALPLATFORM_LOGFILE")), _T("a"));
    else
        fp = _tfopen(LOG_FILENAME, _T("a"));

    if (!fp)
    {
	fp = stderr;
	_ftprintf(fp, _T("Error, could not open log file: %s\n"), LOG_FILENAME);
    }
    time(&t);
    time_s = localtime(&t);

    _sntprintf(format, 256, _T("%.2d/%.2d %.2d:%.2d:%.2d %s"),
			time_s->tm_mday,
			time_s->tm_mon+1,
			time_s->tm_hour,
			time_s->tm_min,
			time_s->tm_sec,
			msg);

    va_start(args, msg);
    _vftprintf(fp, format, args);
    va_end(args);

    #ifdef WIN32
    _fputts(_T("\r\n"), fp);
    #else
    _fputts(_T("\n"), fp);
    #endif // WIN32

    fflush(fp); /* Fixme: more accurate, but slows logging */

    if (fp != stderr)
        fclose(fp);
    }
}
