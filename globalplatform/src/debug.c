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
#include <string.h>
#include "globalplatform/debug.h"
#include "globalplatform/error.h"

#ifdef HAVE_VSYSLOG
#include <syslog.h>
#endif

/**
* The call is redirected to log_Log().
* \param func The function name
*/
void OPGP_log_Start(OPGP_STRING func, OPGP_STRING file, int line)
{
    OPGP_log_Msg(_T("+%s in %s at line %d : start"), func, file, line);
}

/**
 * \param msg [in] The message to print in front of the message. If NULL or empty nothing is printed.
 * \param buffer [in] The buffer to print.
 * \param bufferLength [in] The length of the buffer.
 */
void OPGP_log_Hex(OPGP_STRING msg, PBYTE buffer, DWORD bufferLength) {
	TCHAR *bufferMsg;
	int i;
	// each hex string needs the double size + termination
	bufferMsg = (TCHAR *)malloc(bufferLength * sizeof(TCHAR)*2 + 1);
	// allocation did not succeed
	if (bufferMsg == NULL) {
		OPGP_log_Msg(_T("%sLOG ERROR: Could not allocate log buffer."), msg);
		return;
	}
	for (i=0; (DWORD)i<bufferLength; i++) {
		_sntprintf(bufferMsg+(i*2), (bufferLength-i)*sizeof(TCHAR)*2+1, _T("%02X"), (buffer[i] & 0x00FF));
	}
	// print msg or not
	if ((msg == NULL) || (_tcslen(msg) == 0)) {
		OPGP_log_Msg(_T("%s"), bufferMsg);
	}
	else {
		OPGP_log_Msg(_T("%s%s"), msg, bufferMsg);
	}
}

/**
* The call is redirected to log_Log().
* \param func [in] The function name
* \param rv [in] The return value of the function
*/
void OPGP_log_End(OPGP_STRING func, OPGP_STRING file, int line, OPGP_ERROR_STATUS status)
{
	OPGP_log_Msg(_T(" -%s in %s at line %d : end status %d, error code(0x%0X): %s"), func, file, line, status.errorStatus, status.errorCode, status.errorMessage);
}

/**
* In Unix systems which have a syslog facility the msg is stored there.
* The environment varibale <code>GLOBALPLATFORM_DEBUG</code> must be set to enable the logging.
* With the environment varibale <code>GLOBALPLATFORM_LOGFILE</code> an explicit log file name can
* be set. If a no log file name has been set impilictly <code>/tmp/GlobalPlatform.log</code>
* or <code>C:\TEMP\GlobalPlatform.log</code> under Windows will be used. If a log file name
* is given the syslog if available will not be used.
* \param msg The formatted message which will be stored.
* \param ... Variable argument list
*/
void OPGP_log_Msg(OPGP_STRING msg, ...)
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
        fp = _tfopen(OPGP_LOG_FILENAME, _T("a"));

    if (!fp)
    {
	fp = stderr;
	_ftprintf(fp, _T("Error, could not open log file: %s\n"), OPGP_LOG_FILENAME);
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
