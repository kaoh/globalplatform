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

/*! @file
 * This file defines error structures and functions.
 */

#ifndef OPGP_ERROR_H
#define OPGP_ERROR_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "unicode.h"

#ifdef _WIN32
#define OPGP_ERROR_STATUS_SUCCESS ERROR_SUCCESS //!< No error occured.
#else
#define OPGP_ERROR_STATUS_SUCCESS 0 //!< No error occured.
#endif

#define OPGP_ERROR_STATUS_FAILURE 1 //!< An error occurred.

#define ERROR_MESSAGE_LENGTH 256

/**
 * This structure defines the error status returned by all functions.
 */
typedef struct {
	LONG errorStatus; //!< Identifies, if an error occurred. If no error occurred #OPGP_ERROR_STATUS_SUCCESS must be set. The following fields can be ignored in this case.
	LONG errorCode; //!< The error code.
	TCHAR errorMessage[ERROR_MESSAGE_LENGTH+1]; //!< The error message.
} OPGP_ERROR_STATUS;

/**
 * Returns non zero if an error happened.
 * \param status Must be the #OPGP_ERROR_STATUS structure.
 */
#define OPGP_ERROR_CHECK(status) status.errorStatus

/**
 * Sets the status in case of an error.
 * \param status Must be the #OPGP_ERROR_STATUS structure.
 * \param code Is the error code of the failed function.
 * \param message Is the associated error message.
 */
#define OPGP_ERROR_CREATE_ERROR(status, code, message) status.errorStatus = OPGP_ERROR_STATUS_FAILURE; \
	status.errorCode = code; \
	_tcsncpy(status.errorMessage, message, ERROR_MESSAGE_LENGTH); status.errorMessage[ERROR_MESSAGE_LENGTH] = _T('\0')

/**
 * Sets the status in case of no error.
 * \param status Must be the #OPGP_ERROR_STATUS structure.
 */
#define OPGP_ERROR_CREATE_NO_ERROR(status) status.errorStatus = OPGP_ERROR_STATUS_SUCCESS; status.errorCode = 0; \
	_tcsncpy(status.errorMessage, _T("Success"), ERROR_MESSAGE_LENGTH); status.errorMessage[ERROR_MESSAGE_LENGTH] = _T('\0')

/**
 * Sets the status in case of no error but includes a code e.g. for APDU status word codes.
 * \param status Must be the #OPGP_ERROR_STATUS structure.
 * \param code Must be the error code.
 * \param message Is the associated error message.
 */
#define OPGP_ERROR_CREATE_NO_ERROR_WITH_CODE(status, code, message) status.errorStatus = OPGP_ERROR_STATUS_SUCCESS; \
	status.errorCode = code; \
	_tcsncpy(status.errorMessage, message, ERROR_MESSAGE_LENGTH); status.errorMessage[ERROR_MESSAGE_LENGTH] = _T('\0')

#ifdef __cplusplus
}
#endif
#endif

