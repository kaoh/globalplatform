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

/*
 * Based on a implementation from the Muscle MUSCLE SmartCard Development ( http://www.linuxnet.com ) by David Corcoran <corcoran@linuxnet.com>
 */

/**
 * @file
 * @brief This abstracts dynamic library loading functions.
 */

#ifndef __dyn_generic_h__
#define __dyn_generic_h__

#ifdef __cplusplus
extern "C"
{
#endif

#include "GlobalPlatform/unicode.h"
#include "GlobalPlatform/types.h"
#include "GlobalPlatform/error.h"

//! \brief Loads a library.
OPGP_NO_API
OPGP_ERROR_STATUS DYN_LoadLibrary(PVOID *libraryHandle, LPCTSTR libraryName);

//! \brief Unloads a library.
OPGP_NO_API
OPGP_ERROR_STATUS DYN_CloseLibrary(PVOID *libraryHandle);

//! \brief Gets the address of a function in a library.
OPGP_NO_API
OPGP_ERROR_STATUS DYN_GetAddress(PVOID libraryHandle, PVOID *functionHandle, LPCTSTR functionName);

#ifdef __cplusplus
}
#endif

#endif
