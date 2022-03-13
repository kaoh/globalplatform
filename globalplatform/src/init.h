/*  Copyright (c) 2022, Karsten Ohme
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
 * This file contains the initialization and deinitialization functionality when loading the library.
*/

#ifndef OPGP_INIT_H
#define OPGP_INIT_H

#ifdef __cplusplus
extern "C"
{
#endif


#include "globalplatform/library.h"

//! \brief Handles the library initialization.
OPGP_NO_API
void init(void);

//! \brief Handles the library deinitialization.
OPGP_NO_API
void fini(void);

#ifdef __cplusplus
}
#endif

#endif
