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
 * This file contains Load File functionality.
*/

#ifndef OPGP_LOADFILE_H
#define OPGP_LOADFILE_H

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef WIN32
#include "stdafx.h"
#endif

#include "globalplatform/types.h"
#include "globalplatform/error.h"
#include "globalplatform/library.h"
#include "globalplatform/globalplatform.h"

//! \brief Handles a CAP or IJC file and copies the Executable Load File contents.
OPGP_NO_API
OPGP_ERROR_STATUS handle_load_file(OPGP_CSTRING fileName, PBYTE loadFileBuf, PDWORD loadFileBufSize);

//! \brief Extracts a CAP file.
OPGP_NO_API
OPGP_ERROR_STATUS extract_cap_file(OPGP_CSTRING fileName, PBYTE loadFileBuf, PDWORD loadFileBufSize);

 //! \brief Reads a DAP block and parses it to the buffer buf.
OPGP_NO_API
OPGP_ERROR_STATUS read_load_file_data_block_signature(PBYTE buf, PDWORD bufLength, GP211_DAP_BLOCK loadFileDataBlockSignature);

//! \brief Converts a CAP file to an IJC file (Executable Load File).
OPGP_NO_API
OPGP_ERROR_STATUS cap_to_ijc(OPGP_CSTRING capFileName, OPGP_STRING ijcFileName);


//! \brief Gets the data for a GP211_install_for_load() command.
OPGP_NO_API
OPGP_ERROR_STATUS get_load_data(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						  PBYTE securityDomainAID,
								   DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20],
								   DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
								   DWORD nonVolatileDataSpaceLimit, PBYTE loadData,
								   PDWORD loadDataLength);

//! \brief Can read CAP and IJC files (concatenated extracted CAP files).
OPGP_NO_API
OPGP_ERROR_STATUS read_executable_load_file_parameters(OPGP_STRING loadFileName, OPGP_LOAD_FILE_PARAMETERS *loadFileParams);

//! \brief Reads Executable Load File parameters from a buffer.
OPGP_NO_API
OPGP_ERROR_STATUS read_executable_load_file_parameters_from_buffer(PBYTE loadFileBuf, DWORD loadFileBufSize, OPGP_LOAD_FILE_PARAMETERS *loadFileParams);


#ifdef __cplusplus
}
#endif

#endif
