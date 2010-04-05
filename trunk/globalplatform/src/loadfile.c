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

#include "loadfile.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "util.h"
#include "globalplatform/debug.h"
#include "unzip/zip.h"
#include "unzip/unzip.h"

#define MAX_PATH_LENGTH 256 //!< Max path length

//! \brief Detects if a file is a CAP file.
OPGP_NO_API
int detect_cap_file(OPGP_CSTRING fileName);

/**
 * If loadFileBuf is NULL the loadFileBufSize is ignored and the necessary buffer size
 * is returned in loadFileBufSize and the functions returns.
 * \param fileName [in] The name of the CAP or IJC file.
 * \param loadFileBuf [out] The destination buffer with the Executable Load File contents.
 * \param loadFileBufSize [in, out] The size of the loadFileBuf.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
OPGP_ERROR_STATUS handle_load_file(OPGP_CSTRING fileName, PBYTE loadFileBuf, PDWORD loadFileBufSize)
{
	int rv;
	OPGP_ERROR_STATUS status;
	FILE *file = NULL;
	OPGP_LOG_START(_T("handle_load_file"));
	if (detect_cap_file(fileName)) {
		status = extract_cap_file(fileName, loadFileBuf, loadFileBufSize);
		if (OPGP_ERROR_CHECK(status)) {
			goto end;
		}
	}
	else {
		size_t fileSize;
		file = _tfopen(fileName, _T("rb"));
		if (file == NULL) {
			OPGP_ERROR_CREATE_ERROR(status, errno, OPGP_stringify_error(errno)); goto end;
		}
		rv = fseek(file, 0, SEEK_END);
		if (rv) {
			OPGP_ERROR_CREATE_ERROR(status, errno, OPGP_stringify_error(errno)); goto end;
		}
		fileSize = ftell(file);
		if ((LONG)fileSize == -1L) {
			OPGP_ERROR_CREATE_ERROR(status, errno, OPGP_stringify_error(errno)); goto end;
		}
		rv = fseek(file, 0, SEEK_SET);
		if (rv) {
			OPGP_ERROR_CREATE_ERROR(status, errno, OPGP_stringify_error(errno)); goto end;
		}
		if (loadFileBuf == NULL) {
			*loadFileBufSize = (DWORD)fileSize;
			goto end;
		}
		if (*loadFileBufSize < (DWORD)fileSize) {
			OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end;
		}
		fileSize = fread(loadFileBuf, sizeof(BYTE), fileSize, file);
		if(ferror(file)) {
			OPGP_ERROR_CREATE_ERROR(status, errno, OPGP_stringify_error(errno)); goto end;
		}
		*loadFileBufSize = (DWORD)fileSize;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if (file != NULL) {
		fclose(file);
	}
	OPGP_LOG_END(_T("handle_load_file"), status);
	return status;
}

/**
 * Converts a Unicode char to a single byte char.
 * \param pszDest Single byte char destination
 * \param pszSrc Unicode source buffer
 */
OPGP_NO_API
void convertT_to_C(char* pszDest, const TCHAR* pszSrc)
{
	unsigned int i;
	for(i = 0; i < _tcslen(pszSrc); i++) {
		pszDest[i] = (char) pszSrc[i];
	}
	pszDest[_tcslen(pszSrc)] = '\0';
}


/**
 * If loadFileBuf is NULL the loadFileBufSize is ignored and the necessary buffer size
 * is returned in loadFileBufSize and the functions returns.
 * \param fileName [in] The name of the CAP file.
 * \param loadFileBuf [out] The destination buffer with the Executable Load File contents.
 * \param loadFileBufSize [in, out] The size of the loadFileBuf.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
OPGP_ERROR_STATUS extract_cap_file(OPGP_CSTRING fileName, PBYTE loadFileBuf, PDWORD loadFileBufSize)
{
	int rv;
	OPGP_ERROR_STATUS status;
	zipFile szip;
	unsigned char *appletbuf = NULL;
	unsigned char *classbuf = NULL;
	unsigned char *constantpoolbuf = NULL;
	unsigned char *descriptorbuf = NULL;
	unsigned char *directorybuf = NULL;
	unsigned char *headerbuf = NULL;
	unsigned char *importbuf = NULL;
	unsigned char *methodbuf = NULL;
	unsigned char *reflocationbuf = NULL;
	unsigned char *staticfieldbuf = NULL;
	unsigned char *exportbuf = NULL;

	int appletbufsz = 0;
	int classbufsz = 0;
	int constantpoolbufsz = 0;
	int descriptorbufsz = 0;
	int directorybufsz = 0;
	int headerbufsz = 0;
	int importbufsz = 0;
	int methodbufsz = 0;
	int reflocationbufsz = 0;
	int staticfieldbufsz = 0;
	int exportbufsz = 0;

	unsigned char *buf;
	char capFileName[MAX_PATH_LENGTH];
	DWORD totalSize = 0;

	OPGP_LOG_START(_T("extract_cap_file"));
	convertT_to_C(capFileName, fileName);
#ifdef DEBUG
	OPGP_log_Msg(_T("extract_cap_file: Try to open cap file %s"), fileName);
#endif
	szip = unzOpen((const char *)capFileName);
	if (szip==NULL)
	{
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CAP_UNZIP, OPGP_stringify_error(OPGP_ERROR_CAP_UNZIP)); goto end;
	}
	rv = unzGoToFirstFile(szip);
	while (rv == UNZ_OK)
	{
		// get zipped file info
		unz_file_info unzfi;
		char fn[MAX_PATH_LENGTH];
		int sz;

		if (unzGetCurrentFileInfo(szip, &unzfi, fn, MAX_PATH_LENGTH, NULL, 0, NULL, 0) != UNZ_OK)
		{
			OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CAP_UNZIP, OPGP_stringify_error(OPGP_ERROR_CAP_UNZIP)); goto end;
		}

		if (unzOpenCurrentFile(szip)!=UNZ_OK)
		{
			OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CAP_UNZIP, OPGP_stringify_error(OPGP_ERROR_CAP_UNZIP)); goto end;
		}

#ifdef DEBUG
	OPGP_log_Msg(_T("extract_cap_file: Allocating buffer size for cap file content %s"), fn);
#endif
		// write file
		if (strcmp(fn + strlen(fn)-10, "Header.cap") == 0) {
			totalSize+=unzfi.uncompressed_size;
			headerbufsz = unzfi.uncompressed_size;
			buf = headerbuf = (unsigned char *)malloc(unzfi.uncompressed_size);
		}
		else if (strcmp(fn + strlen(fn)-10, "Applet.cap") == 0) {
			totalSize+=unzfi.uncompressed_size;
			appletbufsz = unzfi.uncompressed_size;
			buf = appletbuf = (unsigned char *)malloc(unzfi.uncompressed_size);
		}
		else if (strcmp(fn + strlen(fn)-9, "Class.cap") == 0) {
			totalSize+=unzfi.uncompressed_size;
			classbufsz = unzfi.uncompressed_size;
			buf = classbuf = (unsigned char *)malloc(unzfi.uncompressed_size);
		}
		else if (strcmp(fn + strlen(fn)-10, "Import.cap") == 0) {
			totalSize+=unzfi.uncompressed_size;
			importbufsz = unzfi.uncompressed_size;
			buf = importbuf = (unsigned char *)malloc(unzfi.uncompressed_size);
		}
		else if (strcmp(fn + strlen(fn)-13, "Directory.cap") == 0) {
			totalSize+=unzfi.uncompressed_size;
			directorybufsz = unzfi.uncompressed_size;
			buf = directorybuf = (unsigned char *)malloc(unzfi.uncompressed_size);
		}
		else if (strcmp(fn + strlen(fn)-10, "Method.cap") == 0) {
			totalSize+=unzfi.uncompressed_size;
			methodbufsz = unzfi.uncompressed_size;
			buf = methodbuf = (unsigned char *)malloc(unzfi.uncompressed_size);
		}
		else if (strcmp(fn + strlen(fn)-16, "ConstantPool.cap") == 0) {
			totalSize+=unzfi.uncompressed_size;
			constantpoolbufsz = unzfi.uncompressed_size;
			buf = constantpoolbuf = (unsigned char *)malloc(unzfi.uncompressed_size);
		}
		else if (strcmp(fn + strlen(fn)-14, "Descriptor.cap") == 0) {
			totalSize+=unzfi.uncompressed_size;
			descriptorbufsz = unzfi.uncompressed_size;
			buf = descriptorbuf = (unsigned char *)malloc(unzfi.uncompressed_size);
		}
		else if (strcmp(fn + strlen(fn)-15, "RefLocation.cap") == 0) {
			totalSize+=unzfi.uncompressed_size;
			reflocationbufsz = unzfi.uncompressed_size;
			buf = reflocationbuf = (unsigned char *)malloc(unzfi.uncompressed_size);
		}
		else if (strcmp(fn + strlen(fn)-15, "StaticField.cap") == 0) {
			totalSize+=unzfi.uncompressed_size;
			staticfieldbufsz = unzfi.uncompressed_size;
			buf = staticfieldbuf = (unsigned char *)malloc(unzfi.uncompressed_size);
		}
		else if (strcmp(fn + strlen(fn)-10, "Export.cap") == 0) {
			totalSize+=unzfi.uncompressed_size;
			exportbufsz = unzfi.uncompressed_size;
			buf = exportbuf = (unsigned char *)malloc(unzfi.uncompressed_size);
		}
		else {
			goto next;
		}

		if ((buf==NULL)&&(unzfi.uncompressed_size!=0))
		{
			OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM)); goto end;
		}
		// read file
		sz = unzReadCurrentFile(szip, buf, unzfi.uncompressed_size);
		if ((unsigned int)sz != unzfi.uncompressed_size)
		{
			OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CAP_UNZIP, OPGP_stringify_error(OPGP_ERROR_CAP_UNZIP)); goto end;
		}

next:
		if (unzCloseCurrentFile(szip)==UNZ_CRCERROR)
		{
			OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CAP_UNZIP, OPGP_stringify_error(OPGP_ERROR_CAP_UNZIP)); goto end;
		}

		rv = unzGoToNextFile(szip);
	}

	if ( rv!=UNZ_END_OF_LIST_OF_FILE )	{
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_CAP_UNZIP, OPGP_stringify_error(OPGP_ERROR_CAP_UNZIP)); goto end;
	}

#ifdef DEBUG
	OPGP_log_Msg(_T("extract_cap_file: Successfully extracted cap file %s"), fileName);
#endif

	if (loadFileBuf == NULL) {
		*loadFileBufSize = totalSize;
		{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
		goto end;
	}

	if (*loadFileBufSize < totalSize) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end;
	}

#ifdef DEBUG
	OPGP_log_Msg(_T("extract_cap_file: Copying extracted cap file contents into buffer"));
#endif
	totalSize = 0;
	if (headerbuf != NULL) {
		memcpy(loadFileBuf+totalSize, headerbuf, headerbufsz);
		totalSize+=headerbufsz;
	}
	if (directorybuf != NULL) {
		memcpy(loadFileBuf+totalSize, directorybuf, directorybufsz);
		totalSize+=directorybufsz;
	}
	if (importbuf != NULL) {
		memcpy(loadFileBuf+totalSize, importbuf, importbufsz);
		totalSize+=importbufsz;
	}
	if (appletbuf != NULL) {
		memcpy(loadFileBuf+totalSize, appletbuf, appletbufsz);
		totalSize+=appletbufsz;
	}
	if (classbuf != NULL) {
		memcpy(loadFileBuf+totalSize, classbuf, classbufsz);
		totalSize+=classbufsz;
	}
	if (methodbuf != NULL) {
		memcpy(loadFileBuf+totalSize, methodbuf, methodbufsz);
		totalSize+=methodbufsz;
	}
	if (staticfieldbuf != NULL) {
		memcpy(loadFileBuf+totalSize, staticfieldbuf, staticfieldbufsz);
		totalSize+=staticfieldbufsz;
	}
	if (exportbuf != NULL) {
		memcpy(loadFileBuf+totalSize, exportbuf, exportbufsz);
		totalSize+=exportbufsz;
	}
	if (constantpoolbuf != NULL) {
		memcpy(loadFileBuf+totalSize, constantpoolbuf, constantpoolbufsz);
		totalSize+=constantpoolbufsz;
	}
	if (reflocationbuf != NULL) {
		memcpy(loadFileBuf+totalSize, reflocationbuf, reflocationbufsz);
		totalSize+=reflocationbufsz;
	}
	if (descriptorbuf != NULL) {
		memcpy(loadFileBuf+totalSize, descriptorbuf, descriptorbufsz);
		totalSize+=descriptorbufsz;
	}
#ifdef DEBUG
	OPGP_log_Msg(_T("extract_cap_file: Buffer copied."));
#endif
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if (szip != NULL) {
		unzClose(szip);
	}
	if (appletbuf != NULL) {
		free(appletbuf);
	}
	if (classbuf != NULL) {
		free(classbuf);
	}
	if (constantpoolbuf != NULL) {
		free(constantpoolbuf);
	}
	if (descriptorbuf != NULL) {
		free(descriptorbuf);
	}
	if (directorybuf != NULL) {
		free(directorybuf);
	}
	if (headerbuf != NULL) {
		free(headerbuf);
	}
	if (importbuf != NULL) {
		free(importbuf);
	}
	if (methodbuf != NULL) {
		free(methodbuf);
	}
	if (reflocationbuf != NULL) {
		free(reflocationbuf);
	}
	if (staticfieldbuf != NULL) {
		free(staticfieldbuf);
	}
	OPGP_LOG_END(_T("extract_cap_file"), status);
	return status;
}

/**
 * Returns 1 if the file is a CAP file 0 otherwise.
 * \param fileName [in] The name of the file.
 * \return 1 if CAP file, 0 otherwise.
 */
int detect_cap_file(OPGP_CSTRING fileName) {
	int rv = 0;
	FILE *loadFile = NULL;
	BYTE magic[2];
	OPGP_ERROR_STATUS status;
	OPGP_LOG_START(_T("detect_cap_file"));
	loadFile = _tfopen(fileName, _T("rb"));
	if (loadFile == NULL) {
		rv = 0;
		goto end;
	}
	if (fread(magic, sizeof(BYTE), sizeof(magic), loadFile) != sizeof(magic)) {
		rv = 0;
		goto end;
	}
#ifdef DEBUG
	OPGP_log_Msg(_T("Magic: 0x%02x 0x%02x"), magic[0], magic[1]);
#endif
	// starts with PK -> is CAP file
	if (magic[0] == 0x50 && magic[1] == 0x4B) {
#ifdef DEBUG
	OPGP_log_Msg(_T("File is a CAP file."));
#endif
		rv = 1;
		goto end;
	}
#ifdef DEBUG
	OPGP_log_Msg(_T("File is not a CAP file."));
#endif
end:
	OPGP_ERROR_CREATE_NO_ERROR(status);
	if (loadFile != NULL) {
		fclose(loadFile);
	}
	OPGP_LOG_END(_T("detect_cap_file"), status);
	return rv;
}

/**
 * \param loadFileName [in] The name of the Executable Load File.
 * \param loadFileParams [out] The parameters of the Executable Load File.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
OPGP_ERROR_STATUS read_executable_load_file_parameters(OPGP_STRING loadFileName, OPGP_LOAD_FILE_PARAMETERS *loadFileParams) {
	OPGP_ERROR_STATUS status;
	PBYTE loadFileBuf = NULL;
	DWORD loadFileBufSize;
	OPGP_LOG_START(_T("read_executable_load_file_parameters"));

	if ((loadFileName == NULL) || (_tcslen(loadFileName) == 0))
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_FILENAME, OPGP_stringify_error(OPGP_ERROR_INVALID_FILENAME)); goto end; }

	status = handle_load_file((OPGP_CSTRING)loadFileName, loadFileBuf, &loadFileBufSize);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	loadFileBuf = (PBYTE)malloc(sizeof(BYTE) * loadFileBufSize);
	if (loadFileBuf == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
		goto end;
	}
	status = handle_load_file((OPGP_CSTRING)loadFileName, loadFileBuf, &loadFileBufSize);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	status = read_executable_load_file_parameters_from_buffer(loadFileBuf, loadFileBufSize, loadFileParams);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if (loadFileBuf != NULL) {
		free(loadFileBuf);
	}
	OPGP_LOG_END(_T("read_executable_load_file_paramaters"), status);
	return status;
}

/**
 * \param capFileName [in] The name of the CAP file.
 * \param ijcFileName [in] The name of the destination IJC file.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
OPGP_ERROR_STATUS cap_to_ijc(OPGP_CSTRING capFileName, OPGP_STRING ijcFileName) {
	OPGP_ERROR_STATUS status;
	PBYTE loadFileBuf = NULL;
	DWORD loadFileBufSize;
	FILE *ijcFile = NULL;
	size_t written = 0;
	OPGP_LOG_START(_T("cap_to_ijc"));

	if ((capFileName == NULL) || (_tcslen(capFileName) == 0))
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_FILENAME, OPGP_stringify_error(OPGP_ERROR_INVALID_FILENAME)); goto end; }

	status = extract_cap_file(capFileName, loadFileBuf, &loadFileBufSize);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	loadFileBuf = (PBYTE)malloc(sizeof(BYTE) * loadFileBufSize);
	if (loadFileBuf == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, ENOMEM, OPGP_stringify_error(ENOMEM));
		goto end;
	}
	status = extract_cap_file(capFileName, loadFileBuf, &loadFileBufSize);
	if (OPGP_ERROR_CHECK(status)) {
		goto end;
	}
	ijcFile = _tfopen(ijcFileName, _T("wb"));
	if (ijcFile == NULL) {
		OPGP_ERROR_CREATE_ERROR(status, errno, OPGP_stringify_error(errno));
		goto end;
	}
	written = fwrite(loadFileBuf, sizeof(BYTE), loadFileBufSize, ijcFile);
	if (ferror(ijcFile) || (loadFileBufSize != written)) {
		OPGP_ERROR_CREATE_ERROR(status, errno, OPGP_stringify_error(errno));
		goto end;
	}
	fclose(ijcFile);
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	if (loadFileBuf != NULL) {
		free(loadFileBuf);
	}
	if (ijcFile != NULL) {
		fclose(ijcFile);
	}
	OPGP_LOG_END(_T("cap_to_ijc"), status);
	return status;
}


/**
 * \param loadFileBuf [in] contents of a Executable Load File.
 * \param loadFileBufSize [in] size of loadFileBuf.
 * \param loadFileParams [out] The parameters of the Executable Load File.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
OPGP_ERROR_STATUS read_executable_load_file_parameters_from_buffer(PBYTE loadFileBuf, DWORD loadFileBufSize, OPGP_LOAD_FILE_PARAMETERS *loadFileParams) {
	OPGP_ERROR_STATUS status;
	DWORD fileSize;
	BYTE packageAID[16];
	BYTE packageAIDLength;
	BYTE appletCount;
	DWORD i, offset=0;
	OPGP_AID appletAIDs[32];
	DWORD componentSize;
	DWORD componentOffset=0;
	OPGP_LOG_START(_T("read_executable_load_file_parameters_from_buffer"));
	fileSize = loadFileBufSize;
	/* header component */
	offset = componentOffset;
	/* tag COMPONENT_Header */
	offset++;
	/* size of header_component */
	if (loadFileBufSize < offset+2) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_LOAD_FILE, OPGP_stringify_error(OPGP_ERROR_INVALID_LOAD_FILE));
		goto end;
	}
	componentSize = get_short(loadFileBuf, offset);
	offset+=2;
	/* magic DECAFFED */
	offset+=4;
	/* minor version */
	offset++;
	/* major version */
	offset++;
	/* flags */
	offset++;
	/* this_package package_info structure */
	/* minor version */
	offset++;
	/* major version */
	offset++;
	/* AID_length */

	if (loadFileBufSize < offset+1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_LOAD_FILE, OPGP_stringify_error(OPGP_ERROR_INVALID_LOAD_FILE));
		goto end;
	}
	packageAIDLength = loadFileBuf[offset];
	offset++;
#ifdef DEBUG
	OPGP_log_Msg(_T("Package AID Length: %d"), packageAIDLength);
#endif
	if (packageAIDLength < 5 || packageAIDLength > 16) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_LOAD_FILE, OPGP_stringify_error(OPGP_ERROR_INVALID_LOAD_FILE));
		goto end;
	}
	/* AID */
	if (loadFileBufSize < offset+packageAIDLength+1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_LOAD_FILE, OPGP_stringify_error(OPGP_ERROR_INVALID_LOAD_FILE));
		goto end;
	}
	memcpy(packageAID, loadFileBuf+offset, packageAIDLength);
	offset+=packageAIDLength;
#ifdef DEBUG
	OPGP_log_Hex(_T("Package AID: "), packageAID, packageAIDLength);
#endif
	/* directory component */
	componentOffset+=componentSize+3;
	offset = componentOffset;
	/* tag COMPONENT_Directory */
	offset++;
	/* size */
	if (loadFileBufSize < offset+2) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_LOAD_FILE, OPGP_stringify_error(OPGP_ERROR_INVALID_LOAD_FILE));
		goto end;
	}
	componentSize = get_short(loadFileBuf, offset);
	offset+=2;

	/* Import Component */
	componentOffset+=componentSize+3;
	offset = componentOffset;
	/* tag COMPONENT_Import */
	offset++;
	/* size */
	if (loadFileBufSize < offset+2) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_LOAD_FILE, OPGP_stringify_error(OPGP_ERROR_INVALID_LOAD_FILE));
		goto end;
	}
	componentSize = get_short(loadFileBuf, offset);
	offset+=2;

	/* Applet Component */
	componentOffset+=componentSize+3;
	offset = componentOffset;
	/* tag COMPONENT_Applet */
	offset++;
	/* size */
	if (loadFileBufSize < offset+2) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_LOAD_FILE, OPGP_stringify_error(OPGP_ERROR_INVALID_LOAD_FILE));
		goto end;
	}
	componentSize = get_short(loadFileBuf, offset);
	offset+=2;
	/* count */
	/* applet_count */
	if (loadFileBufSize < offset+1) {
		OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_LOAD_FILE, OPGP_stringify_error(OPGP_ERROR_INVALID_LOAD_FILE));
		goto end;
	}
	appletCount = loadFileBuf[offset];
	offset++;
#ifdef DEBUG
	OPGP_log_Msg(_T("Applet count: %d"), appletCount);
#endif
	/* applets */
	for (i=0; i<appletCount; i++) {
		/* AID_length */
		if (loadFileBufSize < offset+1) {
			OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_LOAD_FILE, OPGP_stringify_error(OPGP_ERROR_INVALID_LOAD_FILE));
			goto end;
		}
		appletAIDs[i].AIDLength = loadFileBuf[offset];
		offset++;
		if (appletAIDs[i].AIDLength < 5 || appletAIDs[i].AIDLength > 16) {
			OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_LOAD_FILE, OPGP_stringify_error(OPGP_ERROR_INVALID_LOAD_FILE));
			goto end;
		}
		if (loadFileBufSize < offset+appletAIDs[i].AIDLength+1) {
			OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INVALID_LOAD_FILE, OPGP_stringify_error(OPGP_ERROR_INVALID_LOAD_FILE));
			goto end;
		}
		/* AID */
		memcpy(appletAIDs[i].AID, loadFileBuf+offset, appletAIDs[i].AIDLength);
		offset+=appletAIDs[i].AIDLength;
#ifdef DEBUG
		OPGP_log_Hex(_T("Applet AID: "), appletAIDs[i].AID, appletAIDs[i].AIDLength);
#endif
		/* install_method_offset */
		offset+=2;
	}
	loadFileParams->loadFileSize = fileSize;
	loadFileParams->numAppletAIDs = appletCount;
	memcpy(loadFileParams->loadFileAID.AID, packageAID, packageAIDLength);
	loadFileParams->loadFileAID.AIDLength = packageAIDLength;
	for (i=0; i<appletCount; i++) {
		memcpy(loadFileParams->appletAIDs[i].AID, appletAIDs[i].AID, appletAIDs[i].AIDLength);
		loadFileParams->appletAIDs[i].AIDLength = appletAIDs[i].AIDLength;
	}
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("read_executable_load_file_paramaters_from_buffer"), status);
	return status;
}

/**
 * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be 0, if the card does not need or support this tags.
 * \param executableLoadFileAID [in] A buffer containing the Executable Load File AID.
 * \param executableLoadFileAIDLength [in] The length of the Executable Load File AID.
 * \param securityDomainAID [in] A buffer containing the Security Domain AID.
 * \param securityDomainAIDLength [in] The length of the Security Domain AID.
 * \param loadFileDataBlockHash [in] The Load File DAP.
 * \param nonVolatileCodeSpaceLimit [in] The minimum space required to store the application code.
 * \param volatileDataSpaceLimit [in] The minimum amount of RAM space that must be available.
 * \param nonVolatileDataSpaceLimit [in] The minimum amount of space for objects of the application, i.e. the data allocated in its lifetime.
 * \param loadData [out] The data to sign in a load data.
 * \param loadDataLength [in, out] The length of the loadData buffer.
 * \return OPGP_ERROR_SUCCESS if no error, error code else.
 */
OPGP_ERROR_STATUS get_load_data(PBYTE executableLoadFileAID, DWORD executableLoadFileAIDLength,
						  PBYTE securityDomainAID,
								   DWORD securityDomainAIDLength, BYTE loadFileDataBlockHash[20],
								   DWORD nonVolatileCodeSpaceLimit, DWORD volatileDataSpaceLimit,
								   DWORD nonVolatileDataSpaceLimit, PBYTE loadData,
								   PDWORD loadDataLength) {
	OPGP_ERROR_STATUS status;
	unsigned char buf[258];
	DWORD i=0;
	DWORD hiByte, loByte;
	DWORD staticSize;
	OPGP_LOG_START(_T("get_load_data"));
	buf[i++] = 0x02;
	buf[i++] = 0x00;
	buf[i++] = 0x00; // Lc dummy
	buf[i++] = (BYTE)executableLoadFileAIDLength; // Executable Load File AID
	memcpy(buf+i, executableLoadFileAID, executableLoadFileAIDLength);
	i+=executableLoadFileAIDLength;
	buf[i++] = (BYTE)securityDomainAIDLength; // Security Domain AID
	memcpy(buf+i, securityDomainAID, securityDomainAIDLength);
	i+=securityDomainAIDLength;
	if (loadFileDataBlockHash != NULL) {
		buf[i++] = 0x14; // length of SHA-1 hash
		memcpy(buf+i, loadFileDataBlockHash, 20);
		i+=20;
	}
	else buf[i++] = 0x00;
	if ((volatileDataSpaceLimit != 0) || (nonVolatileCodeSpaceLimit != 0) ||
(nonVolatileDataSpaceLimit != 0)) {
		buf[i++] = 0x02; // load parameter field
		if (volatileDataSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileDataSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileCodeSpaceLimit != 0)
			buf[i-1] += 4;
		buf[i++] = 0xEF;
		buf[i++] = 0x00;
		if (volatileDataSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileDataSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileCodeSpaceLimit != 0)
			buf[i-1] += 4;
		if (nonVolatileCodeSpaceLimit != 0) {
			buf[i++] = 0xC6; // non-volatile code space limit.
			buf[i++] = 0x02; //
			staticSize = 8 - (nonVolatileCodeSpaceLimit % 8) + 8;
            nonVolatileCodeSpaceLimit += staticSize;
			hiByte = nonVolatileCodeSpaceLimit >> 8;
			loByte = nonVolatileCodeSpaceLimit - (hiByte << 8);
			buf[i++] = (BYTE)hiByte; // minimum amount
			buf[i++] = (BYTE)loByte; // of space needed
		}
		if (volatileDataSpaceLimit != 0) {
			buf[i++] = 0xC7;
			buf[i++] = 0x02;
			hiByte = volatileDataSpaceLimit >> 8;
			loByte = volatileDataSpaceLimit - (hiByte << 8);
			buf[i++] = (BYTE)hiByte;
			buf[i++] = (BYTE)loByte;
		}
		if (nonVolatileDataSpaceLimit != 0) {
			buf[i++] = 0xC8;
			buf[i++] = 0x02;
			hiByte = nonVolatileDataSpaceLimit >> 8;
			loByte = nonVolatileDataSpaceLimit - (hiByte << 8);
			buf[i++] = (BYTE)hiByte;
			buf[i++] = (BYTE)loByte;
		}
	}
	else buf[i++] = 0x00;

	buf[2] = (BYTE)i-3+128; // Lc (including 128 byte RSA signature length)
	if (i > *loadDataLength) {
		{ OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end; }
	}
	memcpy(loadData, buf, i);
	*loadDataLength = i;
#ifdef DEBUG
	OPGP_log_Hex(_T("get_load_data: Gathered data : "), loadData, *loadDataLength);
#endif
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("get_load_data"), status);
	return status;
}

/**
 * Reads a DAP block and parses it to the buffer buf.
 * \param buf [out] The buffer.
 * \param bufLength [in, out] The length of the buffer and the returned data.
 * \param loadFileDataBlockSignature [in] The Load File Data Block Signature.
 * \return OPGP_ERROR_SUCCESS if no error, error code else
 */
OPGP_ERROR_STATUS read_load_file_data_block_signature(PBYTE buf, PDWORD bufLength, GP211_DAP_BLOCK loadFileDataBlockSignature) {
	OPGP_ERROR_STATUS status;
	DWORD j=0;
	DWORD length;
	OPGP_LOG_START(_T("read_load_file_data_block_signature"));

	/* Length = Tag + length signature block + Tag + length SD AID
	 * + Tag + length signature
	 */
	/* signature length */
	length = loadFileDataBlockSignature.signatureLength;
	/* Tag signature */
	length++;
	/* length byte signature */
	length++;
	/* Dealing with BER length encoding - if greater than 127 coded on two bytes. */
	if (length > 127) {
		length++;
	}
	/* SD AID length */
	length+=loadFileDataBlockSignature.securityDomainAIDLength;
	/* Tag SD */
	length++;
	/* length byte SD */
	length++;

	if (length <= 127) {
		if (length+2 > *bufLength) {
			OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end;
		}
	}
	else {
		if (length+3 > *bufLength) {
			OPGP_ERROR_CREATE_ERROR(status, OPGP_ERROR_INSUFFICIENT_BUFFER, OPGP_stringify_error(OPGP_ERROR_INSUFFICIENT_BUFFER)); goto end;
		}
	}

	buf[j++] = 0xE2; // Tag indicating a DAP block.

	if (length <= 127) {
		buf[j++] = (BYTE)length;
	}
	else if (length > 127) {
		buf[j++] = 0x81;
		buf[j++] = (BYTE)length;
	}

	buf[j++] = 0x4F; // Tag indicating a Security Domain AID.
	buf[j++] = loadFileDataBlockSignature.securityDomainAIDLength;
	memcpy(buf+j, loadFileDataBlockSignature.securityDomainAID, loadFileDataBlockSignature.securityDomainAIDLength);
	j+=loadFileDataBlockSignature.securityDomainAIDLength;
	buf[j++] = 0xC3; // The Tag indicating a signature
	/* Dealing with BER length encoding - if greater than 127 coded on two bytes. */
	if (loadFileDataBlockSignature.signatureLength <= 127) {
		buf[j++] = loadFileDataBlockSignature.signatureLength;
	}
	else if (loadFileDataBlockSignature.signatureLength > 127) {
		buf[j++] = 0x81;
		buf[j++] = loadFileDataBlockSignature.signatureLength;
	}
	memcpy(buf+j, loadFileDataBlockSignature.signature, loadFileDataBlockSignature.signatureLength);
	j+=loadFileDataBlockSignature.signatureLength;
	{ OPGP_ERROR_CREATE_NO_ERROR(status); goto end; }
end:
	OPGP_LOG_END(_T("read_load_file_data_block_signature"), status);
	return status;
}
