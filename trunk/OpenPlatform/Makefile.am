## Process this file with automake to create Makefile.in.

EXTRA_DIST = OpenPlatform.sln OpenPlatform.vcproj \
stdafx.c stdafx.h resource.h version.rc DLLMain.c Doxyfile.cfg

lib_LTLIBRARIES = libOpenPlatform.la

include_HEADERS =

nobase_include_HEADERS = OpenPlatform/OpenPlatform.h OpenPlatform/unicode.h

libOpenPlatform_la_SOURCES = OpenPlatform/OpenPlatform.h OpenPlatform.c debug.h debug.c OpenPlatform/unicode.h
libOpenPlatform_la_LDFLAGS = -version-info 1:2:0

doc : OpenPlatform.c OpenPlatform.h
	doxygen Doxyfile.cfg

