## Process this file with automake to create Makefile.in.

EXTRA_DIST = GlobalPlatform.sln GlobalPlatform.vcproj \
stdafx.c stdafx.h version.h version.rc DLLMain.c Doxyfile.cfg

lib_LTLIBRARIES = libGlobalPlatform.la

include_HEADERS =

nobase_include_HEADERS = GlobalPlatform/GlobalPlatform.h GlobalPlatform/unicode.h

libOpenPlatform_la_SOURCES = GlobalPlatform/GlobalPlatform.h GlobalPlatform.c version.h debug.h debug.c GlobalPlatform/unicode.h
libOpenPlatform_la_LDFLAGS = -version-info 1:0:0

doc : GlobalPlatform.c GlobalPlatform.h
	doxygen Doxyfile.cfg

