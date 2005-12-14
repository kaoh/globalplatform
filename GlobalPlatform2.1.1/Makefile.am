## Process this file with automake to create Makefile.in.

EXTRA_DIST = GlobalPlatform.sln GlobalPlatform.vcproj \
stdafx.c stdafx.h resource.h version.rc DLLMain.c Doxyfile.cfg Makefile.mak

lib_LTLIBRARIES = libGlobalPlatform.la

include_HEADERS =

nobase_include_HEADERS = GlobalPlatform/GlobalPlatform.h GlobalPlatform/unicode.h

libGlobalPlatform_la_SOURCES = GlobalPlatform/GlobalPlatform.h GlobalPlatform.c debug.h debug.c GlobalPlatform/unicode.h
libGlobalPlatform_la_LDFLAGS = -version-info 2:0:1

doc : GlobalPlatform.c GlobalPlatform/GlobalPlatform.h GlobalPlatform/unicode.h
	doxygen Doxyfile.cfg

