## Process this file with automake to create Makefile.in.

EXTRA_DIST= Install.w32 DLLMain.c JOpenPlatformWrapper.sln JOpenPlatformWrapper.vcproj \
stdafx.c stdafx.h version.h version.rc

lib_LTLIBRARIES = libJOpenPlatformWrapper.la
include_HEADERS =

libJOpenPlatformWrapper_la_SOURCES = JOpenPlatformWrapper.h JOpenPlatformWrapper.c org_dyndns_widerstand_OpenPlatform_OPSPWrapper.h
libJOpenPlatformWrapper_la_CPPFLAGS = -I$(JAVA_INC) -I$(JAVA_INC_PLATFORM) $(PCSCLITE_CFLAGS)
libJOpenPlatformWrapper_la_LDFLAGS = -version-info 1:0:0


