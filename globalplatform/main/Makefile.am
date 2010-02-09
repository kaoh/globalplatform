## Process this file with automake to create Makefile.in.

EXTRA_DIST = stdafx.c stdafx.h resource.h version.rc DLLMain.c Doxyfile.cfg Makefile.mak \
unzip/iowin32.c unzip/iowin32.h pcsclite-includes/pcsclite.h \
pcsclite-includes/README pcsclite-includes/wintypes.h pcsclite-includes/winscard.h \
globalplatform/connectionplugin.h

lib_LTLIBRARIES = libGlobalPlatform.la

include_HEADERS =

nobase_include_HEADERS = globalplatform/globalplatform.h globalplatform/unicode.h globalplatform/error.h \
globalplatform/connection.h globalplatform/debug.h globalplatform/errorcodes.h globalplatform/library.h \
globalplatform/types.h globalplatform/stringify.h globalplatform/security.h

libGlobalPlatform_la_SOURCES = GlobalPlatform.c globalplatform/connection.h globalplatform/security.h globalplatform/globalplatform.h globalplatform/debug.h \
globalplatform/unicode.h unzip/crypt.h unzip/ioapi.c unzip/ioapi.h \
unzip/unzip.c unzip/unzip.h unzip/zip.c unzip/zip.h \
globalplatform/errorcodes.h globalplatform/stringify.h globalplatform/types.h globalplatform/error.h \
dyn_generic.h dyn_unix.c connection.c stringify.c crypto.h debug.c util.c util.h loadfile.c loadfile.h crypto.c

libGlobalPlatform_la_LDFLAGS = -version-info 6:0:0 $(PCSCLITE_LIBS)
libGlobalPlatform_la_CPPFLAGS = $(AM_CPPFLAGS) $(PCSCLITE_CFLAGS)

TESTS = GlobalPlatformTest
TESTS_ENVIRONMENT = export LD_LIBRARY_PATH=$(top_builddir)/../gppcscconnectionplugin/.libs/:$LD_LIBRARY_PATH;
check_PROGRAMS = GlobalPlatformTest
GlobalPlatformTest_SOURCES = GlobalPlatformTest.c
GlobalPlatformTest_CFLAGS = @CHECK_CFLAGS@ $(AM_CPPFLAGS) $(PCSCLITE_CFLAGS)
GlobalPlatformTest_LDADD = @CHECK_LIBS@ libGlobalPlatform.la $(PCSCLITE_LIBS)

doc : GlobalPlatform.c globalplatform/globalplatform.h globalplatform/unicode.h globalplatform/connectionplugin.h
	doxygen Doxyfile.cfg

MAINTAINERCLEANFILES = \
	Makefile.in
