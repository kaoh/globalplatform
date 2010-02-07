## Process this file with automake to create Makefile.in.

EXTRA_DIST = stdafx.c stdafx.h resource.h version.rc DLLMain.c Doxyfile.cfg Makefile.mak \
unzip/iowin32.c unzip/iowin32.h pcsclite-includes/pcsclite.h \
pcsclite-includes/README pcsclite-includes/wintypes.h pcsclite-includes/winscard.h

lib_LTLIBRARIES = libGlobalPlatform.la

include_HEADERS =

nobase_include_HEADERS = GlobalPlatform/GlobalPlatform.h GlobalPlatform/unicode.h GlobalPlatform/error.h \
GlobalPlatform/connection.h GlobalPlatform/debug.h GlobalPlatform/errorcodes.h GlobalPlatform/library.h \
GlobalPlatform/types.h GlobalPlatform/stringify.h GlobalPlatform/security.h

libGlobalPlatform_la_SOURCES = GlobalPlatform.c GlobalPlatform/connection.h GlobalPlatform/security.h GlobalPlatform/GlobalPlatform.h GlobalPlatform/debug.h \
GlobalPlatform/unicode.h unzip/crypt.h unzip/ioapi.c unzip/ioapi.h \
unzip/unzip.c unzip/unzip.h unzip/zip.c unzip/zip.h \
GlobalPlatform/errorcodes.h GlobalPlatform/stringify.h GlobalPlatform/types.h GlobalPlatform/error.h \
dyn_generic.h dyn_unix.c connection.c stringify.c crypto.h debug.c util.c util.h loadfile.c loadfile.h crypto.c

libGlobalPlatform_la_LDFLAGS = -version-info 6:0:0 $(PCSCLITE_LIBS)
libGlobalPlatform_la_CPPFLAGS = $(AM_CPPFLAGS) $(PCSCLITE_CFLAGS)

TESTS = GlobalPlatformTest
TESTS_ENVIRONMENT = export LD_LIBRARY_PATH=$(top_builddir)/plugins/pcsc/.libs/:$LD_LIBRARY_PATH;
check_PROGRAMS = GlobalPlatformTest
GlobalPlatformTest_SOURCES = GlobalPlatformTest.c
GlobalPlatformTest_CFLAGS = @CHECK_CFLAGS@ $(AM_CPPFLAGS) $(PCSCLITE_CFLAGS)
GlobalPlatformTest_LDADD = @CHECK_LIBS@ libGlobalPlatform.la $(PCSCLITE_LIBS)

doc : GlobalPlatform.c GlobalPlatform/GlobalPlatform.h GlobalPlatform/unicode.h
	doxygen Doxyfile.cfg

MAINTAINERCLEANFILES = \
	Makefile.in
