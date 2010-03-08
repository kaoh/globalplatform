## Process this file with automake to create Makefile.in.

EXTRA_DIST = stdafx.c stdafx.h resource.h version.rc DLLMain.c Doxyfile.cfg Makefile.mak \
unzip/iowin32.c unzip/iowin32.h pcsclite-includes/pcsclite.h makefile.targ.inc makefile.inc \
pcsclite-includes/README pcsclite-includes/wintypes.h pcsclite-includes/winscard.h \
globalplatform/connectionplugin.h

lib_LTLIBRARIES = libglobalplatform.la

include_HEADERS =

nobase_include_HEADERS = globalplatform/globalplatform.h globalplatform/unicode.h globalplatform/error.h \
globalplatform/connection.h globalplatform/debug.h globalplatform/errorcodes.h globalplatform/library.h \
globalplatform/types.h globalplatform/stringify.h globalplatform/security.h globalplatform/connectionplugin.h

libglobalplatform_la_SOURCES = globalplatform.c globalplatform/connection.h globalplatform/security.h globalplatform/globalplatform.h globalplatform/debug.h \
globalplatform/unicode.h unzip/crypt.h unzip/ioapi.c unzip/ioapi.h \
unzip/unzip.c unzip/unzip.h unzip/zip.c unzip/zip.h \
globalplatform/errorcodes.h globalplatform/stringify.h globalplatform/types.h globalplatform/error.h \
dyn_generic.h dyn_unix.c connection.c stringify.c crypto.h debug.c util.c util.h loadfile.c loadfile.h crypto.c

libglobalplatform_la_LDFLAGS = -version-info 6:0:0 $(PCSCLITE_LIBS)
libglobalplatform_la_CPPFLAGS = $(AM_CPPFLAGS) $(PCSCLITE_CFLAGS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = globalplatform.pc

TESTS = globalplatformTest
TESTS_ENVIRONMENT = ls -la $(top_builddir)/../gppcscconnectionplugin/src/.libs/; export LD_LIBRARY_PATH=$(top_builddir)/../gppcscconnectionplugin/src/.libs/:$LD_LIBRARY_PATH;
check_PROGRAMS = globalplatformTest
globalplatformTest_SOURCES = globalplatformTest.c
globalplatformTest_CFLAGS = @CHECK_CFLAGS@ $(AM_CPPFLAGS) $(PCSCLITE_CFLAGS)
globalplatformTest_LDADD = @CHECK_LIBS@ libglobalplatform.la $(PCSCLITE_LIBS)

doc : globalplatform.c globalplatform/globalplatform.h globalplatform/unicode.h globalplatform/connectionplugin.h
	doxygen Doxyfile.cfg

MAINTAINERCLEANFILES = \
	Makefile.in
