## Process this file with automake to create Makefile.in.

EXTRA_DIST = GlobalPlatform.sln GlobalPlatform.vcproj \
stdafx.c stdafx.h resource.h version.rc DLLMain.c Doxyfile.cfg Makefile.mak \
unzip/iowin32.c unzip/iowin32.h reconf GlobalPlatform.sln.old \
GlobalPlatform.vcproj.7.10.old pcsclite-includes/pcsclite.h \
pcsclite-includes/README pcsclite-includes/wintypes.h pcsclite-includes/winscard.h

lib_LTLIBRARIES = libGlobalPlatform.la

include_HEADERS =

nobase_include_HEADERS = GlobalPlatform/GlobalPlatform.h GlobalPlatform/unicode.h

libGlobalPlatform_la_SOURCES = GlobalPlatform/GlobalPlatform.h GlobalPlatform.c debug.h \
debug.c GlobalPlatform/unicode.h unzip/crypt.h unzip/ioapi.c unzip/ioapi.h \
unzip/unzip.c unzip/unzip.h unzip/zip.c unzip/zip.h

libGlobalPlatform_la_LDFLAGS = -version-info 5:0:0 $(PCSCLITE_LIBS)
libGlobalPlatform_la_CPPFLAGS = $(AM_CPPFLAGS) $(PCSCLITE_CFLAGS)

TESTS = GlobalPlatformTest
check_PROGRAMS = GlobalPlatformTest
GlobalPlatformTest_SOURCES = GlobalPlatformTest.c $(top_builddir)/GlobalPlatform/GlobalPlatform.h
GlobalPlatformTest_CFLAGS = @CHECK_CFLAGS@ $(AM_CPPFLAGS) $(PCSCLITE_CFLAGS)
GlobalPlatformTest_LDADD = @CHECK_LIBS@ $(top_builddir)/libGlobalPlatform.la $(PCSCLITE_LIBS)

doc : GlobalPlatform.c GlobalPlatform/GlobalPlatform.h GlobalPlatform/unicode.h
	doxygen Doxyfile.cfg

MAINTAINERCLEANFILES = \
	Makefile.in \
	configure \
	config.guess \
	config.sub \
	aclocal.m4 \
	install-sh \
	missing \
	config.guess \
	config.sub \
	compile \
	depcomp
