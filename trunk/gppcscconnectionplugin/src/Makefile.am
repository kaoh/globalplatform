## Process this file with automake to create Makefile.in.

EXTRA_DIST = stdafx.c stdafx.h resource.h version.rc DLLMain.c Doxyfile.cfg Makefile.mak

lib_LTLIBRARIES = libgppcscconnectionplugin.la

include_HEADERS =

nobase_include_HEADERS =


libgppcscconnectionplugin_la_SOURCES = gppcscconnectionplugin.h gppcscconnectionplugin.c util.h util.c

libgppcscconnectionplugin_la_LDFLAGS = -version-info 1:1:0 $(PCSCLITE_LIBS) $(GLOBALPLATFORM_LIBS)
libgppcscconnectionplugin_la_CPPFLAGS = $(AM_CPPFLAGS) $(PCSCLITE_CFLAGS) $(GLOBALPLATFORM_CFLAGS)

TESTS = gppcscconnectionpluginTest
check_PROGRAMS = gppcscconnectionpluginTest
gppcscconnectionpluginTest_SOURCES = gppcscconnectionpluginTest.c
gppcscconnectionpluginTest_CFLAGS = @CHECK_CFLAGS@ $(AM_CPPFLAGS) $(PCSCLITE_CFLAGS) $(GLOBALPLATFORM_CFLAGS)
gppcscconnectionpluginTest_LDADD = @CHECK_LIBS@ $(builddir)/libgppcscconnectionplugin.la $(PCSCLITE_LIBS) $(GLOBALPLATFORM_LIBS)

doc : gppcscconnectionplugin.h gppcscconnectionplugin.c
	doxygen Doxyfile.cfg

MAINTAINERCLEANFILES = \
	Makefile.in

