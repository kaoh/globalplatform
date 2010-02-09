## Process this file with automake to create Makefile.in.

EXTRA_DIST = stdafx.c stdafx.h resource.h version.rc $(top_builddir)/../globalplatform/main/DLLMain.c

lib_LTLIBRARIES = libgppcscconnectionplugin.la

include_HEADERS =

nobase_include_HEADERS =


libgppcscconnectionplugin_la_SOURCES = gppcscconnectionplugin.h gppcscconnectionplugin.c \
	$(top_builddir)/../globalplatform/main/util.h $(top_builddir)/../globalplatform/main/util.c $(top_builddir)/../globalplatform/main/stringify.c \
	$(top_builddir)/../globalplatform/main/debug.c

libgppcscconnectionplugin_la_LDFLAGS = -version-info 1:0:0 $(PCSCLITE_LIBS)
libgppcscconnectionplugin_la_CPPFLAGS = $(AM_CPPFLAGS) $(PCSCLITE_CFLAGS)

TESTS = gppcscconnectionpluginTest
check_PROGRAMS = gppcscconnectionpluginTest
gppcscconnectionpluginTest_SOURCES = gppcscconnectionpluginTest.c $(top_builddir)/../globalplatform/main/globalplatform/globalplatform.h
gppcscconnectionpluginTest_CFLAGS = @CHECK_CFLAGS@ $(AM_CPPFLAGS) $(PCSCLITE_CFLAGS)
gppcscconnectionpluginTest_LDADD = @CHECK_LIBS@ $(builddir)/libgppcscconnectionplugin.la $(PCSCLITE_LIBS)

MAINTAINERCLEANFILES = \
	Makefile.in

