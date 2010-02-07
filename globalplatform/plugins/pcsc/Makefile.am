## Process this file with automake to create Makefile.in.

EXTRA_DIST = stdafx.c stdafx.h resource.h version.rc DLLMain.c Makefile.mak

lib_LTLIBRARIES = libgppcscconnectionplugin.la

include_HEADERS =

nobase_include_HEADERS =


libgppcscconnectionplugin_la_SOURCES = pcscconnectionplugin.h pcscconnectionplugin.c \
	$(top_builddir)/main/util.h $(top_builddir)/main/util.c $(top_builddir)/main/stringify.c \
	$(top_builddir)/main/debug.c

libgppcscconnectionplugin_la_LDFLAGS = -version-info 1:0:0 $(PCSCLITE_LIBS)
libgppcscconnectionplugin_la_CPPFLAGS = $(AM_CPPFLAGS) $(PCSCLITE_CFLAGS)

TESTS = pcscconnectionpluginTest
check_PROGRAMS = pcscconnectionpluginTest
pcscconnectionpluginTest_SOURCES = pcscconnectionpluginTest.c $(top_builddir)/GlobalPlatform/GlobalPlatform.h
pcscconnectionpluginTest_CFLAGS = @CHECK_CFLAGS@ $(AM_CPPFLAGS) $(PCSCLITE_CFLAGS)
pcscconnectionpluginTest_LDADD = @CHECK_LIBS@ $(builddir)/libgppcscconnectionplugin.la $(PCSCLITE_LIBS)

MAINTAINERCLEANFILES = \
	Makefile.in

