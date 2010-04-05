## Process this file with automake to produce Makefile.in

bin_PROGRAMS = gpshell

gpshell_SOURCES = gpshell.c
gpshell_CPPFLAGS = $(AM_CPPFLAGS) $(PCSCLITE_CFLAGS) $(GLOBALPLATFORM_CFLAGS)
gpshell_LDADD = $(AM_CPPFLAGS) $(GLOBALPLATFORM_LIBS)

man_MANS = gpshell.1

EXTRA_DIST = $(man_MANS) GPShell.ico

MAINTAINERCLEANFILES = \
	Makefile.in \
	configure \
	myaux\config.guess \
	myaux\config.sub \
	aclocal.m4 \
	myaux/install-sh \
	myaux/missing \
	myaux/config.guess \
	myaux/config.sub \
	myaux/compile \
	myaux/depcomp

