## Process this file with automake to produce Makefile.in

bin_PROGRAMS = gpshell

gpshell_SOURCES = GPShell.c
gpshell_CPPFLAGS = $(AM_CPPFLAGS) "$(PCSCLITE_CFLAGS)" "$(GLOBALPLATFORM_CFLAGS)"
gpshell_LDADD = $(AM_CPPFLAGS) -lGlobalPlatform -L"$(GLOBALPLATFORM_LIB_PATH)"

EXTRA_DIST = GPShell.dep GPShell.dsp GPShell.dsw GPShell.mak stdafx.c \
stdafx.h reconf list.txt helloDelete.txt helloInstall.txt HelloWorld.bin \
HelloWorld.cap putdefault-cflex.txt replacekey-cflex.txt send_apdu.txt \
listgp211.txt helloInstallGP211.txt helloDeleteGP211.txt Makefile-Release CHANGES \
pcsclite-includes/README pcsclite-includes/pcsclite.h pcsclite-includes/winscard.h \
pcsclite-includes/wintypes.h

MAINTAINERCLEANFILES = \
	Makefile.in \
	configure \
	aclocal.m4 \
	myaux/install-sh \
	myaux/missing \
	myaux/config.guess \
	myaux/config.sub \
	myaux/compile \
	myaux/depcomp

