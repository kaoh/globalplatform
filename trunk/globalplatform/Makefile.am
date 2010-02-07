## Process this file with automake to create Makefile.in.

EXTRA_DIST = Makefile.mak Install.w32 reconf GlobalPlatform.sln.old \
GlobalPlatform.vcproj.7.10.old GlobalPlatform.sln GlobalPlatform.vcproj

SUBDIRS = plugins/pcsc main

doc:
	cd main && $(MAKE) $(AM_MAKEFLAGS) doc

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
