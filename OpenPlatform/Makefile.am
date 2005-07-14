## Process this file with automake to create Makefile.in.

lib_LTLIBRARIES = libOpenPlatform.la
include_HEADERS =

nobase_include_HEADERS = OpenPlatform.h

libOpenPlatform_la_SOURCES = OpenPlatform.h OpenPlatform.c version.h
libOpenPlatform_la_LDFLAGS = -version-info 1:0:0

doc : OpenPlatform.c OpenPlatform.h
	doxygen Doxyfile.cfg

