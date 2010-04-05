## Process this file with automake to create Makefile.in.

EXTRA_DIST = GPPCSCConnectionPlugin.cbp Makefile.mak make.bat lib_finder.script INSTALL.w32 reconf GPPCSCConnectionPlugin.vcproj

SUBDIRS = src

doc:
	cd src && $(MAKE) $(AM_MAKEFLAGS) doc

deb:
	rm -rf $(PACKAGE)-$(VERSION)
	tar xzf $(PACKAGE)-$(VERSION).tar.gz
	rm -f $(PACKAGE)_$(VERSION).orig.tar.gz
	cd $(PACKAGE)-$(VERSION) && dh_make -l -c lgpl -e "k_o_@users.sourceforge.net" -f ../$(PACKAGE)-$(VERSION).tar.gz
	cp $(PACKAGE)_$(VERSION).orig.tar.gz lib$(PACKAGE)1_$(VERSION).orig.tar.gz
	cd $(PACKAGE)-$(VERSION) && rm -rf debian
	cd $(PACKAGE)-$(VERSION) && mkdir debian
	cd $(PACKAGE)-$(VERSION) && cp ../debian/* debian/
	cd $(PACKAGE)-$(VERSION) && chmod 755 debian/rules
	cd $(PACKAGE)-$(VERSION) && debuild -S

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
	depcomp \
	m4 \
	globalplatform

