## Process this file with automake to create Makefile.in.

EXTRA_DIST = GlobalPlatform.cbp lib_finder.script GlobalPlatform.workspace GlobalPlatform.depend INSTALL.w32 reconf \
GlobalPlatform.sln GlobalPlatform.vcproj

SUBDIRS = src

doc:
	cd src && $(MAKE) $(AM_MAKEFLAGS) doc

deb:
	tar xzf $(PACKAGE)-$(VERSION).tar.gz
	rm -f $(PACKAGE)_$(VERSION).orig.tar.gz
	cd $(PACKAGE)-$(VERSION) && dh_make -l -c lgpl -e "k_o_@users.sourceforge.net" -f ../$(PACKAGE)-$(VERSION).tar.gz
	cd $(PACKAGE)-$(VERSION) && rm -rf debian
	cd $(PACKAGE)-$(VERSION) && mkdir debian
	cd $(PACKAGE)-$(VERSION) && cp ../debian/* debian/
	cd $(PACKAGE)-$(VERSION) && chmod 755 debian/rules
	cd $(PACKAGE)-$(VERSION) && dpkg-buildpackage -rfakeroot

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
