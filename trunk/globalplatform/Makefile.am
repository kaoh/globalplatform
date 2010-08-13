## Process this file with automake to create Makefile.in.

EXTRA_DIST = GlobalPlatform.cbp lib_finder.script GlobalPlatform.workspace GlobalPlatform.depend INSTALL.w32 reconf \
GlobalPlatform.sln GlobalPlatform.vcproj

SUBDIRS = src

doc:
	cd src && $(MAKE) $(AM_MAKEFLAGS) doc

UBUNTU_DISTS = dapper hardy jaunty karmic lucid maverick

SNAPSHOT_VERSION=4+5-SNAPSHOT-`date +%F-%0k-%0M-%0S%z`
RELEASE_VERSION=4

deb-snapshot:
	rm -rf $(PACKAGE)-$(VERSION)
	tar xzf $(PACKAGE)-$(VERSION).tar.gz
	rm -f $(PACKAGE)_$(VERSION).orig.tar.gz
	cd $(PACKAGE)-$(VERSION) && dh_make -l -c lgpl -e "k_o_@users.sourceforge.net" -f ../$(PACKAGE)-$(VERSION).tar.gz
	cp $(PACKAGE)_$(VERSION).orig.tar.gz lib$(PACKAGE)6_$(VERSION).orig.tar.gz
	cd $(PACKAGE)-$(VERSION) && rm -rf debian
	cd $(PACKAGE)-$(VERSION) && mkdir debian
	cd $(PACKAGE)-$(VERSION) && cp ../debian/* debian/
	cd $(PACKAGE)-$(VERSION) && chmod 755 debian/rules
	for d in $(UBUNTU_DISTS); \
	do \
		cd $(PACKAGE)-$(VERSION); \
		cp ../debian/changelog debian/; \
		sed -e "s/DISTRO/$$d/g" debian/changelog > debian/changelog.tmp; \
		mv debian/changelog.tmp debian/changelog; \
		sed -e "s/VERSION/$(SNAPSHOT_VERSION)/g" debian/changelog > debian/changelog.tmp; \
		mv debian/changelog.tmp debian/changelog; \
		# change binary:Version with Source-Version for dapper \
		if [ $$d == 'dapper' ] ; then \
			sed -e "s/binary:Version/Source-Version/g" debian/control > debian/control.tmp; \
			mv debian/control.tmp debian/control; \
		else \
			cp ../debian/control debian/ ; \
		fi; \
		debuild --no-tgz-check -S; \
	done

deb-dist:
	rm -rf $(PACKAGE)-$(VERSION)
	tar xzf $(PACKAGE)-$(VERSION).tar.gz
	rm -f $(PACKAGE)_$(VERSION).orig.tar.gz
	cd $(PACKAGE)-$(VERSION) && dh_make -l -c lgpl -e "k_o_@users.sourceforge.net" -f ../$(PACKAGE)-$(VERSION).tar.gz
	cp $(PACKAGE)_$(VERSION).orig.tar.gz lib$(PACKAGE)6_$(VERSION).orig.tar.gz
	cd $(PACKAGE)-$(VERSION) && rm -rf debian
	cd $(PACKAGE)-$(VERSION) && mkdir debian
	cd $(PACKAGE)-$(VERSION) && cp ../debian/* debian/;
	cd $(PACKAGE)-$(VERSION) && chmod 755 debian/rules
	for d in $(UBUNTU_DISTS); \
	do \
		cd $(PACKAGE)-$(VERSION); \
		cp ../debian/changelog debian/; \
		sed -e "s/DISTRO/$$d/g" debian/changelog > debian/changelog.tmp; \
		mv debian/changelog.tmp debian/changelog; \
		sed -e "s/VERSION/$(RELEASE_VERSION)/g" debian/changelog > debian/changelog.tmp; \
		mv debian/changelog.tmp debian/changelog; \
		# change binary:Version with Source-Version for dapper \
		if [ $$d == 'dapper' ] ; then \
			sed -e "s/binary:Version/Source-Version/g" debian/control > debian/control.tmp; \
			mv debian/control.tmp debian/control; \
		else \
			cp ../debian/control debian/ ; \
		fi; \
		debuild -S; \
	done

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
