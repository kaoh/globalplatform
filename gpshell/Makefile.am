## Process this file with automake to create Makefile.in.

EXTRA_DIST = lib_finder.script GPShell.cbp \
GPShell.dep INSTALL.w32 \
reconf list.txt helloDelete.txt helloInstall.txt \
helloworld.cap putdefault-cflex.txt replacekey-cflex.txt send_apdu.txt \
listGP211.txt helloInstallGP211.txt helloDeleteGP211.txt Makefile.mak \
helloDeletegemXpressoProR3_2E64.txt make.bat GPShell.vcproj \
helloInstallgemXpressoProR3_2E64.txt listgemXpressoProR3_2E64.txt \
helloInstallCyberflexe-gate32k.txt helloInstallCyberflexAccess64k.txt \
helloInstallNokia6131NFC.txt helloworld.cap.transf helloInstallOberthurCosmo64.txt \
listJCOP10.txt listPalmeraProtectV5.txt helloInstallPalmeraProtectV5.txt \
helloInstallJCOP10.txt helloInstallJCOP31.txt helloInstallJCOP21OrJTopV15.txt \
get_data.txt helloInstallSmartCafeExpert30.txt

SUBDIRS = src

UBUNTU_DISTS = dapper hardy jaunty karmic lucid maverick

SNAPSHOT_VERSION=-SNAPSHOT-`date +%F-%0k-%0M-%0S%z`

deb-snapshot:
	rm -rf $(PACKAGE)-$(VERSION)
	tar xzf $(PACKAGE)-$(VERSION).tar.gz
	rm -f $(PACKAGE)_$(VERSION).orig.tar.gz
	cd $(PACKAGE)-$(VERSION) && dh_make -s -c gpl -e "k_o_@users.sourceforge.net" -f ../$(PACKAGE)-$(VERSION).tar.gz
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
	cd $(PACKAGE)-$(VERSION) && dh_make -s -c gpl -e "k_o_@users.sourceforge.net" -f ../$(PACKAGE)-$(VERSION).tar.gz
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
		sed -e "s/VERSION//g" debian/changelog > debian/changelog.tmp; \
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
	myaux\config.guess \
	myaux\config.sub \
	aclocal.m4 \
	myaux/install-sh \
	myaux/missing \
	myaux/config.guess \
	myaux/config.sub \
	myaux/compile \
	myaux/depcomp
