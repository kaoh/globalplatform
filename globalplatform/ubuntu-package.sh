#!/bin/bash

UBUNTU_DISTS="karmic lucid maverick natty oneiric precise"

PACKAGE=`sed -n -e 's/set(CPACK_DEBIAN_PACKAGE_NAME "\(.*\)".*)/\1/p' CMakeLists.txt`
CURRENT=`sed -n -e 's/SET( ${PROJECT_NAME}_CURRENT \(.*\) .*)/\1/p' CMakeLists.txt`
REVISION=`sed -n -e 's/SET( ${PROJECT_NAME}_REVISION \(.*\) .*)/\1/p' CMakeLists.txt`
AGE=`sed -n -e 's/SET( ${PROJECT_NAME}_AGE \(.*\) .*)/\1/p' CMakeLists.txt`
VERSION=${CURRENT}.${REVISION}.${AGE}

cd Debian
DEBIAN_SOURCE_DIR=`ls -d ${PACKAGE}-${VERSION}*` 
cd ${DEBIAN_SOURCE_DIR};
for d in ${UBUNTU_DISTS}; \
	do \
		 \
		sed -e "s/~.*;/~$d) $d;/g" debian/changelog > debian/changelog.tmp; \
		cp debian/changelog.tmp debian/changelog; \
		# change binary:Version with Source-Version for dapper \
		if [ $$d == 'dapper' ] ; then \
			sed -e "s/binary:Version/Source-Version/g" debian/control > debian/control.tmp; \
			mv debian/control.tmp debian/control; \
		fi; \
		debuild -S; \

	done


