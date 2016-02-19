PROJECT(gpshell C)
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

cmake_policy(VERSION 2.8)

# set this to snapshot so that snapshot specific version number can be set
set(CPACK_DEBIAN_PACKAGE_TYPE	"snapshot")

SET( ${PROJECT_NAME}_CURRENT 1 )
SET( ${PROJECT_NAME}_REVISION 4 )
SET( ${PROJECT_NAME}_AGE 4+5 )
SET(VERSION "${${CMAKE_PROJECT_NAME}_CURRENT}.${${CMAKE_PROJECT_NAME}_REVISION}.${${CMAKE_PROJECT_NAME}_AGE}")

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake_modules/)

IF(UNIX)
  set(DOCUMENTATION_DIRECTORY "share/doc/${PROJECT_NAME}")
  set(MANPAGE_DIRECTORY "share/man")
ELSE(UNIX)
  set(DOCUMENTATION_DIRECTORY "doc")
ENDIF(UNIX)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/AUTHORS ${CMAKE_CURRENT_SOURCE_DIR}/ChangeLog 
              ${CMAKE_CURRENT_SOURCE_DIR}/COPYING
              ${CMAKE_CURRENT_SOURCE_DIR}/README
              ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.OpenSSL
              ${CMAKE_CURRENT_SOURCE_DIR}/NEWS DESTINATION ${DOCUMENTATION_DIRECTORY})
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/helloworld.cap.transf DESTINATION ${DOCUMENTATION_DIRECTORY})
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/helloworld.cap DESTINATION ${DOCUMENTATION_DIRECTORY})

FILE(GLOB samples "${CMAKE_CURRENT_SOURCE_DIR}/*.txt")
INSTALL(FILES ${samples} DESTINATION ${DOCUMENTATION_DIRECTORY})

IF(UNIX)
  INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/gpshell.1 DESTINATION ${MANPAGE_DIRECTORY}/man1)
ENDIF(UNIX)

# build a CPack driven installer package

IF(WIN32)
set(CPACK_GENERATOR "ZIP")
set(CPACK_SOURCE_GENERATOR "ZIP")
ELSE(WIN32)
set(CPACK_GENERATOR "TGZ")
set(CPACK_SOURCE_GENERATOR "TGZ")
ENDIF(WIN32)

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY  "GPShell is a script interpreter which talks to a smart card. It is written on top of the GlobalPlatform library.")
set(CPACK_PACKAGE_FILE_NAME            "${CMAKE_PROJECT_NAME}-binary-${VERSION}")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${VERSION}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY    "${CMAKE_PROJECT_NAME}-${VERSION}")
set(CPACK_PACKAGE_VENDOR               "Karsten Ohme")
set(CPACK_PACKAGE_CONTACT              "Karsten Ohme <k_o_@users.sourceforge.net>")
set(CPACK_PACKAGE_VERSION              "${VERSION}")

# add snapshot specific versioning information
IF(CPACK_DEBIAN_PACKAGE_TYPE STREQUAL "snapshot")
  execute_process(COMMAND date +%Y%m%d%0k%0M%0S%z OUTPUT_VARIABLE SNAPSHOT_DATE_TIME)
  set(CPACK_PACKAGE_VERSION "${VERSION}SNAPSHOT${SNAPSHOT_DATE_TIME}")
  STRING(REPLACE "\n" "" CPACK_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION})
ENDIF(CPACK_DEBIAN_PACKAGE_TYPE STREQUAL "snapshot")

set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_HOME_DIRECTORY}/COPYING")
set(CPACK_PACKAGE_VERSION_MAJOR        "${${CMAKE_PROJECT_NAME}_CURRENT}")
set(CPACK_PACKAGE_VERSION_MINOR        "${${CMAKE_PROJECT_NAME}_REVISION}")
set(CPACK_PACKAGE_VERSION_PATCH        "${${CMAKE_PROJECT_NAME}_AGE}")
set(CPACK_SOURCE_IGNORE_FILES "doc;.*~;Debian;debian;\\\\.svn;\\\\CMakeFiles;/${CPACK_SOURCE_PACKAGE_FILE_NAME}.*;/${CPACK_PACKAGE_FILE_NAME}.*;\\\\CPack*;\\\\CMakeCache.txt;\\\\cmake_install.*;\\\\Makefile;\\\\_CPack_Packages;\\\\install_manifest.txt;\\\\.tar.gz;${CPACK_SOURCE_IGNORE_FILES}")

include(CPack)

IF(UNIX)
# build a Debian package for Launchpad
set(CPACK_DEBIAN_PACKAGE_NAME "gpshell")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "extra")
set(CPACK_DEBIAN_PACKAGE_SECTION "devel")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "http://globalplatform.sourceforge.net/")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_HOME_DIRECTORY}/description.txt")
set(CPACK_DEBIAN_PACKAGE_LICENSE "gpl")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libglobalplatform7, libgppcscconnectionplugin1")
set(CPACK_DEBIAN_PACKAGE_BUILD_NUMBER_PREFIX "0ubuntu")
set(CPACK_DEBIAN_PACKAGE_BUILD_NUMBER "1")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Launchpad PPA for GlobalPlatform <globalplatform-developers@lists.sourceforge.net>")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://launchpad.net/~k-o-/+archive/globalplatform")
set(CPACK_DEBIAN_PACKAGE_SNAPSHOT_HOMEPAGE "https://launchpad.net/~k-o-/+archive/globalplatformsnapshots")
set(DPUT_HOST "gp-ppa")
set(CPACK_DEBIAN_PACKAGE_MANPAGES "/usr/share/doc/${CPACK_DEBIAN_PACKAGE_NAME}/gpshell.1")
set(DPUT_SNAPSHOT_HOST "gpsnapshots-ppa")
set(CPACK_DEBIAN_BUILD_DEPENDS "debhelper (>=5), libc6 (>= 2.7), libglobalplatform7-dev, libpcsclite-dev (>= 1.5.3), pkg-config (>=0.20-1~)")
set(CPACK_DEBIAN_PACKAGE_INSTALL "/usr/bin/gpshell")
set(CPACK_DEBIAN_PACKAGE_DOCS "/usr/share/doc/${CPACK_DEBIAN_PACKAGE_NAME}/*")

include(UploadPPA)
ENDIF(UNIX)

# Enable usual make dist behavior
add_custom_target(dist COMMAND ${CMAKE_MAKE_PROGRAM} package_source)

ADD_SUBDIRECTORY(src)
