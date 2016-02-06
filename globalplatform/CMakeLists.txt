PROJECT(globalplatform C)
CMAKE_MINIMUM_REQUIRED(VERSION 3.5)

cmake_policy(SET CMP0045 OLD)

# set this to snapshot so that snapshot specific version number can be set
set(CPACK_DEBIAN_PACKAGE_TYPE	"snapshot")

SET( ${PROJECT_NAME}_CURRENT 6+7 )
SET( ${PROJECT_NAME}_REVISION 0 )
SET( ${PROJECT_NAME}_AGE 0 )
SET(VERSION "${${CMAKE_PROJECT_NAME}_CURRENT}.${${CMAKE_PROJECT_NAME}_REVISION}.${${CMAKE_PROJECT_NAME}_AGE}")

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake_modules/)

IF(UNIX)
    # Create PkgConfig file
    CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/globalplatform.pc.in ${CMAKE_CURRENT_BINARY_DIR}/globalplatform.pc @ONLY)
    INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc DESTINATION lib${LIB_SUFFIX}/pkgconfig COMPONENT dev)
ENDIF(UNIX)

IF(UNIX)
  set(DOCUMENTATION_DIRECTORY "share/doc/lib${PROJECT_NAME}${${PROJECT_NAME}_CURRENT}")
ELSE(UNIX)
  set(DOCUMENTATION_DIRECTORY "doc")
ENDIf(UNIX)

set(DOXYFILE_SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
set(DOXYFILE_LATEX OFF)
include(UseDoxygen)

set(INSTALL_FILES	${CMAKE_CURRENT_SOURCE_DIR}/AUTHORS ${CMAKE_CURRENT_SOURCE_DIR}/ChangeLog 
              ${CMAKE_CURRENT_SOURCE_DIR}/COPYING ${CMAKE_CURRENT_SOURCE_DIR}/COPYING.LESSER 
              ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.OpenSSL
              ${CMAKE_CURRENT_SOURCE_DIR}/NEWS ${CMAKE_CURRENT_SOURCE_DIR}/README)

INSTALL(FILES ${INSTALL_FILES} DESTINATION ${DOCUMENTATION_DIRECTORY})

INSTALL(FILES ${INSTALL_FILES} DESTINATION ${DOCUMENTATION_DIRECTORY}
              COMPONENT dev)
              
INSTALL(
CODE "FILE (GLOB_RECURSE ALL_DOCS \"${CMAKE_CURRENT_BINARY_DIR}/doc/html/*\")"
CODE "FILE (INSTALL DESTINATION \"\${CMAKE_INSTALL_PREFIX}/${DOCUMENTATION_DIRECTORY}/html\" TYPE FILE FILES \${ALL_DOCS})" 
COMPONENT dev)

# build a CPack driven installer package

IF(WIN32)
set(CPACK_GENERATOR "ZIP")
set(CPACK_SOURCE_GENERATOR "ZIP")
ELSE(WIN32)
set(CPACK_GENERATOR "TGZ")
set(CPACK_SOURCE_GENERATOR "TGZ")
ENDIF(WIN32)

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY  "The GlobalPlatform Library is a smart card management library for OpenPlatform 2.0.1' and GlobalPlatform 2.1.1 smart cards")
set(CPACK_PACKAGE_FILE_NAME            "${CMAKE_PROJECT_NAME}-binary-${VERSION}")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${VERSION}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY    "${CMAKE_PROJECT_NAME}-${VERSION}")
set(CPACK_PACKAGE_VENDOR               "Karsten Ohme")
set(CPACK_PACKAGE_CONTACT              "Karsten Ohme <k_o_@users.sourceforge.net>")
set(CPACK_PACKAGE_VERSION              "${VERSION}")

IF(WIN32)
# add snapshot specific versioning information
IF(CPACK_DEBIAN_PACKAGE_TYPE STREQUAL "snapshot")
  execute_process(COMMAND date +%Y%m%d%0k%0M%0S%z OUTPUT_VARIABLE SNAPSHOT_DATE_TIME)
  set(CPACK_PACKAGE_VERSION "${VERSION}SNAPSHOT${SNAPSHOT_DATE_TIME}")
  STRING(REPLACE "\n" "" CPACK_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION})
ENDIF(CPACK_DEBIAN_PACKAGE_TYPE STREQUAL "snapshot")
ENDIF(WIN32)

set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_HOME_DIRECTORY}/COPYING.LESSER")
set(CPACK_PACKAGE_VERSION_MAJOR        "${${CMAKE_PROJECT_NAME}_CURRENT}")
set(CPACK_PACKAGE_VERSION_MINOR        "${${CMAKE_PROJECT_NAME}_REVISION}")
set(CPACK_PACKAGE_VERSION_PATCH        "${${CMAKE_PROJECT_NAME}_AGE}")
set(CPACK_SOURCE_IGNORE_FILES "doc;.*~;Debian;debian;\\\\.svn;\\\\globalplatform.lib$;\\\\globalplatform.dll;\\\\CMakeFiles;/${CPACK_SOURCE_PACKAGE_FILE_NAME}.*;/${CPACK_PACKAGE_FILE_NAME}.*;\\\\CPack*;\\\\CMakeCache.txt;\\\\cmake_install.*;\\\\Makefile;\\\\_CPack_Packages;\\\\libglobalplatform.so;\\\\libglobalplatform.a;\\\\globalplatform.exp;\\\\globalplatform.manifest;\\\\install_manifest.txt;\\\\.tar.gz;\\\\Doxyfile$;${CPACK_SOURCE_IGNORE_FILES}")

include(CPack)

IF(UNIX)
# build a Debian package for Launchpad
set(CPACK_DEBIAN_PACKAGE_NAME "libglobalplatform7")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "extra")
set(CPACK_DEBIAN_PACKAGE_SECTION "libs")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "http://globalplatform.sourceforge.net/")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_HOME_DIRECTORY}/description.txt")
set(CPACK_DEBIAN_PACKAGE_LICENSE "lgpl")
set(CPACK_DEBIAN_PACKAGE_RECOMMENDS "libgppcscconnectionplugin1")
set(CPACK_DEBIAN_PACKAGE_SUGGESTS "gpshell")
set(CPACK_COMPONENTS_ALL "dev")
set(CPACK_COMPONENT_DEV_DISPLAY_NAME "GlobalPlatform Library development files.")
set(CPACK_COMPONENT_DEV_DESCRIPTION "These are the development files.")
set(CPACK_COMPONENT_DEV_SECTION "libdevel")
set(CPACK_DEBIAN_PACKAGE_BUILD_NUMBER_PREFIX "0ubuntu")
set(CPACK_DEBIAN_PACKAGE_BUILD_NUMBER "1")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Launchpad PPA for GlobalPlatform <globalplatform-developers@lists.sourceforge.net>")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://launchpad.net/~k-o-/+archive/globalplatform")
set(CPACK_DEBIAN_PACKAGE_SNAPSHOT_HOMEPAGE "https://launchpad.net/~k-o-/+archive/globalplatformsnapshots")
set(DPUT_HOST "gp-ppa")
set(DPUT_SNAPSHOT_HOST "gpsnapshots-ppa")
set(CPACK_DEBIAN_BUILD_DEPENDS "debhelper (>=5), libpcsclite-dev (>=1.2.9), zlib1g-dev (>= 1:1.2.3), libssl-dev (>= 0.9.7e), doxygen (>=1.4), pkg-config (>=0.20-1~), check (>=0.9.2)")
set(CPACK_DEBIAN_PACKAGE_INSTALL "/usr/lib/*.so;/usr/lib/*.so.*")
set(CPACK_DEBIAN_PACKAGE_DOCS "/usr/share/doc/${CPACK_DEBIAN_PACKAGE_NAME}/AUTHORS;/usr/share/doc/${CPACK_DEBIAN_PACKAGE_NAME}/README;/usr/share/doc/${CPACK_DEBIAN_PACKAGE_NAME}/COPYING*;/usr/share/doc/${CPACK_DEBIAN_PACKAGE_NAME}/LICENSE*;/usr/share/doc/${CPACK_DEBIAN_PACKAGE_NAME}/ChangeLog;/usr/share/doc/${CPACK_DEBIAN_PACKAGE_NAME}/NEWS")
set(CPACK_COMPONENT_DEV_DOCS "/usr/share/doc/${CPACK_DEBIAN_PACKAGE_NAME}/*")
set(CPACK_DEBIAN_CUSTOM_BUILD_COMMAND "make doxygen")
set(CPACK_COMPONENT_DEV_INSTALL "/usr/lib/pkgconfig;/usr/include;/usr/lib/*.a")

include(UploadPPA)
ENDIF(UNIX)

# Enable usual make dist behavior
add_custom_target(dist COMMAND ${CMAKE_MAKE_PROGRAM} package_source)

ADD_SUBDIRECTORY(src)
