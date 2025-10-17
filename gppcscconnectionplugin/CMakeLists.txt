CMAKE_MINIMUM_REQUIRED(VERSION 3.10)
PROJECT(gppcscconnectionplugin C)

cmake_policy(VERSION 3.10)

SET( ${PROJECT_NAME}_CURRENT 1 )
SET( ${PROJECT_NAME}_REVISION 2 )
SET( ${PROJECT_NAME}_AGE 4 )
SET(VERSION "${${PROJECT_NAME}_CURRENT}.${${PROJECT_NAME}_REVISION}.${${PROJECT_NAME}_AGE}")
SET(SOVERSION "${${PROJECT_NAME}_CURRENT}")

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake_modules/;${PROJECT_SOURCE_DIR}/../globalplatform/cmake_modules/)

set(CMAKE_MACOSX_RPATH 1)

IF(UNIX)
  set(DOCUMENTATION_DIRECTORY "share/doc/lib${PROJECT_NAME}${${PROJECT_NAME}_CURRENT}")
ELSE(UNIX)
  set(DOCUMENTATION_DIRECTORY "doc")
ENDIf(UNIX)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/AUTHORS ${CMAKE_CURRENT_SOURCE_DIR}/ChangeLog
              ${CMAKE_CURRENT_SOURCE_DIR}/COPYING ${CMAKE_CURRENT_SOURCE_DIR}/COPYING.LESSER
              ${CMAKE_CURRENT_SOURCE_DIR}/NEWS ${CMAKE_CURRENT_SOURCE_DIR}/README.md DESTINATION ${DOCUMENTATION_DIRECTORY})

# build a CPack driven installer package

IF(WIN32)
set(CPACK_GENERATOR "ZIP")
set(CPACK_SOURCE_GENERATOR "ZIP")
ELSE(WIN32)
set(CPACK_GENERATOR "TGZ")
set(CPACK_SOURCE_GENERATOR "TGZ")
ENDIF(WIN32)

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY  "This is a PC/SC connection plugin for the GlobalPlatform Library.")
set(CPACK_PACKAGE_FILE_NAME            "${PROJECT_NAME}-binary-${VERSION}")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${VERSION}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY    "${PROJECT_NAME}-${VERSION}")
set(CPACK_PACKAGE_VENDOR               "Karsten Ohme")
set(CPACK_PACKAGE_CONTACT              "Karsten Ohme <k_o_@users.sourceforge.net>")
set(CPACK_PACKAGE_VERSION              "${VERSION}")

set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING.LESSER")
set(CPACK_PACKAGE_VERSION_MAJOR        "${${PROJECT_NAME}_CURRENT}")
set(CPACK_PACKAGE_VERSION_MINOR        "${${PROJECT_NAME}_REVISION}")
set(CPACK_PACKAGE_VERSION_PATCH        "${${PROJECT_NAME}_AGE}")
set(CPACK_SOURCE_IGNORE_FILES "doc;.*~;Debian;debian;\\\\.svn;\\\\.settings;Testing;CMakeFiles;Doxyfile;
CPack.*;CMakeCache\\\\.txt;cmake_install.*;Makefile;CMakeDoxyfile\\\\.in;
_.*;\\\\.cproject;\\\\.project;DartConfiguration.tcl;.*vcxproj.*;.*patch;
\\\\.manifest;.*Test;\\\\.pc;description\\\\.txt;\\\\.sh;\\\\.cmake;install.*;
\\\\.tar\\\\.gz;\\\\.zip;\\\\.lib;\\\\.ilk;\\\\.pdb;\\\\.exe;\\\\.exp;\\\\.a;\\\\.so;\\\\.dll;\\\\.lib$;
Doxyfile$;${CPACK_SOURCE_IGNORE_FILES}")

include(CPack)

ADD_SUBDIRECTORY(src)
