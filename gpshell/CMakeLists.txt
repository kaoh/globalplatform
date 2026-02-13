CMAKE_MINIMUM_REQUIRED(VERSION 3.10)
PROJECT(gpshell C)

cmake_policy(VERSION 3.10)

SET( ${PROJECT_NAME}_CURRENT 3 )
SET( ${PROJECT_NAME}_REVISION 0 )
SET( ${PROJECT_NAME}_AGE 0 )
SET(VERSION "${${PROJECT_NAME}_CURRENT}.${${PROJECT_NAME}_REVISION}.${${PROJECT_NAME}_AGE}")

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake_modules/;${PROJECT_SOURCE_DIR}/../globalplatform/cmake_modules/)

set(CMAKE_MACOSX_RPATH 1)

IF(UNIX)
  set(DOCUMENTATION_DIRECTORY "share/doc/${PROJECT_NAME}${${PROJECT_NAME}_CURRENT}")
  set(MANPAGE_DIRECTORY "share/man")
ELSE(UNIX)
  set(DOCUMENTATION_DIRECTORY "doc")
ENDIF(UNIX)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/AUTHORS ${CMAKE_CURRENT_SOURCE_DIR}/ChangeLog
              ${CMAKE_CURRENT_SOURCE_DIR}/COPYING
              ${CMAKE_CURRENT_SOURCE_DIR}/README.md
              ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE
              ${CMAKE_CURRENT_SOURCE_DIR}/NEWS DESTINATION ${DOCUMENTATION_DIRECTORY})
INSTALL(FILES examples/helloworld.cap.transf DESTINATION ${DOCUMENTATION_DIRECTORY}/examples)
INSTALL(FILES examples/helloworld.cap DESTINATION ${DOCUMENTATION_DIRECTORY}/examples)

FILE(GLOB samples "${CMAKE_CURRENT_SOURCE_DIR}/examples/*.txt")
LIST(REMOVE_ITEM samples "${CMAKE_CURRENT_SOURCE_DIR}/description.txt")
LIST(REMOVE_ITEM samples "${CMAKE_CURRENT_SOURCE_DIR}/CMakeList.txt")
LIST(REMOVE_ITEM samples "${CMAKE_CURRENT_SOURCE_DIR}/install_manifest.txt")
INSTALL(FILES ${samples} DESTINATION ${DOCUMENTATION_DIRECTORY}/examples)

# build a CPack driven installer package

IF(WIN32)
set(CPACK_GENERATOR "ZIP;WIX")
set(CPACK_SOURCE_GENERATOR "ZIP")
ELSEIF(APPLE)
set(CPACK_GENERATOR "DragNDrop")
set(CPACK_SOURCE_GENERATOR "TGZ")
ELSE()
set(CPACK_GENERATOR "DEB;RPM")
set(CPACK_SOURCE_GENERATOR "TGZ")
ENDIF()

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY  "GPShell is a script interpreter which talks to a smart card. It is written on top of the GlobalPlatform library.")
set(CPACK_PACKAGE_FILE_NAME            "${PROJECT_NAME}-binary-${VERSION}")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${VERSION}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY    "${PROJECT_NAME}-${VERSION}")
set(CPACK_PACKAGE_VENDOR               "Karsten Ohme")
set(CPACK_PACKAGE_CONTACT              "Karsten Ohme <k_o_@users.sourceforge.net>")
set(CPACK_PACKAGE_VERSION              "${VERSION}")

set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING")
set(CPACK_PACKAGE_VERSION_MAJOR        "${${PROJECT_NAME}_CURRENT}")
set(CPACK_PACKAGE_VERSION_MINOR        "${${PROJECT_NAME}_REVISION}")
set(CPACK_PACKAGE_VERSION_PATCH        "${${PROJECT_NAME}_AGE}")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER    "Karsten Ohme <k_o_@users.sourceforge.net>")
set(CPACK_DEBIAN_PACKAGE_SECTION       "utils")
set(CPACK_RPM_PACKAGE_LICENSE          "GPL-3.0")
set(CPACK_RPM_PACKAGE_GROUP            "Applications/System")
set(CPACK_RPM_PACKAGE_RELEASE          "1")
set(CPACK_WIX_UPGRADE_GUID             "34f48725-0fe9-4d5c-9f12-90314672e332")
if(STATIC)
  # Only package gpshell artifacts for static builds.
  set(CPACK_INSTALL_CMAKE_PROJECTS "${CMAKE_CURRENT_BINARY_DIR};${PROJECT_NAME};ALL;/")
elseif(WIN32)
  # Avoid preinstall target issues on Windows by installing subprojects directly.
  set(CPACK_INSTALL_CMAKE_PROJECTS
    "${CMAKE_BINARY_DIR}/globalplatform;globalplatform;ALL;/"
    "${CMAKE_BINARY_DIR}/gppcscconnectionplugin;gppcscconnectionplugin;ALL;/"
    "${CMAKE_BINARY_DIR}/gpshell;gpshell;ALL;/")
endif()
set(CPACK_SOURCE_IGNORE_FILES "doc;.*~;Debian;debian;\\\\.svn;\\\\.settings;Testing;CMakeFiles;Doxyfile;
CPack.*;CMakeCache\\\\.txt;cmake_install.*;Makefile;CMakeDoxyfile\\\\.in;
_.*;\\\\.cproject;\\\\.project;DartConfiguration.tcl;.*vcxproj.*;.*patch;
\\\\.manifest;.*Test;\\\\.pc;description\\\\.txt;\\\\.sh;\\\\.cmake;install.*;
\\\\.tar\\\\.gz;\\\\.zip;\\\\.lib;\\\\.ilk;\\\\.pdb;\\\\.exe;\\\\.exp;\\\\.a;\\\\.so;\\\\.dll;\\\\.lib$;
Doxyfile$;${CPACK_SOURCE_IGNORE_FILES}")
set(CPACK_SOURCE_IGNORE_FILES "src/gpshell;${CPACK_SOURCE_IGNORE_FILES}")

include(CPack)

ADD_SUBDIRECTORY(src)
