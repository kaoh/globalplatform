# - Try to find the PC/SC smart card  library
# Once done this will define
#
#  PCSC_FOUND - system has the PC/SC library
#  PCSC_INCLUDE_DIRS - the PC/SC include directory
#  PCSC_LIBRARIES - The libraries needed to use PC/SC
#
# Author: F. Kooman <fkooman@tuxed.net>
# Version: 20101019
#

IF(WIN32)
  # On Windows, always use the OS-provided WinSCard import library from the
  # active toolchain/SDK. This avoids accidentally picking third-party PC/SC
  # libraries from unrelated environments on PATH/LIB.
  FIND_PATH(PCSC_INCLUDE_DIRS NAMES WinSCard.h winscard.h)
  set(PCSC_LIBRARIES WinSCard)
ELSE()
  FIND_PACKAGE(PkgConfig)
  IF(PKG_CONFIG_FOUND)
      # Will find PC/SC library on Linux/BSDs using PkgConfig
      PKG_CHECK_MODULES(PCSC libpcsclite)
  ENDIF()

  IF(NOT PCSC_FOUND)
     # Will find PC/SC headers both on Mac and Unix
     FIND_PATH(PCSC_INCLUDE_DIRS NAMES WinSCard.h winscard.h)
     # PCSC library is for Mac and other Unix-like systems
     FIND_LIBRARY(PCSC_LIBRARIES NAMES PCSC)
  ENDIF()
ENDIF()

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(PCSC DEFAULT_MSG
  PCSC_LIBRARIES
  PCSC_INCLUDE_DIRS
)
MARK_AS_ADVANCED(PCSC_INCLUDE_DIRS PCSC_LIBRARIES)
