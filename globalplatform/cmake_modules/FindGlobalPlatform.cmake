# - Try to find the GlobalPlatform library
# Once done this will define
#
#  GLOBALPLATFORM_FOUND - system has the GlobalPlatform library
#  GLOBALPLATFORM_INCLUDE_DIRS - the GlobalPlatform include directory
#  GLOBALPLATFORM_LIBRARIES - The libraries needed to use GlobalPlatform
#
# Author: Karsten Ohme <k_o_@users.sourceforge.net>
# Version: 20110329
#

FIND_PACKAGE (PkgConfig)
IF(PKG_CONFIG_FOUND)
    # Will find GlobalPlatform library on Linux/BSDs using PkgConfig
    PKG_CHECK_MODULES(GLOBALPLATFORM libglobalplatform)
#   PKG_CHECK_MODULES(GLOBALPLATFORM QUIET libglobalplatform)   # IF CMake >= 2.8.2?
ENDIF(PKG_CONFIG_FOUND)

IF(NOT GLOBALPLATFORM_FOUND)
   # Will find GlobalPlatform headers both on Mac and Windows
   FIND_PATH(GLOBALPLATFORM_INCLUDE_DIRS NAMES globalplatform/globalplatform.h)
   # GlobalPlatform library naming
   FIND_LIBRARY(GLOBALPLATFORM_LIBRARIES NAMES globalplatform GlobalPlatform)
ENDIF(NOT GLOBALPLATFORM_FOUND)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GLOBALPLATFORM DEFAULT_MSG
  GLOBALPLATFORM_LIBRARIES
  GLOBALPLATFORM_INCLUDE_DIRS
)
MARK_AS_ADVANCED(GLOBALPLATFORM_INCLUDE_DIRS GLOBALPLATFORM_LIBRARIES)
