# - Try to find the GlobalPlatform library
# Once done this will define
#
#  GLOBALPLATFORM_FOUND - system has the GlobalPlatform library
#  GLOBALPLATFORM_INCLUDE_DIRS - the GlobalPlatform include directory
#  GLOBALPLATFORM_LIBRARIES - The libraries needed to use GlobalPlatform
#
# Author: Karsten Ohme <k_o_@users.sourceforge.net>
# Version: 20130121
#
IF(UNIX)
  FIND_PACKAGE (PkgConfig)
  # Always prefer globalplatform sources to get no outdated headers and libraries
  IF(NOT EXISTS ${CMAKE_SOURCE_DIR}/globalplatform AND PKG_CONFIG_FOUND)
      # Will find GlobalPlatform library on Linux/BSDs using PkgConfig
      PKG_CHECK_MODULES(GLOBALPLATFORM globalplatform)
  ENDIF()
ENDIF()

IF(NOT GLOBALPLATFORM_FOUND)
   # Will find GlobalPlatform headers both on Mac and Windows
   FIND_PATH(GLOBALPLATFORM_INCLUDE_DIRS NAMES globalplatform/globalplatform.h PATHS ${CMAKE_SOURCE_DIR}/globalplatform/src)
   # if all build from checked out source assume that the library will be there once globalplatform is built
   if(WIN32)
     set(GLOBALPLATFORM_LIBRARIES ${CMAKE_SOURCE_DIR}/globalplatform/src/globalplatform.lib)
   elseif(APPLE)
     set(GLOBALPLATFORM_LIBRARIES ${CMAKE_SOURCE_DIR}/globalplatform/src/libglobalplatform.dylib)
   else()
     set(GLOBALPLATFORM_LIBRARIES ${CMAKE_SOURCE_DIR}/globalplatform/src/libglobalplatform.so)
   endif()
ENDIF(NOT GLOBALPLATFORM_FOUND)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GLOBALPLATFORM DEFAULT_MSG
  GLOBALPLATFORM_LIBRARIES
  GLOBALPLATFORM_INCLUDE_DIRS
)
MARK_AS_ADVANCED(GLOBALPLATFORM_INCLUDE_DIRS GLOBALPLATFORM_LIBRARIES)
