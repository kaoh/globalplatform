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
   # If building in-tree, link against the CMake target to ensure correct build ordering in parallel builds
   if(EXISTS ${CMAKE_SOURCE_DIR}/globalplatform)
     if(TARGET globalplatform)
       # Use the shared target when available
       set(GLOBALPLATFORM_LIBRARIES globalplatform)
     elseif(TARGET globalplatformStatic)
       # Fall back to static when shared is not built
       set(GLOBALPLATFORM_LIBRARIES globalplatformStatic)
     endif()
   endif()
   if(NOT GLOBALPLATFORM_LIBRARIES)
     # Fall back to platform-specific library file when not building the project in-tree
     if(WIN32)
       set(GLOBALPLATFORM_LIBRARIES ${CMAKE_BINARY_DIR}/globalplatform/src/globalplatform.lib)
     elseif(APPLE)
       set(GLOBALPLATFORM_LIBRARIES ${CMAKE_BINARY_DIR}/globalplatform/src/libglobalplatform.dylib)
     else()
       set(GLOBALPLATFORM_LIBRARIES ${CMAKE_BINARY_DIR}/globalplatform/src/libglobalplatform.so)
     endif()
   endif()
ENDIF(NOT GLOBALPLATFORM_FOUND)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GLOBALPLATFORM DEFAULT_MSG
  GLOBALPLATFORM_LIBRARIES
  GLOBALPLATFORM_INCLUDE_DIRS
)
MARK_AS_ADVANCED(GLOBALPLATFORM_INCLUDE_DIRS GLOBALPLATFORM_LIBRARIES)
