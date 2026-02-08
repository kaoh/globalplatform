INCLUDE(FindPCSC)
INCLUDE(FindGlobalPlatform)
SET(SOURCES gppcscconnectionplugin.c "${PROJECT_SOURCE_DIR}/../globalplatform/src/util.c")

INCLUDE(CheckCCompilerFlag)
INCLUDE(CMakePushCheckState)

# Synchronize CMAKE_BUILD_TYPE and the legacy DEBUG switch
IF(CMAKE_BUILD_TYPE STREQUAL "Debug" OR DEBUG)
  SET(DEBUG ON)
  IF(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE "Debug")
  ENDIF()

  # Only add flags NOT handled by CMAKE_BUILD_TYPE=Debug
  IF(MSVC_VERSION)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -W4")
  ELSE()
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -g -O0")
  ENDIF()

  # check for fsanitize support
  CMAKE_PUSH_CHECK_STATE()
  SET(CMAKE_REQUIRED_FLAGS "-fsanitize=address")
  check_c_compiler_flag("-fsanitize=address" FSANITIZE)
  CMAKE_POP_CHECK_STATE()
  IF(FSANITIZE)
  MESSAGE("fsanitize supported")
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
  ENDIF()
  
  # check for Wpedantic support
  CMAKE_PUSH_CHECK_STATE()
  SET(CMAKE_REQUIRED_FLAGS "-Wpedantic")
  check_c_compiler_flag("-Wpedantic" PEDANTIC)
  CMAKE_POP_CHECK_STATE()
  IF(PEDANTIC)
  MESSAGE("pedantic supported")
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wpedantic")
  ENDIF()

ELSE()
  IF(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE "Release")
  ENDIF()
ENDIF()

# Enable debugging output
ADD_DEFINITIONS(-DOPGP_DEBUG)

# Handle Windows build
IF(WIN32)
    SET(SOURCES ${SOURCES} version.rc)
    ADD_DEFINITIONS(-D_CRT_SECURE_NO_WARNINGS)
    ADD_DEFINITIONS(-DUNICODE -D_UNICODE -DWIN32)
ENDIF(WIN32)

# The last is needed to support a system where the globalplatform headers are already installed, but the util.h must still be found in the sub project of globalplatform
INCLUDE_DIRECTORIES(${PCSC_INCLUDE_DIRS} ${GLOBALPLATFORM_INCLUDE_DIRS} "${PROJECT_SOURCE_DIR}/../globalplatform/src")

# without this the compilation in the homebrew docker image does not work
IF(UNIX)
  link_directories(${PCSC_LIBDIR})
ENDIF()

set(GPPCSC_BUILD_STATIC OFF)
set(GPPCSC_BUILD_SHARED OFF)
if(STATIC)
  set(GPPCSC_BUILD_STATIC ON)
else()
  set(GPPCSC_BUILD_SHARED ON)
endif()

# Build shared and static variants
if(GPPCSC_BUILD_SHARED)
  ADD_LIBRARY(gppcscconnectionplugin SHARED ${SOURCES})
  TARGET_LINK_LIBRARIES(gppcscconnectionplugin PUBLIC ${GLOBALPLATFORM_LIBRARIES} ${PCSC_LIBRARIES})
endif()
if(GPPCSC_BUILD_STATIC)
  ADD_LIBRARY(gppcscconnectionpluginStatic STATIC ${SOURCES})
  if(TARGET globalplatformStatic)
    TARGET_LINK_LIBRARIES(gppcscconnectionpluginStatic PUBLIC globalplatformStatic ${PCSC_LIBRARIES})
  else()
    TARGET_LINK_LIBRARIES(gppcscconnectionpluginStatic PUBLIC ${GLOBALPLATFORM_LIBRARIES} ${PCSC_LIBRARIES})
  endif()
endif()

# Under Unix shared and static libraries can have the same base name
IF(UNIX AND GPPCSC_BUILD_STATIC)
  SET_TARGET_PROPERTIES(gppcscconnectionpluginStatic PROPERTIES OUTPUT_NAME gppcscconnectionplugin)
ENDIF()

IF(WINDDK_DIR)
  if(GPPCSC_BUILD_SHARED)
    TARGET_LINK_LIBRARIES(gppcscconnectionplugin ${GLOBALPLATFORM_LIBRARIES} ${PCSC_LIBRARIES} optimized ${WINDDK_DIR}/lib/win7/i386/msvcrt_win2000.obj optimized ${WINDDK_DIR}/lib/Crt/i386/msvcrt.lib)
  endif()
  if(GPPCSC_BUILD_STATIC)
    TARGET_LINK_LIBRARIES(gppcscconnectionpluginStatic ${GLOBALPLATFORM_LIBRARIES} ${PCSC_LIBRARIES} optimized ${WINDDK_DIR}/lib/win7/i386/msvcrt_win2000.obj optimized ${WINDDK_DIR}/lib/Crt/i386/msvcrt.lib)
  endif()
ENDIF(WINDDK_DIR)

IF(UNIX AND GPPCSC_BUILD_SHARED)
  SET_TARGET_PROPERTIES(gppcscconnectionplugin PROPERTIES SOVERSION ${SOVERSION})
ENDIF()

IF(WIN32)
  if(GPPCSC_BUILD_SHARED)
    SET_TARGET_PROPERTIES(gppcscconnectionplugin PROPERTIES DEFINE_SYMBOL OPGP_PL_EXPORTS)
  endif()
  if(GPPCSC_BUILD_STATIC)
    SET_TARGET_PROPERTIES(gppcscconnectionpluginStatic PROPERTIES DEFINE_SYMBOL OPGP_PL_EXPORTS)
  endif()
ENDIF(WIN32)

# Install
IF(WIN32)
  if(TARGET gppcscconnectionplugin)
    INSTALL(TARGETS gppcscconnectionplugin
      EXPORT gppcscconnectionpluginTargets
      RUNTIME DESTINATION lib${LIB_SUFFIX}
      ARCHIVE DESTINATION lib${LIB_SUFFIX})
  endif()
  if(TARGET gppcscconnectionpluginStatic)
    INSTALL(TARGETS gppcscconnectionpluginStatic
      EXPORT gppcscconnectionpluginTargets
      ARCHIVE DESTINATION lib${LIB_SUFFIX})
  endif()
ELSE(WIN32)
  if(TARGET gppcscconnectionplugin)
    INSTALL(TARGETS gppcscconnectionplugin
      EXPORT gppcscconnectionpluginTargets
      LIBRARY DESTINATION lib${LIB_SUFFIX})
  endif()
  if(TARGET gppcscconnectionpluginStatic)
    INSTALL(TARGETS gppcscconnectionpluginStatic
      EXPORT gppcscconnectionpluginTargets
      ARCHIVE DESTINATION lib${LIB_SUFFIX})
  endif()
ENDIF(WIN32)

# Testing
IF(TESTING)
  # gives /usr/bin/ld: /usr/lib/gcc/x86_64-linux-gnu/7/../../../x86_64-linux-gnu/libcheck_pic.a(check_pack.o): undefined reference to symbol '__pthread_unregister_cancel@@GLIBC_2.3.3'
  # https://github.com/libcheck/check/issues/48
  # PKG_CHECK_MODULES(CHECK check>=0.9.2)
#  IF(CHECK_FOUND)
#    INCLUDE_DIRECTORIES(${CHECK_INCLUDE_DIRS})
#    ADD_EXECUTABLE(gppcscconnectionpluginTest gppcscconnectionpluginTest.c)
#    TARGET_LINK_LIBRARIES(gppcscconnectionpluginTest gppcscconnectionplugin ${CHECK_LIBRARIES})
#    ADD_TEST(gppcscconnectionpluginTest ${EXECUTABLE_OUTPUT_PATH}/gppcscconnectionpluginTest)
#    SET_TESTS_PROPERTIES(gppcscconnectionpluginTest PROPERTIES PASS_REGULAR_EXPRESSION "Failures: 0")
#  ENDIF(CHECK_FOUND)
ENDIF(TESTING)
