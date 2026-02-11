cmake_policy(SET CMP0045 NEW)

INCLUDE(FindPCSC)
INCLUDE(FindOpenSSL)
INCLUDE(FindZLIB)

SET(SOURCES connection.c stringify.c crypto.c loadfile.c util.c debug.c init.c globalplatform.c)


INCLUDE(CheckCCompilerFlag)
INCLUDE(CMakePushCheckState)

set(_gp_asan_default OFF)
if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR DEBUG)
  set(_gp_asan_default ON)
endif()
option(GLOBALPLATFORM_ENABLE_ASAN "Enable AddressSanitizer in Debug builds" ${_gp_asan_default})

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
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
  ENDIF()

  if(GLOBALPLATFORM_ENABLE_ASAN)
    # check for fsanitize support
    CMAKE_PUSH_CHECK_STATE()
    SET(CMAKE_REQUIRED_FLAGS "-fsanitize=address")
    check_c_compiler_flag("-fsanitize=address" FSANITIZE)
    CMAKE_POP_CHECK_STATE()
    IF(FSANITIZE)
    MESSAGE("fsanitize supported")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
    set(GLOBALPLATFORM_USE_ASAN ON CACHE INTERNAL "GlobalPlatform uses ASan")
    set(GLOBALPLATFORM_ASAN_FLAGS "-fsanitize=address" CACHE INTERNAL "GlobalPlatform ASan flags")
    ENDIF()
  endif()
  
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
  set(GLOBALPLATFORM_USE_ASAN OFF CACHE INTERNAL "GlobalPlatform uses ASan")
ENDIF()

# Enable debugging output
ADD_DEFINITIONS(-DOPGP_DEBUG)

# Handle Unix build
IF(UNIX)
  SET(SOURCES ${SOURCES} dyn_unix.c)

  IF(USE_SYSTEM_MINIZIP)
    FIND_PACKAGE(PkgConfig)
    IF(PKG_CONFIG_FOUND)
      PKG_CHECK_MODULES(MINIZIP minizip)
    ENDIF(PKG_CONFIG_FOUND)
  ELSE(USE_SYSTEM_MINIZIP)
    SET(SOURCES ${SOURCES} unzip/ioapi.c unzip/unzip.c)
  ENDIF(USE_SYSTEM_MINIZIP)

  # Enable plugin loader
  ADD_DEFINITIONS(-DHAVE_DLFCN_H)

  # enable syslog
  include (CheckSymbolExists)
  CHECK_SYMBOL_EXISTS (vsyslog syslog.h HAVE_VSYSLOG)
    ADD_DEFINITIONS(-DHAVE_VSYSLOG)
  IF(HAVE_VSYSLOG)
  ENDIF(HAVE_VSYSLOG)
ENDIF(UNIX)

# Handle Windows build
IF(WIN32)
    SET(SOURCES ${SOURCES} DLLMain.c dyn_win32.c unzip/unzip.c unzip/iowin32.c unzip/ioapi.c version.rc)
    ADD_DEFINITIONS(-D_CRT_SECURE_NO_WARNINGS -DOPGP_EXPORTS -DZLIB_WINAPI)
    ADD_DEFINITIONS(-DUNICODE -D_UNICODE -DWIN32)
ENDIF(WIN32)

INCLUDE_DIRECTORIES(${PCSC_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR} ${ZLIB_INCLUDE_DIRS})
IF(USE_SYSTEM_MINIZIP)
  INCLUDE_DIRECTORIES(${MINIZIP_INCLUDE_DIRS})
ENDIF(USE_SYSTEM_MINIZIP)

# without this the compilation in the homebrew docker image does not work
IF(UNIX)
  link_directories(${PCSC_LIBDIR})
ENDIF()

set(GP_BUILD_STATIC OFF)
set(GP_BUILD_SHARED OFF)
if(STATIC)
  set(GP_BUILD_STATIC ON)
else()
  set(GP_BUILD_SHARED ON)
endif()

SET(LIBRARIES ${PCSC_LIBRARIES} ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES})
IF(WIN32)
  SET(LIBRARIES ${LIBRARIES} ws2_32 crypt32)
ENDIF(WIN32)

if(GP_BUILD_STATIC)
  ADD_LIBRARY(globalplatformStatic STATIC ${SOURCES})
  target_include_directories(globalplatformStatic
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
      $<INSTALL_INTERFACE:include>)
  target_compile_definitions(globalplatformStatic PUBLIC OPGP_STATIC)
  target_compile_definitions(globalplatformStatic PRIVATE OPGP_STATIC_PCSC)
endif()
if(GP_BUILD_SHARED)
  ADD_LIBRARY(globalplatform SHARED ${SOURCES})
  target_include_directories(globalplatform
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
      $<INSTALL_INTERFACE:include>)
endif()

if(GLOBALPLATFORM_USE_ASAN)
  if(GP_BUILD_STATIC)
    target_link_libraries(globalplatformStatic PUBLIC "${GLOBALPLATFORM_ASAN_FLAGS}")
  endif()
  if(GP_BUILD_SHARED)
    target_link_libraries(globalplatform PUBLIC "${GLOBALPLATFORM_ASAN_FLAGS}")
  endif()
endif()

# Under Unix shared and static libraries can have the same name
IF(UNIX)
  if(GP_BUILD_STATIC)
    SET_TARGET_PROPERTIES(globalplatformStatic PROPERTIES OUTPUT_NAME globalplatform)
  endif()
  SET(LIBRARIES ${LIBRARIES} dl)
ENDIF(UNIX)
IF(USE_SYSTEM_MINIZIP)
  SET(LIBRARIES ${LIBRARIES} ${MINIZIP_LIBRARIES})
ENDIF(USE_SYSTEM_MINIZIP)

if(GP_BUILD_SHARED)
  TARGET_LINK_LIBRARIES(globalplatform PUBLIC ${LIBRARIES})
endif()
if(GP_BUILD_STATIC)
  TARGET_LINK_LIBRARIES(globalplatformStatic PUBLIC ${LIBRARIES})
endif()

IF(WINDDK_DIR)
  if(GP_BUILD_SHARED)
    TARGET_LINK_LIBRARIES(globalplatform PUBLIC optimized ${WINDDK_DIR}/lib/win7/i386/msvcrt_win2000.obj optimized ${WINDDK_DIR}/lib/Crt/i386/msvcrt.lib)
  endif()
  if(GP_BUILD_STATIC)
    TARGET_LINK_LIBRARIES(globalplatformStatic PUBLIC optimized ${WINDDK_DIR}/lib/win7/i386/msvcrt_win2000.obj optimized ${WINDDK_DIR}/lib/Crt/i386/msvcrt.lib)
  endif()
ENDIF(WINDDK_DIR)

IF(UNIX AND GP_BUILD_SHARED)
  SET_TARGET_PROPERTIES(globalplatform PROPERTIES SOVERSION ${SOVERSION})
  # Allow in-tree execution to find the PC/SC plugin without installing it
  set(_globalplatform_plugin_rpath "$ORIGIN/../../gppcscconnectionplugin/src")
  set_target_properties(globalplatform PROPERTIES BUILD_RPATH "${_globalplatform_plugin_rpath}")
ENDIF()

# Install
IF(WIN32)
  if(TARGET globalplatform)
    INSTALL(TARGETS globalplatform
      EXPORT globalplatformTargets
      RUNTIME DESTINATION lib${LIB_SUFFIX}
      ARCHIVE DESTINATION lib${LIB_SUFFIX} COMPONENT dev
      INCLUDES DESTINATION include)
  endif()
  if(TARGET globalplatformStatic)
    INSTALL(TARGETS globalplatformStatic
      EXPORT globalplatformTargets
      ARCHIVE DESTINATION lib${LIB_SUFFIX} COMPONENT dev
      INCLUDES DESTINATION include)
  endif()
ELSE(WIN32)
  # Static library must be build first, otherwise under Ubuntu Karmic the static build removes the .so file of the shared library version.
  if(TARGET globalplatform)
    INSTALL(TARGETS globalplatform
      EXPORT globalplatformTargets
      LIBRARY DESTINATION lib${LIB_SUFFIX}
      INCLUDES DESTINATION include)
  endif()
  if(TARGET globalplatformStatic)
    INSTALL(TARGETS globalplatformStatic
      EXPORT globalplatformTargets
      ARCHIVE DESTINATION lib${LIB_SUFFIX} COMPONENT dev
      INCLUDES DESTINATION include)
  endif()
ENDIF(WIN32)

# Testing
IF(TESTING)
    INCLUDE(FindCMocka)

  IF(CMOCKA_FOUND)
    INCLUDE(AddCMockaTest)
    include(AddMockedTest)

    IF(UNIX AND NOT APPLE)
      add_mocked_test(scp03Test
        SOURCES scp03Test.c testUtil.c ${SOURCES}
        COMPILE_OPTIONS -I${PCSC_INCLUDE_DIRS} "-fno-lto"
        MOCKS RAND_bytes
        LINK_LIBRARIES ${LIBRARIES})

      add_mocked_test(scp02Test
        SOURCES scp02Test.c testUtil.c ${SOURCES}
        COMPILE_OPTIONS -I${PCSC_INCLUDE_DIRS} "-fno-lto"
        MOCKS RAND_bytes
        LINK_LIBRARIES ${LIBRARIES})
      add_custom_command(TARGET scp02Test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
          ${CMAKE_SOURCE_DIR}/gpshell/examples/helloworld.cap
          $<TARGET_FILE_DIR:scp02Test>/helloworld.cap)

      add_mocked_test(scp01Test
        SOURCES scp01Test.c testUtil.c ${SOURCES}
        COMPILE_OPTIONS -I${PCSC_INCLUDE_DIRS} "-fno-lto"
        MOCKS RAND_bytes
        LINK_LIBRARIES ${LIBRARIES})
    ENDIF(UNIX AND NOT APPLE)

    add_cmocka_test(cryptoTest
      SOURCES cryptoTest.c testUtil.c ${SOURCES}
      LINK_LIBRARIES ${LIBRARIES})
    add_custom_command(TARGET cryptoTest POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/rsa_pub_key_test.pem
        $<TARGET_FILE_DIR:cryptoTest>/rsa_pub_key_test.pem)
    
    add_cmocka_test(statusTest
      SOURCES statusTest.c testUtil.c ${SOURCES}
      LINK_LIBRARIES ${LIBRARIES})

    add_cmocka_test(getDataTest
      SOURCES getDataTest.c testUtil.c ${SOURCES}
      LINK_LIBRARIES ${LIBRARIES})
  ELSE()
    MESSAGE("cmocka not found - skipping tests.")
  ENDIF()

  IF(INTEGRATION_TESTING)
    find_package(PkgConfig)
    IF(PKG_CONFIG_FOUND)
      pkg_check_modules(CHECK check)
    ENDIF(PKG_CONFIG_FOUND)

    IF(NOT CHECK_FOUND)
      find_path(CHECK_INCLUDE_DIRS check.h)
      find_library(CHECK_LIBRARIES check)
    ENDIF()

    IF(CHECK_INCLUDE_DIRS AND CHECK_LIBRARIES)
      add_executable(globalplatformIntegrationTest globalplatformTest.c)
      target_include_directories(globalplatformIntegrationTest PRIVATE ${CHECK_INCLUDE_DIRS} ${PCSC_INCLUDE_DIRS})
      target_link_libraries(globalplatformIntegrationTest globalplatform ${CHECK_LIBRARIES} ${LIBRARIES})
      add_test(NAME globalplatformIntegrationTest COMMAND globalplatformIntegrationTest)
      set_tests_properties(globalplatformIntegrationTest PROPERTIES LABELS "integration")
    ELSE()
      MESSAGE("check not found - skipping integration test.")
    ENDIF()
  ENDIF(INTEGRATION_TESTING)
ENDIF(TESTING)


ADD_SUBDIRECTORY(globalplatform)
