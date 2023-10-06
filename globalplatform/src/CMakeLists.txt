cmake_policy(SET CMP0045 NEW)

INCLUDE(FindPCSC)
INCLUDE(FindOpenSSL)
INCLUDE(FindZLIB)

SET(SOURCES connection.c stringify.c crypto.c loadfile.c util.c debug.c init.c globalplatform.c)


INCLUDE(CheckCCompilerFlag)
INCLUDE(CMakePushCheckState)

IF(DEBUG)
  SET(CMAKE_BUILD_TYPE "Debug")
  IF(MSVC_VERSION)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -W4")
  ELSE()
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -Wall")
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
  
ELSE(DEBUG)
  SET(CMAKE_BUILD_TYPE "Release")
ENDIF(DEBUG)

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
    ADD_DEFINITIONS(-DUNICODE)
ENDIF(WIN32)

INCLUDE_DIRECTORIES(${PCSC_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR} ${ZLIB_INCLUDE_DIRS})
IF(USE_SYSTEM_MINIZIP)
  INCLUDE_DIRECTORIES(${MINIZIP_INCLUDE_DIRS})
ENDIF(USE_SYSTEM_MINIZIP)

# without this the compilation in the homebrew docker image does not work
IF(UNIX)
  link_directories(${PCSC_LIBDIR})
ENDIF()

ADD_LIBRARY(globalplatformStatic STATIC ${SOURCES})
ADD_LIBRARY(globalplatform SHARED ${SOURCES})

SET(LIBRARIES ${PCSC_LIBRARIES} ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES})

# Under Unix shared and static libraries can have the same name
IF(UNIX)
  SET_TARGET_PROPERTIES(globalplatformStatic PROPERTIES OUTPUT_NAME globalplatform)
  SET(LIBRARIES ${LIBRARIES} dl)
ENDIF(UNIX)
IF(USE_SYSTEM_MINIZIP)
  SET(LIBRARIES ${LIBRARIES} ${MINIZIP_LIBRARIES})
ENDIF(USE_SYSTEM_MINIZIP)

TARGET_LINK_LIBRARIES(globalplatform globalplatformStatic ${LIBRARIES})

IF(WINDDK_DIR)
  TARGET_LINK_LIBRARIES(globalplatform globalplatformStatic ${LIBRARIES} optimized ${WINDDK_DIR}/lib/win7/i386/msvcrt_win2000.obj optimized ${WINDDK_DIR}/lib/Crt/i386/msvcrt.lib)
ENDIF(WINDDK_DIR)

IF(UNIX)
  SET_TARGET_PROPERTIES(globalplatform PROPERTIES SOVERSION ${SOVERSION})
ENDIF(UNIX)

# Install
IF(WIN32)
 INSTALL(TARGETS globalplatformStatic ARCHIVE DESTINATION lib${LIB_SUFFIX} COMPONENT dev)
 INSTALL(TARGETS globalplatform RUNTIME DESTINATION lib${LIB_SUFFIX})
 INSTALL(TARGETS globalplatform ARCHIVE DESTINATION lib${LIB_SUFFIX} COMPONENT dev)
ELSE(WIN32)
# Static library must be build first, otherwise under Ubuntu Karmic the static build removes the .so file of the shared library version.
 INSTALL(TARGETS globalplatformStatic ARCHIVE DESTINATION lib${LIB_SUFFIX} COMPONENT dev)
 INSTALL(TARGETS globalplatform LIBRARY DESTINATION lib${LIB_SUFFIX})
ENDIF(WIN32)

# Testing
IF(TESTING)
    INCLUDE(FindCMocka)

    # gives /usr/bin/ld: /usr/lib/gcc/x86_64-linux-gnu/7/../../../x86_64-linux-gnu/libcheck_pic.a(check_pack.o): undefined reference to symbol '__pthread_unregister_cancel@@GLIBC_2.3.3'
    #INCLUDE_DIRECTORIES(${CHECK_INCLUDE_DIRS})
    #ADD_EXECUTABLE(globalplatformTest globalplatformTest.c)
    #TARGET_LINK_LIBRARIES(globalplatformTest globalplatform ${CHECK_LIBRARIES})
    #ADD_TEST(globalplatformTest ${EXECUTABLE_OUTPUT_PATH}/globalplatformTest)
    #SET_TESTS_PROPERTIES(globalplatformTest PROPERTIES PASS_REGULAR_EXPRESSION "Failures: 0")

  IF(CMOCKA_FOUND) 
    INCLUDE(AddCMockaTest)
    include(AddMockedTest)

    IF(UNIX AND NOT APPLE)
      add_mocked_test(scp03Test
        SOURCES scp03Test.c testUtil.c ${SOURCES}
        COMPILE_OPTIONS -I${PCSC_INCLUDE_DIRS}
        MOCKS RAND_bytes
        LINK_LIBRARIES ${LIBRARIES})

      add_mocked_test(scp02Test
        SOURCES scp02Test.c testUtil.c ${SOURCES}
        MOCKS RAND_bytes
        LINK_LIBRARIES ${LIBRARIES})

      add_mocked_test(scp01Test
        SOURCES scp01Test.c testUtil.c ${SOURCES}
        MOCKS RAND_bytes
        LINK_LIBRARIES ${LIBRARIES})
    ENDIF(UNIX AND NOT APPLE)

    add_cmocka_test(cryptoTest
      SOURCES cryptoTest.c testUtil.c ${SOURCES}
      LINK_LIBRARIES ${LIBRARIES})
    
    add_cmocka_test(statusTest
      SOURCES statusTest.c testUtil.c ${SOURCES}
      LINK_LIBRARIES ${LIBRARIES})
  ELSE()
    MESSAGE("cmocka not found - skipping tests.")
  ENDIF()
ENDIF(TESTING)


ADD_SUBDIRECTORY(globalplatform)
