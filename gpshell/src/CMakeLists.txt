# Prefer static libraries for OpenSSL and zlib when available (affects only this directory)
set(OPENSSL_USE_STATIC_LIBS TRUE)
set(ZLIB_USE_STATIC_LIBS TRUE)

INCLUDE(FindPCSC)
INCLUDE(FindGlobalPlatform)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
SET(SOURCES gpshell.c)
SET(SOURCES3 gpshell3.c)

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
IF(DEBUG)
    ADD_DEFINITIONS(-DDEBUG)
ENDIF()

# Handle Windows build
IF(WIN32)
    SET(SOURCES ${SOURCES} version.rc)
    ADD_DEFINITIONS(-D_CRT_SECURE_NO_WARNINGS)
    ADD_DEFINITIONS(-DUNICODE -D_UNICODE -DWIN32)
ENDIF(WIN32)

# Ensure we include in-tree GlobalPlatform headers to avoid picking up system-installed ones
INCLUDE_DIRECTORIES(${PCSC_INCLUDE_DIRS} ${GLOBALPLATFORM_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/globalplatform/src)

# without this the compilation in the homebrew docker image does not work
IF(UNIX)
  link_directories(${PCSC_LIBDIR})
ENDIF()

if(NOT STATIC)
  ADD_EXECUTABLE(gpshell ${SOURCES})
  TARGET_LINK_LIBRARIES(gpshell ${GLOBALPLATFORM_LIBRARIES} ${PCSC_LIBRARIES})

  # New simplified CLI
  ADD_EXECUTABLE(gpshell3 ${SOURCES3})
  TARGET_LINK_LIBRARIES(gpshell3 ${GLOBALPLATFORM_LIBRARIES} ${PCSC_LIBRARIES})

  # Allow in-tree execution to find the PC/SC plugin without installing it
  if(UNIX)
    set(_gpshell_plugin_rpath "$ORIGIN/../../gppcscconnectionplugin/src")
    set_target_properties(gpshell PROPERTIES BUILD_RPATH "${_gpshell_plugin_rpath}")
    set_target_properties(gpshell3 PROPERTIES BUILD_RPATH "${_gpshell_plugin_rpath}")
  endif()
endif()

# Optional static gpshell that embeds GlobalPlatform and PC/SC plugin
option(GPSHELL_BUILD_STATIC "Build a statically linked gpshell with built-in PC/SC plugin" ON)
if(STATIC)
  set(GPSHELL_BUILD_STATIC ON CACHE BOOL "Build a statically linked gpshell with built-in PC/SC plugin" FORCE)
else()
  set(GPSHELL_BUILD_STATIC OFF CACHE BOOL "Build a statically linked gpshell with built-in PC/SC plugin" FORCE)
endif()
if(GPSHELL_BUILD_STATIC)
  add_executable(gpshellStatic ${SOURCES})
  add_executable(gpshell3Static ${SOURCES3})
  set_target_properties(gpshellStatic PROPERTIES OUTPUT_NAME "gpshell")
  set_target_properties(gpshell3Static PROPERTIES OUTPUT_NAME "gpshell3")
  
  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(gpshell3Static PRIVATE -g -O0)
    # Ensure the linker doesn't strip symbols from the static executable
    IF(NOT MSVC)
        target_link_options(gpshell3Static PRIVATE -no-pie)
    ENDIF()
  endif()

  # Ensure we include in-tree GlobalPlatform headers
  # Ensure we include in-tree GlobalPlatform headers
  target_include_directories(gpshellStatic PRIVATE ${PCSC_INCLUDE_DIRS} ${GLOBALPLATFORM_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/globalplatform/src)
  target_include_directories(gpshell3Static PRIVATE ${PCSC_INCLUDE_DIRS} ${GLOBALPLATFORM_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/globalplatform/src)

  # Prefer static libcrypto and libz explicitly (do not force static libc)
  set(_orig_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  find_library(ZLIB_STATIC NAMES z zlib)
  find_library(CRYPTO_STATIC NAMES crypto libcrypto)
  set(CMAKE_FIND_LIBRARY_SUFFIXES "${_orig_suffixes}")

  # Link against static globalplatform and static plugin and their dependencies
  # Use the static variants of libcrypto and libz if found; otherwise fall back to the ones from find_package
  if(CRYPTO_STATIC)
    set(_CRYPTO_LIB ${CRYPTO_STATIC})
  else()
    set(_CRYPTO_LIB ${OPENSSL_LIBRARIES})
  endif()
  if(ZLIB_STATIC)
    set(_Z_LIB ${ZLIB_STATIC})
  else()
    set(_Z_LIB ${ZLIB_LIBRARIES})
  endif()

  target_link_libraries(gpshellStatic globalplatformStatic gppcscconnectionpluginStatic ${PCSC_LIBRARIES} ${_CRYPTO_LIB} ${_Z_LIB})
  target_link_libraries(gpshell3Static globalplatformStatic gppcscconnectionpluginStatic ${PCSC_LIBRARIES} ${_CRYPTO_LIB} ${_Z_LIB})
  # Define to make the core use statically linked plugin
  target_compile_definitions(gpshellStatic PRIVATE OPGP_STATIC_PCSC)
  target_compile_definitions(gpshell3Static PRIVATE OPGP_STATIC_PCSC)
  if(UNIX)
    # dyn_unix uses dlfcn for shared; not needed for static path but harmless
    target_link_libraries(gpshellStatic dl)
    target_link_libraries(gpshell3Static dl)
  endif()
  if(WINDDK_DIR)
    TARGET_LINK_LIBRARIES(gpshellStatic optimized ${WINDDK_DIR}/lib/win7/i386/msvcrt_win2000.obj optimized ${WINDDK_DIR}/lib/Crt/i386/msvcrt.lib)
  endif()
  # Install static gpshell as separate binary
  INSTALL(TARGETS gpshellStatic gpshell3Static DESTINATION bin)
endif()

IF(WINDDK_DIR)
  if(TARGET gpshell)
    TARGET_LINK_LIBRARIES(gpshell ${GLOBALPLATFORM_LIBRARIES} ${PCSC_LIBRARIES} optimized ${WINDDK_DIR}/lib/win7/i386/msvcrt_win2000.obj optimized ${WINDDK_DIR}/lib/Crt/i386/msvcrt.lib)
  endif()
ENDIF(WINDDK_DIR)

# Install
if(TARGET gpshell)
  INSTALL(TARGETS gpshell DESTINATION bin)
endif()
if(TARGET gpshell3)
  INSTALL(TARGETS gpshell3 DESTINATION bin)
endif()

IF(NOT WIN32)
	# pandoc man page generation
	
	if(NOT EXISTS ${PANDOC_EXECUTABLE})
	    message("-- Checking for pandoc")
	    find_program(PANDOC_EXECUTABLE pandoc)
	    mark_as_advanced(PANDOC_EXECUTABLE)
	    if(NOT EXISTS ${PANDOC_EXECUTABLE})
	        message(FATAL_ERROR "--   Pandoc not found. Install Pandoc (http://johnmacfarlane.net/pandoc/) or set cache variable PANDOC_EXECUTABLE.")
	        return()
	    else()
	        message("--   Found pandoc")
	    endif()
	endif()
	
	# Inject version number
	configure_file(
		${CMAKE_CURRENT_SOURCE_DIR}/gpshell.1.md
		${CMAKE_CURRENT_BINARY_DIR}/gpshell.1.md
		@ONLY
		)

	# Configure gpshell3 man page markdown
	configure_file(
		${CMAKE_CURRENT_SOURCE_DIR}/gpshell3.1.md
		${CMAKE_CURRENT_BINARY_DIR}/gpshell3.1.md
		@ONLY
		)

	add_custom_command(
	    OUTPUT gpshell.1
	    COMMAND ${PANDOC_EXECUTABLE} --standalone --to man -o gpshell.1 ${CMAKE_CURRENT_BINARY_DIR}/gpshell.1.md
	    COMMENT "Creating man page ..."
	    )

	add_custom_command(
	    OUTPUT gpshell3.1
	    COMMAND ${PANDOC_EXECUTABLE} --standalone --to man -o gpshell3.1 ${CMAKE_CURRENT_BINARY_DIR}/gpshell3.1.md
	    COMMENT "Creating gpshell3 man page ..."
	    )
	
	add_custom_target(gpshell_manpage ALL DEPENDS gpshell.1 gpshell3.1)
	add_custom_target(gpshell3_manpage ALL DEPENDS gpshell3.1)
endif()

file(TO_NATIVE_PATH ${CMAKE_CURRENT_BINARY_DIR}/gpshell.1 native_filepath)
file(TO_NATIVE_PATH ${CMAKE_CURRENT_BINARY_DIR}/gpshell3.1 native_filepath3)
get_directory_property(make_clean_files ADDITIONAL_MAKE_CLEAN_FILES)
set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${make_clean_files};${native_filepath};${native_filepath3}")

IF(UNIX)
  INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/gpshell.1 DESTINATION ${MANPAGE_DIRECTORY}/man1)
  INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/gpshell3.1 DESTINATION ${MANPAGE_DIRECTORY}/man1)
ENDIF()
