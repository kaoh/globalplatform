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
  if(APPLE)
    # Make packaged binaries runnable directly from the DMG layout (bin + ../lib).
    set_target_properties(gpshell PROPERTIES INSTALL_RPATH "@executable_path/../lib")
    set_target_properties(gpshell3 PROPERTIES INSTALL_RPATH "@executable_path/../lib")
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

if(WIN32)
  # Bundle runtime DLL dependencies on Windows so packages (ZIP/MSI/MSIX payload) run
  # on machines without additional OpenSSL/zlib installations.
  set(_gpshell_windows_runtime_dlls)

  # If we linked zlib statically (zlibstat.lib), no DLL is required at runtime.
  # Otherwise, try to locate the corresponding zlib DLL next to the discovered import lib.
  set(_gpshell_zlib_dll "")
  if(ZLIB_LIBRARY)
    get_filename_component(_gpshell_zlib_lib_name "${ZLIB_LIBRARY}" NAME_WE)
    get_filename_component(_gpshell_zlib_lib_dir "${ZLIB_LIBRARY}" DIRECTORY)
    if(NOT _gpshell_zlib_lib_name STREQUAL "zlibstat")
      set(_gpshell_zlib_dll_candidates)
      if(ZLIB_ROOT)
        file(TO_CMAKE_PATH "${ZLIB_ROOT}" _gpshell_zlib_root)
        list(APPEND _gpshell_zlib_dll_candidates "${_gpshell_zlib_root}/${_gpshell_zlib_lib_name}.dll")
      endif()
      if(_gpshell_zlib_lib_dir)
        file(TO_CMAKE_PATH "${_gpshell_zlib_lib_dir}" _gpshell_zlib_lib_dir_cmake)
        list(APPEND _gpshell_zlib_dll_candidates "${_gpshell_zlib_lib_dir_cmake}/../${_gpshell_zlib_lib_name}.dll")
      endif()
      list(APPEND _gpshell_zlib_dll_candidates "${CMAKE_SOURCE_DIR}/zlib-1.3.1/win32-build/${_gpshell_zlib_lib_name}.dll")
      foreach(_cand IN LISTS _gpshell_zlib_dll_candidates)
        if(EXISTS "${_cand}")
          set(_gpshell_zlib_dll "${_cand}")
          break()
        endif()
      endforeach()
    endif()
  endif()
  if(_gpshell_zlib_dll)
    list(APPEND _gpshell_windows_runtime_dlls "${_gpshell_zlib_dll}")
  endif()

  if(OPENSSL_ROOT_DIR)
    file(TO_CMAKE_PATH "${OPENSSL_ROOT_DIR}" _gpshell_openssl_root)
    file(GLOB _gpshell_openssl_dlls
      "${_gpshell_openssl_root}/libcrypto*.dll"
      "${_gpshell_openssl_root}/libssl*.dll"
      "${_gpshell_openssl_root}/libeay*.dll"
      "${_gpshell_openssl_root}/ssleay*.dll"
      "${_gpshell_openssl_root}/bin/libcrypto*.dll"
      "${_gpshell_openssl_root}/bin/libssl*.dll"
      "${_gpshell_openssl_root}/bin/libeay*.dll"
      "${_gpshell_openssl_root}/bin/ssleay*.dll"
      "${_gpshell_openssl_root}/bin/legacy*.dll")
    list(APPEND _gpshell_windows_runtime_dlls ${_gpshell_openssl_dlls})

    # OpenSSL 3 provider modules (default/legacy/etc.) are commonly installed here.
    if(EXISTS "${_gpshell_openssl_root}/ossl-modules")
      install(DIRECTORY "${_gpshell_openssl_root}/ossl-modules/"
        DESTINATION "bin/ossl-modules"
        FILES_MATCHING PATTERN "*.dll")
    endif()
    if(EXISTS "${_gpshell_openssl_root}/bin/ossl-modules")
      install(DIRECTORY "${_gpshell_openssl_root}/bin/ossl-modules/"
        DESTINATION "bin/ossl-modules"
        FILES_MATCHING PATTERN "*.dll")
    endif()
  endif()

  if(_gpshell_windows_runtime_dlls)
    set(_gpshell_windows_runtime_dlls_cmake)
    foreach(_runtime_dll IN LISTS _gpshell_windows_runtime_dlls)
      file(TO_CMAKE_PATH "${_runtime_dll}" _runtime_dll_cmake)
      list(APPEND _gpshell_windows_runtime_dlls_cmake "${_runtime_dll_cmake}")
    endforeach()
    list(REMOVE_DUPLICATES _gpshell_windows_runtime_dlls)
    list(REMOVE_DUPLICATES _gpshell_windows_runtime_dlls_cmake)
    install(FILES ${_gpshell_windows_runtime_dlls_cmake} DESTINATION bin)
  endif()
endif()

if(WIN32)
  set(_default_build_man_page OFF)
else()
  set(_default_build_man_page ON)
endif()

option(GPSHELL_BUILD_MAN_PAGE "Build gpshell man pages (requires pandoc or kramdown)" ${_default_build_man_page})
option(DISABLE_PANDOC "Disable pandoc for man page generation" OFF)
set(GPSHELL_MAN_CONVERTER "AUTO" CACHE STRING "Markdown to man converter (AUTO, PANDOC, KRAMDOWN, OFF)")
set_property(CACHE GPSHELL_MAN_CONVERTER PROPERTY STRINGS "AUTO" "PANDOC" "KRAMDOWN" "OFF")

if(GPSHELL_BUILD_MAN_PAGE)
  string(TOUPPER "${GPSHELL_MAN_CONVERTER}" _gpshell_converter_upper)

  if(_gpshell_converter_upper STREQUAL "OFF")
    set(GPSHELL_BUILD_MAN_PAGE OFF)
    message(STATUS "GPShell man page generation disabled by GPSHELL_MAN_CONVERTER=OFF.")
  elseif(_gpshell_converter_upper STREQUAL "PANDOC")
    if(DISABLE_PANDOC)
      set(GPSHELL_BUILD_MAN_PAGE OFF)
      message(STATUS "GPShell man page generation disabled because DISABLE_PANDOC is ON.")
    else()
      find_program(PANDOC_EXECUTABLE pandoc)
      mark_as_advanced(PANDOC_EXECUTABLE)
      if(NOT PANDOC_EXECUTABLE OR NOT EXISTS "${PANDOC_EXECUTABLE}")
        message(FATAL_ERROR "Pandoc not found (GPSHELL_MAN_CONVERTER=PANDOC). Install pandoc, specify PANDOC_EXECUTABLE, or use -DGPSHELL_MAN_CONVERTER=KRAMDOWN / -DGPSHELL_BUILD_MAN_PAGE=OFF.")
      else()
        set(_active_man_converter "PANDOC")
      endif()
    endif()
  elseif(_gpshell_converter_upper STREQUAL "KRAMDOWN")
    find_program(KRAMDOWN_EXECUTABLE kramdown)
    mark_as_advanced(KRAMDOWN_EXECUTABLE)
    if(NOT KRAMDOWN_EXECUTABLE OR NOT EXISTS "${KRAMDOWN_EXECUTABLE}")
      message(FATAL_ERROR "Kramdown not found (GPSHELL_MAN_CONVERTER=KRAMDOWN). Install kramdown, specify KRAMDOWN_EXECUTABLE, or use -DGPSHELL_MAN_CONVERTER=PANDOC / -DGPSHELL_BUILD_MAN_PAGE=OFF.")
    else()
      set(_active_man_converter "KRAMDOWN")
    endif()
  elseif(_gpshell_converter_upper STREQUAL "AUTO")
    set(_active_man_converter "")
    if(NOT DISABLE_PANDOC)
      find_program(PANDOC_EXECUTABLE pandoc)
      mark_as_advanced(PANDOC_EXECUTABLE)
      if(PANDOC_EXECUTABLE AND EXISTS "${PANDOC_EXECUTABLE}")
        set(_active_man_converter "PANDOC")
      endif()
    endif()

    if(NOT _active_man_converter)
      find_program(KRAMDOWN_EXECUTABLE kramdown)
      mark_as_advanced(KRAMDOWN_EXECUTABLE)
      if(KRAMDOWN_EXECUTABLE AND EXISTS "${KRAMDOWN_EXECUTABLE}")
        set(_active_man_converter "KRAMDOWN")
      endif()
    endif()

    if(NOT _active_man_converter)
      set(GPSHELL_BUILD_MAN_PAGE OFF)
      message(STATUS "Neither pandoc nor kramdown was found. Disabling GPShell man page generation.")
    endif()
  else()
    message(FATAL_ERROR "Invalid GPSHELL_MAN_CONVERTER value: '${GPSHELL_MAN_CONVERTER}'. Valid options are AUTO, PANDOC, KRAMDOWN, OFF.")
  endif()
endif()

if(GPSHELL_BUILD_MAN_PAGE)
  message(STATUS "GPShell man page generation enabled using ${_active_man_converter}")

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

  if(_active_man_converter STREQUAL "PANDOC")
    add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/gpshell.1
      COMMAND ${PANDOC_EXECUTABLE} --standalone --to man -o ${CMAKE_CURRENT_BINARY_DIR}/gpshell.1 ${CMAKE_CURRENT_BINARY_DIR}/gpshell.1.md
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/gpshell.1.md
      COMMENT "Creating gpshell man page using pandoc ..."
    )

    add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/gpshell3.1
      COMMAND ${PANDOC_EXECUTABLE} --standalone --to man -o ${CMAKE_CURRENT_BINARY_DIR}/gpshell3.1 ${CMAKE_CURRENT_BINARY_DIR}/gpshell3.1.md
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/gpshell3.1.md
      COMMENT "Creating gpshell3 man page using pandoc ..."
    )
  elseif(_active_man_converter STREQUAL "KRAMDOWN")
    find_program(SH_EXECUTABLE sh)
    if(NOT SH_EXECUTABLE)
      set(SH_EXECUTABLE sh)
    endif()

    add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/gpshell.1
      COMMAND ${SH_EXECUTABLE} -c "${KRAMDOWN_EXECUTABLE} -o man '${CMAKE_CURRENT_BINARY_DIR}/gpshell.1.md' > '${CMAKE_CURRENT_BINARY_DIR}/gpshell.1'"
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/gpshell.1.md
      COMMENT "Creating gpshell man page using kramdown ..."
      VERBATIM
    )

    add_custom_command(
      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/gpshell3.1
      COMMAND ${SH_EXECUTABLE} -c "${KRAMDOWN_EXECUTABLE} -o man '${CMAKE_CURRENT_BINARY_DIR}/gpshell3.1.md' > '${CMAKE_CURRENT_BINARY_DIR}/gpshell3.1'"
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/gpshell3.1.md
      COMMENT "Creating gpshell3 man page using kramdown ..."
      VERBATIM
    )
  endif()

  add_custom_target(gpshell_manpage ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/gpshell.1 ${CMAKE_CURRENT_BINARY_DIR}/gpshell3.1)
  add_custom_target(gpshell3_manpage ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/gpshell3.1)

  file(TO_NATIVE_PATH ${CMAKE_CURRENT_BINARY_DIR}/gpshell.1 native_filepath)
  file(TO_NATIVE_PATH ${CMAKE_CURRENT_BINARY_DIR}/gpshell3.1 native_filepath3)
  get_directory_property(make_clean_files ADDITIONAL_MAKE_CLEAN_FILES)
  set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${make_clean_files};${native_filepath};${native_filepath3}")

  if(UNIX)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/gpshell.1 DESTINATION ${MANPAGE_DIRECTORY}/man1)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/gpshell3.1 DESTINATION ${MANPAGE_DIRECTORY}/man1)
  endif()
endif()
