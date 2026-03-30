CMAKE_MINIMUM_REQUIRED(VERSION 3.10)
PROJECT(globalplatform C)

cmake_policy(SET CMP0079 NEW)
cmake_policy(SET CMP0045 NEW)
cmake_policy(VERSION 3.10)

# MacOS support for CMake 3+
set(CMAKE_MACOSX_RPATH 1)

# With cmake >= 3.21, version can be set in project().
set(GPSHELL_VERSION 3.0.0)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(INTEGRATION_TESTING "Enable integration tests requiring a real test card" OFF)
option(TOOLS "Build gpshell tools" ON)
option(STATIC "Build static variants only" OFF)

ADD_SUBDIRECTORY(globalplatform)

if(GLOBALPLATFORM_USE_ASAN AND (CMAKE_BUILD_TYPE STREQUAL "Debug" OR DEBUG))
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=address")
  set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -fsanitize=address")
endif()

ADD_SUBDIRECTORY(gppcscconnectionplugin)
if(TOOLS)
  ADD_SUBDIRECTORY(gpshell)
endif()

if(TARGET gppcscconnectionplugin)
  ADD_DEPENDENCIES(gppcscconnectionplugin globalplatform)
endif()
if(TARGET gppcscconnectionpluginStatic AND TARGET globalplatformStatic)
  ADD_DEPENDENCIES(gppcscconnectionpluginStatic globalplatformStatic)
endif()
if(TOOLS)
  if(TARGET gpshell)
    ADD_DEPENDENCIES(gpshell globalplatform gppcscconnectionplugin)
  endif()
  if(TARGET gpshell3)
    ADD_DEPENDENCIES(gpshell3 globalplatform gppcscconnectionplugin)
  endif()
  if(TARGET gpshellStatic)
    ADD_DEPENDENCIES(gpshellStatic globalplatformStatic gppcscconnectionpluginStatic)
  endif()
  if(TARGET gpshell3Static)
    ADD_DEPENDENCIES(gpshell3Static globalplatformStatic gppcscconnectionpluginStatic)
  endif()
endif()

if(APPLE)
  install(CODE [[
    file(GLOB_RECURSE _gp_bin_targets LIST_DIRECTORIES FALSE "${CMAKE_INSTALL_PREFIX}/bin/*")
    file(GLOB_RECURSE _gp_lib_targets LIST_DIRECTORIES FALSE
      "${CMAKE_INSTALL_PREFIX}/lib/*.dylib"
      "${CMAKE_INSTALL_PREFIX}/lib/*.so"
      "${CMAKE_INSTALL_PREFIX}/lib/*.bundle")
    set(_gp_codesign_targets ${_gp_bin_targets} ${_gp_lib_targets})
    list(REMOVE_DUPLICATES _gp_codesign_targets)

    foreach(_gp_target IN LISTS _gp_codesign_targets)
      execute_process(
        COMMAND /usr/bin/codesign --force --sign - "${_gp_target}"
        RESULT_VARIABLE _gp_codesign_result
        OUTPUT_QUIET
        ERROR_VARIABLE _gp_codesign_error)
      if(NOT _gp_codesign_result EQUAL 0)
        string(STRIP "${_gp_codesign_error}" _gp_codesign_error)
        message(FATAL_ERROR "Failed to ad-hoc sign ${_gp_target}: ${_gp_codesign_error}")
      endif()
    endforeach()
  ]])
endif()

IF(TESTING)
    ENABLE_TESTING()
    # Convenience targets to split unit vs integration runs.
    if (CMAKE_CTEST_COMMAND)
      add_custom_target(test-unit
        COMMAND ${CMAKE_CTEST_COMMAND} -LE integration --output-on-failure
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
      add_custom_target(test-integration
        COMMAND ${CMAKE_CTEST_COMMAND} -L integration --output-on-failure
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    endif()
ENDIF()
