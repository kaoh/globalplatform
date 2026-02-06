CMAKE_MINIMUM_REQUIRED(VERSION 3.10)
PROJECT(globalplatform C)

cmake_policy(VERSION 3.10)

# MacOS support for CMake 3+
set(CMAKE_MACOSX_RPATH 1)

# With cmake >= 3.21, version can be set in project().
set(GPSHELL_VERSION 3.0.0)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
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
