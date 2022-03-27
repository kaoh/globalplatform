PROJECT(globalplatform C)
CMAKE_MINIMUM_REQUIRED(VERSION 3.5.1)

cmake_policy(VERSION 3.5.1)

# MacOS support for CMake 3+
set(CMAKE_MACOSX_RPATH 1)

ADD_SUBDIRECTORY(globalplatform)
ADD_SUBDIRECTORY(gppcscconnectionplugin)
ADD_SUBDIRECTORY(gpshell)

ADD_DEPENDENCIES(gppcscconnectionplugin globalplatform)
ADD_DEPENDENCIES(gpshell globalplatform gppcscconnectionplugin)

IF(TESTING)
    ENABLE_TESTING()
ENDIF()
