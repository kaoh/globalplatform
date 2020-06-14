PROJECT(globalplatform C)
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

cmake_policy(VERSION 2.8)

ADD_SUBDIRECTORY(globalplatform)
ADD_SUBDIRECTORY(gppcscconnectionplugin)
ADD_SUBDIRECTORY(gpshell)

ADD_DEPENDENCIES(gppcscconnectionplugin globalplatform)
ADD_DEPENDENCIES(gpshell globalplatform gppcscconnectionplugin)

IF(TESTING)
    ENABLE_TESTING()
ENDIF()
