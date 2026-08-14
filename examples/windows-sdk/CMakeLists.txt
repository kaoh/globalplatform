cmake_minimum_required(VERSION 3.10)
project(globalplatform_sdk_example C)

find_package(globalplatform CONFIG REQUIRED)
find_package(gppcscconnectionplugin CONFIG REQUIRED)

add_executable(globalplatform_sdk_example main.c)
target_link_libraries(globalplatform_sdk_example PRIVATE
  globalplatform::globalplatform
  gppcscconnectionplugin::gppcscconnectionplugin)
