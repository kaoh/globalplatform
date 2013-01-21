INCLUDE(FindPCSC)
INCLUDE(FindGlobalPlatform)
SET(SOURCES gppcscconnectionplugin.c util.c)

SET(CMAKE_BUILD_TYPE "Release")

# Enable debugging output
ADD_DEFINITIONS(-DOPGP_DEBUG)

# Handle Windows build
IF(WIN32)
    SET(SOURCES ${SOURCES} version.rc)
    ADD_DEFINITIONS(-D_CRT_SECURE_NO_WARNINGS)
    ADD_DEFINITIONS(-DUNICODE)
ENDIF(WIN32)

INCLUDE_DIRECTORIES(${PCSC_INCLUDE_DIRS} "${CMAKE_HOME_DIRECTORY}/../globalplatform/src")

ADD_LIBRARY(gppcscconnectionplugin SHARED ${SOURCES})
TARGET_LINK_LIBRARIES(gppcscconnectionplugin ${GLOBALPLATFORM_LIBRARIES} ${PCSC_LIBRARIES})

IF(WINDDK_DIR)
  TARGET_LINK_LIBRARIES(gppcscconnectionplugin optimized ${WINDDK_DIR}/lib/win7/i386/msvcrt_win2000.obj optimized ${WINDDK_DIR}/lib/Crt/i386/msvcrt.lib)
ENDIF(WINDDK_DIR)

IF(UNIX)
  SET_TARGET_PROPERTIES(gppcscconnectionplugin PROPERTIES SOVERSION ${VERSION})
ENDIF(UNIX)

IF(WIN32)
  SET_TARGET_PROPERTIES(gppcscconnectionplugin PROPERTIES DEFINE_SYMBOL OPGP_PL_EXPORTS)
ENDIF(WIN32)

# Install
IF(WIN32)
 INSTALL(TARGETS gppcscconnectionplugin RUNTIME DESTINATION lib${LIB_SUFFIX})
 INSTALL(TARGETS gppcscconnectionplugin ARCHIVE DESTINATION lib${LIB_SUFFIX})
ELSE(WIN32)
 INSTALL(TARGETS gppcscconnectionplugin LIBRARY DESTINATION lib${LIB_SUFFIX})
ENDIF(WIN32)

# Testing
IF(TESTING)
  PKG_CHECK_MODULES(CHECK check>=0.9.2)
  IF(CHECK_FOUND)
    ENABLE_TESTING()
    INCLUDE_DIRECTORIES(${CHECK_INCLUDE_DIRS})
    ADD_EXECUTABLE(gppcscconnectionpluginTest gppcscconnectionpluginTest.c)
    TARGET_LINK_LIBRARIES(gppcscconnectionpluginTest gppcscconnectionplugin ${CHECK_LIBRARIES})
    ADD_TEST(gppcscconnectionpluginTest ${EXECUTABLE_OUTPUT_PATH}/gppcscconnectionpluginTest)
    SET_TESTS_PROPERTIES(gppcscconnectionpluginTest PROPERTIES PASS_REGULAR_EXPRESSION "Failures: 0")
  ENDIF(CHECK_FOUND)
ENDIF(TESTING)

