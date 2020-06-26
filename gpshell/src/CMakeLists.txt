INCLUDE(FindPCSC)
INCLUDE(FindGlobalPlatform)
SET(SOURCES gpshell.c)

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
ADD_DEFINITIONS(-DDEBUG)

# Handle Windows build
IF(WIN32)
    SET(SOURCES ${SOURCES} version.rc)
    ADD_DEFINITIONS(-D_CRT_SECURE_NO_WARNINGS)
    ADD_DEFINITIONS(-DUNICODE)
ENDIF(WIN32)

INCLUDE_DIRECTORIES(${PCSC_INCLUDE_DIRS} ${GLOBALPLATFORM_INCLUDE_DIRS})

# without this the compilation in the homebrew docker image does not work
IF(UNIX)
  link_directories(${PCSC_LIBDIR})
ENDIF()

ADD_EXECUTABLE(gpshell ${SOURCES})
TARGET_LINK_LIBRARIES(gpshell ${GLOBALPLATFORM_LIBRARIES} ${PCSC_LIBRARIES})

IF(WINDDK_DIR)
  TARGET_LINK_LIBRARIES(gpshell ${GLOBALPLATFORM_LIBRARIES} ${PCSC_LIBRARIES} optimized ${WINDDK_DIR}/lib/win7/i386/msvcrt_win2000.obj optimized ${WINDDK_DIR}/lib/Crt/i386/msvcrt.lib)
ENDIF(WINDDK_DIR)

# Install
INSTALL(TARGETS gpshell DESTINATION bin)

IF(NOT(WIN32))
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
	
	add_custom_command(
	    OUTPUT gpshell.1
	    COMMAND ${PANDOC_EXECUTABLE} --standalone --to man -o gpshell.1 gpshell.1.md
	    COMMENT "Creating man page ..."
	    )
	
	add_custom_target(gpshell_manpage ALL DEPENDS gpshell.1)
endif()

file(TO_NATIVE_PATH ${CMAKE_CURRENT_BINARY_DIR}/gpshell.1 native_filepath)
get_directory_property(make_clean_files ADDITIONAL_MAKE_CLEAN_FILES)
set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${make_clean_files};${native_filepath}")

IF(UNIX)
  INSTALL(FILES gpshell.1 DESTINATION ${MANPAGE_DIRECTORY}/man1)
ENDIF(UNIX)
