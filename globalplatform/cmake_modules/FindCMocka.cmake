# - Find cmocka
# Find the native cmocka includes and library.
# Once done this will define
#
#  CMOCKA_INCLUDE_DIRS   - where to find cmocka.h, etc.
#  CMOCKA_LIBRARIES      - List of libraries when using cmocka.
#  CMOCKA_FOUND          - True if cmocka found.
#
PKG_CHECK_MODULES(CMOCKA cmocka>=1.1)

IF (NOT CMOCKA_FOUND)
    
set(_CMOCKA_SEARCHES)

if(CMOCKA_ROOT)
  set(_CMOCKA_SEARCH_ROOT PATHS ${CMOCKA_ROOT} NO_DEFAULT_PATH)
  list(APPEND _CMOCKA_SEARCHES _CMOCKA_SEARCH_ROOT)
endif()

# Normal search.
set(_CMOCKA_SEARCH_NORMAL
  PATHS "$ENV{PROGRAMFILES\(x86\)}/cmocka"
  )
list(APPEND _CMOCKA_SEARCHES _CMOCKA_SEARCH_NORMAL)

set(CMOCKA_NAMES cmocka)

foreach(search ${_CMOCKA_SEARCHES})
  find_path(CMOCKA_INCLUDE_DIR NAMES cmocka.h        ${${search}} PATH_SUFFIXES include)
  find_library(CMOCKA_LIBRARY  NAMES ${CMOCKA_NAMES} ${${search}} PATH_SUFFIXES lib)
endforeach()

mark_as_advanced(CMOCKA_LIBRARY CMOCKA_INCLUDE_DIR)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(CMOCKA REQUIRED_VARS CMOCKA_LIBRARY CMOCKA_INCLUDE_DIR)

if(CMOCKA_FOUND)
    set(CMOCKA_INCLUDE_DIRS ${CMOCKA_INCLUDE_DIR})
    set(CMOCKA_LIBRARIES ${CMOCKA_LIBRARY})
endif()

ENDIF(NOT CMOCKA_FOUND)