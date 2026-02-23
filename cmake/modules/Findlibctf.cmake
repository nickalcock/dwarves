# - Find libctf
# Find the libctf.h header from binutils
#
#  LIBCTF_INCLUDE_DIR - where to find ctf-api.h, etc.
#  LIBCTF_LIBRARIES   - List of libraries when using libctf.

message(STATUS "Checking availability of libctf")

INCLUDE(CheckLibraryExists)
include(CheckCSourceCompiles)

if (LIBCTF_INCLUDE_DIR AND LIBCTF_LIBRARY)
	# Already in cache, be silent
	set(LIBCTF_FIND_QUIETLY TRUE)
endif (LIBCTF_INCLUDE_DIR AND LIBCTF_LIBRARY)

find_path(LIBCTF_INCLUDE_DIR ctf-api.h
	/usr/include
	/usr/local/include
)

find_library(LIBCTF_LIBRARY
	NAMES ctf
	PATHS /usr/lib /usr/local/lib /usr/lib64 /usr/local/lib64
)

if (LIBCTF_INCLUDE_DIR AND LIBCTF_LIBRARY)
	set(LIBCTF_LIBRARIES ${LIBCTF_LIBRARY})
	set(CMAKE_REQUIRED_LIBRARIES ${LIBCTF_LIBRARIES})
	set(CMAKE_REQUIRED_INCLUDES ${LIBCTF_INCLUDE_DIR})

	check_c_source_compiles([[
	#include <ctf-api.h>
	int main (void)
	{
	#if LIBCTF_API_VERSION >= 2
	    return 0;
	#else
	    @@@fail@@@
	#endif
	}
	]] LIBCTF_NEW_API)

	if (LIBCTF_NEW_API)
		set(LIBCTF_FOUND TRUE)
	else(LIBCTF_NEW_API)
		message(FATAL_ERROR "Need libctf v4 API: upgrade binutils")
	endif(LIBCTF_NEW_API)
else (LIBCTF_INCLUDE_DIR AND LIBCTF_LIBRARY)
     	message(FATAL_ERROR "Need libctf v4 API")
endif (LIBCTF_INCLUDE_DIR AND LIBCTF_LIBRARY)

if (LIBCTF_FOUND)
	if (NOT LIBCTF_FIND_QUIETLY)
		message(STATUS "Found libctf.h header: ${LIBCTF_INCLUDE_DIR}")
		message(STATUS "Found libctf library: ${LIBCTF_LIBRARY}")
	endif (NOT LIBCTF_FIND_QUIETLY)
endif (LIBCTF_FOUND)

include_directories(${LIBCTF_INCLUDE_DIR})
mark_as_advanced(LIBCTF_INCLUDE_DIR LIBCTF_LIBRARY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake ${CMAKE_CURRENT_SOURCE_DIR}/config.h)

message(STATUS "Checking availability of libctf - done")
