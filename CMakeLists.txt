cmake_minimum_required(VERSION 3.13)

project(DATUM VERSION 0.4.0 LANGUAGES C)

# Enable C23 if supported, else fall back to C11 for compatibility
if(CMAKE_VERSION VERSION_LESS "3.21")
    # Older CMake: C23 not recognized; use C11
    set(CMAKE_C_STANDARD 11)
    set(CMAKE_C_STANDARD_REQUIRED ON)
else()
    # CMake 3.21+: C23 is available
    set(CMAKE_C_STANDARD 23)
    set(CMAKE_C_STANDARD_REQUIRED OFF)
endif()

option(ENABLE_API "Build API support." ON)

include(GNUInstallDirs)

add_executable(datum_gateway
	src/datum_blocktemplates.c
	src/datum_coinbaser.c
	src/datum_conf.c
	src/datum_conf_tests.c
	src/datum_gateway.c
	src/datum_jsonrpc.c
	src/datum_logger.c
	src/datum_protocol.c
	src/datum_queue.c
	src/datum_sockets.c
	src/datum_stratum.c
	src/datum_stratum_dupes.c
	src/datum_stratum_tests.c
	src/datum_submitblock.c
	src/datum_utils.c
	src/datum_utils_tests.c
	src/thirdparty_base58.c
	src/thirdparty_segwit_addr.c
	${CMAKE_CURRENT_BINARY_DIR}/web_resources.h
)
install(TARGETS datum_gateway DESTINATION bin)

set(WEB_RESOURCES
	www/auth_failed.html
	www/home.html
	www/clients_top.html
	www/coinbaser_top.html
	www/config.html
	www/config_errors.html
	www/config_restart.html
	www/threads_top.html
	www/foot.html
	www/assets/post.js
	www/assets/style.css
	www/assets/icons/datum_logo.svg
	www/assets/icons/favicon.ico
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(JANSSON REQUIRED jansson)
if(ENABLE_API)
pkg_check_modules(MICROHTTPD REQUIRED libmicrohttpd)
endif()
pkg_check_modules(SODIUM REQUIRED libsodium)
find_package(Threads REQUIRED)

include(CheckFunctionExists)
include(CheckLibraryExists)
include(CMakePushCheckState)
cmake_push_check_state(RESET)
string(APPEND CMAKE_REQUIRED_FLAGS -Wno-error)

set(POW_LIBS "")
check_library_exists(m pow "" LIBM)
if(LIBM)
	list(APPEND POW_LIBS "m")
endif()

set(ARGP_LIBS "")
check_function_exists(argp_parse HAVE_ARGP_PARSE)
if(APPLE AND NOT HAVE_ARGP_PARSE)
    find_library(ARGP_LIBRARY NAMES argp libargp HINTS /opt/homebrew/lib)
    if(ARGP_LIBRARY)
        list(APPEND ARGP_LIBS ${ARGP_LIBRARY})
        include_directories(SYSTEM /opt/homebrew/include)
    else()
        message(FATAL_ERROR "libargp not found. Please install it with `brew install argp-standalone`.")
    endif()
endif()

if(NOT HAVE_ARGP_PARSE)
	check_library_exists(argp argp_parse "" ARGP)
	if(NOT ARGP AND CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
		# Workaround bug where CMake doesn't check the standard install location on FreeBSD
		unset(ARGP CACHE)
		check_library_exists(argp argp_parse "/usr/local/lib" ARGP)
	endif()
	if(ARGP)
		list(APPEND ARGP_LIBS "argp")
	endif()
endif()

# Ensure pkg-config can find Homebrew-installed packages on macOS
if(APPLE)
    set(ENV{PKG_CONFIG_PATH} "/opt/homebrew/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
endif()

check_function_exists(epoll_wait HAVE_EPOLL_WAIT)
if(HAVE_EPOLL_WAIT)
	set(EPOLL_SHIM_INCLUDE_DIRS "")
	set(EPOLL_SHIM_LIBRARIES "")
else()
    pkg_check_modules(EPOLL_SHIM REQUIRED epoll-shim)
    if(APPLE)
       if(NOT EPOLL_SHIM_FOUND)
            message(FATAL_ERROR "epoll-shim not found. Install it with `brew install epoll-shim`.")
       endif()
        # Add include directories
        target_include_directories(datum_gateway
            PUBLIC
            ${EPOLL_SHIM_INCLUDE_DIRS}
        )

        # Add link directories
        target_link_directories(datum_gateway
            PUBLIC
            ${EPOLL_SHIM_LIBRARY_DIRS}
        )

        # Add linker flags (e.g. -L... -lepoll-shim)
        target_link_libraries(datum_gateway
            PUBLIC
            ${EPOLL_SHIM_LDFLAGS}
        )
    endif()
endif()

cmake_pop_check_state()

add_custom_target(generate_git_version
	BYPRODUCTS ${PROJECT_BINARY_DIR}/git_version.h
	COMMAND ${CMAKE_COMMAND} -DBUILD_INFO_HEADER_PATH=${PROJECT_BINARY_DIR}/git_version.h -DSOURCE_DIR=${PROJECT_SOURCE_DIR} -P ${PROJECT_SOURCE_DIR}/cmake/script/GenerateBuildInfo.cmake
	DEPENDS cmake/script/GenerateBuildInfo.cmake
	COMMENT "Generating git_version.h"
	VERBATIM
)
add_dependencies(datum_gateway generate_git_version)

add_custom_command(
	OUTPUT web_resources.h
	COMMAND ${CMAKE_COMMAND} "-DINPUT_FILES=${WEB_RESOURCES}" -DOUTPUT_FILE=web_resources.h -DSOURCE_DIR=${PROJECT_SOURCE_DIR} -P ${PROJECT_SOURCE_DIR}/cmake/script/EmbedResources.cmake
	DEPENDS ${WEB_RESOURCES} cmake/script/EmbedResources.cmake
	VERBATIM
)

target_include_directories(datum_gateway
	PRIVATE
	$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>
	${EPOLL_SHIM_INCLUDE_DIRS}
	${CURL_INCLUDE_DIRS}
	${JANSSON_INCLUDE_DIRS}
	${SODIUM_INCLUDE_DIRS}
)
target_link_directories(datum_gateway
	PUBLIC
	${CURL_LIBRARY_DIRS}
	${JANSSON_LIBRARY_DIRS}
	${SODIUM_LIBRARY_DIRS}
)
target_link_libraries(datum_gateway
	PUBLIC
	${POW_LIBS}
	Threads::Threads
	${ARGP_LIBS}
	${EPOLL_SHIM_LIBRARIES}
	${CURL_LIBRARIES} ${CURL_LDFLAGS} ${CURL_LDFLAGS_OTHER}
	${JANSSON_LIBRARIES} ${JANSSON_LDFLAGS} ${JANSSON_LDFLAGS_OTHER}
	${SODIUM_LIBRARIES} ${SODIUM_LDFLAGS} ${SODIUM_LDFLAGS_OTHER}
)
target_compile_options(datum_gateway
	PUBLIC
	${CURL_CFLAGS} ${CURL_CFLAGS_OTHER}
	${JANSSON_CFLAGS} ${JANSSON_CFLAGS_OTHER}
	${SODIUM_CFLAGS} ${SODIUM_CFLAGS_OTHER}
)

if(ENABLE_API)
	target_sources(datum_gateway PRIVATE src/datum_api.c)
	target_include_directories(datum_gateway PRIVATE ${MICROHTTPD_INCLUDE_DIRS})
	target_link_directories(datum_gateway PUBLIC ${MICROHTTPD_LIBRARY_DIRS})
	target_link_libraries(datum_gateway PUBLIC ${MICROHTTPD_LIBRARIES} ${MICROHTTPD_LDFLAGS} ${MICROHTTPD_LDFLAGS_OTHER})
	target_compile_options(datum_gateway PUBLIC
		-DENABLE_API
		${MICROHTTPD_CFLAGS} ${MICROHTTPD_CFLAGS_OTHER}
	)
endif()

install(FILES README.md DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES doc/DATUM_recommended_setup-network_diagram.svg DESTINATION ${CMAKE_INSTALL_DOCDIR}/doc)
install(FILES doc/usernames.md DESTINATION ${CMAKE_INSTALL_DOCDIR})

set(PREGEN_DOC ${CMAKE_SOURCE_DIR}/doc/example_datum_gateway_config.json)
install(FILES ${PREGEN_DOC} DESTINATION ${CMAKE_INSTALL_DOCDIR})

if(NOT CMAKE_CROSSCOMPILING)
	set(GENERATED_DOC ${CMAKE_BINARY_DIR}/CMakeFiles/generated_example_datum_gateway_config.json)
	
	add_custom_command(
		TARGET datum_gateway
		POST_BUILD
		COMMAND ${CMAKE_COMMAND} -DDATUM_GATEWAY=$<TARGET_FILE:datum_gateway> -DGENERATED_DOC=${GENERATED_DOC} -DPREGEN_DOC=${PREGEN_DOC} -P ${PROJECT_SOURCE_DIR}/cmake/script/VerifyExample.cmake
		COMMENT "Verifying pre-generated documentation is up-to-date"
		VERBATIM
	)
endif()
