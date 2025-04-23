# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.16)

# Pick up clang, where available, as the default compiler
if((NOT CMAKE_C_COMPILER)
   AND (NOT CMAKE_CXX_COMPILER)
   AND "$ENV{CC}" STREQUAL ""
   AND "$ENV{CXX}" STREQUAL ""
)
  find_program(FOUND_CMAKE_C_COMPILER NAMES clang)
  find_program(FOUND_CMAKE_CXX_COMPILER NAMES clang++)

  if(NOT (FOUND_CMAKE_C_COMPILER AND FOUND_CMAKE_CXX_COMPILER))
    message(
      WARNING
        "Clang not found, will use default compiler. "
        "Override the compiler by setting CC and CXX environment variables."
    )
  else()
    # CMAKE_*_COMPILER can only be set once, and cannot be unset, we either want
    # both, or none at all.
    set(CMAKE_C_COMPILER "${FOUND_CMAKE_C_COMPILER}")
    set(CMAKE_CXX_COMPILER "${FOUND_CMAKE_CXX_COMPILER}")
  endif()
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wfatal-errors")

project(ccfdns LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(VERBOSE_LOGGING "verbose logging" OFF)
option(TRACE_LOGGING "extra verbose logging" OFF)


set(COMPILE_TARGET virtual)
set(SUFFIX virtual)
find_package(ccf_virtual REQUIRED HINTS ${CCF})

set(CCF_PKG_DIR ${ccf_virtual_DIR})
set(CCF_PKG_INC ${CCF_PKG_DIR}/../include)

set(ENCLAVE_TARGET ccfdns.${SUFFIX})

find_package(ZLIB)

add_ccf_app(ccfdns
  SRCS ccfdns.cpp resolver.cpp rfc4034.cpp rfc5155.cpp base32.cpp
  LINK_LIBS_VIRTUAL ZLIB::ZLIB
)

target_include_directories(${ENCLAVE_TARGET} PRIVATE ${CCF_PKG_DIR}/../include/ccf/_private)
target_compile_definitions(${ENCLAVE_TARGET} PRIVATE ALWAYS_USE_TCP)

if (CMAKE_BUILD_TYPE MATCHES Debug)
  # Need to be behind SAN switch and reviewed
  # set(ASAN_BLACKLIST -fsanitize-blacklist=${CMAKE_CURRENT_SOURCE_DIR}/asan_blacklist.txt)
  # target_compile_options(${ENCLAVE_TARGET} PUBLIC -O1 -g -fsanitize=address ${ASAN_BLACKLIST} -fno-omit-frame-pointer)
  # target_link_options(${ENCLAVE_TARGET} PUBLIC -g -fsanitize=address)
endif()

set(CCFDNS_TEST_UTILITIES tests.sh)
foreach(UTILITY ${CCFDNS_TEST_UTILITIES})
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/${UTILITY} ${CMAKE_CURRENT_BINARY_DIR} COPYONLY
  )
endforeach()

enable_testing()

if (VIRTUAL)
  set(TEST_PLATFORM_ARGS -e virtual -t virtual)
endif()

add_test(NAME e2e_simple_tests COMMAND python ../tests/e2e_simple.py -b "${CCF_PKG_DIR}/../bin" ${TEST_PLATFORM_ARGS})
add_test(NAME e2e_simple_tests_aci COMMAND python ../tests/e2e_simple.py --service-type "ACI" -b "${CCF_PKG_DIR}/../bin" ${TEST_PLATFORM_ARGS})

function(add_unit_test name)
  add_executable(${name} ${ARGN})
  target_include_directories(${name} PRIVATE "." "${CCF_PKG_INC}" "${CCF_PKG_INC}/ccf/_private" "${CCF_PKG_INC}/3rdparty")
  if (VIRTUAL)
    target_link_libraries(${name} PRIVATE ccfcrypto.host)
  endif()
  add_test(NAME ${name} COMMAND ${name})
  set_property(TEST ${name} APPEND PROPERTY LABELS unit_test)
  if (TRACE_LOGGING)
    target_compile_definitions(${name} PRIVATE -DTRACE_LOGGING -DVERBOSE_LOGGING)
  elseif (VERBOSE_LOGGING)
    target_compile_definitions(${name} PRIVATE -DVERBOSE_LOGGING)
  endif()

  if (CMAKE_BUILD_TYPE MATCHES Debug)
    target_compile_options(${name} PRIVATE -fstandalone-debug)
  endif()
endfunction()

add_unit_test(resolver_tests ../tests/resolver_tests.cpp resolver.cpp rfc4034.cpp rfc5155.cpp base32.cpp)
target_link_libraries(resolver_tests PRIVATE ZLIB::ZLIB)