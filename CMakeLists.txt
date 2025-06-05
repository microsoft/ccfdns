# Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the
# Apache 2.0 License.

cmake_minimum_required(VERSION 3.16)

include(FetchContent)

# Pick up clang, where available, as the default compiler
if((NOT CMAKE_C_COMPILER)
   AND (NOT CMAKE_CXX_COMPILER)
   AND "$ENV{CC}" STREQUAL ""
   AND "$ENV{CXX}" STREQUAL "")
  find_program(FOUND_CMAKE_C_COMPILER NAMES clang)
  find_program(FOUND_CMAKE_CXX_COMPILER NAMES clang++)

  if(NOT (FOUND_CMAKE_C_COMPILER AND FOUND_CMAKE_CXX_COMPILER))
    message(
      WARNING
        "Clang not found, will use default compiler. "
        "Override the compiler by setting CC and CXX environment variables.")
  else()
    # CMAKE_*_COMPILER can only be set once, and cannot be unset, we either want
    # both, or none at all.
    set(CMAKE_C_COMPILER "${FOUND_CMAKE_C_COMPILER}")
    set(CMAKE_CXX_COMPILER "${FOUND_CMAKE_CXX_COMPILER}")
  endif()
endif()

# Conflicts with CCF snmalloc harcoding
set(TRIESTE_USE_SNMALLOC OFF)

FetchContent_Declare(
  regocpp
  GIT_REPOSITORY https://github.com/microsoft/rego-cpp
  GIT_TAG 5a6b47653fa212de6cafe1f871c6a6511e59f7b5)
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
FetchContent_MakeAvailable(regocpp)

set_property(TARGET rego PROPERTY POSITION_INDEPENDENT_CODE ON)
set_property(TARGET yaml PROPERTY POSITION_INDEPENDENT_CODE ON)
set_property(TARGET json PROPERTY POSITION_INDEPENDENT_CODE ON)
set_property(TARGET re2 PROPERTY POSITION_INDEPENDENT_CODE ON)

set(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -Wundef -Wpedantic -Wno-unused -Wno-unused-parameter -Wshadow"
)

project(ccfdns LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(VERBOSE_LOGGING "verbose logging" OFF)
option(TRACE_LOGGING "extra verbose logging" OFF)

find_package(ccf_${COMPILE_TARGET} REQUIRED HINTS ${CCF})

set(CCF_PKG_DIR ${ccf_${COMPILE_TARGET}_DIR})
set(CCF_PKG_INC ${CCF_PKG_DIR}/../include)

set(ENCLAVE_TARGET ccfdns.${COMPILE_TARGET})

find_package(ZLIB)

add_ccf_app(
  ccfdns
  SRCS
  src/ccfdns.cpp
  src/resolver.cpp
  src/rfc4034.cpp
  src/rfc5155.cpp
  src/base32.cpp
  LINK_LIBS_VIRTUAL
  ZLIB::ZLIB
  LINK_LIBS_SNP
  ZLIB::ZLIB)

target_include_directories(
  ${ENCLAVE_TARGET}
  PRIVATE ${CCF_PKG_DIR}/../include/ccf/_private
  PRIVATE include)

target_compile_definitions(${ENCLAVE_TARGET} PRIVATE ALWAYS_USE_TCP)

set(CCFDNS_TEST_UTILITIES tests.sh)
foreach(UTILITY ${CCFDNS_TEST_UTILITIES})
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/tests/${UTILITY}
                 ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
endforeach()

enable_testing()

set(TEST_PLATFORM_ARGS -t "${COMPILE_TARGET}")

# For the e2e test to mock the attestation of the service being registered.
if(COMPILE_TARGET STREQUAL "snp")
  execute_process(
    COMMAND "make"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/get-snp-report"
    RESULT_VARIABLE RETURN_CODE)
  if(NOT RETURN_CODE STREQUAL "0")
    message(FATAL_ERROR "Error calling cat /etc/os-release")
  endif()
endif()

add_test(
  NAME e2e_basic
  COMMAND python ../tests/e2e_basic.py -b "${CCF_PKG_DIR}/../bin" --library-dir
          "${CMAKE_CURRENT_BINARY_DIR}" ${TEST_PLATFORM_ARGS})
set_property(
  TEST e2e_basic
  APPEND
  PROPERTY
    ENVIRONMENT
    "SNP_REPORT_BINARY=${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/get-snp-report/bin/get-snp-report"
)

if(COMPILE_TARGET STREQUAL "snp")
  execute_process(
    COMMAND find / -maxdepth 1 -type d -name "security-context*"
    OUTPUT_VARIABLE SECURITY_CONTEXT_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
  message(STATUS "UVM security context directory: ${SECURITY_CONTEXT_DIR}")
endif()

function(add_unit_test name)
  add_executable(${name} ${ARGN})
  target_include_directories(
    ${name} PRIVATE "." "${CCF_PKG_INC}" "${CCF_PKG_INC}/ccf/_private"
                    "${CCF_PKG_INC}/3rdparty")
  if(COMPILE_TARGET STREQUAL "virtual")
    target_link_libraries(${name} PRIVATE ccfcrypto.host)
  endif()
  add_test(NAME ${name} COMMAND ${name})
  set_property(
    TEST ${name}
    APPEND
    PROPERTY LABELS unit_test)
  if(COMPILE_TARGET STREQUAL "snp")
    set_property(
      TEST ${name}
      APPEND
      PROPERTY ENVIRONMENT "UVM_SECURITY_CONTEXT_DIR=${SECURITY_CONTEXT_DIR}")
  endif()
  if(TRACE_LOGGING)
    target_compile_definitions(${name} PRIVATE -DTRACE_LOGGING
                                               -DVERBOSE_LOGGING)
  elseif(VERBOSE_LOGGING)
    target_compile_definitions(${name} PRIVATE -DVERBOSE_LOGGING)
  endif()

  if(CMAKE_BUILD_TYPE MATCHES Debug)
    target_compile_options(${name} PRIVATE -fstandalone-debug)
  endif()
endfunction()

add_unit_test(resolver_tests ../tests/resolver_tests.cpp src/resolver.cpp
              src/rfc4034.cpp src/rfc5155.cpp src/base32.cpp)
target_link_libraries(resolver_tests PRIVATE ZLIB::ZLIB ccf.${COMPILE_TARGET})
target_include_directories(
  resolver_tests
  PRIVATE include
  PRIVATE 3rdparty/test)
