# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.16)

project(ccfdns LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(VIRTUAL "build virtual enclaves" OFF)
option(VERBOSE_LOGGING "verbose logging" OFF)
option(TRACE_LOGGING "extra verbose logging" OFF)

if (VIRTUAL)
  set(COMPILE_TARGET virtual)
  set(SUFFIX virtual)
  find_package(ccf_virtual REQUIRED HINTS ${CCF})
  set(CCF_PKG_DIR ${ccf_virtual_DIR})
else()
  set(COMPILE_TARGET sgx)
  set(SUFFIX enclave)
  find_package(ccf_sgx REQUIRED HINTS ${CCF})
  set(CCF_PKG_DIR ${ccf_sgx_DIR})
endif()

set(ENCLAVE_TARGET ccfdns.${SUFFIX})
set(DEMO_ENCLAVE_TARGET ccf_demo_service.${SUFFIX})
set(CCF_PKG_INC ${CCF_PKG_DIR}/../include)

find_library(RAVL ravl REQUIRED HINTS ${CMAKE_CURRENT_SOURCE_DIR}/../ravl/build)
get_filename_component(RAVL_DIR ${RAVL} DIRECTORY)
set(RAVL_SRC ${RAVL_DIR}/../src)

add_library(ravl INTERFACE)
target_compile_definitions(ravl INTERFACE RAVL_HAVE_OPENSSL RAVL_LIBRARY_BUILD)
target_include_directories(ravl INTERFACE ${RAVL_DIR}/../include)
target_sources(ravl INTERFACE ${RAVL_SRC}/attestation.cpp ${RAVL_SRC}/ravl.cpp ${RAVL_SRC}/request_tracker.cpp ${RAVL_SRC}/http_client.cpp)

set(ZLIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/zlib)
set(ZLIB_SRC ${ZLIB_DIR}/compress.c ${ZLIB_DIR}/deflate.c ${ZLIB_DIR}/inflate.c ${ZLIB_DIR}/trees.c ${ZLIB_DIR}/adler32.c ${ZLIB_DIR}/crc32.c ${ZLIB_DIR}/zutil.c ${ZLIB_DIR}/infback.c ${ZLIB_DIR}/inftrees.c ${ZLIB_DIR}/inffast.c)

add_library(zlib ${ZLIB_SRC})
target_include_directories(zlib PRIVATE ${ZLIB_DIR})
target_compile_options(zlib PRIVATE -fPIC)
target_compile_definitions(zlib PRIVATE)

set(CCFDNS_DIR ${CMAKE_CURRENT_SOURCE_DIR})

add_ccf_app(ccfdns
  SRCS ccfdns.cpp resolver.cpp rfc4034.cpp rfc5155.cpp base32.cpp 
  INCLUDE_DIRS ${CCFDNS_DIR}/3rdparty
  LINK_LIBS_VIRTUAL ravl zlib
  LINK_LIBS_ENCLAVE ravl zlib
)

target_include_directories(${ENCLAVE_TARGET} PRIVATE ${CCF_PKG_DIR}/../include/ccf/_private)
target_compile_definitions(${ENCLAVE_TARGET} PRIVATE ALWAYS_USE_TCP)

if (NOT VIRTUAL)
sign_app_library(
  ${ENCLAVE_TARGET} ${CMAKE_CURRENT_SOURCE_DIR}/oe_sign.conf
  ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
)
endif()

if (TRACE_LOGGING)
  target_compile_definitions(${ENCLAVE_TARGET} PRIVATE -DTRACE_LOGGING -DVERBOSE_LOGGING)
elseif (VERBOSE_LOGGING)
  target_compile_definitions(${ENCLAVE_TARGET} PRIVATE -DVERBOSE_LOGGING)
endif()

if (VIRTUAL)
  if (CMAKE_BUILD_TYPE MATCHES Debug)
    target_compile_definitions(${ENCLAVE_TARGET} PRIVATE ATTESTATION_VERIFICATION_FAILURE_OK)
    target_compile_options(${ENCLAVE_TARGET} PRIVATE -fstandalone-debug)
    set(ASAN_BLACKLIST -fsanitize-blacklist=${CMAKE_CURRENT_SOURCE_DIR}/asan_blacklist.txt)
    target_compile_options(${ENCLAVE_TARGET} PUBLIC -O1 -g -fsanitize=address ${ASAN_BLACKLIST} -fno-omit-frame-pointer)
    target_link_options(${ENCLAVE_TARGET} PUBLIC -g -fsanitize=address)
  endif()
endif()

# Generate an ephemeral signing key
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
  COMMAND openssl genrsa -out ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem -3
          3072
)
add_custom_target(
  ccfdns_signing_key ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
)

set(CCFDNS_TEST_UTILITIES tests.sh)
foreach(UTILITY ${CCFDNS_TEST_UTILITIES})
  configure_file(
    ${CCFDNS_DIR}/tests/${UTILITY} ${CMAKE_CURRENT_BINARY_DIR} COPYONLY
  )
endforeach()


enable_testing()

if (VIRTUAL)
  set(TEST_PLATFORM_ARGS -e virtual -t virtual)
endif()

add_test(NAME e2e_simple_tests COMMAND python ../tests/e2e_simple.py -b "${CCF_PKG_DIR}/../bin" ${TEST_PLATFORM_ARGS})

function(add_unit_test name)
  add_executable(${name} ${ARGN})
  target_include_directories(${name} PRIVATE "." "${CCF_PKG_INC}" "${CCF_PKG_INC}/ccf/_private" "${CCF_PKG_INC}/3rdparty" ${CCFDNS_DIR}/3rdparty)
  target_link_libraries(${name} PRIVATE ravl zlib)
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

if (VIRTUAL)
  add_unit_test(resolver_tests ../tests/resolver_tests.cpp resolver.cpp rfc4034.cpp rfc5155.cpp base32.cpp)
  target_compile_definitions(resolver_tests PRIVATE ATTESTATION_VERIFICATION_FAILURE_OK)
endif()

add_executable(queryperf ../tests/queryperf.cpp)
target_link_libraries(queryperf PRIVATE resolv)

add_ccf_app(ccf_demo_service
  SRCS tests/ccf_demo_service.cpp
  LINK_LIBS_ENCLAVE ravl
  LINK_LIBS_VIRTUAL ravl)
target_include_directories(${DEMO_ENCLAVE_TARGET} PRIVATE "${CCF_PKG_INC}/ccf/_private")
if (TRACE_LOGGING)
  target_compile_definitions(${DEMO_ENCLAVE_TARGET} PRIVATE -DTRACE_LOGGING -DVERBOSE_LOGGING)
elseif (VERBOSE_LOGGING)
  target_compile_definitions(${DEMO_ENCLAVE_TARGET} PRIVATE -DVERBOSE_LOGGING)
endif()
if (CMAKE_BUILD_TYPE MATCHES Debug)
  target_compile_definitions(${DEMO_ENCLAVE_TARGET} PRIVATE ATTESTATION_VERIFICATION_FAILURE_OK)
  target_compile_options(${DEMO_ENCLAVE_TARGET} PRIVATE -fstandalone-debug)
endif()

if (NOT VIRTUAL)
sign_app_library(
  ${DEMO_ENCLAVE_TARGET} ${CMAKE_CURRENT_SOURCE_DIR}/oe_sign.conf
  ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
)
endif()
