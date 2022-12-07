# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.16)

project(ccfdns LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenEnclave REQUIRED HINTS ${OE})
find_package(ccf REQUIRED HINTS ${CCF})

find_library(RAVL ravl REQUIRED HINTS ${CMAKE_CURRENT_SOURCE_DIR}/../ravl/build)
get_filename_component(RAVL_DIR ${RAVL} DIRECTORY)
find_file(RAVL_INCLUDE include HINTS ${RAVL_DIR}/..)
set(RAVL_SRC ${RAVL_DIR}/../src/attestation.cpp ${RAVL_DIR}/../src/ravl.cpp ${RAVL_DIR}/../src/request_tracker.cpp ${RAVL_DIR}/../src/http_client.cpp)
set(RAVL_DEF RAVL_HAVE_OPENSSL)

set(CCFDNS_DIR ${CMAKE_CURRENT_SOURCE_DIR})

add_ccf_app(ccfdns 
  SRCS ccfdns.cpp resolver.cpp rfc4034.cpp rfc5155.cpp base32.cpp ${RAVL_SRC}
  INCLUDE_DIRS ${RAVL_INCLUDE}  
  )

target_compile_definitions(ccfdns.enclave PUBLIC RAVL_HAVE_OPENSSL)
target_compile_definitions(ccfdns.virtual PUBLIC RAVL_HAVE_OPENSSL)

if (VERBOSE_LOGGING)
  target_compile_definitions(ccfdns.enclave PRIVATE -DVERBOSE_LOGGING)
  target_compile_definitions(ccfdns.virtual PRIVATE -DVERBOSE_LOGGING)
endif()

if (CMAKE_BUILD_TYPE MATCHES Debug)
  target_compile_definitions(ccfdns.virtual PRIVATE QUOTE_VERIFICATION_FAILURE_OK)
  target_compile_options(ccfdns.virtual PRIVATE -fstandalone-debug)

  # target_compile_options(ccfdns.virtual PUBLIC -O1 -g -fsanitize=address -fno-omit-frame-pointer)
  # target_link_options(ccfdns.virtual PUBLIC -g -fsanitize=address)
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

sign_app_library(
  ccfdns.enclave ${CMAKE_CURRENT_SOURCE_DIR}/oe_sign.conf
  ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
)

set(CCFDNS_TEST_UTILITIES tests.sh)
foreach(UTILITY ${CCFDNS_TEST_UTILITIES})
  configure_file(
    ${CCFDNS_DIR}/tests/${UTILITY} ${CMAKE_CURRENT_BINARY_DIR} COPYONLY
  )
endforeach()

enable_testing()
add_test(NAME e2e_simple_tests COMMAND python ../tests/e2e_simple.py -b "${ccf_DIR}/../bin")

function(add_unit_test name)
  add_executable(${name} ${ARGN})
  target_include_directories(${name} PRIVATE "." "${ccf_DIR}/../include" "${ccf_DIR}/../include/ccf/_private" "${ccf_DIR}/../include/3rdparty" ${RAVL_INCLUDE})
  target_compile_definitions(${name} PRIVATE -DVERBOSE_LOGGING)
  target_compile_definitions(${name} PRIVATE RAVL_HAVE_OPENSSL)
  target_link_libraries(
    ${name} PRIVATE ccfcrypto.host openenclave::oehost
  )
  add_test(NAME ${name} COMMAND ${name})
  set_property(TEST ${name} APPEND PROPERTY LABELS unit_test)
  if (VERBOSE_LOGGING)
    target_compile_definitions(${name} PRIVATE -DVERBOSE_LOGGING)
  endif()
  if (CMAKE_BUILD_TYPE MATCHES Debug)
    target_compile_options(${name} PRIVATE -fstandalone-debug)
  endif()
endfunction()

add_unit_test(resolver_tests ../tests/resolver_tests.cpp resolver.cpp rfc4034.cpp rfc5155.cpp base32.cpp ${RAVL_SRC})


set(CCF_EXTRA_INCLUDES "${ccf_DIR}/../include/ccf/_private" "${ccf_DIR}/../include/3rdparty/nghttp2/includes")
add_ccf_app(ccf_demo_service SRCS tests/ccf_demo_service.cpp ${RAVL_SRC})
target_include_directories(ccf_demo_service.enclave PRIVATE ${CCF_EXTRA_INCLUDES} ${RAVL_INCLUDE})
target_include_directories(ccf_demo_service.virtual PRIVATE ${CCF_EXTRA_INCLUDES} ${RAVL_INCLUDE})
target_compile_definitions(ccf_demo_service.enclave PRIVATE RAVL_HAVE_OPENSSL)
target_compile_definitions(ccf_demo_service.virtual PRIVATE RAVL_HAVE_OPENSSL)
if (VERBOSE_LOGGING)
  target_compile_definitions(ccf_demo_service.enclave PRIVATE -DVERBOSE_LOGGING)
  target_compile_definitions(ccf_demo_service.virtual PRIVATE -DVERBOSE_LOGGING)
endif()
if (CMAKE_BUILD_TYPE MATCHES Debug)
  target_compile_definitions(ccf_demo_service.virtual PRIVATE QUOTE_VERIFICATION_FAILURE_OK)
  target_compile_options(ccf_demo_service.virtual PRIVATE -fstandalone-debug)
endif()

sign_app_library(
  ccf_demo_service.enclave ${CMAKE_CURRENT_SOURCE_DIR}/oe_sign.conf
  ${CMAKE_CURRENT_BINARY_DIR}/signing_key.pem
)

add_test(NAME ccf_demo_service COMMAND python ../tests/ccf_demo_service_test.py -b "${ccf_DIR}/../bin")