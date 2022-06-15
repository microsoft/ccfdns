# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.16)

project(ccfdns LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(ccf REQUIRED)

add_ccf_app(ccfdns SRCS ccfdns.cpp resolver.cpp)

target_link_options(ccfdns.virtual PUBLIC -fsanitize=undefined)

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

enable_testing()
add_test(NAME dns_test COMMAND python ../tests/dns.py)

function(add_unit_test name)
  add_executable(${name} ${ARGN} "../CCF/src/kv/tx.cpp" "../CCF/src/kv/untyped_map_handle.cpp")
  target_include_directories(${name} PRIVATE "." "${ccf_DIR}/../include" "${ccf_DIR}/../include/ccf/_private" "${ccf_DIR}/../include/3rdparty")
  target_link_libraries(
    ${name} PRIVATE ccfcrypto.host openenclave::oehost
  )
  add_test(NAME ${name} COMMAND ${name})
  set_property(TEST ${name} APPEND PROPERTY LABELS unit_test)
endfunction()

add_unit_test(resolver_tests ../tests/resolver_tests.cpp resolver.cpp)
