cmake_minimum_required(VERSION 3.24)

project(foxreq_nss_shim VERSION 0.1.0 LANGUAGES C)

option(FOXREQ_NSS_STUB "Build the development-only NSS stub" OFF)
option(FOXREQ_NSS_REAL "Build the hash-pinned Firefox NSS backend" OFF)

if(FOXREQ_NSS_STUB AND FOXREQ_NSS_REAL)
  message(FATAL_ERROR "Select exactly one NSS backend")
endif()
if(NOT FOXREQ_NSS_STUB AND NOT FOXREQ_NSS_REAL)
  message(FATAL_ERROR "Select FOXREQ_NSS_STUB or FOXREQ_NSS_REAL")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/ToolchainPolicy.cmake")

if(FOXREQ_NSS_REAL)
  include("${CMAKE_CURRENT_LIST_DIR}/cmake/FindPinnedNSS.cmake")
  foxreq_configure_pinned_nss(pinned_include_dir)
  add_library(
    foxreq_nss STATIC
    src/compression.c
    src/connection.c
    src/error.c
    src/profile.c
    src/runtime.c
    src/verify.c
  )
  target_include_directories(foxreq_nss PRIVATE "${pinned_include_dir}")
  target_compile_definitions(foxreq_nss PUBLIC FOXREQ_NSS_REAL=1)
  target_link_libraries(foxreq_nss PRIVATE bcrypt ws2_32)
else()
  add_library(foxreq_nss STATIC src/foxreq_nss.c)
  target_compile_definitions(foxreq_nss PUBLIC FOXREQ_NSS_STUB=1)
endif()
target_include_directories(
  foxreq_nss
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>"
)
foxreq_apply_c_policy(foxreq_nss)

include(CTest)

if(BUILD_TESTING AND FOXREQ_NSS_STUB)
  add_executable(foxreq_nss_abi_test tests/test_abi.c)
  target_link_libraries(foxreq_nss_abi_test PRIVATE foxreq_nss)
  foxreq_apply_c_policy(foxreq_nss_abi_test)
  add_test(NAME foxreq_nss_abi COMMAND foxreq_nss_abi_test)
endif()

if(BUILD_TESTING AND FOXREQ_NSS_REAL)
  add_executable(foxreq_nss_profile_test tests/test_profile.c)
  target_include_directories(
    foxreq_nss_profile_test
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/src"
  )
  target_link_libraries(foxreq_nss_profile_test PRIVATE foxreq_nss)
  foxreq_apply_c_policy(foxreq_nss_profile_test)
  add_test(NAME foxreq_nss_profile COMMAND foxreq_nss_profile_test)
endif()
