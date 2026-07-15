cmake_minimum_required(VERSION 3.24)

project(foxreq_nss_shim VERSION 0.1.0 LANGUAGES C)

option(FOXREQ_NSS_STUB "Build the development-only NSS stub" OFF)

if(NOT FOXREQ_NSS_STUB)
  message(FATAL_ERROR "The pinned NSS backend is introduced in Task 7; configure with -DFOXREQ_NSS_STUB=ON for now")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/ToolchainPolicy.cmake")

add_library(foxreq_nss STATIC src/foxreq_nss.c)
target_include_directories(
  foxreq_nss
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>"
)
target_compile_definitions(foxreq_nss PUBLIC FOXREQ_NSS_STUB=1)
foxreq_apply_c_policy(foxreq_nss)

include(CTest)

if(BUILD_TESTING)
  add_executable(foxreq_nss_abi_test tests/test_abi.c)
  target_link_libraries(foxreq_nss_abi_test PRIVATE foxreq_nss)
  foxreq_apply_c_policy(foxreq_nss_abi_test)
  add_test(NAME foxreq_nss_abi COMMAND foxreq_nss_abi_test)
endif()
