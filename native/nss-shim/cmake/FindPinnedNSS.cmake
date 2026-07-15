function(foxreq_configure_pinned_nss out_include_dir)
  if(NOT WIN32)
    message(FATAL_ERROR "The real pinned NSS backend currently supports Windows only")
  endif()

  set(lock_path "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../../../third_party/firefox-windows-runtime.lock.json")
  file(READ "${lock_path}" lock_json)
  string(JSON schema_version GET "${lock_json}" schema_version)
  if(NOT schema_version EQUAL 1)
    message(FATAL_ERROR "Unsupported pinned NSS runtime lock schema")
  endif()

  string(JSON platform GET "${lock_json}" platform)
  string(JSON nss_version GET "${lock_json}" nss_version)
  string(JSON nspr_version GET "${lock_json}" nspr_version)
  if(NOT platform STREQUAL "windows-x86_64")
    message(FATAL_ERROR "Pinned NSS runtime platform mismatch: ${platform}")
  endif()
  if(NOT nss_version STREQUAL "3.124" OR NOT nspr_version STREQUAL "4.39")
    message(FATAL_ERROR "Pinned NSS runtime component version mismatch")
  endif()

  set(generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")
  file(MAKE_DIRECTORY "${generated_dir}")
  set(header "${generated_dir}/foxreq_pinned_runtime.h")
  file(WRITE "${header}"
    "#ifndef FOXREQ_PINNED_RUNTIME_H\n#define FOXREQ_PINNED_RUNTIME_H\n\n"
    "#include <stdint.h>\n#include <wchar.h>\n\n"
    "typedef struct foxreq_pinned_file {\n"
    "  const wchar_t *filename;\n  const char *sha256;\n  uint64_t size;\n"
    "} foxreq_pinned_file;\n\n"
    "#define FOXREQ_PINNED_NSS_VERSION \"${nss_version}\"\n"
    "#define FOXREQ_PINNED_NSPR_VERSION \"${nspr_version}\"\n\n"
    "static const foxreq_pinned_file FOXREQ_PINNED_FILES[] = {\n")

  string(JSON file_count LENGTH "${lock_json}" files)
  math(EXPR last_file "${file_count} - 1")
  foreach(index RANGE 0 ${last_file})
    string(JSON filename GET "${lock_json}" files ${index} filename)
    string(JSON sha256 GET "${lock_json}" files ${index} sha256)
    string(JSON size GET "${lock_json}" files ${index} size)
    if(NOT filename MATCHES "^[A-Za-z0-9_.-]+$")
      message(FATAL_ERROR "Unsafe pinned NSS runtime filename: ${filename}")
    endif()
    string(LENGTH "${sha256}" sha256_length)
    if(NOT sha256 MATCHES "^[0-9a-f]+$" OR NOT sha256_length EQUAL 64)
      message(FATAL_ERROR "Invalid pinned NSS runtime SHA-256 for ${filename}")
    endif()
    file(APPEND "${header}"
      "  {L\"${filename}\", \"${sha256}\", UINT64_C(${size})},\n")
  endforeach()
  file(APPEND "${header}"
    "};\n#define FOXREQ_PINNED_FILE_COUNT "
    "(sizeof(FOXREQ_PINNED_FILES) / sizeof(FOXREQ_PINNED_FILES[0]))\n\n"
    "#endif\n")

  set(${out_include_dir} "${generated_dir}" PARENT_SCOPE)
endfunction()
