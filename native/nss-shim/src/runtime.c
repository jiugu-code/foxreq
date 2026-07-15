#include "foxreq_nss_real_internal.h"
#include "foxreq_pinned_runtime.h"

#include <bcrypt.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef struct foxreq_global_runtime {
  SRWLOCK lock;
  uint32_t references;
  wchar_t *directory;
  HMODULE mozglue;
  HMODULE nss3;
  HMODULE freebl3;
  HMODULE softokn3;
  int winsock_started;
  uint8_t *trust_anchor;
  size_t trust_anchor_length;
  foxreq_cert_certificate *trust_certificate;
} foxreq_global_runtime;

static foxreq_global_runtime global_runtime = {SRWLOCK_INIT, 0U, NULL, NULL,
                                               NULL, NULL, NULL, 0, NULL, 0U,
                                               NULL};
foxreq_nss_api foxreq_real_api = {0};

static int slice_is_valid(foxreq_nss_slice slice, int allow_empty) {
  if (slice.length > (uint64_t)SIZE_MAX) {
    return 0;
  }
  if (slice.length == UINT64_C(0)) {
    return allow_empty;
  }
  return slice.data != NULL;
}

static wchar_t *utf8_directory(foxreq_nss_slice value) {
  int source_length;
  int wide_length;
  wchar_t *result;
  if (!slice_is_valid(value, 0) || value.length > (uint64_t)INT_MAX ||
      memchr(value.data, 0, (size_t)value.length) != NULL) {
    return NULL;
  }
  source_length = (int)value.length;
  wide_length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                    (const char *)value.data, source_length,
                                    NULL, 0);
  if (wide_length <= 0 || wide_length == INT_MAX) {
    return NULL;
  }
  result = (wchar_t *)calloc((size_t)wide_length + 1U, sizeof(wchar_t));
  if (result == NULL) {
    return NULL;
  }
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                          (const char *)value.data, source_length, result,
                          wide_length) != wide_length) {
    free(result);
    return NULL;
  }
  return result;
}

static wchar_t *join_path(const wchar_t *directory, const wchar_t *filename) {
  size_t directory_length = wcslen(directory);
  size_t filename_length = wcslen(filename);
  int needs_separator = directory_length > 0U &&
                        directory[directory_length - 1U] != L'\\' &&
                        directory[directory_length - 1U] != L'/';
  size_t length;
  wchar_t *path;
  if (directory_length > SIZE_MAX - filename_length - 2U) {
    return NULL;
  }
  length = directory_length + filename_length + (size_t)needs_separator + 1U;
  path = (wchar_t *)calloc(length, sizeof(wchar_t));
  if (path == NULL) {
    return NULL;
  }
  memcpy(path, directory, directory_length * sizeof(wchar_t));
  if (needs_separator) {
    path[directory_length] = L'\\';
    directory_length += 1U;
  }
  memcpy(path + directory_length, filename,
         (filename_length + 1U) * sizeof(wchar_t));
  return path;
}

static int sha256_file(const wchar_t *path, char output[65]) {
  BCRYPT_ALG_HANDLE algorithm = NULL;
  BCRYPT_HASH_HANDLE hash = NULL;
  HANDLE file = INVALID_HANDLE_VALUE;
  PUCHAR object = NULL;
  DWORD object_length = 0U;
  DWORD hash_length = 0U;
  DWORD property_length = 0U;
  UCHAR digest[32];
  UCHAR buffer[64U * 1024U];
  DWORD read = 0U;
  size_t index;
  int ok = 0;
  static const char digits[] = "0123456789abcdef";

  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL,
                                  0U) != 0) {
    goto cleanup;
  }
  if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                        (PUCHAR)&object_length, sizeof(object_length),
                        &property_length, 0U) != 0 ||
      property_length != sizeof(object_length)) {
    goto cleanup;
  }
  if (BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_length,
                        sizeof(hash_length), &property_length, 0U) != 0 ||
      property_length != sizeof(hash_length) || hash_length != sizeof(digest)) {
    goto cleanup;
  }
  object = (PUCHAR)HeapAlloc(GetProcessHeap(), 0U, object_length);
  if (object == NULL) {
    goto cleanup;
  }
  if (BCryptCreateHash(algorithm, &hash, object, object_length, NULL, 0U, 0U) !=
      0) {
    goto cleanup;
  }
  file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
  if (file == INVALID_HANDLE_VALUE) {
    goto cleanup;
  }
  do {
    if (!ReadFile(file, buffer, (DWORD)sizeof(buffer), &read, NULL)) {
      goto cleanup;
    }
    if (read > 0U && BCryptHashData(hash, buffer, read, 0U) != 0) {
      goto cleanup;
    }
  } while (read > 0U);
  if (BCryptFinishHash(hash, digest, (ULONG)sizeof(digest), 0U) != 0) {
    goto cleanup;
  }
  for (index = 0U; index < sizeof(digest); index += 1U) {
    output[index * 2U] = digits[digest[index] >> 4U];
    output[index * 2U + 1U] = digits[digest[index] & 0x0FU];
  }
  output[64] = '\0';
  ok = 1;

cleanup:
  if (file != INVALID_HANDLE_VALUE) {
    CloseHandle(file);
  }
  if (hash != NULL) {
    BCryptDestroyHash(hash);
  }
  if (object != NULL) {
    HeapFree(GetProcessHeap(), 0U, object);
  }
  if (algorithm != NULL) {
    BCryptCloseAlgorithmProvider(algorithm, 0U);
  }
  return ok;
}

static int verify_file(const wchar_t *directory,
                       const foxreq_pinned_file *pinned) {
  wchar_t *path = join_path(directory, pinned->filename);
  WIN32_FILE_ATTRIBUTE_DATA attributes;
  ULARGE_INTEGER size;
  char digest[65];
  int ok = 0;
  if (path == NULL) {
    return 0;
  }
  if (!GetFileAttributesExW(path, GetFileExInfoStandard, &attributes) ||
      (attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U ||
      (attributes.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) {
    goto cleanup;
  }
  size.HighPart = attributes.nFileSizeHigh;
  size.LowPart = attributes.nFileSizeLow;
  if (size.QuadPart != pinned->size || !sha256_file(path, digest) ||
      strcmp(digest, pinned->sha256) != 0) {
    goto cleanup;
  }
  ok = 1;
cleanup:
  free(path);
  return ok;
}

static HMODULE load_file(const wchar_t *directory, const wchar_t *filename) {
  wchar_t *path = join_path(directory, filename);
  HMODULE module = NULL;
  if (path != NULL) {
    module = LoadLibraryExW(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                                           LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
  }
  free(path);
  return module;
}

static FARPROC require_symbol(HMODULE module, const char *name) {
  if (module == NULL) {
    return NULL;
  }
  return GetProcAddress(module, name);
}

static void clear_api(void) { memset(&foxreq_real_api, 0, sizeof(foxreq_real_api)); }

static void unload_locked(void) {
  if (global_runtime.softokn3 != NULL) {
    FreeLibrary(global_runtime.softokn3);
    global_runtime.softokn3 = NULL;
  }
  if (global_runtime.freebl3 != NULL) {
    FreeLibrary(global_runtime.freebl3);
    global_runtime.freebl3 = NULL;
  }
  if (global_runtime.nss3 != NULL) {
    FreeLibrary(global_runtime.nss3);
    global_runtime.nss3 = NULL;
  }
  if (global_runtime.mozglue != NULL) {
    FreeLibrary(global_runtime.mozglue);
    global_runtime.mozglue = NULL;
  }
  if (global_runtime.winsock_started) {
    (void)WSACleanup();
    global_runtime.winsock_started = 0;
  }
  clear_api();
  free(global_runtime.directory);
  global_runtime.directory = NULL;
}

static int load_locked(wchar_t *directory) {
  size_t index;
  const char *nss_version;
  const char *nspr_version;
  WSADATA winsock;
  for (index = 0U; index < FOXREQ_PINNED_FILE_COUNT; index += 1U) {
    if (!verify_file(directory, &FOXREQ_PINNED_FILES[index])) {
      return 0;
    }
  }
  if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
    return 0;
  }
  global_runtime.winsock_started = 1;
  global_runtime.mozglue = load_file(directory, L"mozglue.dll");
  global_runtime.nss3 = load_file(directory, L"nss3.dll");
  global_runtime.freebl3 = load_file(directory, L"freebl3.dll");
  global_runtime.softokn3 = load_file(directory, L"softokn3.dll");
  if (global_runtime.mozglue == NULL || global_runtime.nss3 == NULL ||
      global_runtime.freebl3 == NULL || global_runtime.softokn3 == NULL) {
    unload_locked();
    return 0;
  }
  foxreq_real_api.nss_get_version =
      (foxreq_version_fn)require_symbol(global_runtime.nss3, "NSS_GetVersion");
  foxreq_real_api.nspr_get_version =
      (foxreq_version_fn)require_symbol(global_runtime.nss3, "PR_GetVersion");
  foxreq_real_api.nss_no_db_init =
      (foxreq_nss_init_fn)require_symbol(global_runtime.nss3, "NSS_NoDB_Init");
  foxreq_real_api.nss_shutdown =
      (foxreq_nss_shutdown_fn)require_symbol(global_runtime.nss3, "NSS_Shutdown");
  foxreq_real_api.pr_get_error =
      (foxreq_pr_get_error_fn)require_symbol(global_runtime.nss3, "PR_GetError");
  foxreq_real_api.cert_get_default_db =
      (foxreq_cert_get_default_db_fn)require_symbol(
          global_runtime.nss3, "CERT_GetDefaultCertDB");
  foxreq_real_api.cert_new_temp = (foxreq_cert_new_temp_fn)require_symbol(
      global_runtime.nss3, "CERT_NewTempCertificate");
  foxreq_real_api.cert_decode_trust =
      (foxreq_cert_decode_trust_fn)require_symbol(
          global_runtime.nss3, "CERT_DecodeTrustString");
  foxreq_real_api.cert_change_trust =
      (foxreq_cert_change_trust_fn)require_symbol(
          global_runtime.nss3, "CERT_ChangeCertTrust");
  foxreq_real_api.cert_destroy = (foxreq_cert_destroy_fn)require_symbol(
      global_runtime.nss3, "CERT_DestroyCertificate");
  foxreq_real_api.pr_import_tcp_socket = (foxreq_pr_import_socket_fn)require_symbol(
      global_runtime.nss3, "PR_ImportTCPSocket");
  foxreq_real_api.pr_set_socket_option =
      (foxreq_pr_set_socket_option_fn)require_symbol(
          global_runtime.nss3, "PR_SetSocketOption");
  foxreq_real_api.pr_get_socket_option =
      (foxreq_pr_get_socket_option_fn)require_symbol(
          global_runtime.nss3, "PR_GetSocketOption");
  foxreq_real_api.pr_poll = (foxreq_pr_poll_fn)require_symbol(
      global_runtime.nss3, "PR_Poll");
  foxreq_real_api.ssl_import_fd = (foxreq_ssl_import_fd_fn)require_symbol(
      global_runtime.nss3, "SSL_ImportFD");
  foxreq_real_api.ssl_option_set = (foxreq_ssl_option_set_fn)require_symbol(
      global_runtime.nss3, "SSL_OptionSet");
  foxreq_real_api.ssl_set_url = (foxreq_ssl_set_url_fn)require_symbol(
      global_runtime.nss3, "SSL_SetURL");
  foxreq_real_api.ssl_version_range_set =
      (foxreq_ssl_version_range_set_fn)require_symbol(
          global_runtime.nss3, "SSL_VersionRangeSet");
  foxreq_real_api.ssl_set_next_proto =
      (foxreq_ssl_set_next_proto_fn)require_symbol(
          global_runtime.nss3, "SSL_SetNextProtoNego");
  foxreq_real_api.ssl_auth_hook = (foxreq_ssl_auth_hook_fn)require_symbol(
      global_runtime.nss3, "SSL_AuthCertificateHook");
  foxreq_real_api.ssl_reset_handshake =
      (foxreq_ssl_reset_handshake_fn)require_symbol(
          global_runtime.nss3, "SSL_ResetHandshake");
  foxreq_real_api.ssl_force_handshake =
      (foxreq_ssl_force_handshake_fn)require_symbol(
          global_runtime.nss3, "SSL_ForceHandshake");
  foxreq_real_api.ssl_get_next_proto =
      (foxreq_ssl_get_next_proto_fn)require_symbol(global_runtime.nss3,
                                                   "SSL_GetNextProto");
  foxreq_real_api.pr_recv = (foxreq_pr_recv_fn)require_symbol(
      global_runtime.nss3, "PR_Recv");
  foxreq_real_api.pr_send = (foxreq_pr_send_fn)require_symbol(
      global_runtime.nss3, "PR_Send");
  foxreq_real_api.pr_close = (foxreq_pr_close_fn)require_symbol(
      global_runtime.nss3, "PR_Close");
  foxreq_real_api.pr_milliseconds = (foxreq_pr_milliseconds_fn)require_symbol(
      global_runtime.nss3, "PR_MillisecondsToInterval");
  if (foxreq_real_api.nss_get_version == NULL ||
      foxreq_real_api.nspr_get_version == NULL ||
      foxreq_real_api.nss_no_db_init == NULL ||
      foxreq_real_api.nss_shutdown == NULL ||
      foxreq_real_api.pr_get_error == NULL ||
      foxreq_real_api.cert_get_default_db == NULL ||
      foxreq_real_api.cert_new_temp == NULL ||
      foxreq_real_api.cert_decode_trust == NULL ||
      foxreq_real_api.cert_change_trust == NULL ||
      foxreq_real_api.cert_destroy == NULL ||
      foxreq_real_api.pr_import_tcp_socket == NULL ||
      foxreq_real_api.pr_set_socket_option == NULL ||
      foxreq_real_api.pr_get_socket_option == NULL ||
      foxreq_real_api.pr_poll == NULL ||
      foxreq_real_api.ssl_import_fd == NULL ||
      foxreq_real_api.ssl_option_set == NULL ||
      foxreq_real_api.ssl_set_url == NULL ||
      foxreq_real_api.ssl_version_range_set == NULL ||
      foxreq_real_api.ssl_set_next_proto == NULL ||
      foxreq_real_api.ssl_auth_hook == NULL ||
      foxreq_real_api.ssl_reset_handshake == NULL ||
      foxreq_real_api.ssl_force_handshake == NULL ||
      foxreq_real_api.ssl_get_next_proto == NULL ||
      foxreq_real_api.pr_recv == NULL || foxreq_real_api.pr_send == NULL ||
      foxreq_real_api.pr_close == NULL ||
      foxreq_real_api.pr_milliseconds == NULL) {
    unload_locked();
    return 0;
  }
  nss_version = foxreq_real_api.nss_get_version();
  nspr_version = foxreq_real_api.nspr_get_version();
  if (nss_version == NULL || nspr_version == NULL ||
      strcmp(nss_version, FOXREQ_PINNED_NSS_VERSION) != 0 ||
      strcmp(nspr_version, FOXREQ_PINNED_NSPR_VERSION) != 0 ||
      foxreq_real_api.nss_no_db_init(NULL) != 0) {
    unload_locked();
    return 0;
  }
  global_runtime.directory = directory;
  return 1;
}

static void clear_trust_locked(void) {
  if (global_runtime.trust_certificate != NULL &&
      foxreq_real_api.cert_destroy != NULL) {
    foxreq_real_api.cert_destroy(global_runtime.trust_certificate);
  }
  global_runtime.trust_certificate = NULL;
  free(global_runtime.trust_anchor);
  global_runtime.trust_anchor = NULL;
  global_runtime.trust_anchor_length = 0U;
}

static foxreq_nss_result install_trust_locked(foxreq_nss_slice anchor) {
  foxreq_cert_db_handle *database;
  foxreq_cert_certificate *certificate;
  foxreq_cert_trust trust;
  foxreq_sec_item item;
  uint8_t *copy;
  if (anchor.length == UINT64_C(0)) {
    return FOXREQ_NSS_RESULT_OK;
  }
  if (anchor.length > (uint64_t)UINT_MAX) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  copy = (uint8_t *)malloc((size_t)anchor.length);
  if (copy == NULL) {
    return FOXREQ_NSS_RESULT_OUT_OF_MEMORY;
  }
  memcpy(copy, anchor.data, (size_t)anchor.length);
  database = foxreq_real_api.cert_get_default_db();
  if (database == NULL) {
    free(copy);
    return FOXREQ_NSS_RESULT_CERTIFICATE;
  }
  item.type = 0;
  item.data = (unsigned char *)anchor.data;
  item.length = (unsigned int)anchor.length;
  certificate = foxreq_real_api.cert_new_temp(database, &item, NULL, 0, 1);
  if (certificate == NULL ||
      foxreq_real_api.cert_decode_trust(&trust, "C,,") != 0 ||
      foxreq_real_api.cert_change_trust(database, certificate, &trust) != 0) {
    if (certificate != NULL) {
      foxreq_real_api.cert_destroy(certificate);
    }
    free(copy);
    return FOXREQ_NSS_RESULT_CERTIFICATE;
  }
  global_runtime.trust_anchor = copy;
  global_runtime.trust_anchor_length = (size_t)anchor.length;
  global_runtime.trust_certificate = certificate;
  return FOXREQ_NSS_RESULT_OK;
}

static int trust_matches_locked(foxreq_nss_slice anchor) {
  if (anchor.length != (uint64_t)global_runtime.trust_anchor_length) {
    return 0;
  }
  return anchor.length == UINT64_C(0) ||
         memcmp(anchor.data, global_runtime.trust_anchor,
                (size_t)anchor.length) == 0;
}

static foxreq_nss_result global_acquire(wchar_t *directory,
                                        foxreq_nss_slice trust_anchor) {
  foxreq_nss_result result = FOXREQ_NSS_RESULT_OK;
  AcquireSRWLockExclusive(&global_runtime.lock);
  if (global_runtime.references == UINT32_C(0)) {
    if (global_runtime.nss3 == NULL) {
      if (!load_locked(directory)) {
        result = FOXREQ_NSS_RESULT_TLS;
      } else {
        directory = NULL;
        result = install_trust_locked(trust_anchor);
        if (result == FOXREQ_NSS_RESULT_OK) {
          global_runtime.references = UINT32_C(1);
        } else {
          (void)foxreq_real_api.nss_shutdown();
        }
      }
    } else if (global_runtime.directory == NULL ||
               wcscmp(global_runtime.directory, directory) != 0) {
      result = FOXREQ_NSS_RESULT_STATE;
    } else if (foxreq_real_api.nss_no_db_init == NULL ||
               foxreq_real_api.nss_no_db_init(NULL) != 0) {
      result = FOXREQ_NSS_RESULT_TLS;
    } else {
      result = install_trust_locked(trust_anchor);
      if (result == FOXREQ_NSS_RESULT_OK) {
        global_runtime.references = UINT32_C(1);
      } else {
        (void)foxreq_real_api.nss_shutdown();
      }
    }
  } else if (global_runtime.directory == NULL ||
             wcscmp(global_runtime.directory, directory) != 0) {
    result = FOXREQ_NSS_RESULT_STATE;
  } else if (!trust_matches_locked(trust_anchor)) {
    result = FOXREQ_NSS_RESULT_STATE;
  } else if (global_runtime.references == UINT32_MAX) {
    result = FOXREQ_NSS_RESULT_STATE;
  } else {
    global_runtime.references += UINT32_C(1);
  }
  ReleaseSRWLockExclusive(&global_runtime.lock);
  free(directory);
  return result;
}

static void global_release(void) {
  AcquireSRWLockExclusive(&global_runtime.lock);
  if (global_runtime.references > UINT32_C(0)) {
    global_runtime.references -= UINT32_C(1);
    if (global_runtime.references == UINT32_C(0)) {
      clear_trust_locked();
      if (foxreq_real_api.nss_shutdown != NULL) {
        (void)foxreq_real_api.nss_shutdown();
      }
    }
  }
  ReleaseSRWLockExclusive(&global_runtime.lock);
}

int foxreq_real_runtime_is_valid(const foxreq_nss_runtime *runtime) {
  return runtime != NULL && runtime->magic == FOXREQ_NSS_RUNTIME_MAGIC;
}

int foxreq_real_cache_is_valid(const foxreq_nss_session_cache *cache) {
  return cache != NULL && cache->magic == FOXREQ_NSS_CACHE_MAGIC;
}

int foxreq_real_connection_is_valid(const foxreq_nss_connection *connection) {
  return connection != NULL && connection->magic == FOXREQ_NSS_CONNECTION_MAGIC;
}

void foxreq_real_runtime_retain(foxreq_nss_runtime *runtime) {
  (void)InterlockedIncrement(&runtime->references);
}

void foxreq_real_runtime_release(foxreq_nss_runtime *runtime) {
  if (InterlockedDecrement(&runtime->references) == 0) {
    global_release();
    free(runtime);
  }
}

uint32_t foxreq_nss_abi_version(void) { return FOXREQ_NSS_ABI_VERSION; }

foxreq_nss_result
foxreq_nss_runtime_create(const foxreq_nss_runtime_options *options,
                          foxreq_nss_runtime **out_runtime) {
  foxreq_nss_runtime *runtime;
  wchar_t *directory;
  foxreq_nss_result result;
  if (out_runtime == NULL) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  *out_runtime = NULL;
  if (options == NULL ||
      options->struct_size < (uint32_t)sizeof(*options) ||
      options->abi_version != FOXREQ_NSS_ABI_VERSION ||
      !slice_is_valid(options->runtime_dir, 0) ||
      !slice_is_valid(options->trust_anchor_der, 1)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  directory = utf8_directory(options->runtime_dir);
  if (directory == NULL) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  result = global_acquire(directory, options->trust_anchor_der);
  if (result != FOXREQ_NSS_RESULT_OK) {
    return result;
  }
  runtime = (foxreq_nss_runtime *)calloc(1U, sizeof(*runtime));
  if (runtime == NULL) {
    global_release();
    return FOXREQ_NSS_RESULT_OUT_OF_MEMORY;
  }
  runtime->magic = FOXREQ_NSS_RUNTIME_MAGIC;
  runtime->references = 1;
  *out_runtime = runtime;
  return FOXREQ_NSS_RESULT_OK;
}

void foxreq_nss_runtime_free(foxreq_nss_runtime *runtime) {
  if (!foxreq_real_runtime_is_valid(runtime)) {
    return;
  }
  runtime->magic = UINT32_C(0);
  foxreq_real_runtime_release(runtime);
}

foxreq_nss_result foxreq_nss_runtime_versions(
    foxreq_nss_runtime *runtime, foxreq_nss_buffer **out_nss_version,
    foxreq_nss_buffer **out_nspr_version) {
  const char *nss_version;
  const char *nspr_version;
  foxreq_nss_result result;
  if (!foxreq_real_runtime_is_valid(runtime) || out_nss_version == NULL ||
      out_nspr_version == NULL || foxreq_real_api.nss_get_version == NULL ||
      foxreq_real_api.nspr_get_version == NULL) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  *out_nss_version = NULL;
  *out_nspr_version = NULL;
  nss_version = foxreq_real_api.nss_get_version();
  nspr_version = foxreq_real_api.nspr_get_version();
  if (nss_version == NULL || nspr_version == NULL) {
    return FOXREQ_NSS_RESULT_STATE;
  }
  result = foxreq_real_buffer_create((const uint8_t *)nss_version,
                                     strlen(nss_version), out_nss_version);
  if (result != FOXREQ_NSS_RESULT_OK) {
    return result;
  }
  result = foxreq_real_buffer_create((const uint8_t *)nspr_version,
                                     strlen(nspr_version), out_nspr_version);
  if (result != FOXREQ_NSS_RESULT_OK) {
    foxreq_nss_buffer_free(*out_nss_version);
    *out_nss_version = NULL;
  }
  return result;
}

foxreq_nss_result foxreq_nss_session_cache_create(
    foxreq_nss_runtime *runtime,
    const foxreq_nss_session_cache_options *options,
    foxreq_nss_session_cache **out_cache) {
  foxreq_nss_session_cache *cache;
  if (out_cache == NULL) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  *out_cache = NULL;
  if (!foxreq_real_runtime_is_valid(runtime) || options == NULL ||
      options->struct_size < (uint32_t)sizeof(*options) ||
      options->abi_version != FOXREQ_NSS_ABI_VERSION ||
      options->capacity == UINT32_C(0)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  cache = (foxreq_nss_session_cache *)calloc(1U, sizeof(*cache));
  if (cache == NULL) {
    return FOXREQ_NSS_RESULT_OUT_OF_MEMORY;
  }
  foxreq_real_runtime_retain(runtime);
  cache->magic = FOXREQ_NSS_CACHE_MAGIC;
  cache->capacity = options->capacity;
  cache->runtime = runtime;
  *out_cache = cache;
  return FOXREQ_NSS_RESULT_OK;
}

void foxreq_nss_session_cache_free(foxreq_nss_session_cache *cache) {
  foxreq_nss_runtime *runtime;
  if (!foxreq_real_cache_is_valid(cache)) {
    return;
  }
  cache->magic = UINT32_C(0);
  runtime = cache->runtime;
  free(cache);
  foxreq_real_runtime_release(runtime);
}
