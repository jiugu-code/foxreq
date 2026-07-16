#include "foxreq_nss_real_internal.h"

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
  const char *profile_id;
  int winsock_started;
  uint8_t *trust_bundle;
  size_t trust_bundle_length;
  foxreq_cert_certificate **trust_certificates;
  size_t trust_certificate_count;
} foxreq_global_runtime;

static foxreq_global_runtime global_runtime = {SRWLOCK_INIT,
                                               0U,
                                               NULL,
                                               NULL,
                                               NULL,
                                               NULL,
                                               NULL,
                                               NULL,
                                               0,
                                               NULL,
                                               0U,
                                               NULL,
                                               0U};
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

static int slice_equals(foxreq_nss_slice slice, const char *expected) {
  size_t length = strlen(expected);
  return slice.length == (uint64_t)length && slice.data != NULL &&
         memcmp(slice.data, expected, length) == 0;
}

static const char *runtime_profile_id(foxreq_nss_slice profile) {
  if (slice_equals(profile, "firefox_140_esr")) {
    return "firefox_140_esr";
  }
  if (slice_equals(profile, "firefox_152")) {
    return "firefox_152";
  }
  return NULL;
}

static uint32_t runtime_profile_value(const char *profile_id) {
  if (profile_id != NULL && strcmp(profile_id, "firefox_140_esr") == 0) {
    return FOXREQ_NSS_PROFILE_140;
  }
  if (profile_id != NULL && strcmp(profile_id, "firefox_152") == 0) {
    return FOXREQ_NSS_PROFILE_152;
  }
  return UINT32_C(0);
}

static int profile_versions(const char *profile_id, const char **out_nss,
                            const char **out_nspr) {
  if (profile_id == NULL || out_nss == NULL || out_nspr == NULL) {
    return 0;
  }
  if (strcmp(profile_id, "firefox_140_esr") == 0) {
    *out_nss = "3.112.5";
    *out_nspr = "4.36.2";
    return 1;
  }
  if (strcmp(profile_id, "firefox_152") == 0) {
    *out_nss = "3.124";
    *out_nspr = "4.39";
    return 1;
  }
  return 0;
}

static int trust_bundle_is_valid(foxreq_nss_slice bundle,
                                 size_t *out_count) {
  size_t count = 0U;
  size_t offset = 0U;
  size_t length;
  if (out_count == NULL || !slice_is_valid(bundle, 1)) {
    return 0;
  }
  if (bundle.length == UINT64_C(0)) {
    *out_count = 0U;
    return 1;
  }
  length = (size_t)bundle.length;
  while (offset < length) {
    uint32_t item_length;
    if (length - offset < 4U) {
      return 0;
    }
    item_length = ((uint32_t)bundle.data[offset] << 24U) |
                  ((uint32_t)bundle.data[offset + 1U] << 16U) |
                  ((uint32_t)bundle.data[offset + 2U] << 8U) |
                  (uint32_t)bundle.data[offset + 3U];
    offset += 4U;
    if (item_length == UINT32_C(0) || (size_t)item_length > length - offset ||
        count == SIZE_MAX) {
      return 0;
    }
    offset += (size_t)item_length;
    count += 1U;
  }
  *out_count = count;
  return offset == length;
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
  global_runtime.profile_id = NULL;
}

static int load_locked(wchar_t *directory, const char *profile_id) {
  const char *nss_version;
  const char *nspr_version;
  const char *expected_nss;
  const char *expected_nspr;
  WSADATA winsock;
  if (!profile_versions(profile_id, &expected_nss, &expected_nspr)) {
    return 0;
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
  foxreq_real_api.ssl_get_implemented_ciphers =
      (foxreq_ssl_get_implemented_ciphers_fn)require_symbol(
          global_runtime.nss3, "SSL_GetImplementedCiphers");
  foxreq_real_api.ssl_get_num_implemented_ciphers =
      (foxreq_ssl_get_num_implemented_ciphers_fn)require_symbol(
          global_runtime.nss3, "SSL_GetNumImplementedCiphers");
  foxreq_real_api.ssl_cipher_pref_set =
      (foxreq_ssl_cipher_pref_set_fn)require_symbol(global_runtime.nss3,
                                                    "SSL_CipherPrefSet");
  foxreq_real_api.ssl_signature_scheme_pref_set =
      (foxreq_ssl_signature_scheme_pref_set_fn)require_symbol(
          global_runtime.nss3, "SSL_SignatureSchemePrefSet");
  foxreq_real_api.ssl_named_group_config =
      (foxreq_ssl_named_group_config_fn)require_symbol(
          global_runtime.nss3, "SSL_NamedGroupConfig");
  foxreq_real_api.ssl_send_additional_key_shares =
      (foxreq_ssl_send_additional_key_shares_fn)require_symbol(
          global_runtime.nss3, "SSL_SendAdditionalKeyShares");
  foxreq_real_api.ssl_get_experimental_api =
      (foxreq_ssl_get_experimental_api_fn)require_symbol(
          global_runtime.nss3, "SSL_GetExperimentalAPI");
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
      foxreq_real_api.ssl_get_implemented_ciphers == NULL ||
      foxreq_real_api.ssl_get_num_implemented_ciphers == NULL ||
      foxreq_real_api.ssl_cipher_pref_set == NULL ||
      foxreq_real_api.ssl_signature_scheme_pref_set == NULL ||
      foxreq_real_api.ssl_named_group_config == NULL ||
      foxreq_real_api.ssl_send_additional_key_shares == NULL ||
      foxreq_real_api.ssl_get_experimental_api == NULL ||
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
      strcmp(nss_version, expected_nss) != 0 ||
      strcmp(nspr_version, expected_nspr) != 0 ||
      foxreq_real_api.nss_no_db_init(NULL) != 0) {
    unload_locked();
    return 0;
  }
  global_runtime.directory = directory;
  global_runtime.profile_id = profile_id;
  return 1;
}

static void clear_trust_locked(void) {
  size_t index;
  if (global_runtime.trust_certificates != NULL &&
      foxreq_real_api.cert_destroy != NULL) {
    for (index = 0U; index < global_runtime.trust_certificate_count; index++) {
      if (global_runtime.trust_certificates[index] != NULL) {
        foxreq_real_api.cert_destroy(global_runtime.trust_certificates[index]);
      }
    }
  }
  free(global_runtime.trust_certificates);
  global_runtime.trust_certificates = NULL;
  global_runtime.trust_certificate_count = 0U;
  free(global_runtime.trust_bundle);
  global_runtime.trust_bundle = NULL;
  global_runtime.trust_bundle_length = 0U;
}

static foxreq_nss_result install_trust_locked(foxreq_nss_slice bundle) {
  foxreq_cert_db_handle *database;
  foxreq_cert_certificate **certificates = NULL;
  foxreq_cert_trust trust;
  uint8_t *copy = NULL;
  size_t count = 0U;
  size_t index = 0U;
  size_t offset = 0U;
  if (!trust_bundle_is_valid(bundle, &count)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  if (count == 0U) {
    return FOXREQ_NSS_RESULT_OK;
  }
  copy = (uint8_t *)malloc((size_t)bundle.length);
  certificates = (foxreq_cert_certificate **)calloc(count, sizeof(*certificates));
  if (copy == NULL || certificates == NULL) {
    free(certificates);
    free(copy);
    return FOXREQ_NSS_RESULT_OUT_OF_MEMORY;
  }
  memcpy(copy, bundle.data, (size_t)bundle.length);
  database = foxreq_real_api.cert_get_default_db();
  if (database == NULL) {
    free(certificates);
    free(copy);
    return FOXREQ_NSS_RESULT_CERTIFICATE;
  }
  if (foxreq_real_api.cert_decode_trust(&trust, "C,,") != 0) {
    free(certificates);
    free(copy);
    return FOXREQ_NSS_RESULT_CERTIFICATE;
  }
  while (index < count) {
    foxreq_sec_item item;
    uint32_t item_length = ((uint32_t)bundle.data[offset] << 24U) |
                           ((uint32_t)bundle.data[offset + 1U] << 16U) |
                           ((uint32_t)bundle.data[offset + 2U] << 8U) |
                           (uint32_t)bundle.data[offset + 3U];
    offset += 4U;
    item.type = 0;
    item.data = (unsigned char *)(bundle.data + offset);
    item.length = (unsigned int)item_length;
    certificates[index] =
        foxreq_real_api.cert_new_temp(database, &item, NULL, 0, 1);
    if (certificates[index] == NULL ||
        foxreq_real_api.cert_change_trust(database, certificates[index],
                                          &trust) != 0) {
      size_t cleanup_index;
      for (cleanup_index = 0U; cleanup_index <= index; cleanup_index++) {
        if (certificates[cleanup_index] != NULL) {
          foxreq_real_api.cert_destroy(certificates[cleanup_index]);
        }
      }
      free(certificates);
      free(copy);
      return FOXREQ_NSS_RESULT_CERTIFICATE;
    }
    offset += (size_t)item_length;
    index += 1U;
  }
  global_runtime.trust_bundle = copy;
  global_runtime.trust_bundle_length = (size_t)bundle.length;
  global_runtime.trust_certificates = certificates;
  global_runtime.trust_certificate_count = count;
  return FOXREQ_NSS_RESULT_OK;
}

static int trust_matches_locked(foxreq_nss_slice bundle) {
  if (bundle.length != (uint64_t)global_runtime.trust_bundle_length) {
    return 0;
  }
  return bundle.length == UINT64_C(0) ||
         memcmp(bundle.data, global_runtime.trust_bundle,
                (size_t)bundle.length) == 0;
}

static foxreq_nss_result global_acquire(wchar_t *directory,
                                        foxreq_nss_slice trust_bundle,
                                        const char *profile_id) {
  foxreq_nss_result result = FOXREQ_NSS_RESULT_OK;
  AcquireSRWLockExclusive(&global_runtime.lock);
  if (global_runtime.references == UINT32_C(0)) {
    if (global_runtime.nss3 == NULL) {
      if (!load_locked(directory, profile_id)) {
        result = FOXREQ_NSS_RESULT_TLS;
      } else {
        directory = NULL;
        result = install_trust_locked(trust_bundle);
        if (result == FOXREQ_NSS_RESULT_OK) {
          global_runtime.references = UINT32_C(1);
        }
      }
    } else if (global_runtime.directory == NULL ||
               global_runtime.profile_id == NULL ||
               strcmp(global_runtime.profile_id, profile_id) != 0 ||
               wcscmp(global_runtime.directory, directory) != 0) {
      result = FOXREQ_NSS_RESULT_STATE;
    } else {
      result = install_trust_locked(trust_bundle);
      if (result == FOXREQ_NSS_RESULT_OK) {
        global_runtime.references = UINT32_C(1);
      }
    }
  } else if (global_runtime.directory == NULL ||
             global_runtime.profile_id == NULL ||
             strcmp(global_runtime.profile_id, profile_id) != 0 ||
             wcscmp(global_runtime.directory, directory) != 0) {
    result = FOXREQ_NSS_RESULT_STATE;
  } else if (!trust_matches_locked(trust_bundle)) {
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
      /* Firefox NSS cannot be reliably shut down and reinitialized after a
       * completed TLS connection. Keep the profile-verified runtime
       * initialized for the process lifetime while releasing all temporary
       * trust certificates at the final active Session boundary. */
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
  const char *profile_id;
  foxreq_nss_result result;
  if (out_runtime == NULL) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  *out_runtime = NULL;
  if (options == NULL ||
      options->struct_size < (uint32_t)sizeof(*options) ||
      options->abi_version != FOXREQ_NSS_ABI_VERSION ||
      !slice_is_valid(options->runtime_dir, 0) ||
      !slice_is_valid(options->trust_anchors_der, 1) ||
      (profile_id = runtime_profile_id(options->profile_id)) == NULL) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  directory = utf8_directory(options->runtime_dir);
  if (directory == NULL) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  result = global_acquire(directory, options->trust_anchors_der, profile_id);
  if (result != FOXREQ_NSS_RESULT_OK) {
    return result;
  }
  runtime = (foxreq_nss_runtime *)calloc(1U, sizeof(*runtime));
  if (runtime == NULL) {
    global_release();
    return FOXREQ_NSS_RESULT_OUT_OF_MEMORY;
  }
  runtime->magic = FOXREQ_NSS_RUNTIME_MAGIC;
  runtime->profile = runtime_profile_value(profile_id);
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
