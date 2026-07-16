#include "foxreq_nss_real_internal.h"

#include <limits.h>
#include <string.h>

#define FOXREQ_ARRAY_LENGTH(values) (sizeof(values) / sizeof((values)[0]))
#define FOXREQ_SSL_SECURITY INT32_C(1)
#define FOXREQ_SSL_HANDSHAKE_AS_CLIENT INT32_C(5)
#define FOXREQ_SSL_NO_CACHE INT32_C(9)
#define FOXREQ_SSL_ENABLE_SESSION_TICKETS INT32_C(18)
#define FOXREQ_SSL_ENABLE_OCSP_STAPLING INT32_C(24)
#define FOXREQ_SSL_ENABLE_SIGNED_CERT_TIMESTAMPS INT32_C(31)
#define FOXREQ_SSL_ENABLE_TLS13_COMPAT_MODE INT32_C(35)
#define FOXREQ_SSL_ENABLE_DELEGATED_CREDENTIALS INT32_C(40)
#define FOXREQ_TLS_1_2 UINT16_C(0x0303)
#define FOXREQ_TLS_1_3 UINT16_C(0x0304)

typedef struct foxreq_profile_config {
  const uint16_t *ciphers;
  size_t cipher_count;
} foxreq_profile_config;

static const uint16_t firefox_140_ciphers[] = {
    UINT16_C(0x1301), UINT16_C(0x1303), UINT16_C(0x1302), UINT16_C(0xC02B),
    UINT16_C(0xC02F), UINT16_C(0xCCA9), UINT16_C(0xCCA8), UINT16_C(0xC02C),
    UINT16_C(0xC030), UINT16_C(0xC00A), UINT16_C(0xC009), UINT16_C(0xC013),
    UINT16_C(0xC014), UINT16_C(0x009C), UINT16_C(0x009D), UINT16_C(0x002F),
    UINT16_C(0x0035)};

static const uint16_t firefox_152_ciphers[] = {
    UINT16_C(0x1301), UINT16_C(0x1303), UINT16_C(0x1302), UINT16_C(0xC02B),
    UINT16_C(0xC02F), UINT16_C(0xCCA9), UINT16_C(0xCCA8), UINT16_C(0xC02C),
    UINT16_C(0xC030), UINT16_C(0xC00A), UINT16_C(0xC013), UINT16_C(0xC014),
    UINT16_C(0x009C), UINT16_C(0x009D), UINT16_C(0x002F), UINT16_C(0x0035)};

static const int32_t firefox_signature_schemes[] = {
    INT32_C(0x0403), INT32_C(0x0503), INT32_C(0x0603), INT32_C(0x0804),
    INT32_C(0x0805), INT32_C(0x0806), INT32_C(0x0401), INT32_C(0x0501),
    INT32_C(0x0601), INT32_C(0x0203), INT32_C(0x0201)};

static const int32_t firefox_named_groups[] = {
    INT32_C(4588), INT32_C(29),  INT32_C(23),  INT32_C(24),
    INT32_C(25),   INT32_C(256), INT32_C(257)};

static const foxreq_profile_config *profile_config(foxreq_nss_slice profile) {
  static const uint8_t firefox_140[] = "firefox_140_esr";
  static const uint8_t firefox_152[] = "firefox_152";
  static const foxreq_profile_config config_140 = {
      firefox_140_ciphers, FOXREQ_ARRAY_LENGTH(firefox_140_ciphers)};
  static const foxreq_profile_config config_152 = {
      firefox_152_ciphers, FOXREQ_ARRAY_LENGTH(firefox_152_ciphers)};
  if (profile.data != NULL &&
      profile.length == (uint64_t)(sizeof(firefox_140) - 1U) &&
      memcmp(profile.data, firefox_140, sizeof(firefox_140) - 1U) == 0) {
    return &config_140;
  }
  if (profile.data != NULL &&
      profile.length == (uint64_t)(sizeof(firefox_152) - 1U) &&
      memcmp(profile.data, firefox_152, sizeof(firefox_152) - 1U) == 0) {
    return &config_152;
  }
  return NULL;
}

static int configure_ciphers(foxreq_pr_file_desc *fd,
                             const foxreq_profile_config *config) {
  const uint16_t *implemented =
      foxreq_real_api.ssl_get_implemented_ciphers();
  uint16_t implemented_count =
      foxreq_real_api.ssl_get_num_implemented_ciphers();
  size_t index;
  if (implemented == NULL || implemented_count == UINT16_C(0)) {
    return 0;
  }
  for (index = 0U; index < (size_t)implemented_count; index += 1U) {
    if (foxreq_real_api.ssl_cipher_pref_set(fd, (int32_t)implemented[index],
                                            0) != 0) {
      return 0;
    }
  }
  for (index = 0U; index < config->cipher_count; index += 1U) {
    if (foxreq_real_api.ssl_cipher_pref_set(
            fd, (int32_t)config->ciphers[index], 1) != 0) {
      return 0;
    }
  }
  return 1;
}

static int enable_grease_ech(foxreq_pr_file_desc *fd) {
  union {
    void *data;
    foxreq_ssl_enable_grease_ech_fn function;
  } api;
  api.data = foxreq_real_api.ssl_get_experimental_api(
      "SSL_EnableTls13GreaseEch");
  return api.function != NULL && api.function(fd, 1) == 0;
}

static int configure_certificate_compression(foxreq_pr_file_desc *fd) {
  static const foxreq_ssl_certificate_compression_algorithm algorithms[] = {
      {UINT16_C(1), "zlib", NULL, foxreq_real_decode_zlib_certificate},
      {UINT16_C(2), "brotli", NULL, foxreq_real_decode_brotli_certificate},
      {UINT16_C(3), "zstd", NULL, foxreq_real_decode_zstd_certificate}};
  union {
    void *data;
    foxreq_ssl_set_certificate_compression_fn function;
  } api;
  size_t index;
  api.data = foxreq_real_api.ssl_get_experimental_api(
      "SSL_SetCertificateCompressionAlgorithm");
  if (api.function == NULL) {
    return 0;
  }
  for (index = 0U; index < FOXREQ_ARRAY_LENGTH(algorithms); index += 1U) {
    if (api.function(fd, algorithms[index]) != 0) {
      return 0;
    }
  }
  return 1;
}

foxreq_nss_result foxreq_real_configure_profile(
    foxreq_nss_connection *connection,
    const foxreq_nss_connect_options *options) {
  foxreq_ssl_version_range range;
  const foxreq_profile_config *config;
  if (connection == NULL || connection->fd == NULL || options == NULL ||
      options->alpn_wire.length > (uint64_t)UINT_MAX) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  config = profile_config(options->profile_id);
  if (config == NULL) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  range.minimum = FOXREQ_TLS_1_2;
  range.maximum = FOXREQ_TLS_1_3;
  if (!configure_ciphers(connection->fd, config) ||
      foxreq_real_api.ssl_signature_scheme_pref_set(
          connection->fd, firefox_signature_schemes,
          (unsigned int)FOXREQ_ARRAY_LENGTH(firefox_signature_schemes)) != 0 ||
      foxreq_real_api.ssl_named_group_config(
          connection->fd, firefox_named_groups,
          (unsigned int)FOXREQ_ARRAY_LENGTH(firefox_named_groups)) != 0 ||
      foxreq_real_api.ssl_send_additional_key_shares(connection->fd, 2U) != 0 ||
      !configure_certificate_compression(connection->fd) ||
      !enable_grease_ech(connection->fd) ||
      foxreq_real_api.ssl_option_set(connection->fd, FOXREQ_SSL_SECURITY, 1) !=
          0 ||
      foxreq_real_api.ssl_option_set(connection->fd,
                                     FOXREQ_SSL_HANDSHAKE_AS_CLIENT, 1) != 0 ||
      foxreq_real_api.ssl_option_set(
          connection->fd, FOXREQ_SSL_ENABLE_SESSION_TICKETS, 1) != 0 ||
      foxreq_real_api.ssl_option_set(
          connection->fd, FOXREQ_SSL_ENABLE_TLS13_COMPAT_MODE, 1) != 0 ||
      foxreq_real_api.ssl_option_set(
          connection->fd, FOXREQ_SSL_ENABLE_OCSP_STAPLING, 1) != 0 ||
      foxreq_real_api.ssl_option_set(
          connection->fd, FOXREQ_SSL_ENABLE_SIGNED_CERT_TIMESTAMPS, 1) != 0 ||
      foxreq_real_api.ssl_option_set(
          connection->fd, FOXREQ_SSL_ENABLE_DELEGATED_CREDENTIALS, 1) != 0 ||
      foxreq_real_api.ssl_option_set(connection->fd, FOXREQ_SSL_NO_CACHE,
                                     options->session_cache == NULL) != 0 ||
      foxreq_real_api.ssl_version_range_set(connection->fd, &range) != 0 ||
      foxreq_real_api.ssl_set_next_proto(
          connection->fd, options->alpn_wire.data,
          (unsigned int)options->alpn_wire.length) != 0) {
    return FOXREQ_NSS_RESULT_TLS;
  }
  return FOXREQ_NSS_RESULT_OK;
}
