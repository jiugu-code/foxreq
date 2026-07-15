#include "foxreq_nss_real_internal.h"

#include <assert.h>
#include <string.h>

#define ARRAY_LENGTH(values) (sizeof(values) / sizeof((values)[0]))

static const uint16_t implemented_ciphers[] = {UINT16_C(0x0001),
                                                UINT16_C(0x0002),
                                                UINT16_C(0x0003)};
static const uint16_t firefox_ciphers[] = {
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

static size_t disabled_cipher_count;
static uint16_t enabled_ciphers[32];
static size_t enabled_cipher_count;
static int32_t signature_schemes[32];
static size_t signature_scheme_count;
static int32_t named_groups[32];
static size_t named_group_count;
static unsigned int additional_key_shares;
static int grease_ech_enabled;
static uint16_t certificate_compression_ids[3];
static size_t certificate_compression_count;
static int option_values[64];

static const uint16_t *__cdecl mock_get_implemented_ciphers(void) {
  return implemented_ciphers;
}

static uint16_t __cdecl mock_get_num_implemented_ciphers(void) {
  return (uint16_t)ARRAY_LENGTH(implemented_ciphers);
}

static int __cdecl mock_cipher_pref_set(foxreq_pr_file_desc *fd,
                                        int32_t cipher, int enabled) {
  assert(fd != NULL);
  if (enabled) {
    assert(enabled_cipher_count < ARRAY_LENGTH(enabled_ciphers));
    enabled_ciphers[enabled_cipher_count++] = (uint16_t)cipher;
  } else {
    disabled_cipher_count += 1U;
  }
  return 0;
}

static int __cdecl mock_signature_scheme_pref_set(
    foxreq_pr_file_desc *fd, const int32_t *schemes, unsigned int count) {
  assert(fd != NULL);
  assert(count <= ARRAY_LENGTH(signature_schemes));
  memcpy(signature_schemes, schemes, count * sizeof(*schemes));
  signature_scheme_count = count;
  return 0;
}

static int __cdecl mock_named_group_config(foxreq_pr_file_desc *fd,
                                           const int32_t *groups,
                                           unsigned int count) {
  assert(fd != NULL);
  assert(count <= ARRAY_LENGTH(named_groups));
  memcpy(named_groups, groups, count * sizeof(*groups));
  named_group_count = count;
  return 0;
}

static int __cdecl mock_send_additional_key_shares(foxreq_pr_file_desc *fd,
                                                    unsigned int count) {
  assert(fd != NULL);
  additional_key_shares = count;
  return 0;
}

static int __cdecl mock_enable_grease_ech(foxreq_pr_file_desc *fd,
                                          int enabled) {
  assert(fd != NULL);
  grease_ech_enabled = enabled;
  return 0;
}

static int __cdecl mock_set_certificate_compression(
    foxreq_pr_file_desc *fd,
    foxreq_ssl_certificate_compression_algorithm algorithm) {
  static const char *names[] = {"zlib", "brotli", "zstd"};
  assert(fd != NULL);
  assert(certificate_compression_count < ARRAY_LENGTH(names));
  assert(algorithm.id == certificate_compression_count + 1U);
  assert(strcmp(algorithm.name, names[certificate_compression_count]) == 0);
  assert(algorithm.encode == NULL);
  assert(algorithm.decode != NULL);
  certificate_compression_ids[certificate_compression_count++] = algorithm.id;
  return 0;
}

static void *__cdecl mock_get_experimental_api(const char *name) {
  if (strcmp(name, "SSL_EnableTls13GreaseEch") == 0) {
    return (void *)mock_enable_grease_ech;
  }
  assert(strcmp(name, "SSL_SetCertificateCompressionAlgorithm") == 0);
  return (void *)mock_set_certificate_compression;
}

static int __cdecl mock_option_set(foxreq_pr_file_desc *fd, int32_t option,
                                   int enabled) {
  assert(fd != NULL);
  assert(option >= 0 && option < (int32_t)ARRAY_LENGTH(option_values));
  option_values[option] = enabled ? 1 : -1;
  return 0;
}

static int __cdecl mock_version_range_set(
    foxreq_pr_file_desc *fd, const foxreq_ssl_version_range *range) {
  assert(fd != NULL);
  assert(range->minimum == UINT16_C(0x0303));
  assert(range->maximum == UINT16_C(0x0304));
  return 0;
}

static int __cdecl mock_set_next_proto(foxreq_pr_file_desc *fd,
                                       const uint8_t *data,
                                       unsigned int length) {
  static const uint8_t expected[] = {UINT8_C(8), 'h', 't', 't', 'p', '/', '1',
                                     '.', '1'};
  assert(fd != NULL);
  assert(length == ARRAY_LENGTH(expected));
  assert(memcmp(data, expected, sizeof(expected)) == 0);
  return 0;
}

int main(void) {
  static const uint8_t alpn[] = {UINT8_C(8), 'h', 't', 't', 'p', '/', '1', '.',
                                 '1'};
  foxreq_nss_connection connection = {0};
  foxreq_nss_connect_options options = {0};

  connection.fd = (foxreq_pr_file_desc *)(uintptr_t)1U;
  options.alpn_wire.data = alpn;
  options.alpn_wire.length = sizeof(alpn);

  foxreq_real_api.ssl_get_implemented_ciphers = mock_get_implemented_ciphers;
  foxreq_real_api.ssl_get_num_implemented_ciphers =
      mock_get_num_implemented_ciphers;
  foxreq_real_api.ssl_cipher_pref_set = mock_cipher_pref_set;
  foxreq_real_api.ssl_signature_scheme_pref_set =
      mock_signature_scheme_pref_set;
  foxreq_real_api.ssl_named_group_config = mock_named_group_config;
  foxreq_real_api.ssl_send_additional_key_shares =
      mock_send_additional_key_shares;
  foxreq_real_api.ssl_get_experimental_api = mock_get_experimental_api;
  foxreq_real_api.ssl_option_set = mock_option_set;
  foxreq_real_api.ssl_version_range_set = mock_version_range_set;
  foxreq_real_api.ssl_set_next_proto = mock_set_next_proto;

  assert(foxreq_real_configure_profile(&connection, &options) ==
         FOXREQ_NSS_RESULT_OK);
  assert(disabled_cipher_count == ARRAY_LENGTH(implemented_ciphers));
  assert(enabled_cipher_count == ARRAY_LENGTH(firefox_ciphers));
  assert(memcmp(enabled_ciphers, firefox_ciphers, sizeof(firefox_ciphers)) == 0);
  assert(signature_scheme_count == ARRAY_LENGTH(firefox_signature_schemes));
  assert(memcmp(signature_schemes, firefox_signature_schemes,
                sizeof(firefox_signature_schemes)) == 0);
  assert(named_group_count == ARRAY_LENGTH(firefox_named_groups));
  assert(memcmp(named_groups, firefox_named_groups,
                sizeof(firefox_named_groups)) == 0);
  assert(additional_key_shares == 2U);
  assert(grease_ech_enabled == 1);
  assert(certificate_compression_count == 3U);
  assert(certificate_compression_ids[0] == UINT16_C(1));
  assert(certificate_compression_ids[1] == UINT16_C(2));
  assert(certificate_compression_ids[2] == UINT16_C(3));
  assert(option_values[1] == 1);
  assert(option_values[5] == 1);
  assert(option_values[9] == 1);
  assert(option_values[18] == 1);
  assert(option_values[24] == 1);
  assert(option_values[31] == 1);
  assert(option_values[35] == 1);
  assert(option_values[40] == 1);
  assert(option_values[43] == 0);
  return 0;
}
