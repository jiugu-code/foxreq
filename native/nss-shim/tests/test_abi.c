#include "foxreq_nss.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expression)                                                      \
  do {                                                                         \
    if (!(expression)) {                                                       \
      fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #expression); \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static foxreq_nss_connect_options connect_options(void) {
  static const uint8_t host[] = "example.test";
  static const uint8_t profile[] = "firefox_152";
  static const uint8_t alpn[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
  foxreq_nss_connect_options options;

  memset(&options, 0, sizeof(options));
  options.struct_size = (uint32_t)sizeof(options);
  options.abi_version = FOXREQ_NSS_ABI_VERSION;
  options.host.data = host;
  options.host.length = (uint64_t)(sizeof(host) - 1U);
  options.port = UINT16_C(443);
  options.timeout_millis = UINT64_C(1000);
  options.profile_id.data = profile;
  options.profile_id.length = (uint64_t)(sizeof(profile) - 1U);
  options.alpn_wire.data = alpn;
  options.alpn_wire.length = (uint64_t)sizeof(alpn);
  options.verification_mode = FOXREQ_NSS_VERIFY_DEFAULT;
  return options;
}

int main(void) {
  foxreq_nss_runtime_options runtime_options;
  foxreq_nss_session_cache_options cache_options;
  foxreq_nss_connect_options options;
  foxreq_nss_runtime *runtime = NULL;
  foxreq_nss_session_cache *cache = NULL;
  foxreq_nss_connection *connection = NULL;
  foxreq_nss_buffer *buffer = NULL;
  foxreq_nss_certificate_result certificate;
  foxreq_nss_error_info error;
  const uint8_t *view = NULL;
  uint64_t length = UINT64_C(0);
  uint64_t transferred = UINT64_C(0);
  uint64_t required = UINT64_C(0);
  uint32_t close_calls = UINT32_C(0);
  uint8_t io_buffer[16];
  char message[64];
  char second_message[64];
  static const uint8_t read_data[] = "abcdef";
  static const uint8_t write_data[] = "abcde";
  static const uint8_t expected_alpn[] = "http/1.1";
  static const uint8_t injected_message[] = "scripted read failure";

  CHECK(foxreq_nss_abi_version() == FOXREQ_NSS_ABI_VERSION);
  CHECK(foxreq_nss_runtime_create(NULL, &runtime) ==
        FOXREQ_NSS_RESULT_INVALID_ARGUMENT);
  CHECK(foxreq_nss_runtime_create(&runtime_options, NULL) ==
        FOXREQ_NSS_RESULT_INVALID_ARGUMENT);
  foxreq_nss_runtime_free(NULL);
  foxreq_nss_connection_free(NULL);
  foxreq_nss_session_cache_free(NULL);
  foxreq_nss_buffer_free(NULL);

  memset(&runtime_options, 0, sizeof(runtime_options));
  runtime_options.struct_size = (uint32_t)sizeof(runtime_options);
  runtime_options.abi_version = FOXREQ_NSS_ABI_VERSION;
  CHECK(foxreq_nss_runtime_create(&runtime_options, &runtime) ==
        FOXREQ_NSS_RESULT_OK);
  CHECK(runtime != NULL);

  memset(&cache_options, 0, sizeof(cache_options));
  cache_options.struct_size = (uint32_t)sizeof(cache_options);
  cache_options.abi_version = FOXREQ_NSS_ABI_VERSION;
  cache_options.capacity = UINT32_C(32);
  CHECK(foxreq_nss_session_cache_create(runtime, &cache_options, &cache) ==
        FOXREQ_NSS_RESULT_OK);

  options = connect_options();
  options.session_cache = cache;
  CHECK(foxreq_nss_connect(runtime, &options, &connection) ==
        FOXREQ_NSS_RESULT_OK);
  CHECK(connection != NULL);

  CHECK(foxreq_nss_connection_negotiated_alpn(connection, &buffer) ==
        FOXREQ_NSS_RESULT_OK);
  CHECK(foxreq_nss_buffer_view(buffer, &view, &length) == FOXREQ_NSS_RESULT_OK);
  CHECK(length == (uint64_t)(sizeof(expected_alpn) - 1U));
  CHECK(memcmp(view, expected_alpn, (size_t)length) == 0);
  foxreq_nss_buffer_free(buffer);
  buffer = NULL;

  memset(&certificate, 0, sizeof(certificate));
  certificate.struct_size = (uint32_t)sizeof(certificate);
  certificate.abi_version = FOXREQ_NSS_ABI_VERSION;
  CHECK(foxreq_nss_connection_certificate_result(connection, &certificate) ==
        FOXREQ_NSS_RESULT_OK);
  CHECK(certificate.verification_performed == UINT32_C(1));
  CHECK(certificate.verified == UINT32_C(1));

  CHECK(foxreq_nss_connection_read(connection, NULL, UINT64_C(0),
                                   UINT64_C(1000), &transferred) ==
        FOXREQ_NSS_RESULT_OK);
  CHECK(transferred == UINT64_C(0));
  CHECK(foxreq_nss_connection_write(connection, NULL, UINT64_C(0),
                                    UINT64_C(1000), &transferred) ==
        FOXREQ_NSS_RESULT_OK);
  CHECK(transferred == UINT64_C(0));

  CHECK(foxreq_nss_stub_set_read_data(connection, read_data,
                                      (uint64_t)(sizeof(read_data) - 1U)) ==
        FOXREQ_NSS_RESULT_OK);
  CHECK(foxreq_nss_stub_set_io_limits(connection, UINT64_C(2), UINT64_C(3)) ==
        FOXREQ_NSS_RESULT_OK);
  CHECK(foxreq_nss_connection_read(connection, io_buffer,
                                   (uint64_t)sizeof(io_buffer), UINT64_C(1000),
                                   &transferred) == FOXREQ_NSS_RESULT_OK);
  CHECK(transferred == UINT64_C(2));
  CHECK(memcmp(io_buffer, "ab", 2U) == 0);
  CHECK(foxreq_nss_connection_write(connection, write_data,
                                    (uint64_t)sizeof(write_data),
                                    UINT64_C(1000), &transferred) ==
        FOXREQ_NSS_RESULT_OK);
  CHECK(transferred == UINT64_C(3));
  CHECK(foxreq_nss_stub_written_data(connection, &buffer) ==
        FOXREQ_NSS_RESULT_OK);
  CHECK(foxreq_nss_buffer_view(buffer, &view, &length) == FOXREQ_NSS_RESULT_OK);
  CHECK(length == UINT64_C(3));
  CHECK(memcmp(view, "abc", 3U) == 0);
  foxreq_nss_buffer_free(buffer);
  buffer = NULL;

  CHECK(foxreq_nss_stub_fail_next(
            connection, FOXREQ_NSS_STUB_OPERATION_READ, FOXREQ_NSS_RESULT_IO,
            INT32_C(-12276), INT32_C(-5990), injected_message,
            (uint64_t)(sizeof(injected_message) - 1U)) == FOXREQ_NSS_RESULT_OK);
  CHECK(foxreq_nss_connection_read(connection, io_buffer,
                                   (uint64_t)sizeof(io_buffer), UINT64_C(1000),
                                   &transferred) == FOXREQ_NSS_RESULT_IO);

  memset(&error, 0, sizeof(error));
  error.struct_size = (uint32_t)sizeof(error);
  error.abi_version = FOXREQ_NSS_ABI_VERSION;
  CHECK(foxreq_nss_connection_last_error(connection, &error, NULL,
                                         UINT64_C(0), &required) ==
        FOXREQ_NSS_RESULT_BUFFER_TOO_SMALL);
  CHECK(required == (uint64_t)sizeof(injected_message));
  CHECK(error.category == FOXREQ_NSS_RESULT_IO);
  CHECK(error.nss_code == INT32_C(-12276));
  CHECK(error.nspr_code == INT32_C(-5990));
  CHECK(foxreq_nss_connection_last_error(
            connection, &error, message, (uint64_t)sizeof(message),
            &required) == FOXREQ_NSS_RESULT_OK);
  CHECK(strcmp(message, (const char *)injected_message) == 0);
  message[0] = 'X';
  CHECK(foxreq_nss_connection_last_error(
            connection, &error, second_message, (uint64_t)sizeof(second_message),
            &required) == FOXREQ_NSS_RESULT_OK);
  CHECK(strcmp(second_message, (const char *)injected_message) == 0);

  CHECK(foxreq_nss_connection_close(connection, UINT64_C(1000)) ==
        FOXREQ_NSS_RESULT_OK);
  CHECK(foxreq_nss_stub_close_calls(connection, &close_calls) ==
        FOXREQ_NSS_RESULT_OK);
  CHECK(close_calls == UINT32_C(1));

  foxreq_nss_connection_free(connection);
  foxreq_nss_session_cache_free(cache);
  foxreq_nss_runtime_free(runtime);
  return 0;
}
