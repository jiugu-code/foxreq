#ifndef FOXREQ_NSS_H
#define FOXREQ_NSS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FOXREQ_NSS_ABI_VERSION UINT32_C(1)

typedef uint32_t foxreq_nss_result;

#define FOXREQ_NSS_RESULT_OK UINT32_C(0)
#define FOXREQ_NSS_RESULT_INVALID_ARGUMENT UINT32_C(1)
#define FOXREQ_NSS_RESULT_OUT_OF_MEMORY UINT32_C(2)
#define FOXREQ_NSS_RESULT_STATE UINT32_C(3)
#define FOXREQ_NSS_RESULT_IO UINT32_C(4)
#define FOXREQ_NSS_RESULT_TIMEOUT UINT32_C(5)
#define FOXREQ_NSS_RESULT_TLS UINT32_C(6)
#define FOXREQ_NSS_RESULT_CERTIFICATE UINT32_C(7)
#define FOXREQ_NSS_RESULT_UNSUPPORTED UINT32_C(8)
#define FOXREQ_NSS_RESULT_BUFFER_TOO_SMALL UINT32_C(9)
#define FOXREQ_NSS_RESULT_END_OF_STREAM UINT32_C(10)

#define FOXREQ_NSS_VERIFY_DEFAULT UINT32_C(0)
#define FOXREQ_NSS_VERIFY_INSECURE_TEST_ONLY UINT32_C(1)

#define FOXREQ_NSS_STUB_OPERATION_READ UINT32_C(1)
#define FOXREQ_NSS_STUB_OPERATION_WRITE UINT32_C(2)
#define FOXREQ_NSS_STUB_OPERATION_CLOSE UINT32_C(3)

typedef struct foxreq_nss_runtime foxreq_nss_runtime;
typedef struct foxreq_nss_session_cache foxreq_nss_session_cache;
typedef struct foxreq_nss_connection foxreq_nss_connection;
typedef struct foxreq_nss_buffer foxreq_nss_buffer;

typedef struct foxreq_nss_slice {
  const uint8_t *data;
  uint64_t length;
} foxreq_nss_slice;

typedef struct foxreq_nss_runtime_options {
  uint32_t struct_size;
  uint32_t abi_version;
  uint64_t reserved;
  foxreq_nss_slice runtime_dir;
  foxreq_nss_slice trust_anchor_der;
  uint64_t reserved2[2];
} foxreq_nss_runtime_options;

typedef struct foxreq_nss_session_cache_options {
  uint32_t struct_size;
  uint32_t abi_version;
  uint32_t capacity;
  uint32_t reserved;
} foxreq_nss_session_cache_options;

typedef struct foxreq_nss_connect_options {
  uint32_t struct_size;
  uint32_t abi_version;
  foxreq_nss_slice host;
  uint16_t port;
  uint16_t reserved16;
  uint32_t verification_mode;
  uint64_t timeout_millis;
  foxreq_nss_slice profile_id;
  foxreq_nss_slice alpn_wire;
  foxreq_nss_session_cache *session_cache;
  uint64_t reserved[2];
} foxreq_nss_connect_options;

typedef struct foxreq_nss_certificate_result {
  uint32_t struct_size;
  uint32_t abi_version;
  uint32_t verification_performed;
  uint32_t verified;
  uint32_t category;
  int32_t nss_code;
  int32_t nspr_code;
  uint32_t reserved32;
} foxreq_nss_certificate_result;

typedef struct foxreq_nss_error_info {
  uint32_t struct_size;
  uint32_t abi_version;
  uint32_t category;
  uint32_t reserved32;
  int32_t nss_code;
  int32_t nspr_code;
  uint64_t auxiliary;
} foxreq_nss_error_info;

uint32_t foxreq_nss_abi_version(void);

foxreq_nss_result
foxreq_nss_runtime_create(const foxreq_nss_runtime_options *options,
                          foxreq_nss_runtime **out_runtime);
void foxreq_nss_runtime_free(foxreq_nss_runtime *runtime);
foxreq_nss_result foxreq_nss_runtime_versions(
    foxreq_nss_runtime *runtime, foxreq_nss_buffer **out_nss_version,
    foxreq_nss_buffer **out_nspr_version);

foxreq_nss_result foxreq_nss_session_cache_create(
    foxreq_nss_runtime *runtime,
    const foxreq_nss_session_cache_options *options,
    foxreq_nss_session_cache **out_cache);
void foxreq_nss_session_cache_free(foxreq_nss_session_cache *cache);

foxreq_nss_result
foxreq_nss_connect(foxreq_nss_runtime *runtime,
                   const foxreq_nss_connect_options *options,
                   foxreq_nss_connection **out_connection);
/* A failed connect may return a diagnostic connection. The caller must free
 * every non-NULL connection regardless of the result code. */
void foxreq_nss_connection_free(foxreq_nss_connection *connection);

foxreq_nss_result foxreq_nss_connection_negotiated_alpn(
    foxreq_nss_connection *connection, foxreq_nss_buffer **out_buffer);
foxreq_nss_result foxreq_nss_connection_certificate_result(
    foxreq_nss_connection *connection,
    foxreq_nss_certificate_result *out_result);
foxreq_nss_result foxreq_nss_connection_read(
    foxreq_nss_connection *connection, uint8_t *destination, uint64_t capacity,
    uint64_t timeout_millis, uint64_t *out_read);
foxreq_nss_result foxreq_nss_connection_write(
    foxreq_nss_connection *connection, const uint8_t *source, uint64_t length,
    uint64_t timeout_millis, uint64_t *out_written);
foxreq_nss_result foxreq_nss_connection_close(
    foxreq_nss_connection *connection, uint64_t timeout_millis);
foxreq_nss_result foxreq_nss_connection_last_error(
    foxreq_nss_connection *connection, foxreq_nss_error_info *out_error,
    char *message, uint64_t message_capacity, uint64_t *out_required);

foxreq_nss_result foxreq_nss_buffer_view(const foxreq_nss_buffer *buffer,
                                         const uint8_t **out_data,
                                         uint64_t *out_length);
void foxreq_nss_buffer_free(foxreq_nss_buffer *buffer);

#if defined(FOXREQ_NSS_STUB)
foxreq_nss_result foxreq_nss_stub_set_read_data(
    foxreq_nss_connection *connection, const uint8_t *data, uint64_t length);
foxreq_nss_result foxreq_nss_stub_set_io_limits(
    foxreq_nss_connection *connection, uint64_t read_limit,
    uint64_t write_limit);
foxreq_nss_result foxreq_nss_stub_fail_next(
    foxreq_nss_connection *connection, uint32_t operation,
    foxreq_nss_result category, int32_t nss_code, int32_t nspr_code,
    const uint8_t *message, uint64_t message_length);
foxreq_nss_result foxreq_nss_stub_written_data(
    foxreq_nss_connection *connection, foxreq_nss_buffer **out_buffer);
foxreq_nss_result foxreq_nss_stub_close_calls(
    foxreq_nss_connection *connection, uint32_t *out_calls);
foxreq_nss_result foxreq_nss_stub_live_counts(
    uint32_t *out_runtimes, uint32_t *out_connections,
    uint32_t *out_session_caches, uint32_t *out_buffers);
#endif

#ifdef __cplusplus
}
#endif

#endif
