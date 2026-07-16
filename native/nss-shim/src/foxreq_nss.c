#include "foxreq_nss_internal.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static uint32_t live_runtimes = UINT32_C(0);
static uint32_t live_connections = UINT32_C(0);
static uint32_t live_session_caches = UINT32_C(0);
static uint32_t live_buffers = UINT32_C(0);

static int runtime_is_valid(const foxreq_nss_runtime *runtime) {
  return runtime != NULL && runtime->magic == FOXREQ_NSS_RUNTIME_MAGIC;
}

static int cache_is_valid(const foxreq_nss_session_cache *cache) {
  return cache != NULL && cache->magic == FOXREQ_NSS_CACHE_MAGIC;
}

static int connection_is_valid(const foxreq_nss_connection *connection) {
  return connection != NULL &&
         connection->magic == FOXREQ_NSS_CONNECTION_MAGIC;
}

static int buffer_is_valid(const foxreq_nss_buffer *buffer) {
  return buffer != NULL && buffer->magic == FOXREQ_NSS_BUFFER_MAGIC;
}

static int slice_is_valid(foxreq_nss_slice slice, int allow_empty) {
  if (slice.length > (uint64_t)SIZE_MAX) {
    return 0;
  }
  if (slice.length == UINT64_C(0)) {
    return allow_empty;
  }
  return slice.data != NULL;
}

static uint32_t runtime_profile_value(foxreq_nss_slice profile) {
  static const uint8_t firefox_140[] = "firefox_140_esr";
  static const uint8_t firefox_152[] = "firefox_152";
  if (profile.length == (uint64_t)(sizeof(firefox_140) - 1U) &&
      profile.data != NULL &&
      memcmp(profile.data, firefox_140, sizeof(firefox_140) - 1U) == 0) {
    return FOXREQ_NSS_PROFILE_140;
  }
  if (profile.length == (uint64_t)(sizeof(firefox_152) - 1U) &&
      profile.data != NULL &&
      memcmp(profile.data, firefox_152, sizeof(firefox_152) - 1U) == 0) {
    return FOXREQ_NSS_PROFILE_152;
  }
  return UINT32_C(0);
}

static int result_is_valid(foxreq_nss_result result) {
  return result <= FOXREQ_NSS_RESULT_END_OF_STREAM;
}

static void set_last_error_bytes(foxreq_nss_connection *connection,
                                 foxreq_nss_result category, int32_t nss_code,
                                 int32_t nspr_code, const uint8_t *message,
                                 size_t message_length) {
  size_t copied = message_length;
  if (copied >= FOXREQ_NSS_ERROR_MESSAGE_CAPACITY) {
    copied = FOXREQ_NSS_ERROR_MESSAGE_CAPACITY - 1U;
  }
  connection->last_category = category;
  connection->last_nss_code = nss_code;
  connection->last_nspr_code = nspr_code;
  if (copied > 0U) {
    memcpy(connection->last_message, message, copied);
  }
  connection->last_message[copied] = '\0';
}

static void set_last_error_text(foxreq_nss_connection *connection,
                                foxreq_nss_result category,
                                const char *message) {
  set_last_error_bytes(connection, category, INT32_C(0), INT32_C(0),
                       (const uint8_t *)message, strlen(message));
}

static foxreq_nss_result require_open(foxreq_nss_connection *connection) {
  if (!connection_is_valid(connection)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  if (connection->closed != UINT32_C(0)) {
    set_last_error_text(connection, FOXREQ_NSS_RESULT_STATE,
                        "connection is closed");
    return FOXREQ_NSS_RESULT_STATE;
  }
  return FOXREQ_NSS_RESULT_OK;
}

static int consume_pending_failure(foxreq_nss_connection *connection,
                                   uint32_t operation,
                                   foxreq_nss_result *out_result) {
  if (connection->pending_operation != operation) {
    return 0;
  }
  set_last_error_bytes(
      connection, connection->pending_category, connection->pending_nss_code,
      connection->pending_nspr_code,
      (const uint8_t *)connection->pending_message,
      strlen(connection->pending_message));
  *out_result = connection->pending_category;
  connection->pending_operation = UINT32_C(0);
  return 1;
}

static foxreq_nss_result buffer_create(const uint8_t *data, size_t length,
                                       foxreq_nss_buffer **out_buffer) {
  foxreq_nss_buffer *buffer;
  if (out_buffer == NULL || (length > 0U && data == NULL)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  *out_buffer = NULL;
  buffer = (foxreq_nss_buffer *)calloc(1U, sizeof(*buffer));
  if (buffer == NULL) {
    return FOXREQ_NSS_RESULT_OUT_OF_MEMORY;
  }
  if (length > 0U) {
    buffer->data = (uint8_t *)malloc(length);
    if (buffer->data == NULL) {
      free(buffer);
      return FOXREQ_NSS_RESULT_OUT_OF_MEMORY;
    }
    memcpy(buffer->data, data, length);
  }
  buffer->magic = FOXREQ_NSS_BUFFER_MAGIC;
  buffer->length = length;
  live_buffers += UINT32_C(1);
  *out_buffer = buffer;
  return FOXREQ_NSS_RESULT_OK;
}

static int alpn_wire_is_valid(foxreq_nss_slice wire,
                              size_t *out_first_length) {
  size_t offset = 0U;
  size_t length;
  if (!slice_is_valid(wire, 0)) {
    return 0;
  }
  length = (size_t)wire.length;
  while (offset < length) {
    size_t protocol_length = (size_t)wire.data[offset];
    offset += 1U;
    if (protocol_length == 0U || protocol_length > length - offset) {
      return 0;
    }
    if (offset == 1U) {
      *out_first_length = protocol_length;
    }
    offset += protocol_length;
  }
  return offset == length;
}

uint32_t foxreq_nss_abi_version(void) { return FOXREQ_NSS_ABI_VERSION; }

static int trust_bundle_is_valid(foxreq_nss_slice bundle) {
  size_t offset = 0U;
  size_t length;
  if (bundle.length == UINT64_C(0)) {
    return 1;
  }
  if (bundle.data == NULL || bundle.length > (uint64_t)SIZE_MAX) {
    return 0;
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
    if (item_length == UINT32_C(0) || (size_t)item_length > length - offset) {
      return 0;
    }
    offset += (size_t)item_length;
  }
  return offset == length;
}

foxreq_nss_result
foxreq_nss_runtime_create(const foxreq_nss_runtime_options *options,
                          foxreq_nss_runtime **out_runtime) {
  foxreq_nss_runtime *runtime;
  uint32_t profile;
  if (out_runtime == NULL) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  *out_runtime = NULL;
  if (options == NULL ||
      options->struct_size < (uint32_t)sizeof(*options) ||
      options->abi_version != FOXREQ_NSS_ABI_VERSION ||
      (profile = runtime_profile_value(options->profile_id)) == UINT32_C(0) ||
      !trust_bundle_is_valid(options->trust_anchors_der)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  runtime = (foxreq_nss_runtime *)calloc(1U, sizeof(*runtime));
  if (runtime == NULL) {
    return FOXREQ_NSS_RESULT_OUT_OF_MEMORY;
  }
  runtime->magic = FOXREQ_NSS_RUNTIME_MAGIC;
  runtime->profile = profile;
  live_runtimes += UINT32_C(1);
  *out_runtime = runtime;
  return FOXREQ_NSS_RESULT_OK;
}

void foxreq_nss_runtime_free(foxreq_nss_runtime *runtime) {
  if (runtime == NULL) {
    return;
  }
  if (runtime->magic == FOXREQ_NSS_RUNTIME_MAGIC) {
    runtime->magic = UINT32_C(0);
    live_runtimes -= UINT32_C(1);
  }
  free(runtime);
}

foxreq_nss_result foxreq_nss_runtime_versions(
    foxreq_nss_runtime *runtime, foxreq_nss_buffer **out_nss_version,
    foxreq_nss_buffer **out_nspr_version) {
  static const uint8_t nss_version[] = "fake-nss";
  static const uint8_t nspr_version[] = "fake-nspr";
  foxreq_nss_result result;
  if (!runtime_is_valid(runtime) || out_nss_version == NULL ||
      out_nspr_version == NULL) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  *out_nss_version = NULL;
  *out_nspr_version = NULL;
  result = buffer_create(nss_version, sizeof(nss_version) - 1U,
                         out_nss_version);
  if (result != FOXREQ_NSS_RESULT_OK) {
    return result;
  }
  result = buffer_create(nspr_version, sizeof(nspr_version) - 1U,
                         out_nspr_version);
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
  if (!runtime_is_valid(runtime) || options == NULL ||
      options->struct_size < (uint32_t)sizeof(*options) ||
      options->abi_version != FOXREQ_NSS_ABI_VERSION ||
      options->capacity == UINT32_C(0)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  cache = (foxreq_nss_session_cache *)calloc(1U, sizeof(*cache));
  if (cache == NULL) {
    return FOXREQ_NSS_RESULT_OUT_OF_MEMORY;
  }
  cache->magic = FOXREQ_NSS_CACHE_MAGIC;
  cache->capacity = options->capacity;
  cache->runtime = runtime;
  live_session_caches += UINT32_C(1);
  *out_cache = cache;
  return FOXREQ_NSS_RESULT_OK;
}

void foxreq_nss_session_cache_free(foxreq_nss_session_cache *cache) {
  if (cache == NULL) {
    return;
  }
  if (cache->magic == FOXREQ_NSS_CACHE_MAGIC) {
    cache->magic = UINT32_C(0);
    live_session_caches -= UINT32_C(1);
  }
  free(cache);
}

foxreq_nss_result
foxreq_nss_connect(foxreq_nss_runtime *runtime,
                   const foxreq_nss_connect_options *options,
                   foxreq_nss_connection **out_connection) {
  foxreq_nss_connection *connection;
  size_t first_alpn_length = 0U;
  if (out_connection == NULL) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  *out_connection = NULL;
  if (!runtime_is_valid(runtime) || options == NULL ||
      options->struct_size < (uint32_t)sizeof(*options) ||
      options->abi_version != FOXREQ_NSS_ABI_VERSION ||
      !slice_is_valid(options->host, 0) ||
      !slice_is_valid(options->profile_id, 0) ||
      runtime_profile_value(options->profile_id) != runtime->profile ||
      options->port == UINT16_C(0) ||
      (options->verification_mode != FOXREQ_NSS_VERIFY_DEFAULT &&
       options->verification_mode != FOXREQ_NSS_VERIFY_INSECURE_TEST_ONLY) ||
      !alpn_wire_is_valid(options->alpn_wire, &first_alpn_length)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  if (options->timeout_millis == UINT64_C(0)) {
    return FOXREQ_NSS_RESULT_TIMEOUT;
  }
  if (options->session_cache != NULL &&
      (!cache_is_valid(options->session_cache) ||
       options->session_cache->runtime != runtime)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }

  connection = (foxreq_nss_connection *)calloc(1U, sizeof(*connection));
  if (connection == NULL) {
    return FOXREQ_NSS_RESULT_OUT_OF_MEMORY;
  }
  connection->negotiated_alpn = (uint8_t *)malloc(first_alpn_length);
  if (connection->negotiated_alpn == NULL) {
    free(connection);
    return FOXREQ_NSS_RESULT_OUT_OF_MEMORY;
  }
  memcpy(connection->negotiated_alpn, options->alpn_wire.data + 1U,
         first_alpn_length);
  connection->negotiated_alpn_length = first_alpn_length;
  connection->magic = FOXREQ_NSS_CONNECTION_MAGIC;
  connection->verification_mode = options->verification_mode;
  connection->runtime = runtime;
  connection->last_category = FOXREQ_NSS_RESULT_OK;
  connection->last_message[0] = '\0';
  live_connections += UINT32_C(1);
  *out_connection = connection;
  return FOXREQ_NSS_RESULT_OK;
}

void foxreq_nss_connection_free(foxreq_nss_connection *connection) {
  if (connection == NULL) {
    return;
  }
  if (connection->magic == FOXREQ_NSS_CONNECTION_MAGIC) {
    connection->magic = UINT32_C(0);
    live_connections -= UINT32_C(1);
  }
  free(connection->negotiated_alpn);
  free(connection->read_data);
  free(connection->written_data);
  free(connection);
}

foxreq_nss_result foxreq_nss_connection_negotiated_alpn(
    foxreq_nss_connection *connection, foxreq_nss_buffer **out_buffer) {
  if (!connection_is_valid(connection)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  return buffer_create(connection->negotiated_alpn,
                       connection->negotiated_alpn_length, out_buffer);
}

foxreq_nss_result foxreq_nss_connection_certificate_result(
    foxreq_nss_connection *connection,
    foxreq_nss_certificate_result *out_result) {
  if (!connection_is_valid(connection) || out_result == NULL ||
      out_result->struct_size < (uint32_t)sizeof(*out_result) ||
      out_result->abi_version != FOXREQ_NSS_ABI_VERSION) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  out_result->verification_performed =
      connection->verification_mode == FOXREQ_NSS_VERIFY_DEFAULT ? UINT32_C(1)
                                                                 : UINT32_C(0);
  out_result->verified = out_result->verification_performed;
  out_result->category = FOXREQ_NSS_RESULT_OK;
  out_result->nss_code = INT32_C(0);
  out_result->nspr_code = INT32_C(0);
  out_result->reserved32 = UINT32_C(0);
  return FOXREQ_NSS_RESULT_OK;
}

foxreq_nss_result foxreq_nss_connection_read(
    foxreq_nss_connection *connection, uint8_t *destination, uint64_t capacity,
    uint64_t timeout_millis, uint64_t *out_read) {
  foxreq_nss_result result;
  size_t available;
  size_t amount;
  if (out_read == NULL || capacity > (uint64_t)SIZE_MAX ||
      (capacity > UINT64_C(0) && destination == NULL)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  *out_read = UINT64_C(0);
  result = require_open(connection);
  if (result != FOXREQ_NSS_RESULT_OK) {
    return result;
  }
  if (timeout_millis == UINT64_C(0)) {
    set_last_error_text(connection, FOXREQ_NSS_RESULT_TIMEOUT,
                        "read deadline expired");
    return FOXREQ_NSS_RESULT_TIMEOUT;
  }
  if (consume_pending_failure(connection, FOXREQ_NSS_STUB_OPERATION_READ,
                              &result)) {
    return result;
  }
  if (capacity == UINT64_C(0)) {
    return FOXREQ_NSS_RESULT_OK;
  }
  available = connection->read_length - connection->read_offset;
  if (available == 0U) {
    set_last_error_text(connection, FOXREQ_NSS_RESULT_END_OF_STREAM,
                        "end of stream");
    return FOXREQ_NSS_RESULT_END_OF_STREAM;
  }
  amount = (size_t)capacity;
  if (amount > available) {
    amount = available;
  }
  if (connection->read_limit > 0U && amount > connection->read_limit) {
    amount = connection->read_limit;
  }
  memcpy(destination, connection->read_data + connection->read_offset, amount);
  connection->read_offset += amount;
  *out_read = (uint64_t)amount;
  return FOXREQ_NSS_RESULT_OK;
}

foxreq_nss_result foxreq_nss_connection_write(
    foxreq_nss_connection *connection, const uint8_t *source, uint64_t length,
    uint64_t timeout_millis, uint64_t *out_written) {
  foxreq_nss_result result;
  size_t amount;
  size_t new_length;
  uint8_t *resized;
  if (out_written == NULL || length > (uint64_t)SIZE_MAX ||
      (length > UINT64_C(0) && source == NULL)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  *out_written = UINT64_C(0);
  result = require_open(connection);
  if (result != FOXREQ_NSS_RESULT_OK) {
    return result;
  }
  if (timeout_millis == UINT64_C(0)) {
    set_last_error_text(connection, FOXREQ_NSS_RESULT_TIMEOUT,
                        "write deadline expired");
    return FOXREQ_NSS_RESULT_TIMEOUT;
  }
  if (consume_pending_failure(connection, FOXREQ_NSS_STUB_OPERATION_WRITE,
                              &result)) {
    return result;
  }
  if (length == UINT64_C(0)) {
    return FOXREQ_NSS_RESULT_OK;
  }
  amount = (size_t)length;
  if (connection->write_limit > 0U && amount > connection->write_limit) {
    amount = connection->write_limit;
  }
  if (amount > SIZE_MAX - connection->written_length) {
    set_last_error_text(connection, FOXREQ_NSS_RESULT_OUT_OF_MEMORY,
                        "write buffer size overflow");
    return FOXREQ_NSS_RESULT_OUT_OF_MEMORY;
  }
  new_length = connection->written_length + amount;
  if (new_length > connection->written_capacity) {
    resized = (uint8_t *)realloc(connection->written_data, new_length);
    if (resized == NULL) {
      set_last_error_text(connection, FOXREQ_NSS_RESULT_OUT_OF_MEMORY,
                          "write buffer allocation failed");
      return FOXREQ_NSS_RESULT_OUT_OF_MEMORY;
    }
    connection->written_data = resized;
    connection->written_capacity = new_length;
  }
  memcpy(connection->written_data + connection->written_length, source, amount);
  connection->written_length = new_length;
  *out_written = (uint64_t)amount;
  return FOXREQ_NSS_RESULT_OK;
}

foxreq_nss_result foxreq_nss_connection_close(
    foxreq_nss_connection *connection, uint64_t timeout_millis) {
  foxreq_nss_result result;
  if (!connection_is_valid(connection)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  connection->close_calls += UINT32_C(1);
  if (connection->closed != UINT32_C(0)) {
    set_last_error_text(connection, FOXREQ_NSS_RESULT_STATE,
                        "connection is already closed");
    return FOXREQ_NSS_RESULT_STATE;
  }
  if (timeout_millis == UINT64_C(0)) {
    set_last_error_text(connection, FOXREQ_NSS_RESULT_TIMEOUT,
                        "close deadline expired");
    return FOXREQ_NSS_RESULT_TIMEOUT;
  }
  if (consume_pending_failure(connection, FOXREQ_NSS_STUB_OPERATION_CLOSE,
                              &result)) {
    return result;
  }
  connection->closed = UINT32_C(1);
  return FOXREQ_NSS_RESULT_OK;
}

foxreq_nss_result foxreq_nss_connection_last_error(
    foxreq_nss_connection *connection, foxreq_nss_error_info *out_error,
    char *message, uint64_t message_capacity, uint64_t *out_required) {
  size_t required;
  if (!connection_is_valid(connection) || out_error == NULL ||
      out_required == NULL ||
      out_error->struct_size < (uint32_t)sizeof(*out_error) ||
      out_error->abi_version != FOXREQ_NSS_ABI_VERSION) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  out_error->category = connection->last_category;
  out_error->reserved32 = UINT32_C(0);
  out_error->nss_code = connection->last_nss_code;
  out_error->nspr_code = connection->last_nspr_code;
  out_error->auxiliary = UINT64_C(0);
  required = strlen(connection->last_message) + 1U;
  *out_required = (uint64_t)required;
  if (message == NULL || message_capacity < (uint64_t)required) {
    return FOXREQ_NSS_RESULT_BUFFER_TOO_SMALL;
  }
  memcpy(message, connection->last_message, required);
  return FOXREQ_NSS_RESULT_OK;
}

foxreq_nss_result foxreq_nss_buffer_view(const foxreq_nss_buffer *buffer,
                                         const uint8_t **out_data,
                                         uint64_t *out_length) {
  if (!buffer_is_valid(buffer) || out_data == NULL || out_length == NULL) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  *out_data = buffer->data;
  *out_length = (uint64_t)buffer->length;
  return FOXREQ_NSS_RESULT_OK;
}

void foxreq_nss_buffer_free(foxreq_nss_buffer *buffer) {
  if (buffer == NULL) {
    return;
  }
  if (buffer->magic == FOXREQ_NSS_BUFFER_MAGIC) {
    buffer->magic = UINT32_C(0);
    live_buffers -= UINT32_C(1);
  }
  free(buffer->data);
  free(buffer);
}

foxreq_nss_result foxreq_nss_stub_set_read_data(
    foxreq_nss_connection *connection, const uint8_t *data, uint64_t length) {
  foxreq_nss_result result = require_open(connection);
  uint8_t *copied = NULL;
  if (result != FOXREQ_NSS_RESULT_OK) {
    return result;
  }
  if (length > (uint64_t)SIZE_MAX ||
      (length > UINT64_C(0) && data == NULL)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  if (length > UINT64_C(0)) {
    copied = (uint8_t *)malloc((size_t)length);
    if (copied == NULL) {
      return FOXREQ_NSS_RESULT_OUT_OF_MEMORY;
    }
    memcpy(copied, data, (size_t)length);
  }
  free(connection->read_data);
  connection->read_data = copied;
  connection->read_length = (size_t)length;
  connection->read_offset = 0U;
  return FOXREQ_NSS_RESULT_OK;
}

foxreq_nss_result foxreq_nss_stub_set_io_limits(
    foxreq_nss_connection *connection, uint64_t read_limit,
    uint64_t write_limit) {
  foxreq_nss_result result = require_open(connection);
  if (result != FOXREQ_NSS_RESULT_OK) {
    return result;
  }
  if (read_limit > (uint64_t)SIZE_MAX || write_limit > (uint64_t)SIZE_MAX) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  connection->read_limit = (size_t)read_limit;
  connection->write_limit = (size_t)write_limit;
  return FOXREQ_NSS_RESULT_OK;
}

foxreq_nss_result foxreq_nss_stub_fail_next(
    foxreq_nss_connection *connection, uint32_t operation,
    foxreq_nss_result category, int32_t nss_code, int32_t nspr_code,
    const uint8_t *message, uint64_t message_length) {
  foxreq_nss_result result = require_open(connection);
  if (result != FOXREQ_NSS_RESULT_OK) {
    return result;
  }
  if ((operation != FOXREQ_NSS_STUB_OPERATION_READ &&
       operation != FOXREQ_NSS_STUB_OPERATION_WRITE &&
       operation != FOXREQ_NSS_STUB_OPERATION_CLOSE) ||
      category == FOXREQ_NSS_RESULT_OK || !result_is_valid(category) ||
      message_length >= (uint64_t)FOXREQ_NSS_ERROR_MESSAGE_CAPACITY ||
      (message_length > UINT64_C(0) && message == NULL) ||
      (message_length > UINT64_C(0) &&
       memchr(message, '\0', (size_t)message_length) != NULL)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  connection->pending_operation = operation;
  connection->pending_category = category;
  connection->pending_nss_code = nss_code;
  connection->pending_nspr_code = nspr_code;
  if (message_length > UINT64_C(0)) {
    memcpy(connection->pending_message, message, (size_t)message_length);
  }
  connection->pending_message[(size_t)message_length] = '\0';
  return FOXREQ_NSS_RESULT_OK;
}

foxreq_nss_result foxreq_nss_stub_written_data(
    foxreq_nss_connection *connection, foxreq_nss_buffer **out_buffer) {
  if (!connection_is_valid(connection)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  return buffer_create(connection->written_data, connection->written_length,
                       out_buffer);
}

foxreq_nss_result foxreq_nss_stub_close_calls(
    foxreq_nss_connection *connection, uint32_t *out_calls) {
  if (!connection_is_valid(connection) || out_calls == NULL) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  *out_calls = connection->close_calls;
  return FOXREQ_NSS_RESULT_OK;
}

foxreq_nss_result foxreq_nss_stub_live_counts(
    uint32_t *out_runtimes, uint32_t *out_connections,
    uint32_t *out_session_caches, uint32_t *out_buffers) {
  if (out_runtimes == NULL || out_connections == NULL ||
      out_session_caches == NULL || out_buffers == NULL) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  *out_runtimes = live_runtimes;
  *out_connections = live_connections;
  *out_session_caches = live_session_caches;
  *out_buffers = live_buffers;
  return FOXREQ_NSS_RESULT_OK;
}
