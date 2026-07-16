#include "foxreq_nss_real_internal.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FOXREQ_PR_IO_TIMEOUT_ERROR INT32_C(-5990)
#define FOXREQ_PR_CONNECT_TIMEOUT_ERROR INT32_C(-5979)
#define FOXREQ_PR_WOULD_BLOCK_ERROR INT32_C(-5998)
#define FOXREQ_PR_SOCKET_NONBLOCKING 0
#define FOXREQ_PR_POLL_READ INT16_C(0x1)
#define FOXREQ_PR_POLL_WRITE INT16_C(0x2)
#define FOXREQ_PR_POLL_EXCEPT INT16_C(0x4)

static int slice_is_valid(foxreq_nss_slice slice, int allow_empty) {
  if (slice.length > (uint64_t)SIZE_MAX) {
    return 0;
  }
  if (slice.length == UINT64_C(0)) {
    return allow_empty;
  }
  return slice.data != NULL;
}

static int text_slice_is_valid(foxreq_nss_slice slice) {
  return slice_is_valid(slice, 0) && slice.length < (uint64_t)SIZE_MAX &&
         memchr(slice.data, 0, (size_t)slice.length) == NULL;
}

static int profile_matches_runtime(const foxreq_nss_runtime *runtime,
                                   foxreq_nss_slice profile) {
  static const uint8_t firefox_140[] = "firefox_140_esr";
  static const uint8_t firefox_152[] = "firefox_152";
  if (runtime == NULL || profile.data == NULL) {
    return 0;
  }
  return (runtime->profile == FOXREQ_NSS_PROFILE_140 &&
          profile.length == sizeof(firefox_140) - 1U &&
          memcmp(profile.data, firefox_140, sizeof(firefox_140) - 1U) == 0) ||
         (runtime->profile == FOXREQ_NSS_PROFILE_152 &&
          profile.length == sizeof(firefox_152) - 1U &&
          memcmp(profile.data, firefox_152, sizeof(firefox_152) - 1U) == 0);
}

static int alpn_wire_is_valid(foxreq_nss_slice wire) {
  size_t offset = 0U;
  if (!slice_is_valid(wire, 0)) {
    return 0;
  }
  while (offset < (size_t)wire.length) {
    size_t protocol_length = (size_t)wire.data[offset];
    offset += 1U;
    if (protocol_length == 0U ||
        protocol_length > (size_t)wire.length - offset) {
      return 0;
    }
    offset += protocol_length;
  }
  return offset == (size_t)wire.length;
}

static char *copy_text(foxreq_nss_slice value) {
  char *result;
  if (!text_slice_is_valid(value)) {
    return NULL;
  }
  result = (char *)malloc((size_t)value.length + 1U);
  if (result == NULL) {
    return NULL;
  }
  memcpy(result, value.data, (size_t)value.length);
  result[value.length] = '\0';
  return result;
}

static uint32_t bounded_timeout(uint64_t timeout_millis) {
  if (timeout_millis > (uint64_t)UINT32_MAX) {
    return UINT32_MAX;
  }
  return (uint32_t)timeout_millis;
}

static void set_error(foxreq_nss_connection *connection,
                      foxreq_nss_result category, int32_t code,
                      const char *message) {
  size_t message_length = strlen(message);
  size_t copied = message_length;
  if (copied >= FOXREQ_NSS_ERROR_MESSAGE_CAPACITY) {
    copied = FOXREQ_NSS_ERROR_MESSAGE_CAPACITY - 1U;
  }
  connection->last_category = category;
  if (code <= INT32_C(-7000)) {
    connection->last_nss_code = code;
    connection->last_nspr_code = INT32_C(0);
  } else {
    connection->last_nss_code = INT32_C(0);
    connection->last_nspr_code = code;
  }
  memcpy(connection->last_message, message, copied);
  connection->last_message[copied] = '\0';
}

static foxreq_nss_result category_for_error(int32_t code,
                                            foxreq_nss_result fallback) {
  if (code == FOXREQ_PR_IO_TIMEOUT_ERROR ||
      code == FOXREQ_PR_CONNECT_TIMEOUT_ERROR) {
    return FOXREQ_NSS_RESULT_TIMEOUT;
  }
  return fallback;
}

static uint64_t deadline_after(uint64_t timeout_millis) {
  uint64_t now = (uint64_t)GetTickCount64();
  if (timeout_millis > UINT64_MAX - now) {
    return UINT64_MAX;
  }
  return now + timeout_millis;
}

static int wait_for_io(foxreq_pr_file_desc *fd, int16_t flags,
                       uint64_t deadline, int32_t *out_error) {
  foxreq_pr_poll_desc descriptor;
  uint64_t now = (uint64_t)GetTickCount64();
  uint64_t remaining;
  int32_t result;
  if (now >= deadline) {
    *out_error = FOXREQ_PR_IO_TIMEOUT_ERROR;
    return 0;
  }
  remaining = deadline - now;
  descriptor.fd = fd;
  descriptor.in_flags = flags;
  descriptor.out_flags = INT16_C(0);
  result = foxreq_real_api.pr_poll(
      &descriptor, 1,
      foxreq_real_api.pr_milliseconds(bounded_timeout(remaining)));
  if (result > 0) {
    return 1;
  }
  *out_error = result == 0 ? FOXREQ_PR_IO_TIMEOUT_ERROR
                           : foxreq_real_api.pr_get_error();
  return 0;
}

static foxreq_nss_result force_handshake(foxreq_nss_connection *connection,
                                         uint64_t timeout_millis,
                                         int32_t *out_error) {
  uint64_t deadline = deadline_after(timeout_millis);
  for (;;) {
    if (foxreq_real_api.ssl_force_handshake(connection->fd) == 0) {
      return FOXREQ_NSS_RESULT_OK;
    }
    *out_error = foxreq_real_api.pr_get_error();
    if (*out_error != FOXREQ_PR_WOULD_BLOCK_ERROR) {
      return connection->verification_mode == FOXREQ_NSS_VERIFY_DEFAULT
                 ? FOXREQ_NSS_RESULT_CERTIFICATE
                 : category_for_error(*out_error, FOXREQ_NSS_RESULT_TLS);
    }
    if (!wait_for_io(connection->fd,
                     FOXREQ_PR_POLL_READ | FOXREQ_PR_POLL_WRITE |
                         FOXREQ_PR_POLL_EXCEPT,
                     deadline, out_error)) {
      return category_for_error(*out_error, FOXREQ_NSS_RESULT_TLS);
    }
  }
}

static int wait_for_connect(SOCKET socket_handle, uint64_t timeout_millis) {
  fd_set writable;
  struct timeval timeout;
  uint64_t seconds = timeout_millis / UINT64_C(1000);
  uint64_t microseconds = (timeout_millis % UINT64_C(1000)) * UINT64_C(1000);
  int socket_error = 0;
  int socket_error_length = (int)sizeof(socket_error);
  int selected;
  if (seconds > (uint64_t)LONG_MAX) {
    seconds = (uint64_t)LONG_MAX;
    microseconds = UINT64_C(0);
  }
  FD_ZERO(&writable);
  FD_SET(socket_handle, &writable);
  timeout.tv_sec = (long)seconds;
  timeout.tv_usec = (long)microseconds;
  selected = select(0, NULL, &writable, NULL, &timeout);
  if (selected <= 0 ||
      getsockopt(socket_handle, SOL_SOCKET, SO_ERROR, (char *)&socket_error,
                 &socket_error_length) != 0 ||
      socket_error != 0) {
    return 0;
  }
  return 1;
}

static SOCKET connect_socket(const char *host, uint16_t port,
                             uint64_t timeout_millis) {
  struct addrinfo hints;
  struct addrinfo *addresses = NULL;
  struct addrinfo *address;
  char service[6];
  SOCKET connected = INVALID_SOCKET;
  u_long nonblocking = 1UL;
  if (timeout_millis == UINT64_C(0) ||
      _snprintf_s(service, sizeof(service), _TRUNCATE, "%u",
                  (unsigned int)port) < 0) {
    return INVALID_SOCKET;
  }
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  if (getaddrinfo(host, service, &hints, &addresses) != 0) {
    return INVALID_SOCKET;
  }
  for (address = addresses; address != NULL; address = address->ai_next) {
    SOCKET candidate = socket(address->ai_family, address->ai_socktype,
                              address->ai_protocol);
    int connect_result;
    if (candidate == INVALID_SOCKET ||
        ioctlsocket(candidate, FIONBIO, &nonblocking) != 0) {
      if (candidate != INVALID_SOCKET) {
        closesocket(candidate);
      }
      continue;
    }
    connect_result = connect(candidate, address->ai_addr,
                             (int)address->ai_addrlen);
    if (connect_result == 0 ||
        (WSAGetLastError() == WSAEWOULDBLOCK &&
         wait_for_connect(candidate, timeout_millis))) {
      connected = candidate;
      break;
    }
    closesocket(candidate);
  }
  freeaddrinfo(addresses);
  if (connected == INVALID_SOCKET) {
    return INVALID_SOCKET;
  }
  return connected;
}

static int __cdecl insecure_auth(void *argument, foxreq_pr_file_desc *fd,
                                 int check_signature, int is_server) {
  foxreq_nss_connection *connection = (foxreq_nss_connection *)argument;
  (void)fd;
  (void)check_signature;
  (void)is_server;
  connection->certificate_verification_performed = UINT32_C(0);
  connection->certificate_verified = UINT32_C(0);
  connection->certificate_category = FOXREQ_NSS_RESULT_OK;
  connection->certificate_nss_code = INT32_C(0);
  connection->certificate_nspr_code = INT32_C(0);
  return 0;
}

foxreq_nss_result
foxreq_nss_connect(foxreq_nss_runtime *runtime,
                   const foxreq_nss_connect_options *options,
                   foxreq_nss_connection **out_connection) {
  foxreq_nss_connection *connection = NULL;
  foxreq_nss_session_cache *cache;
  char *host = NULL;
  SOCKET socket_handle = INVALID_SOCKET;
  foxreq_pr_file_desc *transport = NULL;
  foxreq_pr_socket_option nonblocking;
  foxreq_pr_socket_option nonblocking_probe;
  int32_t error_code = INT32_C(0);
  foxreq_nss_result result = FOXREQ_NSS_RESULT_TLS;

  if (out_connection == NULL) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  *out_connection = NULL;
  if (!foxreq_real_runtime_is_valid(runtime) || options == NULL ||
      options->struct_size < (uint32_t)sizeof(*options) ||
      options->abi_version != FOXREQ_NSS_ABI_VERSION ||
      !text_slice_is_valid(options->host) ||
      !text_slice_is_valid(options->profile_id) ||
      options->port == UINT16_C(0) || options->timeout_millis == UINT64_C(0) ||
      !alpn_wire_is_valid(options->alpn_wire) ||
      (options->verification_mode != FOXREQ_NSS_VERIFY_DEFAULT &&
       options->verification_mode != FOXREQ_NSS_VERIFY_INSECURE_TEST_ONLY) ||
      !profile_matches_runtime(runtime, options->profile_id)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  cache = options->session_cache;
  if (cache != NULL &&
      (!foxreq_real_cache_is_valid(cache) || cache->runtime != runtime)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  host = copy_text(options->host);
  connection = (foxreq_nss_connection *)calloc(1U, sizeof(*connection));
  if (host == NULL || connection == NULL) {
    result = FOXREQ_NSS_RESULT_OUT_OF_MEMORY;
    goto cleanup;
  }
  connection->magic = FOXREQ_NSS_CONNECTION_MAGIC;
  connection->runtime = runtime;
  connection->verification_mode = options->verification_mode;
  connection->last_category = FOXREQ_NSS_RESULT_OK;
  connection->certificate_category = FOXREQ_NSS_RESULT_OK;

  socket_handle = connect_socket(host, options->port, options->timeout_millis);
  if (socket_handle == INVALID_SOCKET) {
    set_error(connection, FOXREQ_NSS_RESULT_IO, (int32_t)WSAGetLastError(),
              "TCP connection failed");
    result = FOXREQ_NSS_RESULT_IO;
    goto cleanup;
  }
  transport =
      foxreq_real_api.pr_import_tcp_socket((intptr_t)socket_handle);
  if (transport == NULL) {
    closesocket(socket_handle);
    socket_handle = INVALID_SOCKET;
    error_code = foxreq_real_api.pr_get_error();
    set_error(connection, FOXREQ_NSS_RESULT_IO, error_code,
              "NSPR socket import failed");
    result = FOXREQ_NSS_RESULT_IO;
    goto cleanup;
  }
  socket_handle = INVALID_SOCKET;
  nonblocking.option = FOXREQ_PR_SOCKET_NONBLOCKING;
  nonblocking.reserved32 = UINT32_C(0);
  nonblocking.value.non_blocking = 1;
  if (foxreq_real_api.pr_set_socket_option(transport, &nonblocking) != 0) {
    error_code = foxreq_real_api.pr_get_error();
    set_error(connection, FOXREQ_NSS_RESULT_IO, error_code,
              "NSPR nonblocking configuration failed");
    (void)foxreq_real_api.pr_close(transport);
    transport = NULL;
    result = FOXREQ_NSS_RESULT_IO;
    goto cleanup;
  }
  nonblocking_probe.option = FOXREQ_PR_SOCKET_NONBLOCKING;
  nonblocking_probe.reserved32 = UINT32_C(0);
  nonblocking_probe.value.non_blocking = 0;
  if (foxreq_real_api.pr_get_socket_option(transport, &nonblocking_probe) != 0 ||
      nonblocking_probe.value.non_blocking == 0) {
    error_code = foxreq_real_api.pr_get_error();
    set_error(connection, FOXREQ_NSS_RESULT_IO, error_code,
              "NSPR nonblocking verification failed");
    (void)foxreq_real_api.pr_close(transport);
    transport = NULL;
    result = FOXREQ_NSS_RESULT_IO;
    goto cleanup;
  }
  connection->fd = foxreq_real_api.ssl_import_fd(NULL, transport);
  if (connection->fd == NULL) {
    (void)foxreq_real_api.pr_close(transport);
    error_code = foxreq_real_api.pr_get_error();
    set_error(connection, FOXREQ_NSS_RESULT_TLS, error_code,
              "NSS socket import failed");
    goto cleanup;
  }
  transport = NULL;
  nonblocking_probe.option = FOXREQ_PR_SOCKET_NONBLOCKING;
  nonblocking_probe.reserved32 = UINT32_C(0);
  nonblocking_probe.value.non_blocking = 0;
  if (foxreq_real_api.pr_get_socket_option(connection->fd,
                                            &nonblocking_probe) != 0 ||
      nonblocking_probe.value.non_blocking == 0) {
    error_code = foxreq_real_api.pr_get_error();
    set_error(connection, FOXREQ_NSS_RESULT_TLS, error_code,
              "NSS nonblocking verification failed");
    result = FOXREQ_NSS_RESULT_TLS;
    goto cleanup;
  }
  if (foxreq_real_api.ssl_set_url(connection->fd, host) != 0) {
    error_code = foxreq_real_api.pr_get_error();
    set_error(connection, FOXREQ_NSS_RESULT_TLS, error_code,
              "NSS server name configuration failed");
    goto cleanup;
  }
  result = foxreq_real_configure_profile(connection, options);
  if (result != FOXREQ_NSS_RESULT_OK) {
    error_code = foxreq_real_api.pr_get_error();
    set_error(connection, result, error_code,
              "Firefox TLS profile configuration failed");
    goto cleanup;
  }
  if (options->verification_mode == FOXREQ_NSS_VERIFY_INSECURE_TEST_ONLY &&
      foxreq_real_api.ssl_auth_hook(connection->fd, insecure_auth, connection) !=
          0) {
    error_code = foxreq_real_api.pr_get_error();
    set_error(connection, FOXREQ_NSS_RESULT_TLS, error_code,
              "test verification hook configuration failed");
    result = FOXREQ_NSS_RESULT_TLS;
    goto cleanup;
  }
  if (foxreq_real_api.ssl_reset_handshake(connection->fd, 0) != 0) {
    error_code = foxreq_real_api.pr_get_error();
    result = FOXREQ_NSS_RESULT_TLS;
    set_error(connection, result, error_code, "TLS handshake reset failed");
    goto cleanup;
  }
  result = force_handshake(connection, options->timeout_millis, &error_code);
  if (result != FOXREQ_NSS_RESULT_OK) {
    set_error(connection, result, error_code, "TLS handshake failed");
    connection->certificate_verification_performed =
        options->verification_mode == FOXREQ_NSS_VERIFY_DEFAULT;
    connection->certificate_verified = UINT32_C(0);
    connection->certificate_category = result;
    connection->certificate_nss_code = connection->last_nss_code;
    connection->certificate_nspr_code = connection->last_nspr_code;
    goto cleanup;
  }
  if (options->verification_mode == FOXREQ_NSS_VERIFY_DEFAULT) {
    connection->certificate_verification_performed = UINT32_C(1);
    connection->certificate_verified = UINT32_C(1);
  }
  foxreq_real_runtime_retain(runtime);
  *out_connection = connection;
  free(host);
  return FOXREQ_NSS_RESULT_OK;

cleanup:
  if (socket_handle != INVALID_SOCKET) {
    closesocket(socket_handle);
  }
  if (connection != NULL && connection->fd != NULL) {
    (void)foxreq_real_api.pr_close(connection->fd);
    connection->fd = NULL;
  }
  if (foxreq_real_connection_is_valid(connection) &&
      connection->last_category != FOXREQ_NSS_RESULT_OK) {
    foxreq_real_runtime_retain(runtime);
    *out_connection = connection;
    connection = NULL;
  }
  free(connection);
  free(host);
  return result;
}

void foxreq_nss_connection_free(foxreq_nss_connection *connection) {
  foxreq_nss_runtime *runtime;
  if (!foxreq_real_connection_is_valid(connection)) {
    return;
  }
  connection->magic = UINT32_C(0);
  if (connection->fd != NULL) {
    (void)foxreq_real_api.pr_close(connection->fd);
    connection->fd = NULL;
  }
  runtime = connection->runtime;
  free(connection);
  foxreq_real_runtime_release(runtime);
}

foxreq_nss_result foxreq_nss_connection_negotiated_alpn(
    foxreq_nss_connection *connection, foxreq_nss_buffer **out_buffer) {
  uint8_t protocol[255];
  unsigned int length = 0U;
  int state = 0;
  if (!foxreq_real_connection_is_valid(connection) || out_buffer == NULL ||
      connection->closed != UINT32_C(0) || connection->fd == NULL) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  *out_buffer = NULL;
  if (foxreq_real_api.ssl_get_next_proto(connection->fd, &state, protocol,
                                         &length, sizeof(protocol)) != 0) {
    int32_t error_code = foxreq_real_api.pr_get_error();
    set_error(connection, FOXREQ_NSS_RESULT_TLS, error_code,
              "ALPN result query failed");
    return FOXREQ_NSS_RESULT_TLS;
  }
  if ((state != 1 && state != 3 && state != 4) || length == 0U) {
    set_error(connection, FOXREQ_NSS_RESULT_TLS, INT32_C(0),
              "ALPN was not negotiated");
    return FOXREQ_NSS_RESULT_TLS;
  }
  return foxreq_real_buffer_create(protocol, (size_t)length, out_buffer);
}

foxreq_nss_result foxreq_nss_connection_certificate_result(
    foxreq_nss_connection *connection,
    foxreq_nss_certificate_result *out_result) {
  if (!foxreq_real_connection_is_valid(connection) || out_result == NULL ||
      out_result->struct_size < (uint32_t)sizeof(*out_result) ||
      out_result->abi_version != FOXREQ_NSS_ABI_VERSION) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  out_result->verification_performed =
      connection->certificate_verification_performed;
  out_result->verified = connection->certificate_verified;
  out_result->category = connection->certificate_category;
  out_result->nss_code = connection->certificate_nss_code;
  out_result->nspr_code = connection->certificate_nspr_code;
  out_result->reserved32 = UINT32_C(0);
  return FOXREQ_NSS_RESULT_OK;
}

foxreq_nss_result foxreq_nss_connection_read(
    foxreq_nss_connection *connection, uint8_t *destination, uint64_t capacity,
    uint64_t timeout_millis, uint64_t *out_read) {
  int32_t amount;
  int32_t error_code = INT32_C(0);
  uint64_t deadline;
  if (!foxreq_real_connection_is_valid(connection) || out_read == NULL ||
      capacity > (uint64_t)INT_MAX ||
      (capacity > UINT64_C(0) && destination == NULL)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  *out_read = UINT64_C(0);
  if (connection->closed != UINT32_C(0) || connection->fd == NULL) {
    set_error(connection, FOXREQ_NSS_RESULT_STATE, INT32_C(0),
              "connection is closed");
    return FOXREQ_NSS_RESULT_STATE;
  }
  if (timeout_millis == UINT64_C(0)) {
    set_error(connection, FOXREQ_NSS_RESULT_TIMEOUT, INT32_C(0),
              "read deadline expired");
    return FOXREQ_NSS_RESULT_TIMEOUT;
  }
  if (capacity == UINT64_C(0)) {
    return FOXREQ_NSS_RESULT_OK;
  }
  deadline = deadline_after(timeout_millis);
  do {
    amount = foxreq_real_api.pr_recv(connection->fd, destination,
                                     (int32_t)capacity, 0, 0U);
    if (amount < 0) {
      error_code = foxreq_real_api.pr_get_error();
      if (error_code == FOXREQ_PR_WOULD_BLOCK_ERROR &&
          wait_for_io(connection->fd,
                      FOXREQ_PR_POLL_READ | FOXREQ_PR_POLL_EXCEPT, deadline,
                      &error_code)) {
        continue;
      }
    }
    break;
  } while (1);
  if (amount > 0) {
    *out_read = (uint64_t)amount;
    return FOXREQ_NSS_RESULT_OK;
  }
  if (amount == 0) {
    set_error(connection, FOXREQ_NSS_RESULT_END_OF_STREAM, INT32_C(0),
              "end of stream");
    return FOXREQ_NSS_RESULT_END_OF_STREAM;
  }
  {
    foxreq_nss_result category =
        category_for_error(error_code, FOXREQ_NSS_RESULT_IO);
    set_error(connection, category, error_code, "TLS read failed");
    return category;
  }
}

foxreq_nss_result foxreq_nss_connection_write(
    foxreq_nss_connection *connection, const uint8_t *source, uint64_t length,
    uint64_t timeout_millis, uint64_t *out_written) {
  int32_t amount;
  int32_t error_code = INT32_C(0);
  uint64_t deadline;
  if (!foxreq_real_connection_is_valid(connection) || out_written == NULL ||
      length > (uint64_t)INT_MAX ||
      (length > UINT64_C(0) && source == NULL)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  *out_written = UINT64_C(0);
  if (connection->closed != UINT32_C(0) || connection->fd == NULL) {
    set_error(connection, FOXREQ_NSS_RESULT_STATE, INT32_C(0),
              "connection is closed");
    return FOXREQ_NSS_RESULT_STATE;
  }
  if (timeout_millis == UINT64_C(0)) {
    set_error(connection, FOXREQ_NSS_RESULT_TIMEOUT, INT32_C(0),
              "write deadline expired");
    return FOXREQ_NSS_RESULT_TIMEOUT;
  }
  if (length == UINT64_C(0)) {
    return FOXREQ_NSS_RESULT_OK;
  }
  deadline = deadline_after(timeout_millis);
  do {
    amount = foxreq_real_api.pr_send(connection->fd, source, (int32_t)length,
                                     0, 0U);
    if (amount < 0) {
      error_code = foxreq_real_api.pr_get_error();
      if (error_code == FOXREQ_PR_WOULD_BLOCK_ERROR &&
          wait_for_io(connection->fd,
                      FOXREQ_PR_POLL_WRITE | FOXREQ_PR_POLL_EXCEPT, deadline,
                      &error_code)) {
        continue;
      }
    }
    break;
  } while (1);
  if (amount >= 0) {
    *out_written = (uint64_t)amount;
    return FOXREQ_NSS_RESULT_OK;
  }
  {
    foxreq_nss_result category =
        category_for_error(error_code, FOXREQ_NSS_RESULT_IO);
    set_error(connection, category, error_code, "TLS write failed");
    return category;
  }
}

foxreq_nss_result foxreq_nss_connection_close(
    foxreq_nss_connection *connection, uint64_t timeout_millis) {
  int status;
  int32_t error_code;
  if (!foxreq_real_connection_is_valid(connection)) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  if (connection->closed != UINT32_C(0) || connection->fd == NULL) {
    set_error(connection, FOXREQ_NSS_RESULT_STATE, INT32_C(0),
              "connection is closed");
    return FOXREQ_NSS_RESULT_STATE;
  }
  if (timeout_millis == UINT64_C(0)) {
    set_error(connection, FOXREQ_NSS_RESULT_TIMEOUT, INT32_C(0),
              "close deadline expired");
    return FOXREQ_NSS_RESULT_TIMEOUT;
  }
  status = foxreq_real_api.pr_close(connection->fd);
  connection->fd = NULL;
  connection->closed = UINT32_C(1);
  if (status != 0) {
    error_code = foxreq_real_api.pr_get_error();
    set_error(connection, FOXREQ_NSS_RESULT_IO, error_code,
              "TLS connection close failed");
    return FOXREQ_NSS_RESULT_IO;
  }
  return FOXREQ_NSS_RESULT_OK;
}

foxreq_nss_result foxreq_nss_connection_last_error(
    foxreq_nss_connection *connection, foxreq_nss_error_info *out_error,
    char *message, uint64_t message_capacity, uint64_t *out_required) {
  size_t required;
  if (!foxreq_real_connection_is_valid(connection) || out_error == NULL ||
      out_required == NULL ||
      out_error->struct_size < (uint32_t)sizeof(*out_error) ||
      out_error->abi_version != FOXREQ_NSS_ABI_VERSION) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  required = strlen(connection->last_message) + 1U;
  *out_required = (uint64_t)required;
  out_error->category = connection->last_category;
  out_error->reserved32 = UINT32_C(0);
  out_error->nss_code = connection->last_nss_code;
  out_error->nspr_code = connection->last_nspr_code;
  out_error->auxiliary = UINT64_C(0);
  if (message_capacity < (uint64_t)required || message == NULL) {
    return FOXREQ_NSS_RESULT_BUFFER_TOO_SMALL;
  }
  memcpy(message, connection->last_message, required);
  return FOXREQ_NSS_RESULT_OK;
}
