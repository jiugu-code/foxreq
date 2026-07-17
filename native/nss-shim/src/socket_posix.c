#include "platform_socket.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int wait_for_connect(int socket_handle, uint64_t timeout_millis,
                            int32_t *out_error) {
  struct pollfd descriptor;
  int socket_error = 0;
  socklen_t socket_error_length = (socklen_t)sizeof(socket_error);
  int timeout = timeout_millis > (uint64_t)INT_MAX ? INT_MAX
                                                   : (int)timeout_millis;
  int result;
  descriptor.fd = socket_handle;
  descriptor.events = POLLOUT;
  descriptor.revents = 0;
  result = poll(&descriptor, 1, timeout);
  if (result <= 0 ||
      getsockopt(socket_handle, SOL_SOCKET, SO_ERROR, &socket_error,
                 &socket_error_length) != 0 ||
      socket_error != 0) {
    *out_error = result == 0 ? ETIMEDOUT
                             : (socket_error != 0 ? socket_error : errno);
    return 0;
  }
  return 1;
}

foxreq_platform_socket foxreq_platform_socket_connect(const char *host,
                                                       uint16_t port,
                                                       uint64_t timeout_millis,
                                                       int32_t *out_error) {
  struct addrinfo hints;
  struct addrinfo *addresses = NULL;
  struct addrinfo *address;
  char service[6];
  int connected = -1;
  if (out_error == NULL) {
    return FOXREQ_PLATFORM_INVALID_SOCKET;
  }
  *out_error = 0;
  if (host == NULL || timeout_millis == UINT64_C(0) ||
      snprintf(service, sizeof(service), "%u", (unsigned int)port) < 0) {
    *out_error = EINVAL;
    return FOXREQ_PLATFORM_INVALID_SOCKET;
  }
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  if (getaddrinfo(host, service, &hints, &addresses) != 0) {
    *out_error = EINVAL;
    return FOXREQ_PLATFORM_INVALID_SOCKET;
  }
  for (address = addresses; address != NULL; address = address->ai_next) {
    int candidate = socket(address->ai_family, address->ai_socktype,
                           address->ai_protocol);
    int flags;
    int connect_result;
    if (candidate < 0) {
      *out_error = errno;
      continue;
    }
    flags = fcntl(candidate, F_GETFL, 0);
    if (flags < 0 || fcntl(candidate, F_SETFL, flags | O_NONBLOCK) != 0) {
      *out_error = errno;
      (void)close(candidate);
      continue;
    }
    connect_result = connect(candidate, address->ai_addr,
                             address->ai_addrlen);
    if (connect_result == 0) {
      connected = candidate;
      break;
    }
    *out_error = errno;
    if (*out_error == EINPROGRESS &&
        wait_for_connect(candidate, timeout_millis, out_error)) {
      connected = candidate;
      break;
    }
    (void)close(candidate);
  }
  freeaddrinfo(addresses);
  return connected < 0 ? FOXREQ_PLATFORM_INVALID_SOCKET
                       : (foxreq_platform_socket)connected;
}

void foxreq_platform_socket_close(foxreq_platform_socket socket_handle) {
  if (socket_handle != FOXREQ_PLATFORM_INVALID_SOCKET) {
    (void)close((int)socket_handle);
  }
}
