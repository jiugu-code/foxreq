#include <winsock2.h>
#include <ws2tcpip.h>

#include "platform_socket.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

static int wait_for_connect(SOCKET socket_handle, uint64_t timeout_millis,
                            int32_t *out_error) {
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
    *out_error = selected == 0 ? WSAETIMEDOUT
                               : (socket_error != 0 ? socket_error
                                                    : WSAGetLastError());
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
  SOCKET connected = INVALID_SOCKET;
  u_long nonblocking = 1UL;
  if (out_error == NULL) {
    return FOXREQ_PLATFORM_INVALID_SOCKET;
  }
  *out_error = INT32_C(0);
  if (host == NULL || timeout_millis == UINT64_C(0) ||
      _snprintf_s(service, sizeof(service), _TRUNCATE, "%u",
                  (unsigned int)port) < 0) {
    *out_error = WSAEINVAL;
    return FOXREQ_PLATFORM_INVALID_SOCKET;
  }
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  if (getaddrinfo(host, service, &hints, &addresses) != 0) {
    *out_error = WSAGetLastError();
    return FOXREQ_PLATFORM_INVALID_SOCKET;
  }
  for (address = addresses; address != NULL; address = address->ai_next) {
    SOCKET candidate = socket(address->ai_family, address->ai_socktype,
                              address->ai_protocol);
    int connect_result;
    if (candidate == INVALID_SOCKET ||
        ioctlsocket(candidate, FIONBIO, &nonblocking) != 0) {
      if (candidate != INVALID_SOCKET) {
        (void)closesocket(candidate);
      }
      *out_error = WSAGetLastError();
      continue;
    }
    connect_result = connect(candidate, address->ai_addr,
                             (int)address->ai_addrlen);
    if (connect_result == 0) {
      connected = candidate;
      break;
    }
    *out_error = WSAGetLastError();
    if (*out_error == WSAEWOULDBLOCK &&
        wait_for_connect(candidate, timeout_millis, out_error)) {
      connected = candidate;
      break;
    }
    (void)closesocket(candidate);
  }
  freeaddrinfo(addresses);
  return connected == INVALID_SOCKET ? FOXREQ_PLATFORM_INVALID_SOCKET
                                     : (foxreq_platform_socket)connected;
}

void foxreq_platform_socket_close(foxreq_platform_socket socket_handle) {
  if (socket_handle != FOXREQ_PLATFORM_INVALID_SOCKET) {
    (void)closesocket((SOCKET)socket_handle);
  }
}
