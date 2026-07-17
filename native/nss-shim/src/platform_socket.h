#ifndef FOXREQ_PLATFORM_SOCKET_H
#define FOXREQ_PLATFORM_SOCKET_H

#include <stdint.h>

typedef intptr_t foxreq_platform_socket;

#define FOXREQ_PLATFORM_INVALID_SOCKET ((foxreq_platform_socket)-1)

foxreq_platform_socket foxreq_platform_socket_connect(const char *host,
                                                       uint16_t port,
                                                       uint64_t timeout_millis,
                                                       int32_t *out_error);
void foxreq_platform_socket_close(foxreq_platform_socket socket_handle);

#endif
