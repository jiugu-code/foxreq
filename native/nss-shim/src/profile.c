#include "foxreq_nss_real_internal.h"

#include <limits.h>

#define FOXREQ_SSL_SECURITY INT32_C(1)
#define FOXREQ_SSL_HANDSHAKE_AS_CLIENT INT32_C(5)
#define FOXREQ_SSL_NO_CACHE INT32_C(9)
#define FOXREQ_SSL_ENABLE_SESSION_TICKETS INT32_C(18)
#define FOXREQ_SSL_ENABLE_TLS13_COMPAT_MODE INT32_C(35)
#define FOXREQ_TLS_1_2 UINT16_C(0x0303)
#define FOXREQ_TLS_1_3 UINT16_C(0x0304)

foxreq_nss_result foxreq_real_configure_profile(
    foxreq_nss_connection *connection,
    const foxreq_nss_connect_options *options) {
  foxreq_ssl_version_range range;
  if (connection == NULL || connection->fd == NULL || options == NULL ||
      options->alpn_wire.length > (uint64_t)UINT_MAX) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  range.minimum = FOXREQ_TLS_1_2;
  range.maximum = FOXREQ_TLS_1_3;
  if (foxreq_real_api.ssl_option_set(connection->fd, FOXREQ_SSL_SECURITY, 1) !=
          0 ||
      foxreq_real_api.ssl_option_set(connection->fd,
                                     FOXREQ_SSL_HANDSHAKE_AS_CLIENT, 1) != 0 ||
      foxreq_real_api.ssl_option_set(
          connection->fd, FOXREQ_SSL_ENABLE_SESSION_TICKETS, 1) != 0 ||
      foxreq_real_api.ssl_option_set(
          connection->fd, FOXREQ_SSL_ENABLE_TLS13_COMPAT_MODE, 1) != 0 ||
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
