#ifndef FOXREQ_NSS_REAL_INTERNAL_H
#define FOXREQ_NSS_REAL_INTERNAL_H

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "foxreq_nss.h"

#include <stddef.h>

#define FOXREQ_NSS_RUNTIME_MAGIC UINT32_C(0x46585254)
#define FOXREQ_NSS_CACHE_MAGIC UINT32_C(0x46584348)
#define FOXREQ_NSS_CONNECTION_MAGIC UINT32_C(0x4658434E)
#define FOXREQ_NSS_BUFFER_MAGIC UINT32_C(0x46584246)
#define FOXREQ_NSS_ERROR_MESSAGE_CAPACITY 256U

typedef const char *(__cdecl *foxreq_version_fn)(void);
typedef int(__cdecl *foxreq_nss_init_fn)(const char *config_dir);
typedef int(__cdecl *foxreq_nss_shutdown_fn)(void);
typedef int(__cdecl *foxreq_pr_get_error_fn)(void);
typedef struct foxreq_cert_db_handle foxreq_cert_db_handle;
typedef struct foxreq_cert_certificate foxreq_cert_certificate;
typedef struct foxreq_sec_item {
  int type;
  unsigned char *data;
  unsigned int length;
} foxreq_sec_item;
typedef struct foxreq_cert_trust {
  unsigned int ssl_flags;
  unsigned int email_flags;
  unsigned int object_signing_flags;
} foxreq_cert_trust;
typedef foxreq_cert_db_handle *(__cdecl *foxreq_cert_get_default_db_fn)(void);
typedef foxreq_cert_certificate *(__cdecl *foxreq_cert_new_temp_fn)(
    foxreq_cert_db_handle *database, foxreq_sec_item *der_certificate,
    char *nickname, int is_permanent, int copy_der);
typedef int(__cdecl *foxreq_cert_decode_trust_fn)(
    foxreq_cert_trust *trust, const char *trust_string);
typedef int(__cdecl *foxreq_cert_change_trust_fn)(
    foxreq_cert_db_handle *database, foxreq_cert_certificate *certificate,
    foxreq_cert_trust *trust);
typedef void(__cdecl *foxreq_cert_destroy_fn)(
    foxreq_cert_certificate *certificate);
typedef struct foxreq_pr_file_desc foxreq_pr_file_desc;
typedef int(__cdecl *foxreq_ssl_auth_callback)(void *argument,
                                              foxreq_pr_file_desc *fd,
                                              int check_signature,
                                              int is_server);
typedef foxreq_pr_file_desc *(__cdecl *foxreq_pr_import_socket_fn)(
    intptr_t socket);
typedef struct foxreq_pr_socket_option {
  int option;
  uint32_t reserved32;
  union {
    int non_blocking;
    uint64_t alignment;
  } value;
} foxreq_pr_socket_option;
typedef int(__cdecl *foxreq_pr_set_socket_option_fn)(
    foxreq_pr_file_desc *fd, const foxreq_pr_socket_option *option);
typedef int(__cdecl *foxreq_pr_get_socket_option_fn)(
    foxreq_pr_file_desc *fd, foxreq_pr_socket_option *option);
typedef struct foxreq_pr_poll_desc {
  foxreq_pr_file_desc *fd;
  int16_t in_flags;
  int16_t out_flags;
} foxreq_pr_poll_desc;
typedef int32_t(__cdecl *foxreq_pr_poll_fn)(foxreq_pr_poll_desc *descriptors,
                                          int count, uint32_t timeout);
typedef foxreq_pr_file_desc *(__cdecl *foxreq_ssl_import_fd_fn)(
    foxreq_pr_file_desc *model, foxreq_pr_file_desc *fd);
typedef int(__cdecl *foxreq_ssl_option_set_fn)(foxreq_pr_file_desc *fd,
                                              int32_t option, int enabled);
typedef int(__cdecl *foxreq_ssl_set_url_fn)(foxreq_pr_file_desc *fd,
                                           const char *url);
typedef struct foxreq_ssl_version_range {
  uint16_t minimum;
  uint16_t maximum;
} foxreq_ssl_version_range;
typedef int(__cdecl *foxreq_ssl_version_range_set_fn)(
    foxreq_pr_file_desc *fd, const foxreq_ssl_version_range *range);
typedef int(__cdecl *foxreq_ssl_set_next_proto_fn)(
    foxreq_pr_file_desc *fd, const uint8_t *data, unsigned int length);
typedef int(__cdecl *foxreq_ssl_auth_hook_fn)(
    foxreq_pr_file_desc *fd, foxreq_ssl_auth_callback callback,
    void *argument);
typedef int(__cdecl *foxreq_ssl_reset_handshake_fn)(foxreq_pr_file_desc *fd,
                                                   int as_server);
typedef int(__cdecl *foxreq_ssl_force_handshake_fn)(foxreq_pr_file_desc *fd);
typedef int(__cdecl *foxreq_ssl_get_next_proto_fn)(
    foxreq_pr_file_desc *fd, int *state, uint8_t *buffer,
    unsigned int *length, unsigned int capacity);
typedef int32_t(__cdecl *foxreq_pr_recv_fn)(foxreq_pr_file_desc *fd,
                                           void *buffer, int32_t length,
                                           int flags, uint32_t timeout);
typedef int32_t(__cdecl *foxreq_pr_send_fn)(foxreq_pr_file_desc *fd,
                                           const void *buffer, int32_t length,
                                           int flags, uint32_t timeout);
typedef int(__cdecl *foxreq_pr_close_fn)(foxreq_pr_file_desc *fd);
typedef uint32_t(__cdecl *foxreq_pr_milliseconds_fn)(uint32_t milliseconds);

typedef struct foxreq_nss_api {
  foxreq_version_fn nss_get_version;
  foxreq_version_fn nspr_get_version;
  foxreq_nss_init_fn nss_no_db_init;
  foxreq_nss_shutdown_fn nss_shutdown;
  foxreq_pr_get_error_fn pr_get_error;
  foxreq_cert_get_default_db_fn cert_get_default_db;
  foxreq_cert_new_temp_fn cert_new_temp;
  foxreq_cert_decode_trust_fn cert_decode_trust;
  foxreq_cert_change_trust_fn cert_change_trust;
  foxreq_cert_destroy_fn cert_destroy;
  foxreq_pr_import_socket_fn pr_import_tcp_socket;
  foxreq_pr_set_socket_option_fn pr_set_socket_option;
  foxreq_pr_get_socket_option_fn pr_get_socket_option;
  foxreq_pr_poll_fn pr_poll;
  foxreq_ssl_import_fd_fn ssl_import_fd;
  foxreq_ssl_option_set_fn ssl_option_set;
  foxreq_ssl_set_url_fn ssl_set_url;
  foxreq_ssl_version_range_set_fn ssl_version_range_set;
  foxreq_ssl_set_next_proto_fn ssl_set_next_proto;
  foxreq_ssl_auth_hook_fn ssl_auth_hook;
  foxreq_ssl_reset_handshake_fn ssl_reset_handshake;
  foxreq_ssl_force_handshake_fn ssl_force_handshake;
  foxreq_ssl_get_next_proto_fn ssl_get_next_proto;
  foxreq_pr_recv_fn pr_recv;
  foxreq_pr_send_fn pr_send;
  foxreq_pr_close_fn pr_close;
  foxreq_pr_milliseconds_fn pr_milliseconds;
} foxreq_nss_api;

struct foxreq_nss_runtime {
  uint32_t magic;
  volatile LONG references;
};

struct foxreq_nss_session_cache {
  uint32_t magic;
  uint32_t capacity;
  foxreq_nss_runtime *runtime;
};

struct foxreq_nss_connection {
  uint32_t magic;
  uint32_t closed;
  uint32_t verification_mode;
  foxreq_nss_runtime *runtime;
  foxreq_pr_file_desc *fd;
  uint32_t certificate_verification_performed;
  uint32_t certificate_verified;
  foxreq_nss_result certificate_category;
  int32_t certificate_nss_code;
  int32_t certificate_nspr_code;
  foxreq_nss_result last_category;
  int32_t last_nss_code;
  int32_t last_nspr_code;
  char last_message[FOXREQ_NSS_ERROR_MESSAGE_CAPACITY];
};

struct foxreq_nss_buffer {
  uint32_t magic;
  uint8_t *data;
  size_t length;
};

extern foxreq_nss_api foxreq_real_api;

int foxreq_real_runtime_is_valid(const foxreq_nss_runtime *runtime);
int foxreq_real_cache_is_valid(const foxreq_nss_session_cache *cache);
int foxreq_real_connection_is_valid(const foxreq_nss_connection *connection);
void foxreq_real_runtime_retain(foxreq_nss_runtime *runtime);
void foxreq_real_runtime_release(foxreq_nss_runtime *runtime);
foxreq_nss_result foxreq_real_buffer_create(const uint8_t *data, size_t length,
                                            foxreq_nss_buffer **out_buffer);
foxreq_nss_result foxreq_real_configure_profile(
    foxreq_nss_connection *connection,
    const foxreq_nss_connect_options *options);

#endif
