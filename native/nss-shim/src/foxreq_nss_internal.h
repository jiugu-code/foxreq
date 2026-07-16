#ifndef FOXREQ_NSS_INTERNAL_H
#define FOXREQ_NSS_INTERNAL_H

#include "foxreq_nss.h"

#include <stddef.h>

#define FOXREQ_NSS_RUNTIME_MAGIC UINT32_C(0x46585254)
#define FOXREQ_NSS_CACHE_MAGIC UINT32_C(0x46584348)
#define FOXREQ_NSS_CONNECTION_MAGIC UINT32_C(0x4658434E)
#define FOXREQ_NSS_BUFFER_MAGIC UINT32_C(0x46584246)
#define FOXREQ_NSS_ERROR_MESSAGE_CAPACITY 256U
#define FOXREQ_NSS_PROFILE_140 UINT32_C(140)
#define FOXREQ_NSS_PROFILE_152 UINT32_C(152)

struct foxreq_nss_runtime {
  uint32_t magic;
  uint32_t profile;
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
  uint8_t *negotiated_alpn;
  size_t negotiated_alpn_length;
  uint8_t *read_data;
  size_t read_length;
  size_t read_offset;
  size_t read_limit;
  uint8_t *written_data;
  size_t written_length;
  size_t written_capacity;
  size_t write_limit;
  uint32_t close_calls;
  uint32_t pending_operation;
  foxreq_nss_result pending_category;
  int32_t pending_nss_code;
  int32_t pending_nspr_code;
  char pending_message[FOXREQ_NSS_ERROR_MESSAGE_CAPACITY];
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

#endif
