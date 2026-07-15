#include "foxreq_nss_real_internal.h"

#include <stdlib.h>
#include <string.h>

static int buffer_is_valid(const foxreq_nss_buffer *buffer) {
  return buffer != NULL && buffer->magic == FOXREQ_NSS_BUFFER_MAGIC;
}

foxreq_nss_result foxreq_real_buffer_create(const uint8_t *data, size_t length,
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
  *out_buffer = buffer;
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
  }
  free(buffer->data);
  free(buffer);
}
