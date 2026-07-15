#include "foxreq_nss_real_internal.h"

typedef struct foxreq_certificate_decoders {
  SRWLOCK lock;
  foxreq_nss_certificate_decoder_fn zlib;
  foxreq_nss_certificate_decoder_fn brotli;
  foxreq_nss_certificate_decoder_fn zstd;
} foxreq_certificate_decoders;

static foxreq_certificate_decoders decoders = {SRWLOCK_INIT, NULL, NULL, NULL};

foxreq_nss_result foxreq_nss_register_certificate_decoders(
    foxreq_nss_runtime *runtime, foxreq_nss_certificate_decoder_fn zlib,
    foxreq_nss_certificate_decoder_fn brotli,
    foxreq_nss_certificate_decoder_fn zstd) {
  foxreq_nss_result result = FOXREQ_NSS_RESULT_OK;
  if (!foxreq_real_runtime_is_valid(runtime) || zlib == NULL || brotli == NULL ||
      zstd == NULL) {
    return FOXREQ_NSS_RESULT_INVALID_ARGUMENT;
  }
  AcquireSRWLockExclusive(&decoders.lock);
  if ((decoders.zlib != NULL && decoders.zlib != zlib) ||
      (decoders.brotli != NULL && decoders.brotli != brotli) ||
      (decoders.zstd != NULL && decoders.zstd != zstd)) {
    result = FOXREQ_NSS_RESULT_STATE;
  } else {
    decoders.zlib = zlib;
    decoders.brotli = brotli;
    decoders.zstd = zstd;
  }
  ReleaseSRWLockExclusive(&decoders.lock);
  return result;
}

static int decode_certificate(foxreq_nss_certificate_decoder_fn decoder,
                              const foxreq_sec_item *input,
                              unsigned char *output, size_t output_length,
                              size_t *used_length) {
  if (decoder == NULL || input == NULL || used_length == NULL ||
      (input->length > 0U && input->data == NULL) ||
      (output_length > 0U && output == NULL)) {
    return -1;
  }
  return decoder(input->data, (size_t)input->length, output, output_length,
                 used_length);
}

int __cdecl foxreq_real_decode_zlib_certificate(
    const foxreq_sec_item *input, unsigned char *output, size_t output_length,
    size_t *used_length) {
  foxreq_nss_certificate_decoder_fn decoder;
  AcquireSRWLockShared(&decoders.lock);
  decoder = decoders.zlib;
  ReleaseSRWLockShared(&decoders.lock);
  return decode_certificate(decoder, input, output, output_length, used_length);
}

int __cdecl foxreq_real_decode_brotli_certificate(
    const foxreq_sec_item *input, unsigned char *output, size_t output_length,
    size_t *used_length) {
  foxreq_nss_certificate_decoder_fn decoder;
  AcquireSRWLockShared(&decoders.lock);
  decoder = decoders.brotli;
  ReleaseSRWLockShared(&decoders.lock);
  return decode_certificate(decoder, input, output, output_length, used_length);
}

int __cdecl foxreq_real_decode_zstd_certificate(
    const foxreq_sec_item *input, unsigned char *output, size_t output_length,
    size_t *used_length) {
  foxreq_nss_certificate_decoder_fn decoder;
  AcquireSRWLockShared(&decoders.lock);
  decoder = decoders.zstd;
  ReleaseSRWLockShared(&decoders.lock);
  return decode_certificate(decoder, input, output, output_length, used_length);
}
