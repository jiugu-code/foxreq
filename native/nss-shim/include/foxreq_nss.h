#ifndef FOXREQ_NSS_H
#define FOXREQ_NSS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FOXREQ_NSS_ABI_VERSION UINT32_C(1)

uint32_t foxreq_nss_abi_version(void);

#ifdef __cplusplus
}
#endif

#endif
