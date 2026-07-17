#ifndef FOXREQ_PLATFORM_RUNTIME_H
#define FOXREQ_PLATFORM_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
typedef SRWLOCK foxreq_platform_mutex;
#define FOXREQ_PLATFORM_MUTEX_INITIALIZER SRWLOCK_INIT
#else
#include <pthread.h>
typedef pthread_mutex_t foxreq_platform_mutex;
#define FOXREQ_PLATFORM_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#ifndef __cdecl
#define __cdecl
#endif
#endif

#define FOXREQ_PLATFORM_MODULE_CAPACITY 4U

typedef struct foxreq_platform_path foxreq_platform_path;
typedef void *foxreq_platform_module;
typedef void(__cdecl *foxreq_platform_symbol)(void);

typedef struct foxreq_platform_modules {
  foxreq_platform_module handles[FOXREQ_PLATFORM_MODULE_CAPACITY];
  size_t count;
  int network_started;
} foxreq_platform_modules;

void foxreq_platform_mutex_lock(foxreq_platform_mutex *mutex);
void foxreq_platform_mutex_unlock(foxreq_platform_mutex *mutex);
int32_t foxreq_platform_atomic_increment(volatile int32_t *value);
int32_t foxreq_platform_atomic_decrement(volatile int32_t *value);
uint64_t foxreq_platform_monotonic_millis(void);

foxreq_platform_path *foxreq_platform_path_from_utf8(const uint8_t *data,
                                                     size_t length);
int foxreq_platform_path_equals(const foxreq_platform_path *left,
                                const foxreq_platform_path *right);
void foxreq_platform_path_free(foxreq_platform_path *path);

int foxreq_platform_runtime_load(const foxreq_platform_path *directory,
                                 foxreq_platform_modules *modules,
                                 foxreq_platform_module *out_nss);
void foxreq_platform_runtime_unload(foxreq_platform_modules *modules);
foxreq_platform_symbol
foxreq_platform_symbol_lookup(foxreq_platform_module module,
                              const char *name);

#endif
