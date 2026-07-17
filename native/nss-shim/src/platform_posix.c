#include "platform_runtime.h"

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct foxreq_platform_path {
  char *value;
};

void foxreq_platform_mutex_lock(foxreq_platform_mutex *mutex) {
  (void)pthread_mutex_lock(mutex);
}

void foxreq_platform_mutex_unlock(foxreq_platform_mutex *mutex) {
  (void)pthread_mutex_unlock(mutex);
}

int32_t foxreq_platform_atomic_increment(volatile int32_t *value) {
  return __atomic_add_fetch(value, INT32_C(1), __ATOMIC_SEQ_CST);
}

int32_t foxreq_platform_atomic_decrement(volatile int32_t *value) {
  return __atomic_sub_fetch(value, INT32_C(1), __ATOMIC_SEQ_CST);
}

uint64_t foxreq_platform_monotonic_millis(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
    return UINT64_C(0);
  }
  return (uint64_t)value.tv_sec * UINT64_C(1000) +
         (uint64_t)value.tv_nsec / UINT64_C(1000000);
}

foxreq_platform_path *foxreq_platform_path_from_utf8(const uint8_t *data,
                                                     size_t length) {
  foxreq_platform_path *path;
  if (data == NULL || length == 0U || length == SIZE_MAX ||
      memchr(data, 0, length) != NULL) {
    return NULL;
  }
  path = (foxreq_platform_path *)calloc(1U, sizeof(*path));
  if (path == NULL) {
    return NULL;
  }
  path->value = (char *)malloc(length + 1U);
  if (path->value == NULL) {
    free(path);
    return NULL;
  }
  memcpy(path->value, data, length);
  path->value[length] = '\0';
  return path;
}

int foxreq_platform_path_equals(const foxreq_platform_path *left,
                                const foxreq_platform_path *right) {
  return left != NULL && right != NULL && left->value != NULL &&
         right->value != NULL && strcmp(left->value, right->value) == 0;
}

void foxreq_platform_path_free(foxreq_platform_path *path) {
  if (path != NULL) {
    free(path->value);
    free(path);
  }
}

static char *join_path(const foxreq_platform_path *directory,
                       const char *filename) {
  size_t directory_length = strlen(directory->value);
  size_t filename_length = strlen(filename);
  int needs_separator =
      directory_length > 0U && directory->value[directory_length - 1U] != '/';
  size_t length;
  char *path;
  if (directory_length > SIZE_MAX - filename_length - 2U) {
    return NULL;
  }
  length = directory_length + filename_length + (size_t)needs_separator + 1U;
  path = (char *)malloc(length);
  if (path == NULL) {
    return NULL;
  }
  memcpy(path, directory->value, directory_length);
  if (needs_separator) {
    path[directory_length] = '/';
    directory_length += 1U;
  }
  memcpy(path + directory_length, filename, filename_length + 1U);
  return path;
}

int foxreq_platform_runtime_load(const foxreq_platform_path *directory,
                                 foxreq_platform_modules *modules,
                                 foxreq_platform_module *out_nss) {
  char *path;
  void *module;
  if (directory == NULL || modules == NULL || out_nss == NULL) {
    return 0;
  }
  memset(modules, 0, sizeof(*modules));
  *out_nss = NULL;
  /* libssl3 is the Linux aggregation root for the SSL entry points while its
   * dependency graph also exposes NSS, CERT and NSPR symbols. */
  path = join_path(directory, "libssl3.so");
  if (path == NULL) {
    return 0;
  }
  module = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  free(path);
  if (module == NULL) {
    return 0;
  }
  modules->handles[0] = module;
  modules->count = 1U;
  *out_nss = module;
  return 1;
}

void foxreq_platform_runtime_unload(foxreq_platform_modules *modules) {
  if (modules == NULL) {
    return;
  }
  while (modules->count > 0U) {
    modules->count -= 1U;
    if (modules->handles[modules->count] != NULL) {
      (void)dlclose(modules->handles[modules->count]);
      modules->handles[modules->count] = NULL;
    }
  }
}

foxreq_platform_symbol
foxreq_platform_symbol_lookup(foxreq_platform_module module,
                              const char *name) {
  foxreq_platform_symbol result = NULL;
  void *symbol;
  if (module == NULL || name == NULL) {
    return NULL;
  }
  symbol = dlsym(module, name);
  if (symbol != NULL && sizeof(result) == sizeof(symbol)) {
    memcpy(&result, &symbol, sizeof(result));
  }
  return result;
}
