#include <winsock2.h>

#include "platform_runtime.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

struct foxreq_platform_path {
  wchar_t *value;
};

void foxreq_platform_mutex_lock(foxreq_platform_mutex *mutex) {
  AcquireSRWLockExclusive(mutex);
}

void foxreq_platform_mutex_unlock(foxreq_platform_mutex *mutex) {
  ReleaseSRWLockExclusive(mutex);
}

int32_t foxreq_platform_atomic_increment(volatile int32_t *value) {
  return (int32_t)InterlockedIncrement((volatile LONG *)value);
}

int32_t foxreq_platform_atomic_decrement(volatile int32_t *value) {
  return (int32_t)InterlockedDecrement((volatile LONG *)value);
}

uint64_t foxreq_platform_monotonic_millis(void) {
  return (uint64_t)GetTickCount64();
}

foxreq_platform_path *foxreq_platform_path_from_utf8(const uint8_t *data,
                                                     size_t length) {
  foxreq_platform_path *path;
  int source_length;
  int wide_length;
  if (data == NULL || length == 0U || length > (size_t)INT_MAX ||
      memchr(data, 0, length) != NULL) {
    return NULL;
  }
  source_length = (int)length;
  wide_length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                    (const char *)data, source_length, NULL, 0);
  if (wide_length <= 0 || wide_length == INT_MAX) {
    return NULL;
  }
  path = (foxreq_platform_path *)calloc(1U, sizeof(*path));
  if (path == NULL) {
    return NULL;
  }
  path->value = (wchar_t *)calloc((size_t)wide_length + 1U, sizeof(wchar_t));
  if (path->value == NULL ||
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)data,
                          source_length, path->value,
                          wide_length) != wide_length) {
    foxreq_platform_path_free(path);
    return NULL;
  }
  return path;
}

int foxreq_platform_path_equals(const foxreq_platform_path *left,
                                const foxreq_platform_path *right) {
  return left != NULL && right != NULL && left->value != NULL &&
         right->value != NULL && wcscmp(left->value, right->value) == 0;
}

void foxreq_platform_path_free(foxreq_platform_path *path) {
  if (path != NULL) {
    free(path->value);
    free(path);
  }
}

static wchar_t *join_path(const foxreq_platform_path *directory,
                          const wchar_t *filename) {
  size_t directory_length = wcslen(directory->value);
  size_t filename_length = wcslen(filename);
  int needs_separator = directory_length > 0U &&
                        directory->value[directory_length - 1U] != L'\\' &&
                        directory->value[directory_length - 1U] != L'/';
  size_t length;
  wchar_t *path;
  if (directory_length > SIZE_MAX - filename_length - 2U) {
    return NULL;
  }
  length = directory_length + filename_length + (size_t)needs_separator + 1U;
  path = (wchar_t *)calloc(length, sizeof(wchar_t));
  if (path == NULL) {
    return NULL;
  }
  memcpy(path, directory->value, directory_length * sizeof(wchar_t));
  if (needs_separator) {
    path[directory_length] = L'\\';
    directory_length += 1U;
  }
  memcpy(path + directory_length, filename,
         (filename_length + 1U) * sizeof(wchar_t));
  return path;
}

static HMODULE load_file(const foxreq_platform_path *directory,
                         const wchar_t *filename) {
  wchar_t *path = join_path(directory, filename);
  HMODULE module = NULL;
  if (path != NULL) {
    module = LoadLibraryExW(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                                           LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
  }
  free(path);
  return module;
}

int foxreq_platform_runtime_load(const foxreq_platform_path *directory,
                                 foxreq_platform_modules *modules,
                                 foxreq_platform_module *out_nss) {
  static const wchar_t *const filenames[] = {
      L"mozglue.dll", L"nss3.dll", L"freebl3.dll", L"softokn3.dll"};
  WSADATA winsock;
  size_t index;
  if (directory == NULL || modules == NULL || out_nss == NULL) {
    return 0;
  }
  memset(modules, 0, sizeof(*modules));
  *out_nss = NULL;
  if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
    return 0;
  }
  modules->network_started = 1;
  for (index = 0U; index < sizeof(filenames) / sizeof(filenames[0]); index++) {
    modules->handles[index] = (foxreq_platform_module)load_file(
        directory, filenames[index]);
    if (modules->handles[index] == NULL) {
      foxreq_platform_runtime_unload(modules);
      return 0;
    }
    modules->count += 1U;
  }
  *out_nss = modules->handles[1];
  return 1;
}

void foxreq_platform_runtime_unload(foxreq_platform_modules *modules) {
  if (modules == NULL) {
    return;
  }
  while (modules->count > 0U) {
    modules->count -= 1U;
    if (modules->handles[modules->count] != NULL) {
      (void)FreeLibrary((HMODULE)modules->handles[modules->count]);
      modules->handles[modules->count] = NULL;
    }
  }
  if (modules->network_started) {
    (void)WSACleanup();
    modules->network_started = 0;
  }
}

foxreq_platform_symbol
foxreq_platform_symbol_lookup(foxreq_platform_module module,
                              const char *name) {
  if (module == NULL || name == NULL) {
    return NULL;
  }
  return (foxreq_platform_symbol)GetProcAddress((HMODULE)module, name);
}
