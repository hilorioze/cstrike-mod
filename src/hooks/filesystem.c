#define _GNU_SOURCE  // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#include "loader.h"

enum {
  kDirectoryBuckets = 1024,
  kLegacyStatVersion = 3,
  kWatchedEvents =
      IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF,
};

typedef struct directory_s {
  struct directory_s* next;
  char* path;
  char** names;
  int count;
} directory_t;

// the engine's `struct stat` is the 32-bit layout of the legacy `__xstat`, the same one
// `filesystem_stdio.so` calls
int LegacyStat(int version, const char* path, struct stat* status);
__asm__(".symver LegacyStat,__xstat@GLIBC_2.0");

static FILE* (*real_FS_fopen)(void* filesystem, const char* path, const char* mode, bool fromCache);

// the CD audio thread of `hw.so` looks up mp3 tracks through the filesystem too
static pthread_mutex_t gLock = PTHREAD_MUTEX_INITIALIZER;
static char gSteamPath[PATH_MAX + 1];
static size_t gSteamPathLength;
static int gNotify;
static directory_t* gDirectories[kDirectoryBuckets];

static uint32_t HashPath(const char* path) {
  uint32_t hash = 2166136261U;
  for (; *path; path++)
    hash = (hash ^ (uint8_t)*path) * 16777619U;

  return hash % kDirectoryBuckets;
}

static void ForgetDirectories(void) {
  for (int i = 0; i < kDirectoryBuckets; i++) {
    while (gDirectories[i]) {
      directory_t* directory = gDirectories[i];
      gDirectories[i] = directory->next;

      for (int name = 0; name < directory->count; name++)
        free(directory->names[name]);
      free(directory->names);
      free(directory->path);
      free(directory);
    }
  }
}

static void ForgetChangedDirectories(void) {
  char events[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
  if (read(gNotify, events, sizeof(events)) <= 0)
    return;

  // drop every listing, not just the changed one: a renamed or replaced directory also stales the
  // listings cached under its old path
  ForgetDirectories();
  close(gNotify);
  gNotify = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
}

static directory_t* ListDirectory(const char* path) {
  directory_t* directory = calloc(1, sizeof(*directory));
  directory->path = strdup(path);

  const char* directoryPath = *path ? path : ".";
  int capacity = 0;

  // watch before reading so a change during `readdir` still drops the listing
  inotify_add_watch(gNotify, directoryPath, kWatchedEvents);

  // components that turn out to be files are listed as empty directories
  DIR* dir = opendir(directoryPath);
  if (dir) {
    for (struct dirent* entry = readdir(dir); entry; entry = readdir(dir)) {
      if (directory->count == capacity) {
        capacity = capacity ? capacity * 2 : 16;
        directory->names = realloc(directory->names, capacity * sizeof(*directory->names));
      }

      directory->names[directory->count++] = strdup(entry->d_name);
    }

    closedir(dir);
  }

  return directory;
}

static directory_t* GetDirectory(char* path, size_t length) {
  char next = path[length];
  path[length] = '\0';

  uint32_t bucket = HashPath(path);
  directory_t* directory = gDirectories[bucket];
  while (directory && strcmp(directory->path, path) != 0)
    directory = directory->next;

  if (!directory) {
    directory = ListDirectory(path);
    directory->next = gDirectories[bucket];
    gDirectories[bucket] = directory;
  }

  path[length] = next;

  return directory;
}

static bool HasName(const directory_t* directory, const char* name, size_t length) {
  for (int i = 0; i < directory->count; i++) {
    if (strlen(directory->names[i]) == length && memcmp(directory->names[i], name, length) == 0)
      return true;
  }

  return false;
}

// the engine's `Descend` over cached listings: keep the current spelling of a component if it
// exists, otherwise try its other spellings in `readdir` order and backtrack when the rest of the
// path doesn't resolve under one
static bool ResolveComponent(char* path, size_t begin) {
  if (!path[begin])
    return true;

  size_t end = begin + strcspn(path + begin, "/");
  size_t length = end - begin;
  bool last = !path[end];
  directory_t* directory = GetDirectory(path, begin);

  if ((length == 0 || HasName(directory, path + begin, length)) &&
      (last || ResolveComponent(path, end + 1)))
    return true;

  for (int i = 0; i < directory->count; i++) {
    const char* name = directory->names[i];
    if (strlen(name) != length || strncasecmp(name, path + begin, length) != 0 ||
        memcmp(name, path + begin, length) == 0)
      continue;

    memcpy(path + begin, name, length);
    if (last || ResolveComponent(path, end + 1))
      return true;
  }

  return false;
}

// the engine's `pathmatch`: keep the spelling of the steam path, lowercase the rest, then find the
// existing spelling of every component
static bool ResolveCase(const char* path, char* resolved) {
  pthread_mutex_lock(&gLock);

  if (!gSteamPathLength) {
    char steamLink[PATH_MAX];
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    (void)snprintf(steamLink, sizeof(steamLink), "%s/.steam/steam", getenv("HOME"));
    char* steamPath = realpath(steamLink, NULL);
    gSteamPathLength = snprintf(gSteamPath, sizeof(gSteamPath), "%s/", steamPath);
    free(steamPath);

    gNotify = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
  }

  ForgetChangedDirectories();

  strcpy(resolved, path);

  size_t begin = resolved[0] == '/';
  if (strncasecmp(resolved, gSteamPath, gSteamPathLength) == 0) {
    memcpy(resolved, gSteamPath, gSteamPathLength);
    begin = gSteamPathLength;
  }

  for (char* c = resolved + begin; *c; c++)
    *c = tolower(*c);

  bool found = ResolveComponent(resolved, begin);

  pthread_mutex_unlock(&gLock);

  return found;
}

// `filesystem_stdio.so` resolves the case of every missing path by scanning each directory on it
// with `opendir`, twice per miss, and the engine probes many missing paths while connecting
__attribute__((visibility("default"))) FILE* FS_fopen(
    void* filesystem, const char* path, const char* mode,
    bool fromCache) __asm__("_ZN17CFileSystem_Stdio8FS_fopenEPKcS1_b");

FILE* FS_fopen(void* filesystem, const char* path, const char* mode, bool fromCache) {
  // writes keep the engine's own choice of the parent directory and the new file's spelling
  if (strpbrk(mode, "wa+")) {
    if (!real_FS_fopen) {
      Dl_info info;
      dladdr(*(void**)filesystem, &info);
      void* library = dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD);
      real_FS_fopen = RealDlsym(library, "_ZN17CFileSystem_Stdio8FS_fopenEPKcS1_b");
    }

    return real_FS_fopen(filesystem, path, mode, fromCache);
  }

  FILE* file = fopen(path, mode);
  if (file)
    return file;

  char resolved[strlen(path) + 1];
  if (!ResolveCase(path, resolved))
    return NULL;

  return fopen(resolved, mode);
}

__attribute__((visibility("default"))) int FS_stat(
    void* filesystem, const char* path,
    struct stat* status) __asm__("_ZN17CFileSystem_Stdio7FS_statEPKcP4stat");

// NOLINTNEXTLINE(misc-unused-parameters)
int FS_stat(void* filesystem, const char* path, struct stat* status) {
  if (LegacyStat(kLegacyStatVersion, path, status) == 0)
    return 0;

  char resolved[strlen(path) + 1];
  if (!ResolveCase(path, resolved))
    return -1;

  return LegacyStat(kLegacyStatVersion, resolved, status);
}
