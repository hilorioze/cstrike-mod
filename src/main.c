#define _GNU_SOURCE  // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

#include <dlfcn.h>
#include <stddef.h>
#include <string.h>

#include "globals.h"
#include "hooks/client.h"
#include "hooks/studio.h"
#include "loader.h"

static void* (*real_dlsym)(void*, const char*);

void* RealDlsym(void* handle, const char* symbol) {
  if (!real_dlsym) {
    real_dlsym = dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.0");
  }

  return real_dlsym(handle, symbol);
}

static struct {
  const char* name;
  const char* lib;
  void* original;
  void* hook;
} dlsym_hooks[] = {
    {"dlsym", NULL, NULL, dlsym},
    {"Initialize", "cstrike/cl_dlls/client.so", &gClientOrigFuncs.Initialize, Initialize},
    {"HUD_AddEntity", "cstrike/cl_dlls/client.so", &gClientOrigFuncs.HUD_AddEntity, HUD_AddEntity},
    {"HUD_Key_Event", "cstrike/cl_dlls/client.so", &gClientOrigFuncs.HUD_Key_Event, HUD_Key_Event},
    {"HUD_Redraw", "cstrike/cl_dlls/client.so", &gClientOrigFuncs.HUD_Redraw, HUD_Redraw},
    {"HUD_GetStudioModelInterface", "cstrike/cl_dlls/client.so",
     &gClientOrigFuncs.HUD_GetStudioModelInterface, HUD_GetStudioModelInterface},
    {NULL}};

__attribute__((visibility("default"))) void* dlsym(void* handle, const char* symbol) {
  void* ptr = RealDlsym(handle, symbol);
  Dl_info info;

  for (int i = 0; dlsym_hooks[i].name; i++) {
    if (strcmp(symbol, dlsym_hooks[i].name) != 0)
      continue;

    if (dlsym_hooks[i].lib && (!dladdr(ptr, &info) || !strstr(info.dli_fname, dlsym_hooks[i].lib)))
      continue;

    if (dlsym_hooks[i].original)
      *(void**)dlsym_hooks[i].original = ptr;

    return dlsym_hooks[i].hook;
  }

  return ptr;
}
