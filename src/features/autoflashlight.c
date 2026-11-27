#define _GNU_SOURCE  // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

#include <dlfcn.h>
#include <stdbool.h>
#include <string.h>

#include "cstrike/player_state.h"
#include "features/autoflashlight.h"
#include "globals.h"
#include "goldsrc/abi.h"
#include "loader.h"
#include "server.h"

enum {
  kImpulseFlashlight = 100,
  kNoKey = -1,
};

static bool gAlive;
static const qboolean* gKeyDown;
static int gFlashlightKey = kNoKey;

void AutoFlashlight_Initialize(void) {
  Dl_info engineInfo;
  if (!dladdr((void*)gEnginefuncs.pfnGetCvarFloat, &engineInfo))
    __builtin_trap();

  void* engineModule = dlopen(engineInfo.dli_fname, RTLD_LAZY | RTLD_NOLOAD);
  if (!engineModule)
    __builtin_trap();

  gKeyDown = RealDlsym(engineModule, "keydown");
  if (!gKeyDown)
    __builtin_trap();

  dlclose(engineModule);
}

// the engine reports a release to the client only for presses the client swallowed, and not at all
// once the console took the keys, so remember the pressed key and follow the engine's own key state
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void AutoFlashlight_HandleKeyEvent(int down, int keynum, const char* pszCurrentBinding) {
  if (down && pszCurrentBinding && strcmp(pszCurrentBinding, "impulse 100") == 0)
    gFlashlightKey = keynum;
}

void AutoFlashlight_OnPostRunCmd(const local_state_t* to) {
  gAlive = PlayerState_IsAlive(to);
}

void AutoFlashlight_CreateMove(usercmd_t* cmd) {
  if (gFlashlightKey == kNoKey)
    return;

  if (!gKeyDown[gFlashlightKey]) {
    gFlashlightKey = kNoKey;

    return;
  }

  // every impulse toggles the flashlight; leave impulses of other binds pressed meanwhile
  if (gAlive && cmd->impulse == 0 && Server_IsFeatureEnabled(kFeatureAutoFlashlight))
    cmd->impulse = kImpulseFlashlight;
}
