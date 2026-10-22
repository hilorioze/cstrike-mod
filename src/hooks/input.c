#define _GNU_SOURCE  // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

#include <dlfcn.h>

#include "goldsrc/abi.h"
#include "loader.h"
#include "vgui2/abi.h"

enum {
  kKeyCount = 256,
};

static void (*real_Key_Event)(int key, qboolean down);
static void (*real_Key_ClearStates)(void);
static void (*real_ClientDLL_ClearStates)(void);

static void* gVGuiPaint;
static qboolean* gKeyDown;
static IInputInternal** gInputInternal;

static void ResolveEngine(void* caller) {
  Dl_info info;
  dladdr(caller, &info);
  void* engine = dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD);

  real_Key_Event = RealDlsym(engine, "Key_Event");
  real_Key_ClearStates = RealDlsym(engine, "Key_ClearStates");
  real_ClientDLL_ClearStates = RealDlsym(engine, "ClientDLL_ClearStates");
  gVGuiPaint = RealDlsym(engine, "VGuiWrap2_Paint");
  gKeyDown = RealDlsym(engine, "keydown");
  gInputInternal = RealDlsym(engine, "g_InputInternal");
}

// the original releases all 256 keys, and a release runs the `-` command of a `+` bind even for a
// key that isn't held, printing `Unknown command` for every script bind
static void ReleaseEngineKeys(void) {
  for (int key = 0; key < kKeyCount; key++) {
    if (gKeyDown[key])
      real_Key_Event(key, false);
  }

  real_Key_ClearStates();
  real_ClientDLL_ClearStates();
}

// vgui misses the releases sent while the window is out of focus, and a shift or ctrl it still
// holds turns a click in the server browser into a range or toggle selection
static void ReleaseVguiKeys(void) {
  IInputInternal* input = *gInputInternal;

  for (KeyCode code = 0; code < KEY_LAST; code++) {
    if (input->vtable->IsKeyDown(input, code))
      input->vtable->InternalKeyCodeReleased(input, code);
  }
}

// the engine clears the keys when the game ui closes and when the window gets focus back: keep the
// game's keys held across focus changes, e.g. attack, until the key is pressed and released again
__attribute__((visibility("default"))) void ClearIOStates(void) __asm__("_Z13ClearIOStatesv");

void ClearIOStates(void) {
  void* caller = __builtin_return_address(0);
  if (!real_Key_Event)
    ResolveEngine(caller);

  Dl_info info;
  dladdr(caller, &info);
  // focus changes come through `CGame::AppActivate` and its unexported copy, which `dladdr` can't
  // name, so tell them apart from `VGuiWrap2_Paint` instead
  if (info.dli_saddr == gVGuiPaint)
    ReleaseEngineKeys();
  else
    ReleaseVguiKeys();
}
