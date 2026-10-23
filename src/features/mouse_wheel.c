#define _GNU_SOURCE  // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

#include <X11/X.h>
#include <dlfcn.h>
#include <dobby.h>
#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <string.h>

#include "codepatch.h"
#include "features/mouse_wheel.h"
#include "loader.h"

static int (*gSendMouseButtonOriginal)(void* window, uint32_t mouseID, uint8_t state,
                                       uint8_t button);
static int (*gSendMouseWheel)(void* window, uint32_t mouseID, int x, int y);

// bundled sdl takes x11 buttons 4/5 for a wheel step only when the next queued event is their
// release with the same timestamp, otherwise it sends them as mouse buttons 4/5 instead of
// `MWHEELUP`/`MWHEELDOWN`
static int SendMouseButton(void* window, uint32_t mouseID, uint8_t state, uint8_t button) {
  if (button != Button4 && button != Button5)
    return gSendMouseButtonOriginal(window, mouseID, state, button);

  return state ? gSendMouseWheel(window, mouseID, 0, button == Button4 ? 1 : -1) : 0;
}

static void* FindCallTarget(uint8_t* code, size_t codeSize, const uint8_t* call, size_t callSize) {
  uint8_t* next = CodePatch_FindPattern(code, codeSize, call, callSize) + callSize;
  int32_t displacement = 0;
  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  memcpy(&displacement, next - sizeof(displacement), sizeof(displacement));

  return next + displacement;
}

static void HookMouseButtons(uint8_t* code, size_t codeSize) {
  // `SDL_SendMouseButton` and `SDL_SendMouseWheel` aren't exported; take them from the calls in the
  // x11 button press handler
  static const uint8_t buttonCall[] = {0xc7, 0x44, 0x24, 0x08, 0x01, 0x00, 0x00, 0x00, 0xc7,
                                       0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x07,
                                       0x89, 0x04, 0x24, 0xe8, 0xef, 0x77, 0xf9, 0xff};
  static const uint8_t wheelCall[] = {0xc7, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00, 0x00, 0xc7,
                                      0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x07,
                                      0x89, 0x04, 0x24, 0xe8, 0xae, 0x72, 0xf9, 0xff};

  void* sendMouseButton = FindCallTarget(code, codeSize, buttonCall, sizeof(buttonCall));
  gSendMouseWheel = FindCallTarget(code, codeSize, wheelCall, sizeof(wheelCall));

  if (DobbyHook(sendMouseButton, SendMouseButton, (void**)&gSendMouseButtonOriginal) != 0)
    __builtin_trap();
}

void MouseWheel_Initialize(void) {
  void* module = dlopen("libSDL2-2.0.so.0", RTLD_NOW | RTLD_NOLOAD);
  void (*getVersion)(void*) = RealDlsym(module, "SDL_GetVersion");
  dlclose(module);

  uint8_t version[3];
  getVersion(version);
  // sdl2-compat and newer sdl take x11 buttons 4/5 for wheel steps without this check
  if (version[0] != 2 || version[1] != 0 || version[2] != 0)
    return;

  Dl_info info;
  dladdr((void*)getVersion, &info);

  const ElfW(Ehdr)* header = info.dli_fbase;
  const ElfW(Phdr)* segments = (const void*)((const uint8_t*)info.dli_fbase + header->e_phoff);
  for (int i = 0; i < header->e_phnum; i++) {
    if (segments[i].p_type == PT_LOAD && (segments[i].p_flags & PF_X)) {
      HookMouseButtons((uint8_t*)info.dli_fbase + segments[i].p_vaddr, segments[i].p_memsz);

      break;
    }
  }
}
