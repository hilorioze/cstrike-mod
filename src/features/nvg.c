#include <dobby.h>
#include <string.h>

#include "cstrike/abi.h"
#include "features/nvg.h"
#include "globals.h"
#include "goldsrc/abi.h"
#include "loader.h"

static bool g_bServerHasNightVision;
static client_hud_t* g_pHUD;
static void (*gResetOriginal)(client_hud_nightvision_t* nightVision);
static int (*gToggleOriginal)(client_hud_nightvision_t* nightVision, const char* name, int size,
                              void* buffer);

enum {
  // bumped from the default `Com_RandomLong(750, 800)`
  kNvgRadius = 1600,
  // `NVG` in ascii
  kNvgLightKey = 0x4e5647,
};

// only night vision calls `EV_HLDM_CreateLight`, once per frame; each call adds an anonymous light
// that lives 0.1s, so a varying number of them overlap and flicker: reuse one keyed light instead
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters,misc-unused-parameters)
static void CreateLight(float* origin, float radius, int r, int g, int b, float time) {
  dlight_t* light = gEnginefuncs.pEfxAPI->CL_AllocDlight(kNvgLightKey);
  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  memcpy(light->origin, origin, sizeof(light->origin));
  light->radius = kNvgRadius;
  light->color.r = 255;
  light->color.g = 255;
  light->color.b = 255;
  light->die = gEnginefuncs.GetClientTime() + time;
}

static void Reset(client_hud_nightvision_t* nightVision) {
  int enabled = nightVision->m_fOn;

  gResetOriginal(nightVision);

  // the server's `ResetHUD` on every spawn turns night vision off; keep the client toggle and reset
  // only the alpha
  if (!g_bServerHasNightVision)
    nightVision->m_fOn = enabled;
}

// server toggle messages only apply to server night vision
static int Toggle(client_hud_nightvision_t* nightVision, const char* name, int size, void* buffer) {
  if (!g_bServerHasNightVision)
    return 1;

  return gToggleOriginal(nightVision, name, size, buffer);
}

void Nvg_Initialize(void* clientModule) {
  g_bServerHasNightVision = false;
  g_pHUD = RealDlsym(clientModule, "gHUD");

  void* createLight = RealDlsym(clientModule, "_Z19EV_HLDM_CreateLightPffiiif");
  if (DobbyHook(createLight, CreateLight, NULL) != 0)
    __builtin_trap();

  void* reset = RealDlsym(clientModule, "_ZN15CHudNightVision5ResetEv");
  if (DobbyHook(reset, Reset, (void**)&gResetOriginal) != 0)
    __builtin_trap();

  void* toggle = RealDlsym(clientModule, "_ZN15CHudNightVision17MsgFunc_NVGToggleEPKciPv");
  if (DobbyHook(toggle, Toggle, (void**)&gToggleOriginal) != 0)
    __builtin_trap();
}

void Nvg_OnItemStatus(int iItemStatus) {
  bool bServerHasNightVision = (iItemStatus & 1) != 0;  // NOLINT(hicpp-signed-bitwise)

  if (bServerHasNightVision && !g_bServerHasNightVision)
    g_pHUD->m_NightVision.m_fOn = 0;

  g_bServerHasNightVision = bServerHasNightVision;
}

int Nvg_HandleKeyEvent(int down, const char* pszCurrentBinding) {
  if (g_bServerHasNightVision || !pszCurrentBinding ||
      strcmp(pszCurrentBinding, "nightvision") != 0)
    return 0;

  if (down)
    g_pHUD->m_NightVision.m_fOn = !g_pHUD->m_NightVision.m_fOn;

  return 1;
}

int Nvg_ShouldSuppressOverlay(int x, int y, int w, int h, int r, int g, int b, int a) {
  SCREENINFO_t screenInfo = {0};

  screenInfo.iSize = sizeof(screenInfo);

  gEnginefuncs.pfnGetScreenInfo(&screenInfo);

  return g_pHUD->m_NightVision.m_fOn && x == 0 && y == 0 && w == screenInfo.iWidth &&
         h == screenInfo.iHeight && r == 50 && g == 225 && b == 50 &&
         a == g_pHUD->m_NightVision.m_iAlpha;
}
