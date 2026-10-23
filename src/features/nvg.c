#include <dobby.h>
#include <string.h>

#include "cstrike/abi.h"
#include "features/nvg.h"
#include "globals.h"
#include "goldsrc/abi.h"
#include "loader.h"

static bool g_bServerHasNightVision;
static bool g_bNightVisionOn;
static void (*g_pfnSendToggle)(int iEnabled);
static int* g_pNvgAlpha;

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

void Nvg_Initialize(void* clientModule, void (*pfnSendToggle)(int iEnabled)) {
  client_hud_t* pHUD = RealDlsym(clientModule, "gHUD");

  g_bServerHasNightVision = false;
  g_bNightVisionOn = false;
  g_pfnSendToggle = pfnSendToggle;
  g_pNvgAlpha = &pHUD->m_NightVision.m_iAlpha;

  void* createLight = RealDlsym(clientModule, "_Z19EV_HLDM_CreateLightPffiiif");
  if (DobbyHook(createLight, CreateLight, NULL) != 0)
    __builtin_trap();
}

void Nvg_OnItemStatus(int iItemStatus) {
  bool bServerHasNightVision = (iItemStatus & 1) != 0;  // NOLINT(hicpp-signed-bitwise)

  if (bServerHasNightVision && !g_bServerHasNightVision && g_bNightVisionOn)
    g_pfnSendToggle(0);

  g_bServerHasNightVision = bServerHasNightVision;
}

void Nvg_OnToggle(int iEnabled) {
  g_bNightVisionOn = iEnabled != 0;
}

int Nvg_HandleKeyEvent(int down, const char* pszCurrentBinding) {
  if (g_bServerHasNightVision || !pszCurrentBinding ||
      strcmp(pszCurrentBinding, "nightvision") != 0)
    return 0;

  if (down)
    g_pfnSendToggle(!g_bNightVisionOn);

  return 1;
}

int Nvg_ShouldSuppressOverlay(int x, int y, int w, int h, int r, int g, int b, int a) {
  SCREENINFO_t screenInfo = {0};

  screenInfo.iSize = sizeof(screenInfo);

  gEnginefuncs.pfnGetScreenInfo(&screenInfo);

  return g_bNightVisionOn && x == 0 && y == 0 && w == screenInfo.iWidth &&
         h == screenInfo.iHeight && r == 50 && g == 225 && b == 50 && a == *g_pNvgAlpha;
}
