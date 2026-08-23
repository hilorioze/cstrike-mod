#include <string.h>

#include "cstrike/abi.h"
#include "features/nvg.h"
#include "globals.h"
#include "goldsrc/abi.h"
#include "loader.h"

static bool g_bServerHasNightVision;
static bool g_bNightVisionOn;
static dlight_t* g_pNvgDlight;
static dlight_t* (*g_pfnOriginalCLAllocDlight)(int key);
static void (*g_pfnSendToggle)(int iEnabled);
static int* g_pNvgAlpha;

enum {
  // bumped from the default `Com_RandomLong(750, 800)`
  kNvgRadius = 1600,
};

static dlight_t* pfnCLAllocDlight(int key) {
  dlight_t* pDlight = g_pfnOriginalCLAllocDlight(key);

  if (key == 0)
    g_pNvgDlight = pDlight;

  return pDlight;
}

void Nvg_Initialize(void* clientModule, void (*pfnSendToggle)(int iEnabled)) {
  client_hud_t* pHUD = RealDlsym(clientModule, "gHUD");

  g_bServerHasNightVision = false;
  g_bNightVisionOn = false;
  g_pNvgDlight = NULL;
  g_pfnSendToggle = pfnSendToggle;
  g_pNvgAlpha = &pHUD->m_NightVision.m_iAlpha;

  if (gEnginefuncs.pEfxAPI->CL_AllocDlight != pfnCLAllocDlight)
    g_pfnOriginalCLAllocDlight = gEnginefuncs.pEfxAPI->CL_AllocDlight;

  gEnginefuncs.pEfxAPI->CL_AllocDlight = pfnCLAllocDlight;
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

void Nvg_OnRedraw(void) {
  if (!g_bNightVisionOn || !g_pNvgDlight)
    return;

  g_pNvgDlight->color.r = 255;
  g_pNvgDlight->color.g = 255;
  g_pNvgDlight->color.b = 255;
  g_pNvgDlight->radius = kNvgRadius;
}
