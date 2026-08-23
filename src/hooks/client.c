#define _GNU_SOURCE  // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include "cstrike/player_state.h"
#include "features/bot.h"
#include "features/buyammo.h"
#include "features/crosshair.h"
#include "features/cstatus.h"
#include "features/nvg.h"
#include "features/player_render.h"
#include "features/scoreboard.h"
#include "globals.h"
#include "goldsrc/abi.h"
#include "hooks/client.h"
#include "loader.h"

typedef struct {
  int (*MsgFunc_ItemStatus)(const char* pszName, int iSize, void* pbuf);
  int (*MsgFunc_Money)(const char* pszName, int iSize, void* pbuf);
  int (*MsgFunc_NVGToggle)(const char* pszName, int iSize, void* pbuf);
  int (*MsgFunc_TeamInfo)(const char* pszName, int iSize, void* pbuf);
} usermsg_orig_funcs_t;

static usermsg_orig_funcs_t gUsermsgOrigFuncs;

static struct {
  void (*BEGIN_READ)(void* buf, int size);
  int (*READ_BYTE)(void);
  int (*READ_LONG)(void);
  const char* (*READ_STRING)(void);
} parsemsg;

static void pfnFillRGBA(int x, int y, int w, int h, int r, int g, int b, int a) {
  if (Nvg_ShouldSuppressOverlay(x, y, w, h, r, g, b, a))
    return;

  gEnginefuncs.pfnFillRGBA(x, y, w, h, r, g, b, a);
}

static int MsgFunc_ItemStatus(const char* pszName, int iSize, void* pbuf) {
  parsemsg.BEGIN_READ(pbuf, iSize);

  int iItemStatus = parsemsg.READ_BYTE();

  Nvg_OnItemStatus(iItemStatus);

  return gUsermsgOrigFuncs.MsgFunc_ItemStatus(pszName, iSize, pbuf);
}

static int MsgFunc_Money(const char* pszName, int iSize, void* pbuf) {
  parsemsg.BEGIN_READ(pbuf, iSize);

  int dollars = parsemsg.READ_LONG();

  BuyAmmo_OnMoney(dollars);

  return gUsermsgOrigFuncs.MsgFunc_Money(pszName, iSize, pbuf);
}

static int MsgFunc_NVGToggle(const char* pszName, int iSize, void* pbuf) {
  parsemsg.BEGIN_READ(pbuf, iSize);

  Nvg_OnToggle(parsemsg.READ_BYTE());

  return gUsermsgOrigFuncs.MsgFunc_NVGToggle(pszName, iSize, pbuf);
}

static void SendNvgToggle(int iEnabled) {
  unsigned char enabled = iEnabled;

  MsgFunc_NVGToggle("NVGToggle", sizeof(enabled), &enabled);
}

static int MsgFunc_TeamInfo(const char* pszName, int iSize, void* pbuf) {
  parsemsg.BEGIN_READ(pbuf, iSize);

  int iPlayer = parsemsg.READ_BYTE();

  PlayerState_SetTeamFromName(iPlayer, parsemsg.READ_STRING());

  return gUsermsgOrigFuncs.MsgFunc_TeamInfo(pszName, iSize, pbuf);
}

// NOLINTNEXTLINE(misc-unused-parameters)
static int MsgFunc_ClCorpse(const char* pszName, int iSize, void* pbuf) {
  return 1;
}

static int pfnHookUserMsg(char* szMsgName, int (*pfn)(const char*, int, void*)) {
  if (strcmp(szMsgName, "ClCorpse") == 0)
    return gEnginefuncs.pfnHookUserMsg(szMsgName, MsgFunc_ClCorpse);

  if (strcmp(szMsgName, "ItemStatus") == 0) {
    gUsermsgOrigFuncs.MsgFunc_ItemStatus = pfn;

    return gEnginefuncs.pfnHookUserMsg(szMsgName, MsgFunc_ItemStatus);
  }

  if (strcmp(szMsgName, "Money") == 0) {
    gUsermsgOrigFuncs.MsgFunc_Money = pfn;

    return gEnginefuncs.pfnHookUserMsg(szMsgName, MsgFunc_Money);
  }

  if (strcmp(szMsgName, "NVGToggle") == 0) {
    gUsermsgOrigFuncs.MsgFunc_NVGToggle = pfn;

    return gEnginefuncs.pfnHookUserMsg(szMsgName, MsgFunc_NVGToggle);
  }

  if (strcmp(szMsgName, "TeamInfo") == 0) {
    gUsermsgOrigFuncs.MsgFunc_TeamInfo = pfn;

    return gEnginefuncs.pfnHookUserMsg(szMsgName, MsgFunc_TeamInfo);
  }

  return gEnginefuncs.pfnHookUserMsg(szMsgName, pfn);
}

static void pfnGetPlayerInfo(int ent_num, hud_player_info_t* pinfo) {
  gEnginefuncs.pfnGetPlayerInfo(ent_num, pinfo);

  Bot_ApplyPlayerInfo(ent_num, pinfo);
}

static const char* PlayerInfo_ValueForKey(int playerNum, const char* key) {
  const char* value = gEnginefuncs.PlayerInfo_ValueForKey(playerNum, key);

  return Bot_OverridePlayerInfoValue(playerNum, key, value);
}

static int ResolveParsemsgFromModule(void* module) {
  void (*pfnBeginRead)(void* buf, int size) = RealDlsym(module, "_Z10BEGIN_READPvi");
  int (*pfnReadByte)(void) = RealDlsym(module, "_Z9READ_BYTEv");
  int (*pfnReadLong)(void) = RealDlsym(module, "_Z9READ_LONGv");
  const char* (*pfnReadString)(void) = RealDlsym(module, "_Z11READ_STRINGv");

  if (pfnBeginRead && pfnReadByte && pfnReadLong && pfnReadString) {
    parsemsg.BEGIN_READ = pfnBeginRead;
    parsemsg.READ_BYTE = pfnReadByte;
    parsemsg.READ_LONG = pfnReadLong;
    parsemsg.READ_STRING = pfnReadString;

    return 1;
  }

  return 0;
}

static int IsCsldrProxy(void* module) {
  const char** pProgramVersion = (const char**)RealDlsym(module, "programVersion");
  if (!pProgramVersion || !*pProgramVersion)
    return 0;

  return strncmp(*pProgramVersion, "\ncsldr version:", sizeof("\ncsldr version:") - 1) == 0;
}

static void* ResolveClientModule(void) {
  Dl_info clientInfo;
  if (!dladdr((void*)gClientOrigFuncs.Initialize, &clientInfo))
    __builtin_trap();

  void* immediateModule = dlopen(clientInfo.dli_fname, RTLD_LAZY | RTLD_NOLOAD);
  if (!immediateModule)
    __builtin_trap();

  if (!IsCsldrProxy(immediateModule))
    return immediateModule;

  dlclose(immediateModule);

  size_t clientDirectoryLength = strlen(clientInfo.dli_fname) - strlen("client.so");
  char clientPath[clientDirectoryLength + sizeof("client_orig.so")];
  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
  (void)snprintf(clientPath, sizeof(clientPath), "%.*sclient_orig.so", (int)clientDirectoryLength,
                 clientInfo.dli_fname);

  void* clientOrigModule = dlopen(clientPath, RTLD_LAZY | RTLD_NOLOAD);
  if (!clientOrigModule)
    __builtin_trap();

  return clientOrigModule;
}

static void ResolveParsemsg(void* clientModule) {
  if (!ResolveParsemsgFromModule(clientModule))
    __builtin_trap();
}

int Initialize(cl_enginefunc_t* pEnginefuncs, int iVersion) {
  void* clientModule = ResolveClientModule();
  ResolveParsemsg(clientModule);

  gEnginefuncs = *pEnginefuncs;
  Nvg_Initialize(clientModule, SendNvgToggle);
  Crosshair_Initialize(clientModule);

  pEnginefuncs->pfnHookUserMsg = pfnHookUserMsg;
  pEnginefuncs->pfnFillRGBA = pfnFillRGBA;
  pEnginefuncs->pfnGetPlayerInfo = pfnGetPlayerInfo;
  pEnginefuncs->PlayerInfo_ValueForKey = PlayerInfo_ValueForKey;

  dlclose(clientModule);

  pEnginefuncs->pfnAddCommand("cstatus", CStatus_Command);

  Scoreboard_Initialize();

  return gClientOrigFuncs.Initialize(pEnginefuncs, iVersion);
}

int HUD_AddEntity(int type, cl_entity_t* ent, const char* modelname) {
  PlayerRender_ApplyEntity(type, ent, modelname);

  return gClientOrigFuncs.HUD_AddEntity(type, ent, modelname);
}

int HUD_Key_Event(int down, int keynum, const char* pszCurrentBinding) {
  if (Nvg_HandleKeyEvent(down, pszCurrentBinding))
    return 0;

  return gClientOrigFuncs.HUD_Key_Event(down, keynum, pszCurrentBinding);
}

int HUD_Redraw(float flTime, int intermission) {
  int iResult = gClientOrigFuncs.HUD_Redraw(flTime, intermission);

  Nvg_OnRedraw();

  return iResult;
}
