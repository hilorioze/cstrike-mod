#define _GNU_SOURCE  // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include "cstrike/player_state.h"
#include "features/auth.h"
#include "features/autopistol.h"
#include "features/autoreload.h"
#include "features/autoshotgun.h"
#include "features/bot.h"
#include "features/buyammo.h"
#include "features/chat.h"
#include "features/crosshair.h"
#include "features/cstatus.h"
#include "features/health_warning.h"
#include "features/intermission.h"
#include "features/mouse_wheel.h"
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

static void ResolveParsemsg(void* clientModule) {
  parsemsg.BEGIN_READ = RealDlsym(clientModule, "_Z10BEGIN_READPvi");
  parsemsg.READ_BYTE = RealDlsym(clientModule, "_Z9READ_BYTEv");
  parsemsg.READ_LONG = RealDlsym(clientModule, "_Z9READ_LONGv");
  parsemsg.READ_STRING = RealDlsym(clientModule, "_Z11READ_STRINGv");

  if (!parsemsg.BEGIN_READ || !parsemsg.READ_BYTE || !parsemsg.READ_LONG || !parsemsg.READ_STRING)
    __builtin_trap();
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

int Initialize(cl_enginefunc_t* pEnginefuncs, int iVersion) {
  void* clientModule = ResolveClientModule();
  ResolveParsemsg(clientModule);

  gEnginefuncs = *pEnginefuncs;
  Auth_Initialize();
  Nvg_Initialize(clientModule);
  Crosshair_Initialize(clientModule);
  Chat_Initialize(clientModule);
  HealthWarning_Initialize(clientModule);
  Intermission_Initialize();
  MouseWheel_Initialize();

  pEnginefuncs->pfnHookUserMsg = pfnHookUserMsg;
  pEnginefuncs->pfnFillRGBA = pfnFillRGBA;
  pEnginefuncs->pfnGetPlayerInfo = pfnGetPlayerInfo;
  pEnginefuncs->PlayerInfo_ValueForKey = PlayerInfo_ValueForKey;

  pEnginefuncs->pfnAddCommand("cstatus", CStatus_Command);

  Scoreboard_Initialize(clientModule);

  dlclose(clientModule);

  return gClientOrigFuncs.Initialize(pEnginefuncs, iVersion);
}

void CL_CreateMove(float frametime, usercmd_t* cmd, int active) {
  gClientOrigFuncs.CL_CreateMove(frametime, cmd, active);

  // auto-reload tells the player's own attack presses apart, so it sees the command before the
  // features releasing attack
  if (active) {
    AutoReload_CreateMove(cmd);
    AutoPistol_CreateMove(cmd);
    AutoShotgun_CreateMove(cmd);
  }
}

void HUD_PostRunCmd(local_state_t* from, local_state_t* to, usercmd_t* cmd, int runfuncs,
                    double time, unsigned int random_seed) {
  gClientOrigFuncs.HUD_PostRunCmd(from, to, cmd, runfuncs, time, random_seed);

  AutoPistol_OnPostRunCmd(to);
  AutoReload_OnPostRunCmd(to);
  AutoShotgun_OnPostRunCmd(to);
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
