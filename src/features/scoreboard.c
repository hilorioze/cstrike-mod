#define _GNU_SOURCE  // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

#include <dlfcn.h>
#include <dobby.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "codepatch.h"
#include "cstrike/abi.h"
#include "cstrike/player_state.h"
#include "features/scoreboard.h"
#include "globals.h"
#include "goldsrc/abi.h"
#include "loader.h"

typedef void (*scoreboard_update_player_info_t)(void* dialog);

static uint8_t* gScoreboardAddSection;
static uint8_t* gScoreboardConstructor;
static uint8_t* gScoreboardUpdateTeamInfo;
static uint8_t* gScoreboardUpdateColumnInAllSections;
static scoreboard_update_player_info_t gScoreboardUpdateTeamInfoOriginal;
static scoreboard_update_player_info_t gScoreboardUpdatePlayerInfo;
static scoreboard_update_player_info_t gScoreboardUpdatePlayerInfoOriginal;
static extra_player_info_t* gScoreboardPlayerExtraInfo;

int Scoreboard_GetPlayerTeam(int index) {
  return gScoreboardPlayerExtraInfo[index].teamnumber;
}

int Scoreboard_IsPlayerDead(int index) {
  return gScoreboardPlayerExtraInfo[index].dead;
}

static void ResolveScoreboardSymbols(void) {
  Dl_info clientInfo;
  if (!dladdr(gClientOrigFuncs.Initialize, &clientInfo))
    __builtin_trap();

  void* clientHandle = dlopen(clientInfo.dli_fname, RTLD_LAZY | RTLD_NOLOAD);
  if (!clientHandle)
    __builtin_trap();

  if (!RealDlsym(clientHandle, "g_PlayerExtraInfo")) {
    dlclose(clientHandle);

    // under `csldr`, the VGUI scoreboard lives in adjacent `client_orig.so`
    size_t clientDirectoryLength = strlen(clientInfo.dli_fname) - strlen("client.so");
    char clientPath[clientDirectoryLength + sizeof("client_orig.so")];
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    (void)snprintf(clientPath, sizeof(clientPath), "%.*sclient_orig.so", (int)clientDirectoryLength,
                   clientInfo.dli_fname);

    clientHandle = dlopen(clientPath, RTLD_LAZY | RTLD_NOLOAD);
    if (!clientHandle)
      __builtin_trap();
  }

  gScoreboardAddSection = RealDlsym(clientHandle, "_ZN25CCSClientScoreBoardDialog10AddSectionEii");
  gScoreboardConstructor =
      RealDlsym(clientHandle, "_ZN25CCSClientScoreBoardDialogC1EPN5vgui25PanelE");
  gScoreboardUpdateTeamInfo =
      RealDlsym(clientHandle, "_ZN25CCSClientScoreBoardDialog14UpdateTeamInfoEv");
  gScoreboardUpdateColumnInAllSections =
      RealDlsym(clientHandle, "_ZN25CCSClientScoreBoardDialog25UpdateColumnInAllSectionsEPKcPKwib");
  gScoreboardUpdatePlayerInfo =
      RealDlsym(clientHandle, "_ZN25CCSClientScoreBoardDialog16UpdatePlayerInfoEv");
  gScoreboardPlayerExtraInfo = RealDlsym(clientHandle, "g_PlayerExtraInfo");

  if (!gScoreboardAddSection || !gScoreboardConstructor || !gScoreboardUpdateTeamInfo ||
      !gScoreboardUpdateColumnInAllSections || !gScoreboardUpdatePlayerInfo ||
      !gScoreboardPlayerExtraInfo)
    __builtin_trap();

  dlclose(clientHandle);
}

static void PatchScoreboardSpectatorSection(void) {
  Dl_info constructorInfo;
  const ElfW(Sym)* constructorSymbol = NULL;
  if (!dladdr1(gScoreboardConstructor, &constructorInfo, (void**)&constructorSymbol,
               RTLD_DL_SYMENT) ||
      !constructorSymbol)
    __builtin_trap();

  // include spectator team `3` in `m_iNumTeams` so `UpdateTeamInfo` renders its header
  static const uint8_t scoreboardTeamCount[] = {
      0xba, 0x02, 0x00, 0x00, 0x00, 0x89, 0x83, 0x4c, 0x04, 0x00,
      0x00, 0x31, 0xc0, 0x89, 0x93, 0x10, 0x01, 0x00, 0x00,
  };
  uint8_t includeSpectatorTeamInTable[] = {0x03};

  uint8_t* scoreboardTeamCountMatch =
      CodePatch_FindPattern(gScoreboardConstructor, constructorSymbol->st_size, scoreboardTeamCount,
                            sizeof(scoreboardTeamCount));
  CodePatch_Apply(scoreboardTeamCountMatch + 1, includeSpectatorTeamInTable,
                  sizeof(includeSpectatorTeamInTable));

  Dl_info addSectionInfo;
  const ElfW(Sym)* addSectionSymbol = NULL;
  if (!dladdr1(gScoreboardAddSection, &addSectionInfo, (void**)&addSectionSymbol, RTLD_DL_SYMENT) ||
      !addSectionSymbol)
    __builtin_trap();

  // redirect `cmp [esp + 0x54], 2; je` to the full layout with rel32 `0x10b`
  static const uint8_t spectatorLayoutBranch[] = {
      0x83, 0x7c, 0x24, 0x54, 0x02, 0x0f, 0x84, 0x73, 0x04, 0x00, 0x00,
  };
  uint8_t fullLayoutBranchDisplacement[] = {0x0b, 0x01, 0x00, 0x00};

  // preserve spectator team `3` in `[esp + 0x28]` and fill the shorter replacement with `nops`
  static const uint8_t spectatorSectionNumber[] = {
      0x31, 0xd2, 0x83, 0xfe, 0x02, 0x0f, 0x94, 0xc2, 0x01, 0xd2, 0x89, 0x54, 0x24, 0x28,
  };
  uint8_t preserveSectionNumber[] = {
      0x89, 0x74, 0x24, 0x28, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
  };

  uint8_t* spectatorLayoutBranchMatch =
      CodePatch_FindPattern(gScoreboardAddSection, addSectionSymbol->st_size, spectatorLayoutBranch,
                            sizeof(spectatorLayoutBranch));
  uint8_t* spectatorSectionNumberMatch =
      CodePatch_FindPattern(gScoreboardAddSection, addSectionSymbol->st_size,
                            spectatorSectionNumber, sizeof(spectatorSectionNumber));

  uint8_t* spectatorLayoutBranchDisplacement = spectatorLayoutBranchMatch +
                                               sizeof(spectatorLayoutBranch) -
                                               sizeof(fullLayoutBranchDisplacement);
  CodePatch_Apply(spectatorLayoutBranchDisplacement, fullLayoutBranchDisplacement,
                  sizeof(fullLayoutBranchDisplacement));
  CodePatch_Apply(spectatorSectionNumberMatch, preserveSectionNumber,
                  sizeof(preserveSectionNumber));

  Dl_info updateColumnInfo;
  const ElfW(Sym)* updateColumnSymbol = NULL;
  if (!dladdr1(gScoreboardUpdateColumnInAllSections, &updateColumnInfo, (void**)&updateColumnSymbol,
               RTLD_DL_SYMENT) ||
      !updateColumnSymbol)
    __builtin_trap();

  // make section `3` receive the same column widths as sections `0`, `1`, and `2`
  static const uint8_t spectatorColumnUpdateBranch[] = {
      0x84,
      0xdb,
      0x75,
      0x19,
  };
  uint8_t updateSpectatorSection[] = {0xeb};

  uint8_t* spectatorColumnUpdateMatch =
      CodePatch_FindPattern(gScoreboardUpdateColumnInAllSections, updateColumnSymbol->st_size,
                            spectatorColumnUpdateBranch, sizeof(spectatorColumnUpdateBranch));
  CodePatch_Apply(spectatorColumnUpdateMatch + 2, updateSpectatorSection,
                  sizeof(updateSpectatorSection));

  Dl_info updateTeamInfo;
  const ElfW(Sym)* updateTeamInfoSymbol = NULL;
  if (!dladdr1(gScoreboardUpdateTeamInfo, &updateTeamInfo, (void**)&updateTeamInfoSymbol,
               RTLD_DL_SYMENT) ||
      !updateTeamInfoSymbol)
    __builtin_trap();

  // include spectator team `3` in the original team-count loop
  static const uint8_t spectatorTeamCountLimit[] = {
      0x8d, 0x4a, 0xff, 0x83, 0xf9, 0x01, 0x77, 0xad,
  };
  uint8_t includeSpectatorTeam[] = {0x02};

  uint8_t* spectatorTeamCountLimitMatch =
      CodePatch_FindPattern(gScoreboardUpdateTeamInfo, updateTeamInfoSymbol->st_size,
                            spectatorTeamCountLimit, sizeof(spectatorTeamCountLimit));
  CodePatch_Apply(spectatorTeamCountLimitMatch + 5, includeSpectatorTeam,
                  sizeof(includeSpectatorTeam));
}

static int IsSpectatorScoreboardPlayer(int playerIndex) {
  int iTeam = PlayerState_GetTeam(playerIndex);

  if (iTeam == TEAM_SPECTATOR)
    return 1;

  if (playerIndex > MAX_PLAYERS || iTeam != TEAM_UNASSIGNED ||
      gScoreboardPlayerExtraInfo[playerIndex].teamnumber != TEAM_UNASSIGNED)
    return 0;

  hud_player_info_t info = {0};
  gEnginefuncs.pfnGetPlayerInfo(playerIndex, &info);

  return info.name != NULL;
}

static void UpdateTeamInfo(void* dialog) {
  short spectatorTeams[MAX_SCOREBOARD_PLAYERS + 1];
  unsigned char spectatorRows[MAX_SCOREBOARD_PLAYERS + 1];

  for (int playerIndex = 1; playerIndex <= MAX_SCOREBOARD_PLAYERS; playerIndex++) {
    spectatorRows[playerIndex] = IsSpectatorScoreboardPlayer(playerIndex);
    if (!spectatorRows[playerIndex])
      continue;

    spectatorTeams[playerIndex] = gScoreboardPlayerExtraInfo[playerIndex].teamnumber;
    gScoreboardPlayerExtraInfo[playerIndex].teamnumber = TEAM_SPECTATOR;
  }

  gScoreboardUpdateTeamInfoOriginal(dialog);

  for (int playerIndex = 1; playerIndex <= MAX_SCOREBOARD_PLAYERS; playerIndex++) {
    if (spectatorRows[playerIndex])
      gScoreboardPlayerExtraInfo[playerIndex].teamnumber = spectatorTeams[playerIndex];
  }
}

static void UpdatePlayerInfo(void* dialog) {
  short spectatorTeams[MAX_SCOREBOARD_PLAYERS + 1];
  unsigned char spectatorDead[MAX_SCOREBOARD_PLAYERS + 1];
  unsigned char spectatorRows[MAX_SCOREBOARD_PLAYERS + 1];

  for (int playerIndex = 1; playerIndex <= MAX_SCOREBOARD_PLAYERS; playerIndex++) {
    spectatorRows[playerIndex] = IsSpectatorScoreboardPlayer(playerIndex);
    if (!spectatorRows[playerIndex])
      continue;

    spectatorTeams[playerIndex] = gScoreboardPlayerExtraInfo[playerIndex].teamnumber;
    spectatorDead[playerIndex] = gScoreboardPlayerExtraInfo[playerIndex].dead;
    gScoreboardPlayerExtraInfo[playerIndex].teamnumber = TEAM_SPECTATOR;
    gScoreboardPlayerExtraInfo[playerIndex].dead = 0;
  }

  gScoreboardUpdatePlayerInfoOriginal(dialog);

  for (int playerIndex = 1; playerIndex <= MAX_SCOREBOARD_PLAYERS; playerIndex++) {
    if (spectatorRows[playerIndex]) {
      gScoreboardPlayerExtraInfo[playerIndex].teamnumber = spectatorTeams[playerIndex];
      gScoreboardPlayerExtraInfo[playerIndex].dead = spectatorDead[playerIndex];
    }
  }
}

static void HookScoreboardSpectatorInfo(void) {
  if (DobbyHook(gScoreboardUpdatePlayerInfo, UpdatePlayerInfo,
                (void**)&gScoreboardUpdatePlayerInfoOriginal) != 0)
    __builtin_trap();
}

static void HookScoreboardTeamInfo(void) {
  if (DobbyHook(gScoreboardUpdateTeamInfo, UpdateTeamInfo,
                (void**)&gScoreboardUpdateTeamInfoOriginal) != 0)
    __builtin_trap();
}

void Scoreboard_Initialize(void) {
  ResolveScoreboardSymbols();

  HookScoreboardTeamInfo();
  HookScoreboardSpectatorInfo();

  PatchScoreboardSpectatorSection();
}
