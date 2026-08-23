#include <stdio.h>

#include "cstrike/abi.h"
#include "cstrike/player_state.h"
#include "features/bot.h"
#include "features/cstatus.h"
#include "features/scoreboard.h"
#include "globals.h"
#include "goldsrc/abi.h"

void CStatus_Command(void) {
  gEnginefuncs.Con_Printf(
      "----------------------------------------------------"
      "------------------------------------------------\n");
  gEnginefuncs.Con_Printf(" #  %-20.20s %-20.20s %-5s %-5s %-10s %-8s %-10s\n", "name", "steamid",
                          "ping", "loss", "team", "state", "model");
  gEnginefuncs.Con_Printf(
      "----------------------------------------------------"
      "------------------------------------------------\n");

  int cPlayers = 0;

  for (int i = 1; i <= MAX_PLAYERS; i++) {
    hud_player_info_t playerInfo = {0};
    gEnginefuncs.pfnGetPlayerInfo(i, &playerInfo);

    if (!playerInfo.name)
      continue;

    cPlayers++;

    const char* pszDisplayName = (playerInfo.name[0] != '\0') ? playerInfo.name : "unnamed";
    const char* pszTeamStr = "UNASSIGNED";
    short team = PlayerState_GetTeam(i);

    if (team == TEAM_TERRORIST)
      pszTeamStr = "TERRORIST";
    else if (team == TEAM_CT)
      pszTeamStr = "CT";
    else if (team == TEAM_SPECTATOR)
      pszTeamStr = "SPECTATOR";

    const char* pszDeadStr = "alive";

    if (Scoreboard_GetPlayerTeam(i) != 0) {
      if (Scoreboard_IsPlayerDead(i))
        pszDeadStr = "dead";
    }

    char szSteamId[32];

    if (Bot_IsPlayer(i, &playerInfo)) {
      // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
      (void)snprintf(szSteamId, sizeof(szSteamId), "%llu (BOT)",
                     (unsigned long long)playerInfo.m_nSteamID);
    } else {
      // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
      (void)snprintf(szSteamId, sizeof(szSteamId), "%llu",
                     (unsigned long long)playerInfo.m_nSteamID);
    }

    const char* pszUserModel = gEnginefuncs.PlayerInfo_ValueForKey(i, "model");

    gEnginefuncs.Con_Printf("%2d  %-20.20s %-20.20s %-5d %-5d %-10s %-8s %-10s\n", i,
                            pszDisplayName, szSteamId, playerInfo.ping, playerInfo.packetloss,
                            pszTeamStr, pszDeadStr, pszUserModel ? pszUserModel : "");
  }

  gEnginefuncs.Con_Printf(
      "----------------------------------------------------"
      "------------------------------------------------\n");
  gEnginefuncs.Con_Printf("Total players: %d\n\n", cPlayers);
}
