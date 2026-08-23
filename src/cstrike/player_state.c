#include <string.h>

#include "cstrike/abi.h"
#include "cstrike/player_state.h"

static short g_PlayerTeam[MAX_SCOREBOARD_PLAYERS + 1];

int PlayerState_GetTeam(int iPlayer) {
  return g_PlayerTeam[iPlayer];
}

static void PlayerState_SetTeam(int iPlayer, int iTeam) {
  g_PlayerTeam[iPlayer] = iTeam;
}

void PlayerState_SetTeamFromName(int iPlayer, const char* pszTeamName) {
  if (iPlayer <= 0 || iPlayer > MAX_PLAYERS)
    return;

  if (strcmp(pszTeamName, "TERRORIST") == 0)
    PlayerState_SetTeam(iPlayer, TEAM_TERRORIST);
  else if (strcmp(pszTeamName, "CT") == 0)
    PlayerState_SetTeam(iPlayer, TEAM_CT);
  else if (strcmp(pszTeamName, "SPECTATOR") == 0 || strcmp(pszTeamName, "UNASSIGNED") == 0)
    PlayerState_SetTeam(iPlayer, TEAM_SPECTATOR);
  else
    PlayerState_SetTeam(iPlayer, TEAM_UNASSIGNED);
}
