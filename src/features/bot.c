#include <string.h>

#include "features/bot.h"
#include "globals.h"
#include "goldsrc/abi.h"

int Bot_IsPlayer(int entindex, const hud_player_info_t* pinfo) {
  enum {
    k_EAccountTypeAnonGameServer = 4,
  };

  const char* pszBot = gEnginefuncs.PlayerInfo_ValueForKey(entindex, "*bot");

  // fake clients may lack the `*bot` marker; zero Steam IDs or anonymous account IDs are indicators
  if (pszBot && strcmp(pszBot, "1") == 0)
    return 1;

  if (!pinfo->name)
    return 0;

  return pinfo->m_nSteamID == 0 ||
         ((pinfo->m_nSteamID >> 52U) & 0xfU) == k_EAccountTypeAnonGameServer;
}

void Bot_ApplyPlayerInfo(int ent_num, hud_player_info_t* pinfo) {
  if (Bot_IsPlayer(ent_num, pinfo))
    pinfo->ping = 0;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
const char* Bot_OverridePlayerInfoValue(int playerNum, const char* key, const char* value) {
  if (strcmp(key, "*bot") == 0) {
    hud_player_info_t info = {0};
    gEnginefuncs.pfnGetPlayerInfo(playerNum, &info);

    if (Bot_IsPlayer(playerNum, &info))
      return "1";
  }

  return value;
}
