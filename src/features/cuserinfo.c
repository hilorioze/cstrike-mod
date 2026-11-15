#include <stdlib.h>

#include "cstrike/abi.h"
#include "features/cuserinfo.h"
#include "globals.h"
#include "goldsrc/abi.h"

static void PrintPlayer(int index) {
  // the studio api counts players from zero, `cstatus` from one
  player_info_t* pPlayerInfo = gEngineStudio.PlayerInfo(index - 1);
  if (!pPlayerInfo || pPlayerInfo->name[0] == '\0')
    return;

  gEnginefuncs.Con_Printf("%2d  %s\n    %s\n", index, pPlayerInfo->name, pPlayerInfo->userinfo);
}

void CUserinfo_Command(void) {
  if (gEnginefuncs.Cmd_Argc() > 1) {
    PrintPlayer((int)strtol(gEnginefuncs.Cmd_Argv(1), NULL, 10));

    return;
  }

  for (int i = 1; i <= MAX_PLAYERS; i++)
    PrintPlayer(i);
}
