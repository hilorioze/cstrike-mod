#pragma once

#include "goldsrc/abi.h"

int Bot_IsPlayer(int entindex, const hud_player_info_t* pinfo);
void Bot_ApplyPlayerInfo(int ent_num, hud_player_info_t* pinfo);
const char* Bot_OverridePlayerInfoValue(int playerNum, const char* key, const char* value);
