#pragma once

#include <stdbool.h>

#include "goldsrc/abi.h"

int PlayerState_GetTeam(int iPlayer);
void PlayerState_SetTeamFromName(int iPlayer, const char* pszTeamName);
bool PlayerState_IsWeaponPredicted(const local_state_t* state);
