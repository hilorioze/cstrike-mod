#pragma once

#include "goldsrc/abi.h"

void AutoReload_OnCurWeapon(int state, int weaponId, int clip);
void AutoReload_OnPostRunCmd(const local_state_t* to);
void AutoReload_CreateMove(usercmd_t* cmd);
