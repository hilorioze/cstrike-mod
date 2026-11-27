#pragma once

#include "goldsrc/abi.h"

void AutoFlashlight_Initialize(void);
void AutoFlashlight_HandleKeyEvent(int down, int keynum, const char* pszCurrentBinding);
void AutoFlashlight_OnPostRunCmd(const local_state_t* to);
void AutoFlashlight_CreateMove(usercmd_t* cmd);
