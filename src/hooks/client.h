#pragma once

#include "goldsrc/abi.h"

int Initialize(cl_enginefunc_t* pEnginefuncs, int iVersion);
int HUD_AddEntity(int type, cl_entity_t* ent, const char* modelname);
int HUD_Key_Event(int down, int keynum, const char* pszCurrentBinding);
int HUD_Redraw(float flTime, int intermission);
