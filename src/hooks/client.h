#pragma once

#include "goldsrc/abi.h"

int Initialize(cl_enginefunc_t* pEnginefuncs, int iVersion);
void CL_CreateMove(float frametime, usercmd_t* cmd, int active);
void V_CalcRefdef(ref_params_t* params);
void HUD_PostRunCmd(local_state_t* from, local_state_t* to, usercmd_t* cmd, int runfuncs,
                    double time, unsigned int random_seed);
int HUD_AddEntity(int type, cl_entity_t* ent, const char* modelname);
int HUD_Key_Event(int down, int keynum, const char* pszCurrentBinding);
