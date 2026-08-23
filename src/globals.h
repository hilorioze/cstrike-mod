#pragma once

#include "goldsrc/abi.h"

extern cl_enginefunc_t gEnginefuncs;

typedef struct {
  int (*HUD_AddEntity)(int type, cl_entity_t* ent, const char* modelname);
  int (*HUD_Key_Event)(int down, int keynum, const char* pszCurrentBinding);
  int (*HUD_Redraw)(float flTime, int intermission);
  int (*Initialize)(cl_enginefunc_t* pEnginefuncs, int iVersion);
  int (*HUD_GetStudioModelInterface)(int version, void** ppinterface, engine_studio_api_t* pstudio);
} client_orig_funcs_t;

extern client_orig_funcs_t gClientOrigFuncs;
extern engine_studio_api_t gEngineStudio;
