#pragma once

#include "goldsrc/abi.h"

extern cl_enginefunc_t gEnginefuncs;

typedef struct {
  int (*HUD_VidInit)(void);
  void (*CL_CreateMove)(float frametime, usercmd_t* cmd, int active);
  int (*CL_IsThirdPerson)(void);
  void (*V_CalcRefdef)(ref_params_t* params);
  void (*HUD_PostRunCmd)(local_state_t* from, local_state_t* to, usercmd_t* cmd, int runfuncs,
                         double time, unsigned int random_seed);
  int (*HUD_AddEntity)(int type, cl_entity_t* ent, const char* modelname);
  int (*HUD_AddEntityNative)(int type, cl_entity_t* ent, const char* modelname);
  void (*HUD_DrawNormalTriangles)(void);
  int (*HUD_Key_Event)(int down, int keynum, const char* pszCurrentBinding);
  int (*Initialize)(cl_enginefunc_t* pEnginefuncs, int iVersion);
  int (*HUD_GetStudioModelInterface)(int version, void** ppinterface, engine_studio_api_t* pstudio);
} client_orig_funcs_t;

extern client_orig_funcs_t gClientOrigFuncs;
extern engine_studio_api_t gEngineStudio;
