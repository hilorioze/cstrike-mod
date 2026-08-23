#pragma once

#include "goldsrc/abi.h"

typedef model_t* (*setup_player_model_t)(int iPlayer);

int PlayerRender_GetVisualPerspective(int* pTeam);
void PlayerRender_Initialize(setup_player_model_t pfnOriginalSetupPlayerModel);
model_t* PlayerRender_SetupPlayerModel(int iPlayer);
int PlayerRender_ShouldRenderModelPair(const entity_state_t* pPlayer, model_t** ppUserModel,
                                       model_t** ppModelIndex);
void PlayerRender_GetModelIndexRender(const cl_entity_t* pEntity, int* pRenderMode,
                                      int* pRenderAmount);
void PlayerRender_GetUserModelRender(int* pRenderMode, int* pRenderAmount);
int PlayerRender_ShouldOverrideRender(const cl_entity_t* pEntity);
void PlayerRender_BeginModelOverride(int iPlayer, model_t* pModel);
void PlayerRender_EndModelOverride(void);
void PlayerRender_ApplyEntity(int type, cl_entity_t* ent, const char* modelname);
