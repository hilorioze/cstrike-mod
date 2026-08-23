#include <string.h>

#include "cstrike/abi.h"
#include "cstrike/player_state.h"
#include "features/player_render.h"
#include "features/scoreboard.h"
#include "globals.h"
#include "goldsrc/abi.h"

static setup_player_model_t g_pfnOriginalSetupPlayerModel;
static model_t* g_pModelOverride;
static int g_iModelOverridePlayer;

static int ModelsMatch(const model_t* pFirst, const model_t* pSecond) {
  return pFirst == pSecond || strcmp(pFirst->name, pSecond->name) == 0;
}

void PlayerRender_Initialize(setup_player_model_t pfnOriginalSetupPlayerModel) {
  g_pfnOriginalSetupPlayerModel = pfnOriginalSetupPlayerModel;
}

model_t* PlayerRender_SetupPlayerModel(int iPlayer) {
  if (g_pModelOverride && iPlayer == g_iModelOverridePlayer)
    return g_pModelOverride;

  return g_pfnOriginalSetupPlayerModel(iPlayer);
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
int PlayerRender_ShouldRenderModelPair(const entity_state_t* pPlayer, model_t** ppUserModel,
                                       model_t** ppModelIndex) {
  int iPerspectiveTeam = 0;
  int iPerspectiveIndex = PlayerRender_GetVisualPerspective(&iPerspectiveTeam);

  if (pPlayer->number <= 0 || pPlayer->number > MAX_PLAYERS || iPerspectiveIndex == -1 ||
      pPlayer->number == iPerspectiveIndex || Scoreboard_IsPlayerDead(pPlayer->number))
    return 0;

  short iPlayerTeam = PlayerState_GetTeam(pPlayer->number);

  if (iPerspectiveTeam == TEAM_SPECTATOR || iPerspectiveTeam == TEAM_UNASSIGNED ||
      iPlayerTeam == TEAM_SPECTATOR || iPlayerTeam == TEAM_UNASSIGNED ||
      iPlayerTeam == iPerspectiveTeam)
    return 0;

  int iPlayer = pPlayer->number - 1;
  // resolve the visual model from the player's `model` userinfo key
  model_t* pUserModel = g_pfnOriginalSetupPlayerModel(iPlayer);
  model_t* pModelIndex = gEngineStudio.GetModelByIndex(pPlayer->modelindex);

  if (!pUserModel || !pModelIndex || ModelsMatch(pUserModel, pModelIndex))
    return 0;

  *ppUserModel = pUserModel;
  *ppModelIndex = pModelIndex;

  return 1;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void PlayerRender_GetModelIndexRender(const cl_entity_t* pEntity, int* pRenderMode,
                                      int* pRenderAmount) {
  *pRenderMode = pEntity->curstate.rendermode;
  *pRenderAmount = pEntity->curstate.renderamt;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void PlayerRender_GetUserModelRender(int* pRenderMode, int* pRenderAmount) {
  *pRenderMode = kRenderTransTexture;
  *pRenderAmount = 128;
}

int PlayerRender_ShouldOverrideRender(const cl_entity_t* pEntity) {
  return pEntity->curstate.rendermode != kRenderTransAlpha;
}

void PlayerRender_BeginModelOverride(int iPlayer, model_t* pModel) {
  g_iModelOverridePlayer = iPlayer;
  g_pModelOverride = pModel;
}

void PlayerRender_EndModelOverride(void) {
  g_pModelOverride = NULL;
  g_iModelOverridePlayer = -1;
}

int PlayerRender_GetVisualPerspective(int* pTeam) {
  cl_entity_t* pLocal = gEnginefuncs.GetLocalPlayer();

  int iObserverMode = pLocal->curstate.iuser1;
  if (iObserverMode == OBS_CHASE_LOCKED || iObserverMode == OBS_CHASE_FREE ||
      iObserverMode == OBS_IN_EYE || iObserverMode == OBS_MAP_CHASE) {
    int iObserverTarget = pLocal->curstate.iuser2;
    if (iObserverTarget > 0 && iObserverTarget <= MAX_PLAYERS) {
      if (pTeam)
        *pTeam = PlayerState_GetTeam(iObserverTarget);

      return iObserverTarget;
    }
  }

  if (iObserverMode == OBS_NONE) {
    if (Scoreboard_IsPlayerDead(pLocal->index))
      return -1;

    if (pTeam)
      *pTeam = PlayerState_GetTeam(pLocal->index);

    return pLocal->index;
  }

  return -1;
}

// NOLINTNEXTLINE(misc-unused-parameters)
void PlayerRender_ApplyEntity(int type, cl_entity_t* ent, const char* modelname) {
  if (ent->index > 0 && ent->index <= MAX_PLAYERS) {
    int iPerspectiveTeam = 0;
    int iPerspectiveIndex = PlayerRender_GetVisualPerspective(&iPerspectiveTeam);

    if (iPerspectiveIndex != -1 && ent->index != iPerspectiveIndex) {
      short iTargetTeam = PlayerState_GetTeam(ent->index);
      if (iPerspectiveTeam != TEAM_SPECTATOR && iPerspectiveTeam != TEAM_UNASSIGNED &&
          iTargetTeam != TEAM_SPECTATOR && iTargetTeam != TEAM_UNASSIGNED &&
          iTargetTeam == iPerspectiveTeam) {
        if (ent->curstate.rendermode != kRenderTransAlpha) {
          ent->curstate.rendermode = kRenderTransAlpha;
          ent->curstate.renderamt = 128;
        }
      }
    }
  } else if (modelname && strcmp(modelname, "models/pallet_with_bags.mdl") == 0) {
    ent->curstate.rendermode = kRenderTransAlpha;
    ent->curstate.renderamt = 75;
  }
}
