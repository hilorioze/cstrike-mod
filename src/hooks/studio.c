#include "features/player_render.h"
#include "globals.h"
#include "goldsrc/abi.h"
#include "hooks/studio.h"

static int (*real_StudioDrawPlayer)(int flags, entity_state_t* pplayer);

enum {
  kStudioInterfaceVersion = 1,
  kStudioRender = 1 << 0,  // NOLINT(hicpp-signed-bitwise)
  kStudioEvents = 1 << 1,  // NOLINT(hicpp-signed-bitwise)
};

static model_t* Hook_StudioSetupPlayerModel(int iPlayer) {
  return PlayerRender_SetupPlayerModel(iPlayer);
}

static int DrawPlayerModel(int flags, entity_state_t* pPlayer, int iPlayer, model_t* pModel,
                           int iRenderMode,      // NOLINT(bugprone-easily-swappable-parameters)
                           int iRenderAmount) {  // NOLINT(bugprone-easily-swappable-parameters)
  cl_entity_t* pCurrentEntity = gEngineStudio.GetCurrentEntity();

  PlayerRender_BeginModelOverride(iPlayer, pModel);

  int bOverride = PlayerRender_ShouldOverrideRender(pCurrentEntity);
  int iSavedRenderMode = 0;
  int iSavedRenderAmount = 0;

  if (bOverride) {
    iSavedRenderMode = pCurrentEntity->curstate.rendermode;
    iSavedRenderAmount = pCurrentEntity->curstate.renderamt;

    pCurrentEntity->curstate.rendermode = iRenderMode;
    gEngineStudio.StudioSetRenderamt(iRenderAmount);
  }

  int iResult = real_StudioDrawPlayer(flags, pPlayer);

  PlayerRender_EndModelOverride();

  if (bOverride) {
    pCurrentEntity->curstate.rendermode = iSavedRenderMode;
    gEngineStudio.StudioSetRenderamt(iSavedRenderAmount);
  }

  return iResult;
}

static int Hook_StudioDrawPlayer(int flags, entity_state_t* pPlayer) {
  if (!(flags & kStudioRender))  // NOLINT(hicpp-signed-bitwise)
    return real_StudioDrawPlayer(flags, pPlayer);

  cl_entity_t* pCurrentEntity = gEngineStudio.GetCurrentEntity();
  if (!pCurrentEntity->player || pCurrentEntity->index != pPlayer->number ||
      pCurrentEntity->curstate.renderfx == kRenderFxDeadPlayer)
    return real_StudioDrawPlayer(flags, pPlayer);

  model_t* pUserModel = NULL;
  model_t* pModelIndex = NULL;

  if (!PlayerRender_ShouldRenderModelPair(pPlayer, &pUserModel, &pModelIndex))
    return real_StudioDrawPlayer(flags, pPlayer);

  int iPlayer = pPlayer->number - 1;
  entity_state_t savedPlayerState = *pPlayer;

  int iRenderMode = 0;
  int iRenderAmount = 0;
  PlayerRender_GetModelIndexRender(pCurrentEntity, &iRenderMode, &iRenderAmount);

  // draw the server-selected `modelindex` model first
  // NOLINTNEXTLINE(hicpp-signed-bitwise)
  int iResult = DrawPlayerModel(flags & ~kStudioEvents, pPlayer, iPlayer, pModelIndex, iRenderMode,
                                iRenderAmount);

  *pPlayer = savedPlayerState;

  // draw the model from the `model` userinfo key on top with reduced opacity
  int iUserModelRenderMode = 0;
  int iUserModelRenderAmount = 0;
  PlayerRender_GetUserModelRender(&iUserModelRenderMode, &iUserModelRenderAmount);

  int iUserModelResult = DrawPlayerModel(flags, pPlayer, iPlayer, pUserModel, iUserModelRenderMode,
                                         iUserModelRenderAmount);

  return iResult ? iResult : iUserModelResult;
}

int HUD_GetStudioModelInterface(int version, void** ppinterface, engine_studio_api_t* pstudio) {
  if (version != kStudioInterfaceVersion)
    return gClientOrigFuncs.HUD_GetStudioModelInterface(version, ppinterface, pstudio);

  if (pstudio->SetupPlayerModel != Hook_StudioSetupPlayerModel) {
    PlayerRender_Initialize(pstudio->SetupPlayerModel);
    pstudio->SetupPlayerModel = Hook_StudioSetupPlayerModel;
  }

  int iResult = gClientOrigFuncs.HUD_GetStudioModelInterface(version, ppinterface, pstudio);

  gEngineStudio = *pstudio;

  r_studio_interface_t* pStudioInterface = (r_studio_interface_t*)*ppinterface;
  if (pStudioInterface->StudioDrawPlayer != Hook_StudioDrawPlayer) {
    real_StudioDrawPlayer = pStudioInterface->StudioDrawPlayer;
    pStudioInterface->StudioDrawPlayer = Hook_StudioDrawPlayer;
  }

  return iResult;
}
