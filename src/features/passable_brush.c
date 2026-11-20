#include "features/passable_brush.h"
#include "goldsrc/abi.h"
#include "server.h"

void PassableBrush_ApplyEntity(cl_entity_t* ent) {
  if (!Server_IsFeatureEnabled(kFeaturePassableBrushTransparency))
    return;

  // `func_illusionary` reaches the client only as a non-solid brush
  if (ent->model->type != mod_brush || ent->curstate.solid != SOLID_NOT)
    return;

  // keep the map's own translucency
  if (ent->curstate.rendermode != kRenderNormal)
    return;

  ent->curstate.rendermode = kRenderTransTexture;
  ent->curstate.renderamt = 180;
}
