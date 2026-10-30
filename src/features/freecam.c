#include <math.h>
#include <stdbool.h>

#include "features/freecam.h"
#include "globals.h"
#include "goldsrc/abi.h"

static bool gEnabled;
static bool gHaveView;
static vec3_t gOrigin;
static vec3_t gAngles;
static vec3_t gPlayerAngles;
static cvar_t* gSpeed;

void Freecam_Reset(void) {
  gEnabled = false;
  gHaveView = false;
}

bool Freecam_IsEnabled(void) {
  return gEnabled;
}

static void Toggle(void) {
  if (gEnabled) {
    gEnabled = false;
    gEnginefuncs.pfnConsolePrint("freecam: off\n");

    return;
  }

  net_status_t status;
  gEnginefuncs.pNetAPI->Status(&status);
  if (!status.connected || !gHaveView) {
    gEnginefuncs.pfnConsolePrint("freecam: not in game\n");

    return;
  }

  gAngles[2] = 0;
  gEnabled = true;
  gEnginefuncs.pfnConsolePrint("freecam: on\n");
}

void Freecam_Initialize(void) {
  gSpeed = gEnginefuncs.pfnRegisterVariable("cl_freecam_speed", "400", FCVAR_ARCHIVE);
  gEnginefuncs.pfnAddCommand("freecam", Toggle);
}

void Freecam_BeforeCreateMove(void) {
  if (!gEnabled)
    return;

  // let the client's input code turn the camera without leaving its angles in the player's state
  gEnginefuncs.GetViewAngles(gPlayerAngles);
  gEnginefuncs.SetViewAngles(gAngles);
}

void Freecam_CreateMove(float frametime, usercmd_t* cmd, int active) {
  if (!gEnabled)
    return;

  gEnginefuncs.GetViewAngles(gAngles);
  gEnginefuncs.SetViewAngles(gPlayerAngles);

  if (active) {
    vec3_t forward;
    vec3_t right;
    vec3_t up;
    gEnginefuncs.pfnAngleVectors(gAngles, forward, right, up);

    float forwardMove = (cmd->forwardmove > 0) - (cmd->forwardmove < 0);
    float sideMove = (cmd->sidemove > 0) - (cmd->sidemove < 0);
    // NOLINTBEGIN(hicpp-signed-bitwise)
    float upMove = ((cmd->buttons & IN_JUMP) != 0) - ((cmd->buttons & IN_DUCK) != 0);
    // NOLINTEND(hicpp-signed-bitwise)
    upMove += (cmd->upmove > 0) - (cmd->upmove < 0);

    vec3_t direction;
    float lengthSquared = 0;
    for (int i = 0; i < 3; i++) {
      direction[i] = (forward[i] * forwardMove) + (right[i] * sideMove);
      if (i == 2)
        direction[i] += upMove;

      lengthSquared += direction[i] * direction[i];
    }

    if (lengthSquared > 0) {
      float distance = gSpeed->value * frametime / sqrtf(lengthSquared);
      for (int i = 0; i < 3; i++)
        gOrigin[i] += direction[i] * distance;
    }
  }

  for (int i = 0; i < 3; i++)
    cmd->viewangles[i] = gPlayerAngles[i];

  cmd->forwardmove = 0;
  cmd->sidemove = 0;
  cmd->upmove = 0;
  cmd->buttons &= IN_SCORE;  // NOLINT(hicpp-signed-bitwise)
  cmd->impulse = 0;
  cmd->weaponselect = 0;
}

void Freecam_CalcRefdef(ref_params_t* params) {
  if (!gEnabled) {
    for (int i = 0; i < 3; i++) {
      gOrigin[i] = params->vieworg[i];
      gAngles[i] = params->viewangles[i];
    }

    gHaveView = true;

    return;
  }

  gEnginefuncs.GetViewAngles(params->cl_viewangles);
  for (int i = 0; i < 3; i++) {
    params->vieworg[i] = gOrigin[i];
    params->viewangles[i] = gAngles[i];
  }

  gEnginefuncs.pfnAngleVectors(params->viewangles, params->forward, params->right, params->up);
  params->nextView = 0;
  params->onlyClientDraw = 0;
}
