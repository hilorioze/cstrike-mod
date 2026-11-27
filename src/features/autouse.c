#include <stdbool.h>

#include "cstrike/player_state.h"
#include "features/autouse.h"
#include "goldsrc/abi.h"
#include "server.h"

static bool gAlive;
static bool gUsePassed;

void AutoUse_OnPostRunCmd(const local_state_t* to) {
  gAlive = PlayerState_IsAlive(to);
}

void AutoUse_CreateMove(usercmd_t* cmd) {
  // NOLINTNEXTLINE(hicpp-signed-bitwise)
  if (!gAlive || !(cmd->buttons & IN_USE) || !Server_IsFeatureEnabled(kFeatureAutoUse)) {
    gUsePassed = false;

    return;
  }

  // the server uses most entities only on a fresh press: release use in every other command so a
  // held use presses again
  if (gUsePassed)
    cmd->buttons &= ~IN_USE;  // NOLINT(hicpp-signed-bitwise)

  gUsePassed = !gUsePassed;
}
