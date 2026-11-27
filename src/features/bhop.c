#include "cstrike/player_state.h"
#include "features/bhop.h"
#include "goldsrc/abi.h"
#include "server.h"

static bool gReleaseJump;
static bool gJumpUpInAir;

void Bhop_OnPostRunCmd(const local_state_t* to) {
  bool onGround = to->client.flags & FL_ONGROUND;  // NOLINT(hicpp-signed-bitwise)

  // swimming and ladders need jump held, so only airborne walking releases it
  gReleaseJump = PlayerState_IsAlive(to) && !onGround && to->client.waterlevel < 2 &&
                 to->playerstate.movetype == MOVETYPE_WALK;
}

void Bhop_CreateMove(usercmd_t* cmd) {
  if (!gReleaseJump || !Server_IsFeatureEnabled(kFeatureBhop)) {
    gJumpUpInAir = false;

    return;
  }

  bool jump = cmd->buttons & IN_JUMP;  // NOLINT(hicpp-signed-bitwise)
  if (!jump) {
    gJumpUpInAir = true;

    return;
  }

  // let one command of a jump pressed again in the air through for server double jumps
  if (gJumpUpInAir) {
    gJumpUpInAir = false;

    return;
  }

  // a jump only starts when the previous command had jump released, so releasing it in the air
  // lets a held jump fire again on landing
  cmd->buttons &= ~IN_JUMP;  // NOLINT(hicpp-signed-bitwise)
}
