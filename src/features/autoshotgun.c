#include <stdbool.h>

#include "cstrike/abi.h"
#include "cstrike/player_state.h"
#include "features/autoshotgun.h"
#include "goldsrc/abi.h"
#include "server.h"

static bool gShotgun;
static bool gAttackPassed;

void AutoShotgun_OnPostRunCmd(const local_state_t* to) {
  gShotgun = false;

  if (!PlayerState_IsWeaponPredicted(to))
    return;

  int weaponId = to->client.m_iId;

  gShotgun = weaponId == WEAPON_M3 || weaponId == WEAPON_XM1014;
}

void AutoShotgun_CreateMove(usercmd_t* cmd) {
  // NOLINTNEXTLINE(hicpp-signed-bitwise)
  if (!gShotgun || !(cmd->buttons & IN_ATTACK) || !Server_IsFeatureEnabled(kFeatureAutoShotgun)) {
    gAttackPassed = false;
    return;
  }

  // keep a shotgun firing even when it fires once per press: release attack in every other command,
  // a shot is at most one command late
  if (gAttackPassed)
    cmd->buttons &= ~IN_ATTACK;  // NOLINT(hicpp-signed-bitwise)

  gAttackPassed = !gAttackPassed;
}
