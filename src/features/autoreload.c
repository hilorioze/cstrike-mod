#include <stdbool.h>

#include "cstrike/abi.h"
#include "cstrike/player_state.h"
#include "features/autoreload.h"
#include "goldsrc/abi.h"
#include "server.h"

static bool gEmptyMagazine;
static bool gLoadingShells;
static bool gAttackHeld;
static bool gReloadInterrupted;

void AutoReload_OnPostRunCmd(const local_state_t* to) {
  gEmptyMagazine = false;
  gLoadingShells = false;

  if (!PlayerState_IsWeaponPredicted(to))
    return;

  int weaponId = to->client.m_iId;

  if (weaponId != WEAPON_NONE) {
    gEmptyMagazine = to->weapondata[weaponId].m_iClip == 0;
    gLoadingShells = to->weapondata[weaponId].m_fInSpecialReload != 0;
  }
}

void AutoReload_CreateMove(usercmd_t* cmd) {
  bool attackHeld = cmd->buttons & IN_ATTACK;  // NOLINT(hicpp-signed-bitwise)
  bool attackPressed = attackHeld && !gAttackHeld;
  gAttackHeld = attackHeld;

  // a shotgun loads one shell at a time and a held attack fires every shell as soon as it's loaded:
  // keep attack released until the magazine is full, unless it's pressed again to interrupt
  if (!gLoadingShells)
    gReloadInterrupted = false;
  else if (attackPressed)
    gReloadInterrupted = true;

  if (!(gEmptyMagazine || (gLoadingShells && !gReloadInterrupted)) ||
      !Server_IsFeatureEnabled(kFeatureAutoReload))
    return;

  // release attack until the magazine is loaded so the weapon can auto-reload
  cmd->buttons &= ~IN_ATTACK;  // NOLINT(hicpp-signed-bitwise)
}
