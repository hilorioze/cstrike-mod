#include <stdbool.h>

#include "cstrike/abi.h"
#include "cstrike/player_state.h"
#include "features/autoreload.h"
#include "goldsrc/abi.h"
#include "server.h"

static bool gEmptyMagazine;
static bool gLoadingShells;
static bool gAttackHeld;
static bool gSecondaryAttackHeld;
static bool gReloadInterrupted;

void AutoReload_OnPostRunCmd(const local_state_t* to) {
  gEmptyMagazine = false;
  gLoadingShells = false;

  if (!PlayerState_IsWeaponPredicted(to))
    return;

  int weaponId = to->client.m_iId;

  switch (weaponId) {
    // these have no magazine, but custom server weapons based on them may report a clip of 0
    case WEAPON_NONE:
    case WEAPON_KNIFE:
    case WEAPON_HEGRENADE:
    case WEAPON_FLASHBANG:
    case WEAPON_SMOKEGRENADE:
    case WEAPON_C4:
      return;
    case WEAPON_M3:
    case WEAPON_XM1014:
      gLoadingShells = to->weapondata[weaponId].m_fInSpecialReload != 0;
      break;
    default:
      break;
  }

  gEmptyMagazine = to->weapondata[weaponId].m_iClip == 0;
}

void AutoReload_CreateMove(usercmd_t* cmd) {
  bool attackHeld = cmd->buttons & IN_ATTACK;  // NOLINT(hicpp-signed-bitwise)
  bool attackPressed = attackHeld && !gAttackHeld;
  gAttackHeld = attackHeld;

  bool secondaryAttackHeld = cmd->buttons & IN_ATTACK2;  // NOLINT(hicpp-signed-bitwise)
  bool secondaryAttackPressed = secondaryAttackHeld && !gSecondaryAttackHeld;
  gSecondaryAttackHeld = secondaryAttackHeld;

  // a shotgun loads one shell at a time and a held attack fires every shell as soon as it's loaded:
  // keep attack released until the magazine is full, unless it's pressed again to interrupt
  if (!gLoadingShells)
    gReloadInterrupted = false;
  else if (attackPressed || secondaryAttackPressed)
    gReloadInterrupted = true;

  if (!(gEmptyMagazine || (gLoadingShells && !gReloadInterrupted)) ||
      !Server_IsFeatureEnabled(kFeatureAutoReload))
    return;

  // release attack until the magazine is loaded so the weapon can auto-reload
  cmd->buttons &= ~IN_ATTACK;  // NOLINT(hicpp-signed-bitwise)

  // weapons reload only with both attacks released, and custom server weapons may fire with the
  // secondary one; a fresh press still passes to zoom or toggle a silencer on an empty magazine
  if (!secondaryAttackPressed)
    cmd->buttons &= ~IN_ATTACK2;  // NOLINT(hicpp-signed-bitwise)
}
