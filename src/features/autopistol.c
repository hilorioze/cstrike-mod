#include "cstrike/abi.h"
#include "cstrike/player_state.h"
#include "features/autopistol.h"
#include "goldsrc/abi.h"
#include "server.h"

static bool gReleaseAttack;

void AutoPistol_OnPostRunCmd(const local_state_t* to) {
  gReleaseAttack = false;

  if (!PlayerState_IsWeaponPredicted(to))
    return;

  int weaponId = to->client.m_iId;

  switch (weaponId) {
    case WEAPON_GLOCK18:
      // NOLINTNEXTLINE(hicpp-signed-bitwise)
      if (to->weapondata[weaponId].m_iWeaponState & WPNSTATE_GLOCK18_BURST_MODE)
        return;

      break;
    case WEAPON_P228:
    case WEAPON_ELITE:
    case WEAPON_FIVESEVEN:
    case WEAPON_USP:
    case WEAPON_DEAGLE:
      break;
    default:
      return;
  }

  // cs stores `m_iShotsFired` in the prediction field named `m_fInZoom` for some reason
  gReleaseAttack = to->weapondata[weaponId].m_fInZoom > 0;
}

void AutoPistol_CreateMove(usercmd_t* cmd) {
  if (!gReleaseAttack || !Server_IsFeatureEnabled(kFeatureAutoPistol))
    return;

  // release attack until the weapon simulation resets its semi-auto shot counter
  cmd->buttons &= ~IN_ATTACK;  // NOLINT(hicpp-signed-bitwise)
}
