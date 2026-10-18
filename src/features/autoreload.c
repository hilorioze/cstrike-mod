#include "cstrike/abi.h"
#include "cstrike/player_state.h"
#include "features/autoreload.h"
#include "goldsrc/abi.h"
#include "server.h"

static bool gEmptyMagazine;

void AutoReload_OnPostRunCmd(const local_state_t* to) {
  gEmptyMagazine = false;

  if (!PlayerState_IsWeaponPredicted(to))
    return;

  int weaponId = to->client.m_iId;

  if (weaponId != WEAPON_NONE)
    gEmptyMagazine = to->weapondata[weaponId].m_iClip == 0;
}

void AutoReload_CreateMove(usercmd_t* cmd) {
  if (!gEmptyMagazine || !Server_IsFeatureEnabled(kFeatureAutoReload))
    return;

  // release attack until the magazine is loaded so the weapon can auto-reload
  cmd->buttons &= ~IN_ATTACK;  // NOLINT(hicpp-signed-bitwise)
}
