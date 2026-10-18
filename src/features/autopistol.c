#include "features/autopistol.h"
#include "globals.h"
#include "goldsrc/abi.h"
#include "server.h"

enum {
  kWeaponP228 = 1,
  kWeaponElite = 10,
  kWeaponFiveSeven = 11,
  kWeaponUsp = 16,
  kWeaponGlock18 = 17,
  kWeaponDeagle = 26,
};

enum {
  kGlock18Burst = 1U << 1U,
};

static bool gReleaseAttack;

void AutoPistol_OnPostRunCmd(const local_state_t* to) {
  gReleaseAttack = false;

  if (to->client.health <= 0 || to->client.iuser1 || gEnginefuncs.pfnGetCvarFloat("cl_lw") == 0)
    return;

  int weaponId = to->client.m_iId;

  switch (weaponId) {
    case kWeaponGlock18:
      // NOLINTNEXTLINE(hicpp-signed-bitwise)
      if (to->weapondata[weaponId].m_iWeaponState & kGlock18Burst)
        return;

      break;
    case kWeaponP228:
    case kWeaponElite:
    case kWeaponFiveSeven:
    case kWeaponUsp:
    case kWeaponDeagle:
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
