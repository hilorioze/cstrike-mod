#include "features/autoreload.h"
#include "globals.h"
#include "goldsrc/abi.h"
#include "server.h"

static int gHudClip = -1;
static bool gEmptyMagazine;

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void AutoReload_OnCurWeapon(int state, int weaponId, int clip) {
  if (weaponId <= 0)
    gHudClip = -1;
  else if (state)
    gHudClip = clip;
}

void AutoReload_OnPostRunCmd(const local_state_t* to) {
  gEmptyMagazine = false;

  if (to->client.health <= 0 || to->client.iuser1)
    return;

  // with `cl_lw 0`, the server omits prediction data; use the hud magazine instead
  if (gEnginefuncs.pfnGetCvarFloat("cl_lw") == 0) {
    gEmptyMagazine = gHudClip == 0;

    return;
  }

  int weaponId = to->client.m_iId;

  // the client weapon simulation updates slots 0 through 31
  if (weaponId > 0 && weaponId < 32)
    gEmptyMagazine = to->weapondata[weaponId].m_iClip == 0;
}

void AutoReload_CreateMove(usercmd_t* cmd) {
  if (!gEmptyMagazine || !Server_IsFeatureEnabled(kFeatureAutoReload))
    return;

  // release attack until the magazine is loaded so the weapon can auto-reload
  cmd->buttons &= ~IN_ATTACK;  // NOLINT(hicpp-signed-bitwise)
}
