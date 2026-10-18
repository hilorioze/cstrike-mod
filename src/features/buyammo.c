#include "features/buyammo.h"
#include "globals.h"
#include "goldsrc/abi.h"
#include "server.h"

void BuyAmmo_OnMoney(int dollars) {
  if (dollars < 5000 || !Server_IsFeatureEnabled(kFeatureBuyAmmo))
    return;

  gEnginefuncs.pfnClientCmd("say /buyammo");
}
