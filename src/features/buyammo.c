#include <netinet/in.h>
#include <string.h>

#include "features/buyammo.h"
#include "globals.h"
#include "goldsrc/abi.h"

void BuyAmmo_OnMoney(int dollars) {
  if (dollars < 5000)
    return;

  net_status_t status;
  gEnginefuncs.pNetAPI->Status(&status);

  if (status.connected && status.remote_address.type == NA_IP &&
      memcmp(status.remote_address.ip, (unsigned char[]){46, 174, 52, 2}, 4) == 0 &&
      status.remote_address.port == htons(27256)) {
    gEnginefuncs.pfnClientCmd("say /buyammo");
  }
}
