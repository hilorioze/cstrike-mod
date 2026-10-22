#include <netinet/in.h>
#include <stddef.h>
#include <string.h>

#include "globals.h"
#include "goldsrc/abi.h"
#include "server.h"

enum {
  // NOLINTNEXTLINE(hicpp-signed-bitwise)
  kDefaultFeatures = kFeatureModelIndex | kFeaturePlayerTransparency | kFeaturePalletTransparency |
                     kFeatureAutoReload | kFeatureAutoPistol | kFeatureHideServer |
                     kFeatureAutoShotgun,
};

typedef struct {
  unsigned char ip[4];
  unsigned short port;
} server_endpoint_t;

typedef struct {
  const server_endpoint_t* endpoints;
  size_t count;
  unsigned int enabledFeatures;
  unsigned int disabledFeatures;
} server_profile_t;

// servers with player models and visibility managed by server plugins
static const server_endpoint_t kCustomModelServers[] = {
    {{46, 174, 48, 101}, 27015},   {{46, 174, 52, 97}, 27015},    {{167, 99, 129, 144}, 27015},
    {{204, 168, 182, 190}, 27015}, {{204, 168, 182, 190}, 27016}, {{204, 168, 182, 190}, 28255},
};

// servers supporting the `/buyammo` chat command
static const server_endpoint_t kBuyAmmoServers[] = {
    {{46, 174, 52, 2}, 27256},
};

static const server_profile_t kServerProfiles[] = {
    {
        .endpoints = kCustomModelServers,
        .count = sizeof(kCustomModelServers) / sizeof(kCustomModelServers[0]),
        // NOLINTNEXTLINE(hicpp-signed-bitwise)
        .disabledFeatures = kFeatureModelIndex | kFeaturePlayerTransparency,
    },
    {
        .endpoints = kBuyAmmoServers,
        .count = sizeof(kBuyAmmoServers) / sizeof(kBuyAmmoServers[0]),
        .enabledFeatures = kFeatureBuyAmmo,
    },
};

static const server_profile_t* FindProfile(const netadr_t* remoteAddress) {
  for (size_t i = 0; i < sizeof(kServerProfiles) / sizeof(kServerProfiles[0]); i++) {
    const server_profile_t* profile = &kServerProfiles[i];

    for (size_t j = 0; j < profile->count; j++) {
      const server_endpoint_t* endpoint = &profile->endpoints[j];
      if (memcmp(remoteAddress->ip, endpoint->ip, sizeof(endpoint->ip)) == 0 &&
          remoteAddress->port == htons(endpoint->port))
        return profile;
    }
  }

  return NULL;
}

static unsigned int ResolveFeatures(const netadr_t* address) {
  const server_profile_t* profile = FindProfile(address);
  if (!profile)
    return kDefaultFeatures;

  // NOLINTNEXTLINE(hicpp-signed-bitwise)
  return (kDefaultFeatures | profile->enabledFeatures) & ~profile->disabledFeatures;
}

int Server_IsFeatureEnabled(server_feature_t feature) {
  net_status_t status;
  gEnginefuncs.pNetAPI->Status(&status);
  if (!status.connected || status.remote_address.type != NA_IP)
    return (kDefaultFeatures & feature) != 0;

  return Server_IsFeatureEnabledAt(feature, &status.remote_address);
}

int Server_IsFeatureEnabledAt(server_feature_t feature, const netadr_t* address) {
  return (ResolveFeatures(address) & feature) != 0;
}
