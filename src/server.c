#include <netinet/in.h>
#include <stddef.h>
#include <string.h>

#include "globals.h"
#include "goldsrc/abi.h"
#include "server.h"

enum {
  // NOLINTNEXTLINE(hicpp-signed-bitwise)
  kDefaultFeatures = kFeatureModelIndex | kFeaturePlayerTransparency | kFeaturePalletTransparency,
};

typedef struct {
  unsigned char ip[4];
  unsigned short port;
} server_endpoint_t;

typedef struct {
  const server_endpoint_t* endpoints;
  size_t count;
  unsigned int enabled_features;
  unsigned int disabled_features;
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
        .enabled_features = 0,
        // NOLINTNEXTLINE(hicpp-signed-bitwise)
        .disabled_features = kFeatureModelIndex | kFeaturePlayerTransparency,
    },
    {
        .endpoints = kBuyAmmoServers,
        .count = sizeof(kBuyAmmoServers) / sizeof(kBuyAmmoServers[0]),
        .enabled_features = kFeatureBuyAmmo,
        .disabled_features = 0,
    },
};

static const server_profile_t* FindProfile(const netadr_t* remoteAddress) {
  for (size_t i = 0; i < sizeof(kServerProfiles) / sizeof(kServerProfiles[0]); i++) {
    const server_profile_t* profile = &kServerProfiles[i];

    for (size_t j = 0; j < profile->count; j++) {
      if (memcmp(remoteAddress->ip, profile->endpoints[j].ip, sizeof(profile->endpoints[j].ip)) ==
              0 &&
          remoteAddress->port == htons(profile->endpoints[j].port))
        return profile;
    }
  }

  return NULL;
}

static unsigned int ResolveFeatures(const net_status_t* status) {
  if (!status->connected || status->remote_address.type != NA_IP)
    return kDefaultFeatures;

  const server_profile_t* profile = FindProfile(&status->remote_address);
  if (!profile)
    return kDefaultFeatures;

  // NOLINTNEXTLINE(hicpp-signed-bitwise)
  return (kDefaultFeatures | profile->enabled_features) & ~profile->disabled_features;
}

int Server_IsFeatureEnabled(server_feature_t feature) {
  static unsigned char cachedIp[4];
  static unsigned short cachedPort;
  static int cachedConnected;
  static unsigned int cachedFeatures = kDefaultFeatures;

  net_status_t status;
  gEnginefuncs.pNetAPI->Status(&status);

  if (status.connected != cachedConnected || status.remote_address.port != cachedPort ||
      memcmp(status.remote_address.ip, cachedIp, sizeof(cachedIp)) != 0) {
    cachedConnected = status.connected;
    cachedPort = status.remote_address.port;
    cachedIp[0] = status.remote_address.ip[0];
    cachedIp[1] = status.remote_address.ip[1];
    cachedIp[2] = status.remote_address.ip[2];
    cachedIp[3] = status.remote_address.ip[3];

    cachedFeatures = ResolveFeatures(&status);
  }

  return (cachedFeatures & feature) != 0;
}
