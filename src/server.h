#pragma once

#include "goldsrc/abi.h"

typedef enum {
  kFeatureModelIndex = 1U << 0U,
  kFeaturePlayerTransparency = 1U << 1U,
  kFeaturePalletTransparency = 1U << 2U,
  kFeatureBuyAmmo = 1U << 3U,
  kFeatureAutoReload = 1U << 4U,
  kFeatureAutoPistol = 1U << 5U,
  kFeatureHideServer = 1U << 6U,
} server_feature_t;

int Server_IsFeatureEnabled(server_feature_t feature);
int Server_IsFeatureEnabledAt(server_feature_t feature, const netadr_t* address);
