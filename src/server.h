#pragma once

typedef enum {
  kFeatureModelIndex = 1U << 0U,
  kFeaturePlayerTransparency = 1U << 1U,
  kFeaturePalletTransparency = 1U << 2U,
  kFeatureBuyAmmo = 1U << 3U,
  kFeatureAutoReload = 1U << 4U,
} server_feature_t;

int Server_IsFeatureEnabled(server_feature_t feature);
