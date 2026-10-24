#define _GNU_SOURCE  // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

#include <dlfcn.h>
#include <link.h>
#include <stddef.h>
#include <stdint.h>

#include "codepatch.h"
#include "features/health_warning.h"
#include "loader.h"

enum {
  // raised from the defaults: 25 turns the health red, 15 draws it at full brightness
  kLowHealth = 100,
};

static void SetThresholds(void* clientModule, const char* name, int count,
                          const uint8_t* comparison, size_t comparisonSize) {
  uint8_t* function = RealDlsym(clientModule, name);
  Dl_info info;
  const ElfW(Sym)* symbol = NULL;
  if (!dladdr1(function, &info, (void**)&symbol, RTLD_DL_SYMENT) || !symbol)
    __builtin_trap();

  uint8_t threshold = kLowHealth;
  // a patched check no longer matches, so each search finds the next one
  for (int i = 0; i < count; i++) {
    uint8_t* check = CodePatch_FindPattern(function, symbol->st_size, comparison, comparisonSize);
    CodePatch_Apply(check + comparisonSize - 1, &threshold, sizeof(threshold));
  }
}

void HealthWarning_Initialize(void* clientModule) {
  // `cmp` of `m_iHealth` with 25 and 15: `Draw` inlines the color check and checks the brightness
  // on both its fading and steady paths, `DrawPain` inlines the color check once per damage
  // direction
  static const uint8_t painColorComparison[] = {0x83, 0x7b, 0x14, 0x19};
  static const uint8_t drawColorComparison[] = {0x83, 0xf8, 0x19};
  static const uint8_t brightnessComparison[] = {0x83, 0xf8, 0x0f};

  SetThresholds(clientModule, "_ZN10CHudHealth12GetPainColorERiS0_S0_", 1, painColorComparison,
                sizeof(painColorComparison));
  SetThresholds(clientModule, "_ZN10CHudHealth4DrawEf", 1, drawColorComparison,
                sizeof(drawColorComparison));
  SetThresholds(clientModule, "_ZN10CHudHealth4DrawEf", 2, brightnessComparison,
                sizeof(brightnessComparison));
  SetThresholds(clientModule, "_ZN10CHudHealth8DrawPainEf", 4, painColorComparison,
                sizeof(painColorComparison));
}
