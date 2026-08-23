#define _GNU_SOURCE  // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

#include <dlfcn.h>
#include <dobby.h>
#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "codepatch.h"
#include "cstrike/abi.h"
#include "features/crosshair.h"
#include "loader.h"

typedef void (*calculate_crosshair_size_t)(client_hud_ammo_t* hudAmmo);

static calculate_crosshair_size_t gOriginalCalculateCrosshairSize;

static void CalculateCrosshairSize(client_hud_ammo_t* hudAmmo) {
  gOriginalCalculateCrosshairSize(hudAmmo);

  hudAmmo->m_iCrosshairScaleBase = 1400;
}

enum CrosshairCheckState {
  kCrosshairCheckInvalid = -1,
  kCrosshairCheckOriginal,
  kCrosshairCheckPatched,
};

enum {
  // keep the four sniper checks together so mixed patch states are rejected
  kSniperCheckCount = 4,
};

// offsets of the four `je` opcodes inside `pattern`; each patch replaces a complete two-byte branch
static const size_t kSniperCheckOffsets[kSniperCheckCount] = {9, 14, 19, 26};

// original `client_orig.so` displacements for the four `je rel8` branches
static const uint8_t kBranchDisplacements[kSniperCheckCount] = {0x3f, 0x3a, 0x35, 0x2e};

static enum CrosshairCheckState GetCrosshairCheckState(const uint8_t* check, uint8_t displacement) {
  if (check[0] == 0x90 && check[1] == 0x90)
    return kCrosshairCheckPatched;

  if (check[0] == 0x74 && check[1] == displacement)
    return kCrosshairCheckOriginal;

  return kCrosshairCheckInvalid;
}

static uint8_t* FindSniperWeaponChecks(uint8_t* code, size_t codeSize) {
  // match `CHudAmmo::Draw`'s four `m_pWeapon->iId` checks:
  // `mov eax, [m_pWeapon + 0x9c]`; `cmp eax, weaponid`; `je rel8`
  static const uint8_t pattern[] = {
      0x8b, 0x87, 0x9c, 0x00, 0x00, 0x00,  // `mov eax, [m_pWeapon + 0x9c]`
      0x83, 0xf8, 0x18, 0x74, 0x00,        // `cmp eax, WEAPON_G3SG1 (0x18); je rel8`
      0x83, 0xf8, 0x12, 0x74, 0x00,        // `cmp eax, WEAPON_AWP (0x12); je rel8`
      0x83, 0xf8, 0x03, 0x74, 0x00,        // `cmp eax, WEAPON_SCOUT (0x03); je rel8`
      0x83, 0xf8, 0x0d, 0x66, 0x90, 0x74,
      0x00,  // `cmp eax, WEAPON_SG550 (0x0d)`; compiler alignment; `je rel8`
  };

  // wildcard the four `je rel8` pairs; their exact state is checked below
  static const char mask[] = "xxxxxxxxx??xxx??xxx??xxxxx??";

  if (codeSize < sizeof(pattern))
    __builtin_trap();

  for (size_t i = 0; i <= codeSize - sizeof(pattern); i++) {
    bool bMatch = true;

    for (size_t j = 0; j < sizeof(pattern); j++) {
      if (mask[j] == 'x' && code[i + j] != pattern[j]) {
        bMatch = false;
        break;
      }
    }

    if (bMatch) {
      enum CrosshairCheckState iState =
          GetCrosshairCheckState(code + i + kSniperCheckOffsets[0], kBranchDisplacements[0]);
      if (iState == kCrosshairCheckInvalid)
        continue;

      for (size_t j = 1; j < kSniperCheckCount; j++) {
        if (GetCrosshairCheckState(code + i + kSniperCheckOffsets[j], kBranchDisplacements[j]) !=
            iState) {
          bMatch = false;
          break;
        }
      }

      if (bMatch)
        return code + i;
    }
  }

  __builtin_trap();
}

void Crosshair_Initialize(void* clientModule) {
  void* hudAmmoDraw = RealDlsym(clientModule, "_ZN8CHudAmmo4DrawEf");
  void* calculateCrosshairSize = RealDlsym(clientModule, "_ZN8CHudAmmo22CalculateCrosshairSizeEv");
  if (!hudAmmoDraw || !calculateCrosshairSize)
    __builtin_trap();

  if (DobbyHook(calculateCrosshairSize, CalculateCrosshairSize,
                (void**)&gOriginalCalculateCrosshairSize) != 0)
    __builtin_trap();

  Dl_info drawInfo;
  const ElfW(Sym)* drawSymbol = NULL;
  if (!dladdr1(hudAmmoDraw, &drawInfo, (void**)&drawSymbol, RTLD_DL_SYMENT) || !drawSymbol)
    __builtin_trap();

  uint8_t* sniperWeaponChecks = FindSniperWeaponChecks((uint8_t*)hudAmmoDraw, drawSymbol->st_size);

  // replace each `je rel8` with two `nop`s so the original instruction length remains unchanged
  static uint8_t nops[] = {0x90, 0x90};
  enum CrosshairCheckState checkState =
      GetCrosshairCheckState(sniperWeaponChecks + kSniperCheckOffsets[0], kBranchDisplacements[0]);

  if (checkState == kCrosshairCheckOriginal) {
    for (size_t i = 0; i < kSniperCheckCount; i++) {
      uint8_t* check = sniperWeaponChecks + kSniperCheckOffsets[i];
      CodePatch_Apply(check, nops, sizeof(nops));
    }
  }
}
