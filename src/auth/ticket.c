#include <stdint.h>
#include <string.h>
#include <time.h>

#include "auth/crypto.h"
#include "auth/ticket.h"

enum {
  kSteamIdHigh = 0x01100001,   // public universe, individual account, desktop instance
  kRevSignature = 0x00726576,  // `'rev'` as an msvc multichar constant
  kSteamEmuVolumeXor = 0xc9710266U,
};

// wire lengths include the legacy formats' unused tails
static const struct {
  const char* name;
  size_t size;
  size_t keyLimit;
} kFormats[kAuthKindCount] = {
    [kAuthSteam] = {"steam", 0, 0},
    [kAuthNoSteam] = {"nosteam", 0, 0},
    [kAuthOldRevEmu] = {"oldrevemu", 10, 0},
    [kAuthSteamEmu] = {"steamemu", 768, 0},
    [kAuthRevEmu] = {"revemu", 152, 127},
    [kAuthSC2009] = {"sc2009", 178, 32},
    [kAuthRevEmu2013] = {"revemu2013", 194, 32},
    [kAuthAVSMP] = {"avsmp", 28, 0},
    [kAuthSetti] = {"setti", 768, 0},
};

auth_kind_t AuthTicket_FindKind(const char* name) {
  for (int i = 0; i < kAuthKindCount; i++) {
    if (strcmp(name, kFormats[i].name) == 0)
      return (auth_kind_t)i;
  }

  return kAuthInvalid;
}

const char* AuthTicket_GetName(auth_kind_t kind) {
  return kFormats[kind].name;
}

size_t AuthTicket_GetSize(auth_kind_t kind) {
  return kFormats[kind].size;
}

size_t AuthTicket_GetKeyLimit(auth_kind_t kind) {
  return kFormats[kind].keyLimit;
}

static void Write32(uint8_t* ticket, size_t offset, uint32_t value) {
  for (size_t i = 0; i < 4; i++)
    ticket[offset + i] = (uint8_t)(value >> (8U * i));
}

static uint32_t RevHash(const char* key) {
  uint32_t hash = 0x4e67c6a7;
  // the emulators hash the key as signed chars
  for (; *key; key++)
    hash ^= (hash >> 2U) + (uint32_t)(int32_t)(int8_t)*key + (32U * hash);

  return hash;
}

static void GenerateRevTicket(uint8_t* ticket, const auth_ticket_config_t* config) {
  uint32_t hash = RevHash(config->key);
  Write32(ticket, 0, config->kind == kAuthRevEmu ? 0x4a : 0x53);
  Write32(ticket, 4, hash);
  Write32(ticket, 8, kRevSignature);
  Write32(ticket, 16, hash << 1U);
  Write32(ticket, 20, kSteamIdHigh);

  size_t keyLength = strlen(config->key);
  if (config->kind == kAuthRevEmu) {
    memcpy(ticket + 24, config->key, keyLength);

    return;
  }

  size_t dataOffset = 24;
  if (config->kind == kAuthRevEmu2013) {
    // copied from the original revemu2013 generator; reunion doesn't read these fields
    uint32_t now = (uint32_t)time(NULL);
    Write32(ticket, 24, now + 90123U);
    ticket[27] = (uint8_t)~(ticket[27] + ticket[24]);
    Write32(ticket, 28, ~now);
    Write32(ticket, 32, (hash << 1U) >> 3U);
    dataOffset = 40;
  }

  uint8_t authData[32] = {0};
  memcpy(authData, config->key, keyLength);
  static const uint8_t encryptionKey[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
  static const uint8_t wrappingKey[] = "_YOU_SERIOUSLY_NEED_TO_GET_LAID_";
  AuthCrypto_Encrypt(encryptionKey, authData, ticket + dataOffset);
  AuthCrypto_Encrypt(wrappingKey, encryptionKey, ticket + dataOffset + 32);
  AuthCrypto_Digest(authData, ticket + dataOffset + 64);
}

void AuthTicket_Generate(uint8_t* ticket, const auth_ticket_config_t* config) {
  memset(ticket, 0, AuthTicket_GetSize(config->kind));

  switch (config->kind) {
    case kAuthOldRevEmu:
      Write32(ticket, 0, 0xffff);
      Write32(ticket, 4, config->volumeId);
      break;
    case kAuthSteamEmu:
      Write32(ticket, 80, UINT32_MAX);
      // steamemu sends the volume serial xored
      Write32(ticket, 84, (config->volumeId ^ kSteamEmuVolumeXor) & 0x7fffffffU);
      break;
    case kAuthRevEmu:
    case kAuthSC2009:
    case kAuthRevEmu2013:
      GenerateRevTicket(ticket, config);
      break;
    case kAuthAVSMP:
      Write32(ticket, 0, 0x14);
      Write32(ticket, 12, config->accountId);
      Write32(ticket, 16, kSteamIdHigh);
      break;
    case kAuthSetti:
      Write32(ticket, 0, 0xd4ca7f7b);
      Write32(ticket, 4, 0xc7db6023);
      Write32(ticket, 8, 0x6d6a2e1f);
      Write32(ticket, 20, 0xb4c43105);
      break;
    default:
      break;
  }
}
