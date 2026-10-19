#pragma once

#include <stddef.h>
#include <stdint.h>

typedef enum {
  kAuthInvalid = -1,
  kAuthSteam,
  kAuthNoSteam,
  kAuthOldRevEmu,
  kAuthSteamEmu,
  kAuthRevEmu,
  kAuthSC2009,
  kAuthRevEmu2013,
  kAuthAVSMP,
  kAuthSetti,
  kAuthKindCount,
} auth_kind_t;

typedef struct {
  auth_kind_t kind;
  const char* key;
  uint32_t volumeId;
  uint32_t accountId;
} auth_ticket_config_t;

auth_kind_t AuthTicket_FindKind(const char* name);
const char* AuthTicket_GetName(auth_kind_t kind);
size_t AuthTicket_GetSize(auth_kind_t kind);
size_t AuthTicket_GetKeyLimit(auth_kind_t kind);
void AuthTicket_Generate(uint8_t* ticket, const auth_ticket_config_t* config);
