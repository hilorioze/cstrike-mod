#define _GNU_SOURCE  // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

#include <dlfcn.h>
#include <dobby.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#include "auth/ticket.h"
#include "features/auth.h"
#include "globals.h"
#include "goldsrc/abi.h"
#include "loader.h"

static cvar_t* gAuth;
static cvar_t* gAuthKey;
static cvar_t* gAuthVolumeId;
static cvar_t* gAuthAccountId;
static auth_ticket_config_t gTicketConfig;
static bool gNativeConnection;
static void (*gSendConnectPacketOriginal)(void);
static void (*gDisconnect)(void);
static void (*gWriteConfiguration)(void);
static int (*gInitiateGameConnectionOriginal)(void* ticket, int capacity, uint64_t serverId,
                                              uint32_t ip, uint16_t port, int secure);
static void (*gTerminateGameConnectionOriginal)(uint32_t ip, uint16_t port);

static void GenerateKey(void) {
  uint8_t random[15];
  if (getrandom(random, sizeof(random), 0) != sizeof(random))
    __builtin_trap();

  // a non-digit makes reunion keep the key as an hdd serial instead of parsing it as a number;
  // 32 bytes fit every rev format
  char key[33] = "CS";
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < sizeof(random); i++) {
    key[2 + 2 * i] = hex[random[i] >> 4U];
    key[3 + 2 * i] = hex[random[i] & 15U];
  }

  gEnginefuncs.Cvar_Set("cl_authkey", key);
}

static void GenerateIdentifier(const cvar_t* variable) {
  uint32_t random;
  if (getrandom(&random, sizeof(random), 0) != sizeof(random))
    __builtin_trap();

  // 31 bits survive every format's masking; bit 16 keeps the ids above the placeholder ones reunion
  // turns into `STEAM_ID_PENDING`
  uint32_t value = (random & 0x7fffffffU) | 0x10000U;
  char text[11];
  (void)snprintf(text, sizeof(text), "%u", value);
  gEnginefuncs.Cvar_Set(variable->name, text);
}

static void EnsureIdentity(void) {
  bool generated = false;
  if (!gAuthKey->string[0]) {
    GenerateKey();
    generated = true;
  }
  if (!gAuthVolumeId->string[0]) {
    GenerateIdentifier(gAuthVolumeId);
    generated = true;
  }
  if (!gAuthAccountId->string[0]) {
    GenerateIdentifier(gAuthAccountId);
    generated = true;
  }

  if (generated)
    gWriteConfiguration();
}

static bool ReadIdentifier(const cvar_t* variable, uint32_t* result) {
  const char* text = variable->string;
  bool hexadecimal = text[0] == '0' && (text[1] == 'x' || text[1] == 'X');
  errno = 0;
  char* end;
  unsigned long long value = strtoull(text, &end, hexadecimal ? 16 : 10);
  if (text[0] < '0' || text[0] > '9' || errno || *end || value > UINT32_MAX) {
    gEnginefuncs.Con_Printf("%s must be an unsigned 32-bit integer (decimal or 0xhex)\n",
                            variable->name);

    return false;
  }

  *result = (uint32_t)value;

  return true;
}

static bool PrepareTicket(void) {
  gTicketConfig.kind = AuthTicket_FindKind(gAuth->string);
  if (gTicketConfig.kind == kAuthInvalid) {
    gEnginefuncs.Con_Printf("unknown cl_auth mode '%s'; use auth to list modes\n", gAuth->string);

    return false;
  }

  if (gTicketConfig.kind != kAuthSteam && gTicketConfig.kind != kAuthNoSteam &&
      gTicketConfig.kind != kAuthSetti)
    EnsureIdentity();

  size_t keyLimit = AuthTicket_GetKeyLimit(gTicketConfig.kind);
  if (keyLimit) {
    size_t keyLength = strlen(gAuthKey->string);
    if (keyLength == 0 || keyLength > keyLimit) {
      gEnginefuncs.Con_Printf("%s requires cl_authkey with 1..%zu bytes\n", gAuth->string,
                              keyLimit);

      return false;
    }

    gTicketConfig.key = gAuthKey->string;
  }

  if (gTicketConfig.kind == kAuthOldRevEmu || gTicketConfig.kind == kAuthSteamEmu)
    return ReadIdentifier(gAuthVolumeId, &gTicketConfig.volumeId);

  if (gTicketConfig.kind == kAuthAVSMP)
    return ReadIdentifier(gAuthAccountId, &gTicketConfig.accountId);

  return true;
}

static void CL_SendConnectPacket(void) {
  if (!PrepareTicket()) {
    gDisconnect();

    return;
  }

  gSendConnectPacketOriginal();
}

static int Steam_GSInitiateGameConnection(void* ticket, int capacity, uint64_t serverId,
                                          uint32_t ip, uint16_t port, int secure) {
  if (gTicketConfig.kind == kAuthSteam) {
    gNativeConnection = true;

    return gInitiateGameConnectionOriginal(ticket, capacity, serverId, ip, port, secure);
  }

  size_t size = AuthTicket_GetSize(gTicketConfig.kind);
  AuthTicket_Generate(ticket, &gTicketConfig);
  gEnginefuncs.Con_Printf("auth: %s (%zu-byte ticket)\n", AuthTicket_GetName(gTicketConfig.kind),
                          size);

  return (int)size;
}

static void Steam_GSTerminateGameConnection(uint32_t ip, uint16_t port) {
  if (gNativeConnection)
    gTerminateGameConnectionOriginal(ip, port);

  gNativeConnection = false;
}

static void PrintStatus(void) {
  gEnginefuncs.Con_Printf(
      "cl_auth \"%s\"\ncl_authkey \"%s\"\ncl_auth_volumeid \"%s\"\ncl_auth_accountid \"%s\"\n",
      gAuth->string, gAuthKey->string, gAuthVolumeId->string, gAuthAccountId->string);
  gEnginefuncs.Con_Printf("auth <mode> | regenerate\nmodes:");
  for (int i = 0; i < kAuthKindCount; i++)
    gEnginefuncs.Con_Printf(" %s", AuthTicket_GetName((auth_kind_t)i));

  gEnginefuncs.Con_Printf("\n");
}

static void Auth_Command(void) {
  if (gEnginefuncs.Cmd_Argc() != 2) {
    PrintStatus();

    return;
  }

  char* argument = gEnginefuncs.Cmd_Argv(1);
  if (strcmp(argument, "regenerate") == 0) {
    GenerateKey();
    GenerateIdentifier(gAuthVolumeId);
    GenerateIdentifier(gAuthAccountId);
    gWriteConfiguration();
    PrintStatus();

    return;
  }

  if (AuthTicket_FindKind(argument) == kAuthInvalid) {
    gEnginefuncs.Con_Printf("unknown auth mode '%s'; use auth to list modes\n", argument);

    return;
  }

  gEnginefuncs.Cvar_Set("cl_auth", argument);
  gWriteConfiguration();
  gEnginefuncs.Con_Printf("auth: %s\n", gAuth->string);
}

void Auth_Initialize(void) {
  gAuth = gEnginefuncs.pfnRegisterVariable("cl_auth", "steam", FCVAR_ARCHIVE);
  gAuthKey = gEnginefuncs.pfnRegisterVariable("cl_authkey", "", FCVAR_ARCHIVE);
  gAuthVolumeId = gEnginefuncs.pfnRegisterVariable("cl_auth_volumeid", "", FCVAR_ARCHIVE);
  gAuthAccountId = gEnginefuncs.pfnRegisterVariable("cl_auth_accountid", "", FCVAR_ARCHIVE);
  gEnginefuncs.pfnAddCommand("auth", Auth_Command);

  Dl_info engineInfo;
  if (!dladdr((void*)gEnginefuncs.pfnGetCvarFloat, &engineInfo))
    __builtin_trap();

  void* engineModule = dlopen(engineInfo.dli_fname, RTLD_LAZY | RTLD_NOLOAD);
  if (!engineModule)
    __builtin_trap();

  void* sendConnectPacket = RealDlsym(engineModule, "CL_SendConnectPacket");
  void* initiateGameConnection = RealDlsym(engineModule, "Steam_GSInitiateGameConnection");
  void* terminateGameConnection = RealDlsym(engineModule, "Steam_GSTerminateGameConnection");
  gDisconnect = RealDlsym(engineModule, "CL_Disconnect");
  gWriteConfiguration = RealDlsym(engineModule, "Host_WriteConfiguration");
  if (!sendConnectPacket || !initiateGameConnection || !terminateGameConnection || !gDisconnect ||
      !gWriteConfiguration)
    __builtin_trap();

  if (DobbyHook(sendConnectPacket, CL_SendConnectPacket, (void**)&gSendConnectPacketOriginal) != 0)
    __builtin_trap();

  if (DobbyHook(initiateGameConnection, Steam_GSInitiateGameConnection,
                (void**)&gInitiateGameConnectionOriginal) != 0)
    __builtin_trap();

  if (DobbyHook(terminateGameConnection, Steam_GSTerminateGameConnection,
                (void**)&gTerminateGameConnectionOriginal) != 0)
    __builtin_trap();

  dlclose(engineModule);
}
