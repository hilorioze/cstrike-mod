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
#include "server.h"

static cvar_t* gAuth;
static cvar_t* gAuthKey;
static cvar_t* gAuthVolumeId;
static cvar_t* gAuthAccountId;
static const qboolean* gHostInitialized;
static void* (*gOpenPathId)(const char* path, const char* mode, const char* pathId);
static int (*gFilePrintf)(void* file, const char* format, ...);
static void (*gCloseFile)(void* file);
static void (*gWriteConfigurationOriginal)(void);
static auth_ticket_config_t gTicketConfig;
static bool gNativeConnection;
static uint32_t gNativeIp;
static uint16_t gNativePort;
static void (*gSendConnectPacketOriginal)(void);
static void (*gDisconnect)(void);
static int (*gInitiateGameConnectionOriginal)(void* ticket, int capacity, uint64_t serverId,
                                              uint32_t ip, uint16_t port, int secure);
static void (*gTerminateGameConnectionOriginal)(uint32_t ip, uint16_t port);

#define SETTINGS_FORMAT \
  "cl_auth \"%s\"\ncl_authkey \"%s\"\ncl_auth_volumeid \"%s\"\ncl_auth_accountid \"%s\"\n"

// keep the settings out of `config.cfg`: the engine rewrites it without unregistered cvars, so a
// game run without the mod would drop the auth mode and identity
static void Host_WriteConfiguration(void) {
  gWriteConfigurationOriginal();

  // a shutdown during startup comes before `auth.cfg` runs and would overwrite it with the defaults
  if (!*gHostInitialized)
    return;

  void* file = gOpenPathId("auth.cfg", "w", "GAMECONFIG");
  gFilePrintf(file, SETTINGS_FORMAT, gAuth->string, gAuthKey->string, gAuthVolumeId->string,
              gAuthAccountId->string);
  gCloseFile(file);
}

static void GenerateKey(void) {
  uint8_t random[64];
  if (getrandom(random, sizeof(random), 0) != sizeof(random))
    __builtin_trap();

  // copy what real clients send so the key doesn't stand out in the server log: revemu sends its
  // hdd serial as 64 uppercase base36 characters, while the 32-byte formats get xash3d-fwgs's
  // shape, 25 lowercase hex digits of an md5 followed by 7 base36 characters its spoofer picks to
  // steer the steam id; the letters keep reunion treating either as an hdd serial rather than a
  // number
  auth_kind_t kind = AuthTicket_FindKind(gAuth->string);
  size_t hexLength = kind != kAuthInvalid && AuthTicket_GetKeyLimit(kind) == 32 ? 25 : 0;
  size_t length = hexLength ? 32 : sizeof(random);

  char key[sizeof(random) + 1];
  static const char hex[] = "0123456789abcdef";
  static const char base36[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  for (size_t i = 0; i < length; i++)
    key[i] = i < hexLength ? hex[random[i] & 15U] : base36[random[i] % (sizeof(base36) - 1)];
  key[length] = '\0';

  gEnginefuncs.Cvar_Set("cl_authkey", key);
}

static void GenerateVolumeId(void) {
  uint32_t value;
  if (getrandom(&value, sizeof(value), 0) != sizeof(value))
    __builtin_trap();

  // a windows volume serial is a full 32-bit number; reunion masks the top bit itself and treats 0
  // as pending, so draw all 32 bits and only avoid 0 (the old `& 0x7fffffff | 0x10000` left bit 31
  // clear and bit 16 set on every id, an obvious tell)
  if (!value)
    value = 1;

  char text[11];
  (void)snprintf(text, sizeof(text), "%u", value);
  gEnginefuncs.Cvar_Set(gAuthVolumeId->name, text);
}

static void GenerateAccountId(void) {
  uint32_t random;
  if (getrandom(&random, sizeof(random), 0) != sizeof(random))
    __builtin_trap();

  // steam account ids are assigned upwards from 1 and currently reach into the ~1.7 billion range;
  // stay inside that window so the id reads like a real account number and lands above the 0/1234
  // values avsmp turns into `STEAM_ID_PENDING`
  uint32_t value = 10000000U + random % 1490000000U;

  char text[11];
  (void)snprintf(text, sizeof(text), "%u", value);
  gEnginefuncs.Cvar_Set(gAuthAccountId->name, text);
}

static void EnsureIdentity(void) {
  bool generated = false;
  if (!gAuthKey->string[0]) {
    GenerateKey();
    generated = true;
  }
  if (!gAuthVolumeId->string[0]) {
    GenerateVolumeId();
    generated = true;
  }
  if (!gAuthAccountId->string[0]) {
    GenerateAccountId();
    generated = true;
  }

  if (generated)
    Host_WriteConfiguration();
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
      gEnginefuncs.Con_Printf(
          "%s requires cl_authkey with 1..%zu bytes; auth regenerate makes one for this mode\n",
          gAuth->string, keyLimit);

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
    // steam reports the server it is given to friends; it only warns about a zero address and the
    // ticket doesn't carry it, so a zero one still connects and shows just the game. the engine
    // passes the address in `netadr_t` byte order
    netadr_t address = {.type = NA_IP, .port = port};
    memcpy(address.ip, &ip, sizeof(address.ip));
    if (Server_IsFeatureEnabledAt(kFeatureHideServer, &address)) {
      serverId = 0;
      ip = 0;
      port = 0;
    }

    gNativeConnection = true;
    gNativeIp = ip;
    gNativePort = port;

    return gInitiateGameConnectionOriginal(ticket, capacity, serverId, ip, port, secure);
  }

  size_t size = AuthTicket_GetSize(gTicketConfig.kind);
  AuthTicket_Generate(ticket, &gTicketConfig);
  gEnginefuncs.Con_Printf("auth: %s (%zu-byte ticket)\n", AuthTicket_GetName(gTicketConfig.kind),
                          size);

  return (int)size;
}

// steam finds the server to drop by the address it was initiated with
static void Steam_GSTerminateGameConnection(uint32_t ip, uint16_t port) {
  if (gNativeConnection)
    gTerminateGameConnectionOriginal(gNativeIp, gNativePort);

  gNativeConnection = false;
}

static void PrintStatus(void) {
  gEnginefuncs.Con_Printf(SETTINGS_FORMAT, gAuth->string, gAuthKey->string, gAuthVolumeId->string,
                          gAuthAccountId->string);
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
    GenerateVolumeId();
    GenerateAccountId();
    Host_WriteConfiguration();
    PrintStatus();

    return;
  }

  if (AuthTicket_FindKind(argument) == kAuthInvalid) {
    gEnginefuncs.Con_Printf("unknown auth mode '%s'; use auth to list modes\n", argument);

    return;
  }

  gEnginefuncs.Cvar_Set("cl_auth", argument);
  Host_WriteConfiguration();
  gEnginefuncs.Con_Printf("auth: %s\n", gAuth->string);
}

void Auth_Initialize(void) {
  // no default mode: connecting without a chosen one fails instead of exposing the steam account
  gAuth = gEnginefuncs.pfnRegisterVariable("cl_auth", "", 0);
  gAuthKey = gEnginefuncs.pfnRegisterVariable("cl_authkey", "", 0);
  gAuthVolumeId = gEnginefuncs.pfnRegisterVariable("cl_auth_volumeid", "", 0);
  gAuthAccountId = gEnginefuncs.pfnRegisterVariable("cl_auth_accountid", "", 0);
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
  void* writeConfiguration = RealDlsym(engineModule, "Host_WriteConfiguration");
  void (*addText)(const char* text) = RealDlsym(engineModule, "Cbuf_AddText");
  gDisconnect = RealDlsym(engineModule, "CL_Disconnect");
  gHostInitialized = RealDlsym(engineModule, "host_initialized");
  gOpenPathId = RealDlsym(engineModule, "FS_OpenPathID");
  gFilePrintf = RealDlsym(engineModule, "FS_FPrintf");
  gCloseFile = RealDlsym(engineModule, "FS_Close");
  if (!sendConnectPacket || !initiateGameConnection || !terminateGameConnection ||
      !writeConfiguration || !addText || !gDisconnect || !gHostInitialized || !gOpenPathId ||
      !gFilePrintf || !gCloseFile)
    __builtin_trap();

  addText("exec auth.cfg\n");

  if (DobbyHook(sendConnectPacket, CL_SendConnectPacket, (void**)&gSendConnectPacketOriginal) != 0)
    __builtin_trap();

  if (DobbyHook(initiateGameConnection, Steam_GSInitiateGameConnection,
                (void**)&gInitiateGameConnectionOriginal) != 0)
    __builtin_trap();

  if (DobbyHook(writeConfiguration, Host_WriteConfiguration,
                (void**)&gWriteConfigurationOriginal) != 0)
    __builtin_trap();

  if (DobbyHook(terminateGameConnection, Steam_GSTerminateGameConnection,
                (void**)&gTerminateGameConnectionOriginal) != 0)
    __builtin_trap();

  dlclose(engineModule);
}
