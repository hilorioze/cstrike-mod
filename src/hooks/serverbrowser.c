#define _GNU_SOURCE  // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "loader.h"
#include "steam/abi.h"

static void (*real_OnRemoveFromFavorites)(void* page);

static void* (*gFindChildByName)(void* panel, const char* childName, bool recurseDown);
static int (*gGetSelectedItemsCount)(void* list);
static int (*gGetSelectedItem)(void* list, int selectionIndex);
static unsigned int (*gGetItemUserData)(void* list, int itemID);
static void* (*gGetItem)(void* list, int itemID);
static const char* (*gGetString)(void* keyValues, const char* keyName, const char* defaultValue);
static ISteamMatchmaking* (*gSteamMatchmaking)(void);

static void ResolveServerBrowser(void* page) {
  Dl_info info;
  dladdr(*(void**)page, &info);
  void* library = dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD);

  real_OnRemoveFromFavorites = RealDlsym(library, "_ZN14CFavoriteGames21OnRemoveFromFavoritesEv");
  gFindChildByName = RealDlsym(library, "_ZN5vgui25Panel15FindChildByNameEPKcb");
  gGetSelectedItemsCount = RealDlsym(library, "_ZN5vgui29ListPanel21GetSelectedItemsCountEv");
  gGetSelectedItem = RealDlsym(library, "_ZN5vgui29ListPanel15GetSelectedItemEi");
  gGetItemUserData = RealDlsym(library, "_ZN5vgui29ListPanel15GetItemUserDataEi");
  gGetItem = RealDlsym(library, "_ZN5vgui29ListPanel7GetItemEi");
  gGetString = RealDlsym(library, "_ZN9KeyValues9GetStringEPKcS1_");
  gSteamMatchmaking = RealDlsym(library, "SteamMatchmaking");
}

static void RemoveFavorite(ISteamMatchmaking* matchmaking, const char* address) {
  int count = matchmaking->vtable->GetFavoriteGameCount(matchmaking);

  for (int i = 0; i < count; i++) {
    AppId_t appID = 0;
    uint32_t ip = 0;
    uint16_t connPort = 0;
    uint16_t queryPort = 0;
    uint32_t flags = 0;
    uint32_t lastPlayed = 0;
    matchmaking->vtable->GetFavoriteGame(matchmaking, i, &appID, &ip, &connPort, &queryPort, &flags,
                                         &lastPlayed);
    if (!(flags & k_unFavoriteFlagFavorite))  // NOLINT(hicpp-signed-bitwise)
      continue;

    // the row's `IPAddr` is `netadr_t::ToString` of the server
    char favoriteAddress[32];
    // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
    (void)snprintf(favoriteAddress, sizeof(favoriteAddress), "%u.%u.%u.%u:%u", ip >> 24U,
                   (ip >> 16U) & 0xffU, (ip >> 8U) & 0xffU, ip & 0xffU, connPort);
    if (strcmp(favoriteAddress, address) == 0) {
      matchmaking->vtable->RemoveFavoriteGame(matchmaking, appID, ip, connPort, queryPort,
                                              k_unFavoriteFlagFavorite);
      return;
    }
  }
}

// a favorite answering a ping after a connect gets a new row with a negative server id that
// `GetServerDetails` doesn't know, so the original skips it until a refresh: find it in steam's
// favorites by address and remove it, steam's callback then drops the row
__attribute__((visibility("default"))) void OnRemoveFromFavorites(void* page) __asm__(
    "_ZN14CFavoriteGames21OnRemoveFromFavoritesEv");

void OnRemoveFromFavorites(void* page) {
  if (!real_OnRemoveFromFavorites)
    ResolveServerBrowser(page);

  ISteamMatchmaking* matchmaking = gSteamMatchmaking();
  void* gameList = gFindChildByName(page, "gamelist", false);
  int count = gGetSelectedItemsCount(gameList);

  for (int i = 0; i < count; i++) {
    int itemID = gGetSelectedItem(gameList, i);
    int serverID = (int)gGetItemUserData(gameList, itemID);
    if (serverID < 0)
      RemoveFavorite(matchmaking, gGetString(gGetItem(gameList, itemID), "IPAddr", ""));
  }

  real_OnRemoveFromFavorites(page);
}
