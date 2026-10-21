#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct FriendGameInfo_t FriendGameInfo_t;
typedef struct ISteamFriends ISteamFriends;

typedef uint32_t AppId_t;
typedef uint64_t SteamAPICall_t;

typedef enum {
  k_EFriendRelationshipNone = 0,
  k_EFriendRelationshipBlocked = 1,
  k_EFriendRelationshipRequestRecipient = 2,
  k_EFriendRelationshipFriend = 3,
  k_EFriendRelationshipRequestInitiator = 4,
  k_EFriendRelationshipIgnored = 5,
  k_EFriendRelationshipIgnoredFriend = 6,
  k_EFriendRelationshipSuggested = 7,
} EFriendRelationship;

typedef enum {
  k_EPersonaStateOffline = 0,
  k_EPersonaStateOnline = 1,
  k_EPersonaStateBusy = 2,
  k_EPersonaStateAway = 3,
  k_EPersonaStateSnooze = 4,
  k_EPersonaStateLookingToTrade = 5,
  k_EPersonaStateLookingToPlay = 6,
} EPersonaState;

typedef enum {
  k_EOverlayToStoreFlag_None = 0,
  k_EOverlayToStoreFlag_AddToCart = 1,
  k_EOverlayToStoreFlag_AddToCartAndShow = 2,
} EOverlayToStoreFlag;

typedef enum {
  k_EChatEntryTypeInvalid = 0,
  k_EChatEntryTypeChatMsg = 1,
  k_EChatEntryTypeTyping = 2,
  k_EChatEntryTypeInviteGame = 3,
  k_EChatEntryTypeEmote = 4,
  k_EChatEntryTypeLeftConversation = 6,
  k_EChatEntryTypeEntered = 7,
  k_EChatEntryTypeWasKicked = 8,
  k_EChatEntryTypeWasBanned = 9,
  k_EChatEntryTypeDisconnected = 10,
  k_EChatEntryTypeHistoricalChat = 11,
} EChatEntryType;

typedef struct {
  union {
    struct {
      uint32_t m_unAccountID : 32;
      unsigned int m_unAccountInstance : 20;
      unsigned int m_EAccountType : 4;
      unsigned int m_EUniverse : 8;
    } m_comp;
    uint64_t m_unAll64Bits;
  } m_steamid;
} CSteamID;

// `SteamFriends013`, the version `libsteam_api.so` of build 8684 hands out
typedef struct {
  const char* (*GetPersonaName)(ISteamFriends* self);
  SteamAPICall_t (*SetPersonaName)(ISteamFriends* self, const char* pchPersonaName);
  EPersonaState (*GetPersonaState)(ISteamFriends* self);
  int (*GetFriendCount)(ISteamFriends* self, int iFriendFlags);
  CSteamID (*GetFriendByIndex)(ISteamFriends* self, int iFriend, int iFriendFlags);
  EFriendRelationship (*GetFriendRelationship)(ISteamFriends* self, CSteamID steamIDFriend);
  EPersonaState (*GetFriendPersonaState)(ISteamFriends* self, CSteamID steamIDFriend);
  const char* (*GetFriendPersonaName)(ISteamFriends* self, CSteamID steamIDFriend);
  bool (*GetFriendGamePlayed)(ISteamFriends* self, CSteamID steamIDFriend,
                              FriendGameInfo_t* pFriendGameInfo);
  const char* (*GetFriendPersonaNameHistory)(ISteamFriends* self, CSteamID steamIDFriend,
                                             int iPersonaName);
  bool (*HasFriend)(ISteamFriends* self, CSteamID steamIDFriend, int iFriendFlags);
  int (*GetClanCount)(ISteamFriends* self);
  CSteamID (*GetClanByIndex)(ISteamFriends* self, int iClan);
  const char* (*GetClanName)(ISteamFriends* self, CSteamID steamIDClan);
  const char* (*GetClanTag)(ISteamFriends* self, CSteamID steamIDClan);
  bool (*GetClanActivityCounts)(ISteamFriends* self, CSteamID steamIDClan, int* pnOnline,
                                int* pnInGame, int* pnChatting);
  SteamAPICall_t (*DownloadClanActivityCounts)(ISteamFriends* self, CSteamID* psteamIDClans,
                                               int cClansToRequest);
  int (*GetFriendCountFromSource)(ISteamFriends* self, CSteamID steamIDSource);
  CSteamID (*GetFriendFromSourceByIndex)(ISteamFriends* self, CSteamID steamIDSource, int iFriend);
  bool (*IsUserInSource)(ISteamFriends* self, CSteamID steamIDUser, CSteamID steamIDSource);
  void (*SetInGameVoiceSpeaking)(ISteamFriends* self, CSteamID steamIDUser, bool bSpeaking);
  void (*ActivateGameOverlay)(ISteamFriends* self, const char* pchDialog);
  void (*ActivateGameOverlayToUser)(ISteamFriends* self, const char* pchDialog, CSteamID steamID);
  void (*ActivateGameOverlayToWebPage)(ISteamFriends* self, const char* pchURL);
  void (*ActivateGameOverlayToStore)(ISteamFriends* self, AppId_t nAppID,
                                     EOverlayToStoreFlag eFlag);
  void (*SetPlayedWith)(ISteamFriends* self, CSteamID steamIDUserPlayedWith);
  void (*ActivateGameOverlayInviteDialog)(ISteamFriends* self, CSteamID steamIDLobby);
  int (*GetSmallFriendAvatar)(ISteamFriends* self, CSteamID steamIDFriend);
  int (*GetMediumFriendAvatar)(ISteamFriends* self, CSteamID steamIDFriend);
  int (*GetLargeFriendAvatar)(ISteamFriends* self, CSteamID steamIDFriend);
  bool (*RequestUserInformation)(ISteamFriends* self, CSteamID steamIDUser, bool bRequireNameOnly);
  SteamAPICall_t (*RequestClanOfficerList)(ISteamFriends* self, CSteamID steamIDClan);
  CSteamID (*GetClanOwner)(ISteamFriends* self, CSteamID steamIDClan);
  int (*GetClanOfficerCount)(ISteamFriends* self, CSteamID steamIDClan);
  CSteamID (*GetClanOfficerByIndex)(ISteamFriends* self, CSteamID steamIDClan, int iOfficer);
  uint32_t (*GetUserRestrictions)(ISteamFriends* self);
  bool (*SetRichPresence)(ISteamFriends* self, const char* pchKey, const char* pchValue);
  void (*ClearRichPresence)(ISteamFriends* self);
  const char* (*GetFriendRichPresence)(ISteamFriends* self, CSteamID steamIDFriend,
                                       const char* pchKey);
  int (*GetFriendRichPresenceKeyCount)(ISteamFriends* self, CSteamID steamIDFriend);
  const char* (*GetFriendRichPresenceKeyByIndex)(ISteamFriends* self, CSteamID steamIDFriend,
                                                 int iKey);
  void (*RequestFriendRichPresence)(ISteamFriends* self, CSteamID steamIDFriend);
  bool (*InviteUserToGame)(ISteamFriends* self, CSteamID steamIDFriend,
                           const char* pchConnectString);
  int (*GetCoplayFriendCount)(ISteamFriends* self);
  CSteamID (*GetCoplayFriend)(ISteamFriends* self, int iCoplayFriend);
  int (*GetFriendCoplayTime)(ISteamFriends* self, CSteamID steamIDFriend);
  AppId_t (*GetFriendCoplayGame)(ISteamFriends* self, CSteamID steamIDFriend);
  SteamAPICall_t (*JoinClanChatRoom)(ISteamFriends* self, CSteamID steamIDClan);
  bool (*LeaveClanChatRoom)(ISteamFriends* self, CSteamID steamIDClan);
  int (*GetClanChatMemberCount)(ISteamFriends* self, CSteamID steamIDClan);
  CSteamID (*GetChatMemberByIndex)(ISteamFriends* self, CSteamID steamIDClan, int iUser);
  bool (*SendClanChatMessage)(ISteamFriends* self, CSteamID steamIDClanChat, const char* pchText);
  int (*GetClanChatMessage)(ISteamFriends* self, CSteamID steamIDClanChat, int iMessage,
                            void* prgchText, int cchTextMax, EChatEntryType*, CSteamID*);
  bool (*IsClanChatAdmin)(ISteamFriends* self, CSteamID steamIDClanChat, CSteamID steamIDUser);
  bool (*IsClanChatWindowOpenInSteam)(ISteamFriends* self, CSteamID steamIDClanChat);
  bool (*OpenClanChatWindowInSteam)(ISteamFriends* self, CSteamID steamIDClanChat);
  bool (*CloseClanChatWindowInSteam)(ISteamFriends* self, CSteamID steamIDClanChat);
  bool (*SetListenForFriendsMessages)(ISteamFriends* self, bool bInterceptEnabled);
  bool (*ReplyToFriendMessage)(ISteamFriends* self, CSteamID steamIDFriend,
                               const char* pchMsgToSend);
  int (*GetFriendMessage)(ISteamFriends* self, CSteamID steamIDFriend, int iMessageID, void* pvData,
                          int cubData, EChatEntryType* peChatEntryType);
  SteamAPICall_t (*GetFollowerCount)(ISteamFriends* self, CSteamID steamID);
  SteamAPICall_t (*IsFollowing)(ISteamFriends* self, CSteamID steamID);
  SteamAPICall_t (*EnumerateFollowingList)(ISteamFriends* self, uint32_t unStartIndex);
} ISteamFriendsVtbl;

struct ISteamFriends {
  const ISteamFriendsVtbl* vtable;
};
