#pragma once

#include <stdbool.h>

#include "goldsrc/abi.h"

#define HITGROUP_HEAD 1

#define MAX_PLAYERS 32
#define MAX_SCOREBOARD_PLAYERS 64

#define OBS_NONE 0
#define OBS_CHASE_LOCKED 1
#define OBS_CHASE_FREE 2
#define OBS_ROAMING 3
#define OBS_IN_EYE 4
#define OBS_MAP_FREE 5
#define OBS_MAP_CHASE 6

#define TEAM_UNASSIGNED 0
#define TEAM_TERRORIST 1
#define TEAM_CT 2
#define TEAM_SPECTATOR 3

typedef struct {
  vec_t x;
  vec_t y;
  vec_t z;
} Vector;

typedef struct extra_player_info_s {
  short frags;
  short deaths;
  short team_id;
  int has_c4;
  int vip;
  Vector origin;
  float radarflash;
  int radarflashon;
  int radarflashes;
  short playerclass;
  short teamnumber;
  char teamname[16];
  bool dead;
  float showhealth;
  int health;
  char location[32];
  int sb_health;
  int sb_account;
  int has_defuse_kit;
} extra_player_info_t;

typedef struct {
  int x;
  int y;
} client_position_t;

typedef struct {
  int left;
  int right;
  int top;
  int bottom;
} client_wrect_t;

typedef struct {
  void* vtable;
  client_position_t m_pos;
  int m_type;
  int m_iFlags;
} client_hud_base_t;

typedef struct {
  unsigned char r;
  unsigned char g;
  unsigned char b;
  unsigned char a;
} client_rgba_t;

typedef struct {
  float fExpire;
  float fBaseline;
  int x;
  int y;
} client_damage_image_t;

typedef struct {
  int effect;
  byte r1;
  byte g1;
  byte b1;
  byte a1;
  byte r2;
  byte g2;
  byte b2;
  byte a2;
  float x;
  float y;
  float fadein;
  float fadeout;
  float holdtime;
  float fxtime;
  const char* pName;
  const char* pMessage;
} client_internal_textmessage_t;

typedef struct {
  float x;
  float y;
  float z;
} client_vector_t;

typedef struct {
  char map[64];
  client_vector_t origin;
  float zoom;
  int layers;
  float layersHeights[1];
  char layersImages[1][255];
  qboolean rotated;
  int insetWindowX;
  int insetWindowY;
  int insetWindowHeight;
  int insetWindowWidth;
} client_overview_info_t;

typedef struct {
  HSPRITE hSprite;
  void* entity;
  double killTime;
} client_overview_entity_t;

typedef struct {
  void* vtable;
  client_vector_t m_StartPoint;
  client_vector_t m_EndPoint;
  client_vector_t m_StartAngle;
  client_vector_t m_EndAngle;
  client_vector_t m_Center;
  float m_StartFov;
  float m_EndFov;
  bool m_SmoothStart;
  bool m_SmoothEnd;
} client_interpolation_t;

typedef struct {
  float time;
  client_vector_t position;
  client_vector_t angle;
  float fov;
  int flags;
} client_camera_waypoint_t;

typedef struct {
  client_textmessage_t* pMessage;
  unsigned int font;
  wchar_t args[4][64];
  int numArgs;
} client_message_t;

typedef struct {
  client_textmessage_t* pMessage;
  float time;
  int x;
  int y;
  int totalWidth;
  int totalHeight;
  int width;
  int lines;
  int lineLength;
  int length;
  int r;
  int g;
  int b;
  int text;
  int fadeBlend;
  float charTime;
  float fadeTime;
} client_message_parms_t;

typedef struct {
  char szSpriteName[24];
  HSPRITE spr;
  client_wrect_t rc;
  unsigned char r;
  unsigned char g;
  unsigned char b;
  int bFlash;
} client_hud_status_icon_t;

typedef struct {
  client_hud_base_t base;
  float m_fFade;
  client_rgba_t m_rgba;
  void* m_pWeapon;
  int m_HUD_bucket0;
  int m_HUD_selection;
  HSPRITE m_hObserverCrosshair;
  client_wrect_t m_rcObserverCrosshair;
  int m_bObserverCrosshair;
  int m_iAmmoLastCheck;
  float m_flCrosshairDistance;
  int m_iAlpha;
  int m_R;
  int m_G;
  int m_B;
  int m_cvarR;
  int m_cvarG;
  int m_cvarB;
  int m_iCurrentCrosshair;
  bool m_bAdditive;
  int m_iCrosshairScaleBase;
} client_hud_ammo_t;

typedef struct {
  client_hud_base_t base;
  int m_iHealth;
  int m_HUD_dmg_bio;
  int m_HUD_cross;
  float m_fFade;
  float m_fAttackFront;
  float m_fAttackRear;
  float m_fAttackLeft;
  float m_fAttackRight;
  bool m_bTrackArray[65];
  int m_iPlayerLastPointedAt;
  int m_iPlayerNum;
  bool m_bDrawRadar;
  HSPRITE m_hSprite;
  HSPRITE m_hDamage;
  client_wrect_t* m_hrad;
  client_wrect_t* m_hradopaque;
  HSPRITE m_hRadar;
  HSPRITE m_hRadaropaque;
  client_damage_image_t m_dmg[12];
  int m_bitsDamage;
} client_hud_health_t;

typedef struct {
  client_hud_base_t base;
  int m_iDrawCycle;
  client_internal_textmessage_t m_HUDMessages[8];
  char m_HUDMessageText[8][128];
  int m_lastHudMessage;
  client_overview_info_t m_OverviewData;
  client_overview_entity_t m_OverviewEntities[128];
  int m_iObserverFlags;
  int m_iSpectatorNumber;
  float m_mapZoom;
  client_vector_t m_mapOrigin;
  void* m_drawnames;
  void* m_drawcone;
  void* m_drawstatus;
  void* m_autoDirector;
  void* m_pip;
  void* m_scoreboard;
  void* m_mode;
  qboolean m_chatEnabled;
  qboolean m_IsInterpolating;
  int m_ChaseEntity;
  int m_WayPoint;
  int m_NumWayPoints;
  client_vector_t m_cameraOrigin;
  client_vector_t m_cameraAngles;
  client_interpolation_t m_WayInterpolation;
  client_vector_t m_vPlayerPos[64];
  HSPRITE m_hsprPlayerBlue;
  HSPRITE m_hsprPlayerRed;
  HSPRITE m_hsprPlayer;
  HSPRITE m_hsprPlayerVIP;
  HSPRITE m_hsprPlayerC4;
  HSPRITE m_hsprCamera;
  HSPRITE m_hsprPlayerDead;
  HSPRITE m_hsprViewcone;
  HSPRITE m_hsprUnkownMap;
  HSPRITE m_hsprBeam;
  HSPRITE m_hsprBomb;
  HSPRITE m_hsprHostage;
  HSPRITE m_hsprBackpack;
  void* m_MapSprite;
  float m_flNextObserverInput;
  float m_FOV;
  float m_zoomDelta;
  float m_moveDelta;
  int m_lastPrimaryObject;
  int m_lastSecondaryObject;
  float m_lastAutoDirector;
  client_camera_waypoint_t m_CamPath[32];
} client_hud_spectator_t;

typedef struct {
  client_hud_base_t base;
  int m_iGeigerRange;
} client_hud_geiger_t;

typedef struct {
  client_hud_base_t base;
  int m_HUD_suit_empty;
  int m_HUD_suit_full;
  int m_HUD_suithelmet_empty;
  int m_HUD_suithelmet_full;
  int m_iBat;
  float m_fFade;
  int m_iArmorType;
} client_hud_battery_t;

typedef struct {
  client_hud_base_t base;
  HSPRITE m_hSprite;
  int m_iPos;
} client_hud_train_t;

typedef struct {
  client_hud_base_t base;
  HSPRITE m_hSprite1;
  HSPRITE m_hSprite2;
  HSPRITE m_hBeam;
  client_wrect_t* m_prc1;
  client_wrect_t* m_prc2;
  client_wrect_t* m_prcBeam;
  float m_flBat;
  int m_iBat;
  int m_fOn;
  float m_fFade;
  int m_iWidth;
} client_hud_flashlight_t;

typedef struct {
  client_hud_base_t base;
  client_message_t m_pMessages[16];
  float m_startTime[16];
  client_message_parms_t m_parms;
  float m_gameTitleTime;
  client_textmessage_t* m_pGameTitle;
  int m_HUD_title_life;
  int m_HUD_title_half;
} client_hud_message_t;

typedef struct {
  client_hud_base_t base;
  char m_szStatusText[1][128];
  char m_szStatusBar[1][128];
  int m_iStatusValues[8];
  int m_bReparseString;
  float* m_pflNameColors[1];
} client_hud_status_bar_t;

typedef struct {
  client_hud_base_t base;
  int m_HUD_d_skull;
  int m_iDeathNoticeGap;
  int m_iDeathNoticeTop;
  int m_iDeathTextGap;
  int m_iDeathNoticeGapRight;
} client_hud_death_notice_t;

typedef struct {
  client_hud_base_t base;
  void* m_HUD_saytext;
  void* m_HUD_saytext_time;
} client_hud_say_text_t;

typedef struct {
  client_hud_base_t base;
  int m_fMenuDisplayed;
  int m_bitsValidSlots;
  float m_flShutoffTime;
  int m_fWaitingForMore;
} client_hud_menu_t;

typedef struct {
  client_hud_base_t base;
  int m_HUD_ammoicon;
  int m_iAmmoAmounts[4];
  float m_fFade;
} client_hud_ammo_secondary_t;

typedef struct {
  client_hud_base_t base;
} client_hud_text_message_t;

typedef struct {
  client_hud_base_t base;
  int m_iCrossWidth;
  int m_bFlashOn;
  float m_tmNextFlash;
  client_hud_status_icon_t m_IconList[4];
} client_hud_status_icons_t;

typedef struct {
  client_hud_base_t base;
  int m_iAccount;
  int m_HUD_dollar;
  int m_HUD_minus;
  int m_HUD_plus;
  int m_iAccountDelta;
  float m_fFade;
  float m_fFadeFast;
  int m_bShowDelta;
  int m_iBlinkCount;
  float m_fBlinkTime;
} client_hud_account_balance_t;

typedef struct {
  client_hud_base_t base;
  float m_flTimeEnd;
  int m_HUD_stopwatch;
  float m_fFade;
  float m_flNewPeriod;
  float m_flNextToggle;
  int m_bPanicColor;
  int m_closestRight;
} client_hud_round_timer_t;

typedef struct {
  client_hud_base_t base;
  float m_tmEnd;
  float m_tmStart;
  float m_tmNewPeriod;
  float m_tmNewElapsed;
  int m_width;
  int m_height;
  int m_x0;
  int m_y0;
  int m_x1;
  int m_y1;
} client_hud_progress_bar_t;

typedef struct {
  client_hud_base_t base;
  int m_fOn;
  int m_iAlpha;
  int m_iScopeTextureID;
} client_hud_nightvision_t;

typedef struct {
  client_hud_base_t base;
  float m_flTimeEnd;
  int m_HUD_stopwatch;
  float m_fFade;
  float m_flNewPeriod;
  float m_flNextToggle;
  int m_bPanicColor;
  bool m_bTaskComplete;
  bool m_bCountdown;
  float m_flAlpha;
  float m_flFadeDelay;
  float m_flFadeStart;
} client_hud_career_task_timer_t;

typedef struct {
  client_hud_base_t base;
  HSPRITE m_hSprite;
  client_wrect_t m_rect;
  int m_alpha;
  float m_nextFlash;
  float m_flashInterval;
  int m_flashAlpha;
} client_hud_scenario_status_t;

typedef struct {
  client_hud_base_t base;
  int m_iScopeTextureID;
  int m_iScopeNWTextureID;
  int m_iScopeNETextureID;
  int m_iScopeSWTextureID;
  int m_iScopeSETextureID;
} client_hud_sniper_scope_t;

typedef struct {
  client_hud_base_t base;
  int m_hudfont;
  float m_flVGUI2StringTime;
  wchar_t m_wCharBuf[512];
  float m_fR;
  float m_fG;
  float m_fB;
  int m_iX;
  int m_iY;
} client_hud_vgui2_print_t;

typedef struct {
  void* m_pHudList;
  HSPRITE m_hsprLogo;
  int m_iLogo;
  client_sprite_t* m_pSpriteList;
  int m_iSpriteCount;
  int m_iSpriteCountAllRes;
  float m_flMouseSensitivity;
  int m_iConcussionEffect;
  HSPRITE m_hsprCursor;
  float m_flTime;
  float m_fOldTime;
  double m_flTimeDelta;
  client_vector_t m_vecOrigin;
  client_vector_t m_vecAngles;
  int m_iKeyBits;
  int m_iHideHUDDisplay;
  int m_iFOV;
  int m_Teamplay;
  int m_iRes;
  void* m_pCvarStealMouse;
  void* m_pCvarDraw;
  int m_PlayerFOV[64];
  int m_iFontHeight;
  int m_iFontEngineHeight;
  void* default_fov;
  HSPRITE* m_rghSprites;
  client_wrect_t* m_rgrcRects;
  char* m_rgszSpriteNames;
  client_hud_ammo_t m_Ammo;
  client_hud_health_t m_Health;
  client_hud_spectator_t m_Spectator;
  client_hud_geiger_t m_Geiger;
  client_hud_battery_t m_Battery;
  client_hud_train_t m_Train;
  client_hud_flashlight_t m_Flash;
  client_hud_message_t m_Message;
  client_hud_status_bar_t m_StatusBar;
  client_hud_death_notice_t m_DeathNotice;
  client_hud_say_text_t m_SayText;
  client_hud_menu_t m_Menu;
  client_hud_ammo_secondary_t m_AmmoSecondary;
  client_hud_text_message_t m_TextMessage;
  client_hud_status_icons_t m_StatusIcons;
  client_hud_account_balance_t m_accountBalance;
  client_hud_round_timer_t m_roundTimer;
  client_hud_progress_bar_t m_progressBar;
  client_hud_nightvision_t m_NightVision;
  client_hud_career_task_timer_t m_careerTaskTimer;
  client_hud_scenario_status_t m_scenarioStatus;
  client_hud_sniper_scope_t m_sniperScope;
  client_hud_vgui2_print_t m_VGUI2Print;
  SCREENINFO_t m_scrinfo;
  int m_iWeaponBits;
  bool m_fPlayerDead;
  int m_iIntermission;
  int m_HUD_number_0;
  float m_flCheatCheckTime;
  float m_flExpensiveCheckTime;
  bool m_bRenderGunSmoke;
  float m_fGLTEXSORT;
  float m_flGLZMAX;
  bool m_bSoftwaremode;
  bool m_bShowTimer;
  bool m_autoBuyStringSent;
  bool m_rebuyStringSent;
  struct {
    int* start;
    int* finish;
    int* end;
  } m_botVoiceEntities;
} client_hud_t;
