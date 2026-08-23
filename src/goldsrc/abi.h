#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAXSTUDIOBONES 128

enum {
  kRenderNormal = 0,
  kRenderTransTexture = 2,
  kRenderTransAlpha = 4,
};

enum {
  kRenderFxNone = 0,
  kRenderFxPulseSlow,
  kRenderFxPulseFast,
  kRenderFxPulseSlowWide,
  kRenderFxPulseFastWide,
  kRenderFxFadeSlow,
  kRenderFxFadeFast,
  kRenderFxSolidSlow,
  kRenderFxSolidFast,
  kRenderFxStrobeSlow,
  kRenderFxStrobeFast,
  kRenderFxStrobeFaster,
  kRenderFxFlickerSlow,
  kRenderFxFlickerFast,
  kRenderFxNoDissipation,
  kRenderFxDistort,
  kRenderFxHologram,
  kRenderFxDeadPlayer,
  kRenderFxExplode,
  kRenderFxGlowShell,
  kRenderFxClampMinScale,
};

typedef struct alight_s alight_t;
typedef struct cache_user_s cache_user_t;
typedef struct client_sprite_s client_sprite_t;
typedef struct client_textmessage_s client_textmessage_t;
typedef struct cmdalias_s cmdalias_t;
typedef struct con_nprint_s con_nprint_t;
typedef struct dclipnode_s dclipnode_t;
typedef struct demo_api_s demo_api_t;
typedef struct dmodel_s dmodel_t;
typedef struct edict_s edict_t;
typedef struct efrag_s efrag_t;
typedef struct efx_api_s efx_api_t;
typedef struct event_api_s event_api_t;
typedef struct event_args_s event_args_t;
typedef struct IVoiceTweak_s IVoiceTweak_t;
typedef struct hull_s hull_t;
typedef struct mleaf_s mleaf_t;
typedef struct medge_s medge_t;
typedef struct mnode_s mnode_t;
typedef struct mplane_s mplane_t;
typedef struct msurface_s msurface_t;
typedef struct mtexinfo_s mtexinfo_t;
typedef struct mvertex_s mvertex_t;
typedef struct net_response_s net_response_t;
typedef struct pmtrace_s pmtrace_t;
typedef struct rect_s wrect_t;
typedef struct screenfade_s screenfade_t;
typedef struct SCREENINFO_s SCREENINFO_t;
typedef struct sentenceEntry_s sentenceEntry_t;
typedef struct sequenceEntry_s sequenceEntry_t;
typedef struct tagPOINT tagPOINT_t;
typedef struct texture_s texture_t;
typedef struct triangleapi_s triangleapi_t;

typedef unsigned char byte;
typedef int int32;
typedef int qboolean;
typedef float vec_t;
typedef vec_t vec3_t[3];
typedef void* HSPRITE;

typedef struct {
  unsigned char r;
  unsigned char g;
  unsigned char b;
} color24;

struct mplane_s {
  vec3_t normal;
  float dist;
  byte type;
  byte signbits;
  byte pad[2];  // padding from the original ABI
};

struct SCREENINFO_s {
  int iSize;
  int iWidth;
  int iHeight;
  int iFlags;
  int iCharHeight;
  short charWidths[256];
};

typedef struct dlight_s {
  vec3_t origin;
  float radius;
  color24 color;
  float die;
  float decay;
  float minlight;
  int key;
  qboolean dark;
} dlight_t;

typedef enum {
  pt_static,
  pt_grav,
  pt_slowgrav,
  pt_fire,
  pt_explode,
  pt_explode2,
  pt_blob,
  pt_blob2,
  pt_vox_slowgrav,
  pt_vox_grav,
  pt_clientcustom,
} ptype_t;

typedef struct particle_s particle_t;
typedef struct beam_s BEAM;
typedef struct tempent_s TEMPENTITY;

struct particle_s {
  vec3_t org;
  short color;
  short packedColor;
  particle_t* next;
  vec3_t vel;
  float ramp;
  float die;
  ptype_t type;
  void (*deathfunc)(particle_t* particle);
  void (*callback)(particle_t* particle, float frametime);
  unsigned char context;
};

struct beam_s {
  BEAM* next;
  int type;
  int flags;
  vec3_t source;
  vec3_t target;
  vec3_t delta;
  float t;
  float freq;
  float die;
  float width;
  float amplitude;
  float r;
  float g;
  float b;
  float brightness;
  float speed;
  float frameRate;
  float frame;
  int segments;
  int startEntity;
  int endEntity;
  int modelIndex;
  int frameCount;
  struct model_s* pFollowModel;
  particle_t* particles;
};

typedef void (*net_api_response_func_t)(struct net_response_s*);
typedef int (*pfnUserMsgHook)(const char*, int, void*);

typedef struct cvar_s {
  char* name;
  char* string;
  int flags;
  float value;
  struct cvar_s* next;
} cvar_t;

typedef struct {
  int bone;
  int group;
  float bbmin[3];
  float bbmax[3];
} mstudiobbox_t;

typedef struct {
  char label[32];
  float fps;
  int flags;
  int activity;
  int actweight;
  int numevents;
  int eventindex;
  int numframes;
  int numpivots;
  int pivotindex;
  int motiontype;
  int motionbone;
  vec3_t linearmovement;
  int automoveposindex;
  int automoveangleindex;
  vec3_t bbmin;
  vec3_t bbmax;
  int numblends;
  int animindex;
  int blendtype[2];
  float blendstart[2];
  float blendend[2];
  int blendparent;
  int seqgroup;
  int entrynode;
  int exitnode;
  int nodeflags;
  int nextseq;
} mstudioseqdesc_t;

typedef struct {
  int id;
  int version;
  char name[64];
  int length;
  float eyeposition[3];
  float min[3];
  float max[3];
  float bbmin[3];
  float bbmax[3];
  int flags;
  int numbones;
  int boneindex;
  int numbonecontrollers;
  int bonecontrollerindex;
  int numhitboxes;
  int hitboxindex;
  int numseq;
  int seqindex;
  int numseqgroups;
  int seqgroupindex;
  int numtextures;
  int textureindex;
  int texturedataindex;
  int numskinref;
  int numskinfamilies;
  int skinindex;
  int numbodyparts;
  int bodypartindex;
  int numattachments;
  int attachmentindex;
  int soundtable;
  int soundindex;
  int soundgroups;
  int soundgroupindex;
  int numtransitions;
  int transitionindex;
} studiohdr_t;

typedef struct entity_state_s {
  int entityType;
  int number;
  float msg_time;
  int messagenum;
  float origin[3];
  float angles[3];
  int modelindex;
  int sequence;
  float frame;
  int colormap;
  short int skin;
  short int solid;
  int effects;
  float scale;
  unsigned char eflags;
  int rendermode;
  int renderamt;

  struct {
    unsigned char r;
    unsigned char g;
    unsigned char b;
  } rendercolor;

  int renderfx;
  int movetype;
  float animtime;
  float framerate;
  int body;
  unsigned char controller[4];
  unsigned char blending[4];
  float velocity[3];
  float mins[3];
  float maxs[3];
  int aiment;
  int owner;
  float friction;
  float gravity;
  int team;
  int playerclass;
  int health;
  qboolean spectator;
  int weaponmodel;
  int gaitsequence;
  float basevelocity[3];
  int usehull;
  int oldbuttons;
  int onground;
  int iStepLeft;
  float flFallVelocity;
  float fov;
  int weaponanim;
  float startpos[3];
  float endpos[3];
  float impacttime;
  float starttime;
  int iuser1;
  int iuser2;
  int iuser3;
  int iuser4;
  float fuser1;
  float fuser2;
  float fuser3;
  float fuser4;
  float vuser1[3];
  float vuser2[3];
  float vuser3[3];
  float vuser4[3];
} entity_state_t;

typedef struct resource_s {
  char szFileName[64];

  enum {
    t_sound = 0,
    t_skin = 1,
    t_model = 2,
    t_decal = 3,
    t_generic = 4,
    t_eventscript = 5,
    t_world = 6,
  } type;

  int nIndex;
  int nDownloadSize;
  unsigned char ucFlags;
  unsigned char rgucMD5_hash[16];
  unsigned char playernum;
  unsigned char rguc_reserved[32];
  struct resource_s* pNext;
  struct resource_s* pPrev;
} resource_t;

typedef enum {
  NA_IP = 3
} netadrtype_t;

typedef struct netadr_s {
  netadrtype_t type;
  unsigned char ip[4];
  unsigned char ipx[10];
  unsigned short port;
} netadr_t;

typedef struct net_status_s {
  int connected;
  netadr_t local_address;
  netadr_t remote_address;
  int packet_loss;
  double latency;
  double connection_time;
  double rate;
} net_status_t;

typedef struct net_api_s {
  void (*InitNetworking)(void);
  void (*Status)(struct net_status_s*);
  void (*SendRequest)(int, int, int, double, struct netadr_s*, net_api_response_func_t);
  void (*CancelRequest)(int);
  void (*CancelAllRequests)(void);
  char* (*AdrToString)(struct netadr_s*);
  int (*CompareAdr)(struct netadr_s*, struct netadr_s*);
  int (*StringToAdr)(char*, struct netadr_s*);
  const char* (*ValueForKey)(const char*, const char*);
  void (*RemoveKey)(char*, const char*);
  void (*SetValueForKey)(char*, const char*, const char*, int);
} net_api_t;

typedef struct model_s {
  char name[64];
  qboolean needload;

  enum {
    mod_brush = 0,
    mod_sprite = 1,
    mod_alias = 2,
    mod_studio = 3,
  } type;

  int numframes;

  enum {
    ST_SYNC = 0,
    ST_RAND = 1,
  } synctype;

  int flags;
  float mins[3];
  float maxs[3];
  float radius;
  int firstmodelsurface;
  int nummodelsurfaces;
  int numsubmodels;
  dmodel_t* submodels;
  int numplanes;
  mplane_t* planes;
  int numleafs;
  mleaf_t* leafs;
  int numvertexes;
  mvertex_t* vertexes;
  int numedges;
  medge_t* edges;
  int numnodes;
  mnode_t* nodes;
  int numtexinfo;
  mtexinfo_t* texinfo;
  int numsurfaces;
  msurface_t* surfaces;
  int numsurfedges;
  int* surfedges;
  int numclipnodes;
  dclipnode_t* clipnodes;
  int nummarksurfaces;
  msurface_t** marksurfaces;

  struct hull_s {
    dclipnode_t* clipnodes;
    mplane_t* planes;
    int firstclipnode;
    int lastclipnode;
    float clip_mins[3];
    float clip_maxs[3];
  } hulls[4];

  int numtextures;
  texture_t** textures;
  byte* visdata;
  color24* lightdata;
  char* entities;

  struct cache_user_s {
    void* data;
  } cache;
} model_t;

typedef struct player_info_s {
  int userid;
  char userinfo[256];
  char name[32];
  int spectator;
  int ping;
  int packet_loss;
  char model[64];
  int topcolor;
  int bottomcolor;
  int renderframe;
  int gaitsequence;
  float gaitframe;
  float gaityaw;
  float prevgaitorigin[3];

  struct customization_s {
    qboolean bInUse;
    struct resource_s resource;
    qboolean bTranslated;
    int nUserData1;
    int nUserData2;
    void* pInfo;
    void* pBuffer;
    struct customization_s* pNext;
  } customdata;

  char hashedcdkey[16];
  long long unsigned int m_nSteamID;
} player_info_t;

typedef struct cl_entity_s {
  int index;
  qboolean player;
  struct entity_state_s baseline;
  struct entity_state_s prevstate;
  struct entity_state_s curstate;
  int current_position;

  struct {
    float animtime;
    float origin[3];
    float angles[3];
  } ph[64];

  struct {
    unsigned char mouthopen;
    unsigned char sndcount;
    int sndavg;
  } mouth;

  struct {
    float prevanimtime;
    float sequencetime;
    unsigned char prevseqblending[2];
    float prevorigin[3];
    float prevangles[3];
    int prevsequence;
    float prevframe;
    unsigned char prevcontroller[4];
    unsigned char prevblending[2];
  } latched;

  float lastmove;
  float origin[3];
  float angles[3];
  float attachment[4][3];
  int trivial_accept;
  struct model_s* model;
  struct efrag_s* efrag;
  struct mnode_s* topnode;
  float syncbase;
  int visframe;

  struct {
    unsigned int r;
    unsigned int g;
    unsigned int b;
    unsigned int a;
  } cvFloorColor;
} cl_entity_t;

struct tempent_s {
  int flags;
  float die;
  float frameMax;
  float x;
  float y;
  float z;
  float fadeSpeed;
  float bounceFactor;
  int hitSound;
  void (*hitcallback)(TEMPENTITY* ent, struct pmtrace_s* ptr);
  void (*callback)(TEMPENTITY* ent, float frametime, float currenttime);
  TEMPENTITY* next;
  int priority;
  short clientIndex;
  vec3_t tentOffset;
  cl_entity_t entity;
};

struct efx_api_s {
  particle_t* (*R_AllocParticle)(void (*callback)(particle_t* particle, float frametime));
  void (*R_BlobExplosion)(float* org);
  void (*R_Blood)(float* org, float* dir, int pcolor, int speed);
  void (*R_BloodSprite)(float* org, int colorindex, int modelIndex, int modelIndex2, float size);
  void (*R_BloodStream)(float* org, float* dir, int pcolor, int speed);
  void (*R_BreakModel)(float* pos, float* size, float* dir, float random, float life, int count,
                       int modelIndex, char flags);
  void (*R_Bubbles)(float* mins, float* maxs, float height, int modelIndex, int count, float speed);
  void (*R_BubbleTrail)(float* start, float* end, float height, int modelIndex, int count,
                        float speed);
  void (*R_BulletImpactParticles)(float* pos);
  void (*R_EntityParticles)(struct cl_entity_s* ent);
  void (*R_Explosion)(float* pos, int model, float scale, float framerate, int flags);
  void (*R_FizzEffect)(struct cl_entity_s* pent, int modelIndex, int density);
  void (*R_FireField)(float* org, int radius, int modelIndex, int count, int flags, float life);
  void (*R_FlickerParticles)(float* org);
  void (*R_FunnelSprite)(float* org, int modelIndex, int reverse);
  void (*R_Implosion)(float* end, float radius, int count, float life);
  void (*R_LargeFunnel)(float* org, int reverse);
  void (*R_LavaSplash)(float* org);
  void (*R_MultiGunshot)(float* org, float* dir, float* noise, int count, int decalCount,
                         int* decalIndices);
  void (*R_MuzzleFlash)(float* pos1, int type);
  void (*R_ParticleBox)(float* mins, float* maxs, unsigned char r, unsigned char g, unsigned char b,
                        float life);
  void (*R_ParticleBurst)(float* pos, int size, int color, float life);
  void (*R_ParticleExplosion)(float* org);
  void (*R_ParticleExplosion2)(float* org, int colorStart, int colorLength);
  void (*R_ParticleLine)(float* start, float* end, unsigned char r, unsigned char g,
                         unsigned char b, float life);
  void (*R_PlayerSprites)(int client, int modelIndex, int count, int size);
  void (*R_Projectile)(float* origin, float* velocity, int modelIndex, int life, int owner,
                       void (*hitcallback)(TEMPENTITY* ent, struct pmtrace_s* ptr));
  void (*R_RicochetSound)(float* pos);
  void (*R_RicochetSprite)(float* pos, struct model_s* pmodel, float duration, float scale);
  void (*R_RocketFlare)(float* pos);
  void (*R_RocketTrail)(float* start, float* end, int type);
  void (*R_RunParticleEffect)(float* org, float* dir, int color, int count);
  void (*R_ShowLine)(float* start, float* end);
  void (*R_SparkEffect)(float* pos, int count, int velocityMin, int velocityMax);
  void (*R_SparkShower)(float* pos);
  void (*R_SparkStreaks)(float* pos, int count, int velocityMin, int velocityMax);
  void (*R_Spray)(float* pos, float* dir, int modelIndex, int count, int speed, int spread,
                  int rendermode);
  void (*R_Sprite_Explode)(TEMPENTITY* pTemp, float scale, int flags);
  void (*R_Sprite_Smoke)(TEMPENTITY* pTemp, float scale);
  void (*R_Sprite_Spray)(float* pos, float* dir, int modelIndex, int count, int speed, int iRand);
  void (*R_Sprite_Trail)(int type, float* start, float* end, int modelIndex, int count, float life,
                         float size, float amplitude, int renderamt, float speed);
  void (*R_Sprite_WallPuff)(TEMPENTITY* pTemp, float scale);
  void (*R_StreakSplash)(float* pos, float* dir, int color, int count, float speed, int velocityMin,
                         int velocityMax);
  void (*R_TracerEffect)(float* start, float* end);
  void (*R_UserTracerParticle)(float* org, float* vel, float life, int colorIndex, float length,
                               unsigned char deathcontext, void (*deathfunc)(particle_t* particle));
  particle_t* (*R_TracerParticles)(float* org, float* vel, float life);
  void (*R_TeleportSplash)(float* org);
  void (*R_TempSphereModel)(float* pos, float speed, float life, int count, int modelIndex);
  TEMPENTITY* (*R_TempModel)(float* pos, float* dir, float* angles, float life, int modelIndex,
                             int soundtype);
  TEMPENTITY* (*R_DefaultSprite)(float* pos, int spriteIndex, float framerate);
  TEMPENTITY* (*R_TempSprite)(float* pos, float* dir, float scale, int modelIndex, int rendermode,
                              int renderfx, float a, float life, int flags);
  int (*Draw_DecalIndex)(int id);
  int (*Draw_DecalIndexFromName)(char* name);
  void (*R_DecalShoot)(int textureIndex, int entity, int modelIndex, float* position, int flags);
  void (*R_AttachTentToPlayer)(int client, int modelIndex, float zoffset, float life);
  void (*R_KillAttachedTents)(int client);
  BEAM* (*R_BeamCirclePoints)(int type, float* start, float* end, int modelIndex, float life,
                              float width, float amplitude, float brightness, float speed,
                              int startFrame, float framerate, float r, float g, float b);
  BEAM* (*R_BeamEntPoint)(int startEnt, float* end, int modelIndex, float life, float width,
                          float amplitude, float brightness, float speed, int startFrame,
                          float framerate, float r, float g, float b);
  BEAM* (*R_BeamEnts)(int startEnt, int endEnt, int modelIndex, float life, float width,
                      float amplitude, float brightness, float speed, int startFrame,
                      float framerate, float r, float g, float b);
  BEAM* (*R_BeamFollow)(int startEnt, int modelIndex, float life, float width, float r, float g,
                        float b, float brightness);
  void (*R_BeamKill)(int deadEntity);
  BEAM* (*R_BeamLightning)(float* start, float* end, int modelIndex, float life, float width,
                           float amplitude, float brightness, float speed);
  BEAM* (*R_BeamPoints)(float* start, float* end, int modelIndex, float life, float width,
                        float amplitude, float brightness, float speed, int startFrame,
                        float framerate, float r, float g, float b);
  BEAM* (*R_BeamRing)(int startEnt, int endEnt, int modelIndex, float life, float width,
                      float amplitude, float brightness, float speed, int startFrame,
                      float framerate, float r, float g, float b);
  dlight_t* (*CL_AllocDlight)(int key);
  dlight_t* (*CL_AllocElight)(int key);
  TEMPENTITY* (*CL_TempEntAlloc)(float* org, struct model_s* model);
  TEMPENTITY* (*CL_TempEntAllocNoModel)(float* org);
  TEMPENTITY* (*CL_TempEntAllocHigh)(float* org, struct model_s* model);
  TEMPENTITY* (*CL_TentEntAllocCustom)(float* origin, struct model_s* model, int high,
                                       void (*callback)(TEMPENTITY* ent, float frametime,
                                                        float currenttime));
  void (*R_GetPackedColor)(short* packed, short color);
  short (*R_LookupColor)(unsigned char r, unsigned char g, unsigned char b);
  void (*R_DecalRemoveAll)(int textureIndex);
  void (*R_FireCustomDecal)(int textureIndex, int entity, int modelIndex, float* position,
                            int flags, float scale);
};

typedef struct hud_player_info_s {
  char* name;
  short ping;
  byte thisplayer;
  byte spectator;
  byte packetloss;
  char* model;
  short topcolor;
  short bottomcolor;
  uint64_t m_nSteamID;
} hud_player_info_t;

typedef struct cl_enginefuncs_s {
  HSPRITE (*pfnSPR_Load)(const char*);
  int (*pfnSPR_Frames)(HSPRITE);
  int (*pfnSPR_Height)(HSPRITE, int);
  int (*pfnSPR_Width)(HSPRITE, int);
  void (*pfnSPR_Set)(HSPRITE, int, int, int);
  void (*pfnSPR_Draw)(int, int, int, const struct rect_s*);
  void (*pfnSPR_DrawHoles)(int, int, int, const struct rect_s*);
  void (*pfnSPR_DrawAdditive)(int, int, int, const struct rect_s*);
  void (*pfnSPR_EnableScissor)(int, int, int, int);
  void (*pfnSPR_DisableScissor)(void);
  struct client_sprite_s* (*pfnSPR_GetList)(char*, int*);
  void (*pfnFillRGBA)(int, int, int, int, int, int, int, int);
  int (*pfnGetScreenInfo)(struct SCREENINFO_s*);
  void (*pfnSetCrosshair)(HSPRITE, wrect_t, int, int, int);
  struct cvar_s* (*pfnRegisterVariable)(char*, char*, int);
  float (*pfnGetCvarFloat)(char*);
  char* (*pfnGetCvarString)(char*);
  int (*pfnAddCommand)(char*, void (*)(void));
  int (*pfnHookUserMsg)(char*, pfnUserMsgHook);
  int (*pfnServerCmd)(char*);
  int (*pfnClientCmd)(char*);
  void (*pfnGetPlayerInfo)(int, struct hud_player_info_s*);
  void (*pfnPlaySoundByName)(char*, float);
  void (*pfnPlaySoundByIndex)(int, float);
  void (*pfnAngleVectors)(const float*, float*, float*, float*);
  struct client_textmessage_s* (*pfnTextMessageGet)(const char*);
  int (*pfnDrawCharacter)(int, int, int, int, int, int);
  int (*pfnDrawConsoleString)(int, int, char*);
  void (*pfnDrawSetTextColor)(float, float, float);
  void (*pfnDrawConsoleStringLen)(const char*, int*, int*);
  void (*pfnConsolePrint)(const char*);
  void (*pfnCenterPrint)(const char*);
  int (*GetWindowCenterX)(void);
  int (*GetWindowCenterY)(void);
  void (*GetViewAngles)(float*);
  void (*SetViewAngles)(float*);
  int (*GetMaxClients)(void);
  void (*Cvar_SetValue)(char*, float);
  int (*Cmd_Argc)(void);
  char* (*Cmd_Argv)(int);
  void (*Con_Printf)(char*, ...);
  void (*Con_DPrintf)(char*, ...);
  void (*Con_NPrintf)(int, char*, ...);
  void (*Con_NXPrintf)(struct con_nprint_s*, char*, ...);
  const char* (*PhysInfo_ValueForKey)(const char*);
  const char* (*ServerInfo_ValueForKey)(const char*);
  float (*GetClientMaxspeed)(void);
  int (*CheckParm)(char*, char**);
  void (*Key_Event)(int, int);
  void (*GetMousePosition)(int*, int*);
  int (*IsNoClipping)(void);
  struct cl_entity_s* (*GetLocalPlayer)(void);
  struct cl_entity_s* (*GetViewModel)(void);
  struct cl_entity_s* (*GetEntityByIndex)(int);
  float (*GetClientTime)(void);
  void (*V_CalcShake)(void);
  void (*V_ApplyShake)(float*, float*, float);
  int (*PM_PointContents)(float*, int*);
  int (*PM_WaterEntity)(float*);
  struct pmtrace_s* (*PM_TraceLine)(float*, float*, int, int, int);
  struct model_s* (*CL_LoadModel)(const char*, int*);
  int (*CL_CreateVisibleEntity)(int, struct cl_entity_s*);
  const struct model_s* (*GetSpritePointer)(HSPRITE);
  void (*pfnPlaySoundByNameAtLocation)(char*, float, float*);
  short unsigned int (*pfnPrecacheEvent)(int, const char*);
  void (*pfnPlaybackEvent)(int, const struct edict_s*, short unsigned int, float, float*, float*,
                           float, float, int, int, int, int);
  void (*pfnWeaponAnim)(int, int);
  float (*pfnRandomFloat)(float, float);
  int32 (*pfnRandomLong)(int32, int32);
  void (*pfnHookEvent)(char*, void (*)(struct event_args_s*));
  int (*Con_IsVisible)(void);
  const char* (*pfnGetGameDirectory)(void);
  struct cvar_s* (*pfnGetCvarPointer)(const char*);
  const char* (*Key_LookupBinding)(const char*);
  const char* (*pfnGetLevelName)(void);
  void (*pfnGetScreenFade)(struct screenfade_s*);
  void (*pfnSetScreenFade)(struct screenfade_s*);
  void* (*VGui_GetPanel)(void);
  void (*VGui_ViewportPaintBackground)(int*);
  byte* (*COM_LoadFile)(char*, int, int*);
  char* (*COM_ParseFile)(char*, char*);
  void (*COM_FreeFile)(void*);
  struct triangleapi_s* pTriAPI;
  struct efx_api_s* pEfxAPI;
  struct event_api_s* pEventAPI;
  struct demo_api_s* pDemoAPI;
  struct net_api_s* pNetAPI;
  struct IVoiceTweak_s* pVoiceTweak;
  int (*IsSpectateOnly)(void);
  struct model_s* (*LoadMapSprite)(const char*);
  void (*COM_AddAppDirectoryToSearchPath)(const char*, const char*);
  int (*COM_ExpandFilename)(const char*, char*, int);
  const char* (*PlayerInfo_ValueForKey)(int, const char*);
  void (*PlayerInfo_SetValueForKey)(const char*, const char*);
  qboolean (*GetPlayerUniqueID)(int, char*);
  int (*GetTrackerIDForPlayer)(int);
  int (*GetPlayerForTrackerID)(int);
  int (*pfnServerCmdUnreliable)(char*);
  void (*pfnGetMousePos)(struct tagPOINT*);
  void (*pfnSetMousePos)(int, int);
  void (*pfnSetMouseEnable)(qboolean);
  struct cvar_s* (*GetFirstCvarPtr)(void);
  unsigned int (*GetFirstCmdFunctionHandle)(void);
  unsigned int (*GetNextCmdFunctionHandle)(unsigned int);
  const char* (*GetCmdFunctionName)(unsigned int);
  float (*hudGetClientOldTime)(void);
  float (*hudGetServerGravityValue)(void);
  struct model_s* (*hudGetModelByIndex)(int);
  void (*pfnSetFilterMode)(int);
  void (*pfnSetFilterColor)(float, float, float);
  void (*pfnSetFilterBrightness)(float);
  sequenceEntry_t* (*pfnSequenceGet)(const char*, const char*);
  void (*pfnSPR_DrawGeneric)(int, int, int, const struct rect_s*, int, int, int, int);
  sentenceEntry_t* (*pfnSequencePickSentence)(const char*, int, int*);
  int (*pfnDrawString)(int, int, const char*, int, int, int);
  int (*pfnDrawStringReverse)(int, int, const char*, int, int, int);
  const char* (*LocalPlayerInfo_ValueForKey)(const char*);
  int (*pfnVGUI2DrawCharacter)(int, int, int, unsigned int);
  int (*pfnVGUI2DrawCharacterAdd)(int, int, int, int, int, int, unsigned int);
  unsigned int (*COM_GetApproxWavePlayLength)(const char*);
  void* (*pfnGetCareerUI)(void);
  void (*Cvar_Set)(char*, char*);
  int (*pfnIsCareerMatch)(void);
  void (*pfnPlaySoundVoiceByName)(char*, float, int);
  void (*pfnPrimeMusicStream)(char*, int);
  double (*GetAbsoluteTime)(void);
  void (*pfnProcessTutorMessageDecayBuffer)(int*, int);
  void (*pfnConstructTutorMessageDecayBuffer)(int*, int);
  void (*pfnResetTutorMessageDecayData)(void);
  void (*pfnPlaySoundByNameAtPitch)(char*, float, int);
  void (*pfnFillRGBABlend)(int, int, int, int, int, int, int, int);
  int (*pfnGetAppID)(void);
  cmdalias_t* (*pfnGetAliasList)(void);
  void (*pfnVguiWrap2_GetMouseDelta)(int*, int*);
  int (*pfnFilteredClientCmd)(char*);
} cl_enginefunc_t;

typedef struct engine_studio_api_s {
  void* (*Mem_Calloc)(int, size_t);
  void* (*Cache_Check)(struct cache_user_s*);
  void (*LoadCacheFile)(char*, struct cache_user_s*);
  struct model_s* (*Mod_ForName)(const char*, int);
  void* (*Mod_Extradata)(struct model_s*);
  struct model_s* (*GetModelByIndex)(int);
  struct cl_entity_s* (*GetCurrentEntity)(void);
  struct player_info_s* (*PlayerInfo)(int);
  struct entity_state_s* (*GetPlayerState)(int);
  struct cl_entity_s* (*GetViewEntity)(void);
  void (*GetTimes)(int*, double*, double*);
  struct cvar_s* (*GetCvar)(const char*);
  void (*GetViewInfo)(float*, float*, float*, float*);
  struct model_s* (*GetChromeSprite)(void);
  void (*GetModelCounters)(int**, int**);
  void (*GetAliasScale)(float*, float*);
  float**** (*StudioGetBoneTransform)(void);
  float**** (*StudioGetLightTransform)(void);
  float*** (*StudioGetAliasTransform)(void);
  float*** (*StudioGetRotationMatrix)(void);
  void (*StudioSetupModel)(int, void**, void**);
  int (*StudioCheckBBox)(void);
  void (*StudioDynamicLight)(struct cl_entity_s*, struct alight_s*);
  void (*StudioEntityLight)(struct alight_s*);
  void (*StudioSetupLighting)(struct alight_s*);
  void (*StudioDrawPoints)(void);
  void (*StudioDrawHulls)(void);
  void (*StudioDrawAbsBBox)(void);
  void (*StudioDrawBones)(void);
  void (*StudioSetupSkin)(void*, int);
  void (*StudioSetRemapColors)(int, int);
  struct model_s* (*SetupPlayerModel)(int);
  void (*StudioClientEvents)(void);
  int (*GetForceFaceFlags)(void);
  void (*SetForceFaceFlags)(int);
  void (*StudioSetHeader)(void*);
  void (*SetRenderModel)(struct model_s*);
  void (*SetupRenderer)(int);
  void (*RestoreRenderer)(void);
  void (*SetChromeOrigin)(void);
  int (*IsHardware)(void);
  void (*GL_StudioDrawShadow)(void);
  void (*GL_SetRenderMode)(int);
  void (*StudioSetRenderamt)(int);
  void (*StudioSetCullState)(int);
  void (*StudioRenderShadow)(int, float*, float*, float*, float*);
} engine_studio_api_t;

typedef struct r_studio_interface_s {
  int version;
  int (*StudioDrawModel)(int);
  int (*StudioDrawPlayer)(int, struct entity_state_s*);
} r_studio_interface_t;
