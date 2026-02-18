#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <arpa/inet.h>

typedef enum
{
    GLT_SYSTEM = 0,
    GLT_WORLD = 4
} GL_TEXTURETYPE;

typedef enum
{
    t_sound = 0,
    t_skin,
    t_model,
    t_decal,
    t_generic,
    t_eventscript,
    t_world,
} resourcetype_t;

typedef struct
{
    char szFileName[64];
    resourcetype_t type;
    unsigned char _pad[9];
    unsigned char rgucMD5_hash[16];
} resource_t;

typedef enum
{
    NA_IP = 3
} netadrtype_t;

typedef struct
{
    netadrtype_t type;
    unsigned char ip[4];
    char _pad[10];
    unsigned short port;
} netadr_t;

typedef struct
{
    int connected;
    netadr_t _pad0;
    netadr_t remote_address;
    int _pad1;
    double _pad2[3];
} net_status_t;

typedef struct
{
    void *_pad;
    void (*Status)(net_status_t *status);
} net_api_t;

enum
{
    kRenderTransAlpha = 4,
};

typedef struct
{
    char name[64];
} model_t;

typedef struct
{
    char _pad0[304];
    char model[64];
} player_info_t;

typedef struct
{
    int index;
    char _pad0[724];
    int modelindex;
    char _pad1[28];
    int rendermode;
    int renderamt;
    char _pad2[2196];
    model_t *model;
} cl_entity_t;

typedef struct
{
    void *_pad0[18];
    int (*pfnHookUserMsg)(const char *szMsgName, int (*pfn)(const char *, int, void *));
    void *_pad1;
    int (*pfnClientCmd)(const char *szCmdString);
    void *_pad2[20];
    void (*Con_DPrintf)(const char *fmt, ...);
    void *_pad3[9];
    cl_entity_t *(*GetLocalPlayer)(void);
    void *_pad4[34];
    net_api_t *pNetAPI;
} cl_enginefunc_t;

typedef struct
{
    void *_pad0[5];
    model_t *(*GetModelByIndex)(int index);
    void *_pad1;
    player_info_t *(*PlayerInfo)(int index);
} engine_studio_api_t;

typedef struct
{
    int (*HUD_AddEntity)(int type, cl_entity_t *ent, const char *modelname);
    int (*Initialize)(cl_enginefunc_t *pEnginefuncs, int iVersion);
    int (*HUD_GetStudioModelInterface)(int version, void **ppinterface, engine_studio_api_t *pstudio);
} cldll_func_t;

typedef struct
{
    int (*MsgFunc_Money)(const char *pszName, int iSize, void *pbuf);
    int (*MsgFunc_ScoreInfo)(const char *pszName, int iSize, void *pbuf);
    int (*MsgFunc_TeamInfo)(const char *pszName, int iSize, void *pbuf);
} usermsg_func_t;

typedef struct
{
    int (*GL_LoadTexture2)(char *identifier, GL_TEXTURETYPE textureType, int width, int height, unsigned char *data, int mipmap, int iType, unsigned char *pPal, int filter);
    void (*Cbuf_AddFilteredText)(char *text);
    void (*CL_AddToResourceList)(resource_t *pResource, resource_t *pList);
} hw_enginefunc_t;

typedef struct
{
    void *(*SteamUser)();
} steam_api_func_t;

typedef struct
{
    void *_pad[3];
    int (*InitiateGameConnection)(void *pThis, void *pAuthBlob, int cbMaxAuthBlob, uint64_t steamIDGameServer, uint32_t unIPServer, uint16_t usPortServer, int bSecure);
} ISteamUser;

static void *(*real_dlsym)(void *, const char *);
static void *hw_handle;
static void *steam_api_handle;

static hw_enginefunc_t gHwEnginefuncs;
static cl_enginefunc_t gEnginefuncs;
static cldll_func_t gClientfuncs;
static engine_studio_api_t gEngineStudio;
static usermsg_func_t gUsermsgfuncs;
static steam_api_func_t gSteamAPIfuncs;
static ISteamUser gSteamUserfuncs;

#define PAGESIZE sysconf(_SC_PAGESIZE)
#define PAGE_ALIGN(address) ((void *)((uintptr_t)(address) & ~(PAGESIZE - 1)))
#define MPROTECT_RWX(address) mprotect(PAGE_ALIGN(address), PAGESIZE * 2, PROT_READ | PROT_WRITE | PROT_EXEC)
#define MPROTECT_RX(address) mprotect(PAGE_ALIGN(address), PAGESIZE * 2, PROT_READ | PROT_EXEC)
#define JMP_REL32 0xE9
#define JMP_SIZE 5
#define INLINE_HOOK(original_function, hook_function) do {                                                      \
    void **__ih_orig_ptr = (void **)&(original_function);                                                       \
    uint8_t *__ih_target = (uint8_t *)*__ih_orig_ptr;                                                           \
                                                                                                                \
    size_t __ih_len = 0;                                                                                        \
    while (__ih_len < JMP_SIZE) {                                                                               \
        uint8_t *__ih_ptr = __ih_target + __ih_len, __ih_row, __ih_col, __ih_modrm;                             \
        size_t __ih_imm_size = 0;                                                                               \
        /* Skip legacy prefixes (0x66, 0x67, segment overrides, etc.) */                                        \
        while (*__ih_ptr == 0x66 || *__ih_ptr == 0x67 || *__ih_ptr == 0x2E || *__ih_ptr == 0x3E ||              \
               *__ih_ptr == 0x26 || *__ih_ptr == 0x64 || *__ih_ptr == 0x65 ||                                   \
               (*__ih_ptr >= 0xF0 && *__ih_ptr <= 0xF3)) __ih_ptr++;                                            \
        __ih_row = *__ih_ptr >> 4; __ih_col = *__ih_ptr & 0xF;                                                  \
        if (*__ih_ptr == 0x0F) { /* Two-byte opcodes */                                                         \
            __ih_ptr++; if (__ih_row == 8) __ih_imm_size += 4; /* Jcc rel32 */                                  \
            else if ((__ih_row == 7 && __ih_col < 4) || *__ih_ptr == 0xA4 || *__ih_ptr == 0xC2 ||               \
                     (*__ih_ptr > 0xC3 && *__ih_ptr <= 0xC6) || *__ih_ptr == 0xBA || *__ih_ptr == 0xAC)         \
                __ih_imm_size++;                                                                                \
            __ih_modrm = *++__ih_ptr; /* ModR/M byte */                                                         \
            if ((__ih_modrm & 7) == 4) __ih_ptr++; /* SIB byte */                                               \
            if (__ih_modrm >= 0x40 && __ih_modrm <= 0x7F) __ih_ptr++; /* disp8 */                               \
            else if ((__ih_modrm <= 0x3F && (__ih_modrm & 7) == 5) ||                                           \
                     (__ih_modrm >= 0x80 && __ih_modrm <= 0xBF)) __ih_ptr += 4; /* disp32 */                    \
        } else {                                                                                                \
            /* One-byte opcodes with immediate values */                                                        \
            if ((__ih_row == 0xE && __ih_col < 8) || (__ih_row == 0xB && __ih_col < 8) ||                       \
                __ih_row == 7 || (__ih_row < 4 && (__ih_col == 4 || __ih_col == 0xC)) ||                        \
                (*__ih_ptr == 0xF6 && !(*(__ih_ptr + 1) & 48)) || *__ih_ptr == 0x6A ||                          \
                *__ih_ptr == 0x6B || *__ih_ptr == 0x80 || *__ih_ptr == 0x82 || *__ih_ptr == 0x83 ||             \
                *__ih_ptr == 0xA8 || *__ih_ptr == 0xC0 || *__ih_ptr == 0xC1 || *__ih_ptr == 0xC6 ||             \
                *__ih_ptr == 0xCD || *__ih_ptr == 0xD4 || *__ih_ptr == 0xD5 || *__ih_ptr == 0xEB)               \
                __ih_imm_size++;                                                                                \
            else if (*__ih_ptr == 0xC2 || *__ih_ptr == 0xCA) __ih_imm_size += 2;                                \
            else if (*__ih_ptr == 0xC8) __ih_imm_size += 3;                                                     \
            else if ((__ih_row < 4 && (__ih_col == 5 || __ih_col == 0xD)) ||                                    \
                     (__ih_row == 0xB && __ih_col >= 8) || (*__ih_ptr == 0xF7 && !(*(__ih_ptr + 1) & 48)) ||    \
                     *__ih_ptr == 0x68 || *__ih_ptr == 0x69 || *__ih_ptr == 0x81 || *__ih_ptr == 0xA9 ||        \
                     *__ih_ptr == 0xC7 || *__ih_ptr == 0xE8 || *__ih_ptr == 0xE9)                               \
                __ih_imm_size += 4;                                                                             \
            else if (__ih_row == 0xA && __ih_col < 4) __ih_imm_size += 4;                                       \
            else if (*__ih_ptr == 0xEA || *__ih_ptr == 0x9A) __ih_imm_size += 6;                                \
            /* Opcodes with ModR/M byte */                                                                      \
            if (*__ih_ptr == 0x62 || *__ih_ptr == 0x63 || *__ih_ptr == 0x69 || *__ih_ptr == 0x6B ||             \
                (*__ih_ptr >= 0xC0 && *__ih_ptr <= 0xC1) || (*__ih_ptr >= 0xC4 && *__ih_ptr <= 0xC7) ||         \
                (*__ih_ptr >= 0xD0 && *__ih_ptr <= 0xD3) || *__ih_ptr == 0xF6 || *__ih_ptr == 0xF7 ||           \
                *__ih_ptr == 0xFE || *__ih_ptr == 0xFF || (__ih_row < 4 && (__ih_col < 4 ||                     \
                (__ih_col >= 8 && __ih_col < 0xC))) || __ih_row == 8 || (__ih_row == 0xD && __ih_col >= 8)) {   \
                __ih_modrm = *++__ih_ptr; if ((__ih_modrm & 7) == 4) __ih_ptr++;                                \
                if (__ih_modrm >= 0x40 && __ih_modrm <= 0x7F) __ih_ptr++;                                       \
                else if ((__ih_modrm <= 0x3F && (__ih_modrm & 7) == 5) ||                                       \
                         (__ih_modrm >= 0x80 && __ih_modrm <= 0xBF)) __ih_ptr += 4;                             \
            }                                                                                                   \
        }                                                                                                       \
        __ih_len += (size_t)(++__ih_ptr + __ih_imm_size - (__ih_target + __ih_len));                            \
    }                                                                                                           \
                                                                                                                \
    /* Allocate trampoline */                                                                                   \
    uint8_t *__ih_trampoline = mmap(NULL, __ih_len + JMP_SIZE,                                                  \
        PROT_READ | PROT_WRITE | PROT_EXEC,                                                                     \
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);                                                                    \
                                                                                                                \
    /* Copy stolen bytes and add jump back to original function */                                              \
    memcpy(__ih_trampoline, __ih_target, __ih_len);                                                             \
    __ih_trampoline[__ih_len] = JMP_REL32;                                                                      \
    *(int32_t *)(__ih_trampoline + __ih_len + 1) = (__ih_target + __ih_len) -                                   \
                                                   (__ih_trampoline + __ih_len + JMP_SIZE);                     \
                                                                                                                \
    /* Patch original function with jump to hook */                                                             \
    MPROTECT_RWX(__ih_target);                                                                                  \
    __ih_target[0] = JMP_REL32;                                                                                 \
    *(int32_t *)(__ih_target + 1) = (uint8_t *)(hook_function) - (__ih_target + JMP_SIZE);                      \
    /* Fill remaining stolen bytes with NOPs */                                                                 \
    for (size_t __ih_i = JMP_SIZE; __ih_i < __ih_len; __ih_i++) __ih_target[__ih_i] = 0x90;                     \
    MPROTECT_RX(__ih_target);                                                                                   \
                                                                                                                \
    *__ih_orig_ptr = (void *)__ih_trampoline;                                                                   \
} while (0)

#define DLSYM(library_handle, symbol_name) (real_dlsym ? real_dlsym(library_handle, symbol_name) : (real_dlsym = dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.0"), real_dlsym(library_handle, symbol_name)))
#define HW(symbol_name) (*(gHwEnginefuncs.symbol_name ? &gHwEnginefuncs.symbol_name : (gHwEnginefuncs.symbol_name = DLSYM(hw_handle ?: (hw_handle = dlopen("hw.so", RTLD_LAZY | RTLD_NOLOAD)), #symbol_name), &gHwEnginefuncs.symbol_name)))
#define STEAM_API(symbol_name) (*(gSteamAPIfuncs.symbol_name ? &gSteamAPIfuncs.symbol_name : (gSteamAPIfuncs.symbol_name = DLSYM(steam_api_handle ?: (steam_api_handle = dlopen("libsteam_api.so", RTLD_LAZY | RTLD_NOLOAD)), #symbol_name), &gSteamAPIfuncs.symbol_name)))

#define MAX_PLAYERS 32
#define TEAM_UNASSIGNED 0
#define TEAM_TERRORIST 1
#define TEAM_CT 2
#define TEAM_SPECTATOR 3

static short g_PlayerTeam[MAX_PLAYERS + 1];

__attribute__((visibility("default")))
int GL_LoadTexture2(char *identifier, GL_TEXTURETYPE textureType, int width, int height, unsigned char *data, int mipmap, int iType, unsigned char *pPal, int filter)
{
    // https://github.com/ValveSoftware/halflife/issues/2234
    if(textureType != GLT_SYSTEM)
    {
        gEnginefuncs.Con_DPrintf("GL_LoadTexture2: tt %d->%d \"%s\" %dx%d\n", textureType, GLT_WORLD, identifier, width, height);

        textureType = GLT_WORLD;
    }

    return HW(GL_LoadTexture2)(identifier, textureType, width, height, data, mipmap, iType, pPal, filter);
}

static void CL_AddToResourceList(resource_t *pResource, resource_t *pList)
{
    const char *type_str;
    switch(pResource->type)
    {
        case t_sound: type_str = "t_sound"; break;
        case t_skin: type_str = "t_skin"; break;
        case t_model: type_str = "t_model"; break;
        case t_decal: type_str = "t_decal"; break;
        case t_generic: type_str = "t_generic"; break;
        case t_eventscript: type_str = "t_eventscript"; break;
        case t_world: type_str = "t_world"; break;
        default: type_str = "t_unknown"; break;
    }

    char md5_hex[16 * 2 + 1];
    for(int i = 0; i < 16; i++)
        sprintf(&md5_hex[i * 2], "%02x", pResource->rgucMD5_hash[i]);
    md5_hex[32] = '\0';

    gEnginefuncs.Con_DPrintf("CL_AddToResourceList: type=%s szFileName=\"%s\" MD5_hash=\"%s\"\n", type_str, pResource->szFileName, md5_hex);

    gHwEnginefuncs.CL_AddToResourceList(pResource, pList);
}

__attribute__((visibility("default")))
void Cbuf_AddFilteredText(char *text)
{
    gEnginefuncs.Con_DPrintf("Cbuf_AddFilteredText: \"%.*s\"\n", (int)strcspn(text, "\n")/* length before \n, so command will be printed clean */, text);
    
    HW(Cbuf_AddFilteredText)(text);
}

static int MsgFunc_Money(const char *pszName, int iSize, void *pbuf)
{
    unsigned char *buf = (unsigned char *)pbuf;
    int amount = buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);

    if(amount >= 5000)
    {
        net_status_t status; gEnginefuncs.pNetAPI->Status(&status);

        if(
            status.connected &&
            status.remote_address.type == NA_IP &&
            memcmp(status.remote_address.ip, (unsigned char[]){46, 174, 52, 2}, 4) == 0 && status.remote_address.port == htons(27256) // 46.174.52.2:27256
        )
            gEnginefuncs.pfnClientCmd("say /buyammo");
    }

    return gUsermsgfuncs.MsgFunc_Money(pszName, iSize, pbuf);
}

static int MsgFunc_ScoreInfo(const char *pszName, int iSize, void *pbuf)
{
    unsigned char *buf = (unsigned char *)pbuf;

    g_PlayerTeam[buf[0]] = (short)(buf[7] | (buf[8] << 8));
    
    return gUsermsgfuncs.MsgFunc_ScoreInfo(pszName, iSize, pbuf);
}

static int MsgFunc_TeamInfo(const char *pszName, int iSize, void *pbuf)
{
    unsigned char *buf = (unsigned char *)pbuf;
    
    int playerIndex = buf[0];
    const char *teamName = (const char *)&buf[1];
    
    if(strcmp(teamName, "TERRORIST") == 0)
        g_PlayerTeam[playerIndex] = TEAM_TERRORIST;
    else if(strcmp(teamName, "CT") == 0)
        g_PlayerTeam[playerIndex] = TEAM_CT;
    else if(strcmp(teamName, "SPECTATOR") == 0 || strcmp(teamName, "UNASSIGNED") == 0)
        g_PlayerTeam[playerIndex] = TEAM_SPECTATOR;
    else
        g_PlayerTeam[playerIndex] = TEAM_UNASSIGNED;
    
    return gUsermsgfuncs.MsgFunc_TeamInfo(pszName, iSize, pbuf);
}

static int HUD_AddEntity(int type, cl_entity_t *ent, const char *modelname)
{
    if(ent->index > 0 && ent->index <= MAX_PLAYERS)
    {
        cl_entity_t *pLocal = gEnginefuncs.GetLocalPlayer();
        if(ent->index != pLocal->index)
        {
            short iTeam = g_PlayerTeam[pLocal->index];
            short iTargetTeam = g_PlayerTeam[ent->index];
            if(
                iTeam != TEAM_SPECTATOR && iTeam != TEAM_UNASSIGNED
                && iTargetTeam != TEAM_SPECTATOR && iTargetTeam != TEAM_UNASSIGNED
            )
            {
                if(iTargetTeam != iTeam)
                {
                    ent->renderamt = 255;

                    model_t *pModel = gEngineStudio.GetModelByIndex(ent->modelindex);

                    const char *p = strstr(pModel->name, "models/player/");
                    if(p)
                    {
                        p += 14;
                        char szModel[64];
                        int i = 0;
                        while(*p && *p != '/' && i < 63)
                            szModel[i++] = *p++;
                        szModel[i] = '\0';

                        if(i > 0)
                        {
                            player_info_t *pInfo = gEngineStudio.PlayerInfo(ent->index - 1);
                            if(pInfo && strcmp(pInfo->model, szModel) != 0)
                                strcpy(pInfo->model, szModel);
                        }
                    }
                }
                else if(iTargetTeam == iTeam)
                {
                    ent->rendermode = kRenderTransAlpha;
                    ent->renderamt = 128;
                }
            }
        }
    }
    else if(strcmp(modelname, "models/pallet_with_bags.mdl") == 0)
    {
        ent->rendermode = kRenderTransAlpha;
        ent->renderamt = 75;
    }
    
    return gClientfuncs.HUD_AddEntity(type, ent, modelname);
}

static int pfnHookUserMsg(const char *szMsgName, int (*pfn)(const char *, int, void *))
{
    if(strcmp(szMsgName, "Money") == 0)
    {
        gUsermsgfuncs.MsgFunc_Money = pfn;
        
        return gEnginefuncs.pfnHookUserMsg(szMsgName, MsgFunc_Money);
    }
    
    if(strcmp(szMsgName, "ScoreInfo") == 0)
    {
        gUsermsgfuncs.MsgFunc_ScoreInfo = pfn;

        return gEnginefuncs.pfnHookUserMsg(szMsgName, MsgFunc_ScoreInfo);
    }

    if(strcmp(szMsgName, "TeamInfo") == 0)
    {
        gUsermsgfuncs.MsgFunc_TeamInfo = pfn;

        return gEnginefuncs.pfnHookUserMsg(szMsgName, MsgFunc_TeamInfo);
    }

    return gEnginefuncs.pfnHookUserMsg(szMsgName, pfn);
}

static int Initialize(cl_enginefunc_t *pEnginefuncs, int iVersion)
{
    gEnginefuncs = *pEnginefuncs;

    pEnginefuncs->pfnHookUserMsg = pfnHookUserMsg;

    INLINE_HOOK(HW(CL_AddToResourceList), CL_AddToResourceList);

    return gClientfuncs.Initialize(pEnginefuncs, iVersion);
}

static int HUD_GetStudioModelInterface(int version, void **ppinterface, engine_studio_api_t *pstudio)
{
    gEngineStudio = *pstudio;

    return gClientfuncs.HUD_GetStudioModelInterface(version, ppinterface, pstudio);
}

static int InitiateGameConnection(void *pThis, void *pAuthBlob, int cbMaxAuthBlob, uint64_t steamIDGameServer, uint32_t unIPServer, uint16_t usPortServer, int bSecure)
{
    int cbAuthBlob = gSteamUserfuncs.InitiateGameConnection(pThis, pAuthBlob, cbMaxAuthBlob, steamIDGameServer, unIPServer, usPortServer, bSecure);

    gEnginefuncs.Con_DPrintf("InitiateGameConnection: pAuthBlob=%p cbMaxAuthBlob=%d steamIDGameServer=%llu IPServer=%u.%u.%u.%u usPortServer=%u bSecure=%d cbAuthBlob=%d\n", pAuthBlob, cbMaxAuthBlob, (unsigned long long)steamIDGameServer, (unIPServer >> 24) & 0xFF, (unIPServer >> 16) & 0xFF, (unIPServer >> 8) & 0xFF, unIPServer & 0xFF, usPortServer, bSecure, cbAuthBlob);

    if(cbAuthBlob > 0 && pAuthBlob)
    {
        FILE *f = fopen("/tmp/ticket.bin", "wb");
        if(f)
        {
            fwrite(pAuthBlob, 1, cbAuthBlob, f);
            fclose(f);
        }
    }

    return cbAuthBlob;
}

__attribute__((visibility("default")))
void *SteamUser()
{
    void *pSteamUser = STEAM_API(SteamUser)();

    if(pSteamUser && !gSteamUserfuncs.InitiateGameConnection)
    {
        ISteamUser *vtable = *(ISteamUser**)pSteamUser;

        gSteamUserfuncs = *vtable;

        MPROTECT_RWX(vtable);

        vtable->InitiateGameConnection = InitiateGameConnection;
        
        MPROTECT_RX(vtable);
    }

    return pSteamUser;
}

static struct {
    const char *name;
    const char *lib;
    void *original;
    void *hook;
} dlsym_hooks[] = {
    {"dlsym", NULL, NULL, dlsym},
    {"Initialize", "cstrike/cl_dlls/client.so", &gClientfuncs.Initialize, Initialize},
    {"HUD_AddEntity", "cstrike/cl_dlls/client.so", &gClientfuncs.HUD_AddEntity, HUD_AddEntity},
    {"HUD_GetStudioModelInterface", "cstrike/cl_dlls/client.so", &gClientfuncs.HUD_GetStudioModelInterface, HUD_GetStudioModelInterface},
    {NULL}
};

__attribute__((visibility("default")))
void *dlsym(void *handle, const char *symbol)
{
    void *ptr = DLSYM(handle, symbol);
    Dl_info info;

    for(int i = 0; dlsym_hooks[i].name; i++)
    {
        if(strcmp(symbol, dlsym_hooks[i].name)) 
            continue;

        if(dlsym_hooks[i].lib && (!dladdr(ptr, &info) || !strstr(info.dli_fname, dlsym_hooks[i].lib)))
            continue;

        if(dlsym_hooks[i].original)
            *(void **)dlsym_hooks[i].original = ptr;

        return dlsym_hooks[i].hook;
    }

    return ptr;
}
