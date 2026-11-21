#define _GNU_SOURCE  // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "goldsrc/abi.h"
#include "loader.h"

enum {
  // `GL_LoadTexture2` stops the game when it needs a new slot with this many in use
  kTextureLimit = 4799,

  // `GL_LoadTexture2` stores this many characters of an identifier but looks textures up by the
  // whole one
  kIdentifierLength = sizeof(((gltexture_t*)0)->identifier) - 1,
  kIdentifierHashDigits = 8,
  kIdentifierPrefixLength = kIdentifierLength - kIdentifierHashDigits,
};

static int (*real_GL_LoadTexture2)(char* identifier, int textureType, int width, int height,
                                   unsigned char* data, int mipmap, int iType, unsigned char* pPal,
                                   int filter);
static void (*real_GL_UnloadTexture)(char* identifier);

static gltexture_t* gTextures;
static int* gNumTextures;
static model_t* gModels;
static int* gNumModels;

static void ResolveEngine(void* caller) {
  Dl_info info;
  dladdr(caller, &info);
  void* engine = dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD);

  real_GL_LoadTexture2 = RealDlsym(engine, "GL_LoadTexture2");
  real_GL_UnloadTexture = RealDlsym(engine, "GL_UnloadTexture");
  gTextures = RealDlsym(engine, "gltextures");
  gNumTextures = RealDlsym(engine, "numgltextures");
  gModels = RealDlsym(engine, "mod_known");
  gNumModels = RealDlsym(engine, "mod_numknown");
}

static bool HasFreeTexture(void) {
  for (int i = 0; i < *gNumTextures; i++) {
    if (gTextures[i].servercount < 0)
      return true;
  }

  return false;
}

// fnv-1a
static uint32_t HashIdentifier(const char* identifier) {
  uint32_t hash = 2166136261U;
  for (; *identifier; identifier++)
    hash = (hash ^ (uint8_t)*identifier) * 16777619U;

  return hash;
}

// a truncated identifier never matches the full one again, so every reload of a model whose cache
// was evicted takes new slots; keep the beginning and replace the rest with a hash of the whole
// identifier
static char* FitIdentifier(char* identifier, char fitted[kIdentifierLength + 1]) {
  if (strlen(identifier) <= kIdentifierLength)
    return identifier;

  snprintf(fitted, kIdentifierLength + 1, "%.*s%08x", kIdentifierPrefixLength, identifier,
           HashIdentifier(identifier));

  return fitted;
}

// studio textures are named `<model><texture>`, sprite frames `<model>_<frame>`
static bool IsModelTexture(const model_t* model, const char* identifier) {
  size_t length = strlen(model->name);
  if (length > kIdentifierPrefixLength)  // the hash replaced the rest of the model name
    return strncmp(identifier, model->name, kIdentifierPrefixLength) == 0;

  if (strncmp(identifier, model->name, length) != 0)
    return false;

  const char* suffix = identifier + length;
  if (model->type == mod_studio)
    return true;

  if (*suffix != '_')
    return false;

  size_t digits = strspn(suffix + 1, "0123456789");

  return digits && !suffix[1 + digits];
}

// models of earlier servers stay in `mod_known` as unreferenced, and once their cache is gone
// nothing points at their textures anymore: `Mod_LoadModel` reloads them from disk with new
// textures if they're needed again
static void FreeOrphanedTextures(void) {
  for (int i = 0; i < *gNumModels; i++) {
    model_t* model = &gModels[i];
    if ((model->type != mod_studio && model->type != mod_sprite) ||
        model->needload != NL_UNREFERENCED || model->cache.data)
      continue;

    for (int texture = 0; texture < *gNumTextures; texture++) {
      if (gTextures[texture].servercount >= 0 &&
          IsModelTexture(model, gTextures[texture].identifier))
        real_GL_UnloadTexture(gTextures[texture].identifier);
    }
  }
}

// the engine never frees the textures of models from earlier servers, so after a few server
// switches the table fills up and `GL_LoadTexture2` stops the game with `MAX_GLTEXTURES`
__attribute__((visibility("default"))) int GL_LoadTexture2(char* identifier, int textureType,
                                                           int width, int height,
                                                           unsigned char* data, int mipmap,
                                                           int iType, unsigned char* pPal,
                                                           int filter);

int GL_LoadTexture2(char* identifier, int textureType, int width, int height, unsigned char* data,
                    int mipmap, int iType, unsigned char* pPal, int filter) {
  if (!real_GL_LoadTexture2)
    ResolveEngine(__builtin_return_address(0));

  if (*gNumTextures >= kTextureLimit && !HasFreeTexture())
    FreeOrphanedTextures();

  char fitted[kIdentifierLength + 1];
  return real_GL_LoadTexture2(FitIdentifier(identifier, fitted), textureType, width, height, data,
                              mipmap, iType, pPal, filter);
}

// `Mod_UnloadSpriteTextures` unloads sprite frames by their full identifiers
__attribute__((visibility("default"))) void GL_UnloadTexture(char* identifier);

void GL_UnloadTexture(char* identifier) {
  if (!real_GL_UnloadTexture)
    ResolveEngine(__builtin_return_address(0));

  char fitted[kIdentifierLength + 1];
  real_GL_UnloadTexture(FitIdentifier(identifier, fitted));
}
