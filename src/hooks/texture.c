#define _GNU_SOURCE  // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

#include <dlfcn.h>
#include <stdbool.h>
#include <string.h>

#include "goldsrc/abi.h"
#include "loader.h"

enum {
  // `GL_LoadTexture2` stops the game when it needs a new slot with this many in use
  kTextureLimit = 4799,
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

// studio textures are named `<model><texture>`, sprite frames `<model>_<frame>`
static bool IsModelTexture(const model_t* model, const char* identifier) {
  size_t length = strlen(model->name);
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

  return real_GL_LoadTexture2(identifier, textureType, width, height, data, mipmap, iType, pPal,
                              filter);
}
