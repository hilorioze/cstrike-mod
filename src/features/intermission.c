#define _GNU_SOURCE  // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

#include <dlfcn.h>
#include <stdint.h>

#include "codepatch.h"
#include "features/intermission.h"
#include "globals.h"
#include "loader.h"

void Intermission_Initialize(void) {
  Dl_info engineInfo;
  if (!dladdr((void*)gEnginefuncs.pfnGetCvarFloat, &engineInfo))
    __builtin_trap();

  void* engineModule = dlopen(engineInfo.dli_fname, RTLD_LAZY | RTLD_NOLOAD);
  if (!engineModule)
    __builtin_trap();

  uint8_t* parseIntermission = RealDlsym(engineModule, "CL_Parse_Intermission");
  if (!parseIntermission)
    __builtin_trap();

  // `svc_intermission` has no payload; return before it sets `cl.intermission`, which stops
  // prediction, mouse look and the normal hud
  static uint8_t returnInstruction[] = {0xc3};
  CodePatch_Apply(parseIntermission, returnInstruction, sizeof(returnInstruction));

  dlclose(engineModule);
}
