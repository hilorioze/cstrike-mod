#include "features/voice.h"
#include "globals.h"
#include "goldsrc/abi.h"

void Voice_Initialize(void) {
  // the engine registers these without `FCVAR_ARCHIVE`, so `config.cfg` drops their values; mark
  // them archived to keep them there
  gEnginefuncs.pfnGetCvarPointer("voice_overdrive")->flags |= FCVAR_ARCHIVE;
  gEnginefuncs.pfnGetCvarPointer("voice_overdrivefadetime")->flags |= FCVAR_ARCHIVE;
}
