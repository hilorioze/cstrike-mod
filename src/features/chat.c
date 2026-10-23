#define _GNU_SOURCE  // NOLINT(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

#include <dlfcn.h>
#include <dobby.h>
#include <link.h>
#include <stdint.h>
#include <stdlib.h>
#include <wchar.h>

#include "codepatch.h"
#include "features/chat.h"
#include "globals.h"
#include "loader.h"

typedef void (*say_text_line_set_text_t)(void* line, wchar_t* buf, int clientIndex);

static say_text_line_set_text_t gSetTextOriginal;

// `SayTextPrint` puts every new chat message into a hud chat line here, so the console gets it as
// soon as it arrives
static void SetText(void* line, wchar_t* buf, int clientIndex) {
  gSetTextOriginal(line, buf, clientIndex);

  // the same conversion as `ScrollTextUp`'s: `ConvertUnicodeToANSI` of vgui2 is a plain `wcstombs`
  char converted[512];
  (void)wcstombs(converted, buf, sizeof(converted));  // NOLINT(concurrency-mt-unsafe)
  converted[sizeof(converted) - 1] = '\0';

  // drop the colour codes `\x01`-`\x05` the hud chat draws team colours with
  char text[sizeof(converted) + 1];
  char* end = text;
  for (const char* c = converted; *c; c++) {
    if ((unsigned char)*c > 5)
      *end++ = *c;
  }
  *end++ = '\n';
  *end = '\0';

  gEnginefuncs.pfnConsolePrint(text);
}

void Chat_Initialize(void* clientModule) {
  void* setText = RealDlsym(clientModule, "_ZN11SayTextLine7SetTextEPwi");
  uint8_t* scrollTextUp = RealDlsym(clientModule, "_Z12ScrollTextUpv");
  if (!setText || !scrollTextUp)
    __builtin_trap();

  if (DobbyHook(setText, SetText, (void**)&gSetTextOriginal) != 0)
    __builtin_trap();

  Dl_info scrollTextUpInfo;
  const ElfW(Sym)* scrollTextUpSymbol = NULL;
  if (!dladdr1(scrollTextUp, &scrollTextUpInfo, (void**)&scrollTextUpSymbol, RTLD_DL_SYMENT) ||
      !scrollTextUpSymbol)
    __builtin_trap();

  // `ScrollTextUp` prints the top line only once it leaves the hud chat, `hud_saytext_time` after
  // it got there: replace its `jne` into the print block with `nop`s
  static const uint8_t printBranch[] = {0x85, 0xff, 0x0f, 0x85, 0x4b, 0x01, 0x00, 0x00};
  uint8_t skipPrint[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

  uint8_t* printBranchMatch = CodePatch_FindPattern(scrollTextUp, scrollTextUpSymbol->st_size,
                                                    printBranch, sizeof(printBranch));
  CodePatch_Apply(printBranchMatch + 2, skipPrint, sizeof(skipPrint));
}
