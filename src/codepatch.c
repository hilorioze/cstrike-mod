#include <dobby.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "codepatch.h"

void CodePatch_Apply(uint8_t* target, uint8_t* patch, size_t patchSize) {
  if (DobbyCodePatch(target, patch, patchSize) != 0)
    __builtin_trap();

  if (memcmp(target, patch, patchSize) != 0)
    __builtin_trap();
}

uint8_t* CodePatch_FindPattern(uint8_t* code, size_t codeSize, const uint8_t* pattern,
                               size_t patternSize) {
  if (codeSize < patternSize)
    __builtin_trap();

  for (size_t offset = 0; offset <= codeSize - patternSize; offset++) {
    if (memcmp(code + offset, pattern, patternSize) == 0)
      return code + offset;
  }

  __builtin_trap();
}
