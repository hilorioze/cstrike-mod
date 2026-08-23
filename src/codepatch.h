#pragma once

#include <stddef.h>
#include <stdint.h>

void CodePatch_Apply(uint8_t* target, uint8_t* patch, size_t patchSize);
uint8_t* CodePatch_FindPattern(uint8_t* code, size_t codeSize, const uint8_t* pattern,
                               size_t patternSize);
