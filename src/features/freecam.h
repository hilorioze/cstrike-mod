#pragma once

#include <stdbool.h>

#include "goldsrc/abi.h"

void Freecam_Initialize(void);
void Freecam_Reset(void);
bool Freecam_IsEnabled(void);
void Freecam_BeforeCreateMove(void);
void Freecam_CreateMove(float frametime, usercmd_t* cmd, int active);
void Freecam_CalcRefdef(ref_params_t* params);
