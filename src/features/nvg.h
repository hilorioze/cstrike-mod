#pragma once

void Nvg_Initialize(void* clientModule);
void Nvg_OnItemStatus(int iItemStatus);
int Nvg_HandleKeyEvent(int down, const char* pszCurrentBinding);
int Nvg_ShouldSuppressOverlay(int x, int y, int w, int h, int r, int g, int b, int a);
