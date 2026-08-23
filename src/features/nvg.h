#pragma once

void Nvg_Initialize(void* clientModule, void (*pfnSendToggle)(int iEnabled));
void Nvg_OnItemStatus(int iItemStatus);
void Nvg_OnToggle(int iEnabled);
int Nvg_HandleKeyEvent(int down, const char* pszCurrentBinding);
int Nvg_ShouldSuppressOverlay(int x, int y, int w, int h, int r, int g, int b, int a);
void Nvg_OnRedraw(void);
