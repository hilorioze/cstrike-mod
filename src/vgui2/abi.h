#pragma once

#include <stdbool.h>
#include <wchar.h>

typedef struct IInputInternal IInputInternal;

typedef int HInputContext;
typedef int KeyCode;
typedef int MouseCode;
typedef unsigned long HCursor;
typedef unsigned int VPANEL;

enum {
  KEY_LAST = 107,
};

// `VGUI_InputInternal001`, which `CInputWin32` of `vgui2.so` implements
typedef struct {
  void (*Destructor)(IInputInternal* self);
  void (*DeletingDestructor)(IInputInternal* self);
  void (*SetMouseFocus)(IInputInternal* self, VPANEL newMouseFocus);
  void (*SetMouseCapture)(IInputInternal* self, VPANEL panel);
  void (*GetKeyCodeText)(IInputInternal* self, KeyCode code, char* buf, int buflen);
  VPANEL (*GetFocus)(IInputInternal* self);
  VPANEL (*GetMouseOver)(IInputInternal* self);
  void (*SetCursorPos)(IInputInternal* self, int x, int y);
  void (*GetCursorPos)(IInputInternal* self, int* x, int* y);
  bool (*WasMousePressed)(IInputInternal* self, MouseCode code);
  bool (*WasMouseDoublePressed)(IInputInternal* self, MouseCode code);
  bool (*IsMouseDown)(IInputInternal* self, MouseCode code);
  void (*SetCursorOveride)(IInputInternal* self, HCursor cursor);
  HCursor (*GetCursorOveride)(IInputInternal* self);
  bool (*WasMouseReleased)(IInputInternal* self, MouseCode code);
  bool (*WasKeyPressed)(IInputInternal* self, KeyCode code);
  bool (*IsKeyDown)(IInputInternal* self, KeyCode code);
  bool (*WasKeyTyped)(IInputInternal* self, KeyCode code);
  bool (*WasKeyReleased)(IInputInternal* self, KeyCode code);
  VPANEL (*GetAppModalSurface)(IInputInternal* self);
  void (*SetAppModalSurface)(IInputInternal* self, VPANEL panel);
  void (*ReleaseAppModalSurface)(IInputInternal* self);
  void (*GetCursorPosition)(IInputInternal* self, int* x, int* y);
  void (*RunFrame)(IInputInternal* self);
  void (*UpdateMouseFocus)(IInputInternal* self, int x, int y);
  void (*PanelDeleted)(IInputInternal* self, VPANEL panel);
  void (*InternalCursorMoved)(IInputInternal* self, int x, int y);
  void (*InternalMousePressed)(IInputInternal* self, MouseCode code);
  void (*InternalMouseDoublePressed)(IInputInternal* self, MouseCode code);
  void (*InternalMouseReleased)(IInputInternal* self, MouseCode code);
  void (*InternalMouseWheeled)(IInputInternal* self, int delta);
  void (*InternalKeyCodePressed)(IInputInternal* self, KeyCode code);
  void (*InternalKeyCodeTyped)(IInputInternal* self, KeyCode code);
  void (*InternalKeyTyped)(IInputInternal* self, wchar_t unichar);
  void (*InternalKeyCodeReleased)(IInputInternal* self, KeyCode code);
  HInputContext (*CreateInputContext)(IInputInternal* self);
  void (*DestroyInputContext)(IInputInternal* self, HInputContext context);
  void (*AssociatePanelWithInputContext)(IInputInternal* self, HInputContext context, VPANEL pRoot);
  void (*ActivateInputContext)(IInputInternal* self, HInputContext context);
} IInputInternalVtbl;

struct IInputInternal {
  const IInputInternalVtbl* vtable;
};
