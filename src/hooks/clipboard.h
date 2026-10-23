#pragma once

#include <X11/X.h>
#include <X11/Xlib.h>

typedef struct {
  int (*XNextEvent)(Display* display, XEvent* event);
  Status (*XSendEvent)(Display* display, Window window, Bool propagate, long eventMask,
                       XEvent* event);
} clipboard_orig_funcs_t;

extern clipboard_orig_funcs_t gClipboardOrigFuncs;

int Clipboard_NextEvent(Display* display, XEvent* event);
Status Clipboard_SendEvent(Display* display, Window window, Bool propagate, long eventMask,
                           XEvent* event);
