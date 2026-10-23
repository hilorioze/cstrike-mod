#include <X11/X.h>
#include <X11/Xlib.h>
#include <dlfcn.h>
#include <string.h>

#include "hooks/clipboard.h"
#include "loader.h"

clipboard_orig_funcs_t gClipboardOrigFuncs;

static Atom gSelectionTarget;
static int (*real_SDL_SetClipboardText)(const char* text);

int Clipboard_NextEvent(Display* display, XEvent* event) {
  int result = gClipboardOrigFuncs.XNextEvent(display, event);
  if (event->type == SelectionRequest)
    gSelectionTarget = event->xselectionrequest.target;

  return result;
}

Status Clipboard_SendEvent(Display* display, Window window, Bool propagate, long eventMask,
                           XEvent* event) {
  // bundled sdl replies with the clipboard text's type in `target` instead of the requested one, so
  // the xwayland clipboard bridge ignores its `TARGETS` reply and never exports the text to wayland
  if (event->type == SelectionNotify)
    event->xselection.target = gSelectionTarget;

  return gClipboardOrigFuncs.XSendEvent(display, window, propagate, eventMask, event);
}

// vgui's `CopySelected` puts `\r` before every `\n` for the windows clipboard, and other programs
// paste it as a stray character
__attribute__((visibility("default"))) int SDL_SetClipboardText(const char* text) {
  if (!real_SDL_SetClipboardText) {
    void* library = dlopen("libSDL2-2.0.so.0", RTLD_NOW | RTLD_NOLOAD);
    real_SDL_SetClipboardText = RealDlsym(library, "SDL_SetClipboardText");
  }

  char converted[strlen(text) + 1];
  char* end = converted;
  for (const char* c = text; *c; c++) {
    if (c[0] != '\r' || c[1] != '\n')
      *end++ = *c;
  }
  *end = '\0';

  return real_SDL_SetClipboardText(converted);
}
