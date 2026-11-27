#include <stdlib.h>
#include <string.h>

#include "goldsrc/abi.h"

static byte* gVisibility;
static size_t gVisibilityCapacity;

// `Mod_LeafPVS` decompresses into a static buffer for 8192 leafs, and on bigger maps the rest
// overwrites `gPVS` behind it, so the next call returns a pointer into nowhere
__attribute__((visibility("default"))) byte* Mod_LeafPVS(mleaf_t* leaf, model_t* model);

byte* Mod_LeafPVS(mleaf_t* leaf, model_t* model) {
  // the world's `numleafs` is the map's `visleafs` as is, negative ones included
  size_t rowLength = model->numleafs > 0 ? ((size_t)model->numleafs + 7) >> 3 : 0;
  if (rowLength > gVisibilityCapacity) {
    gVisibility = realloc(gVisibility, rowLength);
    gVisibilityCapacity = rowLength;
  }

  const byte* compressed = leaf->compressed_vis;
  if (leaf == model->leafs || !compressed) {  // the outside and maps without vis see everything
    memset(gVisibility, 0xff, rowLength);

    return gVisibility;
  }

  for (size_t length = 0; length < rowLength;) {
    if (*compressed) {
      gVisibility[length++] = *compressed++;

      continue;
    }

    size_t zeros = compressed[1];  // a zero byte is followed by how many of them it stands for
    if (zeros > rowLength - length)
      zeros = rowLength - length;

    memset(gVisibility + length, 0, zeros);
    length += zeros;
    compressed += 2;
  }

  return gVisibility;
}
