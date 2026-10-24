#include "features/recoil.h"
#include "globals.h"
#include "goldsrc/abi.h"

void Recoil_CalcRefdef(ref_params_t* params) {
  // hide the punch from the view calculation only: the engine copies `punchangle` back into its own
  // state afterwards
  vec3_t punch;
  for (int i = 0; i < 3; i++) {
    punch[i] = params->punchangle[i];
    params->punchangle[i] = 0;
  }

  gClientOrigFuncs.V_CalcRefdef(params);

  for (int i = 0; i < 3; i++)
    params->punchangle[i] = punch[i];
}
