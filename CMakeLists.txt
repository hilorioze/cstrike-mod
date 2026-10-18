cmake_minimum_required(VERSION 3.13)
project(cstrike_mod C)

add_compile_options(
  -m32
  -fvisibility=hidden
  -Wall
  -Wextra
  -Wno-unused-parameter
)

add_link_options(-m32)

add_library(cstrike_mod SHARED
  # keep-sorted start
  src/codepatch.c
  src/cstrike/player_state.c
  src/features/bot.c
  src/features/buyammo.c
  src/features/crosshair.c
  src/features/cstatus.c
  src/features/nvg.c
  src/features/player_render.c
  src/features/scoreboard.c
  src/globals.c
  src/hooks/client.c
  src/hooks/studio.c
  src/main.c
  src/server.c
  # keep-sorted end
)
target_include_directories(cstrike_mod PRIVATE src)
target_link_libraries(cstrike_mod PRIVATE GL dl dobby)
