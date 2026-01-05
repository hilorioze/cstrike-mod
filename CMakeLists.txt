cmake_minimum_required(VERSION 3.10)
project(cstrike_mod C)

add_compile_options(-m32 -fvisibility=hidden)
add_link_options(-m32)

add_library(cstrike_mod SHARED src/main.c)
target_link_libraries(cstrike_mod PRIVATE dl)
