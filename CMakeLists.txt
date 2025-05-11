cmake_minimum_required(VERSION 3.20)

set(CMAKE_C_COMPILER "gcc")
set(CMAKE_CXX_COMPILER "g++")

project(
  detect-debugger 
  VERSION 0.1 
  LANGUAGES C
)

add_executable(${PROJECT_NAME} src/main.c)

target_compile_options(${PROJECT_NAME} PRIVATE
  $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:GNU>>:
      -Wall -Wextra -Wshadow -s -fvisibility=hidden -O3 -funroll-loops -static -std=gnu17 >
  $<$<CXX_COMPILER_ID:MSVC>:
      /WALL /WX >)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND strip -R .comment ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.exe)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  #set(CMAKE_C_COMPILER musl-gcc)
  add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND strip -R .comment ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME})
  add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND echo 'Ag==' | base64 -d | dd conv=notrunc of=${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME} bs=1 seek=5)
endif()