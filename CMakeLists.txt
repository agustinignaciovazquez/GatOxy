project(socks C)

cmake_minimum_required(VERSION 2.8)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_C_STANDARD 99)

set(CMAKE_C_FLAGS    "--std=c99 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L ")

include(FindCheck.cmake)
include(CTest)
#include(CheckCSourceCompiles)
#include(CheckCSourceRuns)
#include(CheckFunctionExists)
#include(CheckIncludeFile)
#include(CheckIncludeFiles)
#include(CheckLibraryExists)
#include(CheckSymbolExists)
#include(CheckTypeSize)

set(CLANG_TIDY_CHECKS *
   -boost-*
   -mpi-*
   -llvm-*
   -cppcoreguidelines-*
   -clang-analyzer-osx.*
   -cert-*-cpp
   -misc-unused-parameters,
   -clang-diagnostic-missing-declarations)
string(REPLACE ";" "," CLANG_TIDY_CHECKS "${CLANG_TIDY_CHECKS}")

if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    find_program(CLANGTIDY NAMES clang-tidy)
    if(CLANGTIDY)
      message(STATUS "Found clang-tidy: ${CLANGTIDY}")
      set(CMAKE_C_CLANG_TIDY clang-tidy
                       -checks=${CLANG_TIDY_CHECKS}
                       -warnings-as-errors=*
                       -fix)
    endif()
endif()
set(CMAKE_C_FLAGS, "${CMAKE_C_FLAGS} -pedantic -pedantic-errors -Wall -Wextra 
-Werror -Wno-unused-parameter -D_POSIX_C_SOURCE=200112L")

add_subdirectory(src)


