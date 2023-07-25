# Set root project name
set(ROOT_PROJECT_NAME intercept)

# Set minimum CMake version required
cmake_minimum_required(VERSION 3.22.1)

# Set default C/C++ compiler and linker if not defined
if(NOT DEFINED CMAKE_C_COMPILER)
  set(CMAKE_C_COMPILER "clang")
endif()
if(NOT DEFINED CMAKE_CXX_COMPILER)
  set(CMAKE_CXX_COMPILER "clang++")
endif()
if(NOT DEFINED CMAKE_LINKER)
  set(CMAKE_LINKER "lld")
endif()

# Define default C/C++ standard to use
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

# Override default C/C++ build options
set(C_FLAGS
    "-Wall \
  -Wextra \
  -Werror")
set(CXX_FLAGS ${C_FLAGS})
set(CMAKE_C_FLAGS ${C_FLAGS})
set(CMAKE_CXX_FLAGS ${CXX_FLAGS})

# Set C/C++ linker option
add_link_options($<$<COMPILE_LANGUAGE:C>:-fuse-ld=${CMAKE_LINKER}>)
add_link_options($<$<COMPILE_LANGUAGE:C>:-rdynamic>)
add_link_options($<$<COMPILE_LANGUAGE:CXX>:-fuse-ld=${CMAKE_LINKER}>)
add_link_options($<$<COMPILE_LANGUAGE:CXX>:-rdynamic>)

# Override `Debug` and `Release` C/C++ build options
set(C_FLAGS_RELEASE
    "-DNDEBUG \
  -march=native \
  -O2 \
  -ftree-vectorize")
set(CXX_FLAGS_RELEASE ${C_FLAGS_RELEASE})
set(C_FLAGS_DEBUG "-Og")
set(CXX_FLAGS_DEBUG ${C_FLAGS_DEBUG})

# Handle build type
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set(CMAKE_C_FLAGS_RELEASE ${C_FLAGS_RELEASE})
  set(CMAKE_CXX_FLAGS_RELEASE ${CXX_FLAGS_RELEASE})
else()
  set(CMAKE_BUILD_TYPE "Debug")
  set(CMAKE_C_FLAGS_DEBUG ${C_FLAGS_DEBUG})
  set(CMAKE_CXX_FLAGS_DEBUG ${CXX_FLAGS_DEBUG})
endif()

# Set common C/C++ build options for target
set(C_FLAGS_NORM -save-temps -fverbose-asm)
set(CXX_FLAGS_NORM ${C_FLAGS_NORM})
set(C_FLAGS_LTO -flto)
set(CXX_FLAGS_LTO ${C_FLAGS_LTO})

# Set target debug option for gdb if the compiler is gcc, or lldb if clang
set(LLDB_FLAGS_DBG -glldb)
set(GDB_FLAGS_DBG -ggdb3)
set(GENERIC_FLAGS_DBG -g3)
if(CMAKE_C_COMPILER STREQUAL "clang")
  set(C_FLAGS_DBG ${LLDB_FLAGS_DBG})
elseif(CMAKE_C_COMPILER STREQUAL "gcc")
  set(C_FLAGS_DBG ${GDB_FLAGS_DBG})
endif()
set(C_FLAGS_DBG ${C_FLAGS_DBG} ${GENERIC_FLAGS_DBG})
if(CMAKE_CXX_COMPILER STREQUAL "clang++")
  set(CXX_FLAGS_DBG ${LLDB_FLAGS_DBG})
elseif(CMAKE_CXX_COMPILER STREQUAL "g++")
  set(CXX_FLAGS_DBG ${GDB_FLAGS_DBG})
endif()
set(CXX_FLAGS_DBG ${CXX_FLAGS_DBG} ${GENERIC_FLAGS_DBG})

# Set output path
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Declare top-level project
project(${ROOT_PROJECT_NAME})

# Add CMake source subdirectories
add_subdirectory(src)

# Set common target install directories
set(INSTALL_HEADER_DIR "/usr/local/include")
set(INSTALL_LIB_DIR "/usr/local/lib/")

# Install public header
install(
  DIRECTORY ${CMAKE_SOURCE_DIR}/include/
  DESTINATION ${INSTALL_HEADER_DIR}
  FILES_MATCHING
  PATTERN "*.h"
  PATTERN "*.hh"
  PATTERN "*.hpp"
  PATTERN "*.hxx")

# Define script for uninstall
set(UNINSTALL_SCRIPT_CMD
    "xargs"
    "rm"
    "-f"
    "<"
    "install_manifest.txt"
    "&&"
    "sh"
    "-c"
    "\""
    "cd"
    "${INSTALL_HEADER_DIR}"
    "&&"
    "basename"
    "-a"
    "--"
    "${CMAKE_SOURCE_DIR}/include/*/"
    "|"
    "xargs"
    "rmdir"
    "-p"
    "\""
    "&&"
    "rm"
    "-f"
    "install_manifest.txt")

# Add `uninstall` target
add_custom_target(
  uninstall
  COMMAND ${UNINSTALL_SCRIPT_CMD}
  DEPENDS install_manifest.txt)

# Run ldconfig
install(CODE "execute_process (COMMAND ldconfig)")
