cmake_minimum_required(VERSION 3.15)
project(laitoxx_native CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find pybind11
find_package(pybind11 REQUIRED)

# Source files
set(SOURCES
    src/laitoxx_core.cpp
    src/attack_engine.cpp
    src/header_manager.cpp
    src/l7_attacks.cpp
    src/l4_attacks.cpp
    src/l7_bypass.cpp
    src/l7_specialized.cpp
    src/l3_attacks.cpp
    src/l7_database.cpp
    src/l2_attacks.cpp
    src/l7_application.cpp
)

# Windows-only optimized sources
if(WIN32)
    list(APPEND SOURCES
        src/win_tuning.cpp
        src/iocp_engine.cpp
    )
endif()

# Create Python module
pybind11_add_module(laitoxx_core ${SOURCES})

# Include directories
target_include_directories(laitoxx_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Platform-specific settings
if(WIN32)
    target_link_libraries(laitoxx_core PRIVATE ws2_32 mswsock advapi32)
    target_compile_definitions(laitoxx_core PRIVATE _WIN32_WINNT=0x0601)
else()
    # Linux/Unix specific libraries
    target_link_libraries(laitoxx_core PRIVATE pthread)
endif()

# Compiler warnings
if(MSVC)
    target_compile_options(laitoxx_core PRIVATE /W4)
else()
    target_compile_options(laitoxx_core PRIVATE -Wall -Wextra -Wpedantic -Wno-narrowing)
endif()

# Optimization flags for Release build
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(MSVC)
        target_compile_options(laitoxx_core PRIVATE /O2)
    else()
        target_compile_options(laitoxx_core PRIVATE -O3 -march=native)
    endif()
endif()
