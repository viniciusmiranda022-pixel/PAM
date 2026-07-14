cmake_minimum_required(VERSION 3.20)
project(privion_rdp_worker LANGUAGES CXX)

# ── Options (ADR 0006) ──────────────────────────────────────────────────────
option(PRIVION_LAB_ONLY   "Build the lab-only worker (must be ON)"        ON)
option(PRIVION_WITH_FREERDP "Link libfreerdp (native build; CI job)"      OFF)
option(PRIVION_BUILD_TESTS  "Build unit tests"                            ON)

if(NOT PRIVION_LAB_ONLY)
  message(FATAL_ERROR
    "privion-rdp-worker-lab is a lab-only artifact: configure with "
    "-DPRIVION_LAB_ONLY=ON. There is no production build of this worker.")
endif()

# Pinned FreeRDP version (used for the --selftest expected version, always).
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/freerdp-pin.cmake")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)   # strict C++20 ...
add_compile_definitions(_GNU_SOURCE)  # ... plus GNU/POSIX APIs (SO_PEERCRED, accept4)

add_compile_options(-Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion)

add_compile_definitions(
  PRIVION_LAB_ONLY=1
  PRIVION_WORKER_VERSION="0.1.0-spike"
  FREERDP_EXPECTED_VERSION="${FREERDP_VERSION}"
)

find_package(Threads REQUIRED)

# ── Core library (everything except main.cpp) ───────────────────────────────
add_library(privion_rdp_core STATIC
  src/secure_buffer.cpp
  src/log_redaction.cpp
  src/policy.cpp
  src/lifecycle.cpp
  src/config.cpp
  src/credential.cpp
  src/uds_server.cpp
  src/lab_guard.cpp
  src/freerdp_client.cpp
)
target_include_directories(privion_rdp_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(privion_rdp_core PUBLIC Threads::Threads)

if(PRIVION_WITH_FREERDP)
  include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/FreeRDP.cmake")
  privion_link_freerdp(privion_rdp_core)
endif()

# ── Worker executable ───────────────────────────────────────────────────────
add_executable(privion-rdp-worker-lab src/main.cpp)
target_link_libraries(privion-rdp-worker-lab PRIVATE privion_rdp_core)

# ── Harness (lab client) ────────────────────────────────────────────────────
add_subdirectory(harness)

# ── Tests ───────────────────────────────────────────────────────────────────
if(PRIVION_BUILD_TESTS)
  enable_testing()
  set(PRIVION_TESTS
    secure_buffer_test
    log_redaction_test
    policy_test
    lifecycle_test
    uds_server_test
    config_test
    credential_test
    lab_guard_test
  )
  foreach(t ${PRIVION_TESTS})
    add_executable(${t} tests/${t}.cpp)
    target_include_directories(${t} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests")
    target_link_libraries(${t} PRIVATE privion_rdp_core)
    add_test(NAME ${t} COMMAND ${t})
  endforeach()
endif()
