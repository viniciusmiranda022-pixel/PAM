# Builds FreeRDP from the pinned source archive (ADR 0006 §3) and exposes it to
# the worker's freerdp_client boundary. Only used when PRIVION_WITH_FREERDP=ON.
#
# Defense in depth: the archive is fetched from the IMMUTABLE commit-based URL and
# its bytes are verified with URL_HASH (SHA-256). Provenance (tag -> commit) is
# checked separately by scripts/pin-freerdp.sh. Fail-closed if either pin is
# malformed — no dynamic resolution, no TOFU.

include(ExternalProject)
include("${CMAKE_CURRENT_LIST_DIR}/freerdp-pin.cmake")

string(LENGTH "${FREERDP_COMMIT_SHA}" _privion_sha_len)
if(NOT _privion_sha_len EQUAL 40 OR NOT FREERDP_COMMIT_SHA MATCHES "^[0-9a-f]+$")
  message(FATAL_ERROR
    "FREERDP_COMMIT_SHA must be a full 40-hex commit SHA (ADR 0006); got "
    "'${FREERDP_COMMIT_SHA}'.")
endif()

string(LENGTH "${FREERDP_SOURCE_SHA256}" _privion_src_len)
if(NOT _privion_src_len EQUAL 64 OR NOT FREERDP_SOURCE_SHA256 MATCHES "^[0-9a-f]+$")
  message(FATAL_ERROR
    "FREERDP_SOURCE_SHA256 must be a real 64-hex SHA-256 (ADR 0006). Compute it "
    "on a trusted host with `scripts/pin-freerdp.sh --source-hash` and register "
    "it in cmake/freerdp-pin.cmake. The native build fails closed until then.")
endif()

# FREERDP_SOURCE_URL must be an https/oci/file URL (fail closed on placeholder).
# For this lab-only spike the official release URL is accepted; production must
# repoint it at the Privion internal immutable mirror (backlog BLD-ART-01). The
# archive bytes are verified by URL_HASH before extraction, so a tampered public
# origin fails the build; there is a single URL and no fallback.
if(NOT FREERDP_SOURCE_URL MATCHES "^(https|oci|file)://")
  message(FATAL_ERROR
    "FREERDP_SOURCE_URL must be an https/oci/file URL for freerdp-"
    "${FREERDP_VERSION}.tar.gz (ADR 0006). It currently is "
    "'${FREERDP_SOURCE_URL}'.")
endif()

set(FREERDP_PREFIX  "${CMAKE_BINARY_DIR}/freerdp")
set(FREERDP_INSTALL "${FREERDP_PREFIX}/install")

# Minimal client build: no server, no demo clients, TLS via OpenSSL. The download
# is verified against the committed SHA-256 before the archive is unpacked/built.
ExternalProject_Add(freerdp_ext
  URL "${FREERDP_SOURCE_URL}"
  URL_HASH "SHA256=${FREERDP_SOURCE_SHA256}"
  DOWNLOAD_NAME "freerdp-${FREERDP_VERSION}-${FREERDP_COMMIT_SHA}.tar.gz"
  PREFIX "${FREERDP_PREFIX}"
  CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${FREERDP_INSTALL}
    -DCMAKE_BUILD_TYPE=Release
    -DBUILD_SHARED_LIBS=ON
    -DBUILD_TESTING=OFF
    -DWITH_SERVER=OFF
    -DWITH_SAMPLE=OFF
    -DWITH_MANPAGES=OFF
    # Headless connect-only worker: disable GUI/audio/codec/redirection features
    # whose system libs we intentionally do not ship (keeps the image minimal and
    # the build reproducible). The core client + OpenSSL + zlib remain.
    -DWITH_CLIENT_SDL=OFF
    -DWITH_X11=OFF
    -DWITH_WAYLAND=OFF
    -DWITH_FFMPEG=OFF
    -DWITH_SWSCALE=OFF
    -DWITH_CAIRO=OFF
    -DWITH_PULSE=OFF
    -DWITH_ALSA=OFF
    -DWITH_OSS=OFF
    -DWITH_PCSC=OFF
    -DWITH_CUPS=OFF
    -DWITH_FUSE=OFF
    -DWITH_KRB5=OFF
    -DWITH_WEBVIEW=OFF
    # USB redirection channel needs libusb; not needed for a connect-only worker.
    -DCHANNEL_URBDRC=OFF
  BUILD_ALWAYS OFF
)

set(FREERDP_INCLUDE_DIRS
    "${FREERDP_INSTALL}/include/freerdp3"
    "${FREERDP_INSTALL}/include/winpr3")
set(FREERDP_LIB_DIR "${FREERDP_INSTALL}/lib")

function(privion_link_freerdp target)
  add_dependencies(${target} freerdp_ext)
  # SYSTEM: FreeRDP/WinPR headers use anonymous structs and value-narrowing
  # macros that trip our -Wpedantic/-Wconversion/-Werror. Treating them as system
  # headers silences third-party warnings while our own code stays strict.
  target_include_directories(${target} SYSTEM PRIVATE ${FREERDP_INCLUDE_DIRS})
  target_link_directories(${target} PUBLIC "${FREERDP_LIB_DIR}")
  target_link_libraries(${target} PUBLIC freerdp-client3 freerdp3 winpr3)
  target_compile_definitions(${target} PRIVATE PRIVION_WITH_FREERDP=1)
endfunction()
