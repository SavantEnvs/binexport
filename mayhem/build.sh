#!/usr/bin/env bash
#
# binexport/mayhem/build.sh — build google/binexport's BinExport2 parser + reader as a sanitized
# in-process libFuzzer target (+ a standalone reproducer), AND a CLEAN binexport2dump tool used as
# the behavioral oracle by mayhem/test.sh.
#
# binexport builds with CMake and pulls abseil + protobuf via FetchContent (boost is vendored in
# boost_parts/, googletest only when testing is enabled — we keep it OFF). The IDA Pro / Binary Ninja
# plugins default ON and require proprietary SDKs, so both are disabled here; the core library, the
# BinExport2 reader and the binexport2dump tool build with no disassembler SDK at all.
#
# Air-gap (SPEC 6.5): mayhem/Dockerfile bakes the pinned abseil + protobuf source trees into the
# image; here we point CMake's FETCHCONTENT_SOURCE_DIR_* at them and set
# FETCHCONTENT_FULLY_DISCONNECTED=ON so build.sh re-runs with no network.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) so an explicit empty --build-arg SANITIZER_FLAGS builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# DWARF <= 3 (Mayhem triage can't read >= 4; clang-19's plain -g emits DWARF-5). AFTER $SANITIZER_FLAGS
# so -gdwarf-3 wins over any -g there.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS DEBUG_FLAGS

cd "$SRC"

OUT=/mayhem
HARNESS_DIR="$SRC/mayhem/harnesses"

# ── 0) Air-gapped dependency caches (baked by the Dockerfile at the tags CMakeLists pins) ──────────
ABSL_SRC_CACHE="${ABSL_SRC_CACHE:-/opt/absl-cache}"
PROTOBUF_SRC_CACHE="${PROTOBUF_SRC_CACHE:-/opt/protobuf-cache}"

# Fallback for a from-scratch dev run with no baked caches (no-op inside the image).
if [ ! -d "$ABSL_SRC_CACHE" ] || [ -z "$(ls -A "$ABSL_SRC_CACHE" 2>/dev/null)" ]; then
  echo "No abseil cache at $ABSL_SRC_CACHE — cloning"
  git clone https://github.com/abseil/abseil-cpp.git "$ABSL_SRC_CACHE"
  git -C "$ABSL_SRC_CACHE" checkout ce1a8f1ec1793e5cb9d7fffa281efdfea5dd8035
fi
if [ ! -d "$PROTOBUF_SRC_CACHE" ] || [ -z "$(ls -A "$PROTOBUF_SRC_CACHE" 2>/dev/null)" ]; then
  echo "No protobuf cache at $PROTOBUF_SRC_CACHE — fetching v35.1"
  mkdir -p "$PROTOBUF_SRC_CACHE"
  curl -fsSL https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protobuf-35.1.tar.gz \
    | tar -xz --strip-components=1 -C "$PROTOBUF_SRC_CACHE"
fi

# FetchContent_Declare uses the names `absl` and `protobuf`; the override vars are the UPPERCASED name.
FETCH_ARGS=(
  -DFETCHCONTENT_FULLY_DISCONNECTED=ON
  "-DFETCHCONTENT_SOURCE_DIR_ABSL=$ABSL_SRC_CACHE"
  "-DFETCHCONTENT_SOURCE_DIR_PROTOBUF=$PROTOBUF_SRC_CACHE"
)

COMMON_CMAKE=(
  -DCMAKE_BUILD_TYPE=Release
  -DBINEXPORT_ENABLE_IDAPRO=OFF
  -DBINEXPORT_ENABLE_BINARYNINJA=OFF
  -DBINEXPORT_BUILD_TESTING=OFF
  -DBUILD_TESTING=OFF
  -DCMAKE_C_COMPILER="$CC"
  -DCMAKE_CXX_COMPILER="$CXX"
)

# ── 1) Sanitized build of the library (instrumented BinExport2 parser + reader) ────────────────────
# -fsanitize=fuzzer-no-link gives the LIBRARY SanCov instrumentation (edges) without pulling libFuzzer
# main; it is appended UNCONDITIONALLY (even for an empty $SANITIZER_FLAGS) so Mayhem still sees edges.
SAN="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link"
BUILD="$SRC/mayhem-build"
rm -rf "$BUILD"; mkdir -p "$BUILD"

cmake -S "$SRC" -B "$BUILD" \
  "${COMMON_CMAKE[@]}" \
  -DCMAKE_C_FLAGS="$SAN $DEBUG_FLAGS" \
  -DCMAKE_CXX_FLAGS="$SAN $DEBUG_FLAGS" \
  "${FETCH_ARGS[@]}"
cmake --build "$BUILD" --parallel "$MAYHEM_JOBS" \
  --target binexport_shared binexport_reader

# Static-lib link closure: binexport reader + shared (proto is compiled into binexport_shared) plus
# the protobuf + abseil + utf8 archives FetchContent produced under the build tree.
BINEXPORT_READER_A=$(find "$BUILD" -name 'libbinexport_reader.a' | head -1)
BINEXPORT_SHARED_A=$(find "$BUILD" -name 'libbinexport_shared.a' | head -1)
[ -f "$BINEXPORT_READER_A" ] && [ -f "$BINEXPORT_SHARED_A" ] || {
  echo "FAIL: binexport static libs not found under $BUILD" >&2; exit 1; }
BINEXPORT_LIBS="$BINEXPORT_READER_A $BINEXPORT_SHARED_A"
PROTOBUF_LIBS=$(find "$BUILD" -name 'libprotobuf.a' | sort -u)
UTF8_LIBS=$(find "$BUILD" \( -name 'libutf8_range.a' -o -name 'libutf8_validity.a' \) | sort -u)
ABSL_LIBS=$(find "$BUILD" -path '*absl*' -name '*.a' | sort -u)
LINK_LIBS="$BINEXPORT_LIBS $PROTOBUF_LIBS $UTF8_LIBS $ABSL_LIBS"

# Include paths matching binexport_base's INTERFACE include dirs (Google-style third_party/... paths
# resolve via the src_include/gen_include symlinks CMake created at configure time).
INCS="-I$BUILD/gen_include -I$BUILD/src_include -I$SRC -I$SRC/stubs -I$SRC/boost_parts \
      -I$PROTOBUF_SRC_CACHE/src -I$PROTOBUF_SRC_CACHE/third_party/utf8_range -I$ABSL_SRC_CACHE"

# ── 2) Standalone driver object (no libFuzzer runtime) — compiled as C, linked per harness ─────────
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$BUILD/standalone_main.o"

# ── 3) Build the harness: libFuzzer target (-> /mayhem/binexport2_fuzzer) + standalone reproducer ──
echo "Building harness: binexport2_fuzzer"
$CXX $SAN $DEBUG_FLAGS -std=c++20 $INCS \
  "$HARNESS_DIR/binexport2_fuzzer.cc" $LIB_FUZZING_ENGINE \
  -Wl,--start-group $LINK_LIBS -Wl,--end-group \
  -lpthread \
  -o "$OUT/binexport2_fuzzer"

$CXX $SAN $DEBUG_FLAGS -std=c++20 $INCS \
  "$HARNESS_DIR/binexport2_fuzzer.cc" "$BUILD/standalone_main.o" \
  -Wl,--start-group $LINK_LIBS -Wl,--end-group \
  -lpthread \
  -o "$OUT/binexport2_fuzzer-standalone"

# ── 4) CLEAN oracle build of binexport2dump (NORMAL flags: no sanitizer, no -gdwarf-3) ─────────────
# This is the honest behavioral oracle test.sh runs; it must be dynamically linked (default) so the
# anti-reward-hack neuter shim can affect it.
TESTBUILD="$SRC/mayhem-oracle"
rm -rf "$TESTBUILD"; mkdir -p "$TESTBUILD"
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  cmake -S "$SRC" -B "$TESTBUILD" \
    "${COMMON_CMAKE[@]}" \
    "${FETCH_ARGS[@]}"
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  cmake --build "$TESTBUILD" --parallel "$MAYHEM_JOBS" --target binexport2dump

# Stash the oracle binary where test.sh looks for it.
ORACLE_BIN=$(find "$TESTBUILD" -type f -name binexport2dump | head -1)
[ -x "$ORACLE_BIN" ] || { echo "FAIL: clean binexport2dump not built" >&2; exit 1; }
cp "$ORACLE_BIN" "$OUT/binexport2dump-oracle"

echo "build.sh complete:"
ls -la "$OUT/binexport2_fuzzer" "$OUT/binexport2_fuzzer-standalone" "$OUT/binexport2dump-oracle"
file "$OUT/binexport2dump-oracle"
