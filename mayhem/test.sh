#!/usr/bin/env bash
#
# binexport/mayhem/test.sh — behavioral oracle (SPEC 6.3, anti-reward-hacking).
#
# Runs the CLEAN, dynamically-linked binexport2dump tool (built by mayhem/build.sh as
# /mayhem/binexport2dump-oracle) on a real BinExport2 fixture shipped in the repo
# (reader/testdata/*.BinExport) and asserts EXACT values from the rendered disassembly:
#   * the meta-information architecture string,
#   * the "Functions:" section header,
#   * a known function name that only appears when the proto is actually parsed + rendered.
#
# A no-op / exit(0) PATCH FAILS here: the neuter shim LD_PRELOADs a constructor that _exit(0)s the
# tool before it reads the fixture, so it emits NO output -> every grep below fails. bash + coreutils
# are whitelisted by the shim, so the comparisons run where sabotage cannot hide (a ctest/gtest-only
# oracle would false-pass because the runner exits 0 having done nothing — see docs).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

TOOL="$SRC/binexport2dump-oracle"
FIXTURE="$SRC/reader/testdata/0000500ed9f688a309ee2176462eb978efa9a2fb80fcceb5d8fd08168ea50dfd.BinExport"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

PASSED=0
FAILED=0
check() { # <description> <expected-substring>
  local desc="$1" needle="$2"
  # here-string, not a pipe: with `set -o pipefail`, `... | grep -q` makes the producer take SIGPIPE
  # when grep matches early, which would flip the pipeline to non-zero on a successful match.
  if grep -qF -- "$needle" <<<"$OUT"; then
    echo "PASS: $desc"
    PASSED=$(( PASSED + 1 ))
  else
    echo "FAIL: $desc (missing: $needle)" >&2
    FAILED=$(( FAILED + 1 ))
  fi
}

if [ ! -x "$TOOL" ]; then
  echo "FAIL: oracle binary $TOOL missing — mayhem/build.sh must run first" >&2
  emit_ctrf "binexport2dump" 0 1 0; exit 2
fi
if [ ! -f "$FIXTURE" ]; then
  echo "FAIL: fixture $FIXTURE missing" >&2
  emit_ctrf "binexport2dump" 0 1 0; exit 2
fi

echo "=== binexport2dump behavioral oracle ==="
OUT="$("$TOOL" "$FIXTURE" 2>/dev/null || true)"

if [ -z "$OUT" ]; then
  echo "FAIL: binexport2dump produced no output — binary may be neutered or broken" >&2
  emit_ctrf "binexport2dump" 0 1 0; exit 1
fi

# EXACT asserted values, lifted from a real binexport2dump run on this fixture. Each is present ONLY
# when the tool actually parses the BinExport2 proto and renders it:
#   * the executable id + architecture from meta_information (proto parse),
#   * the "Functions:" section header + a generated function name (call-graph vertex render),
#   * a disassembly line with a rendered hex immediate (instruction/operand/expression render path).
check "executable id (meta_information)" "Executable Id:            0000500ed9f688a309ee2176462eb978efa9a2fb80fcceb5d8fd08168ea50dfd"
check "architecture (meta_information)"  "Architecture:             x86-32"
check "functions section header"         "Functions:"
check "call-graph function name render"  "sub_00320400"
check "instruction/expression render"    "mov ecx, 0xe0000"

emit_ctrf "binexport2dump" "$PASSED" "$FAILED" 0
