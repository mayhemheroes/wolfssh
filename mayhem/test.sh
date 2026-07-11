#!/usr/bin/env bash
#
# wolfssh/mayhem/test.sh — RUN wolfSSH's own self-contained unit.test (built by mayhem/build.sh with
# normal flags) and emit a CTRF summary. exit 0 iff no test failed.
#
# ORACLE: tests/unit.test is the self-contained subset of wolfSSH's tests — it does NOT open a live
# server/socket. It exercises the same internal SSH wire-format parsers the fuzzer hits
# (DoProtoId/version exchange, DoUserAuthRequest + service-name handling, DoChannelData/ExtendedData
# overflow guards, DoChannelRequest/Success/Failure, RSA verify, key parsing/keygen) by feeding
# fixed in-memory byte vectors through a simulated IO callback and asserting the expected return /
# parsed result. A no-op or "always succeed" change to the parse path flips one of these expectations
# and the suite reports FAILED -> nonzero. This script only RUNS the pre-built binary; it never builds.
#
# unit.test prints one "<Name>: SUCCESS" or "<Name>: FAILED" line per case and returns nonzero if any
# case failed. We parse those lines for the CTRF counts and fall back to the exit code if unparseable.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

UNIT="$SRC/tests/unit.test"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
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

if [ ! -x "$UNIT" ]; then
  echo "missing $UNIT — run mayhem/build.sh first" >&2
  emit_ctrf "wolfssh-unit" 0 1 0; exit 2
fi

echo "=== running wolfSSH unit.test ==="
# unit.test expects to find its data files relative to the source tree root.
out="$("$UNIT" 2>&1)"; rc=$?
echo "$out"

PASSED=$(printf '%s\n' "$out" | grep -cE ': SUCCESS$' || true)
FAILED=$(printf '%s\n' "$out" | grep -cE ': FAILED$'  || true)
: "${PASSED:=0}" "${FAILED:=0}"

# If no per-case lines were parseable, fall back to the binary's exit code.
if [ "$(( PASSED + FAILED ))" -eq 0 ]; then
  echo "could not parse unit.test output; using exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "wolfssh-unit" 1 0 0; exit 0; }
  emit_ctrf "wolfssh-unit" 0 1 0; exit 1
fi

# Reconcile with the process exit code: a nonzero exit with no parsed FAILED still counts as failure.
if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then
  FAILED=1
fi

emit_ctrf "wolfssh-unit" "$PASSED" "$FAILED" 0
