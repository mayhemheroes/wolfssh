#!/usr/bin/env bash
#
# wolfssh/mayhem/build.sh — build the wolfSSH OSS-Fuzz server harness as a sanitized libFuzzer
# target (+ a standalone run-once reproducer), AND wolfSSH's own self-contained unit.test for
# mayhem/test.sh.
#
# wolfSSH depends on wolfSSL. OSS-Fuzz clones+builds wolfSSL as a sibling dependency; we replicate
# that: clone wolfSSL, configure/build/install it (static, --enable-ssh --enable-keygen), then build
# wolfSSH against that install. BOTH libraries are compiled with $SANITIZER_FLAGS so the fuzzed SSH
# wire-format parser AND the crypto/transport code beneath it are instrumented.
#
# Fuzzed surface (mayhem/harnesses/fuzz_server.c): the harness drives wolfSSH_accept() as a server,
# feeding the fuzzer bytes through a custom IO recv callback. This exercises the SSH version exchange,
# KEXINIT/key exchange, and userauth wire parsers — the primary remote attack surface of an SSH server.
#
# Build contract comes from the org base ENV (CC/CXX/CFLAGS/CXXFLAGS/SANITIZER_FLAGS/
# LIB_FUZZING_ENGINE/STANDALONE_FUZZ_MAIN/SRC). $OUT is forced to /mayhem.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS: explicit DWARF-3 so Mayhem triage can read symbols (clang-19 defaults to DWARF-5).
# `:=` keeps any caller override; default forces -gdwarf-3.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
export DEBUG_FLAGS
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
OUT=/mayhem

# Coverage instrumentation: SANITIZER_FLAGS carries ASan+UBSan but NOT SanitizerCoverage. libFuzzer
# only finds "interesting" inputs if the fuzzed code is built with coverage — so add
# -fsanitize=fuzzer-no-link to the flags used for wolfSSL, wolfSSH and the harness object (the engine
# itself links via $LIB_FUZZING_ENGINE). Without this, fuzz_server runs but never explores (corp 1/1b,
# "no interesting inputs ... Is the code instrumented for coverage?"). Only add it when sanitizing.
COV_FLAGS=""
case " $SANITIZER_FLAGS " in
  *fsanitize=fuzzer-no-link*) ;;                       # already present
  *fsanitize=*) COV_FLAGS="-fsanitize=fuzzer-no-link" ;;  # sanitized build → add coverage
  *) ;;                                                # no sanitizers requested → leave bare
esac
# Build flags = sanitizers + coverage + debug info (DWARF-3). These propagate to autotools via
# CFLAGS/CXXFLAGS and to the direct harness compile. DEBUG_FLAGS comes AFTER SANITIZER_FLAGS so it
# can override any -g that sanitizer flags happen to emit.
CFLAGS="$SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS"
CXXFLAGS="$SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS"
export SANITIZER_FLAGS CC CXX LIB_FUZZING_ENGINE CFLAGS CXXFLAGS MAYHEM_JOBS STANDALONE_FUZZ_MAIN

# wolfSSH source is the baked repo at $SRC (/mayhem). wolfSSL is a build-time dependency we fetch.
WOLFSSH_SRC="$SRC"
DEPS="$SRC/mayhem-deps"
WOLFSSL_SRC="$DEPS/wolfssl"
WOLFSSL_INSTALL="$DEPS/wolfssl/install"
mkdir -p "$DEPS"

# ── 1) wolfSSL (dependency) — clone, build static + install, sanitized ─────────────────────────────
if [ ! -d "$WOLFSSL_SRC/.git" ]; then
  git clone --depth 1 https://github.com/wolfSSL/wolfssl "$WOLFSSL_SRC"
fi
cd "$WOLFSSL_SRC"
./autogen.sh
# Sanitize wolfSSL too so bugs under the SSH parser are caught. Pass the sanitizer/instrumentation
# flags through CFLAGS so autotools propagates them to every compiled object.
CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS" ./configure \
    --enable-static --disable-shared \
    --enable-ssh --enable-keygen \
    --disable-examples --disable-crypttests \
    --prefix="$WOLFSSL_INSTALL"
make -j"$MAYHEM_JOBS"
make install

# ── 2) wolfSSH — build static lib (sanitized) against the wolfSSL install ──────────────────────────
cd "$WOLFSSH_SRC"
./autogen.sh
CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS" ./configure \
    --enable-static --disable-shared \
    --disable-examples \
    --with-wolfssl="$WOLFSSL_INSTALL"
make -j"$MAYHEM_JOBS"

# ── 3) Generate the embedded server RSA private key header the harness #includes ───────────────────
KEY="$WOLFSSH_SRC/keys/server-key-rsa.der"
python3 - "$KEY" > "$DEPS/server_key_rsa.h" <<'PYEOF'
import sys
with open(sys.argv[1], "rb") as f: data = f.read()
print("/* auto-generated */")
print("#ifndef SERVER_KEY_RSA_H")
print("#define SERVER_KEY_RSA_H")
print("#include <stddef.h>")
print("static const unsigned char server_key_rsa_der[] = {")
for i in range(0, len(data), 12):
    print("  " + ", ".join("0x%02x" % b for b in data[i:i+12]) + ",")
print("};")
print("static const size_t server_key_rsa_der_len = sizeof(server_key_rsa_der);")
print("#endif")
PYEOF

HARNESS_DIR="$WOLFSSH_SRC/mayhem/harnesses"
INC="-I$WOLFSSL_INSTALL/include -I$WOLFSSH_SRC -I$DEPS"
LIBS="$WOLFSSH_SRC/src/.libs/libwolfssh.a $WOLFSSL_INSTALL/lib/libwolfssl.a"

# ── 4) Build the harness: libFuzzer target + standalone reproducer ────────────────────────────────
$CC $CFLAGS $INC -c "$HARNESS_DIR/fuzz_server.c" -o "$DEPS/fuzz_server.o"

# libFuzzer target -> /mayhem/fuzz_server
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE "$DEPS/fuzz_server.o" $LIBS -o "$OUT/fuzz_server"

# standalone run-once reproducer (no libFuzzer runtime) -> /mayhem/fuzz_server-standalone.
# Use the base image's StandaloneFuzzTargetMain.c if present (build-contract), else our local driver.
STANDALONE_SRC="$STANDALONE_FUZZ_MAIN"
[ -f "$STANDALONE_SRC" ] || STANDALONE_SRC="$HARNESS_DIR/standalone_main.c"
$CC $CFLAGS -c "$STANDALONE_SRC" -o "$DEPS/standalone_main.o"
$CXX $CXXFLAGS "$DEPS/fuzz_server.o" "$DEPS/standalone_main.o" $LIBS -o "$OUT/fuzz_server-standalone"

echo "built fuzz_server (+ standalone)"

# ── 5) Build wolfSSH's OWN unit.test with NORMAL flags (clean tree) for mayhem/test.sh to RUN ──────
# unit.test is self-contained: it drives the internal SSH packet parsers (DoProtoId,
# DoUserAuthRequest, DoChannel*, key parsing/keygen) over in-memory buffers with a simulated IO
# callback — NO live server/socket. Built here with normal (non-sanitized) flags in a separate
# install so test.sh is an honest functional oracle that only RUNS the suite.
TESTS_PREFIX="$DEPS/wolfssl-tests-install"
if [ ! -d "$TESTS_PREFIX/include" ]; then
  cd "$WOLFSSL_SRC"
  env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS ./configure \
      --enable-static --disable-shared \
      --enable-ssh --enable-keygen \
      --disable-examples --disable-crypttests \
      --prefix="$TESTS_PREFIX" >/dev/null
  env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS make -j"$MAYHEM_JOBS" >/dev/null
  env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS make install >/dev/null
fi

cd "$WOLFSSH_SRC"
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS ./configure \
    --enable-static --disable-shared \
    --enable-all \
    --with-wolfssl="$TESTS_PREFIX"
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS make -j"$MAYHEM_JOBS" tests/unit.test
echo "built wolfSSH unit.test (normal flags) for test.sh"

echo "build.sh complete:"
ls -la "$OUT/fuzz_server" "$OUT/fuzz_server-standalone" "$WOLFSSH_SRC/tests/unit.test" 2>&1 || true
