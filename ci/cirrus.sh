#!/bin/sh

set -e
set -x

export LC_ALL=C

env >> test_env.log

$CC -v || true
valgrind --version || true

./autogen.sh

./configure \
    --enable-experimental="$EXPERIMENTAL" \
    --with-test-override-wide-multiply="$WIDEMUL" --with-asm="$ASM" \
    --with-ecmult-window="$ECMULTWINDOW" \
    --with-ecmult-gen-precision="$ECMULTGENPRECISION" \
    --enable-module-ecdh="$ECDH" --enable-module-recovery="$RECOVERY" \
    --enable-module-ecdsa-s2c="$ECDSA_S2C" \
    --enable-module-bppp="$BPPP" \
    --enable-module-rangeproof="$RANGEPROOF" --enable-module-whitelist="$WHITELIST" --enable-module-generator="$GENERATOR" \
    --enable-module-schnorrsig="$SCHNORRSIG"  --enable-module-musig="$MUSIG" --enable-module-ecdsa-adaptor="$ECDSAADAPTOR" \
    --enable-module-schnorrsig="$SCHNORRSIG" \
    --enable-examples="$EXAMPLES" \
    --with-valgrind="$WITH_VALGRIND" \
    --host="$HOST" $EXTRAFLAGS

# We have set "-j<n>" in MAKEFLAGS.
make

# Print information about binaries so that we can see that the architecture is correct
file *tests* || true
file bench* || true
file .libs/* || true

# This tells `make check` to wrap test invocations.
export LOG_COMPILER="$WRAPPER_CMD"

make "$BUILD"

if [ "$BENCH" = "yes" ]
then
    # Using the local `libtool` because on macOS the system's libtool has nothing to do with GNU libtool
    EXEC='./libtool --mode=execute'
    if [ -n "$WRAPPER_CMD" ]
    then
        EXEC="$EXEC $WRAPPER_CMD"
    fi
    {
        $EXEC ./bench_ecmult
        $EXEC ./bench_internal
        $EXEC ./bench
        if [ "$BPPP" = "yes" ]
        then
            $EXEC ./bench_bppp
        fi
    } >> bench.log 2>&1
fi

if [ "$CTIMETEST" = "yes" ]
then
    ./libtool --mode=execute valgrind --error-exitcode=42 ./valgrind_ctime_test > valgrind_ctime_test.log 2>&1
fi

# Rebuild precomputed files (if not cross-compiling).
if [ -z "$HOST" ]
then
    make clean-precomp
    make precomp
fi

# Check that no repo files have been modified by the build.
# (This fails for example if the precomp files need to be updated in the repo.)
git diff --exit-code
