#!/bin/sh
# Test runner for encripto
# Builds and runs all test binaries, exits with 0 if all pass.

set -e

BUILD_DIR="$(dirname "$0")"
ROOT_DIR="$(dirname "$BUILD_DIR")"
LIBA="${ROOT_DIR}/libencripto.a"

cd "$ROOT_DIR"

# Build library if needed
if [ ! -f "$LIBA" ]; then
    echo "Building library..."
    make lib
fi

all_passed=0
for src in tests/test_*.c; do
    base="${src%.c}"
    binary="$base"
    test_name="$(basename "$base")"

    echo "=== Building ${test_name} ==="
    gcc -std=c11 -Wall -Wextra -Wpedantic -O2 -Iinclude -o "$binary" "$src" "$LIBA"

    echo "=== Running ${test_name} ==="
    if "$binary"; then
        echo ""
    else
        all_passed=1
    fi
done

if [ "$all_passed" -eq 0 ]; then
    echo "All tests passed."
    exit 0
else
    echo "Some tests FAILED."
    exit 1
fi
