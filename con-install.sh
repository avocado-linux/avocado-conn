#!/bin/bash
set -e

# Provided by the SDK environment when run via `avocado ext build`. Guard so an
# unset AVOCADO_BUILD_EXT_SYSROOT can't install to /usr/bin on the build host.
: "${RUST_TARGET_PATH:?must be set (run via 'avocado ext build')}"
: "${OECORE_TARGET_ARCH:?must be set (run via 'avocado ext build')}"
: "${AVOCADO_BUILD_DIR:?must be set (run via 'avocado ext build')}"
: "${AVOCADO_BUILD_EXT_SYSROOT:?must be set (run via 'avocado ext build')}"

# Find the Rust target from RUST_TARGET_PATH
for json_file in "$RUST_TARGET_PATH"/*.json; do
    if [ -f "$json_file" ]; then
        json_name=$(basename "$json_file" .json)
        if [[ "$json_name" == "${OECORE_TARGET_ARCH}-"* ]]; then
            RUST_TARGET="$json_name"
            break
        fi
    fi
done

if [ -z "$RUST_TARGET" ]; then
    echo "Error: Could not find Rust target for $OECORE_TARGET_ARCH"
    exit 1
fi

BINARY_PATH="$AVOCADO_BUILD_DIR/$RUST_TARGET/release/avocado-conn"

if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: Binary not found at $BINARY_PATH"
    exit 1
fi

echo "Installing avocado-conn into extension"
install -D -m 755 "$BINARY_PATH" "$AVOCADO_BUILD_EXT_SYSROOT/usr/bin/avocado-conn"
echo "avocado-conn installed successfully"
