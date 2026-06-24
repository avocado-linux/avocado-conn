#!/bin/bash
set -e

# These are provided by the SDK environment when run via `avocado ext build`.
# Guard up front so a stray invocation can't glob /*.json or write to unexpected
# paths instead of failing clearly.
: "${RUST_TARGET_PATH:?must be set (run via 'avocado ext build')}"
: "${OECORE_TARGET_ARCH:?must be set (run via 'avocado ext build')}"
: "${SDKTARGETSYSROOT:?must be set (run via 'avocado ext build')}"
: "${AVOCADO_BUILD_DIR:?must be set (run via 'avocado ext build')}"

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

echo "Compiling avocado-conn for target: $RUST_TARGET"

cd "$(dirname "$0")"

# Clear any rustflags that might cause conflicts with our .cargo/config.toml
unset RUSTFLAGS
unset CARGO_BUILD_RUSTFLAGS
for var in $(env | grep -o 'CARGO_TARGET_[A-Z0-9_]*_RUSTFLAGS' || true); do
    unset "$var"
done

# Remove only the generated cross-compile config, preserving any committed
# .cargo files (e.g. audit.toml) used for development.
rm -f .cargo/config.toml

# Create config.toml with cross-compilation settings
mkdir -p .cargo
cat > .cargo/config.toml << EOF
[target.$RUST_TARGET]
rustflags = ["--sysroot=$SDKTARGETSYSROOT/usr", "-C", "link-arg=--sysroot=$SDKTARGETSYSROOT"]
EOF

# Use a persistent cargo registry cache to avoid re-downloading crates
export CARGO_HOME="${AVOCADO_BUILD_DIR}/.cargo-cache"

cargo build --release --target "$RUST_TARGET" --target-dir "$AVOCADO_BUILD_DIR"

echo "avocado-conn compiled successfully"
