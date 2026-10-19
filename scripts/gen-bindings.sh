#!/usr/bin/env bash
# Generates Swift and Kotlin bindings for flynn-ffi in library mode.
# Output: build/bindings/{swift,kotlin}
source "$(dirname "$0")/env.sh"

step "Building flynn-ffi for the host (binding metadata)"
cargo build --manifest-path "$CORE/Cargo.toml" -p flynn-ffi --lib
HOST_LIB="$CORE/target/debug/libflynn_ffi.dylib"

# Library mode reads each crate's uniffi.toml through cargo metadata, so run
# from inside the workspace.
bindgen() {
    (cd "$CORE" && cargo run --quiet -p flynn-ffi --features bindgen --bin uniffi-bindgen -- \
        generate --library "$HOST_LIB" "$@")
}

for lang in swift kotlin; do
    step "Generating $lang bindings"
    rm -rf "$BUILD/bindings/$lang"
    mkdir -p "$BUILD/bindings/$lang"
    bindgen --language "$lang" --no-format --out-dir "$BUILD/bindings/$lang"
done
