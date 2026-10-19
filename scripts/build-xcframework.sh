#!/usr/bin/env bash
# Builds the Rust core for iOS devices and the iOS Simulator, packages it as
# FlynnCore.xcframework inside the FlynnKit package, and copies the generated
# Swift bindings into FlynnKit.
#
#   scripts/build-xcframework.sh [debug|release]   (default: debug)
source "$(dirname "$0")/env.sh"

PROFILE="${1:-debug}"
case "$PROFILE" in
    debug) CARGO_PROFILE=() ;;
    release) CARGO_PROFILE=(--release) ;;
    *) echo "usage: $0 [debug|release]" >&2; exit 2 ;;
esac

TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim)
export IPHONEOS_DEPLOYMENT_TARGET=17.0

for target in "${TARGETS[@]}"; do
    step "Building flynn-ffi for $target ($PROFILE)"
    cargo build --manifest-path "$CORE/Cargo.toml" -p flynn-ffi --lib --target "$target" ${CARGO_PROFILE[@]+"${CARGO_PROFILE[@]}"}
done

"$(dirname "$0")/gen-bindings.sh"

step "Packaging FlynnCore.xcframework"
HEADERS="$BUILD/xcframework-headers"
rm -rf "$HEADERS"
mkdir -p "$HEADERS"
cp "$BUILD/bindings/swift/flynn_ffiFFI.h" "$HEADERS/"
# Xcode looks for module.modulemap inside an XCFramework's headers.
cp "$BUILD/bindings/swift/flynn_ffiFFI.modulemap" "$HEADERS/module.modulemap"

XCFRAMEWORK="$FLYNNKIT/FlynnCore.xcframework"
rm -rf "$XCFRAMEWORK"
args=()
for target in "${TARGETS[@]}"; do
    args+=(-library "$CORE/target/$target/$PROFILE/libflynn_ffi.a" -headers "$HEADERS")
done
xcodebuild -create-xcframework "${args[@]}" -output "$XCFRAMEWORK" >/dev/null

step "Copying Swift bindings into FlynnKit"
GENERATED="$FLYNNKIT/Sources/FlynnKit/Generated"
mkdir -p "$GENERATED"
cp "$BUILD/bindings/swift/flynn_ffi.swift" "$GENERATED/"

echo "FlynnCore.xcframework ready at ${XCFRAMEWORK#$ROOT/}"
