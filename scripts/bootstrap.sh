#!/usr/bin/env bash
# One-time setup, and after pulling changes to core/: installs the Rust
# targets, builds the core XCFramework and bindings, generates the Xcode
# project. Open apple/Flynn.xcodeproj afterwards.
source "$(dirname "$0")/env.sh"

step "Rust targets"
rustup target add aarch64-apple-ios aarch64-apple-ios-sim aarch64-linux-android

command -v xcodegen >/dev/null 2>&1 || { echo "error: xcodegen not found; brew install xcodegen" >&2; exit 1; }

"$ROOT/scripts/build-xcframework.sh" debug

step "Generate Xcode project"
(cd "$ROOT/apple" && xcodegen --quiet)

if [ ! -f "$ROOT/apple/Config/Signing.local.xcconfig" ]; then
    echo
    echo "Note: no apple/Config/Signing.local.xcconfig. Copy the .example next to it and"
    echo "set DEVELOPMENT_TEAM before building for a device."
fi
