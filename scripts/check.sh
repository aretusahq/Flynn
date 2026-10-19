#!/usr/bin/env bash
# Every check that runs without a device. Run before each commit.
#
#   FLYNN_SIM="iPhone 17" scripts/check.sh
source "$(dirname "$0")/env.sh"

SIM="${FLYNN_SIM:-iPhone 17}"
DERIVED="$BUILD/DerivedData"

cd "$CORE"

step "Rust: format"
cargo fmt --all --check

step "Rust: clippy"
cargo clippy --workspace --all-targets --quiet -- -D warnings

step "Rust: tests"
cargo test --workspace --quiet

step "Replay fixture: synthetic-basic"
cargo run --quiet -p flynn-harness -- replay fixtures/synthetic-basic.pcap \
    --block tracker.test --expect fixtures/synthetic-basic.expected.txt >/dev/null

# Deeper than the property tests; needs nightly and cargo-fuzz, so optional.
if cargo +nightly fuzz --version >/dev/null 2>&1; then
    for target in ip dns tls; do
        step "Fuzz: $target (${FLYNN_FUZZ_SECS:-20}s)"
        (cd "$CORE/fuzz" && cargo +nightly fuzz run "$target" -- -max_total_time="${FLYNN_FUZZ_SECS:-20}" >/dev/null 2>&1)
    done
else
    step "Fuzz: skipped (install with: rustup toolchain install nightly && cargo install cargo-fuzz)"
fi

# Android is Phase 2, but the core must keep compiling for it from day one.
step "Rust: compile for Android (aarch64-linux-android)"
# The harness is a macOS tool; everything that ships must build for Android.
cargo check --workspace --exclude flynn-harness --target aarch64-linux-android --quiet

cd "$ROOT"

step "Core XCFramework and bindings (Swift + Kotlin)"
scripts/build-xcframework.sh debug

step "Generate Xcode project"
(cd "$ROOT/apple" && xcodegen --quiet)

step "Swift: FlynnKit tests on $SIM"
xcodebuild test -quiet -project apple/Flynn.xcodeproj -scheme Flynn \
    -destination "platform=iOS Simulator,name=$SIM" -derivedDataPath "$DERIVED"

step "Swift: unsigned device build"
xcodebuild build -quiet -project apple/Flynn.xcodeproj -scheme Flynn \
    -destination 'generic/platform=iOS' -derivedDataPath "$DERIVED" CODE_SIGNING_ALLOWED=NO

step "All checks passed"
