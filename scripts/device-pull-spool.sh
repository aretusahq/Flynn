#!/usr/bin/env bash
# Copies the event spool out of Flynn's App Group on a device and prints the
# newest events, with the memory samples the tunnel extension wrote.
#
#   scripts/device-pull-spool.sh "La Sirena" [count]     (default: 60 events)
#
# The files land in build/device-spool/<timestamp>, so they can be read again
# with:  core/target/release/flynn-harness spool-tail <that folder> 500
source "$(dirname "$0")/env.sh"

DEVICE="${1:-}"
COUNT="${2:-60}"
if [ -z "$DEVICE" ]; then
    echo "usage: scripts/device-pull-spool.sh <device name> [count]" >&2
    exit 2
fi

BUNDLE_ID="$(sed -n 's/^FLYNN_BUNDLE_PREFIX *= *//p' "$ROOT/apple/Config/Base.xcconfig" | head -1)"
OUT="$BUILD/device-spool/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

step "Copying the spool from $DEVICE"
xcrun devicectl device copy from --device "$DEVICE" \
    --domain-type appGroupDataContainer --domain-identifier "group.$BUNDLE_ID" \
    --source spool --destination "$OUT"

# devicectl may or may not add a "spool" folder level; find the segments.
SEGMENT="$(find "$OUT" -name 'spool-*.bin' -print -quit)"
if [ -z "$SEGMENT" ]; then
    echo "error: no spool segments were copied into $OUT. Has the tunnel run yet?" >&2
    exit 1
fi
DIR="$(dirname "$SEGMENT")"
echo "spool copied to ${DIR#$ROOT/}"

step "Newest $COUNT events"
cargo run --quiet --release --manifest-path "$CORE/Cargo.toml" -p flynn-harness -- spool-tail "$DIR" "$COUNT"
