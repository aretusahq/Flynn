#!/usr/bin/env bash
# Builds Flynn for a connected iPhone or iPad, installs it and launches it.
#
#   scripts/device-install.sh "La Sirena"            the full app (needs a paid team)
#   scripts/device-install.sh "La Sirena" free       the free-team test build:
#       no tunnel, no extensions, bundle ID <prefix>.freetest. Installs with a
#       free Apple ID; it stops launching after seven days and is reinstalled.
#       After launching it reads the on-device self-test report back.
#
# Needs a signing team: put DEVELOPMENT_TEAM in apple/Config/Signing.local.xcconfig
# (copy Signing.local.xcconfig.example) and be signed in to the developer account
# in Xcode (Settings > Accounts). With -allowProvisioningUpdates Xcode then
# registers the four bundle IDs, the App Group and the Network Extension
# capability itself. The device must be unlocked, trusted and in Developer Mode.
source "$(dirname "$0")/env.sh"

DEVICE="${1:-}"
VARIANT="${2:-full}"
if [ -z "$DEVICE" ] || { [ "$VARIANT" != "full" ] && [ "$VARIANT" != "free" ]; }; then
    echo "usage: scripts/device-install.sh <device name> [free]" >&2
    echo >&2
    xcrun devicectl list devices >&2
    exit 2
fi

SIGNING="$ROOT/apple/Config/Signing.local.xcconfig"
if [ ! -f "$SIGNING" ]; then
    echo "error: $SIGNING is missing." >&2
    echo "Copy Signing.local.xcconfig.example next to it and set DEVELOPMENT_TEAM to your Team ID." >&2
    exit 1
fi
TEAM="$(sed -n 's/^DEVELOPMENT_TEAM *= *\([A-Z0-9]*\).*/\1/p' "$SIGNING" | head -1)"
if [ "${#TEAM}" -ne 10 ] || [ "$TEAM" = "ABCDE12345" ]; then
    echo "error: DEVELOPMENT_TEAM in $SIGNING is not a real 10-character Team ID." >&2
    exit 1
fi

BUNDLE_ID="$(sed -n 's/^FLYNN_BUNDLE_PREFIX *= *//p' "$ROOT/apple/Config/Base.xcconfig" | head -1)"
SCHEME=Flynn
PRODUCT=Flynn
if [ "$VARIANT" = "free" ]; then
    SCHEME=FlynnFree
    PRODUCT=FlynnFree
    BUNDLE_ID="$BUNDLE_ID.freetest"
fi
APP="$BUILD/DerivedData/Build/Products/Debug-iphoneos/$PRODUCT.app"

"$ROOT/scripts/build-xcframework.sh" debug

step "Generate Xcode project"
(cd "$ROOT/apple" && xcodegen --quiet)

step "Build and sign for $DEVICE (team $TEAM)"
xcodebuild build -quiet -project "$ROOT/apple/Flynn.xcodeproj" -scheme "$SCHEME" \
    -destination "platform=iOS,name=$DEVICE" -derivedDataPath "$BUILD/DerivedData" \
    -allowProvisioningUpdates

step "Install on $DEVICE"
xcrun devicectl device install app --device "$DEVICE" "$APP"

step "Launch $BUNDLE_ID"
xcrun devicectl device process launch --device "$DEVICE" --terminate-existing "$BUNDLE_ID"

if [ "$VARIANT" = "free" ]; then
    step "Reading the on-device self-test report"
    sleep 6
    REPORT="$BUILD/device-selftest.txt"
    rm -f "$REPORT"
    if xcrun devicectl device copy from --device "$DEVICE" \
        --domain-type appDataContainer --domain-identifier "$BUNDLE_ID" \
        --source Documents/selftest.txt --destination "$REPORT" >/dev/null 2>&1 && [ -f "$REPORT" ]; then
        cat "$REPORT"
    else
        echo "Could not read the report yet. Open the app on the phone, then run:" >&2
        echo "  xcrun devicectl device copy from --device \"$DEVICE\" --domain-type appDataContainer --domain-identifier $BUNDLE_ID --source Documents/selftest.txt --destination -" >&2
    fi
    echo
    echo "Flynn (free test) is installed on $DEVICE. It has no tunnel: that needs a paid Apple team."
    exit 0
fi

cat <<EOF

Flynn is running on $DEVICE. Tap Start on its screen and allow the VPN
configuration when iOS asks. To read the event spool from the device:

    scripts/device-pull-spool.sh "$DEVICE"
EOF
