# Device checklists

Steps only the human can run: signing, installing on hardware, supervision,
long soaks. Claude adds a section per milestone; record results in
[spike-results.md](spike-results.md).

## M0 — Foundations

- [ ] Apple Developer Program membership active (individual is fine for personal use).
- [ ] Copy `apple/Config/Signing.local.xcconfig.example` to `Signing.local.xcconfig` and set `DEVELOPMENT_TEAM`.
- [ ] In Xcode, with automatic signing, let it register the four bundle IDs:
      `com.kasunben.flynn`, `.tunnel`, `.filter-data`, `.filter-control`,
      the App Group `group.com.kasunben.flynn`, and the Network Extension
      capability (packet tunnel and content filter).
- [ ] Build and run the Flynn scheme on the iPhone. The home screen shows the core version and a shared-container path (not "App Group unavailable").
- [ ] Same on the iPad.
