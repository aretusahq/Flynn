# Flynn — MVP development plan

Oct 19, 2026 · Companion to [Flynn-plan.md](Flynn-plan.md). Keep the two in step: a decision changed in one is changed in the other.

## Context

`docs/Flynn-plan.md` (12 Oct 2026) is the product plan: a local-first network monitor and firewall, iOS/iPadOS first, built on a shared Rust core. This plan turns it into an order of work that Claude Code can carry out end to end, with the human planning and handling the steps that need hardware or an Apple account.

**Settled inputs**
- Platform order: iOS/iPadOS MVP first, then Android, then desktop (doc).
- Core: Rust with UniFFI bindings, native SwiftUI UI (doc's recommendation, taken as decided).
- Licence: MPL-2.0 (doc's proposal; confirm before the first commit).
- Release target: **personal use only**. A paid Apple Developer Program membership as an individual is enough (Network Extension needs it). Guideline 5.4, organisation enrolment and App Review are off the critical path.
- Minimum OS: **iOS/iPadOS 17**, so the 50 MiB extension budget applies (still treat ~12 MiB as the design target, per the iOS 17 report in the doc).
- Hardware: **iPhone = unsupervised** (packet tunnel level), **iPad = supervised** with Apple Configurator (content filter and per-app level).
- Builder: Claude Code writes all code. The human runs anything that needs a device, signing, sudo or a wipe.

**Hard constraint that shapes everything:** Network Extensions do not run in the iOS Simulator. So the core must be testable on the Mac host (unit, property and fuzz tests, pcap replay, a `utun` harness), and the app must have a mock capture source so the UI can be built and checked in the Simulator. Real-device checks become short checklists the human runs at the end of each milestone.

## Fixes applied to Flynn-plan.md (19 Oct)

Inconsistencies found in review, now fixed in Flynn-plan.md. **iOS goes first.** Wherever the product doc said otherwise, it was changed:
1. "Android goes first because it is the only platform where every stated requirement is already proven" (MVP scope) contradicts the decision. Replace it with "iOS goes first because a core that fits inside an iOS extension runs anywhere; Android follows on the same core." Check the Summary, Roadmap and Left-out sections for the same mismatch.
2. MVP check "Store review: Play Console declaration accepted" is an Android check. Replace with "installs and runs from a development-signed build on both devices" (personal use).
3. MVP check "Privacy … except user-enabled list updates" conflicts with "the MVP makes no outside connections." Make it "makes no network requests of its own."
4. "Twenty MVP features" in Open decisions should say 24.
5. Open decision "Paid model" contradicts "nothing in it is sold." Close it or narrow it to "which add-ons need a user-pasted key."
6. Connection detail (MVP) shows ASN and country from bundled lists, but GeoLite2 can't be bundled and Tracker Radar is noncommercial. Name replacement sources (see M5) before the store design hardens.
7. "Always-on lockdown" is MVP but Unverified on iOS. Mark it as a spike item (`includeAllNetworks` plus on-demand rules).
8. Tick the open decisions this plan settles: audience (personal), core (Rust), devices (iPad supervised, iPhone not), platform order (iOS → Android → desktop).
9. Add a short "Codebase layout" note under Architecture and stack, pointing at the Android-ready rules below, so the product doc records the portability commitment.

## Repository layout

```
Flynn/
  docs/                    Flynn-plan.md, spike-results.md, device-checklists.md
  core/                    Cargo workspace
    flynn-types/           platform-neutral shared types: AppId, Platform, Capabilities, GapReason
    flynn-proto/           packet, DNS, TLS ClientHello/SNI, QUIC-initial parsers (no alloc on hot path)
    flynn-rules/           rule model, wildcard-domain trie, CIDR/port matchers, modes, compiled snapshot format
    flynn-dataplane/       flow table, DNS→IP name cache, verdicts, smoltcp TCP/UDP forwarder, event spool writer
    flynn-store/           app side: SQLCipher DB, ingest from spool, raw + rollup tables, retention, query/filter
    flynn-enrich/          bundled tracker/company/ASN/country lookup (compact binary tables)
    flynn-ffi/             UniFFI interface: two facades, DataPlane (extension) and Library (app)
    flynn-harness/         macOS CLI: pcap replay, utun live run (sudo), throughput/memory measurement
    fuzz/                  cargo-fuzz targets for each parser (from M1)
    fixtures/              pcaps + expected verdict/event files, shared by every platform's tests
  android/                 reserved for Phase 2 (README only in the MVP: Gradle + Kotlin VpnService plan)
  apple/
    project.yml            XcodeGen spec (text, editable by Claude; no hand-edited pbxproj)
    Flynn/                 SwiftUI app (iOS + iPadOS)
    FlynnTunnel/           NEPacketTunnelProvider extension
    FlynnFilterData/       NEFilterDataProvider extension
    FlynnFilterControl/    NEFilterControlProvider extension
    FlynnKit/              local Swift package: FlynnCore.xcframework (binary target), generated bindings,
                           shared host code (App Group paths, IPC, Keychain); every target links it statically
    Config/                Base.xcconfig (bundle prefix, App Group), Signing.local.xcconfig (git-ignored Team ID)
  scripts/                 bootstrap.sh, build-xcframework.sh, gen-bindings.sh, check.sh
  data/                    source lists + build step that compiles them into the bundled tables
  LICENSE                  MPL-2.0
```

## Android-ready by construction

iOS ships first, but the codebase is set up so Android is a new capture shell and a new UI, not a port of the core. Rules enforced from M0:

- **No Apple types in `core/`.** Every crate builds for `aarch64-apple-ios` and also for `aarch64-linux-android` (`cargo check` now; `cargo-ndk` and the NDK once a crate has C dependencies, from M5's SQLCipher). `scripts/check.sh` compiles the Android target from M0 on, so portability breaks fail the build at once rather than in Phase 2.
- **Platform differences sit behind small Rust traits** in `flynn-dataplane`, each implemented by the host through UniFFI callback interfaces:
  - `PacketIo`: read/write raw IP packets (iOS `NEPacketTunnelFlow`; Android the TUN fd).
  - `SocketProtector`: called on every outbound socket before connect. A no-op on iOS; Android's `VpnService.protect()`, without which the forwarder loops its own traffic.
  - `AppResolver`: flow → app identity. iOS fills it from the content filter's `sourceAppIdentifier`, or leaves it empty at tunnel level. Android uses `ConnectivityManager.getConnectionOwnerUid` → package name.
  - `Clock`, `Paths` (App Group container on iOS, app files dir on Android), `Notifier`.
- **`AppId` is platform-neutral:** `{platform, id, display_name}`, where id is a bundle ID or a package name. Rules, store schema and exports use it, never a raw bundle ID.
- **Formats are platform-neutral and versioned:** the event spool records, the rule snapshot and the DB schema are byte-for-byte the same on both platforms, so Android reuses the ingest, retention and explorer code unchanged.
- **Logic lives in the core, not the UI.** Explorer queries, filter parsing, rule validation and compilation, gap-log wording keys, coverage-table state and level/capability flags are core APIs. SwiftUI (and later Compose) only renders. Capability flags (`per_app_available`, `can_pause_flow`, `leak_detection_scope`) come from the core plus the host, so the UI never branches on "is iOS."
- **Gap-log and capability reasons are codes** (e.g. `NotSupervised`, `OsExempt::VoLTE`) with localisable text, so Android adds its own reasons (`NoUsageAccess`, `OtherVpnActive`) to the same enum.
- **UniFFI emits Kotlin alongside Swift** in `gen-bindings.sh` from M0. Nothing consumes it yet, but the bindings must generate cleanly.
- **Shared fixtures:** `core/fixtures` pcaps and expected outputs are the conformance suite each platform's capture shell must pass.

## Architecture decisions to carry into code

- **Two-sided core, as the doc says.** `flynn-dataplane` + `flynn-rules` + `flynn-proto` link into the extensions and hold nothing that grows with traffic. `flynn-store` + `flynn-enrich` link only into the app.
- **Extension → app: append-only event spool** in the App Group container: fixed-size binary records, rotated segments, ingested and deleted by the app. File protection `CompleteUntilFirstUserAuthentication`, since the tunnel runs while the device is locked. Segments are encrypted with a key from the shared Keychain access group. The extension never opens SQLite.
- **App → extension: compiled rule snapshot.** The app compiles rules into one immutable binary file, writes it atomically, then calls `sendProviderMessage("reload")`. The extension swaps snapshots with no restart, which meets the "no tunnel restart" check.
- **Modes in the rule engine:** allow-all, block-all + essentials, lockdown (block-all, essentials off), and panic. Panic is a flag in the snapshot header that overrides everything to allow, set in one tap from the app or a widget.
- **Names for flows:** DNS answers seen in the tunnel feed an IP→name cache, and TLS SNI and the QUIC Initial override it. When neither is seen, the flow is an "unknown destination" with ASN/company, never hidden.
- **Level detection:** at launch, try to save an `NEFilterManager` configuration. Success means supervised level, and the failure code means tunnel level. The spike confirms the codes. The result is written to the gap log with its reason.
- **Two-tier retention from the first schema:** raw connections (default 7 days) plus hourly/daily rollups per app/domain (default 13 months). The home screen reads rollups only.
- **Build plumbing:** `cargo build` for `aarch64-apple-ios`, `aarch64-apple-ios-sim` and the macOS host, then `uniffi-bindgen` for Swift, then an XCFramework consumed by FlynnKit. `scripts/check.sh` runs `cargo test`, clippy, the fuzz smoke runs, `xcodegen` and `xcodebuild test` on the Simulator.

## Milestones

Each one ends with its exit criteria. "Human:" marks steps Claude can't do.

### M0 — Foundations (code done 19 Oct; device steps pending)
- Initialise git, add the MPL-2.0 licence and a README with the coverage statement.
- Scaffold the Cargo workspace, the XcodeGen project with the app and three extensions, the App Group, the shared Keychain group, and the build scripts.
- **Human:** enrol in the Apple Developer Program, register bundle IDs, the App Group and Network Extension capabilities (packet-tunnel-provider, content-filter-provider), and give Claude the Team ID. Steps are in `docs/device-checklists.md`.
- Exit: `scripts/check.sh` passes (including the core compiling for `aarch64-linux-android` and Kotlin bindings generating), and the empty app plus extensions build for a device.

### M1 — Spike A: forwarder on the host (highest risk in the build) (code done 19 Oct; live run pending)
- `flynn-proto` parsers for IPv4/IPv6/TCP/UDP/DNS/SNI, with fuzz targets.
- `flynn-dataplane` forwarder: smoltcp terminates TCP locally and opens matching outbound sockets. UDP is relayed with flow timeouts. DNS is intercepted and logged.
- `flynn-harness`: pcap replay to check the parsers and flow accounting, plus a live `utun` mode that routes the Mac's traffic through the forwarder.
- **Human:** run the harness live with sudo and browse normally for 30 minutes.
- Exit: pages load, video streams, and throughput, CPU and RSS are recorded in `docs/spike-results.md`.

### M2 — Spike B: packet tunnel on the iPhone (unsupervised) (code done 19 Oct; device runs pending)
- A minimal tunnel extension around the M1 data plane, logging domain, IP, port and bytes to the spool, and a debug screen in the app that tails it.
- Measure: peak and steady memory in the extension (`task_vm_info` sampled to the spool), battery over 24 hours, and throughput against Flynn off.
- Try out: notifications posted from the extension, `includeAllNetworks` + `enforceRoutes`, on-demand rules restarting the tunnel after reboot or kill, and whether the device receives any unsolicited inbound traffic.
- **Human:** install via Xcode/`devicectl`, run the device checklist and the 24-hour soak.
- Exit: the tunnel holds for 24 hours under ~12 MiB steady, and the figures are written down.

### M3 — Spike C: content filter on the iPad (supervised)
- **Human:** supervise the iPad with Apple Configurator ("Do not enroll", which wipes it).
- Filter data and control providers: confirm `sourceAppIdentifier` per flow, how flow records get out of the data provider's sandbox (`needRules` → control provider, or filter reports), and drop/allow per app.
- Confirm the level-detection failure codes on the iPhone against success on the iPad.
- Experiment: tunnel and filter running together on the iPad (attribution plus packet detail), measuring the memory of both.
- Look at the App Privacy Report export format as a per-app fallback on the iPhone.
- **Gate:** write go/no-go results to `docs/spike-results.md` and update Flynn-plan.md's feasibility labels. The human decides whether the combined mode is in scope.

### M4 — Core data plane, production quality
- `flynn-rules`: rules by app, domain (exact and `*.` wildcard), host, IP/CIDR and port. Precedence is block over allow, specific over general, then mode default. A versioned snapshot format, property tests for precedence, and a bundled essentials list (Apple push, captive portal, time, OCSP).
- Flow table with an LRU cap, coalescing of repeated connections (one row + a counter, a lever from the doc), and batched spool writes.
- Hot rule reload through the provider message.
- ~~QUIC Initial decryption to read the server name.~~ Done 20 Oct, pulled
  forward after the M1 live run (QUIC was 39 of 46 unnamed flows, and it let
  Safari past a name block): RFC 9001/9369 Initial keys, reassembly across
  datagrams, datagrams held until named, and an optional force-TCP fallback
  for QUIC whose name cannot be read.
- Exit: rule-evaluation property tests pass, the parser fuzzers run clean for N minutes, and replaying a fixed pcap gives the same verdicts as a checked-in expected file.

### M5 — Store, enrichment, detection
- `flynn-store`: SQLCipher DB with its key in the Keychain, spool ingestion, raw and rollup tables, a retention job, and an explorer query API (filter, group, sort by app, domain, destination and time).
- `flynn-enrich`: compact bundled tables built in `data/`. **Human decision on sources:** recommended are iptoasn.com (public domain) for ASN and country, and a tracker/company list whose licence allows redistribution. Tracker Radar and GeoLite2 are ruled out, as the doc says.
- Detection: tracker/ad tagging with company names, first-seen app and destination flags, per-day data usage per app and domain.
- Gap log: network path changes (`NWPathMonitor`), captive portal state, level/supervision reason, tunnel down/up, and "not visible" layers. Each entry says what happened, why Flynn couldn't see it, and what would.
- Exit: store tests on the host and in the Simulator, and a day of synthetic traffic stays inside the storage budget with default retention.

### M6 — iOS app UI (built against a mock source in the Simulator)
- `CaptureSource` protocol with two implementations: the real one (spool + provider messages) and a mock that replays recorded sessions, so the Simulator shows live data.
- Screens: onboarding and consent/disclosure; Home (level badge, mode, panic, today's rollups, coverage table); Live; Explorer; Connection detail with block/allow from the row; Rules editor; Gap log; Alerts; Settings (retention, essentials, reset). iPad gets a split view.
- Unblockable items show the reason and the system setting, never a dead Block button.
- Exit: Simulator UI tests cover the explorer check ("find a known connection by filter, open it, block it"), and Claude checks the screens with Simulator screenshots.

### M7 — Supervised level and per-app features
- Hook the filter providers to the core. Per-app rules, attribution and usage show up only when the level is supervised, and on the iPhone the gap log says why they don't.
- A minimal "how to supervise" explainer that states the wipe plainly (the full guided setup stays v1).
- **Human:** run the attribution check on the iPad: 10 common apps in turn, and every connection names the right app.

### M8 — Leak detection, lockdown, resilience
- Leak detection: device-wide interface counters (`getifaddrs`) compared with tunnel byte counts, a calibrated baseline and a threshold flag. Device-wide only on iOS, as the doc says.
- Full lockdown and always-on lockdown, using whatever M2 proved about `includeAllNetworks` and on-demand rules.
- Alerts for blocked connections and new destinations, by whatever route M2 proved.
- Exit: lockdown logs every attempt while nothing gets out, and the panic button restores traffic in one tap.

### M9 — MVP acceptance
- Run the doc's "checks for done", adjusted for iOS and personal use: attribution (iPad), rules without restart, block-all safety, 24-hour stability and battery, explorer, privacy (no outbound requests of Flynn's own, checked with the harness or a proxy log), storage, and performance against the Flynn-off baseline.
- Write the results to `docs/spike-results.md`, then plan Phase 2.

### Phase 2 preview — Android (not in the MVP; shows the fit)
- `android/`: Kotlin VpnService that implements `PacketIo`, `SocketProtector` and `AppResolver` over the same `flynn-ffi`, plus a Compose UI over the same Library facade.
- What the core already provides: the parsers, forwarder, rules, spool, store, enrichment, explorer queries and fixtures. What's new: the capture shell, the UI, usage-access leak counters, the always-on VPN prompt, and the Play/F-Droid build split.

## Verification approach

- **On the host (Claude, every change):** `scripts/check.sh` runs Rust unit, property and fuzz-smoke tests, pcap replay against the expected verdicts, clippy, the XcodeGen build and Simulator unit/UI tests.
- **Simulator (Claude):** the app runs on the mock capture source, with UI tests and screenshots through the iOS Simulator tool.
- **Mac live (human with sudo):** the `flynn-harness` utun run, for forwarder correctness and throughput.
- **Devices (human):** `docs/device-checklists.md`, one short checklist per milestone (install, toggle, browse X, confirm Y, read the memory/battery figures). Claude adds the steps and reads back the logged results from the spool export.
