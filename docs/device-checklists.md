# Device checklists

Steps only the human can run: signing, installing on hardware, supervision,
long soaks. Claude adds a section per milestone; record results in
[spike-results.md](spike-results.md).

## M0 — Foundations

- [ ] Apple Developer Program membership active (individual is fine for personal use).
- [ ] Copy `apple/Config/Signing.local.xcconfig.example` to `Signing.local.xcconfig` and set `DEVELOPMENT_TEAM`.
- [ ] In Xcode, with automatic signing, let it register the four bundle IDs:
      `io.aretusa.flynn`, `.tunnel`, `.filter-data`, `.filter-control`,
      the App Group `group.io.aretusa.flynn`, and the Network Extension
      capability (packet tunnel and content filter).
- [ ] Build and run the Flynn scheme on the iPhone. The home screen shows the core version and a shared-container path (not "App Group unavailable").
- [ ] Same on the iPad.

## M1 — Forwarder on the Mac (needs sudo)

Build once:

    cd core && cargo build --release -p flynn-harness

The harness creates a utun interface and routes traffic into it. Quitting,
or a crash, destroys the interface and its routes, so the network comes back
on its own.

- [ ] **Narrow first:** route one address and check it works.
      `sudo target/release/flynn-harness live --route 1.1.1.1/32 --events`, then
      in another terminal run `curl -sI https://1.1.1.1`. Expect an `open` line
      (no name, since curl sends no server name for a bare address) and a
      `close … (normal)` line with byte counts.
- [ ] **Everything:** `sudo target/release/flynn-harness live --all`, then use
      the Mac normally for 30 minutes: browse, stream a video, a video call if
      you can. Note anything that breaks.
- [ ] **Blocking:** `sudo target/release/flynn-harness live --all --block example.com --events`
      and open https://example.com. It should fail to load, with an `[BLOCK]`
      or `(blocked)` line.
- [ ] **Buffer sizes:** repeat a large download (for example a speed test) with
      `--recv-buffer 16 --send-buffer 32` (the default) and with
      `--recv-buffer 64 --send-buffer 128`, and note the throughput and
      footprint for each.
- [ ] Paste each run's summary block into [spike-results.md](spike-results.md).

Known gaps, so they aren't reported as bugs: ping (ICMP) is not relayed yet;
QUIC flows are named from DNS only; a ClientHello split across several TLS
records (not just several TCP segments) is logged without a name.
