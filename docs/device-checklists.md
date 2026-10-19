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

## M2 — Packet tunnel on the iPhone

Needs the M0 signing steps done (Team ID in `apple/Config/Signing.local.xcconfig`).
Run `scripts/bootstrap.sh`, open `apple/Flynn.xcodeproj`, pick the iPhone and
run the Flynn scheme. The app opens on the debug screen.

**First start**
- [ ] Tap **Start** and allow the VPN configuration. Status reaches **On**.
- [ ] Browse in Safari for a minute. Events appear within a couple of
      seconds; most TLS flows get a name ("Named … from TLS server name").
- [ ] Note whether any flows are named **from DNS**. If none are, DNS isn't
      passing through the tunnel with the default settings. Then try
      **Virtual DNS resolver** with your router's IP as upstream, save,
      stop, start, and check again.

**Blocking**
- [ ] Add `example.com` to blocked domains, **Save to VPN configuration**,
      stop and start the tunnel, open https://example.com. It should fail,
      with a "Closed … (blocked)" event.

**Notifications from the extension**
- [ ] Tap **Send test notification from the extension** (allow
      notifications). Note whether the banner appears.

**Resilience**
- [ ] Turn on **Connect on demand**, save, start. Reboot the phone and note
      whether the tunnel comes back without opening Flynn.
- [ ] Turn on **Include all networks** and **Enforce routes**, save, restart
      the tunnel, and note anything that stops working (AirDrop, CarPlay,
      local devices).

**Measurements**
- [ ] Leave the tunnel on for 24 hours of normal use. Then record from the
      debug screen: extension peak footprint, CPU, relayed totals; and from
      Settings › Battery, Flynn's share (iOS also charges Flynn for traffic it
      relays for other apps).
- [ ] A speed test with the tunnel off, then on (default buffers), then on
      with 64/128 KiB buffers. Record down/up for each.
- [ ] **Export spool** (bottom of the screen), AirDrop it to the Mac, and run
      `core/target/release/flynn-harness spool-tail <folder> 500` on the files' folder, or
      send the folder to Claude.

Record everything in [spike-results.md](spike-results.md) under M2.
