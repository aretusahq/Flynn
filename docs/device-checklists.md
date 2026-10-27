# Device checklists

Steps only the human can run: signing, installing on hardware, supervision,
long soaks. Claude adds a section per milestone; record results in
[spike-results.md](spike-results.md).

## M0 — Foundations

- [ ] Apple Developer Program membership active (paid; an individual account is fine for personal use). Network Extensions need it.
- [ ] Xcode signed in to that account: Xcode > Settings > Accounts. (Until then
      this Mac has no signing identities and nothing can be signed.)
- [ ] Find your 10-character Team ID: developer.apple.com > Account > Membership
      details, or Xcode > Settings > Accounts > the team.
- [ ] Copy `apple/Config/Signing.local.xcconfig.example` to `Signing.local.xcconfig`
      (same folder) and set `DEVELOPMENT_TEAM` to the Team ID. The file is git-ignored.
- [ ] iPhone: plug it in, unlock it and tap **Trust**. Turn on **Developer Mode**
      (Settings > Privacy & Security > Developer Mode; it restarts the phone).
      `xcrun devicectl list devices` should then show it as `connected`
      rather than `unavailable`.
- [ ] Install: `scripts/device-install.sh "<device name>"`. It builds, signs with
      automatic provisioning (Xcode registers the four bundle IDs
      `io.aretusa.flynn`, `.tunnel`, `.filter-data`, `.filter-control`, the App
      Group `group.io.aretusa.flynn` and the Network Extension capability),
      installs and launches. If iOS says the developer is not trusted, open
      Settings > General > VPN & Device Management and trust it.
- [ ] The home screen shows the core version and a shared-container path (not
      "App Group unavailable"). If provisioning is refused, send me the error.
- [ ] Same on the iPad.

## Free-team test build (no paid Apple membership needed)

A free Apple team cannot use Network Extensions, so the full app cannot be
signed with it. The `FlynnFree` target is the same app without the tunnel:
the same Rust core and screens, no extensions, bundle ID
`io.aretusa.flynn.freetest`. It shows an on-device self-test of the core
(QUIC crypto, parsers, file writes, memory sampler, a UDP flow through the
forwarder) and captures nothing.

- [ ] `scripts/device-install.sh "<device name>" free` builds, signs, installs
      and launches it, then reads the self-test report back.
- [ ] The first launch is refused until you trust the developer on the phone:
      Settings > General > VPN & Device Management > your Apple ID > Trust.
      Then run the same command again, or open the app.
- [ ] Free provisioning limits: the app stops launching after seven days (run
      the command again to reinstall) and a device holds up to three such apps.
- [ ] The report is `build/device-selftest.txt`; the app also shows it on screen.
      Every line should say PASS.

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

Needs the M0 signing steps done and the app installed with
`scripts/device-install.sh "<device name>"`. The app opens on the debug screen.

**First start**
- [ ] Tap **Start** and allow the VPN configuration. Status reaches **On**.
- [ ] Browse in Safari for a minute. Events appear within a couple of
      seconds; most TLS flows get a name ("Named … from TLS server name").
- [ ] Note whether any flows are named **from DNS**. If none are, DNS isn't
      passing through the tunnel with the default settings. Then try
      **Virtual DNS resolver** with your router's IP as upstream, save,
      stop, start, and check again.

**Blocking**
- [ ] In **Rules**, type `block subdomains example.com` and `block domain
      example.com`, tap **Save and apply rules** with the tunnel running, and
      open https://example.com. It should fail at once, no restart, with a
      "Blocked … (rule 1 or 2)" event.
- [ ] Remove the lines, apply again, and check it loads.
- [ ] Set mode **Block all**, then try Safari and a push (send yourself an
      iMessage). Note what still works (essentials) and what breaks.
- [ ] Set mode **Lockdown**: an open page should stop loading. Flip **Panic**:
      traffic returns immediately.

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
- [ ] Pull the spool straight off the phone, with no AirDrop:
      `scripts/device-pull-spool.sh "<device name>" 500` copies it into
      `build/device-spool/` and prints the newest events, memory samples
      included. (The **Export spool** button on the debug screen is the
      fallback.) Tell me it is there and I can read it.

Record everything in [spike-results.md](spike-results.md) under M2.
