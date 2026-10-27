# Spike results

Measured findings from M1–M3 and the MVP checks. Each entry: date, device,
OS version, build, what was measured, the figure, and what it decides.

## M1 — Forwarder on the host

### 19 Oct 2026 · in-memory rig · macOS 26, Apple Silicon · release build

`cargo test --release -p flynn-dataplane --test forwarder`: a second smoltcp
stack plays the app, servers on 127.0.0.1 stand in for the internet.

- 1 MiB echoed through the forwarder in about 19 ms over 5 runs: roughly
  55 MB/s (440 Mb/s) each way at once, with 16 KiB receive and 32 KiB send
  buffers per connection. A floor rather than a ceiling, since the rig also
  runs the app's TCP stack and sleeps 200 µs between polls.
- Correct behaviour confirmed: clean FIN close with exact byte counts; a
  refused server reaches the app as a reset with no fake handshake; a
  two-segment ClientHello is reassembled and its server name blocked; DNS
  answers name later connections; lockdown blocks at open.

### 19 Oct 2026 · live utun, one route · MacBook (Wi-Fi en0, IPv4 only) · release build

Step 1 of the live run: only 1.1.1.1/32 routed into utun6.

- `curl -sI https://1.1.1.1`: relayed and closed normally (567 B up,
  2791 B down). No name, as expected: curl sends no SNI for a bare address.
- `curl -sI --resolve one.one.one.one:443:1.1.1.1 https://one.one.one.one`:
  `HTTP/2 200` through the forwarder; the flow was named `one.one.one.one`
  from the ClientHello; closed normally (597 B up, 3619 B down).
- Outbound sockets pinned to en0 with IP_BOUND_IF did not loop back into
  the tunnel.
- 4 non-TCP/UDP packets dropped before any test traffic: macOS's own
  housekeeping on the new interface.
- Harness footprint 1.6 MiB, CPU about 0.1% of one core when idle.
- Found and fixed: the summary counted a flow named late by SNI as both
  unnamed and SNI-named. Each flow now counts once, by its final name source.

### 19 Oct 2026 · live utun, all traffic, first attempt · same Mac

Step 2 with `--all` (routes 0.0.0.0/1 and 128.0.0.0/1): every one of 2,370
flows failed to connect within a millisecond; nothing was relayed. The
forwarder behaved correctly (each refusal reached the app as a reset), but
its own outbound sockets could not leave.

Cause: the Mac had no default route scoped to en0, only the global one. A
socket pinned with IP_BOUND_IF then falls back to the default route, which
macOS finds by looking up 0.0.0.0, and 0.0.0.0/1 captured that lookup, so
every pinned socket resolved to the utun and failed. Step 1's 1.1.1.1/32
route did not cover 0.0.0.0, which is why it worked.

Fix: `--all` now routes 1.0.0.0/8 … 128.0.0.0/1 (all of IPv4 except
0.0.0.0/8), and IPv6 as 2000::/3. Live mode also checks at start that a
pinned socket reaches 1.1.1.1:443 and stops if it cannot.

Bearing on iOS: none expected. Network Extension sockets bypass their own
tunnel without IP_BOUND_IF, but the virtual-DNS and include-all-networks
experiments in M2 should keep this failure mode in mind.

### 19 Oct 2026 · live utun, all traffic · same Mac · default buffers (16/32 KiB)

Step 2 rerun with the fixed routes: 520 s of normal use (browsing, Instagram,
a large download).

| Measure | Result |
| --- | --- |
| Flows | 94 opened, 0 connect failures, 0 blocked |
| Relayed | 0.8 MB up, 255.6 MB down |
| Peak, 5 s window | 241.9 Mb/s down, on one TCP flow (236 MB from proton.me) |
| CPU | 2.4 s total, 0.5% of a core on average; about 20% of a core at the 240 Mb/s peak |
| Footprint | 4.1 MiB peak for the whole harness process, flat once flows settled |
| Closes | 15 normal, 23 reset, 42 idle (UDP) |
| Packets | 18,941 in, 183,029 out, 4 dropped (macOS housekeeping) |

Naming, from the spool:

- 48 of 94 flows named from the TLS server name.
- 46 unnamed: 39 are QUIC (UDP 443), 3 NTP, 2 DNS, 1 plain HTTP, and 1 TLS
  flow without a name.
- Only 2 DNS queries crossed the tunnel. The Mac's first resolver,
  192.168.50.10, is on the LAN, and the LAN route is more specific than the
  tunnel's, so most lookups never reached Flynn. The two that did (to the
  1.1.1.1 fallback) were decoded and cached correctly.
- The 23 resets were all TCP flows to browsing sites (Instagram CDN, Google,
  gallery sites). **Correction, 27 Oct:** the forwarder was reporting a
  clean close that the *server* started as a reset (found in step 4, fixed),
  so some of these 23 were ordinary closes and the count overstates real
  resets. Read it as unreliable.

What it decides:

- The forwarder carries real traffic at well over 200 Mb/s on default buffers
  at modest CPU. The iPhone figure is still to measure in M2.
- Reading the QUIC server name moves up in M4: QUIC is most of what is
  unnamed now.
- DNS visibility depends on where the resolver sits. On iOS the M2 checklist
  already tests the virtual-resolver switch; also test routing a LAN
  resolver's address into the tunnel, or include-all-networks.

### 20 Oct 2026 · live utun, blocking · same Mac

Step 3: `--all --block example.com`, then https://example.com in Safari.
**The page loaded: the block did not apply.**

- No flow named example.com appeared. Safari reached it over QUIC: flow #3,
  UDP to 172.66.147.243:443, which is example.com's current address.
- That flow had no name. QUIC carries the server name inside an encrypted
  Initial packet, which Flynn cannot read yet, and Safari's DNS lookup went
  to the LAN resolver, outside the tunnel.
- Not iCloud Private Relay: its relays are at 17.248.x; no flow went there.
- In the same 25 s, a 236 MB download peaked at 371.7 Mb/s (5 s window), at
  about 26% of one core, with a 2.2 MiB footprint.

What it decides: blocking by name is unreliable until QUIC flows can be
named. Two fixes, which are complementary:

1. Read the server name from the QUIC Initial (planned for M4).
2. Policy fallback: drop UDP 443 to a destination with no name, so browsers
   fall back to TCP, where the TLS server name is readable. It costs a
   little speed on first connection.

**Fixed 20 Oct:** the forwarder now reads QUIC server names (RFC 9001 v1
and RFC 9369 v2 Initial keys, header protection, AES-128-GCM, CRYPTO frames
reassembled across datagrams and out of order). A new QUIC flow's first
datagrams are held, 300 ms at most, until the name is read, so a block drops
them before any reaches the server. Verified against RFC 9001's test
vectors and against real Initials from Apple's QUIC stack, whose ClientHello
spans two datagrams. Optional `--force-tcp-quic` drops QUIC whose name still
cannot be read, so the browser falls back to TCP. Step 3 to be rerun.

### 21 Oct 2026 · live utun, blocking rerun with QUIC naming · same Mac

`--all --block example.com`, then https://example.com in Safari: **blocked;
the page did not load.**

- Safari tried QUIC first (UDP 443). Flynn read `example.com` from the
  encrypted Initial and closed the flow as blocked, with nothing sent to the
  server. Safari then retried over TCP, twice, and both were blocked by the
  TLS server name. It repeated that about every 5 s: 17 blocked flows in
  56 s, all example.com, and nothing else was blocked.
- QUIC naming on real traffic: 27 of 32 UDP-443 flows named from their
  Initials (iCloud, Apple, Google, claude.ai). Five stayed unnamed: one to
  34.128.128.0 (idle after 1200 B up, 42 B down) and four to 17.248.172.x,
  the range mask.icloud.com resolves to, so probably iCloud Private Relay
  connections. The cause is not known; this run had no `--spool`, so the
  packets were not kept.
- Harness footprint peaked at 3.9 MiB at 60 s, 0.3 s of CPU.
- The `dropped` count rose from 4 to 72 within 66 s, though it stayed at 4
  through all of the 520 s of step 2. The cause is not known. Likely
  candidates are ICMP or IGMP: 128.0.0.0/1 covers the multicast range, so
  the tunnel claims group-membership traffic. The harness summary now splits
  `dropped` by cause (IP protocol, later fragments, malformed), so the next
  run will say.

What it decides: blocking by name now holds for QUIC and TCP on this Mac.
`--force-tcp-quic` was not exercised.

### 27 Oct 2026 · live utun, speed against tunnel-off · same Mac (Wi-Fi, IPv4)

`networkQuality -s` (Apple's speed test with responsiveness), once each: with
no tunnel, through Flynn with the default 16/32 KiB of buffer per
connection (receive/send), and through Flynn with 64/128 KiB.

| | No tunnel | Flynn 16/32 KiB | Flynn 64/128 KiB |
| --- | --- | --- | --- |
| Downlink | 271 Mb/s | 372 Mb/s | 351 Mb/s |
| Uplink | 53.0 Mb/s | test did not run | 47.5 Mb/s |
| Downlink responsiveness | 600 RPM (100 ms) | 604 RPM (99 ms) | 641 RPM (93 ms) |
| Uplink responsiveness | 62 RPM (957 ms) | none | 54 RPM (1.10 s) |
| Idle latency | 40.5 ms | 35.7 ms | 40.9 ms |
| Harness: relayed | n/a | 760.8 MB down, 0.8 MB up, 28 s | 393.9 MB down, 123.4 MB up, 48 s |
| Harness: peak rate | n/a | 405.8 Mb/s down | 334 Mb/s down, 45 Mb/s up |
| Harness: CPU | n/a | 4.6 s, 16.3% of a core | 5.1 s, 10.7% of a core |
| Harness: footprint peak | n/a | 4.2 MiB | 5.6 MiB |
| Flows | n/a | 391: 59 normal, 291 reset, 4 idle | 604: 113 normal, 481 reset |

What it shows:

- **Downlink:** no visible penalty up to about 400 Mb/s. The no-tunnel sample
  was the lowest of the three, so run-to-run variation is as large as any
  difference and this cannot say Flynn is faster or slower. Responsiveness
  and idle latency match.
- **Uplink:** 47.5 Mb/s through Flynn at 64/128 KiB against 53.0 with no
  tunnel, about 10% lower and close to the spread of the baseline's own
  readings (53.0 to 54.3). Uplink responsiveness is poor (about 1 s) both
  ways, which is the uplink's own queueing, not Flynn.
- **Uplink at 16/32 KiB failed, and the cause is not known.** networkQuality
  printed its downlink figures, then ended with "network connection was
  lost" (error 53, ECONNABORTED) on a download connection to
  17.253.14.55:443, and the harness saw only 0.8 MB go up in all, which is
  just ClientHello bytes: the upload phase probably never started. One run
  per setting cannot tell a buffer-size effect from a flake. In the
  in-memory rig, 1 MiB each way at 16/32 KiB works.
- **Connection churn:** during the download phase networkQuality opened
  about 25 new TCP connections a second to mensura.cdn-apple.com. In the
  spool, 346 closed flows lasted 0.1 to 0.35 s (most 0.2 to 0.3 s) and each
  carried exactly the ClientHello (1,937 B up) and the server's first
  flight (about 6.1 KB down) and nothing more: the client abandoned the
  handshake. Run 2 churned the same way (16 to 21 a second) and its upload
  worked, so churn alone is not the failure. It looks like the speed test
  racing connection attempts under load.
- **Memory:** footprint counts only pages actually written (buffers are
  zero-filled lazily): 4.2 MiB with 16/32 KiB and 5.6 MiB with 64/128 KiB at
  about 25 concurrent TCP connections. Both are under the 12 MiB iOS design
  target; iOS has to be measured on the device.
- **Dropped packets:** `dropped by cause` was ICMPv6 3 and ICMP 2 in run 1,
  ICMPv6 3 in run 2: macOS's own IPv6 neighbour discovery on the new
  interface, plus two ICMP packets. The rise to 72 seen in step 3 did not
  recur, so its cause is still unknown.

Bugs this run exposed (fixed in the working tree):

- A clean close started by the *server* was reported as `reset`: the socket
  goes FinWait2 to TimeWait on the app's FIN, before the app's EOF was ever
  noticed, and TimeWait was judged by those EOF flags. Reset counts in steps
  2 and 4 therefore overstate real resets. TimeWait now counts as a normal
  close; a test fails on the old behaviour.
- Ctrl-C never shut the forwarder down: the reader thread held the forwarder
  handle, so the shutdown close events and the final second of spool events
  were lost (38 flows had no close in the spool). The reader now holds only
  a packet pusher. A test checks that `stop()` reports every open flow.
- New in the harness summary: `unclean TCP closes`, split by cause (app
  reset during or after the handshake, server read or write failure, and so
  on), to show who ended connections instead of lumping them as resets.

The rerun below answers the question that was open here.

### 27 Oct 2026 · live utun, 16/32 KiB rerun with the new breakdown · same Mac

One 91 s harness session at the default 16/32 KiB, `--spool`, with
`networkQuality -s` run twice during it.

| | Run 1 | Run 2 |
| --- | --- | --- |
| Downlink | 387 Mb/s | 396 Mb/s |
| Uplink | 64.0 Mb/s | 47.9 Mb/s |
| Downlink responsiveness | 1033 RPM (58 ms) | 628 RPM (95 ms) |
| Uplink responsiveness | 69 RPM (868 ms) | 136 RPM (440 ms) |
| Idle latency | 54.7 ms | 60.3 ms |

Harness: 768.9 MB down and 207.4 MB up; peak 364.8 Mb/s down and
48.3 Mb/s up; 9.4 s of CPU (10.3% of a core); footprint peak 5.2 MiB with
up to 40 concurrent TCP flows. 1,136 flows: 173 normal, 934 reset, 9 idle,
1 connect failure. Three dropped packets, all ICMPv6.

- **The uplink failure did not repeat.** Both runs completed with an
  uplink at 16/32 KiB. Between the failed run and these, only labels,
  counters and shutdown changed; the relay path is the same code, so the
  failure looks intermittent. Its cause is still unknown.
- **Idle latency** was 55 and 60 ms here, against 36 to 41 ms in the earlier
  runs through Flynn and 40.5 ms with no tunnel. That is Wi-Fi variation or
  a real cost, and a single speed test per setting cannot separate them.
  Alternating tunnel-off and tunnel-on `curl` timings would.
- **Throughput** through Flynn: downlink 351 to 396 Mb/s in all four runs
  against one no-tunnel sample of 271; uplink 47.5 to 64.0 Mb/s against
  53.0. No measurable penalty, though one baseline sample is thin.
- **What the 934 resets were**, from the new breakdown:
  - 904 "app finished, then reset while the server was open". The app sent
    a FIN, then reset the server's late reply: the speed test cancelling
    connection attempts at about 250 ms, before the server's first flight
    reached it. Matches the flows that carried only a ClientHello.
  - 15 "app reset an open connection".
  - 13 "app never finished its handshake (timed out)". The app gave up while
    the forwarder was still connecting to the server; an abandoned attempt
    sends nothing, so it then reset our SYN-ACK and the flow sat idle for
    the 10 s timeout, holding a server connection and its buffers.
  - 2 "server read failed: ConnectionReset".

Fixed in the working tree: a flow whose app resets the handshake now ends
at once. A test fails without the fix.

Not confirmed: video streaming and a video call through the tunnel.

## M2 — Packet tunnel on the iPhone

### 27 Oct 2026 · free-team test build on the iPhone (no tunnel)

The tunnel could not be signed: Xcode refuses the Network Extensions
capability for a personal (free) team ("Personal development teams ... do not
support the Network Extensions capability"). The device spike is blocked on a
paid Apple Developer Program team. Meanwhile the `FlynnFree` target (same app
and Rust core, no extensions, no entitlements, bundle ID
`io.aretusa.flynn.freetest`) installs with the free team.

On an iPhone 15 Pro, iOS 26.6.2, built with `scripts/device-install.sh
"La Sirena" free`, all six on-device self-test checks passed:

- QUIC Initial keys and header-protection mask match the RFC 9001 vector.
- Server names read from encrypted QUIC Initials, v1 and v2, with the
  ClientHello split over 3 datagrams (AES-GCM and HKDF run correctly on the
  device's arm64).
- TLS ClientHello and DNS parsing, including a CNAME chain.
- The event spool writes and reads back on the device's filesystem.
- The memory sampler (`task_info`, `phys_footprint`) works on iOS: the app
  process read 12.0 MiB. That is the whole SwiftUI app, not the extension, so
  it says nothing yet about the extension's limit.
- The forwarder relays a UDP datagram out and the reply back over loopback:
  its threads, mio/kqueue and sockets work inside an iOS app.

What this does not show: anything about the tunnel itself, the extension's
memory ceiling, DNS visibility or on-demand restarts. Those need the paid
team. Free provisioning expires the profile after seven days (this one on
3 Nov); the same install command renews it.

The first launch right after trusting the developer was still refused; a
freshly installed build launched. Most likely the trust had not taken effect
yet.

Code is ready (19 Oct). Device results pending; steps are in
[device-checklists.md](device-checklists.md#m2--packet-tunnel-on-the-iphone).
To record: DNS visibility with and without the virtual resolver,
notifications from the extension, on-demand restart after reboot, the effect
of include-all-networks, 24-hour peak footprint and CPU, battery share, and
throughput against tunnel-off.
