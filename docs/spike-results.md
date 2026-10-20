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
  gallery sites). This looks like browsers abandoning pre-opened
  connections, not a forwarder fault, but a packet capture would be needed
  to confirm.

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

Step 4 (speed against tunnel-off) still to run.

## M2 — Packet tunnel on the iPhone

Code is ready (19 Oct). Device results pending; steps are in
[device-checklists.md](device-checklists.md#m2--packet-tunnel-on-the-iphone).
To record: DNS visibility with and without the virtual resolver,
notifications from the extension, on-demand restart after reboot, the effect
of include-all-networks, 24-hour peak footprint and CPU, battery share, and
throughput against tunnel-off.
