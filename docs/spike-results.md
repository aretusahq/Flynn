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

### Live utun run, all traffic

Pending: steps 2 to 4 in [device-checklists.md](device-checklists.md#m1--forwarder-on-the-mac-needs-sudo).
Record throughput against no-tunnel, peak footprint, CPU share, and anything
that broke.

## M2 — Packet tunnel on the iPhone

Code is ready (19 Oct). Device results pending; steps are in
[device-checklists.md](device-checklists.md#m2--packet-tunnel-on-the-iphone).
To record: DNS visibility with and without the virtual resolver,
notifications from the extension, on-demand restart after reboot, the effect
of include-all-networks, 24-hour peak footprint and CPU, battery share, and
throughput against tunnel-off.
