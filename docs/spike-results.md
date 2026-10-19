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

### Live utun run

Pending: needs `sudo`; steps in [device-checklists.md](device-checklists.md#m1--forwarder-on-the-mac-needs-sudo).
Record throughput against no-tunnel, peak footprint, CPU share, and anything
that broke.
