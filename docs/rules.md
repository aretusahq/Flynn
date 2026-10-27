# Flynn rules

How Flynn decides whether a connection may go out. The engine is
`core/flynn-rules`; the forwarder in `flynn-dataplane` asks it at three
moments: when a flow opens, when its server name is learned (or known never
to come), and when the rules change.

## Order of decision

1. **Panic** on: allow everything, even in lockdown.
2. **Lockdown** mode: block everything, essentials and allow rules included.
3. The **most specific matching rule**.
4. The **mode's default**: allow in allow-all, block in block-all (except
   essentials, below).

## Which rule is "most specific"

Compared in this order; the first difference decides.

1. A rule limited to an app beats one that is not.
2. Destination: `any` < `cidr` (a longer prefix beats a shorter one) <
   `subdomains` (a deeper suffix beats a shallower one) < `domain` or
   `address` (exact).
3. A rule with a port or port range beats one without.
4. A rule with a transport (`tcp`/`udp`) beats one without.

Still tied: **block beats allow**, then the lower rule id. Rule ids are the
rules' positions in the text, counting from 1.

`subdomains example.com` matches `a.example.com` and `a.b.example.com`, not
`example.com` itself. Use a `domain` rule too for the apex. Names are
compared lowercase, without a trailing dot.

## Modes

| Mode | Default | Essentials |
|---|---|---|
| allow-all | allow | not used |
| block-all | block | reachable, unless `essentials off` |
| lockdown | block, always | blocked too |

**Essentials** are a fallback layer only in block-all: DNS (UDP/TCP 53,
TCP 853), Apple push, captive-portal check, time and certificate revocation,
and the Android equivalents. A rule of yours always beats them, so
`block domain time.apple.com` still blocks it. The list is in
`core/flynn-rules/src/essentials.rs` and is a starting point to tune on a
device.

## Waiting for a name

Most rules name a domain, but the name only arrives with the TLS ClientHello
or the QUIC Initial. Until then the engine can answer `Wait`: it does that
whenever a name could still change the answer, and never gives a final answer
that a later name would overturn. It may wait when it did not strictly need
to. A waiting flow holds its data in both directions. When the name arrives
the flow settles; if none comes within the quiet period the name is marked
unavailable and the flow is decided without it (a DNS-derived name is used if
one exists). Events show a waiting flow as allowed, reason "waiting for name",
followed by a `FlowDecided` event.

## The text form

```text
# comments start with a hash
mode block-all            # allow-all | block-all | lockdown
essentials on             # on | off
panic off                 # on | off
block subdomains tracker.test
allow domain www.example.com tcp port 443
allow cidr 10.0.0.0/8 app com.example.app
block address 203.0.113.9 udp
block any port 25
```

A rule is `allow` or `block`, a destination (`any`, `domain NAME`,
`subdomains NAME`, `cidr ADDR/LEN`, `address ADDR`) and any of `app ID`,
`tcp`, `udp`, `port N` or `port N-M`, in any order. Errors name the line.
In the app, the mode picker, the essentials switch and the panic switch
override the `mode`, `essentials` and `panic` lines in the text.

Without a device-side app resolver (tunnel level on iOS) no flow has an app,
so `app` rules never match there.

## From the app to the tunnel

1. The app parses the text (`parseRulesText`), lays the controls over it and
   writes a snapshot (`writeRuleSnapshot`) into the App Group container,
   atomically (temporary file, then rename).
2. If the tunnel is running, the app sends the provider message
   `reloadRules`. The extension reads and checks the snapshot, swaps it in,
   and answers with the rule count and generation, or the reason it kept the
   old rules.
3. The forwarder looks at every open flow again: lockdown and panic take
   effect on existing connections, not only new ones. Measured on the Mac
   harness: under 10 ms from the file change to the first re-decision.

If the snapshot on disk is damaged at tunnel start, the tunnel runs
allow-all and posts a notification saying so.

## Snapshot format ("FLRS", version 1)

Header: magic, version, mode, flags (panic, essentials), generation, rule
count, string-table length, CRC-32 over header bytes 0..24 and the body.
Then 24-byte rule records and a string table. Little-endian, byte for byte the
same on every platform. Any change bumps the version.

## Trying it

Mac, no device:

```bash
core/target/release/flynn-harness replay core/fixtures/synthetic-basic.pcap --rules core/fixtures/synthetic-basic.rules
sudo core/target/release/flynn-harness live --rules my.rules   # edit the file while it runs
```

Fixtures: `core/fixtures/synthetic-*.rules` with a matching `.expected.txt`
each; `scripts/check.sh` replays all of them.

## Tests

- Unit tests per module, plus property tests (`core/flynn-rules/tests`) that
  compare the compiled engine with a naive reference on random rule sets, and
  check precedence, panic/lockdown ordering, snapshot round trips and
  corruption detection.
- Forwarder integration tests: block, allow, hold-until-named, hot reload
  cutting open flows, lockdown, panic.
- Replay fixtures: same capture, five rule sets, checked-in verdicts.

## Not done yet

- Flow table LRU eviction and coalescing of repeated connections: deferred
  until device data shows they are needed.
- Fuzzers for the snapshot decoder and text parser: cargo-fuzz needs nightly
  and is not installed on the build machine.
- App-scoped rules need the content filter (M3, iPad supervised).
