//! Host harness for the data plane on macOS.
//!
//!   flynn-harness replay <file.pcap> [--block DOMAIN]... [--expect FILE]
//!       Run a capture (pcap or pcapng) through the parsers, naming and
//!       policy, and print one line per flow. With --expect, compare the
//!       output with FILE and exit 1 on any difference.
//!
//!   sudo flynn-harness live [--route CIDR]... [--all] [--block DOMAIN]...
//!       [--interface en0] [--events] [--stats-every SECS]
//!       [--recv-buffer KIB] [--send-buffer KIB]
//!       Open a utun interface, route traffic into it, and relay it through
//!       the forwarder, printing throughput, flows and memory.
//!
//!   flynn-harness spool-tail <dir> [COUNT]
//!       Print the newest events in a spool directory (from `live --spool`
//!       or copied off a device).
//!
//!   flynn-harness demo-spool <dir>
//!       Write the synthetic fixture's flows as spool events, so the app's
//!       screens show data in the Simulator, where the tunnel cannot run.
//!
//!   flynn-harness gen-fixture <out.pcap>
//!       Write the synthetic capture used by the replay fixture test.

mod fixture;
#[cfg(target_os = "macos")]
mod live;
mod pcap;
mod replay;
#[cfg(target_os = "macos")]
mod utun;

use std::process::ExitCode;
use std::sync::Arc;

use flynn_dataplane::{DomainBlocklist, ModePolicy, Policy};
use flynn_rules::Mode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("replay") => cmd_replay(&args[1..]),
        Some("live") => cmd_live(&args[1..]),
        Some("gen-fixture") => cmd_gen_fixture(&args[1..]),
        Some("spool-tail") => cmd_spool_tail(&args[1..]),
        Some("demo-spool") => cmd_demo_spool(&args[1..]),
        _ => {
            print!("{}", USAGE);
            return ExitCode::SUCCESS;
        }
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("flynn-harness: {e}");
            ExitCode::FAILURE
        }
    }
}

const USAGE: &str = "\
usage:
  flynn-harness replay <file.pcap> [--block DOMAIN]... [--expect FILE]
  sudo flynn-harness live [--route CIDR]... [--all] [--block DOMAIN]... [--interface IF]
                          [--events] [--stats-every SECS] [--recv-buffer KIB] [--send-buffer KIB]
                          [--spool DIR]
  flynn-harness spool-tail <dir> [COUNT]
  flynn-harness demo-spool <dir>
  flynn-harness gen-fixture <out.pcap>
";

type CmdResult = Result<ExitCode, String>;

/// Splits `--flag value` pairs and bare `--flag`s from positionals.
struct Args {
    positional: Vec<String>,
    pairs: Vec<(String, String)>,
    flags: Vec<String>,
}

fn parse(args: &[String], takes_value: &[&str]) -> Result<Args, String> {
    let mut out = Args {
        positional: Vec::new(),
        pairs: Vec::new(),
        flags: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if takes_value.contains(&a.as_str()) {
            let v = it.next().ok_or(format!("{a} needs a value"))?;
            out.pairs.push((a.clone(), v.clone()));
        } else if a.starts_with("--") {
            out.flags.push(a.clone());
        } else {
            out.positional.push(a.clone());
        }
    }
    Ok(out)
}

impl Args {
    fn all(&self, flag: &str) -> Vec<String> {
        self.pairs
            .iter()
            .filter(|(f, _)| f == flag)
            .map(|(_, v)| v.clone())
            .collect()
    }
    fn one(&self, flag: &str) -> Option<String> {
        self.all(flag).pop()
    }
    fn has(&self, flag: &str) -> bool {
        self.flags.iter().any(|f| f == flag)
    }
}

fn policy(blocks: Vec<String>) -> Arc<dyn Policy> {
    if blocks.is_empty() {
        Arc::new(ModePolicy(Mode::AllowAll))
    } else {
        Arc::new(DomainBlocklist::new(blocks))
    }
}

fn cmd_replay(args: &[String]) -> CmdResult {
    let a = parse(args, &["--block", "--expect"])?;
    let [path] = a.positional.as_slice() else {
        return Err("replay takes one capture file".into());
    };
    let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let capture = pcap::read(&data).map_err(|e| format!("{path}: {e}"))?;
    let report = replay::report(&capture, policy(a.all("--block")));
    print!("{report}");
    if let Some(expect) = a.one("--expect") {
        let want = std::fs::read_to_string(&expect).map_err(|e| format!("{expect}: {e}"))?;
        if want != report {
            eprintln!("\nreplay output differs from {expect}:");
            for (i, (w, g)) in want.lines().zip(report.lines()).enumerate() {
                if w != g {
                    eprintln!("  line {}:\n    want: {w}\n    got:  {g}", i + 1);
                }
            }
            if want.lines().count() != report.lines().count() {
                eprintln!(
                    "  line count: want {}, got {}",
                    want.lines().count(),
                    report.lines().count()
                );
            }
            return Ok(ExitCode::FAILURE);
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_spool_tail(args: &[String]) -> CmdResult {
    let (dir, count) = match args {
        [dir] => (dir, 50),
        [dir, n] => (dir, n.parse().map_err(|_| format!("not a count: {n}"))?),
        _ => return Err("spool-tail takes a directory and an optional count".into()),
    };
    let events = flynn_dataplane::spool::tail(std::path::Path::new(dir), count)
        .map_err(|e| format!("{dir}: {e}"))?;
    for e in events {
        println!("{}", describe(&e));
    }
    Ok(ExitCode::SUCCESS)
}

fn describe(e: &flynn_dataplane::Event) -> String {
    use flynn_dataplane::Event;
    match e {
        Event::FlowOpened {
            id,
            at_ms,
            key,
            name,
            source,
            verdict,
            ..
        } => format!(
            "{at_ms} open  #{id} {:?} {} -> {} {} ({}) {:?}",
            key.protocol,
            key.src,
            key.dst,
            name.as_deref().unwrap_or("-"),
            source.as_str(),
            verdict
        ),
        Event::FlowNamed { id, name, source } => {
            format!("     name  #{id} {name} ({})", source.as_str())
        }
        Event::FlowClosed {
            id,
            at_ms,
            bytes_up,
            bytes_down,
            reason,
        } => {
            format!(
                "{at_ms} close #{id} up {bytes_up} B down {bytes_down} B ({})",
                reason.as_str()
            )
        }
        Event::DnsAnswer { at_ms, name, addrs } => format!("{at_ms} dns   {name} = {addrs:?}"),
        Event::Sample { at_ms, mem, stats } => format!(
            "{at_ms} sample footprint {:.1} MiB (peak {:.1}) cpu {} ms  tcp {} udp {}  up {} B down {} B",
            mem.footprint as f64 / 1048576.0,
            mem.peak_footprint as f64 / 1048576.0,
            mem.cpu_ms,
            stats.tcp_active,
            stats.udp_active,
            stats.bytes_up,
            stats.bytes_down
        ),
    }
}

fn cmd_demo_spool(args: &[String]) -> CmdResult {
    use flynn_dataplane::observe::FlowTracker;
    use flynn_dataplane::{CloseReason, Event, MemSample, NameSource, StatsSnapshot};

    let [dir] = args else {
        return Err("demo-spool takes one directory".into());
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64);
    let mut tracker = FlowTracker::new(policy(vec!["tracker.test".into()]));
    let packets = fixture::basic();
    let first = packets.first().map_or(0, |p| p.at_ms);
    for p in &packets {
        tracker.observe(p.at_ms, &p.ip);
    }
    let mut events = Vec::new();
    let mut stats = StatsSnapshot::default();
    for (i, f) in tracker.finish().into_iter().enumerate() {
        let id = i as u64 + 1;
        let shift = |t: i64| now - 60_000 + (t - first);
        let blocked = f.verdict == flynn_rules::Verdict::Block;
        events.push(Event::FlowOpened {
            id,
            at_ms: shift(f.first_ms),
            key: f.key,
            name: if f.source == NameSource::Sni {
                None
            } else {
                f.name.clone()
            },
            source: if f.source == NameSource::Sni {
                NameSource::None
            } else {
                f.source
            },
            app: None,
            verdict: if f.source == NameSource::Sni {
                flynn_rules::Verdict::Allow
            } else {
                f.verdict
            },
        });
        if f.source == NameSource::Sni {
            events.push(Event::FlowNamed {
                id,
                name: f.name.clone().unwrap_or_default(),
                source: NameSource::Sni,
            });
        }
        events.push(Event::FlowClosed {
            id,
            at_ms: shift(f.last_ms),
            bytes_up: if blocked { 0 } else { f.bytes_up },
            bytes_down: if blocked { 0 } else { f.bytes_down },
            reason: if blocked {
                CloseReason::Blocked
            } else {
                CloseReason::Normal
            },
        });
        stats.flows_opened += 1;
        stats.flows_blocked += u64::from(blocked);
        stats.bytes_up += f.bytes_up;
        stats.bytes_down += f.bytes_down;
    }
    events.push(Event::Sample {
        at_ms: now - 5_000,
        mem: MemSample {
            footprint: 7_340_032,
            peak_footprint: 9_437_184,
            cpu_ms: 1_250,
        },
        stats,
    });
    let mut writer =
        flynn_dataplane::spool::SpoolWriter::open(std::path::Path::new(dir), 256 * 1024, 64)
            .map_err(|e| format!("{dir}: {e}"))?;
    for e in &events {
        writer.append(e).map_err(|e| format!("{dir}: {e}"))?;
    }
    writer.flush().map_err(|e| format!("{dir}: {e}"))?;
    println!("wrote {} demo events to {dir}", events.len());
    Ok(ExitCode::SUCCESS)
}

fn cmd_gen_fixture(args: &[String]) -> CmdResult {
    let [path] = args else {
        return Err("gen-fixture takes one output path".into());
    };
    let mut file = std::fs::File::create(path).map_err(|e| format!("{path}: {e}"))?;
    pcap::write_raw(&mut file, &fixture::basic()).map_err(|e| format!("{path}: {e}"))?;
    println!("wrote {path}");
    Ok(ExitCode::SUCCESS)
}

#[cfg(target_os = "macos")]
fn cmd_live(args: &[String]) -> CmdResult {
    let a = parse(
        args,
        &[
            "--route",
            "--block",
            "--interface",
            "--stats-every",
            "--recv-buffer",
            "--send-buffer",
            "--spool",
        ],
    )?;
    let num = |flag: &str, default: u64| -> Result<u64, String> {
        a.one(flag).map_or(Ok(default), |v| {
            v.parse().map_err(|_| format!("{flag}: not a number: {v}"))
        })
    };
    let opts = live::LiveOptions {
        routes: a.all("--route"),
        all: a.has("--all"),
        interface: a.one("--interface"),
        print_events: a.has("--events"),
        stats_every: std::time::Duration::from_secs(num("--stats-every", 5)?.max(1)),
        policy: policy(a.all("--block")),
        recv_buffer: num("--recv-buffer", 16)? as usize * 1024,
        send_buffer: num("--send-buffer", 32)? as usize * 1024,
        spool: a.one("--spool").map(std::path::PathBuf::from),
    };
    live::run(opts).map_err(|e| e.to_string())?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(not(target_os = "macos"))]
fn cmd_live(_args: &[String]) -> CmdResult {
    Err("live mode needs macOS (utun)".into())
}
