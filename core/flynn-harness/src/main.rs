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
//!   flynn-harness gen-fixture <out.pcap>
//!       Write the synthetic capture used by the replay fixture test.

mod fixture;
#[cfg(target_os = "macos")]
mod live;
mod mem;
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
    };
    live::run(opts).map_err(|e| e.to_string())?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(not(target_os = "macos"))]
fn cmd_live(_args: &[String]) -> CmdResult {
    Err("live mode needs macOS (utun)".into())
}
