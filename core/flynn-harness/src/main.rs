//! Host harness for the data plane on macOS.
//!
//! M1 adds two modes:
//!   flynn-harness replay <file.pcap>   run a capture through the parsers and
//!                                      rules and print flows and verdicts
//!   flynn-harness live                 open a utun interface (needs sudo) and
//!                                      route the Mac's traffic through the
//!                                      forwarder, printing throughput and RSS

use std::process::ExitCode;

fn main() -> ExitCode {
    let mode = std::env::args().nth(1);
    match mode.as_deref() {
        None | Some("--help") | Some("-h") => {
            println!("flynn-harness: replay <file.pcap> | live   (both land in M1)");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("flynn-harness: mode `{other}` is not implemented yet");
            ExitCode::FAILURE
        }
    }
}
