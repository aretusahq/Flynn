#![no_main]
use flynn_proto::{ip, transport};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = ip::parse(data) {
        let _ = transport::parse_tcp(p.payload);
        let _ = transport::parse_udp(p.payload);
    }
});
