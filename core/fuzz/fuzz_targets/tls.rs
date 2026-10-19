#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = flynn_proto::tls::client_hello_sni(data);
    let _ = flynn_proto::quic::initial_version(data);
});
