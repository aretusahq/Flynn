#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = flynn_proto::tls::client_hello_sni(data);
    let _ = flynn_proto::quic::initial_version(data);
    let _ = flynn_proto::quic::InitialSniffer::new().feed(data);
    let _ = flynn_proto::tls::handshake_sni(data);
});
