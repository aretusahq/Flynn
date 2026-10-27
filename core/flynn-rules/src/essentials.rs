//! What block-all mode keeps reachable so the phone does not break.
//!
//! The list is deliberately small: DNS, push, captive-portal detection, time
//! and certificate revocation. It is a starting point to tune on a device
//! (docs/rules.md). The essentials are never an override: a rule of the
//! user's beats them, so blocking time.apple.com still blocks it.

use flynn_types::Transport;

/// Names reachable in block-all mode.
pub const EXACT: &[&str] = &[
    // Apple: captive portal, time, certificate revocation.
    "captive.apple.com",
    "time.apple.com",
    "time-ios.apple.com",
    "time-macos.apple.com",
    "ocsp.apple.com",
    "ocsp2.apple.com",
    // Android: connectivity checks and time.
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "clients3.google.com",
    "time.android.com",
];

/// Names reachable in block-all mode, along with every subdomain.
pub const SUBDOMAINS: &[&str] = &[
    // Apple push (courier.push.apple.com, 17-courier.push.apple.com, ...).
    "push.apple.com",
    // Android push (Firebase Cloud Messaging).
    "mtalk.google.com",
];

/// DNS is reachable whatever the name: without it no name-based rule can be
/// used and nothing resolves. UDP and TCP 53, and DNS over TLS on 853.
pub fn is_dns_port(transport: Transport, port: u16) -> bool {
    matches!(
        (transport, port),
        (Transport::Udp, 53) | (Transport::Tcp, 53) | (Transport::Tcp, 853)
    )
}

/// Whether a normalised (lowercase, no trailing dot) name is on the list.
pub fn is_essential_name(name: &str) -> bool {
    EXACT.contains(&name)
        || SUBDOMAINS.iter().any(|s| {
            name == *s
                || (name.len() > s.len()
                    && name.ends_with(s)
                    && name.as_bytes()[name.len() - s.len() - 1] == b'.')
        })
}

pub fn is_essential(transport: Transport, port: u16, name: Option<&str>) -> bool {
    is_dns_port(transport, port) || name.is_some_and(is_essential_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_ports_are_essential_for_any_destination() {
        assert!(is_essential(Transport::Udp, 53, None));
        assert!(is_essential(Transport::Tcp, 853, None));
        assert!(!is_essential(Transport::Udp, 853, None));
        assert!(!is_essential(Transport::Tcp, 443, None));
    }

    #[test]
    fn names_match_exactly_or_by_subdomain() {
        assert!(is_essential_name("time.apple.com"));
        assert!(is_essential_name("courier.push.apple.com"));
        assert!(is_essential_name("17-courier.push.apple.com"));
        assert!(is_essential_name("push.apple.com"));
        assert!(!is_essential_name("xtime.apple.com"));
        assert!(!is_essential_name("evilpush.apple.com"));
        assert!(!is_essential_name("push.apple.com.evil.test"));
        assert!(!is_essential_name("apple.com"));
    }
}
