import Foundation
import os

/// Host implementations shared by the iOS capture extensions. Each one is a
/// platform answer to a trait in `flynn-dataplane/src/host.rs`.

public final class SystemClock: HostClock {
    public init() {}

    public func nowUnixMillis() -> Int64 {
        Int64((Date().timeIntervalSince1970 * 1000).rounded())
    }
}

/// On iOS the extension's own sockets already bypass its tunnel, so there is
/// nothing to protect. (Android calls `VpnService.protect` here.)
public final class NoopSocketProtector: HostSocketProtector {
    public init() {}

    public func protect(fd: Int32) -> Bool { true }
}

/// The packet tunnel cannot tell which app opened a flow. Returns nil, and
/// the core records `GapReason.notSupervised` for the missing name.
public final class NoAppResolver: HostAppResolver {
    public init() {}

    public func resolve(flow: FlowKey) -> AppId? { nil }
}

/// Writes notifications to the unified log until M2 settles whether the
/// tunnel extension can post user notifications directly.
public final class LogNotifier: HostNotifier {
    private let logger: Logger

    public init(category: String) {
        logger = Logger(subsystem: "Flynn", category: category)
    }

    public func notify(title: String, body: String) {
        logger.notice("\(title, privacy: .public): \(body, privacy: .private)")
    }
}

/// Discards outbound packets. Used until the tunnel provider wires
/// `NEPacketTunnelFlow` in M2.
public final class DiscardPacketIo: HostPacketIo {
    public init() {}

    public func writePackets(packets: [Data]) -> Bool { true }
}

public extension Capabilities {
    /// An unsupervised iPhone or iPad on the packet tunnel: domains and IPs,
    /// no app names, no paused flows, device-wide leak counters only.
    static let tunnelOnly = Capabilities(perAppAvailable: false, canPauseFlow: false, leakDetectionScope: .device)

    /// A supervised device with the content filter enabled.
    static let supervised = Capabilities(perAppAvailable: true, canPauseFlow: true, leakDetectionScope: .device)
}
