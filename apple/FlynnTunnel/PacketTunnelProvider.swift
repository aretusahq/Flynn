import FlynnKit
@preconcurrency import NetworkExtension
import os

/// The packet tunnel: Flynn's capture route on every iPhone and iPad.
///
/// M0 skeleton. It links the Rust data plane and refuses to start; M2 sets
/// the tunnel network settings and feeds `packetFlow` into the core.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let logger = Logger(subsystem: "Flynn", category: "tunnel")
    private var dataPlane: FlynnDataPlane?

    // Completion-handler forms: NetworkExtension's parameter types are not
    // Sendable, so the async overrides fail Swift 6 isolation checks.
    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let container = SharedContainer.appGroup() else {
            completionHandler(NEVPNError(.configurationInvalid))
            return
        }
        dataPlane = FlynnDataPlane(
            packets: DiscardPacketIo(),
            protector: NoopSocketProtector(),
            apps: NoAppResolver(),
            clock: SystemClock(),
            paths: ContainerPaths(container: container),
            notifier: LogNotifier(category: "tunnel"),
            capabilities: .tunnelOnly
        )
        logger.notice("Flynn core \(coreVersion(), privacy: .public) loaded; capture lands in M2")
        completionHandler(NEVPNError(.configurationDisabled))
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        dataPlane = nil
        completionHandler()
    }
}
