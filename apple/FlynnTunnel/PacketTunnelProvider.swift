import FlynnKit
@preconcurrency import NetworkExtension
import os

/// The packet tunnel: Flynn's capture route on every iPhone and iPad.
///
/// Claims the default routes, hands every packet to the Rust forwarder and
/// writes what comes back to the apps. Events go to the spool in the App
/// Group container, where the app reads them.
final class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
    private let logger = Logger(subsystem: "Flynn", category: "tunnel")
    private let plane = OSAllocatedUnfairLock<FlynnDataPlane?>(initialState: nil)

    // Completion-handler forms: NetworkExtension's parameter types are not
    // Sendable, so the async overrides fail Swift 6 isolation checks.
    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let container = SharedContainer.appGroup() else {
            logger.error("no App Group container; is the extension signed with the App Group?")
            completionHandler(NEVPNError(.configurationInvalid))
            return
        }
        let tunnelOptions = TunnelOptions(
            providerConfiguration: (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        )
        let done = UncheckedBox(completionHandler)
        setTunnelNetworkSettings(Self.networkSettings(tunnelOptions)) { [weak self] error in
            guard let self else { return }
            if let error {
                self.logger.error("tunnel settings rejected: \(error.localizedDescription, privacy: .public)")
                done.value(error)
                return
            }
            do {
                let plane = FlynnDataPlane(
                    packets: PacketFlowIO(self.packetFlow),
                    protector: NoopSocketProtector(),
                    apps: NoAppResolver(),
                    clock: SystemClock(),
                    paths: ContainerPaths(container: container),
                    notifier: UserNotifier(),
                    capabilities: .tunnelOnly
                )
                let report = try plane.start(settings: tunnelOptions.forwarderSettings())
                self.plane.withLock { $0 = plane }
                self.logger.notice("forwarder started, core \(coreVersion(), privacy: .public), \(report.rules.ruleCount) rules")
                if let problem = report.rulesError {
                    // The forwarder runs allow-all in that case, so say so.
                    self.logger.error("rules file unusable: \(problem, privacy: .public)")
                    UserNotifier().notify(
                        title: "Flynn is allowing all traffic",
                        body: "The rules file could not be read, so no rules apply. Open Flynn and save your rules again."
                    )
                }
                self.readPackets()
                done.value(nil)
            } catch {
                self.logger.error("forwarder failed to start: \(error.localizedDescription, privacy: .public)")
                done.value(error)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.notice("stopping, reason \(reason.rawValue)")
        let running = plane.withLock { current -> FlynnDataPlane? in
            defer { current = nil }
            return current
        }
        running?.stop()
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let request = try? JSONDecoder().decode(TunnelRequest.self, from: messageData) else {
            completionHandler?(nil)
            return
        }
        let running = plane.withLock { $0 }
        switch request {
        case .stats:
            let reply = TunnelStatsReply(
                running: running?.isRunning() ?? false,
                stats: running?.stats(),
                spoolErrors: running?.spoolErrors() ?? 0,
                memory: processMemory(),
                rules: running?.rulesInfo()
            )
            completionHandler?(try? JSONEncoder().encode(reply))
        case .reloadRules:
            let reply: RulesReloadReply
            do {
                guard let running else { throw NEVPNError(.configurationInvalid) }
                reply = RulesReloadReply(info: try running.reloadRules())
            } catch {
                reply = RulesReloadReply(error: "\(error)")
            }
            completionHandler?(try? JSONEncoder().encode(reply))
        case .testNotification:
            UserNotifier().notify(title: "Flynn", body: "This notification was posted by the tunnel extension.")
            completionHandler?(Data())
        }
    }

    /// Reads packets until the tunnel stops. Each callback re-arms the read.
    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, let plane = self.plane.withLock({ $0 }) else { return }
            plane.pushPackets(packets: packets)
            self.readPackets()
        }
    }

    /// Default routes for IPv4 and IPv6 through the tunnel. DNS is left to
    /// the network unless the virtual-resolver experiment is on.
    private static func networkSettings(_ options: TunnelOptions) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.mtu = 1500
        let v4 = NEIPv4Settings(addresses: ["10.111.0.2"], subnetMasks: ["255.255.255.255"])
        v4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = v4
        let v6 = NEIPv6Settings(addresses: ["fd00:f1::2"], networkPrefixLengths: [128])
        v6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = v6
        if options.useVirtualDNS, !options.upstreamDNS.isEmpty {
            let dns = NEDNSSettings(servers: [TunnelOptions.virtualDNS])
            dns.matchDomains = [""] // every query
            settings.dnsSettings = dns
        }
        return settings
    }
}

/// Writes packets for apps back into the tunnel.
final class PacketFlowIO: HostPacketIo, @unchecked Sendable {
    private let flow: NEPacketTunnelFlow

    init(_ flow: NEPacketTunnelFlow) {
        self.flow = flow
    }

    func writePackets(packets: [Data]) -> Bool {
        let protocols = packets.map { packet in
            NSNumber(value: packet.first.map { $0 >> 4 } == 6 ? AF_INET6 : AF_INET)
        }
        return flow.writePackets(packets, withProtocols: protocols)
    }
}

/// Carries a non-Sendable value (a completion handler) across a callback
/// that NetworkExtension calls exactly once.
private final class UncheckedBox<T>: @unchecked Sendable {
    let value: T
    init(_ value: T) { self.value = value }
}
