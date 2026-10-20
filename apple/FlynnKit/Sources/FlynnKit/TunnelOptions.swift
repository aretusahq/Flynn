import Foundation

/// What the app asks of the tunnel. The app stores it in the tunnel's
/// provider configuration; the extension reads it at start.
public struct TunnelOptions: Codable, Equatable, Sendable {
    public enum Mode: String, Codable, CaseIterable, Sendable {
        case allowAll, blockAll, lockdown
    }

    public var mode: Mode = .allowAll
    /// Domains (and subdomains) blocked whatever the mode.
    public var blockedDomains: [String] = []
    public var recvBufferKiB: UInt32 = 16
    public var sendBufferKiB: UInt32 = 32
    /// Drop QUIC flows whose server name cannot be read, so apps retry over
    /// TCP, where the name is visible and rules can match it.
    public var forceTCPForUnnamedQUIC = false

    // Spike switches, applied by the app to the VPN configuration.
    /// Route all traffic, including what iOS would otherwise exempt.
    public var includeAllNetworks = false
    /// Keep traffic on the tunnel even for networks with their own routes.
    public var enforceRoutes = false
    /// Restart the tunnel automatically (after reboot, or if it is killed).
    public var onDemand = false

    /// Give iOS a virtual resolver and relay its queries to `upstreamDNS`.
    /// Off: leave the network's own DNS settings alone.
    public var useVirtualDNS = false
    public var upstreamDNS = ""

    public init() {}

    /// Missing keys keep their defaults, so options saved by an older build
    /// survive a new field.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = TunnelOptions()
        mode = try c.decodeIfPresent(Mode.self, forKey: .mode) ?? d.mode
        blockedDomains = try c.decodeIfPresent([String].self, forKey: .blockedDomains) ?? d.blockedDomains
        recvBufferKiB = try c.decodeIfPresent(UInt32.self, forKey: .recvBufferKiB) ?? d.recvBufferKiB
        sendBufferKiB = try c.decodeIfPresent(UInt32.self, forKey: .sendBufferKiB) ?? d.sendBufferKiB
        forceTCPForUnnamedQUIC = try c.decodeIfPresent(Bool.self, forKey: .forceTCPForUnnamedQUIC) ?? d.forceTCPForUnnamedQUIC
        includeAllNetworks = try c.decodeIfPresent(Bool.self, forKey: .includeAllNetworks) ?? d.includeAllNetworks
        enforceRoutes = try c.decodeIfPresent(Bool.self, forKey: .enforceRoutes) ?? d.enforceRoutes
        onDemand = try c.decodeIfPresent(Bool.self, forKey: .onDemand) ?? d.onDemand
        useVirtualDNS = try c.decodeIfPresent(Bool.self, forKey: .useVirtualDNS) ?? d.useVirtualDNS
        upstreamDNS = try c.decodeIfPresent(String.self, forKey: .upstreamDNS) ?? d.upstreamDNS
    }

    public static let providerKey = "options"
    public static let virtualDNS = "10.111.0.53"

    public func providerConfiguration() -> [String: Any] {
        guard let data = try? JSONEncoder().encode(self) else { return [:] }
        return [Self.providerKey: data]
    }

    public init(providerConfiguration: [String: Any]?) {
        if let data = providerConfiguration?[Self.providerKey] as? Data,
           let decoded = try? JSONDecoder().decode(TunnelOptions.self, from: data) {
            self = decoded
        } else {
            self.init()
        }
    }

    /// Settings for the Rust forwarder.
    public func forwarderSettings() -> ForwarderSettings {
        var s = defaultForwarderSettings()
        s.mode = switch mode {
        case .allowAll: .allowAll
        case .blockAll: .blockAll
        case .lockdown: .lockdown
        }
        s.blockedDomains = blockedDomains
        s.tcpRecvBufferKib = recvBufferKiB
        s.tcpSendBufferKib = sendBufferKiB
        s.forceTcpForUnnamedQuic = forceTCPForUnnamedQUIC
        let upstream = upstreamDNS.trimmingCharacters(in: .whitespaces)
        if useVirtualDNS, !upstream.isEmpty {
            let host = upstream.contains(":") && !upstream.hasPrefix("[") ? "[\(upstream)]" : upstream
            s.dnsRedirect = DnsRedirect(virtualAddr: "\(Self.virtualDNS):53", upstream: "\(host):53")
        }
        return s
    }
}

/// Messages from the app to the running tunnel.
public enum TunnelRequest: String, Codable, Sendable {
    case stats
    case testNotification
}

/// The tunnel's answer to `TunnelRequest.stats`.
public struct TunnelStatsReply: Codable, Sendable {
    public var running: Bool
    public var packetsIn: UInt64
    public var packetsOut: UInt64
    public var bytesUp: UInt64
    public var bytesDown: UInt64
    public var tcpActive: UInt64
    public var udpActive: UInt64
    public var flowsOpened: UInt64
    public var flowsBlocked: UInt64
    public var connectFailed: UInt64
    public var dropped: UInt64
    public var spoolErrors: UInt64
    public var footprint: UInt64
    public var peakFootprint: UInt64

    public init(running: Bool, stats: StatsSnapshot?, spoolErrors: UInt64, memory: MemSample) {
        self.running = running
        packetsIn = stats?.packetsIn ?? 0
        packetsOut = stats?.packetsOut ?? 0
        bytesUp = stats?.bytesUp ?? 0
        bytesDown = stats?.bytesDown ?? 0
        tcpActive = stats?.tcpActive ?? 0
        udpActive = stats?.udpActive ?? 0
        flowsOpened = stats?.flowsOpened ?? 0
        flowsBlocked = stats?.flowsBlocked ?? 0
        connectFailed = stats?.connectFailed ?? 0
        dropped = stats?.dropped ?? 0
        self.spoolErrors = spoolErrors
        footprint = memory.footprint
        peakFootprint = memory.peakFootprint
    }
}
