import FlynnKit
import Foundation
@preconcurrency import NetworkExtension
import Observation
import UserNotifications

/// Owns the VPN configuration for the packet tunnel: creates it, applies the
/// spike switches, starts and stops it, and talks to the running extension.
@MainActor
@Observable
final class TunnelController {
    private(set) var status: NEVPNStatus = .invalid
    private(set) var configured = false
    var options: TunnelOptions {
        didSet { Self.saveOptions(options) }
    }
    private(set) var lastError: String?
    private(set) var stats: TunnelStatsReply?
    private(set) var events: [SpoolEvent] = []
    private(set) var latestSample: (mem: MemSample, stats: StatsSnapshot, atMs: Int64)?
    private(set) var peakFootprint: UInt64 = 0
    private(set) var appMemory = processMemory()

    private var manager: NETunnelProviderManager?
    private var statusTask: Task<Void, Never>?
    let spoolDirectory = SharedContainer.appGroup()?.spoolDirectory

    init() {
        options = Self.loadOptions()
    }

    var isActive: Bool {
        status == .connected || status == .connecting || status == .reasserting
    }

    func load() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = managers.first
            configured = manager != nil
            status = manager?.connection.status ?? .invalid
            lastError = nil
        } catch {
            #if targetEnvironment(simulator)
            lastError = "The Simulator cannot run Network Extensions. Run Flynn on a device to start the tunnel."
            #else
            lastError = "Loading the VPN configuration failed: \(error.localizedDescription)"
            #endif
        }
        observeStatus()
    }

    /// Writes the current options into the VPN configuration, creating it
    /// on first use. iOS asks the user to allow the configuration once.
    func apply() async {
        do {
            let manager = self.manager ?? NETunnelProviderManager()
            let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
            proto.providerBundleIdentifier = (Bundle.main.bundleIdentifier ?? "io.aretusa.flynn") + ".tunnel"
            proto.serverAddress = "On this device"
            proto.providerConfiguration = options.providerConfiguration()
            proto.includeAllNetworks = options.includeAllNetworks
            proto.enforceRoutes = options.enforceRoutes
            proto.excludeLocalNetworks = !options.includeAllNetworks
            manager.protocolConfiguration = proto
            manager.localizedDescription = "Flynn"
            manager.isEnabled = true
            if options.onDemand {
                let rule = NEOnDemandRuleConnect()
                rule.interfaceTypeMatch = .any
                manager.onDemandRules = [rule]
            } else {
                manager.onDemandRules = []
            }
            manager.isOnDemandEnabled = options.onDemand
            try await manager.saveToPreferences()
            // Reload so the connection object reflects the saved configuration.
            try await manager.loadFromPreferences()
            self.manager = manager
            configured = true
            status = manager.connection.status
            lastError = nil
            observeStatus()
        } catch {
            lastError = "Saving the VPN configuration failed: \(error.localizedDescription)"
        }
    }

    func start() async {
        await apply()
        guard let manager else { return }
        do {
            try manager.connection.startVPNTunnel()
            lastError = nil
        } catch {
            lastError = "Starting the tunnel failed: \(error.localizedDescription)"
        }
    }

    func stop() {
        // With on-demand on, iOS would restart the tunnel straight away.
        if let manager, manager.isOnDemandEnabled {
            manager.isOnDemandEnabled = false
            Task { try? await manager.saveToPreferences() }
        }
        manager?.connection.stopVPNTunnel()
    }

    /// Reads the spool and, while connected, asks the extension for counters.
    func refresh() async {
        appMemory = processMemory()
        if let dir = spoolDirectory {
            let tail = (try? spoolTail(dir: dir.path(percentEncoded: false), max: 300)) ?? []
            events = tail
            for event in tail.reversed() {
                if case let .sample(atMs, mem, stats) = event {
                    latestSample = (mem, stats, atMs)
                    break
                }
            }
            for case let .sample(_, mem, _) in tail {
                peakFootprint = max(peakFootprint, mem.peakFootprint)
            }
        }
        if status == .connected, let data = await send(.stats) {
            stats = try? JSONDecoder().decode(TunnelStatsReply.self, from: data)
            if let peak = stats?.peakFootprint {
                peakFootprint = max(peakFootprint, peak)
            }
        } else if status != .connected {
            stats = nil
        }
    }

    /// Asks for notification permission, then has the extension post one.
    func testNotification() async {
        do {
            let granted = try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
            guard granted else {
                lastError = "Notifications are not allowed for Flynn."
                return
            }
        } catch {
            lastError = "Notification permission failed: \(error.localizedDescription)"
            return
        }
        guard status == .connected else {
            lastError = "Start the tunnel first: the test notification comes from the extension."
            return
        }
        _ = await send(.testNotification)
    }

    func clearError() {
        lastError = nil
    }

    private func send(_ request: TunnelRequest) async -> Data? {
        guard let session = manager?.connection as? NETunnelProviderSession,
              let message = try? JSONEncoder().encode(request) else { return nil }
        return await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(message) { reply in
                    continuation.resume(returning: reply)
                }
            } catch {
                continuation.resume(returning: nil)
            }
        }
    }

    private func observeStatus() {
        statusTask?.cancel()
        guard let connection = manager?.connection else { return }
        statusTask = Task { [weak self] in
            for await _ in NotificationCenter.default.notifications(named: .NEVPNStatusDidChange, object: connection) {
                self?.status = connection.status
            }
        }
    }

    private static let optionsKey = "tunnelOptions"

    private static func loadOptions() -> TunnelOptions {
        guard let data = UserDefaults.standard.data(forKey: optionsKey),
              let options = try? JSONDecoder().decode(TunnelOptions.self, from: data) else { return TunnelOptions() }
        return options
    }

    private static func saveOptions(_ options: TunnelOptions) {
        if let data = try? JSONEncoder().encode(options) {
            UserDefaults.standard.set(data, forKey: optionsKey)
        }
    }
}

extension NEVPNStatus {
    var label: String {
        switch self {
        case .invalid: "Not configured"
        case .disconnected: "Off"
        case .connecting: "Starting"
        case .connected: "On"
        case .reasserting: "Reconnecting"
        case .disconnecting: "Stopping"
        @unknown default: "Unknown"
        }
    }
}
