import FlynnKit
import NetworkExtension
import SwiftUI

/// The M2 spike screen: start and stop the tunnel, flip the experiments,
/// and watch counters, memory and the event spool. Replaced by the real
/// screens in M6; kept afterwards as a hidden diagnostics page.
struct DebugView: View {
    @State private var controller = TunnelController()
    @State private var blockedText = ""
    @State private var showSamples = false

    var body: some View {
        NavigationStack {
            Form {
                tunnelSection
                if let stats = controller.stats { countersSection(stats) }
                memorySection
                switchesSection
                eventsSection
                aboutSection
            }
            .navigationTitle("Flynn")
            .task {
                blockedText = controller.options.blockedDomains.joined(separator: ", ")
                await controller.load()
                while !Task.isCancelled {
                    await controller.refresh()
                    try? await Task.sleep(for: .seconds(2))
                }
            }
        }
    }

    // MARK: Sections

    private var tunnelSection: some View {
        Section {
            LabeledContent("Tunnel", value: controller.status.label)
            if controller.isActive {
                Button("Stop", role: .destructive) { controller.stop() }
            } else {
                Button("Start") { Task { await controller.start() } }
            }
            if let error = controller.lastError {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .onTapGesture { controller.clearError() }
            }
        } footer: {
            Text("Starting the tunnel for the first time asks you to allow a VPN configuration. Flynn's tunnel ends on this device; nothing is sent to a server.")
        }
    }

    private func countersSection(_ s: TunnelStatsReply) -> some View {
        Section("Live, from the extension") {
            LabeledContent("Relayed up", value: bytes(s.bytesUp))
            LabeledContent("Relayed down", value: bytes(s.bytesDown))
            LabeledContent("Open TCP / UDP", value: "\(s.tcpActive) / \(s.udpActive)")
            LabeledContent("Flows opened", value: "\(s.flowsOpened)")
            LabeledContent("Blocked / connect failed", value: "\(s.flowsBlocked) / \(s.connectFailed)")
            LabeledContent("Packets in / out", value: "\(s.packetsIn) / \(s.packetsOut)")
            LabeledContent("Dropped packets", value: "\(s.dropped)")
            if s.spoolErrors > 0 {
                LabeledContent("Spool write errors", value: "\(s.spoolErrors)")
                    .foregroundStyle(.red)
            }
        }
    }

    private var memorySection: some View {
        Section {
            if let sample = controller.latestSample {
                LabeledContent("Extension footprint", value: mib(sample.mem.footprint))
                LabeledContent("Extension peak", value: mib(controller.peakFootprint))
                LabeledContent("Extension CPU", value: String(format: "%.1f s", Double(sample.mem.cpuMs) / 1000))
                LabeledContent("Last sample", value: age(sample.atMs))
            } else {
                Text("No samples yet. The extension writes one every 10 seconds while running.")
                    .foregroundStyle(.secondary)
            }
            LabeledContent("App footprint", value: mib(controller.appMemory.footprint))
        } header: {
            Text("Memory")
        } footer: {
            Text("Footprint is the figure iOS compares with the extension's memory limit (about 50 MiB on iOS 17; design target 12 MiB).")
        }
    }

    private var switchesSection: some View {
        Section {
            Picker("Mode", selection: $controller.options.mode) {
                Text("Allow all").tag(TunnelOptions.Mode.allowAll)
                Text("Block all").tag(TunnelOptions.Mode.blockAll)
                Text("Lockdown").tag(TunnelOptions.Mode.lockdown)
            }
            TextField("Blocked domains, comma-separated", text: $blockedText)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .onSubmit(saveBlocked)
            Stepper("Receive buffer \(controller.options.recvBufferKiB) KiB",
                    value: $controller.options.recvBufferKiB, in: 4...256, step: 4)
            Stepper("Send buffer \(controller.options.sendBufferKiB) KiB",
                    value: $controller.options.sendBufferKiB, in: 4...512, step: 8)
            Toggle("Include all networks", isOn: $controller.options.includeAllNetworks)
            Toggle("Enforce routes", isOn: $controller.options.enforceRoutes)
            Toggle("Connect on demand", isOn: $controller.options.onDemand)
            Toggle("Virtual DNS resolver", isOn: $controller.options.useVirtualDNS)
            if controller.options.useVirtualDNS {
                TextField("Upstream resolver IP (e.g. your router)", text: $controller.options.upstreamDNS)
                    .keyboardType(.numbersAndPunctuation)
                    .autocorrectionDisabled()
            }
            Button("Save to VPN configuration") {
                saveBlocked()
                Task { await controller.apply() }
            }
            Button("Send test notification from the extension") {
                Task { await controller.testNotification() }
            }
        } header: {
            Text("Spike switches")
        } footer: {
            Text("Changes take effect the next time the tunnel starts. Lockdown and block-all have no essentials list yet, so they cut almost everything.")
        }
    }

    private var eventsSection: some View {
        Section {
            Toggle("Show memory samples", isOn: $showSamples)
            let rows = controller.events.reversed().filter { showSamples || !$0.isSample }.prefix(150)
            if rows.isEmpty {
                Text("No events yet.").foregroundStyle(.secondary)
            }
            ForEach(Array(rows.enumerated()), id: \.offset) { _, event in
                EventRow(event: event)
            }
        } header: {
            Text("Events (newest first)")
        }
    }

    private var aboutSection: some View {
        Section("About") {
            LabeledContent("Core", value: coreVersion())
            if let files = spoolFiles(), !files.isEmpty {
                ShareLink("Export spool (\(files.count) files)", items: files)
            }
            if let dir = controller.spoolDirectory {
                Text(dir.path(percentEncoded: false))
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
            } else {
                Text("App Group unavailable: the app is not signed with the Flynn App Group.")
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// Spool segments, for AirDrop to a Mac and `flynn-harness spool-tail`.
    private func spoolFiles() -> [URL]? {
        guard let dir = controller.spoolDirectory else { return nil }
        return try? FileManager.default
            .contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "bin" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    private func saveBlocked() {
        controller.options.blockedDomains = blockedText
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            .filter { !$0.isEmpty }
    }
}

private struct EventRow: View {
    let event: SpoolEvent

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.subheadline)
            Text(detail).font(.caption.monospaced()).foregroundStyle(.secondary)
        }
    }

    private var title: String {
        switch event {
        case let .flowOpened(_, _, transport, _, _, name, _, _, verdict):
            "\(verdict == .block ? "Blocked" : "Opened") \(transport == .tcp ? "TCP" : "UDP") \(name ?? "unknown destination")"
        case let .flowNamed(_, name, _):
            "Named \(name)"
        case let .flowClosed(id, _, _, _, reason):
            "Closed #\(id) (\(reason.label))"
        case let .dnsAnswer(_, name, _):
            "DNS \(name)"
        case let .sample(_, mem, _):
            "Sample: footprint \(mib(mem.footprint))"
        }
    }

    private var detail: String {
        switch event {
        case let .flowOpened(id, atMs, _, src, dst, _, source, _, _):
            "#\(id) \(src) → \(dst) · name from \(source.label) · \(time(atMs))"
        case let .flowNamed(id, _, source):
            "#\(id) · from \(source.label)"
        case let .flowClosed(_, atMs, up, down, _):
            "up \(bytes(up)) · down \(bytes(down)) · \(time(atMs))"
        case let .dnsAnswer(atMs, _, addrs):
            "\(addrs.joined(separator: ", ")) · \(time(atMs))"
        case let .sample(atMs, mem, stats):
            "peak \(mib(mem.peakFootprint)) · tcp \(stats.tcpActive) udp \(stats.udpActive) · \(time(atMs))"
        }
    }
}

private extension SpoolEvent {
    var isSample: Bool {
        if case .sample = self { true } else { false }
    }
}

private extension CloseReason {
    var label: String {
        switch self {
        case .normal: "normal"
        case .reset: "reset"
        case .blocked: "blocked"
        case .connectFailed: "connect failed"
        case .idle: "idle"
        case .capacity: "flow table full"
        case .shutdown: "tunnel stopped"
        }
    }
}

private extension NameSource {
    var label: String {
        switch self {
        case .none: "nowhere"
        case .dns: "DNS"
        case .sni: "TLS server name"
        }
    }
}

private func bytes(_ n: UInt64) -> String {
    n == 0 ? "0 B" : Int64(n).formatted(.byteCount(style: .binary))
}

private func mib(_ n: UInt64) -> String {
    String(format: "%.1f MiB", Double(n) / 1_048_576)
}

private func time(_ ms: Int64) -> String {
    Date(timeIntervalSince1970: Double(ms) / 1000).formatted(date: .omitted, time: .standard)
}

private func age(_ ms: Int64) -> String {
    let seconds = Int(Date().timeIntervalSince1970 - Double(ms) / 1000)
    return seconds < 60 ? "\(max(seconds, 0)) s ago" : "\(seconds / 60) min ago"
}

#Preview {
    DebugView()
}
