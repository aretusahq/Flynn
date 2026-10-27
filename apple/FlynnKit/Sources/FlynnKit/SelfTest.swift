import Foundation

/// One check from the Rust core's on-device self-test.
public struct SelfTestResult: Identifiable, Sendable, Equatable {
    public let name: String
    public let passed: Bool
    public let detail: String
    public var id: String { name }
}

/// Runs the core's self-test inside the calling process: the QUIC crypto, the
/// parsers, file writes, the memory sampler and a UDP flow through the
/// forwarder. For builds that cannot run the tunnel, and for CI.
public enum CoreSelfTest {
    public static func run() -> [SelfTestResult] {
        let dir = FileManager.default.temporaryDirectory
            .appending(path: "flynn-selftest", directoryHint: .isDirectory)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        return coreSelfTest(scratchDir: dir.path(percentEncoded: false)).map {
            SelfTestResult(name: $0.name, passed: $0.passed, detail: $0.detail)
        }
    }

    public static func report(_ results: [SelfTestResult]) -> String {
        var lines = [
            "Flynn core self-test",
            "core \(coreVersion()) on \(ProcessInfo.processInfo.operatingSystemVersionString)",
            ISO8601DateFormatter().string(from: Date()),
            "",
        ]
        for r in results {
            lines.append("\(r.passed ? "PASS" : "FAIL")  \(r.name)")
            lines.append("      \(r.detail)")
        }
        let failed = results.filter { !$0.passed }.count
        lines.append("")
        lines.append(failed == 0 ? "all \(results.count) checks passed" : "\(failed) of \(results.count) checks FAILED")
        return lines.joined(separator: "\n") + "\n"
    }

    /// Saves the report as Documents/selftest.txt so it can be copied off a
    /// device with `devicectl`. Best effort.
    @discardableResult
    public static func saveReport(_ results: [SelfTestResult]) -> URL? {
        guard let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            return nil
        }
        let url = docs.appending(path: "selftest.txt")
        do {
            try report(results).write(to: url, atomically: true, encoding: .utf8)
            return url
        } catch {
            return nil
        }
    }
}
