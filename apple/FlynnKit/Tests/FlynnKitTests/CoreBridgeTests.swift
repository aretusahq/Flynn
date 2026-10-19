import Foundation
import Testing
@testable import FlynnKit

/// Proves the Rust core links and that Swift host objects cross the FFI
/// boundary in both directions.
struct CoreBridgeTests {
    @Test func coreVersionIsReported() {
        #expect(!coreVersion().isEmpty)
    }

    @Test func dataPlaneRoundTripsCapabilities() {
        let container = SharedContainer(root: FileManager.default.temporaryDirectory)
        let plane = FlynnDataPlane(
            packets: DiscardPacketIo(),
            protector: NoopSocketProtector(),
            apps: NoAppResolver(),
            clock: SystemClock(),
            paths: ContainerPaths(container: container),
            notifier: LogNotifier(category: "tests"),
            capabilities: .tunnelOnly
        )
        #expect(plane.capabilities() == .tunnelOnly)
        plane.setCapabilities(capabilities: .supervised)
        #expect(plane.capabilities() == .supervised)
    }

    @Test func containerPathsPointInsideTheContainer() {
        let root = URL(filePath: "/tmp/flynn-test", directoryHint: .isDirectory)
        let paths = ContainerPaths(container: SharedContainer(root: root))
        #expect(paths.spoolDir() == "/tmp/flynn-test/spool/")
        #expect(paths.ruleSnapshot() == "/tmp/flynn-test/rules.snapshot")
    }
}
