import Foundation

/// Locations shared by the app and its extensions through the App Group.
///
/// The App Group identifier comes from each target's Info.plist
/// (`FlynnAppGroup`, set from `FLYNN_APP_GROUP` in project.yml), so the
/// bundle prefix is defined in one place.
public struct SharedContainer: Sendable {
    public let root: URL

    public init(root: URL) {
        self.root = root
    }

    /// The App Group container for the running target, or nil when the
    /// target is not signed with the App Group (unit tests, unsigned builds).
    public static func appGroup(bundle: Bundle = .main) -> SharedContainer? {
        guard
            let group = bundle.object(forInfoDictionaryKey: "FlynnAppGroup") as? String,
            let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group)
        else { return nil }
        return SharedContainer(root: url)
    }

    /// Directory the capture extension writes event spool segments to.
    public var spoolDirectory: URL { root.appending(path: "spool", directoryHint: .isDirectory) }

    /// The compiled rule snapshot the app writes and the extension loads.
    public var ruleSnapshot: URL { root.appending(path: "rules.snapshot") }
}

/// `HostPaths` backed by a shared container.
public final class ContainerPaths: HostPaths {
    private let container: SharedContainer

    public init(container: SharedContainer) {
        self.container = container
    }

    public func spoolDir() -> String { container.spoolDirectory.path(percentEncoded: false) }
    public func ruleSnapshot() -> String { container.ruleSnapshot.path(percentEncoded: false) }
}
