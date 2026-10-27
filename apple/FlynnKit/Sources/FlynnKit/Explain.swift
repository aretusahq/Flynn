import Foundation

/// A plain sentence for an error from the Rust core. UniFFI's own
/// description is a debug dump.
public func explain(_ error: Error) -> String {
    switch error as? FlynnError {
    case let .Io(message)?, let .InvalidSettings(message)?, let .InvalidRules(message)?:
        return message
    case .AlreadyRunning?:
        return "The tunnel is already running."
    case nil:
        return error.localizedDescription
    }
}
