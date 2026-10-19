@preconcurrency import NetworkExtension

/// The content filter's control provider: can write to the shared container
/// and update the data provider's rules.
///
/// M0 skeleton. M3 uses it to log flows the data provider defers to it.
final class FilterControlProvider: NEFilterControlProvider {
    override func startFilter() async throws {}

    override func stopFilter(with reason: NEProviderStopReason) async {}

    override func handleNewFlow(_ flow: NEFilterFlow, completionHandler: @escaping (NEFilterControlVerdict) -> Void) {
        completionHandler(.allow(withUpdateRules: false))
    }
}
