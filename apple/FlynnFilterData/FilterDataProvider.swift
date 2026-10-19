@preconcurrency import NetworkExtension

/// The content filter's data provider: sees every flow with its source app,
/// on supervised devices only.
///
/// M0 skeleton that allows everything. M3 settles how flow records leave
/// this provider's sandbox (it cannot write files or open sockets).
final class FilterDataProvider: NEFilterDataProvider {
    override func startFilter() async throws {}

    override func stopFilter(with reason: NEProviderStopReason) async {}

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        .allow()
    }
}
