import Foundation
import Testing
@testable import FlynnKit

struct TunnelOptionsTests {
    @Test func survivesProviderConfigurationRoundTrip() {
        var options = TunnelOptions()
        options.mode = .lockdown
        options.rulesText = "block subdomains ads.example\n"
        options.panic = true
        options.recvBufferKiB = 64
        options.onDemand = true
        let restored = TunnelOptions(providerConfiguration: options.providerConfiguration())
        #expect(restored == options)
    }

    @Test func olderSavedOptionsKeepTheirValuesAndDefaultNewFields() throws {
        let old = Data(#"{"mode":"lockdown","blockedDomains":["a.test"],"recvBufferKiB":64,"sendBufferKiB":32,"includeAllNetworks":false,"enforceRoutes":false,"onDemand":true,"useVirtualDNS":false,"upstreamDNS":""}"#.utf8)
        let decoded = try JSONDecoder().decode(TunnelOptions.self, from: old)
        #expect(decoded.mode == .lockdown)
        #expect(decoded.onDemand)
        #expect(decoded.forceTCPForUnnamedQUIC == false)
    }

    @Test func forceTCPMapsToForwarderSettings() {
        var options = TunnelOptions()
        options.forceTCPForUnnamedQUIC = true
        #expect(options.forwarderSettings().forceTcpForUnnamedQuic)
    }

    @Test func missingConfigurationGivesDefaults() {
        #expect(TunnelOptions(providerConfiguration: nil) == TunnelOptions())
    }

    @Test func mapsToForwarderSettings() {
        var options = TunnelOptions()
        options.mode = .blockAll
        options.sendBufferKiB = 128
        let s = options.forwarderSettings()
        #expect(s.tcpSendBufferKib == 128)
        #expect(s.dnsRedirect == nil)
    }

    @Test func virtualDNSRedirectsToUpstream() {
        var options = TunnelOptions()
        options.useVirtualDNS = true
        options.upstreamDNS = "192.168.1.1"
        #expect(options.forwarderSettings().dnsRedirect == DnsRedirect(virtualAddr: "10.111.0.53:53", upstream: "192.168.1.1:53"))
        options.upstreamDNS = "fe80::1"
        #expect(options.forwarderSettings().dnsRedirect?.upstream == "[fe80::1]:53")
    }

    @Test func oldBlockedDomainsMigrateIntoRulesTextOnce() {
        var options = TunnelOptions()
        options.blockedDomains = ["tracker.test"]
        options.migrateBlockedDomains()
        #expect(options.blockedDomains.isEmpty)
        #expect(options.rulesText.contains("block subdomains tracker.test"))
        let migrated = options.rulesText
        options.blockedDomains = ["other.test"]
        options.migrateBlockedDomains()
        #expect(options.rulesText == migrated)
    }

    @Test func controlsOverrideTheTextAndMistakesNameTheLine() throws {
        var options = TunnelOptions()
        options.rulesText = "mode lockdown\nblock any port 25\n"
        options.mode = .blockAll
        options.panic = true
        let config = try options.rulesConfig()
        #expect(config.mode == .blockAll)
        #expect(config.panic)
        #expect(config.rules.count == 1)

        options.rulesText = "block any\nfrobnicate\n"
        #expect(throws: (any Error).self) { try options.rulesConfig() }
        do { _ = try options.rulesConfig() } catch { #expect(explain(error).contains("line 2")) }
    }

    @Test func aSnapshotIsWrittenAndReadBack() throws {
        let path = FileManager.default.temporaryDirectory
            .appending(path: "flynn-rules-\(UUID().uuidString)/rules.snapshot").path
        var options = TunnelOptions()
        options.rulesText = "block subdomains tracker.test\nallow domain ok.test tcp port 443\n"
        options.mode = .blockAll
        try writeRuleSnapshot(path: path, config: options.rulesConfig(), generation: 9)
        let info = try #require(try readRulesInfo(path: path))
        #expect(info.generation == 9)
        #expect(info.ruleCount == 2)
        #expect(info.mode == .blockAll)
    }
}
