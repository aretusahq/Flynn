import Foundation
import Testing
@testable import FlynnKit

struct TunnelOptionsTests {
    @Test func survivesProviderConfigurationRoundTrip() {
        var options = TunnelOptions()
        options.mode = .lockdown
        options.blockedDomains = ["ads.example"]
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
        options.blockedDomains = ["tracker.test"]
        options.sendBufferKiB = 128
        let s = options.forwarderSettings()
        #expect(s.mode == .blockAll)
        #expect(s.blockedDomains == ["tracker.test"])
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
}
