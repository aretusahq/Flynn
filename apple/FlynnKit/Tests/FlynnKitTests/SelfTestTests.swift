import Testing
@testable import FlynnKit

struct SelfTestTests {
    /// The same checks the free-team test build shows on the phone, run on
    /// whatever platform the tests run on.
    @Test func coreSelfTestPassesOnThisPlatform() {
        let results = CoreSelfTest.run()
        let failed = results.filter { !$0.passed }
        #expect(results.count == 7)
        #expect(failed.isEmpty, "failed: \(failed)")
    }

    @Test func reportListsEveryCheck() {
        let report = CoreSelfTest.report([
            SelfTestResult(name: "a", passed: true, detail: "fine"),
            SelfTestResult(name: "b", passed: false, detail: "broken"),
        ])
        #expect(report.contains("PASS  a"))
        #expect(report.contains("FAIL  b"))
        #expect(report.contains("1 of 2 checks FAILED"))
    }
}
