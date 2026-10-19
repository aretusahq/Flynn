# Fixtures

Packet captures and their expected results, shared by every platform. Each
capture shell (the iOS tunnel, later the Android VpnService) must reproduce
the same flows and verdicts from the same input.

Layout, from M1:

    <name>.pcap            input traffic
    <name>.rules           rule set applied during replay
    <name>.expected.json   flows, names and verdicts the core must produce

Captures must contain no personal traffic. Generate them against test hosts
or scrub them before committing.
