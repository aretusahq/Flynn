# Flynn Plan

Oct 12, 2026 · @Kasun

## Summary

Flynn is feasible on every platform named, but capability is uneven. iOS and iPadOS come first: any iPhone or iPad gives domain-level visibility and blocking, and a supervised device adds per-app visibility and control, which a power user can set up on a Mac with Apple Configurator. Android can deliver almost the full set without that step, and desktop can match it.

- **What it is:** Flynn, a local-first network monitor and firewall that logs every connection a device makes, lets you investigate them in an explorer, and blocks or allows by app, domain, IP or port. Nothing leaves the device by default.
- **MVP:** Flynn on iOS and iPadOS with live capture, per-app logs, an explorer, allow-all and block-all modes, rules by app, domain, IP and port, lockdown and leak detection. It makes no outside connections at all: no account, no server, no API. Android follows in the next phase on the same shared core.
- **Biggest risks:** per-app attribution and blocking on iOS, Apple's rules for VPN apps on the App Store, Google Play's limits on anything that blocks ads, and block-all mode breaking the phone.
- **Status:** planning only, no code yet. Feasibility labels below come from existing apps and platform documentation checked on 12 October 2026.

## The name

Flynn, after Kevin Flynn in Tron (1982), the programmer who ends up inside the system and finally sees what it is really doing. A surname reads as someone working for you, which suits an app that asks to see every packet and then reports back. The other names in the category, NetGuard, Lockdown and Portmaster, all sound like perimeter defence.

Four constraints come with it.

- **Keep the reference in the name alone.** Tron is Disney's. No neon grid, light-cycle geometry, "End of Line", Master Control Program or Flynn's Arcade anywhere in the branding, or a generic surname becomes a deliberate evocation of their property.
- **Check availability before committing.** An open-source PaaS held flynn.io until it wound down a few years ago, so the obvious domains are probably gone. Fallbacks to try: flynn.app, getflynn.com.
- **Protection is narrow.** A common surname is weak trademark material, and search results will mix with Errol, Gillian and Michael Flynn.
- **Never label anything MCP.** It now means Model Context Protocol, so it would confuse a technical audience twice over.

### What the name checks found

Checked on 12 October 2026. The name is usable but not clean, and one registration deserves a closer look before any money goes into branding.

- **A live US registration covers FLYNN for software.** Prime Directive, Inc., the company behind the Flynn PaaS, holds it in class 9 for tools that deploy, scale, monitor and manage applications, with the Section 8 declaration accepted in January 2021 ([USPTO record](https://trademarks.justia.com/862/63/flynn-86263562.html)). Two things soften it: it sits on the Supplemental Register, which carries weaker rights than the Principal Register, and the goods are developer infrastructure rather than a consumer security app. Worth checking whether the ten-year renewal was filed in late 2024, since the project shut down in 2021.
- **A second class 9 filing is dead.** FLYNN Inc.'s application for mobile apps went abandoned in 2019 for no statement of use.
- **flynn.io is taken** and still serves the old PaaS marketing page, although [the repository was archived in September 2021](https://github.com/flynn/flynn).
- **Not checked from here:** domain registration status for the alternatives, and app names in either store. App Store names are reserved in App Store Connect, so claim one early; Google Play allows duplicates but a crowded name hurts search.

Before committing: a clearance search by a trademark attorney covering the territories you will sell in, the renewal check above, and a reserved App Store Connect name.

## Requirements

The app must log all device traffic, let you control it with simple rules, and make investigation easy on every platform you target.

**Stated on 12 October**

- **Platforms:** Android, iOS and iPadOS first. macOS, Windows and Linux later if possible. The order has since been decided: iOS and iPadOS, then Android, then desktop (see Open decisions).
- **Default modes:** a choice between block-all and allow-all by default.
- **Rules:** block or allow by domain, app, host and IP, plus custom rules.
- **Logging:** every request, incoming and outgoing, with an explorer to investigate, filter, block, allow and set alerts. It must be easy to read.
- **Detection:** flag suspicious connections for review, and identify trackers and malware.
- **Depth:** URLs, headers and bodies for advanced investigation where possible.
- **Insight:** a live view and statistics, including data usage where possible.
- **Coverage:** log every request and let the user allow or block it, whether or not it passes through the tunnel.
- **Other channels:** identify requests made over Bluetooth, NFC and similar, as far as the platform allows.
- **Nothing silent:** whatever Flynn cannot block, it must still log. A blind spot becomes an entry that names itself.
- **Works plain, better supervised:** the app must work out of the box on an ordinary iPhone or iPad, and unlock full per-app tracking once the device is supervised.

**Added from our review, to confirm**

- **Custom rules:** field-based matching with wildcards, with regex kept for URL and path rules on decrypted traffic.
- **Safer modes:** ask mode, learning mode, log-only mode, an essentials allow-list and a panic button.
- **Rule tooling:** simulate a rule on past logs, profiles and schedules, and one filter syntax for search and rules.
- **Data handling:** encrypted local storage, export to JSON, CSV, PCAPNG and HAR, and an optional desktop explorer with sync.
- **Offline first:** the app installs and works with no outside service. Anything that needs a connection is a separate add-on the user turns on one at a time.

## Feasibility by platform

Every platform except Apple's mobile ones is proven by a shipping app. Only iOS and iPadOS are constrained, by Apple's deployment and App Store rules.

Status key: **Proven** means an existing app ships it. **Feasible** means the platform documents the capability. **Constrained** means it works only within the stated limits. **Blocked** means the platform prevents it. **Unverified** means not yet tested.

| Platform | Capture route | What you get | Constraints | Status |
| --- | --- | --- | --- | --- |
| Android | VpnService local tunnel. The user approves a consent dialog, and only one VPN service can be active per user or profile ([Android docs](https://developer.android.com/develop/connectivity/vpn)). | All-app traffic. Per-app attribution through a connection-owner lookup on Android 10 and newer, with a `/proc` fallback below ([Rethink README](https://github.com/0xlne/rethink-app)). Blocking by app, domain, IP and port. | Play Console VpnService declaration and in-app disclosure ([Play policy](https://support.google.com/googleplay/android-developer/answer/12564964?hl=en)). No second VPN alongside it. | Proven. PCAPdroid, NetGuard and RethinkDNS ship it. |
| iOS and iPadOS | Packet tunnel app extension, iOS 9 and newer. Content filter extension on supervised devices, on Screen Time child devices, or per-app on managed devices ([Apple TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment.md)). | Domains, IPs and bytes through the tunnel, plus domain and IP blocking. Per-app attribution and blocking only through the content filter, so only on supervised or managed devices. App Privacy Report import gives per-app domain lists for the past 7 days ([Apple Support](https://support.apple.com/102188)). | Apple DTS says local-only packet processing is not a supported packet tunnel use, because tunnels are meant for VPNs with a server ([Apple forums](https://developer.apple.com/forums/thread/844482)). Lockdown and Proxyman ship local tunnels anyway ([Cult of Mac](https://www.cultofmac.com/how-to/lockdown-open-source-ios-firewall), [Proxyman docs](https://docs.proxyman.com/proxyman-ios)). A paid Developer Program membership is needed, with no entitlement approval step ([Apple forums](https://developer.apple.com/forums/thread/819032)). Extension memory limits still to verify. | Constrained. |
| macOS | Content filter in a system extension, distributable on the App Store or with Developer ID ([Apple TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment.md)). Each flow is a connection opened by an app and can be passed, blocked or paused ([Apple docs](https://developer.apple.com/documentation/networkextension/nefilterdataprovider.md)). | Per-app visibility and blocking. Ask prompts by pausing a flow until the user decides. | LuLu is free and open source, alerts on each new outgoing connection and keeps per-process rules, including wildcards. Entitlement requirements still to confirm. | Proven. [LuLu](https://objective-see.org/products/lulu) and Little Snitch ship it. |
| Windows | Windows Filtering Platform user-mode API. Filters can apply per application, user and connection ([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/FWP/about-windows-filtering-platform)). | Per-app allow and block, plus connection monitoring. | Changing filters needs administrator rights. Inspecting or modifying payloads needs a kernel-mode callout driver. | Proven. [simplewall](https://github.com/henrypp/simplewall) ships it, and blocks every application by default. |
| Linux | nftables with process attribution through eBPF. OpenSnitch does this with a Go daemon and a GUI ([Linux Uprising](https://linuxuprising.com/2021/09/opensnitch-application-firewall-140.html)). | Per-process allow, block and prompt for each new connection. | Privilege requirements and distribution differences still to confirm. | Proven. OpenSnitch ships it. |

The Apple questions that decide the iOS design are listed under Risks and open decisions.

### Supervised mode on iOS and iPadOS

A power user can supervise their own device with Apple's free tools and no MDM server, which unlocks per-app attribution and blocking. Status: Feasible, documented but not tested end to end.

1. Install Apple Configurator on a Mac. It is free from the Mac App Store.
2. Connect the device by USB, choose Prepare and Manual Configuration, and tick supervision.
3. Choose "Do not enroll in Device Management". Only an organization name is required ([Apple guide](https://support.apple.com/guide/apple-configurator-mac/prepare-an-iphone-ipad-or-apple-tv-manually-cad99bc2a859/mac)). Expect the device to be erased and set up again.
4. Install the app from the App Store or TestFlight.
5. The app creates and enables its own content filter. Apple says filter configurations in distribution builds can be created only on supervised devices ([NEFilterManager](https://developer.apple.com/documentation/networkextension/nefiltermanager.md)), and iOS may ask the user to approve it.

The filter sees every app's flows, attributes them per app and can allow or block them. It cannot change other device settings, install apps or read inside encrypted traffic. Supervision lasts until the next wipe, and the app cannot remove it. Not yet tested: the full chain end to end, and App Review acceptance of an app whose filter works only on supervised devices.

There are three routes on iOS, and the spike should price all three. The **local packet tunnel** works on any device today but gives domains and IPs only, and Apple says it is not a supported use. **Supervision plus a content filter** gives per-app control and needs a wipe. The **Screen Time route** runs a content filter on a child device under Family Controls from iOS 15, with no VPN configuration at all, but it needs the family-controls entitlement approved by Apple before distribution and only fits a family setup ([Apple TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment.md)).

### One app, two levels

Flynn ships both extensions and works out which one it is allowed to use. On an ordinary iPhone or iPad it runs the packet tunnel: domains, IPs, bytes and timing, with rules by domain, IP and port. On a supervised device the content filter also becomes available, and with it per-app attribution and per-app rules. Nothing is reinstalled and nothing is bought; the same app simply sees more.

The app works out its own level rather than asking the user to declare it. No public API reports supervision to an ordinary app, so the likely method is to attempt to save a filter configuration and read the failure, which the spike has to confirm.

What matters more than the mechanism is saying so. The app states which level it is running at, and the gap log carries the reason: on an unsupervised device, "app names are unavailable because this device is not supervised" is an entry rather than a silence. Supervising then becomes an offer the user can take, with the wipe it requires stated plainly, instead of a prerequisite that keeps them out.

One experiment worth running early: whether both extensions can run at once, giving the filter's app names alongside the tunnel's packet detail. That would be the best of both, and it may cost more memory than the extension budget allows.

## What Flynn can cover

Full coverage is the goal, and three of the four layers are reachable. The fourth is closed by the operating system, so the plan names it rather than implying it away.

| Layer | What Flynn sees | What Flynn can do | Status |
| --- | --- | --- | --- |
| App traffic through the tunnel | App, domain, IP, port, bytes, timing | Allow, block, ask | Proven |
| App traffic that goes around the tunnel | That it happened: which app, how much, when. Not where it went | Block it, by forcing all traffic through the tunnel | Feasible |
| Traffic the OS never offers to any app | Not the traffic. The event and its reason: the phone joined this network, a call was active, a watch connected | Record it in the gap log and say why it is invisible | Blocked for capture, Unverified for the events |
| Non-IP radios: Bluetooth, NFC, Wi-Fi Direct | Connection events, where the platform exposes them | Log the event, alert, and offer the system setting that does stop it | Unverified |

### Catching what bypasses the tunnel

The kernel counts every byte each app sends on each interface, whether or not it crossed our tunnel. Flynn counts what did. A persistent difference between the two means traffic went around us, and that difference is the detection: the app, the volume and the timing, with no sight of the destination. On Android the per-app counters come from the usage-access permission the user grants in Settings. On iOS only device-wide interface counters are available, so there is no per-app attribution. Both need verifying in the spike.

This is an estimate, not an audit. The exempt traffic in the third row shows up in those counters too, so every device has a legitimate baseline gap that has to be calibrated, and header overhead and retransmits mean the two numbers never match exactly. It is a threshold that raises a flag, and the flag is worth having: no app we compared offers one.

Blocking that layer is a different mechanism and a solved one. Android's always-on VPN with lockdown lets a device policy controller "force applications to pass traffic through a specified VPN app that can't be bypassed", and if the tunnel drops, "traffic can't leak to the open Internet" ([Android docs](https://developer.android.com/work/dpc/network-telephony)). The user can switch that on by hand on any phone. Flynn can set it itself only as a device owner, which needs the phone enrolled as managed and so a factory reset: the Android counterpart of supervision on iOS, same price and same prize.

### What stays out of reach

Apple lists what no VPN receives, whatever its settings: network control plane traffic such as DHCP, captive portal negotiation, certain cellular services such as VoLTE, and traffic to a companion device such as a watch ([Apple docs](https://developer.apple.com/documentation/networkextension/nevpnprotocol/includeallnetworks)). Android does not publish an equivalent list, which is itself a finding for the spike. Calls and SMS sit here too.

Bluetooth, NFC and Wi-Fi Direct are not IP at all, so nothing in the tunnel design touches them. What a normal app can observe is connection events rather than content: that a Bluetooth device connected and which one, that Wi-Fi Direct peered, that NFC is switched on. It cannot read another app's Bluetooth payloads, cannot see another app's NFC exchanges, and cannot block any of it. Reading calls and SMS would need permissions that Google Play restricts to default handlers, and that would widen Flynn's own reach into exactly the data it promises not to collect, so the plan rules it out.

The result is a radio activity log that sits beside the connection log: event-level, context rather than traffic, with alerts as the only control. Treat every claim in this paragraph as Unverified. The Android reference pages did not confirm the specific broadcasts and permissions, so the spike settles what is actually observable.

### The gap log

The rule the rest of this follows: whatever Flynn cannot block, it logs. Where it cannot log the traffic, it logs the gap. Every blind spot becomes an entry that names itself, so the app never holds a silence it has not accounted for.

A gap entry carries three things: what happened, why Flynn could not see or stop it, and what would. "14:02, joined Wi-Fi network Hotel Guest. The sign-in exchange with the portal is not visible to any app. Flynn's own view starts once the network is validated." Or: "09:31 to 09:38, a voice call was active. Calls travel on the carrier network and never reach the tunnel." Or: "Bluetooth connected to Pixel Buds. Flynn cannot read or stop Bluetooth traffic. Turning Bluetooth off is the only control, and this opens that setting."

Most of these cost little: network attach and validation, captive portal state and Bluetooth connection events all arrive through callbacks the app needs anyway. Call state is the one that needs its own permission and its own decision, so the gap log should work without it and treat calls as an optional, numberless entry if that permission is ever added.

The second rule follows from the first: where something cannot be blocked, the interface never shows a dead Block button. It shows the reason and the system setting that would work, which keeps the app honest at the exact moment a user discovers a limit.

## Feature list

Of 42 features, 24 are proposed for the MVP, 16 for v1 and 2 for later; none is blocked outright, and 8 of the 24 MVP features are Constrained on an unsupervised iPhone or iPad. All 24 MVP features run with no outside connection. Anything that needs one is an add-on, listed under Connected add-ons.

Status uses the key under Feasibility by platform, where the sources are. Priority is a dropdown, so change it inline. Desktop covers macOS, Windows and Linux, and names a platform where they differ.

### Capture and logging

| Feature | Priority | Android | iOS and iPadOS | Desktop |
| --- | --- | --- | --- | --- |
| Live capture of all device traffic | MVP | Proven | Constrained: Apple does not support local-only packet tunnels | Feasible |
| Per-app attribution | MVP | Proven | Constrained: supervised or managed devices only. App Privacy Report import gives domains per app | Proven: OpenSnitch, LuLu and simplewall |
| Connection log with domain, IP, port, protocol, bytes and time | MVP | Proven | Feasible | Feasible |
| Domain name for every connection, from DNS and the TLS server name | MVP | Proven | Feasible | Feasible |
| Live view of connections as they happen | MVP | Proven | Feasible | Feasible |
| Encrypted local history with retention limits | MVP | Feasible | Feasible | Feasible |
| Resume capture after a reboot or after the app is killed | MVP | Feasible: always-on VPN and a boot receiver | Feasible: on-demand rules restart the tunnel | Feasible: a service or daemon |
| Leak detection: flag traffic that went around the tunnel | MVP | Feasible: per-app counters through the usage-access permission | Constrained: device-wide counters only, no per-app attribution | Feasible |
| Radio activity log: Bluetooth, NFC and Wi-Fi Direct events | v1 | Unverified: connection events only, no payloads, no blocking | Unverified: likely narrower than Android | Unverified |
| Gap log: record what Flynn cannot see or stop, and why | MVP | Feasible: network, portal and Bluetooth events through existing callbacks | Feasible: fewer event sources than Android | Feasible |

Incoming means replies to connections the device opened, plus their data volume. A phone behind NAT rarely receives unsolicited packets, which the first spike should confirm. Encrypted ClientHello and apps that run their own encrypted DNS can hide domain names, leaving only the IP address.

### Control and rules

| Feature | Priority | Android | iOS and iPadOS | Desktop |
| --- | --- | --- | --- | --- |
| Allow-all and block-all default modes | MVP | Proven | Constrained: domain and IP only, no per-app rules | Feasible |
| Full lockdown: block everything, essentials included | MVP | Feasible: drop every packet, with always-on VPN so nothing leaks if the tunnel dies | Feasible: the tunnel drops everything | Feasible: default deny with no exceptions |
| Rules by app | MVP | Proven | Constrained: supervised or managed devices only | Proven: OpenSnitch, LuLu and simplewall |
| Rules by domain and host, with wildcards | MVP | Proven | Proven ([Lockdown](https://www.cultofmac.com/how-to/lockdown-open-source-ios-firewall)) | Feasible |
| Rules by IP, CIDR range and port | MVP | Proven | Feasible | Feasible |
| Essentials allow-list and panic button | MVP | Feasible | Feasible | Feasible |
| Custom rules from fields: protocol, direction, country, tracker category | v1 | Feasible | Feasible | Feasible |
| Ask mode: prompt on a new connection | v1 | Feasible: a notification prompt while the connection waits | Constrained: only the content filter can pause a flow, so supervised or managed devices | Proven on Linux ([OpenSnitch](https://linuxuprising.com/2021/09/opensnitch-application-firewall-140.html)) and macOS, with LuLu |
| Learning mode: allow and log, then propose rules | v1 | Feasible | Feasible | Feasible |
| Rule tester: simulate a rule on past logs | v1 | Feasible | Feasible | Feasible |
| Profiles and schedules | v1 | Feasible | Feasible | Feasible |
| Per-network rules for Wi-Fi and mobile data | Later | Feasible | Unverified | Feasible |
| Always-on lockdown: block traffic when the tunnel is down | MVP | Feasible: Android's always-on VPN with block connections without VPN | Unverified: `includeAllNetworks` with on-demand rules, settled in the iOS spike | Not applicable, the firewall runs in the OS |

Lockdown is block-all with the essentials allow-list switched off, so it costs almost nothing to build once block-all works. Two honest limits: it does not stop calls or SMS, which never enter the tunnel, and it cannot catch traffic that bypasses the tunnel. What it gives over airplane mode is a record. Every attempt is still logged, so afterwards you can see exactly what the phone tried to do while it was sealed.

### Investigate

| Feature | Priority | Android | iOS and iPadOS | Desktop |
| --- | --- | --- | --- | --- |
| Explorer: filter, group and sort by app, domain, destination and time | MVP | Proven | Feasible | Feasible |
| Connection detail with app, domain, IP, ASN, country, bytes and timeline | MVP | Proven | Constrained: app field only on supervised or managed devices | Feasible |
| Block or allow from any log row | MVP | Proven | Feasible | Feasible |
| Alerts for blocked connections and new destinations | MVP | Feasible | Unverified: notifications from the tunnel extension untested | Feasible |
| One filter syntax shared by search and rules | v1 | Feasible | Feasible | Feasible |
| URL, header and body inspection through HTTPS interception | v1 | Constrained: only apps that trust user certificates, pinned apps bypass | Constrained: certificate installed and trusted by hand, pinned apps bypass ([Proxyman docs](https://docs.proxyman.com/proxyman-ios)) | Constrained: pinned apps bypass |
| Export to JSON, CSV, PCAPNG and HAR | v1 | Proven | Feasible | Feasible |

### Detection and insight

| Feature | Priority | Android | iOS and iPadOS | Desktop |
| --- | --- | --- | --- | --- |
| Tracker and ad identification and blocking, with company names, from bundled lists | MVP | Proven | Proven | Feasible |
| First-seen app and destination flags | MVP | Feasible | Constrained: app flags need supervision, destination flags work | Feasible |
| Data usage per app and domain, per day | MVP | Proven | Constrained: per-app bytes need supervision, per-domain works | Feasible |
| Review queue for flagged connections | v1 | Feasible | Feasible | Feasible |
| Malware and phishing domain feeds, an add-on, licences to check | v1 | Feasible | Feasible | Feasible |
| Behavioural detections: beaconing, random-looking domains, off-screen traffic | v1 | Unverified | Unverified | Unverified |
| GeoIP and ASN enrichment | v1 | Feasible | Feasible | Feasible |

### Platform and data

| Feature | Priority | Android | iOS and iPadOS | Desktop |
| --- | --- | --- | --- | --- |
| Consent and disclosure screens for the VPN and extension permissions | MVP | Proven | Feasible | Feasible |
| Supervised mode: guided setup and filter check | v1 | Not applicable | Feasible: Apple Configurator supervises the device with no MDM server, then the app enables its own content filter. Not tested end to end | Not applicable |
| Desktop explorer with optional encrypted sync | Later | Feasible | Feasible | Feasible |
| Back up and restore rules and settings | v1 | Feasible | Feasible | Feasible |
| Device owner mode: set always-on lockdown without the user in Settings | v1 | Feasible: needs the phone enrolled as managed, so a factory reset | Not applicable: supervision is the equivalent | Not applicable |

## MVP scope

The MVP is Flynn on iOS and iPadOS, capturing, logging and controlling traffic on one device. It works on any iPhone or iPad out of the box, and unlocks per-app visibility and control once the device is supervised. It makes no outside connections, so the whole MVP works in airplane mode apart from the traffic it watches. It covers the 24 features marked MVP in the feature list and proves the shared core before Android and desktop build on it.

iOS and iPadOS go first because a core written to fit inside an iOS extension runs anywhere, and one written for Android first does not. Android is the only platform where every stated requirement is already proven by shipping apps, which makes it the safer second step: it follows on the same core with a new capture shell and UI, not a port.

### Left out of the MVP

- **Android app.** It follows in the next phase on the same core, which is written under the tighter iOS memory limits so that it ports without a rewrite.
- **HTTPS interception** with URL, header and body inspection. It needs certificate handling and a pinned-app bypass, so it ships in v1.
- **Smarter rules:** ask mode, learning mode, custom field rules, the rule tester, profiles and schedules.
- **Deeper detection:** malware feeds, behavioural detections, the review queue and GeoIP and ASN enrichment.
- **Reach:** export, desktop explorer and sync, and per-network rules.
- **Anything that needs a connection:** every add-on in the next section, including list updates. The MVP ships with its tracker, company, GeoIP and ASN lists bundled in the app.

### Proposed checks for done

These are proposals to confirm, not agreed targets.

| Check | Pass condition |
| --- | --- |
| Attribution | On the supervised iPad, with 10 common apps open in turn, every logged connection names the right app. On the unsupervised iPhone, the gap log says why app names are missing. |
| Rules | A block rule by app, domain, IP and port each stops its matching traffic without restarting the tunnel. |
| Block-all safety | Block-all mode leaves the phone usable through the essentials allow-list, and the panic button restores traffic in one tap. |
| Stability | Capture runs 24 hours on a test phone without the tunnel dropping. Battery cost is measured and recorded. |
| Explorer | A known test connection can be found by filter, opened and blocked from its row. |
| Privacy | History is encrypted at rest, and the app makes no network requests of its own. |
| Install | A development-signed build installs and runs on both test devices: an unsupervised iPhone and a supervised iPad. The first release is for personal use, so App Store review is out of the MVP. |
| Storage | A day of ordinary use produces a log the phone can hold comfortably, and the default retention keeps the database bounded without the user touching it. |
| Performance | Throughput, battery over 24 hours, steady-state memory and log growth are all measured against a baseline with Flynn off, and the figures are written down before the iOS design is committed. |

## Connected add-ons

Everything that needs a connection is an add-on the user turns on one at a time, each with its own switch, its own explanation of what leaves the device, and an off state that is the default. Nothing here is gated behind a payment. The last column is what each one costs the project to run, which is what funding has to cover.

| Add-on | What it connects to | What leaves the device | What it costs the project |
| --- | --- | --- | --- |
| Blocklist and tracker list updates | A list host, or the list projects directly | A download request, no logs | Bandwidth |
| Malware and phishing feeds | A feed provider | A download request, or domain lookups if the feed is queried live | Licence fees, the one real cost |
| GeoIP and ASN updates | Public routing and registry data, or a database provider | A download request | Bandwidth |
| Encrypted sync to the desktop explorer | Our sync service, or storage the user owns | Encrypted logs | Hosting |
| Shared rules across several devices | Our service | Rules, and optionally alerts | Hosting |
| Scheduled audit reports | Email or file delivery | The report | Little |
| Threat intelligence lookups on one connection | A lookup service, on demand | The one domain or IP the user asks about | Per-query fees |
| Crash reports | Our own endpoint | Crash traces, no connection logs | Little |

The rule for all of them: the app never sends a connection log anywhere unless the user turns on an add-on that says it does. Nothing in the app is withheld pending payment, connected or local.

Every feature in this plan is free, which is more than [PCAPdroid](https://github.com/emanuele-f/PCAPdroid), [NetGuard](https://github.com/M66B/NetGuard) and [Lockdown](https://www.cultofmac.com/how-to/lockdown-open-source-ios-firewall) give away.

## Licence and funding

Flynn is fully open source and nothing in it is sold. What funding has to cover is the running cost of the add-ons above, so the money sits beside the project rather than inside the app.

### Picking a licence

The App Store is the constraint. VLC was pulled from it in 2011 after one of its own developers objected that the GPL's terms "are contradicted by the products usage rules of the App Store" ([InformationWeek](https://www.informationweek.com/it-leadership/apple-pulls-vlc-player-from-app-store)). A sole copyright holder can grant an App Store exception, but that lasts only while they hold all the copyright, so in practice it means a contributor licence agreement, which deters the contributors an open privacy tool most wants. It is probably not a coincidence that NetGuard, OpenSnitch and simplewall are all GPL and none of them ships on an Apple platform.

Proposal: **MPL-2.0**. File-level copyleft, so a modified Flynn must publish its changes to the files that matter, with no CLA and no App Store conflict. Apache-2.0 is the alternative if reach matters more than protection.

### What open source does not fix

The data licences are unchanged, and two obvious sources are ruled out. Tracker Radar's data is noncommercial only, and a noncommercial dataset in the repository would restrict everyone who redistributes it ([Tracker Radar README](https://github.com/mainzelM/tracker-radar/blob/main/README.md)). GeoLite2 cannot be bundled into a shipped app: its agreement says "you will not disclose the Services to any third party" beyond what its Creative Commons terms allow, and obliges you to destroy old copies within 30 days of an update ([MaxMind EULA](https://www.maxmind.com/en/geolite2/eula)). And the obvious malware and phishing source says commercial use "may require a paid subscription, which will be managed by Spamhaus", limits free access to "not-for-profit purposes", and requires consent for derivative works ([abuse.ch terms](https://abuse.ch/terms-of-use/)).

So feeds are the one genuinely expensive add-on, and the only one whose cost is somebody else's price rather than our hosting bill. Two alternatives to settle before the bundled-data design hardens: build ASN and country from public routing and registry data rather than licensing a database, and prefer share-alike blocklists that permit commercial use. The MVP's connection detail shows ASN and country from bundled data, so this choice has to be made before that store is built. The leading candidate for ASN and country is iptoasn.com, which is public domain. The tracker and company list is still to choose.

### Pay what you want

Money stays out of the app. It is free, has no purchases, no account, and works forever without contacting us. Support is collected on a separate site, and any add-on needing a key accepts one the user pastes in.

Three reasons beyond principle:

- Apple's in-app purchase tiers cannot express an arbitrary amount, so pay-what-you-want is not buildable inside the app.
- The F-Droid build then behaves identically to the store build, with no payment code to strip out.
- A free app with no purchases is the simplest thing App Review can look at, which is worth something given the 5.4 risk.

What makes it work rather than merely exist:

- **A customer-chosen amount** with a minimum and a suggested default, which Stripe Checkout supports directly. Recurring arbitrary amounts are awkward in every processor, so a few preset monthly tiers sit beside the free-form one-off.
- **Published costs.** Pay-what-you-want without an anchor collects very little. "This costs so much a month to run, this many people cover it, here is the ledger" collects far more, and Open Collective is built for exactly that.
- **Anonymous by construction:** a random account number, no email, payment details never touching our systems. A privacy app that builds a customer profile to take money has argued against itself.
- **Check the processor's country coverage** against whichever entity collects, before the rest is designed around it.

## Architecture and stack

Each OS gets a thin native capture layer and every decision happens in one shared core, so a rule written once works on every platform.

&#91;embedded content: architecture · 3 layers, MVP path marked\]

Capture reports each connection up to the core, and the core answers allow, block or ask. Both apps read the core's local store, and the desktop explorer gets a synced copy. The core makes no network requests of its own, so every outside call belongs to an add-on the user switched on.

### Stack choices

| Layer | Proposed choice | Reason |
| --- | --- | --- |
| Shared core | Rust, to confirm | One rule engine, flow tracker and log format on every platform. |
| Android capture | Kotlin VpnService with a userspace TCP and UDP forwarder | Study the forwarders in [PCAPdroid](https://github.com/emanuele-f/PCAPdroid) and [Rethink](https://github.com/0xlne/rethink-app) before writing our own. |
| Apple capture | Swift Network Extension: packet tunnel everywhere, content filter on macOS and on supervised or managed devices | Matches the capture routes in the feasibility table. |
| Windows and Linux capture | Windows Filtering Platform; nftables with eBPF | [OpenSnitch](https://linuxuprising.com/2021/09/opensnitch-application-firewall-140.html) shows the Linux route works. |
| Storage | Encrypted SQLite on the device | Nothing leaves the device by default. |
| Enrichment data | Bundled tracker, company, GeoIP and ASN lists | Updated only when the user allows it. |
| Desktop explorer and sync | To decide | Depends on the core language and on whether sync is wanted early. |

### Why those choices

**Rust rather than Go.** The deciding constraint is the iOS extension memory cap, not taste. A garbage-collected runtime costs several megabytes before any of our code runs, and collection timing is not ours to control, which is a poor bet against a hard ceiling. Rethink uses Go through gomobile, and Rethink is Android-only.

**Rust rather than C.** The core parses hostile input — packet headers, DNS responses and TLS ClientHellos from anywhere — inside a privileged network path. That is the worst place to be memory-unsafe. PCAPdroid's zdtun is C, and it is also Android-only.

**The userspace TCP stack cannot be deferred.** A tunnel interface hands over raw IP packets, and sending anything out means opening our own sockets, which means terminating each TCP connection locally and opening a matching one outbound. That is why PCAPdroid carries zdtun and Rethink embeds a network stack. It is needed even for the MVP, where we only log and gate; TLS interception adds to it later but is not what creates the need. In Rust the candidate is smoltcp. This is the highest-risk component in the build, and the spike should prove it carrying real traffic rather than proving the permission flow, which is the easy part.

**The core splits in two across the extension boundary.** A lean data plane inside the extension that parses and decides, and a fatter library in the app process for history, enrichment and the explorer. Nothing that grows with traffic belongs inside the extension.

**Native UI on both platforms.** Cross-platform UI is tempting for one developer, but these are dense live lists, platform conventions carry weight in a trust-sensitive app, and the tunnel needs native code regardless. A cross-platform layer buys the easy half and complicates the hard half.

**Two-tier retention from the first schema.** Raw events for days, rolled-up aggregates for months. A busy device makes thousands of connections an hour, and the home screen's daily totals must not be computed by scanning raw rows.

**UniFFI for the bindings**, generating Kotlin and Swift from one interface definition, with cargo-ndk for Android and an XCFramework for Apple platforms.

### Codebase layout: iOS first, Android-ready

iOS ships first, but the codebase is laid out so Android needs a new capture shell and a new UI, not a port of the core. The core holds no Apple types and is compiled for Android from the first commit, so a portability break fails the build at once. Platform differences sit behind a few small interfaces the host implements: packet I/O, a socket-protect hook (a no-op on iOS, `VpnService.protect()` on Android), app attribution, storage paths, clock and notifications. App identity, the event spool, the rule snapshot and the database schema are platform-neutral and versioned. Explorer queries, filter parsing, rule compilation and capability flags live in the core, so the native UI only renders. Shared packet captures with expected results act as the conformance suite every capture shell must pass. The full layout and milestones are in [development-plan.md](development-plan.md).

## Performance and battery

The cost depends almost entirely on one decision: how much traffic passes through userspace. Blocking is nearly free, and watching is what costs.

- **Routing alone is cheap.** On Android, an app the user has fully blocked or fully allowed can be left out of the tunnel, so its packets never reach our code and cost nothing per packet. NetGuard works this way by default and says it "will hardly use any battery power" ([NetGuard FAQ](https://github.com/M66B/NetGuard/blob/master/FAQ.md)).
- **Inspection is where the cost is.** Logging every connection means each packet is copied into the app, reassembled and sent out again. NetGuard flags exactly these settings, IP filtering and logging, as the ones that add drain, and says the cost depends on the quality of the tunnel implementation and the device's processor. On older devices it warns the drain "might be unacceptable". Flynn needs this mode for its whole premise, so the forwarder's efficiency is the single most important piece of engineering in the MVP.
- **No published throughput figures exist** for any of the apps we checked, so ours have to be measured rather than estimated. The MVP check covers it.

### The iOS memory ceiling

Apple's developer support gives hard limits per extension type, and they moved recently ([Apple forums](https://developer.apple.com/forums/thread/73148)).

| Extension | Up to iOS 14 | iOS 15 | iOS 16 and later |
| --- | --- | --- | --- |
| Packet tunnel | 15 MiB | 50 MiB | 50 MiB |
| Filter data provider | 6 MiB | 6 MiB | 50 MiB |
| Filter control provider | 12 MiB | 12 MiB | 50 MiB |

Apple says not to hard-code these and to test across devices, and one developer reported a packet tunnel killed at about 12 MB on iOS 17. The design consequence holds either way: the extension stays small and does one job, parse and decide, while history, enrichment and the explorer live in the app. Nothing that grows with traffic belongs inside the extension.

### A problem that is not engineering

Android credits a VPN app with the battery and data usage of every app whose traffic passes through it, so Flynn will appear in the battery screen with a number it did not cause. NetGuard's FAQ raises the same complaint. Users uninstall over that number. Flynn should show its own measured cost inside the app and explain the attribution plainly, rather than letting the system screen make the argument.

### Levers if the measurements come back badly

Leave fully decided apps out of the tunnel; collapse repeated connections to the same destination into one row with a counter instead of logging each; batch writes to the database; slow the live view when the screen is off; and make full packet capture something the user turns on for a session rather than the default.

## Roadmap

Three phases run in order: the iOS and iPadOS MVP, then Android and v1, then desktop and the later features.

&#91;embedded content: roadmap · 3 phases, 1 gate\]

Each phase inherits the core from the one before, which is why the order matters: a core written to fit inside an iOS extension runs anywhere, and one written for Android first does not. No dates are set yet.

## Risks and open decisions

The biggest unknown is whether Apple tolerates a local-only packet tunnel on iOS. Every other risk has a workable fallback.

| Risk | Why it matters | Fallback |
| --- | --- | --- |
| iOS local-only tunnel | Apple DTS says packet tunnels are meant for VPNs with a server ([Apple forums](https://developer.apple.com/forums/thread/844482)), though Lockdown and Proxyman ship local ones. App Review or a later iOS release could pull it. | Test it in the spike through TestFlight first. If it fails, fall back to App Privacy Report import and a content filter on supervised devices. |
| iOS per-app control | Per-app attribution and blocking need the content filter, which runs only on supervised or managed devices ([Apple TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment.md)). | Offer domain-level control to everyone and per-app control on supervised or managed devices. |
| Google Play VPN policy | VpnService apps need a Play Console declaration and an in-app disclosure, and the policy bars using VpnService to "redirect or manipulate user traffic from other apps on a device for monetization purposes" ([Play policy](https://support.google.com/googleplay/android-developer/answer/12564964?hl=en)). The declaration form adds that any manipulation of ads affecting monetization will be rejected. Tracker and ad blocking sits close to that line: TrackerControl's Play build is analysis only. | Declare under the permitted device security category, which names firewalls, and build the disclosure screens into the MVP. Keep an F-Droid or direct-APK build as the home for full blocking, as NetGuard and TrackerControl do. |
| Block-all breaks the phone | Blocking everything can cut notifications, captive-portal sign-in and other basics. | Start in allow-all, build rules from the log, and enable block-all only with the essentials allow-list and panic button in place. |
| Hidden destination names | Encrypted ClientHello, QUIC and apps with their own encrypted DNS can leave only an IP address. | Enrich the IP with ASN and company, and flag it as an unknown destination rather than hiding it. |
| HTTPS inspection limits | Pinned apps and apps that do not trust user certificates bypass interception. | Make it a per-app opt-in and mark such connections as not inspectable. |
| Battery and memory | A userspace forwarder costs battery on Android, and the cost lands on the one feature Flynn cannot drop. Android also blames the VPN app for other apps' battery and data use. | Measure against a baseline in the MVP check, keep the levers under Performance and battery in reserve, and show Flynn's own measured cost in the app so the system battery screen does not speak for us. |
| Sensitive logs | Logs, URLs and bodies hold private data. | Encrypted local storage, per-app opt-in for bodies, redaction of tokens, and no cloud sync by default. |
| Another VPN is active | Android allows one active VPN service per user or profile ([Android docs](https://developer.android.com/develop/connectivity/vpn)). | Detect it, explain that this app replaces it, and let the user switch back. |
| Supervision needs a wipe | Supervising a device erases it, so only users comfortable with Apple Configurator will do it. App Review acceptance of a filter that works only on supervised devices is untested. | Keep supervised mode optional, with the domain-level tunnel as the default, and test the review path in the iOS spike. |
| App Store organization rule | Guideline 5.4 says apps offering VPN services must use NEVPNManager and may only be offered by developers enrolled as an organization, and that content blocking and security apps from approved providers may also use it ([App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/)). A packet tunnel installs a VPN configuration, so App Review is likely to read Flynn as a VPN app. Approved provider is nowhere defined. | Enrol a registered company rather than an individual before the iOS build starts, and ask App Review in writing whether a local-only tunnel falls under 5.4. The Screen Time route avoids a VPN configuration entirely. |
| Claiming full coverage | The goal is to log and control every request, but one layer is permanently invisible to any app. A promise of total coverage would be false, and for a tool people trust with exactly this question, being caught overclaiming is worse than the gap itself. | Put the coverage table in the app, not only in this plan, and show per layer what is covered. Say plainly that calls, SMS and VoLTE are outside, and that leak detection reports volume rather than destinations. |

### Open decisions

- [x] **Scope:** decided on 12 October — iOS and iPadOS first, then Android, then desktop. The codebase is laid out so Android fits without a port; see Codebase layout.
- [x] **Your iOS devices:** decided on 19 October — an iPad that will be supervised with Apple Configurator for per-app work, and an iPhone left unsupervised for the packet tunnel level.
- [x] **Audience:** decided on 19 October — personal use first. Development-signed builds on our own devices; App Store and Google Play review, guideline 5.4 and organisation enrolment come later.
- [x] **Core:** decided on 19 October — a shared Rust core with native capture and native UI on each OS. Minimum OS is iOS and iPadOS 17.
- [ ] **HTTPS interception:** keep it in v1, or drop it given pinned apps and store review.
- [x] **Source model:** fully open source, decided on 12 October. Which licence is still open; see Licence and funding.
- [x] **Paid model:** closed — nothing in the app is sold (see Licence and funding). What remains open is which add-ons need a key the user pastes in.
- [ ] **Sync hosting:** do we run a sync service, or let the user point at their own storage? Running one brings costs, accounts and privacy duties.
- [ ] **Name checks:** a trademark attorney's clearance search, confirmation that the 2014 FLYNN registration was renewed in 2024, and a reserved App Store Connect name. First-pass findings are under The name.
- [ ] **Who it is for:** a technical audience who will read a connection log, or ordinary people who want a verdict. The plan currently assumes the first, which shapes the explorer, the defaults and the pricing.
- [ ] **Effort and timeline:** Claude Code writes the code end to end; the human plans and runs the device, signing and supervision steps. The period is still open. Twenty-four MVP features is a large first release, and the roadmap carries no dates. The milestone order is in [development-plan.md](development-plan.md).

## Competitive position and sources

None of the nine products we checked spans Android and iOS with one log format, per-app data, rules and an explorer; each covers part. The plan's edge is that combination, kept local-first, with dry-run and ask modes we did not find together in any of them.

| Product | Platform | Strongest at | Gap against this plan |
| --- | --- | --- | --- |
| [PCAPdroid](https://github.com/emanuele-f/PCAPdroid) | Android | Per-app log, IP and country, TLS decryption for chosen apps, PCAP, HAR and CSV export | Firewall and malware detection are paid. Takes the one VPN slot. |
| [RethinkDNS](https://www.rethinkdns.com/download) | Android | Per-app firewall, DNS logs and blocklists | Android only. No URL, header or body inspection found. |
| [NetGuard](https://github.com/M66B/NetGuard) | Android | Per-app rules for Wi-Fi and mobile data, access log, usage tracking | No VPN chaining. No inspection found. |
| [TrackerControl](https://github.com/TrackerControl/tracker-control-android) | Android | Tracker and company identification per app | One VPN at a time. The Play build is analysis only, with no blocking. |
| [Lockdown Privacy](https://www.cultofmac.com/how-to/lockdown-open-source-ios-firewall) | iOS | Open source domain blocking through an on-device VPN | Blocks by address for all apps, with no per-app control or inspection. |
| [Proxyman](https://docs.proxyman.com/proxyman-ios) | iOS | Full HTTP(S) URLs, headers and bodies | Pinned apps are unreadable, and it does not work alongside other VPN apps. |
| [App Privacy Report](https://support.apple.com/102188) | Built into iOS | Per-app domain lists | Read-only, domains only, last 7 days. |
| [Firewalla](https://firewalla.com/products/firewalla-gold) | Network hardware | Whole-network flows, rules and alerts | Cannot say which phone app made a request. |

The full 30-row comparison, with a source list per product, is in [Network Monitor Comparison](https://claude.ai/artifact/SG88pz5u9j1QmmKoGcL1dc).

### Sources

Checked on 12 October 2026. Product pages change, so confirm anything you plan to rely on with the vendor.

- **Platform rules:** [Android VPN docs](https://developer.android.com/develop/connectivity/vpn), [Google Play VpnService policy](https://support.google.com/googleplay/android-developer/answer/12564964?hl=en), [Apple TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment.md), [Apple NEFilterDataProvider](https://developer.apple.com/documentation/networkextension/nefilterdataprovider.md), [Apple NEFilterManager](https://developer.apple.com/documentation/networkextension/nefiltermanager.md), [Apple Configurator: prepare a device](https://support.apple.com/guide/apple-configurator-mac/prepare-an-iphone-ipad-or-apple-tv-manually-cad99bc2a859/mac), [Apple forums on local tunnels](https://developer.apple.com/forums/thread/844482), [Apple forums on entitlements](https://developer.apple.com/forums/thread/819032), [Apple forums on content filters](https://developer.apple.com/forums/thread/732385), [App Privacy Report](https://support.apple.com/102188), [Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/FWP/about-windows-filtering-platform), [OpenSnitch](https://linuxuprising.com/2021/09/opensnitch-application-firewall-140.html), [Rethink README](https://github.com/0xlne/rethink-app).
- **Existing products:** the links in the table above, plus the per-product lists in the comparison page.
