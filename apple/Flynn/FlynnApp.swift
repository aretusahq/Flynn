import FlynnKit
import SwiftUI

@main
struct FlynnApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

/// Placeholder until the M6 screens. Shows that the Rust core is linked and
/// which App Group the app sees.
struct ContentView: View {
    private let container = SharedContainer.appGroup()

    var body: some View {
        NavigationStack {
            List {
                Section("Core") {
                    LabeledContent("Version", value: coreVersion())
                }
                Section("Shared container") {
                    if let container {
                        Text(container.root.path(percentEncoded: false))
                            .font(.footnote.monospaced())
                            .textSelection(.enabled)
                    } else {
                        Text("App Group unavailable. The app is not signed with the Flynn App Group.")
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Flynn")
        }
    }
}

#Preview {
    ContentView()
}
