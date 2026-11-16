import SwiftUI

@main
struct SSHMobileApp: App {
    @State private var hostStore = HostStore()
    @State private var identityStore = IdentityStore()
    @State private var knownHosts = KnownHostsStore()
    @State private var sessions: SessionManager

    init() {
        if UITestMode.enabled { UIView.setAnimationsEnabled(false) }
        let hosts = HostStore(), ids = IdentityStore(), kh = KnownHostsStore()
        _hostStore = State(initialValue: hosts)
        _identityStore = State(initialValue: ids)
        _knownHosts = State(initialValue: kh)
        _sessions = State(initialValue: SessionManager(hostStore: hosts, identityStore: ids, knownHosts: kh))
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(hostStore)
                .environment(identityStore)
                .environment(knownHosts)
                .environment(sessions)
        }
    }
}

struct ContentView: View {
    @Environment(SessionManager.self) private var sessions

    var body: some View {
        @Bindable var sessions = sessions
        TabView {
            HostListView()
                .tabItem { Label("Hosts", systemImage: "server.rack") }
            SessionsView()
                .tabItem { Label("Sessions", systemImage: "terminal") }
                .badge(sessions.sessions.count)
            IdentitiesView()
                .tabItem { Label("Keys", systemImage: "key") }
            SettingsView()
                .tabItem { Label("Settings", systemImage: "gearshape") }
        }
        .fullScreenCover(item: Binding(
            get: { sessions.presentedSession },
            set: { sessions.presentedSession = $0 })
        ) { session in
            TerminalScreen(session: session)
        }
    }
}

/// Set by the UI tests (`-uiTesting` launch argument). Turns off the few perpetual animations
/// that otherwise keep XCUITest waiting for the app to become idle.
enum UITestMode {
    static let enabled = CommandLine.arguments.contains("-uiTesting")
}
