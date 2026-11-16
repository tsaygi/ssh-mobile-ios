import SwiftUI

/// Full-screen terminal for one session, with the host-key and credential prompts the
/// engine raises, plus access to SFTP, port forwards, one-off commands and the log.
struct TerminalScreen: View {
    @Bindable var session: SSHSession
    @Environment(SessionManager.self) private var sessions
    @State private var showingSFTP = false
    @State private var showingForwards = false
    @State private var showingCommand = false
    @State private var showingLog = false
    @State private var confirmClose = false

    var body: some View {
        NavigationStack {
            ZStack(alignment: .top) {
                TerminalContainer(session: session, theme: session.host.colorScheme, fontSize: session.fontSize)
                    .ignoresSafeArea(.container, edges: .bottom)
                statusBanner
            }
            .background(Color(uiColor: UIColor(hex: session.host.colorScheme.background)))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .principal) {
                    VStack(spacing: 0) {
                        Text(session.title).font(.headline).lineLimit(1)
                        Text(stateText).font(.caption2).foregroundStyle(stateColor).accessibilityIdentifier("sessionStatus")
                    }
                }
                ToolbarItem(placement: .topBarLeading) {
                    Button { sessions.presentedSession = nil } label: { Label("Hide", systemImage: "chevron.down") }
                }
                ToolbarItem(placement: .topBarTrailing) { menu }
            }
            .toolbarBackground(.visible, for: .navigationBar)
        }
        .alert(hostKeyTitle, isPresented: Binding(get: { session.hostKeyPrompt != nil }, set: { _ in }), presenting: session.hostKeyPrompt) { prompt in
            Button(prompt.isMismatch ? "Replace key and connect" : "Trust and connect", role: prompt.isMismatch ? .destructive : nil) { prompt.decide(true) }
            Button("Cancel", role: .cancel) { prompt.decide(false) }
        } message: { prompt in
            Text(hostKeyMessage(prompt))
        }
        .sheet(item: $session.credentialPrompt) { prompt in
            CredentialPromptView(prompt: prompt).interactiveDismissDisabled()
        }
        .sheet(isPresented: $showingSFTP) { SFTPBrowserView(session: session) }
        .sheet(isPresented: $showingForwards) { PortForwardsView(session: session) }
        .sheet(isPresented: $showingCommand) { CommandRunnerView(session: session) }
        .sheet(isPresented: $showingLog) { SessionLogView(session: session) }
        .confirmationDialog("Close this session?", isPresented: $confirmClose, titleVisibility: .visible) {
            Button("Disconnect and close", role: .destructive) { sessions.close(session) }
        }
    }

    private var menu: some View {
        Menu {
            Section {
                Button("SFTP files", systemImage: "folder") { showingSFTP = true }
                Button("Port forwards", systemImage: "point.3.connected.trianglepath.dotted") { showingForwards = true }
                Button("Run command", systemImage: "play.circle") { showingCommand = true }
                Button("Session log", systemImage: "list.bullet.rectangle") { showingLog = true }
            }
            .disabled(!session.state.isConnected)
            Section("Send") {
                Button("Paste", systemImage: "doc.on.clipboard") { if let s = UIPasteboard.general.string { session.send(text: s) } }
                Button("Ctrl+C", systemImage: "xmark.octagon") { session.send([0x03]) }
                Button("Ctrl+D (EOF)", systemImage: "arrow.right.to.line") { session.send([0x04]) }
                Button("Ctrl+Z", systemImage: "pause") { session.send([0x1a]) }
                Button("Ctrl+L (clear)", systemImage: "rectangle.dashed") { session.send([0x0c]) }
            }
            Section("Font") {
                Button("Larger", systemImage: "textformat.size.larger") { session.fontSize = min(28, session.fontSize + 1) }
                Button("Smaller", systemImage: "textformat.size.smaller") { session.fontSize = max(8, session.fontSize - 1) }
            }
            Section {
                if session.state.canReconnect {
                    Button("Reconnect", systemImage: "arrow.clockwise") { Task { await session.connect() } }
                } else {
                    Button("Disconnect", systemImage: "xmark.circle") { Task { await session.disconnect() } }
                }
                Button("Close session", systemImage: "trash", role: .destructive) { confirmClose = true }
            }
        } label: { Label("Actions", systemImage: "ellipsis.circle") }
    }

    @ViewBuilder private var statusBanner: some View {
        switch session.state {
        case .connecting(let what):
            HStack {
                if UITestMode.enabled { Image(systemName: "bolt.horizontal") } else { ProgressView() }
                Text(what)
            }
                .font(.footnote).padding(8).background(.thinMaterial, in: Capsule()).padding(.top, 8)
        case .failed(let why):
            Label(why, systemImage: "exclamationmark.triangle").font(.footnote).foregroundStyle(.red)
                .padding(8).background(.thinMaterial, in: Capsule()).padding(.top, 8)
        case .disconnected(let why?):
            Label(why, systemImage: "bolt.slash").font(.footnote).foregroundStyle(.orange)
                .padding(8).background(.thinMaterial, in: Capsule()).padding(.top, 8)
        default:
            EmptyView()
        }
    }

    private var stateText: String {
        switch session.state {
        case .idle: return "Idle"
        case .connecting: return "Connecting…"
        case .connected: return "\(session.host.username)@\(session.host.hostname) · \(session.cols)×\(session.rows)"
        case .disconnected: return "Disconnected"
        case .failed: return "Failed"
        }
    }

    private var stateColor: Color {
        switch session.state {
        case .connected: return .green
        case .connecting: return .secondary
        default: return .orange
        }
    }

    private var hostKeyTitle: String {
        session.hostKeyPrompt?.isMismatch == true ? "Host key has changed" : "Unknown host"
    }

    private func hostKeyMessage(_ p: SSHSession.HostKeyPrompt) -> String {
        if let prev = p.previousFingerprint {
            return "The \(p.keyType) key for \(p.hostname):\(p.port) differs from the one on file.\n\nStored: \(prev)\nPresented: \(p.fingerprint)\n\nThis can mean the server was reinstalled, or that someone is intercepting the connection."
        }
        return "The authenticity of \(p.hostname):\(p.port) can't be established.\n\n\(p.keyType) key fingerprint:\n\(p.fingerprint)"
    }
}

struct CredentialPromptView: View {
    let prompt: SSHSession.CredentialPrompt
    @State private var secret = ""
    @State private var remember = false
    @FocusState private var focused: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField(fieldLabel, text: $secret)
                        .accessibilityIdentifier("credentialSecret")
                        .focused($focused)
                        .onSubmit { prompt.submit(secret, remember) }
                    if case .password = prompt.kind {
                        Toggle("Remember in Keychain", isOn: $remember)
                    }
                } header: { Text(header) } footer: {
                    if let m = prompt.message { Text(m).foregroundStyle(.red) }
                }
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { prompt.submit(nil, false) } }
                ToolbarItem(placement: .confirmationAction) { Button("OK") { prompt.submit(secret, remember) }.disabled(secret.isEmpty).accessibilityIdentifier("credentialSubmit") }
            }
            .onAppear { focused = true }
        }
        .presentationDetents([.medium])
    }

    private var title: String {
        switch prompt.kind {
        case .password: return "Password"
        case .passphrase: return "Key passphrase"
        }
    }
    private var header: String {
        switch prompt.kind {
        case .password(let u, let h): return "\(u)@\(h)"
        case .passphrase(let k): return "Enter passphrase for key \"\(k)\""
        }
    }
    private var fieldLabel: String {
        switch prompt.kind {
        case .password: return "Password"
        case .passphrase: return "Passphrase"
        }
    }
}

struct SessionLogView: View {
    let session: SSHSession
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            List(session.events.reversed()) { e in
                VStack(alignment: .leading, spacing: 2) {
                    Text(e.message).font(.footnote.monospaced()).foregroundStyle(color(e.level))
                    Text(e.date, style: .time).font(.caption2).foregroundStyle(.tertiary)
                }
            }
            .navigationTitle("Session log")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }
    private func color(_ l: SessionEvent.Level) -> Color {
        switch l { case .info: return .primary; case .warning: return .orange; case .error: return .red }
    }
}
