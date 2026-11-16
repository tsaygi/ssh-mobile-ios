import SwiftUI

struct SessionsView: View {
    @Environment(SessionManager.self) private var sessions

    var body: some View {
        NavigationStack {
            List {
                if sessions.sessions.isEmpty {
                    ContentUnavailableView("No active sessions", systemImage: "terminal",
                                           description: Text("Connect to a host to start a session. Sessions stay open while you switch between them."))
                }
                ForEach(sessions.sessions) { session in
                    Button { sessions.presentedSession = session } label: {
                        HStack {
                            Circle().fill(color(session.state)).frame(width: 10, height: 10)
                            VStack(alignment: .leading) {
                                Text(session.title).font(.headline)
                                Text(subtitle(session)).font(.subheadline).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Image(systemName: "chevron.right").foregroundStyle(.tertiary)
                        }
                    }
                    .buttonStyle(.plain)
                    .swipeActions {
                        Button(role: .destructive) { sessions.close(session) } label: { Label("Close", systemImage: "xmark") }
                    }
                }
            }
            .navigationTitle("Sessions")
            .toolbar {
                if !sessions.sessions.isEmpty {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button("Close all", role: .destructive) { sessions.closeAll() }
                    }
                }
            }
        }
    }

    private func color(_ s: SSHSession.State) -> Color {
        switch s {
        case .connected: return .green
        case .connecting: return .yellow
        case .failed: return .red
        default: return .gray
        }
    }

    private func subtitle(_ s: SSHSession) -> String {
        switch s.state {
        case .connected: return "\(s.host.username)@\(s.host.hostname) · \(ByteCountFormatter.file.string(fromByteCount: Int64(s.bytesReceived))) received"
        case .connecting(let w): return w
        case .failed(let e): return e
        case .disconnected(let r): return r ?? "Disconnected"
        case .idle: return "Idle"
        }
    }
}
