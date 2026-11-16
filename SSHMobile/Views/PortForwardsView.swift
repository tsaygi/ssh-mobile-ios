import SwiftUI

struct PortForwardsView: View {
    let session: SSHSession
    @Environment(\.dismiss) private var dismiss
    @State private var adding = false

    var body: some View {
        NavigationStack {
            List {
                if session.host.portForwards.isEmpty && session.forwardStates.isEmpty {
                    ContentUnavailableView("No port forwards", systemImage: "point.3.connected.trianglepath.dotted",
                                           description: Text("Add -L, -R or -D forwards to this host, or start one for this session only."))
                }
                ForEach(session.host.portForwards) { f in
                    row(f)
                }
            }
            .navigationTitle("Port forwards")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } }
                ToolbarItem(placement: .topBarTrailing) { Button { adding = true } label: { Label("Add", systemImage: "plus") } }
            }
            .sheet(isPresented: $adding) {
                PortForwardEditor(forward: PortForward()) { f in session.startForward(f) }
            }
        }
    }

    private func row(_ f: PortForward) -> some View {
        let state = session.forwardStates[f.id]
        return HStack {
            VStack(alignment: .leading) {
                Text(f.summary).font(.body.monospaced())
                Text(state?.label ?? "Not started").font(.caption).foregroundStyle(color(state))
            }
            Spacer()
            if case .active = state {
                Button("Stop") { session.stopForward(f.id) }.buttonStyle(.bordered)
            } else {
                Button("Start") { session.startForward(f) }.buttonStyle(.bordered).disabled(!session.state.isConnected)
            }
        }
    }

    private func color(_ s: ForwardState?) -> Color {
        switch s {
        case .active: return .green
        case .failed: return .red
        case .starting: return .yellow
        default: return .secondary
        }
    }
}
