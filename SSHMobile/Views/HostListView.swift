import SwiftUI

struct HostListView: View {
    @Environment(HostStore.self) private var hostStore
    @Environment(SessionManager.self) private var sessions
    @State private var editing: HostProfile?
    @State private var showingQuickConnect = false
    @State private var search = ""

    private var filtered: [HostProfile] {
        let all = hostStore.hosts.sorted { ($0.lastConnected ?? .distantPast) > ($1.lastConnected ?? .distantPast) }
        guard !search.isEmpty else { return all }
        return all.filter {
            $0.displayName.localizedCaseInsensitiveContains(search) || $0.hostname.localizedCaseInsensitiveContains(search)
                || $0.tags.contains { $0.localizedCaseInsensitiveContains(search) }
        }
    }

    var body: some View {
        NavigationStack {
            List {
                if hostStore.hosts.isEmpty {
                    ContentUnavailableView("No hosts yet", systemImage: "server.rack",
                                           description: Text("Add a host, or use Quick Connect for a one-off session."))
                }
                ForEach(filtered) { host in
                    Button { sessions.open(host) } label: { HostRow(host: host) }
                        .buttonStyle(.plain)
                        .swipeActions(edge: .trailing) {
                            Button(role: .destructive) { hostStore.delete([host.id]) } label: { Label("Delete", systemImage: "trash") }
                            Button { editing = host } label: { Label("Edit", systemImage: "pencil") }.tint(.orange)
                        }
                        .contextMenu {
                            Button("Connect", systemImage: "terminal") { sessions.open(host) }
                            Button("Edit", systemImage: "pencil") { editing = host }
                            Button("Duplicate", systemImage: "doc.on.doc") {
                                var copy = host; copy.id = UUID(); copy.name = host.displayName + " copy"; copy.lastConnected = nil
                                hostStore.upsert(copy)
                            }
                            Button("Delete", systemImage: "trash", role: .destructive) { hostStore.delete([host.id]) }
                        }
                }
            }
            .searchable(text: $search, prompt: "Search hosts")
            .navigationTitle("Hosts")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button { showingQuickConnect = true } label: { Label("Quick Connect", systemImage: "bolt") }
                        .accessibilityIdentifier("quickConnectButton")
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button { editing = HostProfile() } label: { Label("Add", systemImage: "plus") }
                }
            }
            .sheet(item: $editing) { host in
                HostEditorView(host: host)
            }
            .sheet(isPresented: $showingQuickConnect) {
                QuickConnectView()
            }
        }
    }
}

struct HostRow: View {
    let host: HostProfile
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: host.jumpHostID != nil ? "arrow.triangle.branch" : "server.rack")
                .foregroundStyle(.tint)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(host.displayName).font(.headline)
                Text("\(host.username.isEmpty ? "?" : host.username)@\(host.hostname)\(host.port == 22 ? "" : ":\(host.port)")")
                    .font(.subheadline).foregroundStyle(.secondary)
                if !host.tags.isEmpty {
                    Text(host.tags.joined(separator: " · ")).font(.caption).foregroundStyle(.tertiary)
                }
            }
            Spacer()
            if !host.portForwards.isEmpty {
                Image(systemName: "point.3.connected.trianglepath.dotted").foregroundStyle(.secondary)
            }
            Image(systemName: host.authMethod == .publicKey ? "key" : "lock").foregroundStyle(.secondary)
        }
        .contentShape(Rectangle())
    }
}

/// `user@host:port` or `ssh://user@host:port` one-off connections, like typing `ssh ...`.
struct QuickConnectView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(SessionManager.self) private var sessions
    @Environment(HostStore.self) private var hostStore
    @Environment(IdentityStore.self) private var identityStore
    @State private var target = ""
    @State private var identityID: UUID?
    @State private var save = false

    var parsed: HostProfile? {
        var s = target.trimmingCharacters(in: .whitespaces)
        guard !s.isEmpty else { return nil }
        if s.hasPrefix("ssh://") { s.removeFirst(6) }
        var profile = HostProfile()
        if let at = s.lastIndex(of: "@") {
            profile.username = String(s[..<at]); s = String(s[s.index(after: at)...])
        } else {
            profile.username = NSUserName()
        }
        let (h, p) = SSHConfigParser.splitHostPort(s)
        if let h, let p { profile.hostname = h; profile.port = p } else { profile.hostname = s }
        guard !profile.hostname.isEmpty else { return nil }
        if let identityID { profile.authMethod = .publicKey; profile.identityID = identityID }
        return profile
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Destination") {
                    TextField("user@hostname:port", text: $target)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                        .accessibilityIdentifier("quickConnectDestination")
                }
                Section("Authentication") {
                    Picker("Private key", selection: $identityID) {
                        Text("Password").tag(UUID?.none)
                        ForEach(identityStore.identities) { Text($0.name).tag(UUID?.some($0.id)) }
                    }
                }
                Section {
                    Toggle("Save as host", isOn: $save)
                }
            }
            .navigationTitle("Quick Connect")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Connect") {
                        guard let p = parsed else { return }
                        if save { hostStore.upsert(p) }
                        dismiss()
                        sessions.open(p)
                    }.disabled(parsed == nil).accessibilityIdentifier("quickConnectGo")
                }
            }
        }
    }
}
