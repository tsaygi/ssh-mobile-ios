import SwiftUI

struct HostEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(HostStore.self) private var hostStore
    @Environment(IdentityStore.self) private var identityStore
    @State var host: HostProfile
    @State private var editingForward: PortForward?
    @State private var newEnvKey = ""
    @State private var newEnvValue = ""
    @State private var tagsText: String

    init(host: HostProfile) {
        _host = State(initialValue: host)
        _tagsText = State(initialValue: host.tags.joined(separator: ", "))
    }

    private var isNew: Bool { hostStore.host(id: host.id) == nil }
    private var hasSavedPassword: Bool { CredentialStore.password(for: host.id) != nil }

    var body: some View {
        NavigationStack {
            Form {
                Section("Host") {
                    TextField("Name (alias)", text: $host.name)
                    TextField("Hostname or IP", text: $host.hostname)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                    TextField("Port", value: $host.port, format: .number).keyboardType(.numberPad)
                    TextField("Username", text: $host.username)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("Tags (comma separated)", text: $tagsText)
                }

                Section("Authentication") {
                    Picker("Method", selection: $host.authMethod) {
                        ForEach(HostProfile.AuthMethod.allCases.filter { $0 != .keyboardInteractive }) { Text($0.label).tag($0) }
                    }
                    if host.authMethod == .publicKey {
                        Picker("Private key", selection: $host.identityID) {
                            Text("None").tag(UUID?.none)
                            ForEach(identityStore.identities) { Text($0.name).tag(UUID?.some($0.id)) }
                        }
                        if identityStore.identities.isEmpty {
                            Text("Generate or import a key in the Keys tab.").font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                    if hasSavedPassword {
                        Button("Forget saved password", role: .destructive) { CredentialStore.delete(for: host.id) }
                    }
                }

                Section {
                    Picker("Jump host (ProxyJump)", selection: $host.jumpHostID) {
                        Text("None").tag(UUID?.none)
                        ForEach(hostStore.hosts.filter { $0.id != host.id }) { Text($0.displayName).tag(UUID?.some($0.id)) }
                    }
                    Stepper("Keepalive: \(host.keepAliveSeconds == 0 ? "off" : "\(host.keepAliveSeconds)s")", value: $host.keepAliveSeconds, in: 0...300, step: 5)
                    Stepper("Connect timeout: \(host.connectTimeoutSeconds)s", value: $host.connectTimeoutSeconds, in: 3...120)
                } header: { Text("Connection") }

                Section("Terminal") {
                    TextField("TERM", text: $host.terminalType).textInputAutocapitalization(.never).autocorrectionDisabled()
                    Picker("Theme", selection: $host.colorScheme) {
                        ForEach(TerminalTheme.all) { Text($0.name).tag($0) }
                    }
                    Stepper("Font size: \(Int(host.fontSize))", value: $host.fontSize, in: 8...28)
                    Toggle("Request TTY", isOn: $host.requestTTY)
                    TextField("Remote command (optional)", text: $host.remoteCommand)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                }

                Section("Environment (SetEnv)") {
                    ForEach(host.environment.keys.sorted(), id: \.self) { key in
                        HStack { Text(key).font(.body.monospaced()); Spacer(); Text(host.environment[key] ?? "").foregroundStyle(.secondary) }
                    }
                    .onDelete { offsets in
                        let keys = host.environment.keys.sorted()
                        for i in offsets { host.environment[keys[i]] = nil }
                    }
                    HStack {
                        TextField("NAME", text: $newEnvKey).textInputAutocapitalization(.never).autocorrectionDisabled()
                        TextField("value", text: $newEnvValue).textInputAutocapitalization(.never).autocorrectionDisabled()
                        Button { host.environment[newEnvKey] = newEnvValue; newEnvKey = ""; newEnvValue = "" } label: { Image(systemName: "plus.circle.fill") }
                            .disabled(newEnvKey.isEmpty)
                    }
                }

                Section("Port forwarding") {
                    ForEach(host.portForwards) { f in
                        Button { editingForward = f } label: {
                            HStack {
                                Text(f.summary).font(.body.monospaced()).foregroundStyle(f.enabled ? .primary : .secondary)
                                Spacer()
                                Image(systemName: "chevron.right").foregroundStyle(.tertiary)
                            }
                        }.buttonStyle(.plain)
                    }
                    .onDelete { host.portForwards.remove(atOffsets: $0) }
                    Button("Add forward", systemImage: "plus") { editingForward = PortForward() }
                }
            }
            .navigationTitle(isNew ? "New Host" : "Edit Host")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        host.tags = tagsText.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                        hostStore.upsert(host)
                        dismiss()
                    }
                    .disabled(host.hostname.isEmpty || host.username.isEmpty)
                }
            }
            .sheet(item: $editingForward) { f in
                PortForwardEditor(forward: f) { saved in
                    if let i = host.portForwards.firstIndex(where: { $0.id == saved.id }) { host.portForwards[i] = saved } else { host.portForwards.append(saved) }
                }
            }
        }
    }
}

struct PortForwardEditor: View {
    @Environment(\.dismiss) private var dismiss
    @State var forward: PortForward
    let onSave: (PortForward) -> Void

    var body: some View {
        NavigationStack {
            Form {
                Picker("Type", selection: $forward.kind) {
                    ForEach(PortForward.Kind.allCases) { Text($0.label).tag($0) }
                }
                Section(forward.kind == .remote ? "Listen on server" : "Listen on this device") {
                    TextField("Bind address", text: $forward.bindAddress).textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("Port", value: $forward.bindPort, format: .number).keyboardType(.numberPad)
                }
                if forward.kind != .dynamic {
                    Section(forward.kind == .remote ? "Forward to (reachable from this device)" : "Forward to (reachable from server)") {
                        TextField("Host", text: $forward.targetHost).textInputAutocapitalization(.never).autocorrectionDisabled()
                        TextField("Port", value: $forward.targetPort, format: .number).keyboardType(.numberPad)
                    }
                }
                Toggle("Start automatically", isOn: $forward.enabled)
                Section { Text(forward.summary).font(.body.monospaced()).foregroundStyle(.secondary) }
            }
            .navigationTitle("Port Forward")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) { Button("Done") { onSave(forward); dismiss() } }
            }
        }
    }
}
