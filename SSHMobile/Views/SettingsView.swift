import SwiftUI

struct SettingsView: View {
    @Environment(HostStore.self) private var hostStore
    @Environment(KnownHostsStore.self) private var knownHosts
    @State private var importingConfig = false
    @State private var exportingConfig = false
    @State private var importedCount: Int?

    var body: some View {
        NavigationStack {
            Form {
                Section("OpenSSH config") {
                    Button("Import ~/.ssh/config", systemImage: "square.and.arrow.down") { importingConfig = true }
                    Button("Export hosts as ssh_config", systemImage: "square.and.arrow.up") { exportingConfig = true }
                    Text("Supports Host, HostName, Port, User, IdentityFile, ProxyJump, LocalForward, RemoteForward, DynamicForward, SetEnv, ServerAliveInterval, ConnectTimeout, RequestTTY, RemoteCommand and PreferredAuthentications. Wildcard Host * blocks apply as defaults.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Section("Security") {
                    NavigationLink("Known hosts", destination: KnownHostsView())
                    LabeledContent("Hosts", value: "\(hostStore.hosts.count)")
                    LabeledContent("Known host keys", value: "\(knownHosts.entries.count)")
                }
                Section("About") {
                    LabeledContent("Version", value: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0")
                    LabeledContent("Transport", value: "SwiftNIO SSH via Citadel")
                    LabeledContent("Terminal", value: "SwiftTerm (xterm-256color)")
                    Text("Supported: Ed25519, ECDSA and RSA keys, password auth, host key verification, PTY shell, remote commands, -L/-R/-D port forwarding, ProxyJump, SFTP.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Settings")
            .sheet(isPresented: $importingConfig) {
                TextImportSheet(title: "Import ssh_config", placeholder: "Paste the contents of ~/.ssh/config") { text in
                    importedCount = hostStore.importSSHConfig(text)
                }
            }
            .fileExporter(isPresented: $exportingConfig, document: TextFile(text: hostStore.exportSSHConfig()),
                          contentType: .plainText, defaultFilename: "ssh_config") { _ in }
            .alert("Imported", isPresented: Binding(get: { importedCount != nil }, set: { if !$0 { importedCount = nil } })) {
                Button("OK") {}
            } message: { Text("\(importedCount ?? 0) host(s) imported. Select a private key for key-based hosts in the host editor.") }
        }
    }
}
