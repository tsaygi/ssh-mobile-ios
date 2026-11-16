import SwiftUI
import UniformTypeIdentifiers

struct IdentitiesView: View {
    @Environment(IdentityStore.self) private var store
    @State private var showingGenerate = false
    @State private var showingImport = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            List {
                if store.identities.isEmpty {
                    ContentUnavailableView("No keys", systemImage: "key",
                                           description: Text("Generate a new key pair or import an existing OpenSSH private key."))
                }
                ForEach(store.identities) { identity in
                    NavigationLink(value: identity.id) {
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Text(identity.name).font(.headline)
                                if identity.hasPassphrase { Image(systemName: "lock.fill").font(.caption).foregroundStyle(.secondary) }
                            }
                            Text(identity.keyType.label).font(.subheadline).foregroundStyle(.secondary)
                            Text(identity.fingerprintSHA256).font(.caption.monospaced()).foregroundStyle(.tertiary).lineLimit(1)
                        }
                    }
                }
                .onDelete { store.delete(at: $0) }
            }
            .navigationTitle("Keys")
            .navigationDestination(for: UUID.self) { id in
                if let identity = store.identity(id: id) { IdentityDetailView(identity: identity) }
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button("Generate key pair", systemImage: "wand.and.stars") { showingGenerate = true }
                        Button("Import private key", systemImage: "square.and.arrow.down") { showingImport = true }
                    } label: { Label("Add", systemImage: "plus") }
                }
            }
            .sheet(isPresented: $showingGenerate) { GenerateKeyView() }
            .sheet(isPresented: $showingImport) { ImportKeyView() }
            .errorAlert($error)
        }
    }
}

struct GenerateKeyView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(IdentityStore.self) private var store
    @State private var name = ""
    @State private var type: Identity.KeyType = .ed25519
    @State private var comment = ""
    @State private var passphrase = ""
    @State private var confirm = ""
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("Key") {
                    TextField("Name", text: $name)
                    Picker("Type", selection: $type) {
                        ForEach(KeyGenerator.generatableTypes) { Text($0.label).tag($0) }
                    }
                    TextField("Comment (e.g. you@device)", text: $comment).textInputAutocapitalization(.never).autocorrectionDisabled()
                }
                Section {
                    SecureField("Passphrase (optional)", text: $passphrase)
                    SecureField("Confirm passphrase", text: $confirm)
                } footer: {
                    Text("Keys are stored in the iOS Keychain and never leave this device unless you export them. RSA keys can be imported but are not generated here; Ed25519 is recommended.")
                }
            }
            .navigationTitle("Generate key")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Generate") { generate() }.disabled(passphrase != confirm)
                }
            }
            .errorAlert($error)
        }
    }

    private func generate() {
        do {
            let material = try KeyGenerator.generate(type)
            let text = try OpenSSHPrivateKey.serialize(material, comment: comment, passphrase: passphrase.isEmpty ? nil : passphrase)
            _ = try store.add(name: name.isEmpty ? "\(type.label) key" : name, privateKeyText: text, comment: comment)
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }
}

struct ImportKeyView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(IdentityStore.self) private var store
    @State private var name = ""
    @State private var text = ""
    @State private var showingPicker = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("Name") { TextField("Name", text: $name) }
                Section {
                    TextEditor(text: $text).font(.caption.monospaced()).frame(minHeight: 180)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button("Paste from clipboard", systemImage: "doc.on.clipboard") { text = UIPasteboard.general.string ?? "" }
                    Button("Choose file…", systemImage: "folder") { showingPicker = true }
                } header: { Text("Private key (OpenSSH format)") } footer: {
                    Text("Encrypted keys are kept encrypted; you will be asked for the passphrase when connecting. Keys in the legacy PEM format must be converted first: ssh-keygen -p -f key -m RFC4716... or simply ssh-keygen -p -o -f key.")
                }
            }
            .navigationTitle("Import key")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) { Button("Import") { importKey() }.disabled(text.isEmpty) }
            }
            .fileImporter(isPresented: $showingPicker, allowedContentTypes: [.data, .text]) { result in
                guard case .success(let url) = result else { return }
                let accessed = url.startAccessingSecurityScopedResource()
                defer { if accessed { url.stopAccessingSecurityScopedResource() } }
                if let data = try? Data(contentsOf: url) {
                    text = String(decoding: data, as: UTF8.self)
                    if name.isEmpty { name = url.lastPathComponent }
                }
            }
            .errorAlert($error)
        }
    }

    private func importKey() {
        do {
            _ = try store.add(name: name, privateKeyText: text)
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }
}

struct IdentityDetailView: View {
    @Environment(IdentityStore.self) private var store
    @Environment(\.dismiss) private var dismiss
    let identity: Identity
    @State private var name: String
    @State private var sharing: [Any]?
    @State private var exportingPrivate = false
    @State private var exportPassphrase = ""
    @State private var showingExportPrompt = false
    @State private var error: String?

    init(identity: Identity) {
        self.identity = identity
        _name = State(initialValue: identity.name)
    }

    var body: some View {
        Form {
            Section("Name") {
                TextField("Name", text: $name).onSubmit { store.rename(identity.id, to: name) }
            }
            Section("Details") {
                LabeledContent("Type", value: identity.keyType.label)
                LabeledContent("Fingerprint") { Text(identity.fingerprintSHA256).font(.caption.monospaced()).textSelection(.enabled) }
                LabeledContent("Protected", value: identity.hasPassphrase ? "Passphrase" : "Keychain only")
                LabeledContent("Created", value: identity.createdAt.formatted(date: .abbreviated, time: .shortened))
            }
            Section("Public key") {
                Text(identity.publicKeyOpenSSH).font(.caption.monospaced()).textSelection(.enabled)
                Button("Copy public key", systemImage: "doc.on.doc") { UIPasteboard.general.string = identity.publicKeyOpenSSH }
                Button("Share public key", systemImage: "square.and.arrow.up") { sharing = [identity.publicKeyOpenSSH] }
                Text("Add it to ~/.ssh/authorized_keys on the server.").font(.footnote).foregroundStyle(.secondary)
            }
            Section {
                Button("Export private key…", systemImage: "lock.doc") { showingExportPrompt = true }
            } footer: {
                Text("Exports the private key in OpenSSH format so you can use it on another device. Keep it safe.")
            }
            Section {
                Button("Delete key", role: .destructive) { store.delete([identity.id]); dismiss() }
            }
        }
        .navigationTitle(identity.name)
        .onDisappear { if name != identity.name { store.rename(identity.id, to: name) } }
        .sheet(isPresented: Binding(get: { sharing != nil }, set: { if !$0 { sharing = nil } })) {
            if let items = sharing { ShareSheet(items: items) }
        }
        .alert("Export private key", isPresented: $showingExportPrompt) {
            SecureField("Passphrase for the export (optional)", text: $exportPassphrase)
            Button("Export") { exportPrivate() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("An unencrypted key will be re-encrypted with this passphrase; leave empty to export as stored.")
        }
        .errorAlert($error)
    }

    private func exportPrivate() {
        do {
            guard let stored = try store.privateKeyText(for: identity.id) else { return }
            var text = stored
            if !exportPassphrase.isEmpty {
                let parsed = try OpenSSHPrivateKey.parse(stored, passphrase: nil)
                if let material = parsed.material {
                    text = try OpenSSHPrivateKey.serialize(material, comment: parsed.comment, passphrase: exportPassphrase)
                }
            }
            let url = FileManager.default.temporaryDirectory.appendingPathComponent(identity.name.replacingOccurrences(of: " ", with: "_"))
            try Data(text.utf8).write(to: url, options: .completeFileProtection)
            sharing = [url]
        } catch {
            self.error = error.localizedDescription
        }
    }
}
