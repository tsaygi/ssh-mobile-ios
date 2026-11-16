import SwiftUI

struct KnownHostsView: View {
    @Environment(KnownHostsStore.self) private var store
    @State private var importing = false
    @State private var importText = ""

    var body: some View {
        List {
            if store.entries.isEmpty {
                ContentUnavailableView("No known hosts", systemImage: "checkmark.shield",
                                       description: Text("Host keys are recorded here the first time you connect."))
            }
            ForEach(store.entries) { e in
                VStack(alignment: .leading, spacing: 2) {
                    Text(e.hostPattern).font(.headline)
                    Text(e.keyType).font(.subheadline).foregroundStyle(.secondary)
                    Text(e.fingerprintSHA256).font(.caption.monospaced()).foregroundStyle(.tertiary)
                    Text("First seen \(e.firstSeen.formatted(date: .abbreviated, time: .shortened))").font(.caption2).foregroundStyle(.tertiary)
                }
                .contextMenu { Button("Copy known_hosts line") { UIPasteboard.general.string = e.knownHostsLine } }
            }
            .onDelete { store.remove(at: $0) }
        }
        .navigationTitle("Known hosts")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button("Import known_hosts", systemImage: "square.and.arrow.down") { importing = true }
                    Button("Copy all", systemImage: "doc.on.doc") { UIPasteboard.general.string = store.exportKnownHosts() }
                } label: { Label("More", systemImage: "ellipsis.circle") }
            }
        }
        .sheet(isPresented: $importing) {
            TextImportSheet(title: "Import known_hosts", placeholder: "Paste known_hosts lines") { text in
                _ = store.importKnownHosts(text)
            }
        }
    }
}

struct TextImportSheet: View {
    @Environment(\.dismiss) private var dismiss
    let title: String
    let placeholder: String
    let onImport: (String) -> Void
    @State private var text = ""

    var body: some View {
        NavigationStack {
            VStack {
                TextEditor(text: $text).font(.caption.monospaced())
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .overlay(alignment: .topLeading) {
                        if text.isEmpty { Text(placeholder).foregroundStyle(.tertiary).padding(8) }
                    }
                    .padding()
                Button("Paste from clipboard") { text = UIPasteboard.general.string ?? "" }.padding(.bottom)
            }
            .navigationTitle(title)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) { Button("Import") { onImport(text); dismiss() }.disabled(text.isEmpty) }
            }
        }
    }
}
