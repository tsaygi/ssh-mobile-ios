import SwiftUI
import Citadel
import NIOCore

/// Minimal SFTP file manager over the session's connection: browse, download, upload,
/// create folders, rename and delete.
struct SFTPBrowserView: View {
    let session: SSHSession
    @Environment(\.dismiss) private var dismiss
    @State private var model: SFTPBrowserModel

    init(session: SSHSession) {
        self.session = session
        _model = State(initialValue: SFTPBrowserModel(session: session))
    }

    var body: some View {
        NavigationStack {
            List {
                if model.path != "/" {
                    Button { Task { await model.up() } } label: { Label("..", systemImage: "arrow.up.doc") }
                }
                ForEach(model.entries) { entry in
                    if entry.isDirectory {
                        Button { Task { await model.enter(entry.name) } } label: { EntryRow(entry: entry) }
                            .buttonStyle(.plain)
                            .contextMenu { actions(entry) }
                    } else {
                        EntryRow(entry: entry)
                            .contextMenu { actions(entry) }
                            .swipeActions {
                                Button(role: .destructive) { Task { await model.delete(entry) } } label: { Label("Delete", systemImage: "trash") }
                                Button { Task { await model.download(entry) } } label: { Label("Download", systemImage: "arrow.down.circle") }.tint(.blue)
                            }
                    }
                }
            }
            .overlay { if model.loading { ProgressView().controlSize(.large) } }
            .navigationTitle(model.path)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } }
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button("Upload file", systemImage: "arrow.up.doc") { model.showingUpload = true }
                        Button("New folder", systemImage: "folder.badge.plus") { model.newFolderName = ""; model.showingNewFolder = true }
                        Button("Refresh", systemImage: "arrow.clockwise") { Task { await model.refresh() } }
                        Button("Go to path", systemImage: "text.cursor") { model.gotoText = model.path; model.showingGoto = true }
                    } label: { Label("More", systemImage: "ellipsis.circle") }
                }
            }
            .task { await model.start() }
            .fileImporter(isPresented: $model.showingUpload, allowedContentTypes: [.data, .item]) { result in
                if case .success(let url) = result { Task { await model.upload(url) } }
            }
            .fileExporter(isPresented: $model.showingDownload, document: model.downloaded.map { DataFile(data: $0.data) },
                          contentType: .data, defaultFilename: model.downloaded?.name) { _ in model.downloaded = nil }
            .alert("New folder", isPresented: $model.showingNewFolder) {
                TextField("Name", text: $model.newFolderName)
                Button("Create") { Task { await model.mkdir() } }
                Button("Cancel", role: .cancel) {}
            }
            .alert("Rename", isPresented: $model.showingRename) {
                TextField("Name", text: $model.renameText)
                Button("Rename") { Task { await model.rename() } }
                Button("Cancel", role: .cancel) {}
            }
            .alert("Go to path", isPresented: $model.showingGoto) {
                TextField("/path", text: $model.gotoText)
                Button("Go") { Task { await model.go(model.gotoText) } }
                Button("Cancel", role: .cancel) {}
            }
            .errorAlert($model.error)
        }
    }

    @ViewBuilder private func actions(_ entry: SFTPEntry) -> some View {
        if !entry.isDirectory {
            Button("Download", systemImage: "arrow.down.circle") { Task { await model.download(entry) } }
        }
        Button("Rename", systemImage: "pencil") { model.renaming = entry; model.renameText = entry.name; model.showingRename = true }
        Button("Copy path", systemImage: "doc.on.doc") { UIPasteboard.general.string = model.fullPath(entry.name) }
        Button("Delete", systemImage: "trash", role: .destructive) { Task { await model.delete(entry) } }
    }
}

struct EntryRow: View {
    let entry: SFTPEntry
    var body: some View {
        HStack {
            Image(systemName: entry.isDirectory ? "folder.fill" : (entry.isSymlink ? "link" : "doc"))
                .foregroundStyle(entry.isDirectory ? .yellow : .secondary).frame(width: 24)
            VStack(alignment: .leading) {
                Text(entry.name).lineLimit(1)
                Text(entry.detail).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if entry.isDirectory { Image(systemName: "chevron.right").foregroundStyle(.tertiary) }
        }
        .contentShape(Rectangle())
    }
}

struct SFTPEntry: Identifiable {
    var id: String { name }
    let name: String
    let longname: String
    let size: UInt64?
    let permissions: UInt32?
    let modified: Date?

    var isDirectory: Bool { permissions.map { ($0 & 0o170000) == 0o040000 } ?? longname.hasPrefix("d") }
    var isSymlink: Bool { permissions.map { ($0 & 0o170000) == 0o120000 } ?? longname.hasPrefix("l") }
    var detail: String {
        var parts: [String] = []
        if let p = permissions { parts.append(Self.modeString(p)) }
        if !isDirectory, let s = size { parts.append(ByteCountFormatter.file.string(fromByteCount: Int64(s))) }
        if let m = modified { parts.append(m.formatted(date: .abbreviated, time: .shortened)) }
        return parts.joined(separator: "  ")
    }

    static func modeString(_ mode: UInt32) -> String {
        let flags = ["r", "w", "x"]
        var s = ""
        for shift in stride(from: 8, through: 0, by: -1) {
            s += (mode >> UInt32(shift)) & 1 == 1 ? flags[(8 - shift) % 3] : "-"
        }
        return s
    }
}

@MainActor
@Observable
final class SFTPBrowserModel {
    let session: SSHSession
    private var client: SFTPClient?
    var path = "/"
    var entries: [SFTPEntry] = []
    var loading = false
    var error: String?
    var showingUpload = false
    var showingDownload = false
    var downloaded: (name: String, data: Data)?
    var showingNewFolder = false
    var newFolderName = ""
    var showingRename = false
    var renameText = ""
    var renaming: SFTPEntry?
    var showingGoto = false
    var gotoText = ""

    init(session: SSHSession) { self.session = session }

    func fullPath(_ name: String) -> String { path == "/" ? "/\(name)" : "\(path)/\(name)" }

    func start() async {
        guard client == nil else { return }
        loading = true
        do {
            let c = try await session.openSFTP()
            client = c
            path = (try? await c.getRealPath(atPath: ".")) ?? "/"
            await refresh()
        } catch {
            self.error = SSHSession.describe(error)
        }
        loading = false
    }

    func refresh() async {
        guard let client else { return }
        loading = true
        defer { loading = false }
        do {
            let names = try await client.listDirectory(atPath: path)
            entries = names.flatMap(\.components)
                .filter { $0.filename != "." && $0.filename != ".." }
                .map { c in
                    SFTPEntry(name: c.filename, longname: c.longname, size: c.attributes.size,
                              permissions: c.attributes.permissions, modified: c.attributes.accessModificationTime?.modificationTime)
                }
                .sorted { a, b in
                    if a.isDirectory != b.isDirectory { return a.isDirectory }
                    return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
                }
        } catch {
            self.error = SSHSession.describe(error)
        }
    }

    func enter(_ name: String) async { await go(fullPath(name)) }

    func up() async {
        let parent = (path as NSString).deletingLastPathComponent
        await go(parent.isEmpty ? "/" : parent)
    }

    func go(_ newPath: String) async {
        guard let client else { return }
        do {
            path = try await client.getRealPath(atPath: newPath)
            await refresh()
        } catch {
            self.error = SSHSession.describe(error)
        }
    }

    func download(_ entry: SFTPEntry) async {
        guard let client else { return }
        loading = true
        defer { loading = false }
        do {
            let file = try await client.openFile(filePath: fullPath(entry.name), flags: .read)
            let buffer = try await file.readAll()
            try await file.close()
            downloaded = (entry.name, Data(buffer.readableBytesView))
            showingDownload = true
        } catch {
            self.error = SSHSession.describe(error)
        }
    }

    func upload(_ url: URL) async {
        guard let client else { return }
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }
        loading = true
        defer { loading = false }
        do {
            let data = try Data(contentsOf: url)
            let file = try await client.openFile(filePath: fullPath(url.lastPathComponent), flags: [.write, .create, .truncate])
            let chunk = 32 * 1024
            var offset = 0
            while offset < data.count {
                let end = min(offset + chunk, data.count)
                try await file.write(ByteBuffer(bytes: data[offset..<end]), at: UInt64(offset))
                offset = end
            }
            try await file.close()
            session.log("Uploaded \(url.lastPathComponent) (\(data.count) bytes) to \(path)")
            await refresh()
        } catch {
            self.error = SSHSession.describe(error)
        }
    }

    func mkdir() async {
        guard let client, !newFolderName.isEmpty else { return }
        do { try await client.createDirectory(atPath: fullPath(newFolderName)); await refresh() }
        catch { self.error = SSHSession.describe(error) }
    }

    func rename() async {
        guard let client, let entry = renaming, !renameText.isEmpty else { return }
        do { try await client.rename(at: fullPath(entry.name), to: fullPath(renameText)); await refresh() }
        catch { self.error = SSHSession.describe(error) }
        renaming = nil
    }

    func delete(_ entry: SFTPEntry) async {
        guard let client else { return }
        do {
            if entry.isDirectory { try await client.rmdir(at: fullPath(entry.name)) } else { try await client.remove(at: fullPath(entry.name)) }
            await refresh()
        } catch {
            self.error = SSHSession.describe(error)
        }
    }
}
