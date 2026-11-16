import Foundation
import Observation

/// Equivalent of `~/.ssh/known_hosts` with trust-on-first-use semantics.
@Observable
final class KnownHostsStore {
    private(set) var entries: [KnownHost] = []
    private let file = "known_hosts.json"

    init() { entries = JSONStore.load([KnownHost].self, from: file) ?? [] }

    enum Verdict: Equatable {
        case trusted
        case unknown
        /// The host presented a key of a type we have on file, but it differs.
        case mismatch(stored: KnownHost)
    }

    func verify(hostname: String, port: Int, keyType: String, publicKeyBase64: String) -> Verdict {
        let matches = entries.filter { $0.hostname.lowercased() == hostname.lowercased() && $0.port == port }
        if matches.contains(where: { $0.keyType == keyType && $0.publicKeyBase64 == publicKeyBase64 }) {
            return .trusted
        }
        if let sameType = matches.first(where: { $0.keyType == keyType }) {
            return .mismatch(stored: sameType)
        }
        return .unknown
    }

    func trust(hostname: String, port: Int, keyType: String, publicKeyBase64: String, fingerprint: String) {
        entries.removeAll { $0.hostname.lowercased() == hostname.lowercased() && $0.port == port && $0.keyType == keyType }
        entries.append(KnownHost(hostname: hostname, port: port, keyType: keyType,
                                 publicKeyBase64: publicKeyBase64, fingerprintSHA256: fingerprint))
        persist()
    }

    func remove(_ ids: Set<UUID>) {
        entries.removeAll { ids.contains($0.id) }
        persist()
    }

    func remove(at offsets: IndexSet) { remove(Set(offsets.map { entries[$0].id })) }

    /// Import plain `known_hosts` lines (hashed `|1|` entries are skipped).
    func importKnownHosts(_ text: String) -> Int {
        var n = 0
        for line in text.split(separator: "\n") {
            let parts = line.split(separator: " ").map(String.init)
            guard parts.count >= 3, !parts[0].hasPrefix("|1|"), !parts[0].hasPrefix("@") else { continue }
            let (host, port) = SSHConfigParser.splitHostPort(parts[0].split(separator: ",").first.map(String.init) ?? parts[0])
            guard let hostname = host ?? (port == nil ? parts[0] : nil) else { continue }
            guard let blob = Data(base64Encoded: parts[2]) else { continue }
            trust(hostname: hostname, port: port ?? 22, keyType: parts[1], publicKeyBase64: parts[2],
                  fingerprint: Fingerprint.sha256(blob))
            n += 1
        }
        return n
    }

    func exportKnownHosts() -> String { entries.map(\.knownHostsLine).joined(separator: "\n") + "\n" }

    private func persist() { JSONStore.save(entries, to: file) }
}

enum Fingerprint {
    /// OpenSSH-style `SHA256:<base64 without padding>` fingerprint of a public key blob.
    static func sha256(_ blob: Data) -> String {
        import_sha256(blob)
    }
}
