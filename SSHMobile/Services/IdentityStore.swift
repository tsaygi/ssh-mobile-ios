import Foundation
import Observation

/// Manages key pairs. Metadata is stored as JSON; private key text (OpenSSH format)
/// lives in the Keychain keyed by the identity's UUID.
@Observable
final class IdentityStore {
    private(set) var identities: [Identity] = []
    private let file = "identities.json"

    init() { identities = JSONStore.load([Identity].self, from: file) ?? [] }

    func identity(id: UUID?) -> Identity? {
        guard let id else { return nil }
        return identities.first { $0.id == id }
    }

    /// Store a key pair. `privateKeyText` is the OpenSSH private key file contents.
    func add(name: String, privateKeyText: String, comment: String = "") throws -> Identity {
        let parsed = try OpenSSHPrivateKey.parse(privateKeyText, passphrase: nil)
        var identity = Identity(name: name, keyType: parsed.publicKey.keyType,
                                publicKeyOpenSSH: parsed.publicKey.openSSHLine(comment: comment.isEmpty ? parsed.comment : comment),
                                fingerprintSHA256: parsed.publicKey.fingerprint,
                                hasPassphrase: parsed.isEncrypted,
                                comment: comment.isEmpty ? parsed.comment : comment)
        identity.name = name.isEmpty ? (identity.comment.isEmpty ? parsed.publicKey.keyType.label : identity.comment) : name
        try Keychain.save(Data(privateKeyText.utf8), for: identity.id.uuidString)
        identities.append(identity)
        persist()
        return identity
    }

    func privateKeyText(for id: UUID) throws -> String? {
        guard let data = try Keychain.load(id.uuidString) else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    func rename(_ id: UUID, to name: String) {
        guard let i = identities.firstIndex(where: { $0.id == id }) else { return }
        identities[i].name = name
        persist()
    }

    func delete(_ ids: Set<UUID>) {
        for id in ids { Keychain.delete(id.uuidString) }
        identities.removeAll { ids.contains($0.id) }
        persist()
    }

    func delete(at offsets: IndexSet) { delete(Set(offsets.map { identities[$0].id })) }

    private func persist() { JSONStore.save(identities, to: file) }
}
