import Foundation

/// Optional per-host saved passwords. Stored in the Keychain next to private keys.
enum CredentialStore {
    private static func key(_ hostID: UUID) -> String { "password-\(hostID.uuidString)" }

    static func password(for hostID: UUID) -> String? {
        guard let data = try? Keychain.load(key(hostID)) else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    static func save(password: String, for hostID: UUID) {
        try? Keychain.save(Data(password.utf8), for: key(hostID))
    }

    static func delete(for hostID: UUID) { Keychain.delete(key(hostID)) }
}
