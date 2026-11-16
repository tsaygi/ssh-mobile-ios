import Foundation

// MARK: - Host

/// A saved SSH destination. Mirrors the knobs an OpenSSH `Host` block exposes.
struct HostProfile: Identifiable, Codable, Hashable {
    var id: UUID = UUID()
    var name: String = ""
    var hostname: String = ""
    var port: Int = 22
    var username: String = ""
    var authMethod: AuthMethod = .password
    /// Identity (private key) used when `authMethod == .publicKey`.
    var identityID: UUID?
    /// `ProxyJump` equivalent: another saved host to tunnel through.
    var jumpHostID: UUID?
    var terminalType: String = "xterm-256color"
    var keepAliveSeconds: Int = 30
    var connectTimeoutSeconds: Int = 15
    var agentForwarding: Bool = false
    var compression: Bool = false
    /// Environment variables sent with `SendEnv` semantics.
    var environment: [String: String] = [:]
    /// Optional command executed instead of a login shell (like `ssh host cmd`).
    var remoteCommand: String = ""
    var requestTTY: Bool = true
    var portForwards: [PortForward] = []
    var colorScheme: TerminalTheme = .defaultDark
    var fontSize: Double = 13
    var lastConnected: Date?
    var tags: [String] = []

    enum AuthMethod: String, Codable, CaseIterable, Identifiable {
        case password, publicKey, keyboardInteractive, none
        var id: String { rawValue }
        var label: String {
            switch self {
            case .password: return "Password"
            case .publicKey: return "Public key"
            case .keyboardInteractive: return "Keyboard-interactive"
            case .none: return "None"
            }
        }
    }

    var displayName: String { name.isEmpty ? "\(username)@\(hostname)" : name }
    var sshURL: String { "ssh://\(username)@\(hostname):\(port)" }
}

// MARK: - Port forwarding

/// `-L`, `-R`, `-D` equivalents.
struct PortForward: Identifiable, Codable, Hashable {
    var id: UUID = UUID()
    var kind: Kind = .local
    var bindAddress: String = "127.0.0.1"
    var bindPort: Int = 8080
    var targetHost: String = "localhost"
    var targetPort: Int = 80
    var enabled: Bool = true

    enum Kind: String, Codable, CaseIterable, Identifiable {
        case local, remote, dynamic
        var id: String { rawValue }
        var label: String {
            switch self {
            case .local: return "Local (-L)"
            case .remote: return "Remote (-R)"
            case .dynamic: return "Dynamic SOCKS (-D)"
            }
        }
        var flag: String {
            switch self {
            case .local: return "-L"
            case .remote: return "-R"
            case .dynamic: return "-D"
            }
        }
    }

    var summary: String {
        switch kind {
        case .local: return "-L \(bindAddress):\(bindPort):\(targetHost):\(targetPort)"
        case .remote: return "-R \(bindAddress):\(bindPort):\(targetHost):\(targetPort)"
        case .dynamic: return "-D \(bindAddress):\(bindPort)"
        }
    }
}

// MARK: - Identity (key pair)

/// Metadata for a private key. The key material itself lives in the Keychain,
/// addressed by `id`.
struct Identity: Identifiable, Codable, Hashable {
    var id: UUID = UUID()
    var name: String
    var keyType: KeyType
    var publicKeyOpenSSH: String       // "ssh-ed25519 AAAA... comment"
    var fingerprintSHA256: String
    var hasPassphrase: Bool
    var createdAt: Date = Date()
    var comment: String = ""

    enum KeyType: String, Codable, CaseIterable, Identifiable {
        case ed25519, ecdsaP256, ecdsaP384, ecdsaP521, rsa2048, rsa3072, rsa4096
        var id: String { rawValue }
        var label: String {
            switch self {
            case .ed25519: return "Ed25519"
            case .ecdsaP256: return "ECDSA P-256"
            case .ecdsaP384: return "ECDSA P-384"
            case .ecdsaP521: return "ECDSA P-521"
            case .rsa2048: return "RSA 2048"
            case .rsa3072: return "RSA 3072"
            case .rsa4096: return "RSA 4096"
            }
        }
        var sshName: String {
            switch self {
            case .ed25519: return "ssh-ed25519"
            case .ecdsaP256: return "ecdsa-sha2-nistp256"
            case .ecdsaP384: return "ecdsa-sha2-nistp384"
            case .ecdsaP521: return "ecdsa-sha2-nistp521"
            case .rsa2048, .rsa3072, .rsa4096: return "ssh-rsa"
            }
        }
    }
}

// MARK: - Known hosts

/// One line of `~/.ssh/known_hosts`.
struct KnownHost: Identifiable, Codable, Hashable {
    var id: UUID = UUID()
    var hostname: String
    var port: Int
    var keyType: String            // e.g. ssh-ed25519
    var publicKeyBase64: String    // key blob, base64
    var fingerprintSHA256: String
    var firstSeen: Date = Date()

    var hostPattern: String { port == 22 ? hostname : "[\(hostname)]:\(port)" }
    var knownHostsLine: String { "\(hostPattern) \(keyType) \(publicKeyBase64)" }
}

// MARK: - Terminal appearance

struct TerminalTheme: Codable, Hashable, Identifiable {
    var id: String
    var name: String
    var background: String   // hex RRGGBB
    var foreground: String
    var cursor: String
    var ansi: [String]       // 16 hex colours

    static let defaultDark = TerminalTheme(
        id: "default-dark", name: "Default Dark",
        background: "1E1E1E", foreground: "D4D4D4", cursor: "AEAFAD",
        ansi: ["000000", "CD3131", "0DBC79", "E5E510", "2472C8", "BC3FBC", "11A8CD", "E5E5E5",
               "666666", "F14C4C", "23D18B", "F5F543", "3B8EEA", "D670D6", "29B8DB", "FFFFFF"])

    static let solarizedDark = TerminalTheme(
        id: "solarized-dark", name: "Solarized Dark",
        background: "002B36", foreground: "839496", cursor: "93A1A1",
        ansi: ["073642", "DC322F", "859900", "B58900", "268BD2", "D33682", "2AA198", "EEE8D5",
               "002B36", "CB4B16", "586E75", "657B83", "839496", "6C71C4", "93A1A1", "FDF6E3"])

    static let light = TerminalTheme(
        id: "light", name: "Light",
        background: "FFFFFF", foreground: "1F1F1F", cursor: "1F1F1F",
        ansi: ["000000", "C91B00", "00C200", "C7C400", "0225C7", "CA30C7", "00C5C7", "C7C7C7",
               "686868", "FF6E67", "5FFA68", "FFFC67", "6871FF", "FF77FF", "60FDFF", "FFFFFF"])

    static let all: [TerminalTheme] = [.defaultDark, .solarizedDark, .light]
}

// MARK: - Session log entry

struct SessionEvent: Identifiable, Hashable {
    var id = UUID()
    var date = Date()
    var message: String
    var level: Level = .info
    enum Level { case info, warning, error }
}
