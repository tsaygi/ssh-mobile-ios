import XCTest
import Network
@testable import SSHMobile

struct TimeoutError: Error {}

enum Fixtures {
    static func text(_ name: String) throws -> String {
        let bundle = Bundle(for: TestToken.self)
        guard let url = bundle.url(forResource: name, withExtension: nil, subdirectory: "Fixtures")
                ?? bundle.url(forResource: name, withExtension: nil) else {
            throw NSError(domain: "fixture", code: 1, userInfo: [NSLocalizedDescriptionKey: "missing fixture \(name)"])
        }
        return try String(contentsOf: url, encoding: .utf8)
    }

    /// Fingerprints as printed by `ssh-keygen -lf`, keyed by comment.
    static func fingerprints() throws -> [String: String] {
        var map: [String: String] = [:]
        for line in try text("fingerprints.txt").split(separator: "\n") {
            let parts = line.split(separator: " ")
            if parts.count >= 3 { map[String(parts[2])] = String(parts[1]) }
        }
        return map
    }
}

private final class TestToken {}

/// Test server started by the repo's `scripts/test-server.sh` (Alpine OpenSSH in Docker).
enum TestServer {
    static let host = "127.0.0.1"
    static let port = 2222
    static let user = "tester"
    static let password = "testpass123"
    static let passphrase = "secret"

    static func isReachable() async -> Bool {
        (try? await TCP.readBanner(host: host, port: port))?.hasPrefix("SSH-2.0") ?? false
    }

    static func profile(auth: HostProfile.AuthMethod = .password, identity: UUID? = nil) -> HostProfile {
        var p = HostProfile(name: "test", hostname: host, port: port, username: user)
        p.authMethod = auth
        p.identityID = identity
        p.keepAliveSeconds = 0
        return p
    }
}

@MainActor
func waitUntil(_ timeout: TimeInterval = 20, _ condition: @MainActor () -> Bool) async throws {
    let deadline = Date().addingTimeInterval(timeout)
    while !condition() {
        if Date() > deadline { throw TimeoutError() }
        try await Task.sleep(nanoseconds: 50_000_000)
    }
}

/// Answers host-key and credential prompts the way a user would.
@MainActor
func autoRespond(_ session: SSHSession, trustHostKey: Bool = true,
                 password: String? = TestServer.password, passphrase: String? = TestServer.passphrase) -> Task<Void, Never> {
    Task { @MainActor in
        while !Task.isCancelled {
            if let p = session.hostKeyPrompt { p.decide(trustHostKey) }
            if let c = session.credentialPrompt {
                switch c.kind {
                case .password: c.submit(password, false)
                case .passphrase: c.submit(passphrase, false)
                }
            }
            try? await Task.sleep(nanoseconds: 30_000_000)
        }
    }
}

/// Minimal TCP helpers built on Network.framework for probing forwards.
enum TCP {
    static func connect(host: String, port: Int) async throws -> NWConnection {
        let conn = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(integerLiteral: UInt16(port)), using: .tcp)
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            var resumed = false
            conn.stateUpdateHandler = { state in
                guard !resumed else { return }
                switch state {
                case .ready: resumed = true; cont.resume()
                case .failed(let e): resumed = true; cont.resume(throwing: e)
                case .cancelled: resumed = true; cont.resume(throwing: TimeoutError())
                default: break
                }
            }
            conn.start(queue: .global())
        }
        return conn
    }

    static func send(_ conn: NWConnection, _ bytes: [UInt8]) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            conn.send(content: Data(bytes), completion: .contentProcessed { e in
                if let e { cont.resume(throwing: e) } else { cont.resume() }
            })
        }
    }

    static func receive(_ conn: NWConnection, min: Int = 1, max: Int = 4096) async throws -> Data {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            conn.receive(minimumIncompleteLength: min, maximumLength: max) { data, _, _, error in
                if let error { cont.resume(throwing: error) } else { cont.resume(returning: data ?? Data()) }
            }
        }
    }

    static func readBanner(host: String, port: Int) async throws -> String {
        let conn = try await connect(host: host, port: port)
        defer { conn.cancel() }
        let data = try await withTimeout(seconds: 5, cancel: { conn.cancel() }) { try await receive(conn) }
        return String(decoding: data, as: UTF8.self)
    }

    /// SOCKS5 CONNECT through a `-D` listener, returning whatever the target sends first.
    static func readBannerViaSOCKS5(socksPort: Int, targetHost: String, targetPort: Int) async throws -> String {
        let conn = try await connect(host: "127.0.0.1", port: socksPort)
        defer { conn.cancel() }
        try await send(conn, [5, 1, 0])
        let greeting = try await withTimeout(seconds: 5, cancel: { conn.cancel() }) { try await receive(conn, min: 2, max: 2) }
        guard Array(greeting) == [5, 0] else { throw TimeoutError() }
        let hostBytes = Array(targetHost.utf8)
        try await send(conn, [5, 1, 0, 3, UInt8(hostBytes.count)] + hostBytes + [UInt8(targetPort >> 8), UInt8(targetPort & 0xff)])
        let reply = try await withTimeout(seconds: 5, cancel: { conn.cancel() }) { try await receive(conn, min: 10, max: 10) }
        guard reply.count >= 2, reply[1] == 0 else { throw NSError(domain: "socks", code: Int(reply.count > 1 ? reply[1] : 99)) }
        let data = try await withTimeout(seconds: 5, cancel: { conn.cancel() }) { try await receive(conn) }
        return String(decoding: data, as: UTF8.self)
    }

    /// Runs `op` with a deadline. `cancel` must make `op` return (e.g. by cancelling the
    /// connection) because Network.framework callbacks ignore task cancellation.
    static func withTimeout<T>(seconds: Double, cancel: @escaping () -> Void, _ op: @escaping () async throws -> T) async throws -> T {
        let timer = Task { try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000)); cancel() }
        defer { timer.cancel() }
        return try await op()
    }
}
