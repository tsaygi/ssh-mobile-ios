import Foundation
import Observation
import NIOCore
import NIOSSH
import Citadel

/// One SSH connection: jump chain, authentication, interactive shell (or remote command),
/// port forwards, and SFTP. UI observes `state`, `events`, and the prompt properties.
@MainActor
@Observable
final class SSHSession: Identifiable {
    enum State: Equatable {
        case idle
        case connecting(String)
        case connected
        case disconnected(String?)
        case failed(String)

        var isConnected: Bool { self == .connected }
        var isBusy: Bool { if case .connecting = self { return true } else { return false } }
        var canReconnect: Bool {
            switch self { case .disconnected, .failed, .idle: return true; default: return false }
        }
    }

    struct HostKeyPrompt: Identifiable {
        let id = UUID()
        let hostname: String
        let port: Int
        let keyType: String
        let fingerprint: String
        let previousFingerprint: String?
        let decide: (Bool) -> Void
        var isMismatch: Bool { previousFingerprint != nil }
    }

    struct CredentialPrompt: Identifiable {
        enum Kind { case password(username: String, host: String), passphrase(keyName: String) }
        let id = UUID()
        let kind: Kind
        let message: String?
        let submit: (String?, _ remember: Bool) -> Void
    }

    let id = UUID()
    let host: HostProfile
    private(set) var state: State = .idle
    var title: String
    private(set) var events: [SessionEvent] = []
    var hostKeyPrompt: HostKeyPrompt?
    var credentialPrompt: CredentialPrompt?
    private(set) var forwardStates: [UUID: ForwardState] = [:]
    private(set) var exitStatus: Int?
    private(set) var bytesReceived = 0
    private(set) var cols = 80
    private(set) var rows = 24
    var fontSize: Double

    /// Set by the terminal view. Output is buffered until it attaches.
    var terminalSink: ((ArraySlice<UInt8>) -> Void)? {
        didSet { flushPending() }
    }
    private var pending: [UInt8] = []

    private let hostStore: HostStore
    private let identityStore: IdentityStore
    private let knownHosts: KnownHostsStore

    private var clients: [SSHClient] = []
    var client: SSHClient? { clients.last }
    private var stdin: TTYStdinWriter?
    private var shellTask: Task<Void, Never>?
    private var keepAliveTask: Task<Void, Never>?
    private var writerTask: Task<Void, Never>?
    private var outbound: AsyncStream<[UInt8]>.Continuation?
    private var forwarders: [UUID: PortForwarder] = [:]

    init(host: HostProfile, hostStore: HostStore, identityStore: IdentityStore, knownHosts: KnownHostsStore) {
        self.host = host
        self.hostStore = hostStore
        self.identityStore = identityStore
        self.knownHosts = knownHosts
        self.title = host.displayName
        self.fontSize = host.fontSize
    }

    // MARK: - Lifecycle

    func connect() async {
        guard state.canReconnect else { return }
        exitStatus = nil
        let chain: [HostProfile]
        do { chain = try resolveChain() } catch { fail(error); return }

        do {
            var current: SSHClient?
            for hop in chain {
                let isTarget = hop.id == host.id
                state = .connecting(isTarget ? "Connecting to \(hop.hostname):\(hop.port)…" : "Via jump host \(hop.displayName)…")
                log("Connecting to \(hop.hostname) port \(hop.port)")
                let auth = try await makeAuth(for: hop)
                var settings = SSHClientSettings(
                    host: hop.hostname, port: hop.port,
                    authenticationMethod: { .custom(auth) },
                    hostKeyValidator: .custom(makeVerifier(for: hop)))
                settings.connectTimeout = .seconds(Int64(max(1, hop.connectTimeoutSeconds)))
                settings.loginTimeout = .seconds(300) // leave time for password/passphrase prompts
                let next: SSHClient
                if let current { next = try await current.jump(to: settings) } else { next = try await SSHClient.connect(to: settings) }
                clients.append(next)
                current = next
                log("Authenticated to \(hop.hostname) as \(hop.username)")
            }
        } catch {
            fail(error)
            await teardownClients()
            return
        }

        state = .connected
        hostStore.markConnected(host.id)
        client?.onDisconnect { [weak self] in
            Task { @MainActor in self?.handleRemoteDisconnect() }
        }
        startForwards()
        startShell()
        startKeepAlive()
    }

    func disconnect() async {
        log("Disconnecting")
        shellTask?.cancel()
        keepAliveTask?.cancel()
        for f in forwarders.values { f.stop() }
        forwarders.removeAll()
        await teardownClients()
        if state == .connected || state.isBusy { state = .disconnected(nil) }
    }

    private func teardownClients() async {
        stdin = nil
        outbound?.finish()
        outbound = nil
        writerTask?.cancel()
        for c in clients.reversed() { try? await c.close() }
        clients.removeAll()
    }

    private func handleRemoteDisconnect() {
        guard state == .connected else { return }
        state = .disconnected("Connection closed by remote host")
        log("Connection closed by remote host")
        shellTask?.cancel()
        keepAliveTask?.cancel()
        for f in forwarders.values { f.stop() }
    }

    private func fail(_ error: Error) {
        let text = Self.describe(error)
        state = .failed(text)
        log(text, level: .error)
        log("Underlying error: \(error)", level: .error)
    }

    // MARK: - Jump chain

    private func resolveChain() throws -> [HostProfile] {
        var chain = [host]
        var seen: Set<UUID> = [host.id]
        var cursor = host
        while let jumpID = cursor.jumpHostID {
            guard let jump = hostStore.host(id: jumpID) else { throw SessionError.missingJumpHost }
            guard !seen.contains(jump.id) else { throw SessionError.jumpLoop }
            seen.insert(jump.id)
            chain.insert(jump, at: 0)
            cursor = jump
        }
        return chain
    }

    // MARK: - Authentication

    private func makeAuth(for hop: HostProfile) async throws -> OfferChainAuthDelegate {
        var providers: [OfferChainAuthDelegate.Provider] = []
        let username = hop.username

        func passwordProviders() -> [OfferChainAuthDelegate.Provider] {
            var saved = CredentialStore.password(for: hop.id)
            var attempts = 0
            let provider: OfferChainAuthDelegate.Provider = { [weak self] _ in
                guard let self else { return nil }
                attempts += 1
                if let p = saved { saved = nil; return SSHAuthBuilder.passwordOffer(username: username, password: p) }
                let message = attempts > 1 ? "Permission denied, please try again." : nil
                guard let (p, remember) = await self.promptPassword(username: username, host: hop.hostname, message: message) else { return nil }
                if remember { CredentialStore.save(password: p, for: hop.id) }
                return SSHAuthBuilder.passwordOffer(username: username, password: p)
            }
            return [provider, provider, provider]
        }

        switch hop.authMethod {
        case .none:
            providers.append { _ in SSHAuthBuilder.noneOffer(username: username) }
        case .password, .keyboardInteractive:
            if hop.authMethod == .keyboardInteractive {
                log("keyboard-interactive is not supported by the SSH transport; using password authentication", level: .warning)
            }
            providers.append(contentsOf: passwordProviders())
        case .publicKey:
            guard let identity = identityStore.identity(id: hop.identityID) else { throw SessionError.missingIdentity }
            let material = try await loadKey(identity)
            let offer = try SSHAuthBuilder.offer(username: username, material: material)
            providers.append { _ in offer }
            // Like OpenSSH, fall back to password if the key is rejected.
            providers.append(contentsOf: passwordProviders())
        }
        return OfferChainAuthDelegate(providers: providers) { [weak self] error in
            Task { @MainActor in self?.log("Authentication error: \(error.localizedDescription)", level: .warning) }
        }
    }

    private func loadKey(_ identity: Identity) async throws -> PrivateKeyMaterial {
        guard let text = try identityStore.privateKeyText(for: identity.id) else { throw SessionError.missingIdentity }
        var parsed = try OpenSSHPrivateKey.parse(text, passphrase: nil)
        var message: String? = nil
        var attempts = 0
        while parsed.material == nil {
            attempts += 1
            guard attempts <= 3, let (passphrase, _) = await promptPassphrase(keyName: identity.name, message: message) else {
                throw SessionError.cancelled
            }
            do {
                parsed = try OpenSSHPrivateKey.parse(text, passphrase: passphrase)
            } catch OpenSSHKeyError.wrongPassphrase {
                message = "Incorrect passphrase."
            }
        }
        return parsed.material!
    }

    private func promptPassword(username: String, host: String, message: String?) async -> (String, Bool)? {
        await withCheckedContinuation { cont in
            credentialPrompt = CredentialPrompt(kind: .password(username: username, host: host), message: message) { value, remember in
                self.credentialPrompt = nil
                cont.resume(returning: value.map { ($0, remember) })
            }
        }
    }

    private func promptPassphrase(keyName: String, message: String?) async -> (String, Bool)? {
        await withCheckedContinuation { cont in
            credentialPrompt = CredentialPrompt(kind: .passphrase(keyName: keyName), message: message) { value, remember in
                self.credentialPrompt = nil
                cont.resume(returning: value.map { ($0, remember) })
            }
        }
    }

    // MARK: - Host keys

    private func makeVerifier(for hop: HostProfile) -> HostKeyVerifier {
        HostKeyVerifier { [weak self] presented in
            guard let self else { return false }
            return await self.decideHostKey(hop: hop, presented: presented)
        }
    }

    private func decideHostKey(hop: HostProfile, presented: HostKeyVerifier.Presented) async -> Bool {
        switch knownHosts.verify(hostname: hop.hostname, port: hop.port, keyType: presented.keyType, publicKeyBase64: presented.base64) {
        case .trusted:
            log("Host key \(presented.keyType) \(presented.fingerprint) matches known_hosts")
            return true
        case .unknown:
            let ok = await askHostKey(hop: hop, presented: presented, previous: nil)
            if ok {
                knownHosts.trust(hostname: hop.hostname, port: hop.port, keyType: presented.keyType, publicKeyBase64: presented.base64, fingerprint: presented.fingerprint)
                log("Permanently added \(hop.hostname) (\(presented.keyType)) to known hosts", level: .warning)
            }
            return ok
        case .mismatch(let stored):
            log("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED for \(hop.hostname)", level: .error)
            let ok = await askHostKey(hop: hop, presented: presented, previous: stored.fingerprintSHA256)
            if ok {
                knownHosts.trust(hostname: hop.hostname, port: hop.port, keyType: presented.keyType, publicKeyBase64: presented.base64, fingerprint: presented.fingerprint)
                log("Replaced host key for \(hop.hostname)", level: .warning)
            }
            return ok
        }
    }

    private func askHostKey(hop: HostProfile, presented: HostKeyVerifier.Presented, previous: String?) async -> Bool {
        await withCheckedContinuation { cont in
            hostKeyPrompt = HostKeyPrompt(hostname: hop.hostname, port: hop.port, keyType: presented.keyType,
                                          fingerprint: presented.fingerprint, previousFingerprint: previous) { accept in
                self.hostKeyPrompt = nil
                cont.resume(returning: accept)
            }
        }
    }

    // MARK: - Shell / command

    private func startShell() {
        let env = host.environment.map { SSHChannelRequestEvent.EnvironmentRequest(wantReply: false, name: $0.key, value: $0.value) }
        let command = host.remoteCommand.trimmingCharacters(in: .whitespacesAndNewlines)
        let wantsPTY = host.requestTTY || command.isEmpty
        let request = SSHChannelRequestEvent.PseudoTerminalRequest(
            wantReply: true, term: host.terminalType,
            terminalCharacterWidth: cols, terminalRowHeight: rows,
            terminalPixelWidth: 0, terminalPixelHeight: 0,
            terminalModes: SSHTerminalModes([:]))

        shellTask = Task { [weak self] in
            guard let self, let client = self.client else { return }
            // Exit status arrives as a thrown CommandFailed at the end of the stream; Citadel's
            // own close() may then throw "already closed" and mask it, so record it here.
            let exitBox = ExitBox()
            do {
                if wantsPTY {
                    try await client.withPTY(request, environment: env) { @Sendable inbound, writer in
                        // Citadel invokes this closure on a non-main thread.
                        await MainActor.run { self.attachStdin(writer) }
                        if !command.isEmpty {
                            try await writer.write(ByteBuffer(string: command + "; exit\n"))
                        }
                        do {
                            for try await chunk in inbound { await MainActor.run { self.feed(chunk) } }
                        } catch let failure as SSHClient.CommandFailed {
                            exitBox.code = failure.exitCode
                        }
                    }
                } else {
                    let stream = try await client.executeCommandStream(command, environment: env)
                    do {
                        for try await chunk in stream { self.feed(chunk) }
                    } catch let failure as SSHClient.CommandFailed {
                        exitBox.code = failure.exitCode
                    }
                }
                await self.shellEnded(status: exitBox.code ?? 0, error: nil)
            } catch let failure as SSHClient.CommandFailed {
                await self.shellEnded(status: failure.exitCode, error: nil)
            } catch let channelError as ChannelError where channelError == .alreadyClosed {
                await self.shellEnded(status: exitBox.code ?? 0, error: nil)
            } catch {
                await self.shellEnded(status: exitBox.code, error: error)
            }
        }
    }

    private final class ExitBox: @unchecked Sendable { var code: Int? }

    private func attachStdin(_ writer: TTYStdinWriter) {
        stdin = writer
        let (stream, continuation) = AsyncStream<[UInt8]>.makeStream()
        outbound = continuation
        writerTask = Task {
            for await bytes in stream {
                try? await writer.write(ByteBuffer(bytes: bytes))
            }
        }
        Task { try? await writer.changeSize(cols: cols, rows: rows, pixelWidth: 0, pixelHeight: 0) }
    }

    private func shellEnded(status: Int?, error: Error?) async {
        guard !Task.isCancelled else { return }
        exitStatus = status
        if let error {
            let text = Self.describe(error)
            log("Session ended: \(text)", level: .error)
            feedText("\r\n[\(text)]\r\n")
            state = .disconnected(text)
        } else {
            let text = status == 0 || status == nil ? "Session closed" : "Remote process exited with status \(status!)"
            log(text)
            feedText("\r\n[\(text)]\r\n")
            state = .disconnected(text)
        }
        keepAliveTask?.cancel()
        for f in forwarders.values { f.stop() }
        forwarders.removeAll()
        await teardownClients()
    }

    private func feed(_ output: ExecCommandOutput) {
        switch output {
        case .stdout(let buf), .stderr(let buf):
            let bytes = Array(buf.readableBytesView)
            bytesReceived += bytes.count
            if let sink = terminalSink { sink(bytes[...]) } else { pending.append(contentsOf: bytes) }
        }
    }

    private func feedText(_ text: String) {
        let bytes = Array(text.utf8)
        if let sink = terminalSink { sink(bytes[...]) } else { pending.append(contentsOf: bytes) }
    }

    private func flushPending() {
        guard let sink = terminalSink, !pending.isEmpty else { return }
        sink(pending[...])
        pending.removeAll()
    }

    /// Keystrokes from the terminal view.
    func send(_ bytes: ArraySlice<UInt8>) {
        outbound?.yield(Array(bytes))
    }

    func send(text: String) { send(Array(text.utf8)[...]) }

    func resize(cols: Int, rows: Int) {
        guard cols > 0, rows > 0, cols != self.cols || rows != self.rows else { return }
        self.cols = cols
        self.rows = rows
        guard let stdin else { return }
        Task { try? await stdin.changeSize(cols: cols, rows: rows, pixelWidth: 0, pixelHeight: 0) }
    }

    /// The transport has no public keepalive request, so a no-op window-change request is
    /// sent instead; it keeps NAT mappings alive and detects dead connections.
    private func startKeepAlive() {
        guard host.keepAliveSeconds > 0 else { return }
        let interval = UInt64(host.keepAliveSeconds)
        keepAliveTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: interval * 1_000_000_000)
                guard let self, let stdin = self.stdin else { continue }
                do { try await stdin.changeSize(cols: self.cols, rows: self.rows, pixelWidth: 0, pixelHeight: 0) }
                catch { self.log("Keepalive failed: \(error.localizedDescription)", level: .warning) }
            }
        }
    }

    // MARK: - Port forwards

    private func startForwards() {
        guard let client else { return }
        for f in host.portForwards where f.enabled {
            startForward(f, client: client)
        }
    }

    func startForward(_ f: PortForward) {
        guard let client else { return }
        startForward(f, client: client)
    }

    private func startForward(_ f: PortForward, client: SSHClient) {
        forwarders[f.id]?.stop()
        let forwarder = PortForwarder(forward: f, client: client,
                                      onState: { [weak self] s in Task { @MainActor in self?.forwardStates[f.id] = s } },
                                      log: { [weak self] m in Task { @MainActor in self?.log(m, level: .warning) } })
        forwarders[f.id] = forwarder
        Task { await forwarder.start() }
    }

    func stopForward(_ id: UUID) {
        forwarders[id]?.stop()
        forwarders[id] = nil
    }

    // MARK: - One-off commands and SFTP

    struct CommandResult { var stdout: String; var stderr: String; var exitCode: Int }

    func runCommand(_ command: String) async throws -> CommandResult {
        guard let client else { throw SessionError.notConnected }
        var out = "", err = ""
        var code = 0
        do {
            let stream = try await client.executeCommandStream(command)
            for try await chunk in stream {
                switch chunk {
                case .stdout(let b): out += String(buffer: b)
                case .stderr(let b): err += String(buffer: b)
                }
            }
        } catch let failure as SSHClient.CommandFailed {
            code = failure.exitCode
        }
        return CommandResult(stdout: out, stderr: err, exitCode: code)
    }

    func openSFTP() async throws -> SFTPClient {
        guard let client else { throw SessionError.notConnected }
        return try await client.openSFTP()
    }

    // MARK: - Logging

    func log(_ message: String, level: SessionEvent.Level = .info) {
        events.append(SessionEvent(message: message, level: level))
        if events.count > 500 { events.removeFirst(events.count - 500) }
    }

    static func describe(_ error: Error) -> String {
        if let e = error as? SessionError { return e.localizedDescription }
        if error is InvalidHostKey || error is HostKeyRejected { return "Host key verification failed." }
        if error is AuthenticationExhausted { return "Permission denied (authentication failed)." }
        if let e = error as? OpenSSHKeyError { return e.localizedDescription }
        let text = "\(error)"
        if text.contains("connectTimeout") || text.contains("timed out") { return "Connection timed out." }
        if text.contains("Connection refused") || text.contains("connectionRefused") { return "Connection refused." }
        if text.contains("nodename nor servname") || text.contains("getaddrinfo") || text.contains("unknownHost") { return "Could not resolve hostname." }
        if text.contains("authentication") || text.contains("Authentication") || text.contains("allAuthenticationOptionsFailed") { return "Permission denied (authentication failed)." }
        if text.contains("connectionClosed") || text.contains("ioOnClosedChannel") { return "Connection closed." }
        return (error as? LocalizedError)?.errorDescription ?? text
    }
}

enum SessionError: LocalizedError {
    case missingJumpHost, jumpLoop, missingIdentity, cancelled, notConnected

    var errorDescription: String? {
        switch self {
        case .missingJumpHost: return "The configured jump host no longer exists."
        case .jumpLoop: return "ProxyJump configuration forms a loop."
        case .missingIdentity: return "No private key is selected for this host."
        case .cancelled: return "Cancelled."
        case .notConnected: return "Not connected."
        }
    }
}
