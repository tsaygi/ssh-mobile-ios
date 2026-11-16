import XCTest
@testable import SSHMobile

/// End-to-end tests against the Docker OpenSSH server (see scripts/test-server.sh).
/// They are skipped when nothing listens on 127.0.0.1:2222.
@MainActor
final class IntegrationTests: XCTestCase {
    var hosts: HostStore!
    var identities: IdentityStore!
    var knownHosts: KnownHostsStore!
    var responders: [Task<Void, Never>] = []
    var sessions: [SSHSession] = []

    override func setUp() async throws {
        guard await TestServer.isReachable() else { throw XCTSkip("test SSH server not running on 127.0.0.1:2222") }
        JSONStore.directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: JSONStore.directory, withIntermediateDirectories: true)
        hosts = HostStore(); identities = IdentityStore(); knownHosts = KnownHostsStore()
    }

    override func tearDown() async throws {
        responders.forEach { $0.cancel() }
        for s in sessions { await s.disconnect() }
        identities?.delete(Set(identities.identities.map(\.id)))
    }

    private func makeSession(_ profile: HostProfile, respond: Bool = true) -> SSHSession {
        hosts.upsert(profile)
        let s = SSHSession(host: profile, hostStore: hosts, identityStore: identities, knownHosts: knownHosts)
        sessions.append(s)
        if respond { responders.append(autoRespond(s)) }
        return s
    }

    private func connected(_ profile: HostProfile) async throws -> SSHSession {
        let s = makeSession(profile)
        await s.connect()
        XCTAssertEqual(s.state, .connected, s.events.map(\.message).joined(separator: "\n"))
        return s
    }

    // MARK: Authentication and host keys

    func testPasswordAuthAndExec() async throws {
        let s = try await connected(TestServer.profile())
        let r = try await s.runCommand("echo hello; echo oops 1>&2; exit 3")
        XCTAssertEqual(r.stdout, "hello\n")
        XCTAssertEqual(r.stderr, "oops\n")
        XCTAssertEqual(r.exitCode, 3)
        XCTAssertEqual(knownHosts.entries.count, 1, "host key recorded on first use")
    }

    func testWrongPasswordFails() async throws {
        let s = makeSession(TestServer.profile(), respond: false)
        responders.append(autoRespond(s, password: "nope"))
        await s.connect()
        guard case .failed(let why) = s.state else { return XCTFail("expected failure, got \(s.state)") }
        XCTAssertTrue(why.lowercased().contains("denied") || why.lowercased().contains("auth"), why)
    }

    func testRejectedHostKeyFails() async throws {
        let s = makeSession(TestServer.profile(), respond: false)
        responders.append(autoRespond(s, trustHostKey: false))
        await s.connect()
        guard case .failed(let why) = s.state else { return XCTFail("expected failure, got \(s.state)") }
        XCTAssertTrue(why.contains("Host key"), why)
        XCTAssertEqual(knownHosts.entries.count, 0)
    }

    func testChangedHostKeyIsFlagged() async throws {
        // Seed a bogus key of the type the server will present.
        let first = try await connected(TestServer.profile())
        await first.disconnect()
        let real = knownHosts.entries[0]
        knownHosts.remove([real.id])
        knownHosts.trust(hostname: real.hostname, port: real.port, keyType: real.keyType, publicKeyBase64: "AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", fingerprint: "SHA256:bogus")

        let s = makeSession(TestServer.profile(), respond: false)
        var sawMismatch = false
        responders.append(Task { @MainActor in
            while !Task.isCancelled {
                if let p = s.hostKeyPrompt { sawMismatch = p.isMismatch; p.decide(false) }
                try? await Task.sleep(nanoseconds: 30_000_000)
            }
        })
        await s.connect()
        XCTAssertTrue(sawMismatch)
        guard case .failed = s.state else { return XCTFail("expected failure") }
    }

    func testKeyAuthForEveryKeyType() async throws {
        for file in ["id_ed25519", "id_ecdsa", "id_rsa", "id_ed25519_enc", "id_ecdsa_enc", "id_rsa_enc"] {
            let identity = try identities.add(name: file, privateKeyText: try Fixtures.text(file))
            let s = try await connected(TestServer.profile(auth: .publicKey, identity: identity.id))
            let r = try await s.runCommand("echo \(file)")
            XCTAssertEqual(r.stdout, "\(file)\n")
            await s.disconnect()
        }
    }

    func testUnauthorizedKeyFallsBackToPassword() async throws {
        // Like OpenSSH: when the key is rejected, continue with password authentication.
        let fresh = try OpenSSHPrivateKey.serialize(try KeyGenerator.generate(.ed25519), comment: "unauthorized")
        let identity = try identities.add(name: "unauthorized", privateKeyText: fresh)
        let s = try await connected(TestServer.profile(auth: .publicKey, identity: identity.id))
        let r = try await s.runCommand("echo fallback")
        XCTAssertEqual(r.stdout, "fallback\n")
    }

    // MARK: Interactive shell

    func testPTYShellRoundTrip() async throws {
        var p = TestServer.profile()
        p.environment = ["SSHMOBILE_TEST": "env-ok"]
        let s = try await connected(p)
        var received = ""
        s.terminalSink = { bytes in received += String(decoding: bytes, as: UTF8.self) }
        s.resize(cols: 100, rows: 30)
        do { try await waitUntil { received.contains("$") } }          // shell prompt
        catch { XCTFail("no prompt. received=\(received.debugDescription) events=\(s.events.map(\.message))"); throw error }
        s.send(text: "echo PTY-$((20+22)) $SSHMOBILE_TEST; stty size\n")
        try await waitUntil { received.contains("PTY-42 env-ok") && received.contains("30 100") }
        s.send(text: "exit\n")
        try await waitUntil { if case .disconnected = s.state { return true } else { return false } }
        XCTAssertEqual(s.exitStatus, 0)
    }

    func testRemoteCommandWithoutTTY() async throws {
        var p = TestServer.profile()
        p.requestTTY = false
        p.remoteCommand = "printf 'no-tty\\n'; exit 7"
        let s = makeSession(p)
        var received = ""
        s.terminalSink = { bytes in received += String(decoding: bytes, as: UTF8.self) }
        await s.connect()
        try await waitUntil { if case .disconnected = s.state { return true } else { return false } }
        XCTAssertTrue(received.contains("no-tty"), received)
        XCTAssertEqual(s.exitStatus, 7)
    }

    // MARK: Port forwarding

    func testLocalForward() async throws {
        var p = TestServer.profile()
        var f = PortForward(kind: .local); f.bindPort = 0; f.targetHost = "127.0.0.1"; f.targetPort = 22
        p.portForwards = [f]
        let s = try await connected(p)
        try await waitUntil { if case .active = s.forwardStates[f.id] { return true } else { return false } }
        guard case .active(let port) = s.forwardStates[f.id] else { return XCTFail() }
        let banner = try await TCP.readBanner(host: "127.0.0.1", port: port)
        XCTAssertTrue(banner.hasPrefix("SSH-2.0-OpenSSH"), banner)
        s.stopForward(f.id)
    }

    func testDynamicSOCKSForward() async throws {
        var p = TestServer.profile()
        var f = PortForward(kind: .dynamic); f.bindPort = 0
        p.portForwards = [f]
        let s = try await connected(p)
        try await waitUntil { if case .active = s.forwardStates[f.id] { return true } else { return false } }
        guard case .active(let port) = s.forwardStates[f.id] else { return XCTFail() }
        let banner = try await TCP.readBannerViaSOCKS5(socksPort: port, targetHost: "localhost", targetPort: 22)
        XCTAssertTrue(banner.hasPrefix("SSH-2.0-OpenSSH"), banner)
    }

    func testRemoteForward() async throws {
        // Server-side listener forwarded back to the Mac's mapped sshd port; verified from
        // inside the server with busybox nc.
        var p = TestServer.profile()
        var f = PortForward(kind: .remote); f.bindAddress = "127.0.0.1"; f.bindPort = Int.random(in: 20000...40000)
        f.targetHost = "127.0.0.1"; f.targetPort = TestServer.port
        p.portForwards = [f]
        let s = try await connected(p)
        try await waitUntil { if case .active = s.forwardStates[f.id] { return true } else { return false } }
        guard case .active(let port) = s.forwardStates[f.id], port > 0 else { return XCTFail("\(String(describing: s.forwardStates[f.id]))") }
        let r = try await s.runCommand("sleep 2 | nc 127.0.0.1 \(port) | head -c 7")
        XCTAssertEqual(r.stdout, "SSH-2.0", "stderr: \(r.stderr)")
    }

    // MARK: Jump host and SFTP

    func testProxyJump() async throws {
        let jump = TestServer.profile()
        hosts.upsert(jump)
        var target = HostProfile(name: "inner", hostname: "127.0.0.1", port: 22, username: TestServer.user)
        target.jumpHostID = jump.id
        target.keepAliveSeconds = 0
        let s = try await connected(target)
        let r = try await s.runCommand("echo via-jump")
        XCTAssertEqual(r.stdout, "via-jump\n")
        XCTAssertEqual(Set(knownHosts.entries.map(\.port)), [22, 2222])
    }

    func testSFTP() async throws {
        let s = try await connected(TestServer.profile())
        let sftp = try await s.openSFTP()
        let home = try await sftp.getRealPath(atPath: ".")
        XCTAssertEqual(home, "/home/tester")
        let dir = "\(home)/sftp-\(UUID().uuidString.prefix(8))"
        try await sftp.createDirectory(atPath: dir)
        let file = try await sftp.openFile(filePath: "\(dir)/hello.txt", flags: [.write, .create, .truncate])
        try await file.write(.init(string: "hello sftp"), at: 0)
        try await file.close()
        let names = try await sftp.listDirectory(atPath: dir).flatMap(\.components).map(\.filename)
        XCTAssertTrue(names.contains("hello.txt"), "\(names)")
        let read = try await sftp.openFile(filePath: "\(dir)/hello.txt", flags: .read)
        let content = try await read.readAll()
        XCTAssertEqual(String(buffer: content), "hello sftp")
        try await read.close()
        try await sftp.rename(at: "\(dir)/hello.txt", to: "\(dir)/renamed.txt")
        try await sftp.remove(at: "\(dir)/renamed.txt")
        try await sftp.rmdir(at: dir)
        try await sftp.close()
    }
}
