import XCTest
@testable import SSHMobile

final class KnownHostsTests: XCTestCase {
    override func setUp() {
        JSONStore.directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try? FileManager.default.createDirectory(at: JSONStore.directory, withIntermediateDirectories: true)
    }

    func testTrustOnFirstUseThenMismatch() {
        let store = KnownHostsStore()
        XCTAssertEqual(store.verify(hostname: "h", port: 22, keyType: "ssh-ed25519", publicKeyBase64: "AAAA"), .unknown)
        store.trust(hostname: "H", port: 22, keyType: "ssh-ed25519", publicKeyBase64: "AAAA", fingerprint: "SHA256:x")
        XCTAssertEqual(store.verify(hostname: "h", port: 22, keyType: "ssh-ed25519", publicKeyBase64: "AAAA"), .trusted)
        XCTAssertEqual(store.verify(hostname: "h", port: 2222, keyType: "ssh-ed25519", publicKeyBase64: "AAAA"), .unknown)
        if case .mismatch(let stored) = store.verify(hostname: "h", port: 22, keyType: "ssh-ed25519", publicKeyBase64: "BBBB") {
            XCTAssertEqual(stored.fingerprintSHA256, "SHA256:x")
        } else { XCTFail("expected mismatch") }
        // A different key type from the same host is simply unknown, like OpenSSH.
        XCTAssertEqual(store.verify(hostname: "h", port: 22, keyType: "ssh-rsa", publicKeyBase64: "CCCC"), .unknown)
        // Persisted.
        XCTAssertEqual(KnownHostsStore().entries.count, 1)
    }

    func testImportExport() throws {
        let store = KnownHostsStore()
        let pub = try Fixtures.text("id_ed25519.pub").split(separator: " ")
        let text = "example.com \(pub[0]) \(pub[1])\n[example.org]:2200 \(pub[0]) \(pub[1])\n|1|hashed|x ssh-rsa AAAA\n"
        XCTAssertEqual(store.importKnownHosts(text), 2)
        XCTAssertEqual(store.verify(hostname: "example.org", port: 2200, keyType: "ssh-ed25519", publicKeyBase64: String(pub[1])), .trusted)
        XCTAssertEqual(store.entries.first?.fingerprintSHA256, try Fixtures.fingerprints()["test-ed25519"])
        let exported = store.exportKnownHosts()
        XCTAssertTrue(exported.contains("[example.org]:2200 ssh-ed25519 "))
    }
}
