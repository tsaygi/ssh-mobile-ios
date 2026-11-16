import XCTest
@testable import SSHMobile

final class OpenSSHKeyTests: XCTestCase {
    func testParsesSSHKeygenFixtures() throws {
        let fps = try Fixtures.fingerprints()
        for (file, type) in [("id_ed25519", Identity.KeyType.ed25519), ("id_ecdsa", .ecdsaP256), ("id_rsa", .rsa2048)] {
            let parsed = try OpenSSHPrivateKey.parse(try Fixtures.text(file), passphrase: nil)
            XCTAssertNotNil(parsed.material, file)
            XCTAssertFalse(parsed.isEncrypted)
            XCTAssertEqual(parsed.publicKey.keyType, type, file)
            let pub = try Fixtures.text(file + ".pub").trimmingCharacters(in: .whitespacesAndNewlines)
            XCTAssertEqual(parsed.publicKey.openSSHLine(comment: parsed.comment), pub, file)
            XCTAssertEqual(parsed.publicKey.fingerprint, fps[parsed.comment], file)
            // The private half must reproduce the same public key.
            XCTAssertEqual(parsed.material!.publicKey.blob, parsed.publicKey.blob, file)
        }
    }

    func testEncryptedFixtures() throws {
        for file in ["id_ed25519_enc", "id_ecdsa_enc", "id_rsa_enc"] {
            let text = try Fixtures.text(file)
            let locked = try OpenSSHPrivateKey.parse(text, passphrase: nil)
            XCTAssertTrue(locked.isEncrypted, file)
            XCTAssertNil(locked.material, file)
            XCTAssertThrowsError(try OpenSSHPrivateKey.parse(text, passphrase: "wrong"), file) { error in
                XCTAssertEqual(error as? OpenSSHKeyError, .wrongPassphrase, file)
            }
            let unlocked = try OpenSSHPrivateKey.parse(text, passphrase: "secret")
            XCTAssertNotNil(unlocked.material, file)
            XCTAssertEqual(unlocked.material!.publicKey.blob, unlocked.publicKey.blob, file)
            let pub = try Fixtures.text(file + ".pub").trimmingCharacters(in: .whitespacesAndNewlines)
            XCTAssertEqual(unlocked.publicKey.openSSHLine(comment: unlocked.comment), pub, file)
        }
    }

    func testGenerateSerializeParseRoundTrip() throws {
        for type in KeyGenerator.generatableTypes {
            let material = try KeyGenerator.generate(type)
            let plain = try OpenSSHPrivateKey.serialize(material, comment: "rt")
            let parsed = try OpenSSHPrivateKey.parse(plain, passphrase: nil)
            XCTAssertEqual(parsed.publicKey.blob, material.publicKey.blob, type.rawValue)
            XCTAssertEqual(parsed.comment, "rt")

            let encrypted = try OpenSSHPrivateKey.serialize(material, comment: "rt", passphrase: "hunter2")
            XCTAssertTrue(try OpenSSHPrivateKey.parse(encrypted, passphrase: nil).isEncrypted)
            let unlocked = try OpenSSHPrivateKey.parse(encrypted, passphrase: "hunter2")
            XCTAssertEqual(unlocked.material!.publicKey.blob, material.publicKey.blob, type.rawValue)
        }
    }

    func testRSARoundTripPreservesComponents() throws {
        let parsed = try OpenSSHPrivateKey.parse(try Fixtures.text("id_rsa"), passphrase: nil)
        let text = try OpenSSHPrivateKey.serialize(parsed.material!, comment: parsed.comment, passphrase: "x")
        let again = try OpenSSHPrivateKey.parse(text, passphrase: "x")
        guard case .rsa(let n1, let e1, let d1, let i1, let p1, let q1) = parsed.material!,
              case .rsa(let n2, let e2, let d2, let i2, let p2, let q2) = again.material! else { return XCTFail() }
        XCTAssertEqual([n1, e1, d1, i1, p1, q1], [n2, e2, d2, i2, p2, q2])
    }

    func testRejectsGarbage() {
        XCTAssertThrowsError(try OpenSSHPrivateKey.parse("not a key", passphrase: nil))
        XCTAssertThrowsError(try OpenSSHPrivateKey.parse("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----", passphrase: nil))
    }

    func testPublicLineParsing() throws {
        let line = try Fixtures.text("id_ed25519.pub")
        let (key, comment) = try OpenSSHPrivateKey.parsePublicLine(line)
        XCTAssertEqual(key.keyType, .ed25519)
        XCTAssertEqual(comment, "test-ed25519")
    }
}
