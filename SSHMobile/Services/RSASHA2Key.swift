import Foundation
import CryptoKit
import NIOCore
import NIOSSH
import BigInt

/// RSA user authentication with `rsa-sha2-256` (RFC 8332). Citadel's RSA signs with SHA-1
/// (`ssh-rsa`), which OpenSSH 8.8+ rejects, so public-key auth with RSA keys goes through
/// this implementation instead: PKCS#1 v1.5 padding and plain modular exponentiation.
struct RSASHA256Signature: NIOSSHSignatureProtocol {
    static let signaturePrefix = "rsa-sha2-256"
    let rawRepresentation: Data

    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHString(rawRepresentation)
    }

    static func read(from buffer: inout ByteBuffer) throws -> RSASHA256Signature {
        guard let bytes = buffer.readSSHStringData() else { throw OpenSSHKeyError.truncated }
        return RSASHA256Signature(rawRepresentation: bytes)
    }
}

struct RSASHA256PublicKey: NIOSSHPublicKeyProtocol {
    /// Advertised as the user-auth algorithm name; the key blob itself is still `ssh-rsa`.
    static let publicKeyPrefix = "rsa-sha2-256"
    static let blobPrefix = "ssh-rsa"
    let n: BigUInt
    let e: BigUInt

    var rawRepresentation: Data {
        var w = SSHWireWriter()
        w.writeString("ssh-rsa"); w.writeMPInt(e.serialize()); w.writeMPInt(n.serialize())
        return w.data
    }

    func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool {
        let s = BigUInt(signature.rawRepresentation)
        let em = s.power(e, modulus: n).serialize()
        return RSASHA2.leftPad(em, to: n.serialize().count) == RSASHA2.encodedMessage(for: Data(data), length: n.serialize().count)
    }

    /// Body of the blob after the `ssh-rsa` type string: mpint e, mpint n.
    func write(to buffer: inout ByteBuffer) -> Int {
        var w = SSHWireWriter()
        w.writeMPInt(e.serialize()); w.writeMPInt(n.serialize())
        return buffer.writeBytes(w.data)
    }

    static func read(from buffer: inout ByteBuffer) throws -> RSASHA256PublicKey {
        guard let e = buffer.readSSHStringData(), let n = buffer.readSSHStringData() else { throw OpenSSHKeyError.truncated }
        return RSASHA256PublicKey(n: BigUInt(n), e: BigUInt(e))
    }
}

struct RSASHA256PrivateKey: NIOSSHPrivateKeyProtocol {
    static let keyPrefix = "rsa-sha2-256"
    let n: BigUInt
    let e: BigUInt
    let d: BigUInt

    init(n: Data, e: Data, d: Data) {
        self.n = BigUInt(n); self.e = BigUInt(e); self.d = BigUInt(d)
    }

    var publicKey: NIOSSHPublicKeyProtocol { RSASHA256PublicKey(n: n, e: e) }

    func signature<D: DataProtocol>(for data: D) throws -> NIOSSHSignatureProtocol {
        let k = n.serialize().count
        let em = BigUInt(RSASHA2.encodedMessage(for: Data(data), length: k))
        let s = em.power(d, modulus: n).serialize()
        return RSASHA256Signature(rawRepresentation: RSASHA2.leftPad(s, to: k))
    }
}

enum RSASHA2 {
    /// DER DigestInfo prefix for SHA-256 (RFC 8017 §9.2 note 1).
    private static let sha256Prefix: [UInt8] = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]

    /// EMSA-PKCS1-v1_5 encoding of SHA-256(message) to `length` bytes.
    static func encodedMessage(for message: Data, length: Int) -> Data {
        let t = sha256Prefix + Array(SHA256.hash(data: message))
        let padding = max(8, length - t.count - 3)
        return Data([0x00, 0x01]) + Data(repeating: 0xff, count: padding) + Data([0x00]) + Data(t)
    }

    static func leftPad(_ d: Data, to n: Int) -> Data {
        d.count >= n ? Data(d.suffix(n)) : Data(repeating: 0, count: n - d.count) + d
    }
}

private extension ByteBuffer {
    mutating func writeSSHString(_ data: Data) -> Int {
        var n = writeInteger(UInt32(data.count))
        n += writeBytes(data)
        return n
    }

    mutating func readSSHStringData() -> Data? {
        guard let length = readInteger(as: UInt32.self), let bytes = readBytes(length: Int(length)) else { return nil }
        return Data(bytes)
    }
}
