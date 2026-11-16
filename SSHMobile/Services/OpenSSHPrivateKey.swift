import Foundation
import CryptoKit
import CommonCrypto
import CCitadelBcrypt

/// Public half of a key pair, in SSH wire form.
struct SSHPublicKeyBlob: Hashable {
    let keyType: Identity.KeyType
    /// Full wire blob: string(type) + type-specific fields.
    let blob: Data

    var typeName: String { keyType.sshName }
    var fingerprint: String { import_sha256(blob) }
    var base64: String { blob.base64EncodedString() }

    func openSSHLine(comment: String) -> String {
        comment.isEmpty ? "\(typeName) \(base64)" : "\(typeName) \(base64) \(comment)"
    }
}

/// Decoded private key material, independent of file encoding.
enum PrivateKeyMaterial {
    case ed25519(Curve25519.Signing.PrivateKey)
    case p256(P256.Signing.PrivateKey)
    case p384(P384.Signing.PrivateKey)
    case p521(P521.Signing.PrivateKey)
    /// Raw big-endian magnitudes as stored in the OpenSSH format.
    case rsa(n: Data, e: Data, d: Data, iqmp: Data, p: Data, q: Data)

    var publicKey: SSHPublicKeyBlob {
        var w = SSHWireWriter()
        switch self {
        case .ed25519(let k):
            w.writeString("ssh-ed25519"); w.writeString(k.publicKey.rawRepresentation)
            return SSHPublicKeyBlob(keyType: .ed25519, blob: w.data)
        case .p256(let k):
            w.writeString("ecdsa-sha2-nistp256"); w.writeString("nistp256"); w.writeString(k.publicKey.x963Representation)
            return SSHPublicKeyBlob(keyType: .ecdsaP256, blob: w.data)
        case .p384(let k):
            w.writeString("ecdsa-sha2-nistp384"); w.writeString("nistp384"); w.writeString(k.publicKey.x963Representation)
            return SSHPublicKeyBlob(keyType: .ecdsaP384, blob: w.data)
        case .p521(let k):
            w.writeString("ecdsa-sha2-nistp521"); w.writeString("nistp521"); w.writeString(k.publicKey.x963Representation)
            return SSHPublicKeyBlob(keyType: .ecdsaP521, blob: w.data)
        case .rsa(let n, let e, _, _, _, _):
            w.writeString("ssh-rsa"); w.writeMPInt(e); w.writeMPInt(n)
            let bits = n.count * 8
            let type: Identity.KeyType = bits >= 4096 ? .rsa4096 : (bits >= 3072 ? .rsa3072 : .rsa2048)
            return SSHPublicKeyBlob(keyType: type, blob: w.data)
        }
    }

    /// Type-specific private section as written inside an OpenSSH key file.
    fileprivate func writePrivateSection(into w: inout SSHWireWriter) {
        switch self {
        case .ed25519(let k):
            w.writeString("ssh-ed25519")
            w.writeString(k.publicKey.rawRepresentation)
            w.writeString(k.rawRepresentation + k.publicKey.rawRepresentation)
        case .p256(let k):
            w.writeString("ecdsa-sha2-nistp256"); w.writeString("nistp256")
            w.writeString(k.publicKey.x963Representation); w.writeMPInt(k.rawRepresentation)
        case .p384(let k):
            w.writeString("ecdsa-sha2-nistp384"); w.writeString("nistp384")
            w.writeString(k.publicKey.x963Representation); w.writeMPInt(k.rawRepresentation)
        case .p521(let k):
            w.writeString("ecdsa-sha2-nistp521"); w.writeString("nistp521")
            w.writeString(k.publicKey.x963Representation); w.writeMPInt(k.rawRepresentation)
        case .rsa(let n, let e, let d, let iqmp, let p, let q):
            w.writeString("ssh-rsa")
            w.writeMPInt(n); w.writeMPInt(e); w.writeMPInt(d); w.writeMPInt(iqmp); w.writeMPInt(p); w.writeMPInt(q)
        }
    }
}

struct ParsedPrivateKey {
    let material: PrivateKeyMaterial?   // nil when encrypted and no passphrase was supplied
    let publicKey: SSHPublicKeyBlob
    let comment: String
    let isEncrypted: Bool
}

/// Parser and serializer for the `openssh-key-v1` private key container used by
/// `ssh-keygen` since OpenSSH 7.8. Supports Ed25519, ECDSA P-256/384/521 and RSA, with
/// `aes128/256-ctr`, `aes128/256-cbc` encryption via `bcrypt` KDF.
enum OpenSSHPrivateKey {
    private static let magic = Data("openssh-key-v1\0".utf8)
    private static let pemHeader = "-----BEGIN OPENSSH PRIVATE KEY-----"
    private static let pemFooter = "-----END OPENSSH PRIVATE KEY-----"

    // MARK: Parsing

    /// Parses a key. When the key is encrypted and `passphrase` is nil, the public key and
    /// metadata are still returned but `material` is nil.
    static func parse(_ text: String, passphrase: String?) throws -> ParsedPrivateKey {
        let body = try pemBody(text)
        var r = SSHWireReader(body)
        guard try r.readBytes(magic.count) == magic else { throw OpenSSHKeyError.badMagic }
        let cipherName = try r.readText()
        let kdfName = try r.readText()
        let kdfOptions = try r.readString()
        let keyCount = try r.readUInt32()
        guard keyCount == 1 else { throw OpenSSHKeyError.malformed("expected exactly one key, found \(keyCount)") }
        let publicBlob = try r.readString()
        let publicKey = try parsePublicBlob(publicBlob)
        var privateSection = try r.readString()

        let isEncrypted = cipherName != "none"
        if isEncrypted {
            guard let passphrase, !passphrase.isEmpty else {
                return ParsedPrivateKey(material: nil, publicKey: publicKey, comment: "", isEncrypted: true)
            }
            privateSection = try decrypt(privateSection, cipher: cipherName, kdf: kdfName, kdfOptions: kdfOptions, passphrase: passphrase)
        }

        var p = SSHWireReader(privateSection)
        let check1 = try p.readUInt32()
        let check2 = try p.readUInt32()
        guard check1 == check2 else {
            throw isEncrypted ? OpenSSHKeyError.wrongPassphrase : OpenSSHKeyError.malformed("check bytes differ")
        }
        let typeName = try p.readText()
        let material: PrivateKeyMaterial
        switch typeName {
        case "ssh-ed25519":
            _ = try p.readString() // public
            let priv = try p.readString() // 64 bytes: seed || public
            guard priv.count == 64 else { throw OpenSSHKeyError.malformed("ed25519 private length \(priv.count)") }
            material = .ed25519(try Curve25519.Signing.PrivateKey(rawRepresentation: priv.prefix(32)))
        case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
            _ = try p.readText() // curve
            _ = try p.readString() // Q
            let d = try p.readMPInt()
            switch typeName {
            case "ecdsa-sha2-nistp256": material = .p256(try P256.Signing.PrivateKey(rawRepresentation: leftPad(d, to: 32)))
            case "ecdsa-sha2-nistp384": material = .p384(try P384.Signing.PrivateKey(rawRepresentation: leftPad(d, to: 48)))
            default: material = .p521(try P521.Signing.PrivateKey(rawRepresentation: leftPad(d, to: 66)))
            }
        case "ssh-rsa":
            let n = try p.readMPInt(), e = try p.readMPInt(), d = try p.readMPInt()
            let iqmp = try p.readMPInt(), pp = try p.readMPInt(), q = try p.readMPInt()
            material = .rsa(n: n, e: e, d: d, iqmp: iqmp, p: pp, q: q)
        default:
            throw OpenSSHKeyError.unsupportedKeyType(typeName)
        }
        let comment = (try? p.readText()) ?? ""
        return ParsedPrivateKey(material: material, publicKey: publicKey, comment: comment, isEncrypted: isEncrypted)
    }

    static func parsePublicBlob(_ blob: Data) throws -> SSHPublicKeyBlob {
        var r = SSHWireReader(blob)
        let type = try r.readText()
        switch type {
        case "ssh-ed25519": return SSHPublicKeyBlob(keyType: .ed25519, blob: blob)
        case "ecdsa-sha2-nistp256": return SSHPublicKeyBlob(keyType: .ecdsaP256, blob: blob)
        case "ecdsa-sha2-nistp384": return SSHPublicKeyBlob(keyType: .ecdsaP384, blob: blob)
        case "ecdsa-sha2-nistp521": return SSHPublicKeyBlob(keyType: .ecdsaP521, blob: blob)
        case "ssh-rsa":
            _ = try r.readMPInt()
            let n = try r.readMPInt()
            let bits = n.count * 8
            return SSHPublicKeyBlob(keyType: bits >= 4096 ? .rsa4096 : (bits >= 3072 ? .rsa3072 : .rsa2048), blob: blob)
        default: throw OpenSSHKeyError.unsupportedKeyType(type)
        }
    }

    /// Parses an `authorized_keys`/`id_*.pub` style line.
    static func parsePublicLine(_ line: String) throws -> (key: SSHPublicKeyBlob, comment: String) {
        let parts = line.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ", maxSplits: 2).map(String.init)
        guard parts.count >= 2, let blob = Data(base64Encoded: parts[1]) else { throw OpenSSHKeyError.malformed("public key line") }
        return (try parsePublicBlob(blob), parts.count == 3 ? parts[2] : "")
    }

    // MARK: Serialization

    /// Serializes to the OpenSSH container. With a passphrase, uses `aes256-ctr` + `bcrypt`
    /// with 16 rounds, matching `ssh-keygen` defaults.
    static func serialize(_ material: PrivateKeyMaterial, comment: String, passphrase: String? = nil) throws -> String {
        let encrypt = !(passphrase ?? "").isEmpty
        let cipherName = encrypt ? "aes256-ctr" : "none"
        let blockSize = encrypt ? 16 : 8

        var priv = SSHWireWriter()
        let check = UInt32.random(in: .min ... .max)
        priv.writeUInt32(check); priv.writeUInt32(check)
        material.writePrivateSection(into: &priv)
        priv.writeString(comment)
        var pad: UInt8 = 1
        while priv.data.count % blockSize != 0 { priv.writeByte(pad); pad &+= 1 }
        var privateSection = priv.data

        var kdfOptions = Data()
        if encrypt, let passphrase {
            var salt = Data(count: 16)
            _ = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
            let rounds: UInt32 = 16
            var ko = SSHWireWriter(); ko.writeString(salt); ko.writeUInt32(rounds)
            kdfOptions = ko.data
            let keyIV = try bcryptPBKDF(passphrase: passphrase, salt: salt, rounds: rounds, length: 48)
            privateSection = try aesCTR(privateSection, key: keyIV.prefix(32), iv: keyIV.suffix(16))
        }

        var w = SSHWireWriter()
        w.writeBytes(magic)
        w.writeString(cipherName)
        w.writeString(encrypt ? "bcrypt" : "none")
        w.writeString(kdfOptions)
        w.writeUInt32(1)
        w.writeString(material.publicKey.blob)
        w.writeString(privateSection)

        let b64 = w.data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "\(pemHeader)\n\(b64)\n\(pemFooter)\n"
    }

    // MARK: Helpers

    static func pemBody(_ text: String) throws -> Data {
        let lines = text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
        guard let start = lines.firstIndex(of: pemHeader) else {
            if lines.contains(where: { $0.hasPrefix("-----BEGIN") }) {
                throw OpenSSHKeyError.malformed("only the OpenSSH key format is supported; convert with `ssh-keygen -p -m RFC4716 -f key` or re-export the key")
            }
            throw OpenSSHKeyError.notPEM
        }
        let end = lines.firstIndex(of: pemFooter) ?? lines.endIndex
        let b64 = lines[(start + 1)..<end].joined()
        guard let data = Data(base64Encoded: b64) else { throw OpenSSHKeyError.malformed("base64 body") }
        return data
    }

    static func leftPad(_ d: Data, to n: Int) -> Data {
        d.count >= n ? Data(d.suffix(n)) : Data(repeating: 0, count: n - d.count) + d
    }

    private static func decrypt(_ data: Data, cipher: String, kdf: String, kdfOptions: Data, passphrase: String) throws -> Data {
        guard kdf == "bcrypt" else { throw OpenSSHKeyError.unsupportedKDF(kdf) }
        var r = SSHWireReader(kdfOptions)
        let salt = try r.readString()
        let rounds = try r.readUInt32()
        let keyLen: Int, mode: CCMode
        switch cipher {
        case "aes256-ctr": keyLen = 32; mode = CCMode(kCCModeCTR)
        case "aes128-ctr": keyLen = 16; mode = CCMode(kCCModeCTR)
        case "aes256-cbc": keyLen = 32; mode = CCMode(kCCModeCBC)
        case "aes128-cbc": keyLen = 16; mode = CCMode(kCCModeCBC)
        default: throw OpenSSHKeyError.unsupportedCipher(cipher)
        }
        let keyIV = try bcryptPBKDF(passphrase: passphrase, salt: salt, rounds: rounds, length: keyLen + 16)
        return try aes(data, key: keyIV.prefix(keyLen), iv: keyIV.suffix(16), mode: mode, encrypt: false)
    }

    static func bcryptPBKDF(passphrase: String, salt: Data, rounds: UInt32, length: Int) throws -> Data {
        installSHA512()
        var out = Data(count: length)
        let pass = Data(passphrase.utf8)
        let rc = out.withUnsafeMutableBytes { outPtr in
            pass.withUnsafeBytes { passPtr in
                salt.withUnsafeBytes { saltPtr in
                    citadel_bcrypt_pbkdf(passPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), pass.count,
                                         saltPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), salt.count,
                                         outPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), length, rounds)
                }
            }
        }
        guard rc == 0 else { throw OpenSSHKeyError.malformed("bcrypt kdf failed") }
        return out
    }

    private static var sha512Installed = false
    private static func installSHA512() {
        guard !sha512Installed else { return }
        sha512Installed = true
        citadel_set_crypto_hash_sha512 { out, input, length in
            guard let out, let input else { return }
            let digest = SHA512.hash(data: UnsafeRawBufferPointer(start: input, count: Int(length)))
            digest.withUnsafeBytes { out.update(from: $0.baseAddress!.assumingMemoryBound(to: UInt8.self), count: 64) }
        }
    }

    static func aesCTR(_ data: Data, key: Data, iv: Data) throws -> Data {
        try aes(data, key: key, iv: iv, mode: CCMode(kCCModeCTR), encrypt: true)
    }

    private static func aes(_ data: Data, key: Data, iv: Data, mode: CCMode, encrypt: Bool) throws -> Data {
        var cryptor: CCCryptorRef?
        let op = CCOperation(encrypt ? kCCEncrypt : kCCDecrypt)
        var status = key.withUnsafeBytes { k in
            iv.withUnsafeBytes { v in
                CCCryptorCreateWithMode(op, mode, CCAlgorithm(kCCAlgorithmAES), CCPadding(ccNoPadding),
                                        v.baseAddress, k.baseAddress, key.count, nil, 0, 0, 0, &cryptor)
            }
        }
        guard status == kCCSuccess, let cryptor else { throw OpenSSHKeyError.malformed("cipher init \(status)") }
        defer { CCCryptorRelease(cryptor) }
        var out = Data(count: data.count + 16)
        var moved = 0
        status = data.withUnsafeBytes { input in
            out.withUnsafeMutableBytes { output in
                CCCryptorUpdate(cryptor, input.baseAddress, data.count, output.baseAddress, output.count, &moved)
            }
        }
        guard status == kCCSuccess else { throw OpenSSHKeyError.malformed("cipher update \(status)") }
        var total = moved
        status = out.withUnsafeMutableBytes { output in
            CCCryptorFinal(cryptor, output.baseAddress! + total, output.count - total, &moved)
        }
        guard status == kCCSuccess else { throw OpenSSHKeyError.malformed("cipher final \(status)") }
        total += moved
        return out.prefix(total)
    }
}

// MARK: - Key generation

enum KeyGenerator {
    /// Generates a new key pair. RSA generation is not offered in-app (see README); import RSA keys instead.
    static func generate(_ type: Identity.KeyType) throws -> PrivateKeyMaterial {
        switch type {
        case .ed25519: return .ed25519(Curve25519.Signing.PrivateKey())
        case .ecdsaP256: return .p256(P256.Signing.PrivateKey())
        case .ecdsaP384: return .p384(P384.Signing.PrivateKey())
        case .ecdsaP521: return .p521(P521.Signing.PrivateKey())
        case .rsa2048, .rsa3072, .rsa4096:
            throw OpenSSHKeyError.unsupportedKeyType("RSA generation (import an existing RSA key instead)")
        }
    }

    static var generatableTypes: [Identity.KeyType] { [.ed25519, .ecdsaP256, .ecdsaP384, .ecdsaP521] }
}
