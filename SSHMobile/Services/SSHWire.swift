import Foundation

/// Reader/writer for the SSH wire encoding (RFC 4251): uint32 length-prefixed strings,
/// mpints, and uint32s. Used by the OpenSSH key parser and known-hosts handling.
struct SSHWireReader {
    private let data: Data
    private(set) var offset: Int

    init(_ data: Data) { self.data = data; self.offset = 0 }

    var isAtEnd: Bool { offset >= data.count }
    var remaining: Data { data[offset...] }

    mutating func readUInt32() throws -> UInt32 {
        guard offset + 4 <= data.count else { throw OpenSSHKeyError.truncated }
        let v = data[offset..<offset + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        offset += 4
        return v
    }

    mutating func readBytes(_ n: Int) throws -> Data {
        guard n >= 0, offset + n <= data.count else { throw OpenSSHKeyError.truncated }
        let d = Data(data[offset..<offset + n])
        offset += n
        return d
    }

    mutating func readString() throws -> Data {
        let n = Int(try readUInt32())
        return try readBytes(n)
    }

    mutating func readText() throws -> String {
        String(decoding: try readString(), as: UTF8.self)
    }

    /// Reads an mpint and returns its magnitude with the sign byte and leading zeros stripped.
    mutating func readMPInt() throws -> Data {
        var d = try readString()
        while d.first == 0 { d = d.dropFirst() }
        return Data(d)
    }
}

struct SSHWireWriter {
    private(set) var data = Data()

    mutating func writeUInt32(_ v: UInt32) {
        data.append(contentsOf: [UInt8(v >> 24), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)])
    }

    mutating func writeBytes(_ d: Data) { data.append(d) }
    mutating func writeByte(_ b: UInt8) { data.append(b) }

    mutating func writeString(_ d: Data) {
        writeUInt32(UInt32(d.count))
        data.append(d)
    }

    mutating func writeString(_ s: String) { writeString(Data(s.utf8)) }

    /// Writes an unsigned magnitude as a positive mpint.
    mutating func writeMPInt(_ magnitude: Data) {
        var m = magnitude
        while m.first == 0 { m = m.dropFirst() }
        if let first = m.first, first & 0x80 != 0 {
            writeUInt32(UInt32(m.count + 1))
            data.append(0)
            data.append(m)
        } else {
            writeString(Data(m))
        }
    }
}

enum OpenSSHKeyError: LocalizedError, Equatable {
    case truncated
    case badMagic
    case notPEM
    case unsupportedCipher(String)
    case unsupportedKDF(String)
    case unsupportedKeyType(String)
    case passphraseRequired
    case wrongPassphrase
    case malformed(String)

    var errorDescription: String? {
        switch self {
        case .truncated: return "The key file is truncated."
        case .badMagic: return "Not an OpenSSH private key (bad magic)."
        case .notPEM: return "Expected a PEM block such as -----BEGIN OPENSSH PRIVATE KEY-----."
        case .unsupportedCipher(let c): return "Unsupported key cipher \(c)."
        case .unsupportedKDF(let k): return "Unsupported key derivation \(k)."
        case .unsupportedKeyType(let t): return "Unsupported key type \(t)."
        case .passphraseRequired: return "This key is encrypted. Enter its passphrase."
        case .wrongPassphrase: return "Incorrect passphrase."
        case .malformed(let why): return "Malformed key: \(why)"
        }
    }
}
