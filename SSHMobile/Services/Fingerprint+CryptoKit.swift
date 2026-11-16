import Foundation
import CryptoKit

func import_sha256(_ blob: Data) -> String {
    let digest = SHA256.hash(data: blob)
    let b64 = Data(digest).base64EncodedString().replacingOccurrences(of: "=", with: "")
    return "SHA256:\(b64)"
}
