import Foundation
import NIOCore
import NIOSSH
import Citadel
import CryptoKit

/// Builds `NIOSSHUserAuthenticationOffer`s on demand, so we can prompt the user for a
/// password or passphrase only after the server rejects earlier attempts, the same way
/// OpenSSH walks `PreferredAuthentications`.
final class OfferChainAuthDelegate: NIOSSHClientUserAuthenticationDelegate {
    typealias Provider = (NIOSSHAvailableUserAuthenticationMethods) async throws -> NIOSSHUserAuthenticationOffer?

    private var providers: [Provider]
    private let onError: (Error) -> Void

    init(providers: [Provider], onError: @escaping (Error) -> Void) {
        self.providers = providers
        self.onError = onError
    }

    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods,
                                nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        guard !providers.isEmpty else {
            // Every offer was rejected (or the user cancelled): end the handshake instead of
            // leaving the server waiting for a method we don't have.
            nextChallengePromise.fail(AuthenticationExhausted())
            return
        }
        let provider = providers.removeFirst()
        Task {
            do {
                if let offer = try await provider(availableMethods) {
                    nextChallengePromise.succeed(offer)
                } else {
                    // Provider declined (user cancelled); try the next one.
                    self.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: nextChallengePromise)
                }
            } catch {
                onError(error)
                nextChallengePromise.fail(error)
            }
        }
    }
}

enum SSHAuthBuilder {
    /// Turns decoded key material into a NIOSSH offer.
    static func offer(username: String, material: PrivateKeyMaterial) throws -> NIOSSHUserAuthenticationOffer {
        let key: NIOSSHPrivateKey
        switch material {
        case .ed25519(let k): key = NIOSSHPrivateKey(ed25519Key: k)
        case .p256(let k): key = NIOSSHPrivateKey(p256Key: k)
        case .p384(let k): key = NIOSSHPrivateKey(p384Key: k)
        case .p521(let k): key = NIOSSHPrivateKey(p521Key: k)
        case .rsa(let n, let e, let d, _, _, _):
            // rsa-sha2-256 signatures; see RSASHA2Key.swift.
            key = NIOSSHPrivateKey(custom: RSASHA256PrivateKey(n: n, e: e, d: d))
        }
        return NIOSSHUserAuthenticationOffer(username: username, serviceName: "", offer: .privateKey(.init(privateKey: key)))
    }

    static func passwordOffer(username: String, password: String) -> NIOSSHUserAuthenticationOffer {
        NIOSSHUserAuthenticationOffer(username: username, serviceName: "", offer: .password(.init(password: password)))
    }

    static func noneOffer(username: String) -> NIOSSHUserAuthenticationOffer {
        NIOSSHUserAuthenticationOffer(username: username, serviceName: "", offer: .none)
    }
}

/// Host key verification against the known-hosts store with a UI callback for
/// trust-on-first-use and key-changed decisions.
final class HostKeyVerifier: NIOSSHClientServerAuthenticationDelegate {
    struct Presented {
        let keyType: String
        let blob: Data
        var base64: String { blob.base64EncodedString() }
        var fingerprint: String { import_sha256(blob) }
    }

    private let decide: (Presented) async -> Bool

    init(decide: @escaping (Presented) async -> Bool) { self.decide = decide }

    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        _ = hostKey.write(to: &buffer)
        let blob = Data(buffer.readableBytesView)
        var reader = SSHWireReader(blob)
        let keyType = (try? reader.readText()) ?? "unknown"
        let presented = Presented(keyType: keyType, blob: blob)
        Task {
            if await decide(presented) {
                validationCompletePromise.succeed(())
            } else {
                validationCompletePromise.fail(HostKeyRejected())
            }
        }
    }
}

/// Raised when the user declines an unknown or changed host key.
struct HostKeyRejected: LocalizedError {
    var errorDescription: String? { "Host key verification failed." }
}

/// All configured authentication methods were tried and rejected.
struct AuthenticationExhausted: LocalizedError {
    var errorDescription: String? { "Permission denied (authentication failed)." }
}
