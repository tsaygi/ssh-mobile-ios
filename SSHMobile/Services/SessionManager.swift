import Foundation
import Observation

/// Owns live sessions so they survive view navigation and can run concurrently.
@MainActor
@Observable
final class SessionManager {
    private(set) var sessions: [SSHSession] = []
    var presentedSessionID: UUID?

    let hostStore: HostStore
    let identityStore: IdentityStore
    let knownHosts: KnownHostsStore

    init(hostStore: HostStore, identityStore: IdentityStore, knownHosts: KnownHostsStore) {
        self.hostStore = hostStore
        self.identityStore = identityStore
        self.knownHosts = knownHosts
    }

    var presentedSession: SSHSession? {
        get { sessions.first { $0.id == presentedSessionID } }
        set { presentedSessionID = newValue?.id }
    }

    @discardableResult
    func open(_ host: HostProfile) -> SSHSession {
        let session = SSHSession(host: host, hostStore: hostStore, identityStore: identityStore, knownHosts: knownHosts)
        sessions.append(session)
        presentedSessionID = session.id
        Task { await session.connect() }
        return session
    }

    func close(_ session: SSHSession) {
        Task { await session.disconnect() }
        sessions.removeAll { $0.id == session.id }
        if presentedSessionID == session.id { presentedSessionID = nil }
    }

    func closeAll() {
        for s in sessions { Task { await s.disconnect() } }
        sessions.removeAll()
        presentedSessionID = nil
    }
}
