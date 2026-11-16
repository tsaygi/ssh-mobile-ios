import Foundation
import Observation

@Observable
final class HostStore {
    private(set) var hosts: [HostProfile] = []
    private let file = "hosts.json"

    init() {
        hosts = JSONStore.load([HostProfile].self, from: file) ?? []
    }

    func host(id: UUID?) -> HostProfile? {
        guard let id else { return nil }
        return hosts.first { $0.id == id }
    }

    func upsert(_ host: HostProfile) {
        if let i = hosts.firstIndex(where: { $0.id == host.id }) {
            hosts[i] = host
        } else {
            hosts.append(host)
        }
        persist()
    }

    func delete(_ ids: Set<UUID>) {
        hosts.removeAll { ids.contains($0.id) }
        // Drop dangling jump-host references.
        for i in hosts.indices where hosts[i].jumpHostID.map(ids.contains) == true {
            hosts[i].jumpHostID = nil
        }
        persist()
    }

    func delete(at offsets: IndexSet) {
        delete(Set(offsets.map { hosts[$0].id }))
    }

    func markConnected(_ id: UUID) {
        guard let i = hosts.firstIndex(where: { $0.id == id }) else { return }
        hosts[i].lastConnected = Date()
        persist()
    }

    /// Merge hosts parsed from an OpenSSH config file. Existing hosts with the
    /// same alias are updated in place.
    func importSSHConfig(_ text: String) -> Int {
        let parsed = SSHConfigParser.parse(text)
        var count = 0
        for p in parsed {
            if let i = hosts.firstIndex(where: { $0.name == p.name }) {
                var merged = p
                merged.id = hosts[i].id
                merged.identityID = hosts[i].identityID
                hosts[i] = merged
            } else {
                hosts.append(p)
            }
            count += 1
        }
        persist()
        return count
    }

    func exportSSHConfig() -> String {
        SSHConfigParser.render(hosts, resolveJump: { [weak self] id in self?.host(id: id)?.name })
    }

    private func persist() { JSONStore.save(hosts, to: file) }
}
