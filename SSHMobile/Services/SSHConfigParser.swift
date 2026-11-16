import Foundation

/// Parses and renders the subset of `ssh_config(5)` that maps onto `HostProfile`.
/// Wildcard `Host *` blocks are applied as defaults to the concrete hosts that follow,
/// matching OpenSSH's first-obtained-value-wins semantics.
enum SSHConfigParser {
    struct Block {
        var patterns: [String]
        var options: [(key: String, value: String)] = []
    }

    static func tokenize(_ text: String) -> [Block] {
        var blocks: [Block] = []
        var current: Block?
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            var line = rawLine.trimmingCharacters(in: .whitespaces)
            if let hash = line.firstIndex(of: "#") { line = String(line[..<hash]) }
            guard !line.isEmpty else { continue }
            // Accept both "Key Value" and "Key=Value".
            let parts: [String]
            if let eq = line.firstIndex(of: "="), !line[..<eq].contains(" ") {
                parts = [String(line[..<eq]), String(line[line.index(after: eq)...])]
            } else {
                let split = line.split(maxSplits: 1, whereSeparator: { $0 == " " || $0 == "\t" })
                parts = split.map(String.init)
            }
            guard parts.count == 2 else { continue }
            let key = parts[0].lowercased()
            let value = parts[1].trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            if key == "host" {
                if let c = current { blocks.append(c) }
                current = Block(patterns: value.split(separator: " ").map(String.init))
            } else if key == "match" {
                if let c = current { blocks.append(c) }
                current = nil // Match blocks are not supported; skip their contents.
            } else if current != nil {
                current!.options.append((key, value))
            }
        }
        if let c = current { blocks.append(c) }
        return blocks
    }

    static func parse(_ text: String) -> [HostProfile] {
        let blocks = tokenize(text)
        var results: [HostProfile] = []
        var aliasToID: [String: UUID] = [:]
        var pendingJumps: [(UUID, String)] = []

        for (index, block) in blocks.enumerated() {
            for pattern in block.patterns where !pattern.contains("*") && !pattern.contains("?") && !pattern.hasPrefix("!") {
                var profile = HostProfile(name: pattern, hostname: pattern)
                var applied = Set<String>()
                // This block's options first, then wildcard blocks anywhere in the file
                // that match (OpenSSH uses the first obtained value).
                apply(block.options, to: &profile, applied: &applied, pendingJumps: &pendingJumps)
                for (j, other) in blocks.enumerated() where j != index {
                    if other.patterns.contains(where: { glob($0, matches: pattern) }) {
                        apply(other.options, to: &profile, applied: &applied, pendingJumps: &pendingJumps)
                    }
                }
                aliasToID[pattern] = profile.id
                results.append(profile)
            }
        }
        // Resolve ProxyJump aliases to saved host IDs.
        for (hostID, jumpAlias) in pendingJumps {
            let alias = jumpAlias.split(separator: ",").first.map(String.init) ?? jumpAlias
            let stripped = alias.split(separator: "@").last.map(String.init) ?? alias
            if let target = aliasToID[stripped] ?? aliasToID[alias],
               let i = results.firstIndex(where: { $0.id == hostID }) {
                results[i].jumpHostID = target
            }
        }
        return results
    }

    private static func apply(_ options: [(key: String, value: String)], to p: inout HostProfile,
                              applied: inout Set<String>, pendingJumps: inout [(UUID, String)]) {
        for (key, value) in options {
            guard !applied.contains(key) || key == "localforward" || key == "remoteforward" || key == "dynamicforward" || key == "setenv" else { continue }
            applied.insert(key)
            switch key {
            case "hostname": p.hostname = value
            case "port": p.port = Int(value) ?? 22
            case "user": p.username = value
            case "identityfile":
                p.authMethod = .publicKey
            case "proxyjump": pendingJumps.append((p.id, value))
            case "serveraliveinterval": p.keepAliveSeconds = Int(value) ?? 30
            case "connecttimeout": p.connectTimeoutSeconds = Int(value) ?? 15
            case "forwardagent": p.agentForwarding = value.lowercased() == "yes"
            case "compression": p.compression = value.lowercased() == "yes"
            case "requesttty": p.requestTTY = value.lowercased() != "no"
            case "remotecommand": p.remoteCommand = value
            case "preferredauthentications":
                if value.contains("publickey") { p.authMethod = .publicKey }
                else if value.contains("keyboard-interactive") { p.authMethod = .keyboardInteractive }
                else if value.contains("password") { p.authMethod = .password }
            case "setenv":
                for pair in value.split(separator: " ") {
                    let kv = pair.split(separator: "=", maxSplits: 1).map(String.init)
                    if kv.count == 2 { p.environment[kv[0]] = kv[1] }
                }
            case "localforward":
                if let f = parseForward(value, kind: .local) { p.portForwards.append(f) }
            case "remoteforward":
                if let f = parseForward(value, kind: .remote) { p.portForwards.append(f) }
            case "dynamicforward":
                if let f = parseForward(value, kind: .dynamic) { p.portForwards.append(f) }
            default: break
            }
        }
    }

    /// `LocalForward [bind:]port host:hostport`
    static func parseForward(_ value: String, kind: PortForward.Kind) -> PortForward? {
        let parts = value.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        guard let first = parts.first else { return nil }
        var f = PortForward(kind: kind)
        let (bindAddr, bindPort) = splitHostPort(first)
        f.bindAddress = bindAddr ?? "127.0.0.1"
        guard let bp = bindPort else { return nil }
        f.bindPort = bp
        if kind != .dynamic {
            guard parts.count >= 2 else { return nil }
            let (th, tp) = splitHostPort(parts[1])
            f.targetHost = th ?? "localhost"
            guard let tpp = tp else { return nil }
            f.targetPort = tpp
        }
        return f
    }

    /// Handles `port`, `host:port`, `[v6::addr]:port`.
    static func splitHostPort(_ s: String) -> (String?, Int?) {
        if s.hasPrefix("[") , let close = s.firstIndex(of: "]") {
            let host = String(s[s.index(after: s.startIndex)..<close])
            let rest = s[s.index(after: close)...].dropFirst() // skip ':'
            return (host, Int(rest))
        }
        if let colon = s.lastIndex(of: ":") {
            return (String(s[..<colon]), Int(s[s.index(after: colon)...]))
        }
        return (nil, Int(s))
    }

    /// Minimal ssh_config glob: `*`, `?`, and negation with `!`.
    static func glob(_ pattern: String, matches host: String) -> Bool {
        if pattern.hasPrefix("!") { return !glob(String(pattern.dropFirst()), matches: host) }
        var regex = "^"
        for ch in pattern {
            switch ch {
            case "*": regex += ".*"
            case "?": regex += "."
            default: regex += NSRegularExpression.escapedPattern(for: String(ch))
            }
        }
        regex += "$"
        return host.range(of: regex, options: .regularExpression) != nil
    }

    static func render(_ hosts: [HostProfile], resolveJump: (UUID) -> String?) -> String {
        var out = "# Exported by SSH Mobile\n"
        for h in hosts {
            out += "\nHost \(h.name.isEmpty ? h.hostname : h.name)\n"
            out += "    HostName \(h.hostname)\n"
            if h.port != 22 { out += "    Port \(h.port)\n" }
            if !h.username.isEmpty { out += "    User \(h.username)\n" }
            if let j = h.jumpHostID, let name = resolveJump(j) { out += "    ProxyJump \(name)\n" }
            if h.keepAliveSeconds > 0 { out += "    ServerAliveInterval \(h.keepAliveSeconds)\n" }
            if h.connectTimeoutSeconds != 15 { out += "    ConnectTimeout \(h.connectTimeoutSeconds)\n" }
            if h.compression { out += "    Compression yes\n" }
            if h.agentForwarding { out += "    ForwardAgent yes\n" }
            if !h.requestTTY { out += "    RequestTTY no\n" }
            if !h.remoteCommand.isEmpty { out += "    RemoteCommand \(h.remoteCommand)\n" }
            switch h.authMethod {
            case .publicKey: out += "    PreferredAuthentications publickey\n"
            case .password: out += "    PreferredAuthentications password\n"
            case .keyboardInteractive: out += "    PreferredAuthentications keyboard-interactive\n"
            case .none: break
            }
            for (k, v) in h.environment.sorted(by: { $0.key < $1.key }) { out += "    SetEnv \(k)=\(v)\n" }
            for f in h.portForwards {
                switch f.kind {
                case .local: out += "    LocalForward \(f.bindAddress):\(f.bindPort) \(f.targetHost):\(f.targetPort)\n"
                case .remote: out += "    RemoteForward \(f.bindAddress):\(f.bindPort) \(f.targetHost):\(f.targetPort)\n"
                case .dynamic: out += "    DynamicForward \(f.bindAddress):\(f.bindPort)\n"
                }
            }
        }
        return out
    }
}
