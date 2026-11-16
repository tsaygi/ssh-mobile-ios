# SSH Mobile

A native iOS SSH client (phase 1) that aims for parity with the desktop `ssh` command:
interactive terminal, key and password authentication, host-key verification, port
forwarding, jump hosts, remote commands and SFTP.

## Features

| Capability | Desktop equivalent | Status |
| --- | --- | --- |
| Interactive shell with PTY, xterm-256color emulation (SwiftTerm) | `ssh host` | ✅ |
| Password authentication, optional Keychain storage | `PasswordAuthentication` | ✅ |
| Public-key auth: Ed25519, ECDSA P-256/384/521, RSA | `IdentityFile` | ✅ |
| Encrypted OpenSSH keys (bcrypt + aes-ctr/cbc), passphrase prompt | `ssh-keygen -p` | ✅ |
| Key generation and export (Ed25519, ECDSA) | `ssh-keygen -t` | ✅ (RSA: import only) |
| Host key verification, trust-on-first-use, changed-key warning | `known_hosts` | ✅ |
| Remote command with or without TTY, exit status | `ssh host cmd`, `-t`/`-T` | ✅ |
| Local, dynamic (SOCKS5/4a) and remote port forwards | `-L`, `-D`, `-R` | ✅ |
| Jump hosts (chained) | `-J` / `ProxyJump` | ✅ |
| Environment variables | `SetEnv` | ✅ |
| SFTP browser: list, download, upload, mkdir, rename, delete | `sftp` | ✅ |
| Import/export `~/.ssh/config` and `known_hosts` | | ✅ |
| Multiple concurrent sessions, on-screen Esc/Ctrl/Tab/arrow keys | | ✅ |
| Keepalive | `ServerAliveInterval` | ✅ (see notes) |
| Keyboard-interactive auth, agent forwarding, compression, X11 | | ❌ not available in the transport / on iOS |

## Building

Requirements: Xcode 27, iOS 17+, [XcodeGen](https://github.com/yonaskolb/XcodeGen).

```sh
xcodegen generate
open SSHMobile.xcodeproj
```

Or from the command line:

```sh
xcodebuild build -project SSHMobile.xcodeproj -scheme SSHMobile \
  -destination 'platform=iOS Simulator,name=iPhone 17e' CODE_SIGNING_ALLOWED=NO
```

Dependencies (Swift Package Manager): [Citadel](https://github.com/orlandos-nl/Citadel) on
[SwiftNIO SSH](https://github.com/apple/swift-nio-ssh) for the protocol,
[SwiftTerm](https://github.com/migueldeicaza/SwiftTerm) 1.11.2 for terminal emulation, and
BigInt for RSA signing. SwiftTerm is pinned because newer releases require the Metal
toolchain and a build plugin. Citadel and NIOSSH are vendored under `Vendor/` with two small
patches (see `Vendor/PATCHES.md`): `rsa-sha2-256` key blobs, and auth fallback across
challenges. RSA logins use `rsa-sha2-256`, which OpenSSH 8.8+ requires.

## Testing

Unit tests cover the `ssh_config` parser, the OpenSSH private key format, and known-hosts
logic. Integration tests run against a real OpenSSH server in Docker:

```sh
scripts/test-server.sh        # starts tester@127.0.0.1:2222 (password testpass123)
xcodebuild test -project SSHMobile.xcodeproj -scheme SSHMobile \
  -destination 'platform=iOS Simulator,name=iPhone 17e' CODE_SIGNING_ALLOWED=NO
```

The integration tests exercise password and all key types, TOFU and changed host keys,
PTY shell round trips, non-TTY commands with exit codes, -L/-D/-R forwards, ProxyJump and
SFTP. They are skipped when the server is not running. The UI test target walks through
Quick Connect in the real app.

## Layout

```
SSHMobile/
  App/            SwiftUI app entry and tab shell
  Models/         HostProfile, PortForward, Identity, KnownHost, themes
  Services/
    SSHSession     connection lifecycle, auth chain, host keys, PTY, exec, keepalive
    PortForwarder  -L/-D/-R listeners, SOCKS handler, channel glue
    OpenSSHPrivateKey  openssh-key-v1 parser/serializer with bcrypt/AES
    SSHConfigParser    ssh_config import/export
    HostStore, IdentityStore, KnownHostsStore, Keychain, CredentialStore
  Views/          host list/editor, terminal, keys, known hosts, SFTP, forwards, settings
SSHMobileTests/   unit + integration tests (fixture keys are throwaway test keys)
SSHMobileUITests/ UI smoke test
Vendor/           patched copies of Citadel and swift-nio-ssh (see Vendor/PATCHES.md)
scripts/          Docker test server
```

## Notes and limitations

- **Keepalive**: SwiftNIO SSH exposes no public keepalive request, so the app sends a
  no-op window-change request on the shell channel at the configured interval. It keeps
  NAT mappings alive and detects dead links; it is not `keepalive@openssh.com`.
- **Remote forwards** need an explicit port (the transport keys inbound channels by the
  requested port, so port 0 cannot be matched).
- **Background**: iOS suspends sockets shortly after the app leaves the foreground;
  reconnect from the session menu. Persistent background sessions are a phase-2 item.
- **Keyboard-interactive** is not implemented by SwiftNIO SSH; such hosts fall back to
  password authentication, which works for most servers.
- **RSA host keys**: the transport can only verify RSA host keys with SHA-1 (`ssh-rsa`), which
  modern servers no longer offer. Servers that also have ECDSA or Ed25519 host keys (the
  default since OpenSSH 6.5) negotiate those instead.
- Keys live in the Keychain (`WhenUnlockedThisDeviceOnly`). Encrypted keys stay encrypted
  and prompt for the passphrase at connect time.

## Phase 2 candidates

Android client, background session persistence (mosh-style or push-based reconnect),
Secure Enclave keys, agent forwarding to other apps, X11-less `-t` command chaining,
`Match` blocks in `ssh_config`, iCloud sync of hosts.
