# Vendored packages

Both packages are local copies of the versions Citadel 0.12.1 resolves, each with a small patch.
Everything else is unchanged.

## swift-nio-ssh 0.3.7 (Wellz26 fork used by Citadel)

- `NIOSSHPublicKeyProtocol.blobPrefix` (default: `publicKeyPrefix`) lets a custom key use a
  different type string inside its serialized blob than the user-auth algorithm name. RFC 8332
  `rsa-sha2-256` needs exactly that: algorithm `rsa-sha2-256`, blob `ssh-rsa`. Used by
  `SSHMobile/Services/RSASHA2Key.swift`.

## Citadel 0.12.1

- `Package.swift` depends on `../swift-nio-ssh` (the vendored copy above).
- `SSHAuthenticationMethod.custom` keeps delegating to the custom delegate on every
  authentication challenge; upstream consumes it after the first one, which makes
  publickey-then-password fallback impossible.
- `SSHClientSettings.loginTimeout` (default 10 s, the previous hard-coded value) bounds the
  handshake and authentication phase separately from the TCP connect timeout, so interactive
  password and passphrase prompts don't abort the connection.
