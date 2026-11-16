import Foundation
import NIOCore
import NIOPosix
import NIOSSH
import Citadel

enum ForwardState: Equatable {
    case starting
    case active(boundPort: Int)
    case failed(String)
    case stopped

    var label: String {
        switch self {
        case .starting: return "Starting"
        case .active(let p): return "Listening on \(p)"
        case .failed(let e): return "Failed: \(e)"
        case .stopped: return "Stopped"
        }
    }
}

/// Copies bytes between two channels on the same event loop. One instance sits in each
/// pipeline; they are linked as partners.
final class GlueHandler: ChannelDuplexHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var partner: GlueHandler?
    private var context: ChannelHandlerContext?
    private var pendingRead = false

    static func matchedPair() -> (GlueHandler, GlueHandler) {
        let a = GlueHandler(), b = GlueHandler()
        a.partner = b; b.partner = a
        return (a, b)
    }

    func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
        // The partner may have deferred its first read until we existed.
        partner?.partnerBecameWritable()
    }
    func handlerRemoved(context: ChannelHandlerContext) { self.context = nil; partner = nil }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        partner?.partnerWrite(data)
    }

    func channelReadComplete(context: ChannelHandlerContext) { partner?.partnerFlush() }

    func channelInactive(context: ChannelHandlerContext) {
        partner?.partnerCloseFull()
        partner = nil
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if case .inputClosed = event as? ChannelEvent {
            partner?.partnerWriteEOF()
        } else {
            context.fireUserInboundEventTriggered(event)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }

    func read(context: ChannelHandlerContext) {
        if partner?.partnerWritable ?? true { context.read() } else { pendingRead = true }
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        if context.channel.isWritable { partner?.partnerBecameWritable() }
    }

    private var partnerWritable: Bool { context?.channel.isWritable ?? false }
    private func partnerWrite(_ data: NIOAny) { context?.write(data, promise: nil) }
    private func partnerFlush() { context?.flush() }
    private func partnerWriteEOF() {
        guard let context else { return }
        context.close(mode: .output).whenFailure { _ in context.close(promise: nil) }
    }
    private func partnerCloseFull() { context?.close(promise: nil) }
    private func partnerBecameWritable() {
        if pendingRead { pendingRead = false; context?.read() }
    }
}

/// Translates between `SSHChannelData` on an SSH child channel and plain `ByteBuffer`s.
final class SSHDataCodec: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let channelData = unwrapInboundIn(data)
        guard case .byteBuffer(let buffer) = channelData.data, channelData.type == .channel else { return }
        context.fireChannelRead(wrapInboundOut(buffer))
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let buffer = unwrapOutboundIn(data)
        context.write(wrapOutboundOut(SSHChannelData(type: .channel, data: .byteBuffer(buffer))), promise: promise)
    }
}

/// Runs one `-L`, `-R` or `-D` forward over a connected `SSHClient`.
final class PortForwarder {
    let forward: PortForward
    private let client: SSHClient
    private var serverChannel: Channel?
    private var remoteTask: Task<Void, Never>?
    private let onState: (ForwardState) -> Void
    private let log: (String) -> Void

    init(forward: PortForward, client: SSHClient, onState: @escaping (ForwardState) -> Void, log: @escaping (String) -> Void) {
        self.forward = forward
        self.client = client
        self.onState = onState
        self.log = log
    }

    func start() async {
        onState(.starting)
        do {
            switch forward.kind {
            case .local: try await startListener(socks: false)
            case .dynamic: try await startListener(socks: true)
            case .remote: startRemote()
            }
        } catch {
            onState(.failed(error.localizedDescription))
            log("\(forward.summary): \(error.localizedDescription)")
        }
    }

    func stop() {
        serverChannel?.close(promise: nil)
        serverChannel = nil
        remoteTask?.cancel()
        remoteTask = nil
        onState(.stopped)
    }

    // MARK: Local and dynamic

    private func startListener(socks: Bool) async throws {
        let loop = client.eventLoop
        let bootstrap = ServerBootstrap(group: loop)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(ChannelOptions.autoRead, value: !socks ? false : true)
            .childChannelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
            .childChannelInitializer { [weak self] channel in
                guard let self else { return channel.eventLoop.makeFailedFuture(ChannelError.ioOnClosedChannel) }
                if socks {
                    let handler = SOCKSHandler(connect: { host, port in self.openDirect(host: host, port: port, from: channel) }, log: self.log)
                    return channel.pipeline.addHandler(handler)
                } else {
                    return self.link(channel, toHost: self.forward.targetHost, port: self.forward.targetPort)
                }
            }
        let channel = try await bootstrap.bind(host: forward.bindAddress, port: forward.bindPort).get()
        serverChannel = channel
        let bound = channel.localAddress?.port ?? forward.bindPort
        onState(.active(boundPort: bound))
        log("\(forward.summary): listening on \(forward.bindAddress):\(bound)")
        channel.closeFuture.whenComplete { [weak self] _ in self?.onState(.stopped) }
    }

    /// Opens a direct-tcpip channel with a glue handler, returning the glue's partner for the
    /// local side. The local channel must have autoRead disabled until this completes.
    private func openDirect(host: String, port: Int, from local: Channel) -> EventLoopFuture<GlueHandler> {
        let promise = local.eventLoop.makePromise(of: GlueHandler.self)
        let (localGlue, remoteGlue) = GlueHandler.matchedPair()
        let originator = (try? SocketAddress(ipAddress: "127.0.0.1", port: 0)) ?? local.remoteAddress!
        Task {
            do {
                _ = try await client.createDirectTCPIPChannel(
                    using: SSHChannelType.DirectTCPIP(targetHost: host, targetPort: port, originatorAddress: originator)
                ) { channel in channel.pipeline.addHandler(remoteGlue) }
                promise.succeed(localGlue)
            } catch {
                promise.fail(error)
            }
        }
        return promise.futureResult
    }

    private func link(_ local: Channel, toHost host: String, port: Int) -> EventLoopFuture<Void> {
        openDirect(host: host, port: port, from: local).flatMap { glue in
            local.pipeline.addHandler(glue).flatMap {
                local.setOption(ChannelOptions.autoRead, value: true)
            }
        }.flatMapError { error in
            self.log("forward to \(host):\(port) failed: \(error)")
            return local.close()
        }
    }

    // MARK: Remote

    /// `-R`: the server listens and opens `forwarded-tcpip` channels back to us; each one is
    /// glued to a fresh TCP connection to the target made from this device.
    private func startRemote() {
        let f = forward
        guard f.bindPort > 0 else {
            onState(.failed("remote forwards need an explicit port"))
            return
        }
        remoteTask = Task { [weak self] in
            guard let self else { return }
            do {
                try await client.withRemotePortForward(host: f.bindAddress, port: f.bindPort, onOpen: { info in
                    self.onState(.active(boundPort: info.boundPort))
                    self.log("\(f.summary): server listening on \(info.host):\(info.boundPort)")
                }, handleChannel: { sshChannel, _ in
                    let (remoteGlue, localGlue) = GlueHandler.matchedPair()
                    return sshChannel.pipeline.addHandlers([SSHDataCodec(), remoteGlue]).flatMap {
                        ClientBootstrap(group: sshChannel.eventLoop)
                            .channelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
                            .channelInitializer { $0.pipeline.addHandler(localGlue) }
                            .connect(host: f.targetHost, port: f.targetPort)
                            .map { _ in () }
                    }.flatMapError { error in
                        self.log("\(f.summary): connect to \(f.targetHost):\(f.targetPort) failed: \(error)")
                        return sshChannel.close()
                    }
                })
                if !Task.isCancelled { onState(.stopped) }
            } catch {
                if !Task.isCancelled {
                    onState(.failed(error.localizedDescription))
                    log("\(f.summary): \(error.localizedDescription)")
                }
            }
        }
    }
}

/// Minimal SOCKS5 (no auth, CONNECT, IPv4/IPv6/domain) and SOCKS4/4a server handler for `-D`.
final class SOCKSHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer

    private enum Phase { case greeting, request, connecting, done }
    private var phase: Phase = .greeting
    private var buffer = ByteBuffer()
    private let connect: (String, Int) -> EventLoopFuture<GlueHandler>
    private let log: (String) -> Void

    init(connect: @escaping (String, Int) -> EventLoopFuture<GlueHandler>, log: @escaping (String) -> Void) {
        self.connect = connect
        self.log = log
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)
        if phase == .done { context.fireChannelRead(data); return }
        buffer.writeBuffer(&incoming)
        guard phase != .connecting else { return }
        process(context: context)
    }

    private func process(context: ChannelHandlerContext) {
        let bytes = Array(buffer.readableBytesView)
        guard let version = bytes.first else { return }
        switch (phase, version) {
        case (.greeting, 5):
            guard bytes.count >= 2, bytes.count >= 2 + Int(bytes[1]) else { return }
            buffer.moveReaderIndex(forwardBy: 2 + Int(bytes[1]))
            context.writeAndFlush(wrapInboundOut(ByteBuffer(bytes: [5, 0])), promise: nil)
            phase = .request
            process(context: context)
        case (.request, 5):
            guard bytes.count >= 4 else { return }
            let atyp = bytes[3]
            var host = "", consumed = 0
            switch atyp {
            case 1:
                guard bytes.count >= 10 else { return }
                host = bytes[4..<8].map(String.init).joined(separator: "."); consumed = 10
            case 3:
                let len = Int(bytes[4]); guard bytes.count >= 5 + len + 2 else { return }
                host = String(decoding: bytes[5..<5 + len], as: UTF8.self); consumed = 5 + len + 2
            case 4:
                guard bytes.count >= 22 else { return }
                host = stride(from: 4, to: 20, by: 2).map { String(format: "%02x%02x", bytes[$0], bytes[$0 + 1]) }.joined(separator: ":"); consumed = 22
            default:
                reply5(context: context, code: 8); return
            }
            guard bytes[1] == 1 else { reply5(context: context, code: 7); return } // CONNECT only
            let port = Int(bytes[consumed - 2]) << 8 | Int(bytes[consumed - 1])
            buffer.moveReaderIndex(forwardBy: consumed)
            establish(context: context, host: host, port: port, v5: true)
        case (.greeting, 4):
            guard bytes.count >= 9, let nul = bytes[8...].firstIndex(of: 0) else { return }
            let port = Int(bytes[2]) << 8 | Int(bytes[3])
            var host = bytes[4..<8].map(String.init).joined(separator: ".")
            var consumed = nul + 1
            if bytes[4] == 0, bytes[5] == 0, bytes[6] == 0, bytes[7] != 0 { // SOCKS4a
                guard let end = bytes[consumed...].firstIndex(of: 0) else { return }
                host = String(decoding: bytes[consumed..<end], as: UTF8.self)
                consumed = end + 1
            }
            guard bytes[1] == 1 else { context.writeAndFlush(wrapInboundOut(ByteBuffer(bytes: [0, 91, 0, 0, 0, 0, 0, 0])), promise: nil); context.close(promise: nil); return }
            buffer.moveReaderIndex(forwardBy: consumed)
            establish(context: context, host: host, port: port, v5: false)
        default:
            context.close(promise: nil)
        }
    }

    private func establish(context: ChannelHandlerContext, host: String, port: Int, v5: Bool) {
        phase = .connecting
        context.channel.setOption(ChannelOptions.autoRead, value: false).whenComplete { _ in }
        connect(host, port).whenComplete { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let glue):
                let ok: [UInt8] = v5 ? [5, 0, 0, 1, 0, 0, 0, 0, 0, 0] : [0, 90, 0, 0, 0, 0, 0, 0]
                context.writeAndFlush(self.wrapInboundOut(ByteBuffer(bytes: ok)), promise: nil)
                self.phase = .done
                let leftover = self.buffer
                context.pipeline.addHandler(glue).flatMap {
                    context.pipeline.removeHandler(self)
                }.whenComplete { _ in
                    if leftover.readableBytes > 0 { context.channel.pipeline.fireChannelRead(NIOAny(leftover)) }
                    context.channel.setOption(ChannelOptions.autoRead, value: true).whenComplete { _ in }
                }
            case .failure(let error):
                self.log("SOCKS connect \(host):\(port) failed: \(error)")
                if v5 { self.reply5(context: context, code: 5) } else {
                    context.writeAndFlush(self.wrapInboundOut(ByteBuffer(bytes: [0, 91, 0, 0, 0, 0, 0, 0])), promise: nil)
                    context.close(promise: nil)
                }
            }
        }
    }

    private func reply5(context: ChannelHandlerContext, code: UInt8) {
        context.writeAndFlush(wrapInboundOut(ByteBuffer(bytes: [5, code, 0, 1, 0, 0, 0, 0, 0, 0])), promise: nil)
        context.close(promise: nil)
    }
}
