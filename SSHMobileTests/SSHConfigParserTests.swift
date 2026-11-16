import XCTest
@testable import SSHMobile

final class SSHConfigParserTests: XCTestCase {
    let sample = """
    # comment
    Host *
        ServerAliveInterval 45
        User fallback

    Host bastion
        HostName bastion.example.com
        User ops
        Port 2200
        IdentityFile ~/.ssh/id_ed25519

    Host web1 web2
        HostName %h.internal   # unsupported token kept verbatim
        ProxyJump ops@bastion
        LocalForward 8080 localhost:80
        LocalForward 127.0.0.1:5432 db.internal:5432
        RemoteForward 9000 127.0.0.1:3000
        DynamicForward 1080
        SetEnv LANG=C.UTF-8 TZ=UTC
        RequestTTY no
        RemoteCommand uptime
        ConnectTimeout=7
    """

    func testParsesHostsAndDefaults() {
        let hosts = SSHConfigParser.parse(sample)
        XCTAssertEqual(hosts.map(\.name), ["bastion", "web1", "web2"])

        let bastion = hosts[0]
        XCTAssertEqual(bastion.hostname, "bastion.example.com")
        XCTAssertEqual(bastion.username, "ops")           // explicit wins over Host * fallback
        XCTAssertEqual(bastion.port, 2200)
        XCTAssertEqual(bastion.authMethod, .publicKey)
        XCTAssertEqual(bastion.keepAliveSeconds, 45)      // inherited from Host *

        let web1 = hosts[1]
        XCTAssertEqual(web1.username, "fallback")
        XCTAssertEqual(web1.jumpHostID, bastion.id)
        XCTAssertEqual(web1.portForwards.count, 4)
        XCTAssertEqual(web1.portForwards[0].summary, "-L 127.0.0.1:8080:localhost:80")
        XCTAssertEqual(web1.portForwards[1].summary, "-L 127.0.0.1:5432:db.internal:5432")
        XCTAssertEqual(web1.portForwards[2].kind, .remote)
        XCTAssertEqual(web1.portForwards[3].summary, "-D 127.0.0.1:1080")
        XCTAssertEqual(web1.environment, ["LANG": "C.UTF-8", "TZ": "UTC"])
        XCTAssertFalse(web1.requestTTY)
        XCTAssertEqual(web1.remoteCommand, "uptime")
        XCTAssertEqual(web1.connectTimeoutSeconds, 7)
    }

    func testRenderRoundTrip() {
        let hosts = SSHConfigParser.parse(sample)
        let text = SSHConfigParser.render(hosts) { id in hosts.first { $0.id == id }?.name }
        let again = SSHConfigParser.parse(text)
        XCTAssertEqual(again.map(\.name), hosts.map(\.name))
        XCTAssertEqual(again[1].portForwards.map(\.summary), hosts[1].portForwards.map(\.summary))
        XCTAssertEqual(again[1].environment, hosts[1].environment)
        XCTAssertEqual(again[1].jumpHostID, again[0].id)
        XCTAssertEqual(again[0].port, 2200)
    }

    func testSplitHostPort() {
        XCTAssertEqual(SSHConfigParser.splitHostPort("8080").1, 8080)
        XCTAssertNil(SSHConfigParser.splitHostPort("8080").0)
        XCTAssertEqual(SSHConfigParser.splitHostPort("db:5432").0, "db")
        XCTAssertEqual(SSHConfigParser.splitHostPort("[::1]:22").0, "::1")
        XCTAssertEqual(SSHConfigParser.splitHostPort("[::1]:22").1, 22)
    }

    func testGlob() {
        XCTAssertTrue(SSHConfigParser.glob("*", matches: "anything"))
        XCTAssertTrue(SSHConfigParser.glob("web?", matches: "web1"))
        XCTAssertFalse(SSHConfigParser.glob("web?", matches: "web10"))
        XCTAssertTrue(SSHConfigParser.glob("*.example.com", matches: "a.example.com"))
        XCTAssertFalse(SSHConfigParser.glob("!web1", matches: "web1"))
    }

    func testHostStoreImportMergesByAlias() {
        JSONStore.directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try? FileManager.default.createDirectory(at: JSONStore.directory, withIntermediateDirectories: true)
        let store = HostStore()
        XCTAssertEqual(store.importSSHConfig(sample), 3)
        XCTAssertEqual(store.importSSHConfig(sample), 3)
        XCTAssertEqual(store.hosts.count, 3)
    }
}
