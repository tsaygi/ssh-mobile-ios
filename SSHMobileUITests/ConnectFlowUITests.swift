import XCTest

/// Drives the real UI through Quick Connect against the Docker test server
/// (scripts/test-server.sh). Skipped when the server is not reachable.
final class ConnectFlowUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
        guard serverReachable() else { throw XCTSkip("test SSH server not running on 127.0.0.1:2222") }
    }

    func testQuickConnectPasswordLogin() throws {
        let app = XCUIApplication()
        app.launchArguments = ["-uiTesting"]
        app.launch()

        app.buttons["quickConnectButton"].tap()
        let destination = app.textFields["quickConnectDestination"]
        XCTAssertTrue(destination.waitForExistence(timeout: 5))
        destination.tap()
        destination.typeText("tester@127.0.0.1:2222")
        app.buttons["quickConnectGo"].tap()

        // Trust-on-first-use host key alert (absent when the key is already known).
        let trust = app.alerts.buttons["Trust and connect"]
        let password = app.secureTextFields["credentialSecret"]
        let deadline = Date().addingTimeInterval(15)
        while Date() < deadline, !trust.exists, !password.exists { usleep(200_000) }
        if trust.exists { trust.tap() }

        // Password prompt.
        XCTAssertTrue(password.waitForExistence(timeout: 10))
        password.tap()
        password.typeText("testpass123")
        app.buttons["credentialSubmit"].tap()

        // Connected state is shown under the title.
        let status = app.staticTexts["sessionStatus"]
        XCTAssertTrue(status.waitForExistence(timeout: 15))
        let connected = NSPredicate(format: "label BEGINSWITH 'tester@127.0.0.1'")
        expectation(for: connected, evaluatedWith: status)
        waitForExpectations(timeout: 20)

        // Give the shell a moment to print its prompt, then keep a screenshot for the report.
        sleep(2)
        let shot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        shot.lifetime = .keepAlways
        add(shot)
        try? XCUIScreen.main.screenshot().pngRepresentation.write(to: URL(fileURLWithPath: "/tmp/sshmobile-terminal.png"))
    }

    private func serverReachable() -> Bool {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        defer { close(sock) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(2222).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        return result == 0
    }
}
