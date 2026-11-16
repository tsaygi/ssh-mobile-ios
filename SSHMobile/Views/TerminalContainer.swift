import SwiftUI
import UIKit
import SwiftTerm

/// Bridges SwiftTerm's UIKit `TerminalView` into SwiftUI and wires it to an `SSHSession`.
struct TerminalContainer: UIViewRepresentable {
    let session: SSHSession
    let theme: TerminalTheme
    let fontSize: Double

    func makeCoordinator() -> Coordinator { Coordinator(session: session) }

    func makeUIView(context: Context) -> TerminalView {
        let view = TerminalView(frame: .zero, font: Self.font(fontSize))
        view.terminalDelegate = context.coordinator
        view.optionAsMetaKey = true
        view.allowMouseReporting = true
        view.backgroundColor = UIColor(hex: theme.background)
        view.keyboardAppearance = .dark
        view.autocorrectionType = .no
        view.autocapitalizationType = .none
        view.smartQuotesType = .no
        view.smartDashesType = .no
        view.smartInsertDeleteType = .no
        Self.apply(theme, to: view)

        let accessory = TerminalAccessory(frame: CGRect(x: 0, y: 0, width: UIScreen.main.bounds.width, height: 40),
                                          inputViewStyle: .keyboard, container: view)
        accessory.sizeToFit()
        view.inputAccessoryView = accessory

        if UITestMode.enabled { view.feed(text: "\u{1b}[2 q") } // steady cursor: no repeating animation
        session.terminalSink = { [weak view] bytes in view?.feed(byteArray: bytes) }
        context.coordinator.view = view
        DispatchQueue.main.async { _ = view.becomeFirstResponder() }
        return view
    }

    func updateUIView(_ view: TerminalView, context: Context) {
        if view.font.pointSize != fontSize { view.font = Self.font(fontSize) }
        if context.coordinator.themeID != theme.id {
            context.coordinator.themeID = theme.id
            Self.apply(theme, to: view)
        }
    }

    static func dismantleUIView(_ view: TerminalView, coordinator: Coordinator) {
        coordinator.session.terminalSink = nil
    }

    private static func font(_ size: Double) -> UIFont {
        UIFont(name: "Menlo", size: size) ?? UIFont.monospacedSystemFont(ofSize: size, weight: .regular)
    }

    private static func apply(_ theme: TerminalTheme, to view: TerminalView) {
        view.installColors(theme.ansi.map { SwiftTerm.Color(hex: $0) })
        view.nativeBackgroundColor = UIColor(hex: theme.background)
        view.nativeForegroundColor = UIColor(hex: theme.foreground)
        view.caretColor = UIColor(hex: theme.cursor)
        view.backgroundColor = UIColor(hex: theme.background)
    }

    final class Coordinator: NSObject, TerminalViewDelegate {
        let session: SSHSession
        weak var view: TerminalView?
        var themeID: String = ""

        init(session: SSHSession) { self.session = session }

        func sizeChanged(source: TerminalView, newCols: Int, newRows: Int) {
            MainActor.assumeIsolated { session.resize(cols: newCols, rows: newRows) }
        }
        func setTerminalTitle(source: TerminalView, title: String) {
            MainActor.assumeIsolated { if !title.isEmpty { session.title = title } }
        }
        func hostCurrentDirectoryUpdate(source: TerminalView, directory: String?) {}
        func send(source: TerminalView, data: ArraySlice<UInt8>) { MainActor.assumeIsolated { session.send(data) } }
        func scrolled(source: TerminalView, position: Double) {}
        func requestOpenLink(source: TerminalView, link: String, params: [String: String]) {
            if let url = URL(string: link) { UIApplication.shared.open(url) }
        }
        func bell(source: TerminalView) {
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
        }
        func clipboardCopy(source: TerminalView, content: Data) {
            UIPasteboard.general.string = String(decoding: content, as: UTF8.self)
        }
        func iTermContent(source: TerminalView, content: ArraySlice<UInt8>) {}
        func rangeChanged(source: TerminalView, startY: Int, endY: Int) {}
    }
}

extension UIColor {
    convenience init(hex: String) {
        var value: UInt64 = 0
        Scanner(string: hex.replacingOccurrences(of: "#", with: "")).scanHexInt64(&value)
        self.init(red: CGFloat((value >> 16) & 0xff) / 255, green: CGFloat((value >> 8) & 0xff) / 255,
                  blue: CGFloat(value & 0xff) / 255, alpha: 1)
    }
}

extension SwiftTerm.Color {
    convenience init(hex: String) {
        var value: UInt64 = 0
        Scanner(string: hex.replacingOccurrences(of: "#", with: "")).scanHexInt64(&value)
        self.init(red: UInt16((value >> 16) & 0xff) * 257, green: UInt16((value >> 8) & 0xff) * 257, blue: UInt16(value & 0xff) * 257)
    }
}
