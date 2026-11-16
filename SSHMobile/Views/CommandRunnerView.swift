import SwiftUI

/// Equivalent of `ssh host 'command'` without a terminal: shows stdout, stderr and the exit code.
struct CommandRunnerView: View {
    let session: SSHSession
    @Environment(\.dismiss) private var dismiss
    @State private var command = ""
    @State private var result: SSHSession.CommandResult?
    @State private var running = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                HStack {
                    TextField("command", text: $command)
                        .textFieldStyle(.roundedBorder).font(.body.monospaced())
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .onSubmit(run)
                    Button(action: run) { Image(systemName: running ? "hourglass" : "play.fill") }
                        .disabled(command.isEmpty || running)
                }
                .padding()
                ScrollView {
                    if let r = result {
                        VStack(alignment: .leading, spacing: 8) {
                            if !r.stdout.isEmpty { Text(r.stdout).font(.caption.monospaced()).textSelection(.enabled) }
                            if !r.stderr.isEmpty { Text(r.stderr).font(.caption.monospaced()).foregroundStyle(.red).textSelection(.enabled) }
                            Text("exit status \(r.exitCode)").font(.caption).foregroundStyle(r.exitCode == 0 ? Color.secondary : Color.red)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading).padding()
                    }
                }
            }
            .navigationTitle("Run command")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
            .errorAlert($error)
        }
    }

    private func run() {
        guard !command.isEmpty else { return }
        running = true
        Task {
            do { result = try await session.runCommand(command) } catch { self.error = SSHSession.describe(error) }
            running = false
        }
    }
}
