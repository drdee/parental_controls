import Foundation

/// Result of one shell command.
struct CommandResult: Sendable {
    var command: String
    var exitCode: Int32
    var stdout: String
    var stderr: String

    var succeeded: Bool { exitCode == 0 }

    /// Whatever the command actually said, preferring stdout.
    var output: String {
        let out = stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        let err = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        if out.isEmpty { return err }
        if err.isEmpty { return out }
        return out + "\n" + err
    }
}

enum RunnerError: LocalizedError {
    case authorizationCancelled
    case launchFailed(String)

    var errorDescription: String? {
        switch self {
        case .authorizationCancelled:
            return "Administrator authorization was cancelled."
        case .launchFailed(let why):
            return "Could not run command: \(why)"
        }
    }
}

/// Runs shell commands, with and without elevation.
///
/// Elevation goes through `osascript ... with administrator privileges`, which
/// prompts once per invocation and needs no privileged helper or XPC service.
/// A `SMAppService` helper would be the textbook approach, but this tool runs
/// once per machine — a persistent root helper is a larger attack surface than
/// the job justifies.
struct PrivilegedRunner: Sendable {
    /// Set to true to log commands without executing anything that mutates.
    var dryRun: Bool = false

    // MARK: - Unprivileged

    @discardableResult
    func run(_ executable: String, _ arguments: [String]) throws -> CommandResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let outPipe = Pipe(), errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe

        do {
            try process.run()
        } catch {
            throw RunnerError.launchFailed(error.localizedDescription)
        }

        // Read before waiting: a command that fills the pipe buffer would
        // otherwise deadlock against waitUntilExit().
        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        return CommandResult(
            command: ([executable] + arguments).joined(separator: " "),
            exitCode: process.terminationStatus,
            stdout: String(decoding: outData),
            stderr: String(decoding: errData)
        )
    }

    /// Convenience for read-only probes where failure is informative, not fatal.
    func probe(_ executable: String, _ arguments: [String]) -> CommandResult {
        (try? run(executable, arguments))
            ?? CommandResult(command: executable, exitCode: -1, stdout: "", stderr: "could not launch")
    }

    // MARK: - Privileged

    /// Runs a whole script as root behind a single authorization prompt.
    ///
    /// Batching matters: one prompt for the run reads as intentional, whereas a
    /// prompt per command trains people to click through them.
    @discardableResult
    func runPrivileged(script: String, description: String) throws -> CommandResult {
        if dryRun {
            return CommandResult(command: "[dry-run] \(description)", exitCode: 0,
                                 stdout: script, stderr: "")
        }

        let wrapped = "do shell script \(Self.appleScriptLiteral(script)) with administrator privileges"
        let result = try run("/usr/bin/osascript", ["-e", wrapped])

        // osascript reports user cancellation as -128.
        if !result.succeeded, result.stderr.contains("-128") {
            throw RunnerError.authorizationCancelled
        }
        return result
    }

    /// Quotes a string for embedding in AppleScript source.
    ///
    /// The script text is interpolated into AppleScript, so backslashes and
    /// quotes have to be escaped or the surrounding literal breaks — and a
    /// stray quote in a hostname would otherwise let user input extend the
    /// command being run as root.
    static func appleScriptLiteral(_ raw: String) -> String {
        var escaped = ""
        for character in raw {
            switch character {
            case "\\": escaped += "\\\\"
            case "\"": escaped += "\\\""
            default:   escaped.append(character)
            }
        }
        return "\"" + escaped + "\""
    }
}

extension PrivilegedRunner {
    /// `run` on a background thread.
    ///
    /// The synchronous variants block until the child process exits, which for
    /// an admin prompt or a package install can be tens of seconds. Calling
    /// those directly from `@MainActor` freezes the UI, so all callers on the
    /// main actor should use these.
    func runAsync(_ executable: String, _ arguments: [String]) async throws -> CommandResult {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(with: Result { try run(executable, arguments) })
            }
        }
    }

    func probeAsync(_ executable: String, _ arguments: [String]) async -> CommandResult {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: probe(executable, arguments))
            }
        }
    }

    /// `runPrivileged` on a background thread. The authorization dialog is
    /// presented by the system, so it still appears normally.
    func runPrivilegedAsync(script: String, description: String) async throws -> CommandResult {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(with: Result { try runPrivileged(script: script, description: description) })
            }
        }
    }
}

private extension String {
    init(decoding data: Data) {
        self = String(data: data, encoding: .utf8) ?? ""
    }
}
