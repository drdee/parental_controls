import Foundation

/// Result of one shell command.
public struct CommandResult: Sendable {
    public var command: String
    public var exitCode: Int32
    public var stdout: String
    public var stderr: String

    public init(command: String, exitCode: Int32, stdout: String, stderr: String) {
        self.command = command
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }

    public var succeeded: Bool { exitCode == 0 }

    /// Whatever the command actually said, preferring stdout.
    public var output: String {
        let out = stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        let err = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        if out.isEmpty { return err }
        if err.isEmpty { return out }
        return out + "\n" + err
    }
}

public enum RunnerError: LocalizedError {
    case authorizationCancelled
    case launchFailed(String)

    public var errorDescription: String? {
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
public struct PrivilegedRunner: CommandRunning {
    public init(dryRun: Bool = false, log: DiagnosticLog? = nil) {
        self.dryRun = dryRun
        self.log = log
    }

    /// Set to true to log commands without executing anything that mutates.
    public var dryRun: Bool = false

    /// Records every command and its output when set.
    ///
    /// Attached here rather than at the call sites because this type is the
    /// one place all shell execution passes through, so nothing can be run
    /// without appearing in the log. The log redacts before writing.
    public var log: DiagnosticLog?

    // MARK: - Unprivileged

    @discardableResult
    public func run(_ executable: String, _ arguments: [String]) throws -> CommandResult {
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

        let result = CommandResult(
            command: ([executable] + arguments).joined(separator: " "),
            exitCode: process.terminationStatus,
            stdout: String(decoding: outData),
            stderr: String(decoding: errData)
        )
        log?.record(result)
        return result
    }

    /// Convenience for read-only probes where failure is informative, not fatal.
    public func probe(_ executable: String, _ arguments: [String]) -> CommandResult {
        (try? run(executable, arguments))
            ?? CommandResult(command: executable, exitCode: -1, stdout: "", stderr: "could not launch")
    }

    // MARK: - Privileged

    /// Runs a whole script as root behind a single authorization prompt.
    ///
    /// Batching matters: one prompt for the run reads as intentional, whereas a
    /// prompt per command trains people to click through them.
    @discardableResult
    public func runPrivileged(script: String, description: String) throws -> CommandResult {
        if dryRun {
            return CommandResult(command: "[dry-run] \(description)", exitCode: 0,
                                 stdout: script, stderr: "")
        }

        // Logged by description only. The wrapped form passed to osascript
        // contains the whole script, and run() below would otherwise record it
        // verbatim — the redactor catches that line, but naming the step here
        // keeps the log readable instead of a row of redaction markers.
        log?.log("privileged step: \(description)")

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
    public static func appleScriptLiteral(_ raw: String) -> String {
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

private extension String {
    init(decoding data: Data) {
        self = String(data: data, encoding: .utf8) ?? ""
    }
}
