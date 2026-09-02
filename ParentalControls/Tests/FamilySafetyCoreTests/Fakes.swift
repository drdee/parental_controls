import Foundation
@testable import FamilySafetyCore

/// Records every command instead of running it, and replays scripted results.
///
/// This is what makes the destructive paths testable: `Reverter` removes
/// configuration profiles and rewrites `/etc/hosts`, and `WARPInstaller`
/// installs a package as root. Neither can be exercised for real, but both can
/// be checked for *what they would do* and *how they react to failure*.
final class FakeRunner: CommandRunning, @unchecked Sendable {
    /// One recorded invocation.
    struct Invocation: Equatable {
        enum Kind: Equatable { case run, probe, privileged }
        var kind: Kind
        /// Executable for run/probe, or the script for privileged.
        var command: String
        var arguments: [String]
    }

    private let lock = NSLock()
    private var _invocations: [Invocation] = []

    /// Results keyed by a substring of the command. First match wins.
    var responses: [(match: String, result: CommandResult)] = []
    /// Used when nothing matches.
    var defaultResult = CommandResult(command: "", exitCode: 0, stdout: "", stderr: "")
    /// When set, `run` and `runPrivileged` throw instead of returning.
    var errorToThrow: (any Error)?

    var invocations: [Invocation] {
        lock.withLock { _invocations }
    }

    /// Every command string seen, joined — convenient for coarse assertions.
    var transcript: String {
        invocations.map { "\($0.command) \($0.arguments.joined(separator: " "))" }
            .joined(separator: "\n")
    }

    func stub(_ match: String, exitCode: Int32 = 0, stdout: String = "", stderr: String = "") {
        responses.append((match, CommandResult(command: match, exitCode: exitCode,
                                               stdout: stdout, stderr: stderr)))
    }

    private func result(for command: String) -> CommandResult {
        for response in responses where command.contains(response.match) {
            return response.result
        }
        return defaultResult
    }

    private func record(_ invocation: Invocation) {
        lock.withLock { _invocations.append(invocation) }
    }

    func run(_ executable: String, _ arguments: [String]) throws -> CommandResult {
        record(Invocation(kind: .run, command: executable, arguments: arguments))
        if let errorToThrow { throw errorToThrow }
        return result(for: executable + " " + arguments.joined(separator: " "))
    }

    func probe(_ executable: String, _ arguments: [String]) -> CommandResult {
        record(Invocation(kind: .probe, command: executable, arguments: arguments))
        return result(for: executable + " " + arguments.joined(separator: " "))
    }

    func runPrivileged(script: String, description: String) throws -> CommandResult {
        record(Invocation(kind: .privileged, command: script, arguments: [description]))
        if let errorToThrow { throw errorToThrow }
        return result(for: script)
    }

    // MARK: - Assertions

    /// Whether any recorded command contains `fragment`.
    func ran(_ fragment: String) -> Bool {
        transcript.contains(fragment)
    }

    var privilegedScripts: [String] {
        invocations.filter { $0.kind == .privileged }.map(\.command)
    }
}

/// An in-memory filesystem, so tests can describe a machine's state.
struct FakeFileSystem: FileSystemReading {
    var files: [String: String] = [:]
    var directories: [String: [String]] = [:]
    var downloads: URL = URL(fileURLWithPath: NSTemporaryDirectory())

    func fileExists(atPath path: String) -> Bool {
        files[path] != nil
    }

    func contents(atPath path: String) -> String? {
        files[path]
    }

    func directoryContents(atPath path: String) -> [String] {
        directories[path] ?? []
    }

    var downloadsDirectory: URL { downloads }
}

extension FakeFileSystem {
    /// A machine with the tool's changes already applied.
    static var configured: FakeFileSystem {
        FakeFileSystem(
            files: [
                "/etc/hosts": """
                127.0.0.1\tlocalhost
                \(Hardening.hostsMarkerBegin)
                0.0.0.0\ttiktok.com
                \(Hardening.hostsMarkerEnd)
                """,
                Hardening.hostsBackupPath: "127.0.0.1\tlocalhost",
            ],
            directories: [
                "/Library/Managed Preferences": [
                    "com.google.Chrome.plist",
                    "org.mozilla.firefox.plist",
                    "com.apple.applicationaccess.plist",
                ],
            ]
        )
    }

    /// A machine the tool has never touched.
    static var clean: FakeFileSystem {
        FakeFileSystem(
            files: ["/etc/hosts": "127.0.0.1\tlocalhost"],
            directories: ["/Library/Managed Preferences": []]
        )
    }
}

/// Produces a local file instead of downloading, so the suite never touches
/// the network. Can also simulate a failed transfer.
struct FakeDownloader: PackageDownloading {
    var contents = "fake package"
    var errorToThrow: (any Error)?
    /// Progress values reported before completing.
    var progressSteps: [Double] = [0.0, 0.5, 1.0]

    func download(progress: @escaping @Sendable (Double) -> Void) async throws -> URL {
        for step in progressSteps { progress(step) }
        if let errorToThrow { throw errorToThrow }
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("fake-warp-\(UUID().uuidString).pkg")
        try contents.write(to: url, atomically: true, encoding: .utf8)
        return url
    }
}

/// Resolves from a fixed table, so filtering can be simulated without touching
/// the network or depending on the machine's real DNS configuration.
struct FakeResolver: HostResolving {
    /// Hosts mapped to the addresses they resolve to. A sinkhole address or an
    /// empty array means blocked.
    var table: [String: [String]] = [:]
    /// Used for any host not in the table.
    var fallback: [String] = ["93.184.216.34"]

    func addresses(for host: String) -> [String] {
        table[host] ?? fallback
    }

    /// A resolver where the filtered domains are sinkholed.
    static func filtering(_ blocked: [String]) -> FakeResolver {
        var table: [String: [String]] = [:]
        for host in blocked { table[host] = ["0.0.0.0"] }
        return FakeResolver(table: table)
    }

    /// A resolver that filters nothing.
    static var unfiltered: FakeResolver { FakeResolver() }
}
