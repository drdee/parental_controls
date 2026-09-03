import Foundation

/// A per-run diagnostic log, written so a parent can hand it to someone
/// debugging a failed setup.
///
/// Written to `~/Library/Logs/FamilySafety/`, which is where Console.app looks
/// and which needs no privileges. One file per run, because the useful
/// question is almost always "what happened the time it broke" rather than
/// "what has ever happened".
///
/// Everything written here is redacted first. This log records commands run as
/// root, and those commands carry account names and, in the AppleScript
/// wrapper, whole scripts. A diagnostic file exists to be shared — pasted into
/// an issue, mailed to whoever is helping — so it must not be the thing that
/// leaks a password. `Redactor` is deliberately aggressive: losing a little
/// fidelity costs a second guess, whereas leaking a credential cannot be
/// undone once the file is sent.
public final class DiagnosticLog: @unchecked Sendable {

    /// Redacts secrets from text bound for the log.
    ///
    /// Kept separate from the writer so it can be tested directly, and so the
    /// rules are readable in one place rather than scattered through call
    /// sites.
    public struct Redactor: Sendable {
        /// The account name being created, if any. Redacted because it is
        /// interpolated into privileged scripts and is personal data.
        public var accountUsername: String?

        public init(accountUsername: String? = nil) {
            self.accountUsername = accountUsername
        }

        /// Anything on these lines is replaced wholesale rather than
        /// pattern-matched inside: a password can contain any character, so
        /// trying to match the value precisely is how redactors spring leaks.
        private static let secretMarkers = [
            "password", "passwd", "-password", "--password",
            "secret", "token", "api-key", "apikey", "app-specific",
        ]

        public func redact(_ text: String) -> String {
            var lines: [String] = []
            for line in text.components(separatedBy: .newlines) {
                lines.append(redactLine(line))
            }
            return lines.joined(separator: "\n")
        }

        private func redactLine(_ line: String) -> String {
            let lowered = line.lowercased()

            // An AppleScript elevation wrapper embeds the entire script, which
            // may contain anything. Keep the shape, drop the contents.
            if lowered.contains("with administrator privileges") {
                return "<privileged script redacted>"
            }

            if Self.secretMarkers.contains(where: { lowered.contains($0) }) {
                return "<line containing a secret redacted>"
            }

            var result = line
            if let accountUsername, !accountUsername.isEmpty {
                result = result.replacingOccurrences(of: accountUsername, with: "<username>")
            }
            // The operator's own short name shows up in home-directory paths
            // even when no account is being created.
            let home = FileManager.default.homeDirectoryForCurrentUser.lastPathComponent
            if !home.isEmpty {
                result = result.replacingOccurrences(of: "/Users/" + home, with: "/Users/<user>")
            }
            return result
        }
    }

    public let fileURL: URL
    public var redactor: Redactor

    private let queue = DispatchQueue(label: "com.familysafety.diagnosticlog")
    private let handle: FileHandle?
    private static let directoryName = "FamilySafety"
    /// Keeps a run's worth of history without letting the directory grow
    /// without bound in someone's Library.
    private static let keepMostRecent = 10

    /// Creates a log for this run. Never throws: diagnostics failing must not
    /// stop the app from doing its job, so a log that cannot be opened simply
    /// swallows writes.
    public init(directory: URL? = nil, redactor: Redactor = Redactor(), now: Date = Date()) {
        self.redactor = redactor

        let folder = directory ?? Self.defaultDirectory()
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)

        let stamp = Self.fileStamp.string(from: now)
        let url = folder.appendingPathComponent("family-safety-\(stamp).log")
        self.fileURL = url

        FileManager.default.createFile(atPath: url.path, contents: nil)
        self.handle = try? FileHandle(forWritingTo: url)

        Self.prune(in: folder)
    }

    deinit {
        try? handle?.close()
    }

    public static func defaultDirectory() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/\(directoryName)")
    }

    // MARK: - Writing

    /// Writes one timestamped line.
    public func log(_ message: String) {
        write(Self.lineStamp.string(from: Date()) + "  " + redactor.redact(message))
    }

    /// A visually distinct section heading, so a long log stays scannable.
    public func section(_ title: String) {
        write("")
        write("== " + redactor.redact(title) + " ==")
    }

    /// Records a command and everything it produced.
    ///
    /// The output is logged whether or not the command succeeded — a failure
    /// with no output is exactly the case that needs the context.
    public func record(_ result: CommandResult) {
        log("$ \(result.command)")
        log("  exit: \(result.exitCode)")
        let output = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
        if output.isEmpty {
            log("  output: (none)")
        } else {
            for line in output.components(separatedBy: .newlines) {
                log("  | " + line)
            }
        }
    }

    private func write(_ line: String) {
        guard let handle else { return }
        queue.sync {
            if let data = (line + "\n").data(using: .utf8) {
                try? handle.write(contentsOf: data)
            }
        }
    }

    // MARK: - Housekeeping

    /// Deletes all but the most recent logs.
    private static func prune(in folder: URL) {
        let manager = FileManager.default
        guard let files = try? manager.contentsOfDirectory(
            at: folder, includingPropertiesForKeys: [.creationDateKey]
        ) else { return }

        let logs = files
            .filter { $0.lastPathComponent.hasPrefix("family-safety-") }
            .sorted { left, right in
                let l = (try? left.resourceValues(forKeys: [.creationDateKey]).creationDate) ?? .distantPast
                let r = (try? right.resourceValues(forKeys: [.creationDateKey]).creationDate) ?? .distantPast
                return l > r
            }

        for stale in logs.dropFirst(keepMostRecent) {
            try? manager.removeItem(at: stale)
        }
    }

    // MARK: - Formatting

    /// Colons are legal in HFS+ filenames but display as `/` in Finder, so the
    /// stamp uses dashes throughout.
    private static let fileStamp: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd-HHmmss"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter
    }()

    private static let lineStamp: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter
    }()
}
