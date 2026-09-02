import Foundation

/// Generates the installer package that applies the privileged changes.
///
/// Replaces in-app privilege escalation entirely. `installer` runs a package's
/// `postinstall` as root, so nothing here needs to escalate — which removes the
/// whole `osascript … with administrator privileges` path, and with it the
/// AppleScript-quoting attack surface.
///
/// Chosen over a `SMAppService` privileged helper because this configuration
/// runs once per machine: a permanently installed root daemon with an XPC
/// interface would be a lasting attack surface for a one-time job.
public struct PackageBuilder {
    public init(mode: RunMode, hardening: Hardening, profileData: Data) {
        self.mode = mode
        self.hardening = hardening
        self.profileData = profileData
    }

    public var mode: RunMode
    public var hardening: Hardening
    public var profileData: Data
    /// Where the profile is copied so the user can double-click it afterwards.
    public var profileInstallPath = "/Users/Shared/Family-Safety.mobileconfig"

    public var identifier = "com.familysafety.setup.pkg"
    public var version = "1.0"

    public enum BuildError: LocalizedError {
        case toolFailed(tool: String, output: String)

        public var errorDescription: String? {
            switch self {
            case .toolFailed(let tool, let output):
                return "\(tool) failed: \(output)"
            }
        }
    }

    // MARK: - postinstall

    /// The script `installer` executes as root.
    ///
    /// Deliberately built from the same `Hardening.steps(for:)` the app shows
    /// on the review screen, so what is previewed and what runs cannot drift
    /// apart.
    public func postinstallScript() -> String {
        let steps = hardening.steps(for: mode)

        var lines = [
            "#!/bin/bash",
            "#",
            "# Family Safety — applied by the macOS installer as root.",
            "# Generated; do not edit. Every command below is shown in the app's",
            "# review screen before the package is built.",
            "",
            // Not `set -e`: a later step should still run if an earlier one
            // fails, and each step reports its own status.
            "set -u",
            "",
            "STATUS=0",
            "log() { echo \"[family-safety] $*\"; }",
            "fail() { echo \"[family-safety] FAILED: $*\" >&2; STATUS=1; }",
            "",
        ]

        for (index, step) in steps.enumerated() {
            lines.append("# --- Step \(index + 1) of \(steps.count): \(step.title)")
            lines.append("log \(Self.shellQuoted(step.title))")
            // Run each step in a subshell and branch on its status, rather
            // than wrapping the commands in `if ! { … }`. Commands are emitted
            // verbatim and unindented: a step may contain a heredoc, whose
            // terminator must start at column zero, so any indentation here
            // would silently break the script.
            lines.append("(")
            lines.append(contentsOf: step.command.split(separator: "\n", omittingEmptySubsequences: false).map(String.init))
            lines.append(")")
            lines.append("if [ $? -ne 0 ]; then fail \(Self.shellQuoted(step.title)); fi")
            lines.append("")
        }

        lines += [
            "# --- Place the configuration profile where the user can reach it",
            "# The profile still has to be installed by hand: macOS removed the",
            "# ability to install one programmatically.",
            "if [ -f \"$PWD/Family-Safety.mobileconfig\" ]; then",
            "  /bin/cp \"$PWD/Family-Safety.mobileconfig\" \(Self.shellQuoted(profileInstallPath)) 2>/dev/null || true",
            "  /bin/chmod 644 \(Self.shellQuoted(profileInstallPath)) 2>/dev/null || true",
            "fi",
            "",
            "log \"Done.\"",
            "log \"\"",
            "log \"Two things left to do:\"",
            "log \"  1. Install the profile: open \(profileInstallPath)\"",
            "log \"     then approve it in System Settings > General > Device Management.\"",
            "log \"  2. Open Family Safety Setup in Applications to verify it worked,\"",
            "log \"     or to undo everything.\"",
            "exit $STATUS",
            "",
        ]

        return lines.joined(separator: "\n")
    }

    // MARK: - Build

    /// Builds an unsigned package into `directory` and returns its URL.
    ///
    /// Signing and notarization are left to `Scripts/build-pkg.sh`, which has
    /// the Developer ID identity; keeping them out of the app avoids embedding
    /// signing behaviour in a tool a parent runs.
    public func build(in directory: URL, runner: PrivilegedRunner) throws -> URL {
        let fileManager = FileManager.default
        let scripts = directory.appendingPathComponent("scripts")
        try fileManager.createDirectory(at: scripts, withIntermediateDirectories: true)

        // The profile travels with the package so postinstall can place it.
        try profileData.write(to: scripts.appendingPathComponent("Family-Safety.mobileconfig"))

        let postinstall = scripts.appendingPathComponent("postinstall")
        try postinstallScript().write(to: postinstall, atomically: true, encoding: .utf8)
        try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: postinstall.path)

        let output = directory.appendingPathComponent("Family-Safety.pkg")
        try? fileManager.removeItem(at: output)

        // --nopayload: this package only runs a script; it installs no files.
        let result = try runner.run("/usr/bin/pkgbuild", [
            "--nopayload",
            "--scripts", scripts.path,
            "--identifier", identifier,
            "--version", version,
            output.path,
        ])
        guard result.succeeded else {
            throw BuildError.toolFailed(tool: "pkgbuild", output: result.output)
        }
        return output
    }

    /// Single-quotes a value for safe inclusion in the generated script.
    public static func shellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
