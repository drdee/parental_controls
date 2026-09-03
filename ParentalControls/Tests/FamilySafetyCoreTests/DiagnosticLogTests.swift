import Testing
import Foundation
@testable import FamilySafetyCore

@Suite("Diagnostic log redaction")
struct DiagnosticLogRedactionTests {

    @Test("A privileged script is never written verbatim")
    func privilegedScriptIsRedacted() {
        let redactor = DiagnosticLog.Redactor()
        let line = #"/usr/bin/osascript -e do shell script "rm -rf /tmp/x" with administrator privileges"#
        let output = redactor.redact(line)

        #expect(!output.contains("rm -rf"))
        #expect(output == "<privileged script redacted>")
    }

    @Test("Lines mentioning a password are dropped whole", arguments: [
        "--password abcd-efgh-ijkl-mnop",
        "PASSWORD=hunter2",
        "notarytool --password s3cret",
        "export API_TOKEN=abc123",
        "passwd: updated",
    ])
    func secretsAreRedacted(line: String) {
        let output = DiagnosticLog.Redactor().redact(line)
        #expect(output == "<line containing a secret redacted>", "leaked: \(output)")
    }

    @Test("The account username does not reach the log")
    func usernameIsRedacted() {
        let redactor = DiagnosticLog.Redactor(accountUsername: "tessa")
        let output = redactor.redact("/usr/sbin/sysadminctl -addUser tessa -fullName Tessa")

        #expect(!output.contains("tessa"))
        #expect(output.contains("<username>"))
    }

    @Test("Ordinary lines pass through unchanged")
    func harmlessTextSurvives() {
        let output = DiagnosticLog.Redactor().redact("/usr/bin/dscacheutil -flushcache")
        #expect(output == "/usr/bin/dscacheutil -flushcache")
    }

    @Test("Redaction covers every line, not just the first")
    func multilineIsFullyRedacted() {
        let redactor = DiagnosticLog.Redactor(accountUsername: "kid")
        let output = redactor.redact("""
            harmless first line
            --password topsecret
            adduser kid
            """)

        #expect(!output.contains("topsecret"))
        #expect(!output.contains("kid"))
        #expect(output.contains("harmless first line"))
    }
}

@Suite("Diagnostic log writing")
struct DiagnosticLogWritingTests {

    /// A scratch directory per test, so nothing touches the real ~/Library.
    private func temporaryDirectory() -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("difftest-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test("A run produces a readable log file")
    func writesAFile() throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let log = DiagnosticLog(directory: directory)
        log.section("Applying changes")
        log.log("something happened")

        let contents = try String(contentsOf: log.fileURL, encoding: .utf8)
        #expect(contents.contains("== Applying changes =="))
        #expect(contents.contains("something happened"))
    }

    @Test("A command's exit code and output are recorded")
    func recordsCommands() throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let log = DiagnosticLog(directory: directory)
        log.record(CommandResult(command: "/bin/echo hi", exitCode: 0,
                                 stdout: "hi", stderr: ""))

        let contents = try String(contentsOf: log.fileURL, encoding: .utf8)
        #expect(contents.contains("/bin/echo hi"))
        #expect(contents.contains("exit: 0"))
        #expect(contents.contains("| hi"))
    }

    @Test("A secret in command output never reaches the file")
    func commandOutputIsRedacted() throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let log = DiagnosticLog(directory: directory)
        log.record(CommandResult(command: "installer --password hunter2",
                                 exitCode: 1, stdout: "", stderr: "bad --password hunter2"))

        let contents = try String(contentsOf: log.fileURL, encoding: .utf8)
        #expect(!contents.contains("hunter2"), "the log leaked a password")
    }

    /// The end-to-end shape check: a realistic run, read back as a whole file.
    /// The per-rule tests above prove each redaction; this proves they hold
    /// together when the writer, the redactor and the formatter all interact.
    @Test("A realistic run produces a log that is readable and carries no secrets")
    func realisticRunIsSafeAndReadable() throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let log = DiagnosticLog(directory: directory,
                                redactor: .init(accountUsername: "testkid"))
        log.section("Family Safety run")
        log.log("mode: family")
        log.log("privileged step: Create standard account")
        log.record(CommandResult(
            command: #"/usr/bin/osascript -e do shell script "sysadminctl -addUser testkid" with administrator privileges"#,
            exitCode: 0, stdout: "created", stderr: ""))
        log.record(CommandResult(command: "installer --password hunter2",
                                 exitCode: 1, stdout: "", stderr: "bad --password hunter2"))

        let contents = try String(contentsOf: log.fileURL, encoding: .utf8)

        // Nothing sensitive survives.
        #expect(!contents.contains("hunter2"))
        #expect(!contents.contains("testkid"))
        #expect(!contents.contains("sysadminctl -addUser"))

        // But it is still worth reading.
        #expect(contents.contains("== Family Safety run =="))
        #expect(contents.contains("mode: family"))
        #expect(contents.contains("privileged step: Create standard account"))
        #expect(contents.contains("exit: 1"))
    }

    @Test("Old logs are pruned so the directory cannot grow without bound")
    func prunesOldLogs() throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        // Twelve runs, two more than the ten that should survive.
        for index in 0..<12 {
            _ = DiagnosticLog(directory: directory,
                              now: Date().addingTimeInterval(TimeInterval(index)))
        }

        let remaining = try FileManager.default
            .contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix("family-safety-") }
        #expect(remaining.count <= 10, "found \(remaining.count) logs")
    }
}
