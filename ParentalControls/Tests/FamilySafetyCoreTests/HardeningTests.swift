import Testing
import Foundation
@testable import FamilySafetyCore

/// The hosts-file and login changes. These run as root and edit a file the
/// whole system depends on, so the tests execute the generated script against
/// a copy of the real `/etc/hosts` rather than only inspecting strings.
@Suite("Hardening")
struct HardeningTests {

    private func hardening(
        _ sites: [BlockedSite] = BlockedSite.socialMedia,
        youTube: SafeSearch.YouTubeLevel = .moderate,
        safeSearch: Bool = true
    ) -> Hardening {
        Hardening(runner: PrivilegedRunner(dryRun: true), blockedSites: sites,
                  youTubeLevel: youTube, forceSafeSearch: safeSearch)
    }

    // MARK: - Mode safety

    /// The property that makes Family Mode safe to hand to another family: it
    /// must be incapable of locking anyone out of their own Mac.
    @Test("Family Mode never touches accounts, FileVault or login settings")
    func familyModeIsNonDestructive() {
        let steps = hardening().steps(for: .family)
        #expect(steps.count == 1, "family mode should only edit /etc/hosts")
        #expect(steps.allSatisfy { !$0.isAdvancedOnly })

        let allCommands = steps.map(\.command).joined(separator: "\n")
        for dangerous in ["sysadminctl", "dseditgroup", "fdesetup", "dscl", "systemsetup", "bputil", "csrutil"] {
            #expect(!allCommands.contains(dangerous),
                    "family mode must not invoke \(dangerous)")
        }
    }

    @Test("Advanced Mode adds login hardening on top of Family Mode")
    func advancedModeAddsSteps() {
        let family = hardening().steps(for: .family)
        let advanced = hardening().steps(for: .advanced)
        #expect(advanced.count > family.count)
        #expect(advanced.contains { $0.isAdvancedOnly })
        // Everything Family Mode does must also happen in Advanced Mode.
        for step in family {
            #expect(advanced.contains { $0.title == step.title })
        }
    }

    @Test("Every step is individually reversible")
    func stepsAreReversible() {
        for step in hardening().steps(for: .advanced) {
            #expect(step.undoCommand != nil, "\(step.title) has no undo")
            #expect(step.explanation.isEmpty == false, "\(step.title) has no explanation")
        }
    }

    @Test("Step titles are unique so they can be used as identifiers")
    func stepTitlesAreUnique() {
        for mode in [RunMode.family, .advanced] {
            let ids = hardening().steps(for: mode).map(\.id)
            #expect(Set(ids).count == ids.count, "duplicate step id in \(mode)")
        }
    }

    // MARK: - hosts file content

    @Test("Hostnames are deduplicated across overlapping sites")
    func deduplicatesHostnames() {
        // openai.com is already listed under chatgpt.com, so adding it
        // explicitly must not produce two identical hosts lines.
        let sites = BlockedSite.aiChatbots + [BlockedSite("openai.com")]
        let hosts = Hardening.hostsToWrite(for: sites)
        #expect(Set(hosts).count == hosts.count)
    }

    @Test("Invalid sites are dropped rather than written")
    func dropsInvalidSites() {
        let hosts = Hardening.hostsToWrite(for: [
            BlockedSite("valid.com"),
            BlockedSite("nodot"),
            BlockedSite(""),
            BlockedSite(".."),
        ])
        #expect(hosts.contains("valid.com"))
        #expect(!hosts.contains("nodot"))
        #expect(!hosts.contains(""))
        #expect(!hosts.contains(".."))
    }

    /// A hostname equal to the heredoc terminator would end the heredoc early
    /// and turn the remaining lines into root commands.
    @Test("A hostname cannot match the heredoc delimiter")
    func delimiterCannotLeak() {
        let hosts = Hardening.hostsToWrite(for: [
            BlockedSite(Hardening.hostsHeredocDelimiter),
        ])
        #expect(!hosts.contains(Hardening.hostsHeredocDelimiter))
    }

    @Test("The generated hosts script has balanced heredoc delimiters")
    func heredocIsBalanced() {
        let command = hardening().hostsSinkhole().command
        let opens = command.components(separatedBy: "<<'\(Hardening.hostsHeredocDelimiter)'").count - 1
        let closes = command.components(separatedBy: "\n\(Hardening.hostsHeredocDelimiter)").count - 1
        #expect(opens == 1)
        #expect(closes == 1)
    }

    @Test("SafeSearch pinning is included only when requested")
    func safeSearchPinning() {
        let on = hardening(youTube: .moderate, safeSearch: true).hostsSinkhole().command
        #expect(on.contains("\(SafeSearch.strictAddress)\twww.google.com"))
        #expect(on.contains("\(SafeSearch.moderateAddress)\twww.youtube.com"))
        // The API hosts matter: the apps use them directly.
        #expect(on.contains("youtubei.googleapis.com"))

        let off = hardening(youTube: .off, safeSearch: false).hostsSinkhole().command
        #expect(!off.contains(SafeSearch.strictAddress))
        #expect(!off.contains(SafeSearch.moderateAddress))
    }

    @Test("Strict YouTube uses the strict address")
    func strictYouTubePinning() {
        let command = hardening(youTube: .strict, safeSearch: false).hostsSinkhole().command
        #expect(command.contains("\(SafeSearch.strictAddress)\twww.youtube.com"))
    }

    // MARK: - Executing the generated script

    /// Rewrites the script to operate on a temporary copy so the real
    /// `/etc/hosts` is never touched by the test suite.
    private func runAgainstCopy(_ command: String, hosts: URL, backup: URL) throws -> Int32 {
        var script = command
            .replacingOccurrences(of: Hardening.hostsBackupPath, with: backup.path)
            .replacingOccurrences(of: "/etc/hosts", with: hosts.path)
        // Drop the cache-flush commands: they need root and are irrelevant here.
        script = script
            .split(separator: "\n")
            .filter { !$0.contains("dscacheutil") && !$0.contains("killall") }
            .joined(separator: "\n")

        let scriptFile = hosts.deletingLastPathComponent().appendingPathComponent("run.sh")
        try script.write(to: scriptFile, atomically: true, encoding: .utf8)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = [scriptFile.path]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }

    private func makeTemporaryHosts() throws -> (directory: URL, hosts: URL, backup: URL, original: String) {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("familysafety-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let hosts = directory.appendingPathComponent("hosts")
        // Use the real file as the fixture: it is the actual input shape.
        let original = (try? String(contentsOfFile: "/etc/hosts", encoding: .utf8))
            ?? "127.0.0.1\tlocalhost\n"
        try original.write(to: hosts, atomically: true, encoding: .utf8)
        return (directory, hosts, directory.appendingPathComponent("hosts.backup"), original)
    }

    @Test("The hosts script is valid bash")
    func hostsScriptIsValidBash() throws {
        for mode in [RunMode.family, RunMode.advanced] {
            for step in hardening().steps(for: mode) {
                let file = URL(fileURLWithPath: NSTemporaryDirectory())
                    .appendingPathComponent("check-\(UUID().uuidString).sh")
                try step.command.write(to: file, atomically: true, encoding: .utf8)
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/bin/bash")
                process.arguments = ["-n", file.path]
                process.standardError = Pipe()
                try process.run()
                process.waitUntilExit()
                #expect(process.terminationStatus == 0, "\(step.title) is not valid bash")
                try? FileManager.default.removeItem(at: file)
            }
        }
    }

    @Test("Applying the hosts script blocks the configured sites")
    func hostsScriptApplies() throws {
        let fixture = try makeTemporaryHosts()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }

        let status = try runAgainstCopy(hardening().hostsSinkhole().command,
                                        hosts: fixture.hosts, backup: fixture.backup)
        #expect(status == 0)

        let result = try String(contentsOf: fixture.hosts, encoding: .utf8)
        #expect(result.contains(Hardening.hostsMarkerBegin))
        #expect(result.contains(Hardening.hostsMarkerEnd))
        #expect(result.contains("0.0.0.0\ttiktok.com"))
        #expect(FileManager.default.fileExists(atPath: fixture.backup.path))
    }

    @Test("Re-applying is idempotent")
    func hostsScriptIsIdempotent() throws {
        let fixture = try makeTemporaryHosts()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }

        let command = hardening().hostsSinkhole().command
        _ = try runAgainstCopy(command, hosts: fixture.hosts, backup: fixture.backup)
        let first = try String(contentsOf: fixture.hosts, encoding: .utf8)
        _ = try runAgainstCopy(command, hosts: fixture.hosts, backup: fixture.backup)
        let second = try String(contentsOf: fixture.hosts, encoding: .utf8)

        #expect(first == second, "second run changed the file")
        #expect(second.components(separatedBy: Hardening.hostsMarkerBegin).count - 1 == 1,
                "duplicate managed block")
    }

    @Test("Applying preserves entries the user already had")
    func hostsScriptPreservesExistingEntries() throws {
        let fixture = try makeTemporaryHosts()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }

        let sentinel = "10.9.9.9\tmy-own-entry.local"
        try (fixture.original + "\n" + sentinel + "\n")
            .write(to: fixture.hosts, atomically: true, encoding: .utf8)

        _ = try runAgainstCopy(hardening().hostsSinkhole().command,
                               hosts: fixture.hosts, backup: fixture.backup)
        let result = try String(contentsOf: fixture.hosts, encoding: .utf8)
        #expect(result.contains(sentinel))
        #expect(result.contains("127.0.0.1"))
    }

    /// Undo must remove only the managed block, leaving anything the user
    /// added afterwards intact.
    @Test("Undo restores the file byte-for-byte and keeps later additions")
    func undoIsClean() throws {
        let fixture = try makeTemporaryHosts()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }

        let step = hardening().hostsSinkhole()
        _ = try runAgainstCopy(step.command, hosts: fixture.hosts, backup: fixture.backup)

        // Something added by the user *after* we applied our block.
        let sentinel = "10.9.9.9\tadded-later.local"
        let applied = try String(contentsOf: fixture.hosts, encoding: .utf8)
        try (applied + sentinel + "\n").write(to: fixture.hosts, atomically: true, encoding: .utf8)

        _ = try runAgainstCopy(step.undoCommand!, hosts: fixture.hosts, backup: fixture.backup)

        let result = try String(contentsOf: fixture.hosts, encoding: .utf8)
        #expect(result.contains(sentinel), "undo removed an unrelated entry")
        #expect(!result.contains(Hardening.hostsMarkerBegin))
        #expect(!result.contains("tiktok.com"))
        // Ignoring the deliberately added line, the file should match the original.
        let withoutSentinel = result
            .split(separator: "\n", omittingEmptySubsequences: false)
            .filter { !$0.contains("added-later.local") }
            .joined(separator: "\n")
        #expect(withoutSentinel.trimmingCharacters(in: .whitespacesAndNewlines)
                == fixture.original.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    @Test("A hostile domain cannot inject a hosts entry")
    func hostileDomainCannotInject() throws {
        let fixture = try makeTemporaryHosts()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }

        let attack = Hardening(runner: PrivilegedRunner(dryRun: true),
                               blockedSites: [BlockedSite("evil.com\n0.0.0.0 apple.com")])
        _ = try runAgainstCopy(attack.hostsSinkhole().command,
                               hosts: fixture.hosts, backup: fixture.backup)

        let result = try String(contentsOf: fixture.hosts, encoding: .utf8)
        #expect(!result.contains("0.0.0.0 apple.com"), "injection succeeded")
    }
}
