import Testing
import Foundation
@testable import FamilySafetyCore

/// The installer package replaces in-app privilege escalation: `installer` runs
/// its postinstall as root. A malformed script would fail *after* the user has
/// authenticated, so syntax and content are checked here rather than at install
/// time.
@Suite("Installer package")
struct PackageBuilderTests {

    private func builder(_ mode: RunMode = .family) throws -> PackageBuilder {
        let sites = BlockedSite.socialMedia + BlockedSite.aiChatbots
        return PackageBuilder(
            mode: mode,
            hardening: Hardening(runner: PrivilegedRunner(), blockedSites: sites),
            profileData: try ProfileGenerator(blockedSites: sites).xmlData()
        )
    }

    private func checkBash(_ script: String) throws -> (status: Int32, output: String) {
        let file = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pkg-\(UUID().uuidString).sh")
        try script.write(to: file, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: file) }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = ["-n", file.path]
        let err = Pipe()
        process.standardError = err
        try process.run()
        let data = err.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }

    /// The regression that matters most: indenting a step's commands broke the
    /// heredoc, because a heredoc terminator must start at column zero.
    @Test("The postinstall script is valid bash in every mode", arguments: [RunMode.family, .advanced])
    func postinstallIsValidBash(_ mode: RunMode) throws {
        let result = try checkBash(try builder(mode).postinstallScript())
        #expect(result.status == 0, "bash -n failed: \(result.output)")
    }

    @Test("The postinstall script has a shebang and exits with a status")
    func postinstallStructure() throws {
        let script = try builder().postinstallScript()
        #expect(script.hasPrefix("#!/bin/bash"))
        #expect(script.contains("exit $STATUS"))
        // `set -e` would abort the run on the first failure; each step should
        // instead report its own status and continue.
        #expect(!script.contains("set -e\n"))
        #expect(script.contains("set -u"))
    }

    /// Both the review screen and the package come from `Hardening.steps`, so
    /// what is previewed cannot drift from what runs.
    @Test("The script contains exactly the planned steps", arguments: [RunMode.family, .advanced])
    func scriptMatchesPlannedSteps(_ mode: RunMode) throws {
        let package = try builder(mode)
        let script = try package.postinstallScript()
        let steps = package.hardening.steps(for: mode)

        for step in steps {
            #expect(script.contains(step.title), "missing step: \(step.title)")
        }
        #expect(script.contains("Step 1 of \(steps.count)"))
    }

    @Test("Advanced mode adds its extra steps to the script")
    func advancedScriptHasMoreSteps() throws {
        let family = try builder(.family).postinstallScript()
        let advanced = try builder(.advanced).postinstallScript()
        #expect(advanced.count > family.count)
        #expect(advanced.contains("sysadminctl -guestAccount off"))
        #expect(!family.contains("sysadminctl"))
    }

    @Test("Heredocs inside steps survive script assembly")
    func heredocSurvivesAssembly() throws {
        let script = try builder().postinstallScript()
        let opens = script.components(separatedBy: "<<'\(Hardening.hostsHeredocDelimiter)'").count - 1
        let closes = script.components(separatedBy: "\n\(Hardening.hostsHeredocDelimiter)").count - 1
        #expect(opens == 1)
        #expect(closes == 1)
        // The terminator must be at column zero or bash never ends the heredoc.
        #expect(script.contains("\n\(Hardening.hostsHeredocDelimiter)\n"))
    }

    @Test("Step titles are quoted where they are echoed")
    func titlesAreQuoted() throws {
        let sites = [BlockedSite("example.com")]
        let package = PackageBuilder(
            mode: .family,
            hardening: Hardening(runner: PrivilegedRunner(), blockedSites: sites),
            profileData: Data()
        )
        let script = try package.postinstallScript()
        // Titles are echoed via log/fail and must be single-quoted.
        #expect(script.contains("log 'Block sites in /etc/hosts'"))
    }

    @Test("Shell quoting escapes embedded apostrophes")
    func shellQuoting() {
        #expect(PackageBuilder.shellQuoted("plain") == "'plain'")
        #expect(PackageBuilder.shellQuoted("it's") == "'it'\\''s'")
        #expect(PackageBuilder.shellQuoted("") == "''")
    }

    @Test("The script places the profile where the user can reach it")
    func scriptPlacesProfile() throws {
        let package = try builder()
        let script = try package.postinstallScript()
        #expect(script.contains(package.profileInstallPath))
        #expect(script.contains("Family-Safety.mobileconfig"))
    }

    @Test("Building produces an installable package whose scripts run as root")
    func buildsPackage() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pkgbuild-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let url = try builder().build(in: directory, runner: PrivilegedRunner())
        #expect(FileManager.default.fileExists(atPath: url.path))

        // Expand it and confirm the postinstall and profile travelled with it.
        let expanded = directory.appendingPathComponent("expanded")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/pkgutil")
        process.arguments = ["--expand", url.path, expanded.path]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        try process.run()
        process.waitUntilExit()
        #expect(process.terminationStatus == 0)

        let info = try String(contentsOf: expanded.appendingPathComponent("PackageInfo"), encoding: .utf8)
        // auth="root" is the property that removes the need for in-app
        // privilege escalation.
        #expect(info.contains("auth=\"root\""))
        #expect(info.contains("postinstall"))
    }
}

/// Undo. A control you cannot remove is one you cannot safely try, so revert is
/// treated as a first-class path.
@Suite("Revert")
struct ReverterTests {

    @Test("The plan describes what will be undone")
    func planIsDescribed() {
        let plan = Reverter(runner: PrivilegedRunner(dryRun: true)).plan()
        #expect(plan.count >= 3)
        let text = plan.joined(separator: " ").lowercased()
        #expect(text.contains("profile"))
        #expect(text.contains("hosts"))
        #expect(text.contains("guest"))
    }

    /// Deleting an account would remove someone's home folder, so revert
    /// deliberately does not — and must say so.
    @Test("The limits of undo are disclosed")
    func limitsAreDisclosed() {
        let limits = Reverter(runner: PrivilegedRunner(dryRun: true)).willNotUndo()
        #expect(limits.count >= 3)
        let text = limits.joined(separator: " ").lowercased()
        #expect(text.contains("account"))
        #expect(text.contains("warp"))
        #expect(text.contains("screen time"))
    }

    @Test("Detection is read-only")
    func detectionIsReadOnly() async throws {
        let hostsBefore = try String(contentsOfFile: "/etc/hosts", encoding: .utf8)
        // Detection must not mutate anything, whatever it finds. On an
        // unconfigured machine the result is empty; the point is the file
        // comparison below, not the contents.
        _ = await Reverter(runner: PrivilegedRunner(dryRun: true)).detectApplied()
        #expect(try String(contentsOfFile: "/etc/hosts", encoding: .utf8) == hostsBefore)
    }

    @Test("Profile identity is shared between generation and removal")
    func identityIsShared() throws {
        // If these drift apart, revert silently stops finding the profile.
        let data = try ProfileGenerator(blockedSites: []).xmlData()
        let root = try PropertyListSerialization.propertyList(from: data, format: nil) as! [String: Any]
        #expect(root["PayloadIdentifier"] as? String == ProfileIdentity.prefix)
        #expect(ProfileIdentity.prefix.lowercased().contains(ProfileIdentity.listingMarker))
    }
}
