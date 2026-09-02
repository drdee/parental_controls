import Testing
import Foundation
@testable import FamilySafetyCore

/// The real (non-dry-run) apply and revert flows.
///
/// Previously untestable: applying for real edits `/etc/hosts`, creates
/// accounts and installs packages. With an injected runner the whole flow runs
/// while the machine is untouched, and the commands it *would* issue are
/// observable.
@MainActor
@Suite("App state (injected)")
struct AppStateInjectedTests {

    private func state(
        _ runner: FakeRunner,
        _ fileSystem: FakeFileSystem = .clean,
        downloader: (any PackageDownloading)? = FakeDownloader()
    ) -> AppState {
        var fs = fileSystem
        // Writing the profile must land somewhere disposable.
        fs.downloads = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("appstate-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: fs.downloads, withIntermediateDirectories: true)
        return AppState(runner: runner, fileSystem: fs, downloader: downloader)
    }

    // MARK: - Applying for real

    @Test("A real apply writes the profile and runs the hardening steps")
    func realApplyRunsSteps() async {
        let runner = FakeRunner()
        let appState = state(runner)
        appState.mode = .family

        await appState.apply()

        #expect(appState.stage == .results)
        #expect(appState.generatedProfileURL != nil)
        #expect(FileManager.default.fileExists(atPath: appState.generatedProfileURL!.path))
        // The hosts edit must have been attempted.
        #expect(runner.privilegedScripts.contains { $0.contains(Hardening.hostsMarkerBegin) })
    }

    @Test("The generated profile on disk is a valid property list")
    func writtenProfileIsValid() async throws {
        let runner = FakeRunner()
        let appState = state(runner)
        await appState.apply()

        let data = try Data(contentsOf: appState.generatedProfileURL!)
        let plist = try PropertyListSerialization.propertyList(from: data, format: nil) as! [String: Any]
        #expect(plist["PayloadScope"] as? String == "System")
    }

    /// All hardening runs in one privileged batch, so the user sees a single
    /// authorization prompt rather than one per change.
    @Test("Hardening is applied in a single privileged batch")
    func hardeningIsBatched() async {
        let runner = FakeRunner()
        let appState = state(runner)
        appState.mode = .advanced

        await appState.apply()

        let hardeningScripts = runner.privilegedScripts.filter {
            $0.contains(Hardening.hostsMarkerBegin) || $0.contains("sysadminctl")
        }
        #expect(hardeningScripts.count == 1, "expected one batch, got \(hardeningScripts.count)")
    }

    @Test("A failing batch is reported against every step in it")
    func batchFailureReported() async {
        let runner = FakeRunner()
        runner.defaultResult = CommandResult(command: "", exitCode: 1,
                                             stdout: "", stderr: "operation not permitted")
        let appState = state(runner)
        appState.mode = .advanced

        await appState.apply()

        let hardening = appState.stepResults.filter { !$0.title.contains("profile") }
        #expect(!hardening.isEmpty)
        #expect(hardening.allSatisfy { !$0.succeeded })
        #expect(hardening.contains { $0.detail.contains("not permitted") })
    }

    @Test("A cancelled authorization surfaces as an error")
    func cancelledAuthorizationSurfaces() async {
        let runner = FakeRunner()
        runner.errorToThrow = RunnerError.authorizationCancelled
        let appState = state(runner)

        await appState.apply()

        #expect(appState.runError != nil)
        #expect(appState.stepResults.contains { !$0.succeeded })
    }

    @Test("Family Mode never issues an account or FileVault command")
    func familyModeIssuesNoAccountCommands() async {
        let runner = FakeRunner()
        let appState = state(runner)
        appState.mode = .family
        appState.installWARP = true

        await appState.apply()

        let everything = runner.transcript + runner.privilegedScripts.joined(separator: "\n")
        for dangerous in ["-addUser", "dseditgroup", "fdesetup", "-deleteUser"] {
            #expect(!everything.contains(dangerous), "family mode issued \(dangerous)")
        }
    }

    // MARK: - Account creation

    @Test("Account creation runs and is then verified, not assumed")
    func accountCreationIsVerified() async {
        let runner = FakeRunner()
        // dseditgroup reports the new account is *not* an admin.
        runner.stub("dseditgroup", stdout: "no")
        runner.stub("sysadminctl", stdout: "")

        let appState = state(runner)
        appState.mode = .advanced
        appState.createAccount = true
        appState.accountUsername = "sophie"

        await appState.apply()

        #expect(runner.privilegedScripts.contains { $0.contains("-addUser 'sophie'") })
        // The check must actually have run.
        #expect(runner.ran("checkmember"))
        let result = appState.stepResults.first { $0.title.contains("sophie") }!
        #expect(result.succeeded)
    }

    /// An account that ends up an admin would undo everything else, so this
    /// must be reported as a failure even though the command itself succeeded.
    @Test("An account that turns out to be an admin is reported as a failure")
    func adminAccountIsAFailure() async {
        let runner = FakeRunner()
        runner.stub("dseditgroup", stdout: "yes")   // it IS an admin

        let appState = state(runner)
        appState.mode = .advanced
        appState.createAccount = true
        appState.accountUsername = "sophie"

        await appState.apply()

        let result = appState.stepResults.first { $0.title.contains("sophie") }!
        #expect(!result.succeeded)
        #expect(result.detail.contains("IS an admin"))
    }

    @Test("Secure Token status is reported so the reboot risk is visible")
    func secureTokenReported() async {
        let runner = FakeRunner()
        runner.stub("dseditgroup", stdout: "no")
        runner.stub("secureTokenStatus", stdout: "Secure token is DISABLED for user sophie")

        let appState = state(runner)
        appState.mode = .advanced
        appState.createAccount = true
        appState.accountUsername = "sophie"

        await appState.apply()

        let token = appState.stepResults.first { $0.title.contains("Secure Token") }!
        #expect(token.detail.contains("reboot"))
    }

    @Test("An invalid account name fails without running anything privileged")
    func invalidAccountNameIsRefused() async {
        let runner = FakeRunner()
        let appState = state(runner)
        appState.mode = .advanced
        appState.createAccount = true
        // Bypasses the UI validation to exercise the script-level guard.
        appState.accountUsername = "root"

        await appState.apply()

        #expect(!runner.privilegedScripts.contains { $0.contains("-addUser") })
        #expect(appState.stepResults.contains { $0.title.contains("account") && !$0.succeeded })
    }

    // MARK: - WARP

    @Test("An already-installed WARP is left alone")
    func warpAlreadyInstalled() async {
        let runner = FakeRunner()
        runner.stub("defaults", stdout: "2026.7.1376.0")
        var fileSystem = FakeFileSystem.clean
        fileSystem.files["/Applications/Cloudflare WARP.app"] = ""

        let appState = state(runner, fileSystem)
        appState.installWARP = true

        await appState.apply()

        let warp = appState.stepResults.first { $0.title.contains("WARP") }!
        #expect(warp.succeeded)
        #expect(warp.detail.contains("Already installed"))
        #expect(!runner.ran("/usr/sbin/installer"))
    }

    @Test("WARP is skipped entirely when not requested")
    func warpNotRequested() async {
        let runner = FakeRunner()
        let appState = state(runner)
        appState.installWARP = false
        await appState.apply()
        #expect(!appState.stepResults.contains { $0.title.contains("WARP") })
    }

    // MARK: - Verification

    @Test("Verification reads managed preferences through the filesystem")
    func verificationUsesInjectedFileSystem() async {
        let runner = FakeRunner()
        runner.stub("profiles", stdout: "com.familysafety.parental")
        let appState = state(runner, .configured)

        await appState.runVerification()

        #expect(!appState.verifications.isEmpty)
        let managed = appState.verifications.first { $0.title.contains("Managed preferences") }!
        #expect(managed.outcome == .verified)
    }

    @Test("A missing profile is reported with a remedy")
    func missingProfileReported() async {
        let runner = FakeRunner()
        runner.stub("profiles", stdout: "There are no configuration profiles installed")
        let appState = state(runner, .clean)

        await appState.runVerification()

        let profile = appState.verifications.first { $0.title.contains("profile installed") }!
        #expect(profile.outcome == .notWorking)
        #expect(profile.remedy?.contains("Device Management") == true)
    }

    /// A mistyped Zero Trust gateway still answers DNS, so only a functional
    /// check proves filtering is live.
    @Test("Filtering that is not active is reported as not working")
    func inactiveFilteringDetected() async {
        let runner = FakeRunner()
        // The reference resolver answers, and so does the configured one:
        // the test domain resolves, so filtering is not active.
        runner.stub("dig", stdout: "66.254.114.41")
        let appState = state(runner, .clean)

        await appState.runVerification()

        let filtering = appState.verifications.first { $0.title.contains("Adult content") }!
        #expect(filtering.outcome == .notWorking)
        #expect(filtering.remedy?.contains("gateway") == true)
    }

    @Test("Filtering that is active is reported as verified")
    func activeFilteringDetected() async {
        // The configured resolver sinkholes; the reference resolver does not.
        final class SplitResolver: CommandRunning, @unchecked Sendable {
            func run(_ executable: String, _ arguments: [String]) throws -> CommandResult {
                probe(executable, arguments)
            }
            func probe(_ executable: String, _ arguments: [String]) -> CommandResult {
                guard executable.contains("dig") else {
                    return CommandResult(command: executable, exitCode: 0, stdout: "", stderr: "")
                }
                let usesReference = arguments.contains { $0.hasPrefix("@") }
                return CommandResult(command: executable, exitCode: 0,
                                     stdout: usesReference ? "66.254.114.41" : "0.0.0.0",
                                     stderr: "")
            }
            func runPrivileged(script: String, description: String) throws -> CommandResult {
                CommandResult(command: script, exitCode: 0, stdout: "", stderr: "")
            }
        }

        let appState = AppState(runner: SplitResolver(), fileSystem: FakeFileSystem.configured,
                                downloader: FakeDownloader())
        await appState.runVerification()

        let filtering = appState.verifications.first { $0.title.contains("Adult content") }!
        #expect(filtering.outcome == .verified)
    }

    // MARK: - Revert through AppState

    @Test("Revert runs for real even when dry run is set")
    func revertIgnoresDryRun() async {
        let runner = FakeRunner()
        runner.stub("profiles", stdout: "com.familysafety.parental")
        let appState = state(runner, .configured)
        // A silent no-op here would leave someone believing they had undone it.
        appState.dryRun = true

        await appState.revertEverything()

        #expect(appState.stage == .revertResults)
        #expect(!runner.privilegedScripts.isEmpty, "revert did nothing")
        #expect(runner.privilegedScripts.contains { $0.contains(Hardening.hostsMarkerBegin) })
    }

    @Test("Revert results are recorded and detection is refreshed")
    func revertRecordsResults() async {
        let runner = FakeRunner()
        runner.stub("profiles", stdout: "none")
        let appState = state(runner, .clean)

        await appState.revertEverything()

        #expect(appState.revertResults.count == 3)
        #expect(appState.isReverting == false)
    }

    // MARK: - Preflight

    @Test("Preflight surfaces a machine that fails a hard requirement")
    func preflightDetectsNonAdmin() async {
        let runner = FakeRunner()
        runner.stub("dseditgroup", stdout: "no")   // not an admin
        let appState = state(runner)

        await appState.runPreflight()

        #expect(appState.preflightBlocks, "a non-admin machine should block")
        let check = appState.preflightChecks.first { $0.title.contains("administrator") }!
        #expect(check.status == .fail)
        #expect(check.rationale != nil)
    }

    @Test("Preflight passes on a machine that meets the requirements")
    func preflightPassesOnGoodMachine() async {
        let runner = FakeRunner()
        runner.stub("dseditgroup", stdout: "yes")
        runner.stub("fdesetup", stdout: "FileVault is On.")
        runner.stub("spctl", stdout: "assessments enabled")
        runner.stub("uname", stdout: "arm64")
        let appState = state(runner)

        await appState.runPreflight()

        #expect(!appState.preflightBlocks)
    }

    @Test("FileVault off is a warning, not a hard block")
    func fileVaultOffWarnsOnly() async {
        let runner = FakeRunner()
        runner.stub("dseditgroup", stdout: "yes")
        runner.stub("fdesetup", stdout: "FileVault is Off.")
        let appState = state(runner)

        await appState.runPreflight()

        let check = appState.preflightChecks.first { $0.title.contains("FileVault") }!
        #expect(check.status == .warn)
        #expect(check.rationale?.contains("Recovery") == true)
        #expect(!appState.preflightBlocks)
    }

    @Test("Existing account names are gathered for duplicate checking")
    func existingAccountsGathered() async {
        let runner = FakeRunner()
        runner.stub("dscl", stdout: "root\ndaemon\nsophie\n")
        let appState = state(runner)

        await appState.runPreflight()

        #expect(appState.existingUsernames.contains("sophie"))
        appState.mode = .advanced
        appState.createAccount = true
        appState.accountUsername = "sophie"
        #expect(appState.configurationError?.contains("already exists") == true)
    }
}
