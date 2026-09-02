import Testing
import Foundation
@testable import FamilySafetyCore

/// Undo, exercised properly.
///
/// These paths remove configuration profiles and rewrite `/etc/hosts`, so they
/// cannot run against the real machine. With an injected runner the actual
/// commands and the failure handling are both observable.
@Suite("Revert (injected)")
struct RevertInjectedTests {

    private func reverter(
        _ runner: FakeRunner,
        _ fileSystem: FakeFileSystem = .configured
    ) -> Reverter {
        Reverter(runner: runner, fileSystem: fileSystem)
    }

    // MARK: - Detection

    @Test("Detects a fully configured machine")
    func detectsConfiguredMachine() async {
        let runner = FakeRunner()
        runner.stub("profiles", stdout: "com.familysafety.parental")

        let found = await reverter(runner, .configured).detectApplied()
        #expect(found.contains { $0.contains("profile") })
        #expect(found.contains { $0.contains("/etc/hosts") })
        #expect(found.contains { $0.contains("backup") })
    }

    @Test("Finds nothing on a clean machine")
    func detectsCleanMachine() async {
        let runner = FakeRunner()
        runner.stub("profiles", stdout: "There are no configuration profiles installed")

        let found = await reverter(runner, .clean).detectApplied()
        #expect(found.isEmpty)
    }

    @Test("Detection only reads; it never runs a privileged command")
    func detectionIsReadOnly() async {
        let runner = FakeRunner()
        _ = await reverter(runner).detectApplied()
        #expect(runner.privilegedScripts.isEmpty)
    }

    // MARK: - Reverting

    @Test("Reverting a configured machine undoes all three areas")
    func revertsEverything() async {
        let runner = FakeRunner()
        // Present first, gone after removal.
        runner.responses = [
            ("profiles", CommandResult(command: "", exitCode: 0,
                                       stdout: "com.familysafety.parental", stderr: "")),
        ]
        let results = await reverter(runner, .configured).revertAll()

        #expect(results.count == 3)
        #expect(results.contains { $0.title.contains("hosts") })
        #expect(results.contains { $0.title.contains("login") })
        #expect(results.contains { $0.title.contains("profile") })
    }

    @Test("The hosts revert removes only the managed block and the backup")
    func hostsRevertCommands() async {
        let runner = FakeRunner()
        _ = await reverter(runner, .configured).revertAll()

        let script = runner.privilegedScripts.joined(separator: "\n")
        #expect(script.contains(Hardening.hostsMarkerBegin))
        #expect(script.contains(Hardening.hostsMarkerEnd))
        #expect(script.contains(Hardening.hostsBackupPath))
        // The cache must be flushed or the old answers linger.
        #expect(script.contains("dscacheutil"))
    }

    @Test("Login settings are restored")
    func loginRevertCommands() async {
        let runner = FakeRunner()
        _ = await reverter(runner, .configured).revertAll()

        let script = runner.privilegedScripts.joined(separator: "\n")
        #expect(script.contains("sysadminctl -guestAccount on"))
        #expect(script.contains("DisableConsoleAccess"))
    }

    /// Removing an account would delete a home folder, so revert must not.
    @Test("Revert never touches user accounts or FileVault")
    func revertNeverDeletesAccounts() async {
        let runner = FakeRunner()
        _ = await reverter(runner, .configured).revertAll()

        let everything = runner.transcript + runner.privilegedScripts.joined(separator: "\n")
        #expect(!everything.contains("-deleteUser"))
        #expect(!everything.contains("fdesetup"))
        #expect(!everything.contains("rm -rf /Users"))
    }

    @Test("Nothing to do is reported as such rather than as success")
    func nothingToDoOnCleanMachine() async {
        let runner = FakeRunner()
        runner.stub("profiles", stdout: "There are no configuration profiles installed")

        let results = await reverter(runner, .clean).revertAll()
        let hosts = results.first { $0.title.contains("hosts") }!
        let profile = results.first { $0.title.contains("profile") }!
        #expect(hosts.outcome == .nothingToDo)
        #expect(profile.outcome == .nothingToDo)
    }

    @Test("A clean machine needs no privileged hosts edit")
    func cleanMachineSkipsHostsEdit() async {
        let runner = FakeRunner()
        runner.stub("profiles", stdout: "none")
        _ = await reverter(runner, .clean).revertAll()
        #expect(!runner.privilegedScripts.contains { $0.contains(Hardening.hostsMarkerBegin) })
    }

    // MARK: - Failure handling

    @Test("A failing hosts edit is reported as a failure")
    func hostsFailureReported() async {
        let runner = FakeRunner()
        runner.defaultResult = CommandResult(command: "", exitCode: 1,
                                             stdout: "", stderr: "permission denied")
        let results = await reverter(runner, .configured).revertAll()
        let hosts = results.first { $0.title.contains("hosts") }!
        #expect(hosts.outcome == .failed)
        #expect(hosts.detail.contains("permission denied"))
    }

    @Test("A cancelled authorization is surfaced, not swallowed")
    func cancelledAuthorizationReported() async {
        let runner = FakeRunner()
        runner.errorToThrow = RunnerError.authorizationCancelled
        let results = await reverter(runner, .configured).revertAll()
        #expect(results.contains { $0.outcome == .failed })
    }

    /// `profiles remove` can fail on a user-approved profile, so the fallback
    /// is manual instructions rather than a bare error.
    @Test("A profile that will not remove falls back to manual instructions")
    func profileRemovalFallsBackToManual() async {
        let runner = FakeRunner()
        // Still listed even after the removal attempt.
        runner.stub("profiles", stdout: "com.familysafety.parental")

        let results = await reverter(runner, .configured).revertAll()
        let profile = results.first { $0.title.contains("profile") }!
        #expect(profile.outcome == .manualStepRequired)
        #expect(profile.detail.contains("System Settings"))
    }

    @Test("A profile that removes cleanly is reported as reverted")
    func profileRemovalSucceeds() async {
        final class Sequencer: CommandRunning, @unchecked Sendable {
            private let lock = NSLock()
            private var profilesCalls = 0
            func run(_ executable: String, _ arguments: [String]) throws -> CommandResult {
                probe(executable, arguments)
            }
            func probe(_ executable: String, _ arguments: [String]) -> CommandResult {
                guard executable.contains("profiles") else {
                    return CommandResult(command: executable, exitCode: 0, stdout: "", stderr: "")
                }
                let count = lock.withLock { () -> Int in profilesCalls += 1; return profilesCalls }
                // Present on the first look, gone once removal has run.
                return CommandResult(command: executable, exitCode: 0,
                                     stdout: count == 1 ? "com.familysafety.parental" : "none",
                                     stderr: "")
            }
            func runPrivileged(script: String, description: String) throws -> CommandResult {
                CommandResult(command: script, exitCode: 0, stdout: "", stderr: "")
            }
        }

        let results = await Reverter(runner: Sequencer(), fileSystem: FakeFileSystem.configured).revertAll()
        let profile = results.first { $0.title.contains("profile") }!
        #expect(profile.outcome == .reverted)
    }

    @Test("The removal command targets our own profile identifier")
    func removalTargetsOurIdentifier() async {
        let runner = FakeRunner()
        runner.stub("profiles", stdout: "com.familysafety.parental")
        _ = await reverter(runner, .configured).revertAll()

        let script = runner.privilegedScripts.joined(separator: "\n")
        #expect(script.contains("profiles remove"))
        #expect(script.contains(ProfileIdentity.prefix))
    }

    @Test("Every result carries a usable detail message")
    func resultsAreExplained() async {
        let runner = FakeRunner()
        for results in [
            await reverter(runner, .configured).revertAll(),
            await reverter(FakeRunner(), .clean).revertAll(),
        ] {
            for result in results {
                #expect(!result.detail.isEmpty, "\(result.title) has no detail")
                if result.outcome == .manualStepRequired {
                    #expect(result.detail.contains("System Settings"))
                }
            }
        }
    }
}
