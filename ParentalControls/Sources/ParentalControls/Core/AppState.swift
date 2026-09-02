import Foundation
import Observation

/// Where the user is in the flow.
enum Stage: Int, Comparable, Sendable {
    case chooseMode
    case configure
    case review
    case running
    case results
    case revertConfirm
    case reverting
    case revertResults

    static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// Outcome of a single applied step.
struct StepResult: Identifiable, Sendable {
    var id: String { title }
    var title: String
    var succeeded: Bool
    var detail: String
}

@MainActor
@Observable
final class AppState {
    // MARK: - Configuration

    var stage: Stage = .chooseMode
    var mode: RunMode = .family
    var blockedSites: [BlockedSite] = BlockedSite.defaults

    /// The blocklist actually applied: the editable list plus whichever
    /// presets are switched on.
    var effectiveBlockedSites: [BlockedSite] {
        var sites = blockedSites
        if blockSocialMedia { sites += BlockedSite.socialMedia }
        if blockAIChatbots { sites += BlockedSite.aiChatbots }
        if blockChatAndGaming { sites += BlockedSite.chatAndGaming }
        return sites
    }

    var useZeroTrust = false
    var zeroTrustURL = ""
    var installWARP = false

    var youTubeLevel: SafeSearch.YouTubeLevel = .moderate
    var forceSafeSearch = true
    var restrictAirDrop = true
    var blockSocialMedia = true
    var blockAIChatbots = true
    var blockChatAndGaming = false

    /// Walk the whole wizard and report what *would* change, touching nothing.
    ///
    /// Worth having beyond simple caution: it is how someone decides whether to
    /// trust this app on their family's Mac in the first place.
    var dryRun = false

    /// Advanced-mode account creation is opt-in even within Advanced mode,
    /// because it is the only step that can lock someone out.
    var createAccount = false
    var accountUsername = ""
    var accountFullName = ""

    var dnsBackend: DNSBackend {
        useZeroTrust ? .zeroTrust(dohURL: zeroTrustURL) : .families
    }

    /// Blocking reason for the current configuration, if any.
    var configurationError: String? {
        if useZeroTrust, let error = dnsBackend.validationError { return error }
        if mode == .advanced, createAccount {
            let raw = accountUsername.trimmingCharacters(in: .whitespaces)
            if raw.isEmpty {
                return "Enter a short name for the new account."
            }
            // Same validator the privileged script uses, so the UI cannot
            // accept a name that would later be refused (or be unsafe).
            if AccountName(raw) == nil {
                return "“\(raw)” can’t be used. Use lowercase letters, numbers, hyphen or underscore, starting with a letter."
            }
            if existingUsernames.contains(raw.lowercased()) {
                return "An account named “\(raw)” already exists on this Mac."
            }
        }
        if effectiveBlockedSites.isEmpty && !useZeroTrust {
            return "Turn on at least one category, add a site, or use Zero Trust with its own policy."
        }
        return nil
    }

    // MARK: - Results

    var preflightChecks: [PreflightCheck] = []
    var stepResults: [StepResult] = []
    var verifications: [Verification] = []
    var generatedProfileURL: URL?
    var warpProgress: Double?
    var runError: String?
    var isRunning = false

    // MARK: - Services

    private var runner: PrivilegedRunner { PrivilegedRunner(dryRun: dryRun) }

    /// Plain-language description of every change, for the dry-run walkthrough.
    var changePlan: ChangePlan {
        ChangePlan(
            mode: mode,
            backend: dnsBackend,
            blockedSites: effectiveBlockedSites,
            installWARP: installWARP,
            youTubeLevel: youTubeLevel,
            forceSafeSearch: forceSafeSearch,
            restrictAirDrop: restrictAirDrop,
            createAccount: mode == .advanced && createAccount,
            accountUsername: accountUsername.trimmingCharacters(in: .whitespaces)
        )
    }

    /// Existing local account names, so we don't offer to create a duplicate.
    private(set) var existingUsernames: Set<String> = []

    func runPreflight() async {
        let runner = self.runner
        let mode = self.mode
        preflightChecks = await Preflight(runner: runner).runAllAsync(mode: mode)
        existingUsernames = Set(
            await runner.probeAsync("/usr/bin/dscl", [".", "-list", "/Users"])
                .output
                .split(separator: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
                .filter { !$0.isEmpty }
        )
    }

    var preflightBlocks: Bool {
        preflightChecks.contains { $0.status == .fail }
    }

    /// Hardening configured from the current settings.
    private var hardening: Hardening {
        Hardening(
            runner: runner,
            blockedSites: effectiveBlockedSites,
            youTubeLevel: youTubeLevel,
            forceSafeSearch: forceSafeSearch
        )
    }

    /// Steps that will run, for the review screen.
    var plannedSteps: [HardeningStep] {
        hardening.steps(for: mode)
    }

    // MARK: - Apply

    func apply() async {
        isRunning = true
        runError = nil
        stepResults = []
        defer { isRunning = false }

        let hardening = self.hardening

        guard await generateProfileStep() else { return }

        if installWARP {
            await warpStep()
        }
        await hardeningStep(hardening)

        // Account creation is last: it is the riskiest step, so nothing else
        // depends on it having run.
        if mode == .advanced, createAccount {
            await accountStep(hardening)
        }

        stage = .results
    }

    /// Writes the profile. Returns false if the run should stop.
    ///
    /// The profile cannot be installed programmatically — `profiles` dropped
    /// the install verb — so the user double-clicks it afterwards.
    private func generateProfileStep() async -> Bool {
        let generator = ProfileGenerator(
            blockedSites: effectiveBlockedSites,
            dnsBackend: dnsBackend,
            youTubeLevel: youTubeLevel,
            forceSafeSearch: forceSafeSearch,
            restrictAirDrop: restrictAirDrop
        )
        do {
            if dryRun {
                // Build it to prove generation works, but write nothing.
                let data = try generator.xmlData()
                stepResults.append(StepResult(
                    title: "Generate configuration profile",
                    succeeded: true,
                    detail: "Would write \(data.count) bytes to your Downloads folder. Nothing was saved."
                ))
            } else {
                let url = try writeProfile(generator)
                generatedProfileURL = url
                stepResults.append(StepResult(
                    title: "Generate configuration profile",
                    succeeded: true,
                    detail: url.path
                ))
            }
            return true
        } catch {
            stepResults.append(StepResult(
                title: "Generate configuration profile",
                succeeded: false,
                detail: error.localizedDescription
            ))
            runError = error.localizedDescription
            return false
        }
    }

    /// Installs WARP, which is what enforces Zero Trust policy on the device
    /// rather than only pointing DNS at it.
    private func warpStep() async {
        if dryRun {
            let existing = await WARPInstaller(runner: runner).installedVersionAsync()
            stepResults.append(StepResult(
                title: "Cloudflare WARP",
                succeeded: true,
                detail: existing.map { "Already installed (version \($0)); would be left alone." }
                    ?? "Would download about 150 MB, verify Cloudflare's signature, and install. Nothing was downloaded."
            ))
        } else {
            await installWARPClient()
        }
    }

    /// Applies local hardening in a single privileged batch, so the user sees
    /// one authorization prompt rather than one per change.
    private func hardeningStep(_ hardening: Hardening) async {
        let steps = hardening.steps(for: mode)
        guard !steps.isEmpty else { return }

        if dryRun {
            for step in steps {
                stepResults.append(StepResult(
                    title: step.title,
                    succeeded: true,
                    detail: "Would run, but nothing was changed."
                ))
            }
            return
        }

        let script = steps.map(\.command).joined(separator: "\n")
        do {
            let result = try await runner.runPrivilegedAsync(
                script: script,
                description: "Apply \(steps.count) system changes"
            )
            for step in steps {
                stepResults.append(StepResult(
                    title: step.title,
                    succeeded: result.succeeded,
                    detail: result.succeeded ? "Applied" : result.output
                ))
            }
        } catch {
            runError = error.localizedDescription
            for step in steps {
                stepResults.append(StepResult(
                    title: step.title, succeeded: false,
                    detail: error.localizedDescription
                ))
            }
        }
    }

    private func accountStep(_ hardening: Hardening) async {
        if dryRun {
            stepResults.append(StepResult(
                title: "Create standard account “\(accountUsername)”",
                succeeded: true,
                detail: "Would create a non-admin account and prompt for its password. No account was created."
            ))
        } else {
            await createStandardAccount(hardening)
        }
    }

    private func writeProfile(_ generator: ProfileGenerator) throws -> URL {
        let data = try generator.xmlData()
        let directory = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        let url = directory.appendingPathComponent("Family-Safety.mobileconfig")
        try data.write(to: url)
        return url
    }

    private func installWARPClient() async {
        let installer = WARPInstaller(runner: runner)
        if let version = await installer.installedVersionAsync() {
            stepResults.append(StepResult(
                title: "Cloudflare WARP",
                succeeded: true,
                detail: "Already installed (version \(version))"
            ))
            return
        }
        do {
            warpProgress = 0
            let package = try await installer.download { [weak self] fraction in
                Task { @MainActor in self?.warpProgress = fraction }
            }
            try await installer.installAsync(package: package)
            warpProgress = nil
            stepResults.append(StepResult(
                title: "Cloudflare WARP",
                succeeded: true,
                detail: "Downloaded, signature verified, and installed"
            ))
        } catch {
            warpProgress = nil
            stepResults.append(StepResult(
                title: "Cloudflare WARP",
                succeeded: false,
                detail: error.localizedDescription
            ))
        }
    }

    private func createStandardAccount(_ hardening: Hardening) async {
        let username = accountUsername.trimmingCharacters(in: .whitespaces)
        let fullName = accountFullName.isEmpty ? username : accountFullName
        do {
            let script = try hardening.createStandardAccountScript(username: username, fullName: fullName)
            let result = try await runner.runPrivilegedAsync(script: script, description: "Create standard account")
            // Never trust the exit code here — confirm the account really is
            // non-admin, because an admin account would undo everything else.
            let check = await hardening.verifyStandardAccountAsync(username: username)
            stepResults.append(StepResult(
                title: "Create standard account “\(username)”",
                succeeded: result.succeeded && check.isStandard,
                detail: check.detail
            ))
            stepResults.append(StepResult(
                title: "Secure Token status",
                succeeded: true,
                detail: await hardening.secureTokenStatusAsync(username: username)
                    + "  —  reboot and log in as this user before handing over the Mac."
            ))
        } catch {
            stepResults.append(StepResult(
                title: "Create standard account",
                succeeded: false,
                detail: error.localizedDescription
            ))
        }
    }

    // MARK: - Revert

    var revertResults: [RevertResult] = []
    var detectedChanges: [String] = []
    var isReverting = false

    var revertPlan: [String] { Reverter(runner: runner).plan() }
    var revertWillNotUndo: [String] { Reverter(runner: runner).willNotUndo() }

    /// Look for evidence this tool has been run, so the confirmation screen can
    /// say what is actually present rather than guessing.
    func detectExistingChanges() async {
        detectedChanges = await Reverter(runner: runner).detectApplied()
    }

    func revertEverything() async {
        isReverting = true
        defer { isReverting = false }
        // Never honour dry-run here: reverting is the safe direction, and a
        // silent no-op would leave someone believing they had undone it.
        let reverter = Reverter(runner: PrivilegedRunner(dryRun: false))
        revertResults = await reverter.revertAll()
        detectedChanges = await reverter.detectApplied()
        stage = .revertResults
    }

    func runVerification() async {
        // Pointless after a dry run — nothing was applied, so every check would
        // report "not working" and read as a failure rather than a no-op.
        guard !dryRun else {
            verifications = []
            return
        }
        verifications = await Verifier(runner: runner)
            .runAllAsync(backend: dnsBackend, blockedSites: effectiveBlockedSites)
    }
}
