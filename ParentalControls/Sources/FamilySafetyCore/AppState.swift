import Foundation
import Observation

/// Where the user is in the flow.
public enum Stage: Int, Comparable, Sendable {
    case chooseMode
    case configure
    case review
    case running
    case results
    case revertConfirm
    case reverting
    case revertResults

    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// Outcome of a single applied step.
public struct StepResult: Identifiable, Sendable {
    public var id: String { title }
    public var title: String
    public var succeeded: Bool
    public var detail: String
}

@MainActor
@Observable
public final class AppState {
    /// Injected so the destructive paths can be tested. Defaults to the real
    /// implementations, so production callers construct `AppState()`.
    private let injectedRunner: (any CommandRunning)?
    private let fileSystem: any FileSystemReading
    private let downloader: (any PackageDownloading)?
    private let resolver: any HostResolving

    /// Records this run for diagnostics. Nil in tests, which pass a runner of
    /// their own and should not litter the filesystem.
    public let diagnosticLog: DiagnosticLog?

    /// Set when a newer release exists. Notify-only: nothing is downloaded.
    public var availableUpdate: AvailableRelease?
    /// Cleared for the session once the banner is dismissed.
    public var updateBannerDismissed = false

    public init(runner: (any CommandRunning)? = nil,
                fileSystem: any FileSystemReading = LiveFileSystem(),
                downloader: (any PackageDownloading)? = nil,
                resolver: any HostResolving = SystemResolver(),
                diagnosticLog: DiagnosticLog? = nil) {
        self.injectedRunner = runner
        self.fileSystem = fileSystem
        self.downloader = downloader
        self.resolver = resolver
        // Only the real app logs. A test injecting a runner is exercising
        // logic, not a session worth recording.
        self.diagnosticLog = diagnosticLog ?? (runner == nil ? DiagnosticLog() : nil)
    }

    // MARK: - Configuration

    public var stage: Stage = .chooseMode
    public var mode: RunMode = .family
    public var blockedSites: [BlockedSite] = BlockedSite.defaults

    /// The blocklist actually applied: the editable list plus whichever
    /// presets are switched on.
    public var effectiveBlockedSites: [BlockedSite] {
        var sites = blockedSites
        if blockSocialMedia { sites += BlockedSite.socialMedia }
        if blockAIChatbots { sites += BlockedSite.aiChatbots }
        if blockChatAndGaming { sites += BlockedSite.chatAndGaming }
        return sites
    }

    public var useZeroTrust = false
    public var zeroTrustURL = ""
    public var installWARP = false

    public var youTubeLevel: SafeSearch.YouTubeLevel = .moderate
    public var forceSafeSearch = true
    public var installAdBlocker = true
    public var blockThirdPartyCookies = true
    public var educationalBookmarks = true
    public var blockSocialMedia = true
    public var blockAIChatbots = true
    public var blockChatAndGaming = false

    /// Walk the whole wizard and report what *would* change, touching nothing.
    ///
    /// Worth having beyond simple caution: it is how someone decides whether to
    /// trust this app on their family's Mac in the first place.
    public var dryRun = false

    /// Advanced-mode account creation is opt-in even within Advanced mode,
    /// because it is the only step that can lock someone out.
    public var createAccount = false
    public var accountUsername = ""
    public var accountFullName = ""

    public var dnsBackend: DNSBackend {
        useZeroTrust ? .zeroTrust(dohURL: zeroTrustURL) : .families
    }

    /// Blocking reason for the current configuration, if any.
    public var configurationError: String? {
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

    public var preflightChecks: [PreflightCheck] = []
    public var stepResults: [StepResult] = []
    public var verifications: [Verification] = []
    public var generatedProfileURL: URL?
    public var warpProgress: Double?
    public var runError: String?
    public var isRunning = false

    // MARK: - Services

    private var runner: any CommandRunning {
        injectedRunner ?? PrivilegedRunner(dryRun: dryRun, log: diagnosticLog)
    }

    /// Plain-language description of every change, for the dry-run walkthrough.
    public var changePlan: ChangePlan {
        ChangePlan(
            mode: mode,
            backend: dnsBackend,
            blockedSites: effectiveBlockedSites,
            installWARP: installWARP,
            youTubeLevel: youTubeLevel,
            forceSafeSearch: forceSafeSearch,
            installAdBlocker: installAdBlocker,
            blockThirdPartyCookies: blockThirdPartyCookies,
            educationalBookmarks: educationalBookmarks,
            createAccount: mode == .advanced && createAccount,
            accountUsername: accountUsername.trimmingCharacters(in: .whitespaces)
        )
    }

    /// Existing local account names, so we don't offer to create a duplicate.
    private(set) var existingUsernames: Set<String> = []

    public func runPreflight() async {
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

    public var preflightBlocks: Bool {
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
    public var plannedSteps: [HardeningStep] {
        hardening.steps(for: mode)
    }

    // MARK: - Diagnostics

    /// Records what was run and on what, so a log read later stands alone.
    private func logRunHeader() {
        guard let diagnosticLog else { return }
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let app = ReleaseVersion.current().map(String.init(describing:)) ?? "unknown"

        diagnosticLog.section("Family Safety run")
        diagnosticLog.log("app version: \(app)")
        diagnosticLog.log("macOS: \(os.majorVersion).\(os.minorVersion).\(os.patchVersion)")
        diagnosticLog.log("mode: \(mode.rawValue)")
        diagnosticLog.log("preview (dry run): \(dryRun)")
        diagnosticLog.log("blocked sites: \(effectiveBlockedSites.count)")
        diagnosticLog.log("install WARP: \(installWARP)")
        diagnosticLog.log("create account: \(createAccount)")
    }

    // MARK: - Updates

    /// Looks for a newer release. Silent on every failure; see `UpdateChecker`.
    ///
    /// Skipped in preview mode, which exists to show what would happen without
    /// the app reaching out to anything.
    public func checkForUpdate(using checker: UpdateChecker = UpdateChecker()) async {
        guard !dryRun else { return }
        let found = await checker.checkForUpdate()
        availableUpdate = found
        if let found {
            diagnosticLog?.log("update available: \(found.version)")
        }
    }

    // MARK: - Apply

    public func apply() async {
        isRunning = true
        runError = nil
        stepResults = []
        defer { isRunning = false }

        // The username is only known now, so the redactor has to be told
        // before any privileged step can put it in the log.
        diagnosticLog?.redactor.accountUsername = accountUsername
        logRunHeader()

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
            installAdBlocker: installAdBlocker,
            blockThirdPartyCookies: blockThirdPartyCookies,
            educationalBookmarks: educationalBookmarks
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
            let existing = await WARPInstaller(runner: runner, fileSystem: fileSystem, downloader: downloader).installedVersionAsync()
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
        let directory = fileSystem.downloadsDirectory
        let url = directory.appendingPathComponent("Family-Safety.mobileconfig")
        try data.write(to: url)
        return url
    }

    private func installWARPClient() async {
        let installer = WARPInstaller(runner: runner, fileSystem: fileSystem, downloader: downloader)
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
            let package = try await installer.fetch { [weak self] fraction in
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

    public var revertResults: [RevertResult] = []
    public var detectedChanges: [String] = []
    public var isReverting = false

    public var revertPlan: [String] { Reverter(runner: runner, fileSystem: fileSystem).plan() }
    public var revertWillNotUndo: [String] { Reverter(runner: runner, fileSystem: fileSystem).willNotUndo() }

    /// Look for evidence this tool has been run, so the confirmation screen can
    /// say what is actually present rather than guessing.
    public func detectExistingChanges() async {
        detectedChanges = await Reverter(runner: runner, fileSystem: fileSystem).detectApplied()
    }

    public func revertEverything() async {
        isReverting = true
        defer { isReverting = false }
        // Never honour dry-run here: reverting is the safe direction, and a
        // silent no-op would leave someone believing they had undone it.
        let reverter = Reverter(runner: injectedRunner ?? PrivilegedRunner(dryRun: false, log: diagnosticLog),
                                fileSystem: fileSystem)
        revertResults = await reverter.revertAll()
        detectedChanges = await reverter.detectApplied()
        stage = .revertResults
    }

    /// Whether verification re-runs on its own.
    ///
    /// On by default on the results screen: the remaining steps are manual and
    /// happen in System Settings, so the parent would otherwise have to keep
    /// coming back and pressing a button to find out whether what they just
    /// did worked.
    public var continuousVerification = true
    /// Set while a re-check is in flight, so the UI can show it without
    /// clearing the previous results.
    public var isVerifying = false
    public var lastVerifiedAt: Date?

    /// True once no check is failing.
    public var everythingVerified: Bool {
        !verifications.isEmpty && !verifications.contains { $0.outcome == .notWorking }
    }

    public var verificationsOutstanding: Int {
        verifications.filter { $0.outcome == .notWorking }.count
    }

    /// Re-runs verification on an interval until nothing is failing.
    ///
    /// Stops once everything passes, so a finished setup does not keep
    /// shelling out to `dig` and `defaults` indefinitely.
    public func startContinuousVerification() async {
        guard !dryRun else { return }
        while continuousVerification, !Task.isCancelled {
            await runVerification()
            if everythingVerified { break }
            // Long enough not to hammer the resolver, short enough that
            // flipping a switch in System Settings shows up quickly.
            try? await Task.sleep(for: .seconds(5))
        }
    }

    public func runVerification() async {
        // Pointless after a dry run — nothing was applied, so every check would
        // report "not working" and read as a failure rather than a no-op.
        guard !dryRun else {
            verifications = []
            return
        }
        isVerifying = true
        defer {
            isVerifying = false
            lastVerifiedAt = Date()
        }
        verifications = await Verifier(runner: runner, fileSystem: fileSystem, resolver: resolver)
            .runAllAsync(backend: dnsBackend, blockedSites: effectiveBlockedSites)
    }
}
