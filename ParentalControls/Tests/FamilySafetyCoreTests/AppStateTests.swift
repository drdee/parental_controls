import Testing
import Foundation
@testable import FamilySafetyCore

/// Orchestration and validation. This is where the dry-run guarantee and the
/// preset composition live, so a regression here is user-visible or unsafe.
@MainActor
@Suite("App state")
struct AppStateTests {

    // MARK: - Defaults

    @Test("Defaults are the intended safe starting point")
    func defaults() {
        let state = AppState()
        #expect(state.stage == .chooseMode)
        #expect(state.mode == .family, "family mode is the safe default")
        #expect(state.dryRun == false)
        #expect(state.blockSocialMedia)
        #expect(state.blockAIChatbots)
        #expect(state.blockChatAndGaming == false, "chat and gaming is opt-in")
        #expect(state.forceSafeSearch)
        #expect(state.youTubeLevel == .moderate, "strict hides legitimate content")
        #expect(state.installAdBlocker)
        #expect(state.blockThirdPartyCookies)
        #expect(state.educationalBookmarks)
        #expect(state.createAccount == false, "account creation is opt-in")
        #expect(state.useZeroTrust == false)
        #expect(state.installWARP == false)
    }

    // MARK: - Preset composition

    @Test("Enabled presets compose into the effective block list")
    func presetComposition() {
        let state = AppState()
        state.blockSocialMedia = true
        state.blockAIChatbots = true
        state.blockChatAndGaming = false

        let domains = Set(state.effectiveBlockedSites.map(\.domain))
        #expect(domains.contains("tiktok.com"))
        #expect(domains.contains("chatgpt.com"))
        #expect(!domains.contains("discord.com"))
    }

    @Test("Each preset can be toggled independently")
    func presetsToggleIndependently() {
        let state = AppState()

        state.blockSocialMedia = false
        state.blockAIChatbots = false
        state.blockChatAndGaming = false
        #expect(state.effectiveBlockedSites.isEmpty)

        state.blockChatAndGaming = true
        let domains = Set(state.effectiveBlockedSites.map(\.domain))
        #expect(domains.contains("discord.com"))
        #expect(!domains.contains("tiktok.com"))
    }

    @Test("ChatGPT is grouped with AI chatbots, not social media")
    func chatGPTCategorisation() {
        let state = AppState()
        state.blockSocialMedia = true
        state.blockAIChatbots = false
        #expect(!state.effectiveBlockedSites.map(\.domain).contains("chatgpt.com"))

        state.blockSocialMedia = false
        state.blockAIChatbots = true
        #expect(state.effectiveBlockedSites.map(\.domain).contains("chatgpt.com"))
    }

    @Test("Manually added sites are additive to the presets")
    func manualSitesAreAdditive() {
        let state = AppState()
        state.blockedSites = [BlockedSite("example.com")]
        let domains = Set(state.effectiveBlockedSites.map(\.domain))
        #expect(domains.contains("example.com"))
        #expect(domains.contains("tiktok.com"), "presets still apply")
    }

    // MARK: - Validation

    @Test("A default configuration is valid")
    func defaultConfigurationIsValid() {
        #expect(AppState().configurationError == nil)
    }

    @Test("Blocking nothing at all is rejected")
    func emptyConfigurationIsRejected() {
        let state = AppState()
        state.blockSocialMedia = false
        state.blockAIChatbots = false
        state.blockChatAndGaming = false
        state.blockedSites = []
        state.useZeroTrust = false
        #expect(state.configurationError != nil)
    }

    /// Zero Trust supplies its own categories, so an empty local list is fine.
    @Test("Zero Trust alone is a valid configuration")
    func zeroTrustWithoutLocalListIsValid() {
        let state = AppState()
        state.blockSocialMedia = false
        state.blockAIChatbots = false
        state.blockChatAndGaming = false
        state.blockedSites = []
        state.useZeroTrust = true
        state.zeroTrustURL = "https://abc.cloudflare-gateway.com/dns-query"
        #expect(state.configurationError == nil)
    }

    @Test("Malformed Zero Trust endpoints are rejected", arguments: [
        "",
        "   ",
        "http://x.cloudflare-gateway.com/dns-query",   // not https
        "https://x.cloudflare-gateway.com",            // no /dns-query
        "not a url",
    ])
    func rejectsBadZeroTrustURLs(_ url: String) {
        let state = AppState()
        state.useZeroTrust = true
        state.zeroTrustURL = url
        #expect(state.configurationError != nil, "\(url.debugDescription) should be rejected")
    }

    @Test("A well-formed Zero Trust endpoint is accepted")
    func acceptsGoodZeroTrustURL() {
        let state = AppState()
        state.useZeroTrust = true
        state.zeroTrustURL = "https://abc123.cloudflare-gateway.com/dns-query"
        #expect(state.configurationError == nil)
        #expect(state.dnsBackend.blocksSocialMediaByCategory)
    }

    @Test("Account short names are validated with the same rule as the script", arguments: [
        ("sophie", true),
        ("", false),
        ("has space", false),
        ("root", false),
        ("kid\nrm -rf /", false),
        ("1digit", false),
    ])
    func validatesAccountNames(_ name: String, _ shouldBeValid: Bool) {
        let state = AppState()
        state.mode = .advanced
        state.createAccount = true
        state.accountUsername = name
        #expect((state.configurationError == nil) == shouldBeValid, "\(name.debugDescription)")
    }

    @Test("Account name validation is skipped when not creating an account")
    func accountValidationOnlyWhenCreating() {
        let state = AppState()
        state.mode = .advanced
        state.createAccount = false
        state.accountUsername = "!!invalid!!"
        #expect(state.configurationError == nil)
    }

    // MARK: - DNS backend

    @Test("The DNS backend follows the Zero Trust toggle")
    func dnsBackendSelection() {
        let state = AppState()
        #expect(state.dnsBackend == .families)
        #expect(!state.dnsBackend.blocksSocialMediaByCategory)

        state.useZeroTrust = true
        state.zeroTrustURL = "https://x.cloudflare-gateway.com/dns-query"
        #expect(state.dnsBackend.blocksSocialMediaByCategory)
    }

    // MARK: - Planned steps

    @Test("Planned steps reflect the selected mode")
    func plannedStepsFollowMode() {
        let state = AppState()
        state.mode = .family
        let family = state.plannedSteps.count
        state.mode = .advanced
        #expect(state.plannedSteps.count > family)
    }

    @Test("Planned steps reflect the current block list")
    func plannedStepsReflectBlockList() {
        let state = AppState()
        state.blockSocialMedia = true
        state.blockAIChatbots = false
        let command = state.plannedSteps.map(\.command).joined()
        #expect(command.contains("tiktok.com"))
        #expect(!command.contains("claude.ai"))
    }

    // MARK: - Change plan

    @Test("The change plan covers every enabled option")
    func changePlanCoversOptions() {
        let state = AppState()
        state.mode = .advanced
        state.createAccount = true
        state.accountUsername = "sophie"
        state.installWARP = true

        let titles = state.changePlan.descriptions().map(\.title)
        #expect(titles.contains { $0.contains("filtering service") })
        #expect(titles.contains { $0.contains("configuration profile") })
        #expect(titles.contains { $0.contains("block list") })
        #expect(titles.contains { $0.contains("safe search") })
        #expect(titles.contains { $0.contains("ad blocker") })
        #expect(titles.contains { $0.contains("cookies") })
        #expect(titles.contains { $0.contains("bookmarks") })
        #expect(titles.contains { $0.contains("WARP") })
        #expect(titles.contains { $0.contains("sophie") })
    }

    /// The reason Family Mode is safe to share: nothing in its plan is
    /// classified as touching accounts or startup.
    @Test("Family Mode's plan contains no sensitive changes")
    func familyModePlanHasNoSensitiveChanges() {
        let state = AppState()
        state.mode = .family
        state.installWARP = true
        let plan = state.changePlan
        #expect(!plan.descriptions().contains { $0.impact == .sensitive })
        #expect(plan.summaryLine.contains("None of them"))
    }

    @Test("Advanced Mode flags account creation as sensitive")
    func advancedModeFlagsAccountCreation() {
        let state = AppState()
        state.mode = .advanced
        state.createAccount = true
        state.accountUsername = "sophie"
        let sensitive = state.changePlan.descriptions().filter { $0.impact == .sensitive }
        #expect(sensitive.count == 1)
        #expect(sensitive[0].title.contains("sophie"))
    }

    @Test("Every change description is complete and jargon-free")
    func changeDescriptionsAreComplete() {
        for mode in [RunMode.family, .advanced] {
            let state = AppState()
            state.mode = mode
            state.createAccount = mode == .advanced
            state.accountUsername = "sophie"
            state.installWARP = true

            for change in state.changePlan.descriptions() {
                #expect(!change.title.isEmpty)
                #expect(!change.whatChanges.isEmpty, "\(change.title)")
                #expect(!change.whatTheyWillNotice.isEmpty, "\(change.title)")
                #expect(!change.howToUndo.isEmpty, "\(change.title)")
                // Shell commands must not leak into copy aimed at a parent.
                for jargon in ["/usr/bin", "/usr/sbin", "sudo ", "&&", "|", "$(" ] {
                    #expect(!change.whatChanges.contains(jargon),
                            "\(change.title) leaks \(jargon.debugDescription)")
                }
            }
        }
    }

    @Test("Change description ids are unique for every configuration")
    func changeDescriptionIDsAreUnique() {
        for warp in [true, false] {
            for account in [true, false] {
                for mode in [RunMode.family, .advanced] {
                    let state = AppState()
                    state.mode = mode
                    state.installWARP = warp
                    state.createAccount = account
                    state.accountUsername = "sophie"
                    let ids = state.changePlan.descriptions().map(\.id)
                    #expect(Set(ids).count == ids.count,
                            "duplicate id (mode=\(mode) warp=\(warp) account=\(account))")
                }
            }
        }
    }

    // MARK: - Dry run

    /// The dry-run guarantee: walking the whole flow must not write anything.
    @Test("A dry run changes nothing on disk")
    func dryRunWritesNothing() async throws {
        let state = AppState()
        state.dryRun = true
        state.mode = .family

        let downloads = FileManager.default
            .urls(for: .downloadsDirectory, in: .userDomainMask).first!
            .appendingPathComponent("Family-Safety.mobileconfig")
        let existedBefore = FileManager.default.fileExists(atPath: downloads.path)
        let hostsBefore = try String(contentsOfFile: "/etc/hosts", encoding: .utf8)

        await state.apply()

        #expect(state.stage == .results)
        #expect(state.generatedProfileURL == nil, "a dry run must not write the profile")
        #expect(FileManager.default.fileExists(atPath: downloads.path) == existedBefore)
        #expect(try String(contentsOfFile: "/etc/hosts", encoding: .utf8) == hostsBefore)
    }

    @Test("A dry run still reports every step it would take")
    func dryRunReportsSteps() async {
        let state = AppState()
        state.dryRun = true
        state.mode = .advanced
        state.createAccount = true
        state.accountUsername = "sophie"
        state.installWARP = true

        await state.apply()

        #expect(!state.stepResults.isEmpty)
        let allSucceeded = state.stepResults.allSatisfy { $0.succeeded }
        #expect(allSucceeded)
        // Each result must make clear nothing actually happened.
        let details = state.stepResults.map(\.detail).joined(separator: " ").lowercased()
        #expect(details.contains("would") || details.contains("nothing"))
        #expect(state.stepResults.contains { $0.title.contains("sophie") })
    }

    /// Verification after a dry run would report "not working" for everything
    /// and read as failure rather than a no-op.
    @Test("Verification is skipped after a dry run")
    func dryRunSkipsVerification() async {
        let state = AppState()
        state.dryRun = true
        await state.runVerification()
        #expect(state.verifications.isEmpty)
    }

    @Test("Step result ids stay unique so the results list renders correctly")
    func stepResultIDsAreUnique() async {
        let state = AppState()
        state.dryRun = true
        state.mode = .advanced
        state.createAccount = true
        state.accountUsername = "sophie"
        state.installWARP = true
        await state.apply()
        let ids = state.stepResults.map(\.id)
        #expect(Set(ids).count == ids.count)
    }

    // MARK: - Preflight

    @Test("Preflight inspects the real machine without changing it")
    func preflightRuns() async throws {
        let state = AppState()
        let hostsBefore = try String(contentsOfFile: "/etc/hosts", encoding: .utf8)

        await state.runPreflight()

        #expect(!state.preflightChecks.isEmpty)
        #expect(state.preflightChecks.contains { $0.title.contains("macOS") })
        #expect(state.preflightChecks.contains { $0.title.contains("FileVault") })
        // It should have found this machine's own accounts.
        #expect(!state.existingUsernames.isEmpty)
        #expect(state.existingUsernames.contains("root"))
        #expect(try String(contentsOfFile: "/etc/hosts", encoding: .utf8) == hostsBefore)
    }

    @Test("An existing account name is rejected")
    func rejectsExistingAccountName() async {
        let state = AppState()
        await state.runPreflight()
        state.mode = .advanced
        state.createAccount = true
        state.accountUsername = "root"
        #expect(state.configurationError != nil)
    }

    // MARK: - Revert

    @Test("The revert plan is described and its limits disclosed")
    func revertPlanIsHonest() {
        let state = AppState()
        #expect(!state.revertPlan.isEmpty)
        #expect(state.revertWillNotUndo.count >= 3)
        let disclosure = state.revertWillNotUndo.joined(separator: " ").lowercased()
        // Deleting an account would destroy a home folder, so we do not.
        #expect(disclosure.contains("account"))
        #expect(disclosure.contains("warp"))
        #expect(disclosure.contains("screen time"))
    }

    @Test("Detecting existing changes does not modify anything")
    func detectionIsReadOnly() async throws {
        let state = AppState()
        let hostsBefore = try String(contentsOfFile: "/etc/hosts", encoding: .utf8)
        await state.detectExistingChanges()
        #expect(try String(contentsOfFile: "/etc/hosts", encoding: .utf8) == hostsBefore)
    }
}
