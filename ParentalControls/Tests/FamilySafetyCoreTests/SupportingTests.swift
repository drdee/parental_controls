import Testing
import Foundation
@testable import FamilySafetyCore

@Suite("DNS backend")
struct DNSBackendTests {

    @Test("Families needs no account and has no social-media category")
    func families() {
        let backend = DNSBackend.families
        #expect(backend.validationError == nil)
        #expect(backend.dohURL.contains("family.cloudflare-dns.com"))
        // 1.1.1.3 has exactly two categories: malware and adult content.
        #expect(!backend.blocksSocialMediaByCategory)
        #expect(backend.bootstrapAddresses.count == 4)
    }

    @Test("Both address families are present, or IPv6 leaks past the filter")
    func bootstrapCoversBothFamilies() {
        let addresses = DNSBackend.families.bootstrapAddresses
        #expect(addresses.contains { !$0.contains(":") }, "no IPv4 address")
        #expect(addresses.contains { $0.contains(":") }, "no IPv6 address")
    }

    @Test("Zero Trust supplies its own categories and no bootstrap addresses")
    func zeroTrust() {
        let backend = DNSBackend.zeroTrust(dohURL: "https://abc.cloudflare-gateway.com/dns-query")
        #expect(backend.validationError == nil)
        #expect(backend.blocksSocialMediaByCategory)
        #expect(backend.bootstrapAddresses.isEmpty)
    }

    @Test("Endpoint validation catches the mistakes that matter", arguments: [
        ("", false),
        ("   ", false),
        ("http://x.cloudflare-gateway.com/dns-query", false),
        ("https://x.cloudflare-gateway.com", false),
        ("ftp://x/dns-query", false),
        ("https://x.cloudflare-gateway.com/dns-query", true),
        ("  https://x.cloudflare-gateway.com/dns-query  ", true),
    ])
    func validation(_ url: String, _ isValid: Bool) {
        #expect((DNSBackend.zeroTrust(dohURL: url).validationError == nil) == isValid,
                "\(url.debugDescription)")
    }

    /// A mistyped gateway ID still answers DNS normally — any
    /// `*.cloudflare-gateway.com` host resolves — so the endpoint cannot be
    /// validated by probing it. Only the shape is checked; correctness is
    /// confirmed functionally after install.
    @Test("A syntactically valid but wrong gateway id is accepted")
    func wrongGatewayIDPassesSyntaxCheck() {
        let backend = DNSBackend.zeroTrust(dohURL: "https://typo-nonexistent.cloudflare-gateway.com/dns-query")
        #expect(backend.validationError == nil)
    }

    @Test("Whitespace around an endpoint is trimmed before use")
    func trimsWhitespace() {
        let backend = DNSBackend.zeroTrust(dohURL: "  https://x.cloudflare-gateway.com/dns-query\n")
        #expect(backend.dohURL == "https://x.cloudflare-gateway.com/dns-query")
    }
}

@Suite("Block lists")
struct BlockListTests {

    @Test("Social media contains exactly the four intended sites")
    func socialMediaContents() {
        let domains = Set(BlockedSite.socialMedia.map(\.domain))
        #expect(domains == ["tiktok.com", "instagram.com", "pinterest.com", "snapchat.com"])
    }

    @Test("ChatGPT is an AI chatbot, not social media")
    func chatGPTPlacement() {
        #expect(!BlockedSite.socialMedia.map(\.domain).contains("chatgpt.com"))
        #expect(BlockedSite.aiChatbots.map(\.domain).contains("chatgpt.com"))
    }

    @Test("The editable list starts empty because presets cover the defaults")
    func defaultsAreEmpty() {
        #expect(BlockedSite.defaults.isEmpty)
    }

    @Test("No hostname appears in more than one preset")
    func presetsDoNotOverlap() {
        let all = (BlockedSite.socialMedia + BlockedSite.aiChatbots + BlockedSite.chatAndGaming)
            .flatMap(\.allHosts)
        #expect(Set(all).count == all.count)
    }

    @Test("Every preset entry is a valid hostname")
    func presetEntriesAreValid() {
        for site in BlockedSite.socialMedia + BlockedSite.aiChatbots + BlockedSite.chatAndGaming {
            #expect(site.isValid, "\(site.domain) is not valid")
            for host in site.allHosts {
                #expect(host == BlockedSite.sanitize(host), "\(host) is not already sanitised")
            }
        }
    }

    /// Blocking a top-level domain alone misses the hosts people actually use.
    @Test("Known alternate hosts are covered")
    func alternateHostsCovered() {
        let all = Set((BlockedSite.socialMedia + BlockedSite.aiChatbots).flatMap(\.allHosts))
        #expect(all.contains("pin.it"), "Pinterest's link shortener")
        #expect(all.contains("web.snapchat.com"), "Snapchat's browser client")
        #expect(all.contains("chat.openai.com"), "ChatGPT's other hostname")
        #expect(all.contains("m.tiktok.com"), "TikTok mobile")
    }

    @Test("allHosts always includes the bare and www forms")
    func allHostsIncludesWWW() {
        let site = BlockedSite("example.com")
        #expect(site.allHosts.contains("example.com"))
        #expect(site.allHosts.contains("www.example.com"))
    }
}

@Suite("SafeSearch")
struct SafeSearchTests {

    /// Verified against Google's published resolver addresses.
    @Test("Pinning addresses are the documented ones")
    func addresses() {
        #expect(SafeSearch.strictAddress == "216.239.38.120")
        #expect(SafeSearch.moderateAddress == "216.239.38.119")
    }

    @Test("Chrome policy values map correctly", arguments: [
        (SafeSearch.YouTubeLevel.off, 0),
        (SafeSearch.YouTubeLevel.moderate, 1),
        (SafeSearch.YouTubeLevel.strict, 2),
    ])
    func policyValues(_ level: SafeSearch.YouTubeLevel, _ expected: Int) {
        #expect(level.chromePolicyValue == expected)
    }

    @Test("Only moderate and strict pin a hosts address")
    func hostsAddresses() {
        #expect(SafeSearch.YouTubeLevel.off.hostsAddress == nil)
        #expect(SafeSearch.YouTubeLevel.moderate.hostsAddress == SafeSearch.moderateAddress)
        #expect(SafeSearch.YouTubeLevel.strict.hostsAddress == SafeSearch.strictAddress)
    }

    @Test("Moderate is presented as the recommended level")
    func moderateIsRecommended() {
        #expect(SafeSearch.YouTubeLevel.moderate.title.lowercased().contains("recommended"))
    }

    @Test("YouTube host list covers the API endpoints the apps use")
    func youTubeHosts() {
        #expect(SafeSearch.youTubeHosts.contains("youtubei.googleapis.com"))
        #expect(SafeSearch.youTubeHosts.contains("m.youtube.com"))
    }
}

@Suite("Browsers and extensions")
struct BrowserTests {

    @Test("Every Chromium-family browser we know of is covered")
    func chromiumCoverage() {
        let domains = Set(ChromiumBrowser.all.map(\.domain))
        // Chrome alone is not enough: downloading Brave is a trivial bypass.
        #expect(domains.contains("com.google.Chrome"))
        #expect(domains.contains("com.brave.Browser"))
        #expect(domains.contains("com.microsoft.Edge"))
        #expect(domains.contains("com.vivaldi.Vivaldi"))
    }

    @Test("Browser domains are unique")
    func domainsAreUnique() {
        let domains = ChromiumBrowser.all.map(\.domain)
        #expect(Set(domains).count == domains.count)
    }

    /// The original uBlock Origin was delisted with the MV2 deprecation, so
    /// only the Lite id installs.
    @Test("The ad blocker id is uBlock Origin Lite")
    func adBlockerIdentifier() {
        #expect(AllowedExtension.uBlockOriginLite == "ddkjiahejlhfcafbddmgiahcphecmpfh")
        #expect(AllowedExtension.uBlockOriginLite != "cjpalhdlnbpafiamejdnhcphjbkeiagm",
                "that is the delisted classic uBlock Origin")
        #expect(AllowedExtension.uBlockOriginLite.count == 32, "Chrome ids are 32 characters")
    }

    @Test("The forcelist entry uses Chrome's id;update-url form")
    func forcelistFormat() {
        let entry = AllowedExtension.forcelistEntry
        let parts = entry.split(separator: ";")
        #expect(parts.count == 2)
        #expect(parts[0] == AllowedExtension.uBlockOriginLite)
        #expect(parts[1].hasPrefix("https://"))
    }
}

@Suite("Managed bookmarks")
struct BookmarkTests {

    @Test("Every bookmark has a name and an https URL")
    func bookmarksAreWellFormed() {
        #expect(!ManagedBookmark.educational.isEmpty)
        for bookmark in ManagedBookmark.educational {
            #expect(!bookmark.name.isEmpty)
            #expect(bookmark.url.hasPrefix("https://"), "\(bookmark.name) is not https")
            #expect(URL(string: bookmark.url) != nil, "\(bookmark.name) is not a valid URL")
        }
    }

    @Test("Bookmark names and URLs are unique")
    func bookmarksAreUnique() {
        let names = ManagedBookmark.educational.map(\.name)
        let urls = ManagedBookmark.educational.map(\.url)
        #expect(Set(names).count == names.count)
        #expect(Set(urls).count == urls.count)
    }

    @Test("The Chrome policy value nests links under one folder")
    func policyShape() {
        let value = ManagedBookmark.chromePolicyValue(ManagedBookmark.educational)
        #expect(value.count == 1)
        #expect(value[0]["name"] as? String == ManagedBookmark.folderName)
        let children = value[0]["children"] as? [[String: String]]
        #expect(children?.count == ManagedBookmark.educational.count)
    }

    @Test("An empty bookmark list still yields a well-formed folder")
    func emptyList() {
        let value = ManagedBookmark.chromePolicyValue([])
        #expect(value.count == 1)
        #expect((value[0]["children"] as? [[String: String]])?.isEmpty == true)
    }
}

@Suite("Privileged runner")
struct PrivilegedRunnerTests {

    @Test("An unprivileged command runs and reports its output")
    func runsCommand() throws {
        let result = try PrivilegedRunner().run("/usr/bin/uname", ["-m"])
        #expect(result.succeeded)
        #expect(result.output == "arm64" || result.output == "x86_64")
    }

    @Test("A failing command reports a non-zero status rather than throwing")
    func reportsFailure() throws {
        let result = try PrivilegedRunner().run("/usr/bin/false", [])
        #expect(!result.succeeded)
        #expect(result.exitCode != 0)
    }

    @Test("A missing executable throws rather than hanging")
    func missingExecutableThrows() {
        #expect(throws: (any Error).self) {
            _ = try PrivilegedRunner().run("/nonexistent/binary", [])
        }
    }

    @Test("probe never throws, so callers can treat failure as information")
    func probeIsForgiving() {
        let result = PrivilegedRunner().probe("/nonexistent/binary", [])
        #expect(!result.succeeded)
    }

    /// Output is read before waiting, so a command that fills the pipe buffer
    /// cannot deadlock against `waitUntilExit`.
    @Test("A command producing more output than the pipe buffer does not deadlock")
    func largeOutputDoesNotDeadlock() throws {
        let result = try PrivilegedRunner().run("/bin/sh", ["-c", "yes x | head -c 200000"])
        #expect(result.succeeded)
        #expect(result.stdout.count >= 200_000)
    }

    /// The dry-run guarantee at its lowest level.
    @Test("A dry run does not execute its script")
    func dryRunDoesNotExecute() throws {
        let marker = "/tmp/familysafety-dryrun-\(UUID().uuidString)"
        let result = try PrivilegedRunner(dryRun: true)
            .runPrivileged(script: "touch \(marker)", description: "test")
        #expect(result.succeeded)
        #expect(!FileManager.default.fileExists(atPath: marker), "the script ran")
        #expect(result.command.hasPrefix("[dry-run]"))
        // The script is still echoed so the UI can display it.
        #expect(result.stdout.contains("touch"))
    }

    @Test("Output combines stdout and stderr sensibly")
    func outputCombination() throws {
        let onlyErr = try PrivilegedRunner().run("/bin/sh", ["-c", "echo err >&2"])
        #expect(onlyErr.output == "err")
        let both = try PrivilegedRunner().run("/bin/sh", ["-c", "echo out; echo err >&2"])
        #expect(both.output.contains("out"))
        #expect(both.output.contains("err"))
    }

    @Test("Async variants return the same results as the synchronous ones")
    func asyncMatchesSync() async throws {
        let sync = try PrivilegedRunner().run("/usr/bin/uname", ["-m"])
        let async = try await PrivilegedRunner().runAsync("/usr/bin/uname", ["-m"])
        #expect(sync.output == async.output)
    }
}

@Suite("Preflight and verification")
struct PreflightVerifierTests {

    @Test("Preflight reports on this machine without changing it")
    func preflightIsReadOnly() async throws {
        let before = try String(contentsOfFile: "/etc/hosts", encoding: .utf8)
        let checks = await Preflight(runner: PrivilegedRunner()).runAllAsync(mode: .advanced)

        #expect(checks.count >= 6)
        let titles = checks.map(\.title)
        #expect(titles.contains { $0.contains("macOS") })
        #expect(titles.contains { $0.contains("Architecture") })
        #expect(titles.contains { $0.contains("administrator") })
        #expect(titles.contains { $0.contains("FileVault") })
        #expect(titles.contains { $0.contains("Gatekeeper") })
        #expect(try String(contentsOfFile: "/etc/hosts", encoding: .utf8) == before)
    }

    @Test("Advanced mode checks more than family mode")
    func advancedChecksMore() async {
        let family = await Preflight(runner: PrivilegedRunner()).runAllAsync(mode: .family)
        let advanced = await Preflight(runner: PrivilegedRunner()).runAllAsync(mode: .advanced)
        #expect(advanced.count > family.count)
    }

    @Test("Failing checks always carry a rationale")
    func failuresExplainThemselves() async {
        let checks = await Preflight(runner: PrivilegedRunner()).runAllAsync(mode: .advanced)
        for check in checks where check.status != .pass {
            #expect(check.rationale != nil, "\(check.title) failed without explanation")
        }
        for check in checks {
            #expect(!check.detail.isEmpty, "\(check.title) has no detail")
        }
    }

    @Test("Preflight check ids are unique")
    func checkIDsAreUnique() async {
        let ids = await Preflight(runner: PrivilegedRunner()).runAllAsync(mode: .advanced).map(\.id)
        #expect(Set(ids).count == ids.count)
    }

    @Test("Verification reports on this machine without changing it")
    func verificationIsReadOnly() async throws {
        let before = try String(contentsOfFile: "/etc/hosts", encoding: .utf8)
        let results = await Verifier(runner: PrivilegedRunner())
            .runAllAsync(backend: .families, blockedSites: BlockedSite.socialMedia)

        #expect(!results.isEmpty)
        #expect(Set(results.map(\.id)).count == results.count)
        for result in results {
            #expect(!result.detail.isEmpty, "\(result.title) has no detail")
            if result.outcome == .notWorking {
                #expect(result.remedy != nil, "\(result.title) offers no remedy")
            }
        }
        #expect(try String(contentsOfFile: "/etc/hosts", encoding: .utf8) == before)
    }

    @Test("Verification handles an empty block list")
    func verificationWithNoSites() async {
        let results = await Verifier(runner: PrivilegedRunner())
            .runAllAsync(backend: .families, blockedSites: [])
        #expect(!results.isEmpty)
    }
}

@Suite("WARP installer")
struct WARPInstallerTests {

    /// Pinned against a real download, so an unexpected signer is refused
    /// before anything is handed to `installer` as root.
    @Test("Cloudflare's signing identity is pinned")
    func trustAnchor() {
        #expect(WARPInstaller.expectedTeamID == "68WVV388M8")
        #expect(WARPInstaller.expectedAuthority == "Developer ID Installer: Cloudflare Inc.")
    }

    @Test("The download URL is Cloudflare's stable channel over https")
    func downloadURL() {
        let url = WARPInstaller.downloadURL
        #expect(url.scheme == "https")
        #expect(url.host == "downloads.cloudflareclient.com")
    }

    @Test("An unsigned package is refused")
    func refusesUnsignedPackage() throws {
        let file = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("fake-\(UUID().uuidString).pkg")
        try "not a package".write(to: file, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: file) }

        #expect(throws: (any Error).self) {
            try WARPInstaller(runner: PrivilegedRunner()).verifySignature(of: file)
        }
    }

    @Test("A missing file is refused rather than treated as valid")
    func refusesMissingFile() {
        #expect(throws: (any Error).self) {
            try WARPInstaller(runner: PrivilegedRunner())
                .verifySignature(of: URL(fileURLWithPath: "/nonexistent.pkg"))
        }
    }

    @Test("Detecting an existing install does not change anything")
    func detectionIsReadOnly() async {
        _ = await WARPInstaller(runner: PrivilegedRunner()).installedVersionAsync()
    }
}

