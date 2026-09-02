import Testing
import Foundation
@testable import FamilySafetyCore

/// The configuration profile is the app's central artifact. Most of its keys
/// fail *silently* when wrong — a malformed payload installs and does nothing —
/// so these assertions check structure and exact key values rather than just
/// that generation succeeded.
@Suite("Profile generation")
struct ProfileGeneratorTests {

    /// Parses a generated profile into a payload-type-keyed dictionary.
    private func payloads(
        _ generator: ProfileGenerator
    ) throws -> (root: [String: Any], byType: [String: [String: Any]]) {
        let data = try generator.xmlData()
        let root = try PropertyListSerialization.propertyList(from: data, format: nil) as! [String: Any]
        let list = root["PayloadContent"] as! [[String: Any]]
        var byType: [String: [String: Any]] = [:]
        for payload in list {
            byType[payload["PayloadType"] as! String] = payload
        }
        return (root, byType)
    }

    private var standardSites: [BlockedSite] {
        BlockedSite.socialMedia + BlockedSite.aiChatbots
    }

    // MARK: - Structure

    @Test("Generated profile is a valid property list")
    func generatesValidPlist() throws {
        let data = try ProfileGenerator(blockedSites: standardSites).xmlData()
        #expect(throws: Never.self) {
            _ = try PropertyListSerialization.propertyList(from: data, format: nil)
        }
    }

    /// The DNS payload handler rejects user-scoped profiles outright:
    /// "Failed to install DNS proxy/settings profile - profile must be scoped
    /// to system". Getting this wrong disables DNS filtering silently.
    @Test("PayloadScope is System")
    func payloadScopeIsSystem() throws {
        let (root, _) = try payloads(ProfileGenerator(blockedSites: standardSites))
        #expect(root["PayloadScope"] as? String == "System")
    }

    @Test("Root payload carries the required top-level keys")
    func rootKeysPresent() throws {
        let (root, _) = try payloads(ProfileGenerator(blockedSites: standardSites))
        #expect(root["PayloadType"] as? String == "Configuration")
        #expect(root["PayloadVersion"] as? Int == 1)
        #expect(root["PayloadIdentifier"] as? String == ProfileIdentity.prefix)
        #expect(root["PayloadDisplayName"] as? String == ProfileIdentity.displayName)
        #expect(root["PayloadRemovalDisallowed"] as? Bool == true)
        #expect((root["PayloadUUID"] as? String)?.isEmpty == false)
    }

    @Test("Every payload has a unique UUID and identifier")
    func payloadIdentityIsUnique() throws {
        let data = try ProfileGenerator(blockedSites: standardSites).xmlData()
        let root = try PropertyListSerialization.propertyList(from: data, format: nil) as! [String: Any]
        let list = root["PayloadContent"] as! [[String: Any]]

        let uuids = list.compactMap { $0["PayloadUUID"] as? String }
        let identifiers = list.compactMap { $0["PayloadIdentifier"] as? String }
        #expect(uuids.count == list.count)
        #expect(Set(uuids).count == uuids.count, "duplicate PayloadUUID")
        #expect(Set(identifiers).count == identifiers.count, "duplicate PayloadIdentifier")
    }

    @Test("Each generated profile gets fresh UUIDs")
    func uuidsAreFreshPerGeneration() throws {
        let generator = ProfileGenerator(blockedSites: standardSites)
        let (first, _) = try payloads(generator)
        let (second, _) = try payloads(generator)
        #expect(first["PayloadUUID"] as? String != second["PayloadUUID"] as? String)
    }

    // MARK: - DNS

    @Test("Families backend pins DoH with IPv4 and IPv6 bootstrap addresses")
    func familiesDNSPayload() throws {
        let (_, byType) = try payloads(ProfileGenerator(blockedSites: standardSites, dnsBackend: .families))
        let dns = byType["com.apple.dnsSettings.managed"]!
        let settings = dns["DNSSettings"] as! [String: Any]

        #expect(settings["DNSProtocol"] as? String == "HTTPS")
        #expect(settings["ServerURL"] as? String == "https://family.cloudflare-dns.com/dns-query")

        let addresses = settings["ServerAddresses"] as! [String]
        #expect(addresses.contains("1.1.1.3"))
        #expect(addresses.contains("1.0.0.3"))
        // IPv6 matters: a machine with IPv6 nameservers resolves around an
        // IPv4-only filter entirely.
        #expect(addresses.contains("2606:4700:4700::1113"))
        #expect(addresses.contains("2606:4700:4700::1003"))
    }

    /// Regression guard.
    ///
    /// `ProhibitDisablement` requires the profile to arrive over an MDM
    /// channel: the DNS payload validator checks `installedByMDM`, and on an
    /// un-enrolled Mac its presence fails the *entire* profile install with
    /// "unexpected error CPDomainPlugin:101". It is also advisory outside MDM,
    /// so it costs nothing to omit and everything to include.
    @Test("ProhibitDisablement is never emitted")
    func prohibitDisablementOmitted() throws {
        let (_, byType) = try payloads(ProfileGenerator(blockedSites: standardSites))
        let dns = byType["com.apple.dnsSettings.managed"]!
        #expect(dns["ProhibitDisablement"] == nil,
                "this key breaks profile installation on a Mac without MDM")
        #expect((dns["DNSSettings"] as! [String: Any])["ProhibitDisablement"] == nil)
    }

    /// Nothing in the profile may require MDM enrolment, or the install fails
    /// outright rather than degrading gracefully.
    @Test("No payload carries a key that requires MDM enrolment")
    func noMDMOnlyKeys() throws {
        let (_, byType) = try payloads(ProfileGenerator(blockedSites: standardSites))
        let mdmOnlyKeys = ["ProhibitDisablement", "PayloadRemovalDisallowedByMDM"]
        for (type, payload) in byType {
            for key in mdmOnlyKeys {
                #expect(payload[key] == nil, "\(type) sets \(key), which needs MDM")
            }
        }
    }

    /// Absent means "all domains". Adding it would *narrow* enforcement to
    /// only the listed domains — the opposite of what is wanted.
    @Test("SupplementalMatchDomains is omitted")
    func supplementalMatchDomainsOmitted() throws {
        let (_, byType) = try payloads(ProfileGenerator(blockedSites: standardSites))
        let settings = byType["com.apple.dnsSettings.managed"]!["DNSSettings"] as! [String: Any]
        #expect(settings["SupplementalMatchDomains"] == nil)
    }

    @Test("Zero Trust backend uses the given endpoint and omits bootstrap addresses")
    func zeroTrustDNSPayload() throws {
        let url = "https://abc123.cloudflare-gateway.com/dns-query"
        let (_, byType) = try payloads(
            ProfileGenerator(blockedSites: standardSites, dnsBackend: .zeroTrust(dohURL: url))
        )
        let settings = byType["com.apple.dnsSettings.managed"]!["DNSSettings"] as! [String: Any]
        #expect(settings["ServerURL"] as? String == url)
        // An empty array would be worse than omitting the key.
        #expect(settings["ServerAddresses"] == nil)
    }

    // MARK: - Restrictions

    @Test("Restriction keys that work unsupervised are set")
    func restrictionKeys() throws {
        let (_, byType) = try payloads(ProfileGenerator(blockedSites: standardSites))
        let access = byType["com.apple.applicationaccess"]!
        for key in [
            "allowCloudPrivateRelay",
            "allowSafariPrivateBrowsing",
            "allowSafariHistoryClearing",
            "allowLocalUserCreation",
            "allowStartupDiskModification",
            "allowAccountModification",
            "allowUIConfigurationProfileInstallation",
            "allowiPhoneMirroring",
        ] {
            #expect(access[key] as? Bool == false, "\(key) should be false")
        }
    }

    /// An iOS/supervised key that does nothing on macOS. App installation is
    /// actually controlled by `/Applications` ownership plus the user not
    /// being an admin.
    @Test("allowAppInstallation is not emitted")
    func appInstallationKeyAbsent() throws {
        let (_, byType) = try payloads(ProfileGenerator(blockedSites: standardSites))
        #expect(byType["com.apple.applicationaccess"]!["allowAppInstallation"] == nil)
    }

    @Test("AirDrop is not restricted")
    func airDropNotRestricted() throws {
        let (_, byType) = try payloads(ProfileGenerator(blockedSites: standardSites))
        #expect(byType["com.apple.applicationaccess"]!["allowAirDrop"] == nil)
    }

    @Test("Security updates stay enabled and major upgrades are deferred")
    func softwareUpdatePolicy() throws {
        let (_, byType) = try payloads(ProfileGenerator(blockedSites: standardSites))
        let update = byType["com.apple.SoftwareUpdate"]!
        // An unpatched machine is a worse outcome than a slightly newer one.
        #expect(update["CriticalUpdateInstall"] as? Bool == true)
        #expect(update["AutomaticCheckEnabled"] as? Bool == true)
        #expect(update["forceDelayedMajorSoftwareUpdates"] as? Bool == true)
        #expect(update["MajorOSManagedDeferredInstallDelay"] as? Int == 90)
    }

    @Test("Guest account and internet sharing are disabled")
    func mcxPolicy() throws {
        let (_, byType) = try payloads(ProfileGenerator(blockedSites: standardSites))
        #expect(byType["com.apple.MCX"]!["DisableGuestAccount"] as? Bool == true)
        #expect(byType["com.apple.MCX"]!["forceInternetSharingOff"] as? Bool == true)
    }

    // MARK: - Browsers

    /// Hardening Chrome alone is defeated by downloading Brave, so every
    /// Chromium-family browser gets the same policy.
    @Test("All Chromium browsers receive identical hardening")
    func chromiumCoverage() throws {
        let (_, byType) = try payloads(ProfileGenerator(blockedSites: standardSites))
        #expect(ChromiumBrowser.all.count >= 5)

        for browser in ChromiumBrowser.all {
            guard let policy = byType[browser.domain] else {
                Issue.record("no payload for \(browser.name) (\(browser.domain))")
                continue
            }
            // Both DoH keys are required: disabling DoH while leaving the
            // built-in resolver active still bypasses system DNS.
            #expect(policy["DnsOverHttpsMode"] as? String == "off", "\(browser.name)")
            #expect(policy["BuiltInDnsClientEnabled"] as? Bool == false, "\(browser.name)")
            #expect(policy["IncognitoModeAvailability"] as? Int == 1, "\(browser.name)")
            #expect(policy["DeveloperToolsAvailability"] as? Int == 2, "\(browser.name)")
            #expect(policy["QuicAllowed"] as? Bool == false, "\(browser.name)")
            #expect((policy["ProxySettings"] as? [String: Any])?["ProxyMode"] as? String == "direct",
                    "\(browser.name)")
            #expect(policy["SyncDisabled"] as? Bool == true, "\(browser.name)")
        }
    }

    /// Without `EnterprisePoliciesEnabled` every other Firefox key is ignored,
    /// and without `BlockAboutConfig` a user can re-enable DoH from
    /// about:config, defeating the `Locked` flag.
    @Test("Firefox policy includes both load-bearing keys")
    func firefoxPolicy() throws {
        let (_, byType) = try payloads(ProfileGenerator(blockedSites: standardSites))
        let firefox = byType["org.mozilla.firefox"]!

        #expect(firefox["EnterprisePoliciesEnabled"] as? Bool == true)
        #expect(firefox["BlockAboutConfig"] as? Bool == true)

        let doh = firefox["DNSOverHTTPS"] as! [String: Any]
        #expect(doh["Enabled"] as? Bool == false)
        #expect(doh["Locked"] as? Bool == true)

        let proxy = firefox["Proxy"] as! [String: Any]
        #expect(proxy["Mode"] as? String == "none")
        #expect(proxy["Locked"] as? Bool == true)

        #expect(firefox["DisablePrivateBrowsing"] as? Bool == true)
        #expect(firefox["BlockAboutProfiles"] as? Bool == true)
    }

    @Test("Blocklists cover alternate hosts, not just the top-level domain")
    func blocklistsCoverAlternateHosts() throws {
        let (_, byType) = try payloads(ProfileGenerator(blockedSites: standardSites))
        let chromeList = byType["com.google.Chrome"]!["URLBlocklist"] as! [String]
        // chatgpt.com also serves from chat.openai.com; blocking only the
        // top-level domain leaves an obvious back door.
        #expect(chromeList.contains("chat.openai.com"))
        #expect(chromeList.contains("chatgpt.com"))
        // Pinterest's link shortener lives on a different domain entirely.
        #expect(chromeList.contains("pin.it"))
        // Snapchat's browser client is the one that matters on a laptop.
        #expect(chromeList.contains("web.snapchat.com"))
    }

    // MARK: - SafeSearch, ad blocker, cookies, bookmarks

    @Test("SafeSearch policies follow the configured YouTube level", arguments: [
        (SafeSearch.YouTubeLevel.off, nil as Int?),
        (SafeSearch.YouTubeLevel.moderate, 1),
        (SafeSearch.YouTubeLevel.strict, 2),
    ])
    func safeSearchPolicies(_ level: SafeSearch.YouTubeLevel, _ expected: Int?) throws {
        let (_, byType) = try payloads(
            ProfileGenerator(blockedSites: standardSites, youTubeLevel: level, forceSafeSearch: true)
        )
        let chrome = byType["com.google.Chrome"]!
        #expect(chrome["ForceGoogleSafeSearch"] as? Bool == true)
        #expect(chrome["ForceYouTubeRestrict"] as? Int == expected)
    }

    @Test("SafeSearch can be turned off entirely")
    func safeSearchOff() throws {
        let (_, byType) = try payloads(
            ProfileGenerator(blockedSites: standardSites, youTubeLevel: .off, forceSafeSearch: false)
        )
        let chrome = byType["com.google.Chrome"]!
        #expect(chrome["ForceGoogleSafeSearch"] == nil)
        #expect(chrome["ForceYouTubeRestrict"] == nil)
    }

    @Test("The ad blocker is allowlisted and force-installed when enabled")
    func adBlockerEnabled() throws {
        let (_, byType) = try payloads(
            ProfileGenerator(blockedSites: standardSites, installAdBlocker: true)
        )
        for browser in ChromiumBrowser.all {
            let policy = byType[browser.domain]!
            #expect(policy["ExtensionInstallBlocklist"] as? [String] == ["*"], "\(browser.name)")
            #expect(policy["ExtensionInstallAllowlist"] as? [String]
                    == [AllowedExtension.uBlockOriginLite], "\(browser.name)")
            let forcelist = policy["ExtensionInstallForcelist"] as! [String]
            #expect(forcelist.count == 1)
            // Chrome expects "<id>;<update-url>".
            #expect(forcelist[0] == AllowedExtension.forcelistEntry)
            #expect(forcelist[0].contains(";https://"))
        }
    }

    /// Turning the ad blocker off must not reopen the extension hole — that
    /// blanket block is what stops proxy and VPN extensions.
    @Test("Disabling the ad blocker still blocks every extension")
    func adBlockerDisabledStillBlocksExtensions() throws {
        let (_, byType) = try payloads(
            ProfileGenerator(blockedSites: standardSites, installAdBlocker: false)
        )
        for browser in ChromiumBrowser.all {
            let policy = byType[browser.domain]!
            #expect(policy["ExtensionInstallBlocklist"] as? [String] == ["*"], "\(browser.name)")
            #expect((policy["ExtensionInstallAllowlist"] as? [String])?.isEmpty == true, "\(browser.name)")
            #expect(policy["ExtensionInstallForcelist"] == nil, "\(browser.name)")
        }
    }

    /// `DefaultCookiesSetting = 2` would block all cookies and break sign-in
    /// on school sites, so only third-party cookies are blocked.
    @Test("Cookie policy blocks third-party cookies only")
    func cookiePolicy() throws {
        let (_, byType) = try payloads(
            ProfileGenerator(blockedSites: standardSites, blockThirdPartyCookies: true)
        )
        let chrome = byType["com.google.Chrome"]!
        #expect(chrome["BlockThirdPartyCookies"] as? Bool == true)
        #expect(chrome["DefaultCookiesSetting"] == nil)
    }

    @Test("Cookie policy is absent when disabled")
    func cookiePolicyOff() throws {
        let (_, byType) = try payloads(
            ProfileGenerator(blockedSites: standardSites, blockThirdPartyCookies: false)
        )
        #expect(byType["com.google.Chrome"]!["BlockThirdPartyCookies"] == nil)
    }

    @Test("Managed bookmarks use Chrome's folder-and-children shape")
    func managedBookmarks() throws {
        let (_, byType) = try payloads(
            ProfileGenerator(blockedSites: standardSites, educationalBookmarks: true)
        )
        let bookmarks = byType["com.google.Chrome"]!["ManagedBookmarks"] as! [[String: Any]]
        #expect(bookmarks.count == 1)
        #expect(bookmarks[0]["name"] as? String == ManagedBookmark.folderName)

        let children = bookmarks[0]["children"] as! [[String: String]]
        #expect(children.count == ManagedBookmark.educational.count)
        for child in children {
            #expect(child["name"]?.isEmpty == false)
            #expect(child["url"]?.hasPrefix("https://") == true)
        }
    }

    @Test("Bookmarks are absent when disabled")
    func managedBookmarksOff() throws {
        let (_, byType) = try payloads(
            ProfileGenerator(blockedSites: standardSites, educationalBookmarks: false)
        )
        #expect(byType["com.google.Chrome"]!["ManagedBookmarks"] == nil)
    }

    // MARK: - Edge cases

    @Test("An empty blocklist still produces a valid profile")
    func emptyBlocklistIsValid() throws {
        let (root, byType) = try payloads(ProfileGenerator(blockedSites: []))
        #expect(root["PayloadScope"] as? String == "System")
        // DNS filtering and browser hardening still apply with no sites listed.
        #expect(byType["com.apple.dnsSettings.managed"] != nil)
        #expect((byType["com.google.Chrome"]!["URLBlocklist"] as! [String]).isEmpty)
    }

    @Test("Hostile domains cannot corrupt the generated profile")
    func hostileDomainsAreSanitised() throws {
        let sites = [BlockedSite("evil.com\n<key>Injected</key>"), BlockedSite("ok.com")]
        let data = try ProfileGenerator(blockedSites: sites).xmlData()
        // Must still parse, and must not have gained a key.
        let root = try PropertyListSerialization.propertyList(from: data, format: nil) as! [String: Any]
        #expect(root["Injected"] == nil)
        #expect(!String(data: data, encoding: .utf8)!.contains("<key>Injected</key>"))
    }
}
