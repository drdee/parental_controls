import Foundation

/// Builds the `.mobileconfig` configuration profile.
///
/// Because `profiles` can no longer install profiles from the command line
/// ("profiles tool no longer supports installs"), this only *generates* the
/// file — installation is a manual double-click plus approval in System
/// Settings. The app walks the user through that.
public struct ProfileGenerator {
    public init(blockedSites: [BlockedSite],
                dnsBackend: DNSBackend = .families,
                youTubeLevel: SafeSearch.YouTubeLevel = .moderate,
                forceSafeSearch: Bool = true,
                installAdBlocker: Bool = true,
                blockThirdPartyCookies: Bool = true,
                educationalBookmarks: Bool = true) {
        self.blockedSites = blockedSites
        self.dnsBackend = dnsBackend
        self.youTubeLevel = youTubeLevel
        self.forceSafeSearch = forceSafeSearch
        self.installAdBlocker = installAdBlocker
        self.blockThirdPartyCookies = blockThirdPartyCookies
        self.educationalBookmarks = educationalBookmarks
    }

    public var blockedSites: [BlockedSite]
    public var dnsBackend: DNSBackend = .families
    public var youTubeLevel: SafeSearch.YouTubeLevel = .moderate
    public var forceSafeSearch = true
    public var installAdBlocker = true
    public var blockThirdPartyCookies = true
    public var educationalBookmarks = true
    public var organization: String = "Family"
    public var displayName: String = ProfileIdentity.displayName
    public var identifierPrefix: String = ProfileIdentity.prefix

    // MARK: - Top level

    public func makeProfile() -> [String: Any] {
        [
            "PayloadType": "Configuration",
            "PayloadVersion": 1,
            "PayloadIdentifier": identifierPrefix,
            "PayloadUUID": UUID().uuidString,
            "PayloadDisplayName": displayName,
            "PayloadOrganization": organization,
            "PayloadDescription": "DNS content filtering and browser restrictions.",
            // MUST be System. The DNS payload handler rejects user-scoped
            // profiles outright: "Failed to install DNS proxy/settings profile
            // - profile must be scoped to system".
            "PayloadScope": "System",
            // Advisory only on a non-MDM profile: it greys out Remove for a
            // standard user, but an admin can still remove it (and `profiles
            // remove` still works). The real control is not granting admin.
            "PayloadRemovalDisallowed": true,
            "PayloadContent": [
                dnsPayload(),
                restrictionsPayload(),
                appStorePayload(),
                softwareUpdatePayload(),
                mcxPayload(),
                webContentFilterPayload(),
                firefoxPayload(),
            ] + ChromiumBrowser.all.map(chromiumPayload),
        ]
    }

    public func xmlData() throws -> Data {
        try PropertyListSerialization.data(
            fromPropertyList: makeProfile(),
            format: .xml,
            options: 0
        )
    }

    // MARK: - Payload scaffolding

    private func base(_ type: String, _ suffix: String, _ name: String) -> [String: Any] {
        [
            "PayloadType": type,
            "PayloadIdentifier": "\(identifierPrefix).\(suffix)",
            "PayloadUUID": UUID().uuidString,
            "PayloadVersion": 1,
            "PayloadDisplayName": name,
            "PayloadEnabled": true,
        ]
    }

    // MARK: - DNS (the centrepiece)

    /// Encrypted DNS pinned to Cloudflare for Families.
    ///
    /// Preferred over `networksetup` because it applies to every network
    /// service — including Wi-Fi networks joined later — and being DoH it can't
    /// be downgraded or intercepted on a hostile network.
    private func dnsPayload() -> [String: Any] {
        var payload = base("com.apple.dnsSettings.managed", "dns", dnsBackend.displayName)
        var settings: [String: Any] = [
            "DNSProtocol": "HTTPS",
            "ServerURL": dnsBackend.dohURL,
            // SupplementalMatchDomains is deliberately omitted: absent means
            // "all domains". Adding it would *narrow* enforcement.
        ]
        // Only meaningful for Families; an empty array would be worse than
        // omitting the key.
        let bootstrap = dnsBackend.bootstrapAddresses
        if !bootstrap.isEmpty {
            settings["ServerAddresses"] = bootstrap
        }
        payload["DNSSettings"] = settings
        // `ProhibitDisablement` is deliberately NOT set.
        //
        // It requires the profile to have been installed over an MDM channel:
        // the DNS payload validator checks `installedByMDM`, and on a Mac that
        // is not enrolled the whole profile install fails with
        // "unexpected error CPDomainPlugin:101".
        //
        // It was never doing anything useful here either — like
        // PayloadRemovalDisallowed, it is advisory outside MDM. The control
        // that actually keeps this in place is the child not being an admin.
        return payload
    }

    // MARK: - System restrictions

    /// Note: `allowAppInstallation` is deliberately absent. It is an
    /// iOS/supervised key and does nothing on macOS — app-install control here
    /// comes from `/Applications` being `root:admin` and the user not being an
    /// admin.
    private func restrictionsPayload() -> [String: Any] {
        var payload = base("com.apple.applicationaccess", "restrictions", "Restrictions")
        // Private Relay tunnels DNS and would bypass the resolver above.
        payload["allowCloudPrivateRelay"] = false
        payload["allowSafariPrivateBrowsing"] = false
        // Keeps the history trail intact, which is often more useful than the block.
        payload["allowSafariHistoryClearing"] = false
        payload["allowLocalUserCreation"] = false
        payload["allowStartupDiskModification"] = false
        payload["allowAccountModification"] = false
        // Verified against /System/Library/CoreServices/ManagedClient.app/
        // Contents/Resources/Supervised.plist: the only supervision-gated keys
        // in this domain are the four forceClassroom* ones, so these all apply
        // on an unsupervised Mac.
        payload["allowUIConfigurationProfileInstallation"] = false
        payload["allowiPhoneMirroring"] = false
        return payload
    }

    private func appStorePayload() -> [String: Any] {
        var payload = base("com.apple.appstore", "appstore", "App Store")
        payload["restrict-store-require-admin-to-install"] = true
        return payload
    }

    /// Security updates stay on — an unpatched machine is a worse outcome than a
    /// slightly newer one. Major OS upgrades are deferred so a surprise upgrade
    /// can't quietly reset this configuration.
    private func softwareUpdatePayload() -> [String: Any] {
        var payload = base("com.apple.SoftwareUpdate", "softwareupdate", "Software Update")
        payload["AutomaticCheckEnabled"] = true
        payload["AutomaticDownload"] = true
        payload["CriticalUpdateInstall"] = true
        payload["AutomaticallyInstallMacOSUpdates"] = true
        payload["forceDelayedMajorSoftwareUpdates"] = true
        payload["MajorOSManagedDeferredInstallDelay"] = 90
        return payload
    }

    private func mcxPayload() -> [String: Any] {
        var payload = base("com.apple.MCX", "mcx", "System Policy")
        payload["DisableGuestAccount"] = true
        // Stops this Mac sharing its connection onward to other devices.
        payload["forceInternetSharingOff"] = true
        return payload
    }

    /// Defence in depth only, not a control: this filter is Safari/WebKit-only
    /// and appears to require supervision to take effect. Chrome and Firefox
    /// ignore it entirely — they get their own policy payloads below.
    private func webContentFilterPayload() -> [String: Any] {
        var payload = base("com.apple.webcontent-filter", "webfilter", "Web Content Filter")
        payload["FilterType"] = "BuiltIn"
        payload["AutoFilterEnabled"] = true
        payload["BlacklistedURLs"] = blockedSites.flatMap { site in
            site.allHosts.map { "https://\($0)" }
        }
        payload["PermittedURLs"] = [String]()
        return payload
    }

    // MARK: - Browsers

    /// Chrome ships its own DNS-over-HTTPS, which would route straight around
    /// the system resolver. Both keys are required: turning DoH off while
    /// leaving Chrome's built-in resolver active still bypasses system DNS.
    private func chromiumPayload(_ browser: ChromiumBrowser) -> [String: Any] {
        var payload = base(browser.domain,
                           "chromium." + browser.domain,
                           browser.name + " Policy")
        payload["DnsOverHttpsMode"] = "off"
        payload["DnsOverHttpsTemplates"] = ""
        payload["BuiltInDnsClientEnabled"] = false
        payload["IncognitoModeAvailability"] = 1  // 1 = disabled
        payload["BrowserSignin"] = 0
        payload["SyncDisabled"] = true
        // A proxy/VPN extension is a likelier bypass than a native VPN app, so
        // everything is blocked by default and exceptions are explicit.
        payload["ExtensionInstallBlocklist"] = ["*"]
        if installAdBlocker {
            // Ad networks are a real malware delivery route, so an ad blocker
            // is a net security gain — the one extension worth allowing.
            // Forcelist installs it silently; allowlist keeps the "*" block
            // from overriding that.
            payload["ExtensionInstallAllowlist"] = [AllowedExtension.uBlockOriginLite]
            payload["ExtensionInstallForcelist"] = [AllowedExtension.forcelistEntry]
        } else {
            payload["ExtensionInstallAllowlist"] = [String]()
        }
        if blockThirdPartyCookies {
            // Parity with Safari, which has blocked these by default since
            // Safari 13.1. Deliberately not DefaultCookiesSetting = 2, which
            // would break sign-in on school sites.
            payload["BlockThirdPartyCookies"] = true
        }
        if educationalBookmarks {
            payload["ManagedBookmarks"] = ManagedBookmark.chromePolicyValue(ManagedBookmark.educational)
        }
        payload["DeveloperToolsAvailability"] = 2  // 2 = disallowed
        payload["URLBlocklist"] = chromeBlocklist()
        payload["URLAllowlist"] = [String]()
        // Firefox's proxy was locked but Chromium's was not — the same hole.
        payload["ProxySettings"] = ["ProxyMode": "direct"]
        // QUIC carries traffic over UDP/443 and evades some network inspection.
        payload["QuicAllowed"] = false
        if forceSafeSearch {
            payload["ForceGoogleSafeSearch"] = true
        }
        if youTubeLevel != .off {
            payload["ForceYouTubeRestrict"] = youTubeLevel.chromePolicyValue
        }
        return payload
    }

    /// Covers the alternate hosts too (chatgpt.com also serves from
    /// chat.openai.com), otherwise the blocklist misses the obvious back door.
    private func chromeBlocklist() -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for site in blockedSites {
            for host in [site.domain] + site.extraHosts {
                for pattern in [host, "*.\(host)"] where seen.insert(pattern).inserted {
                    out.append(pattern)
                }
            }
        }
        return out
    }

    /// `EnterprisePoliciesEnabled` is required or every other key here is
    /// ignored. `BlockAboutConfig` is equally load-bearing: without it,
    /// `about:config` can flip `network.trr.mode` and re-enable DoH, defeating
    /// the `Locked` flag.
    private func firefoxPayload() -> [String: Any] {
        var payload = base("org.mozilla.firefox", "firefox", "Firefox Policy")
        payload["EnterprisePoliciesEnabled"] = true
        payload["DNSOverHTTPS"] = ["Enabled": false, "Locked": true]
        payload["Proxy"] = ["Mode": "none", "Locked": true]
        payload["DisablePrivateBrowsing"] = true
        payload["BlockAboutConfig"] = true
        payload["BlockAboutProfiles"] = true
        payload["DisableDeveloperTools"] = true
        payload["WebsiteFilter"] = [
            "Block": blockedSites.flatMap { site in
                ([site.domain] + site.extraHosts).map { "*://*.\($0)/*" }
            },
            "Exceptions": [String](),
        ]
        payload["ExtensionSettings"] = [
            "*": ["installation_mode": "blocked"],
        ]
        return payload
    }
}
