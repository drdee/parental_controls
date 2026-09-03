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
                contentFilterPayload(),
                appStorePayload(),
                softwareUpdatePayload(),
                mcxPayload(),
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
        // allowSafariPrivateBrowsing and allowSafariHistoryClearing are
        // deliberately NOT set. Apple's schema marks both
        // `allowmanualinstall: false` on macOS: they require the profile to
        // arrive over MDM, and including them fails a manual install outright
        // with "unexpected error CPDomainPlugin:101".
        //
        // Safari private browsing is instead disabled through Screen Time's
        // Content & Privacy settings — see docs/MANUAL-STEPS.md.
        payload["allowLocalUserCreation"] = false
        payload["allowStartupDiskModification"] = false
        // Spotlight will load a URL typed into it in its own preview window,
        // outside any browser, so none of the browser policy below applies to
        // it. DNS filtering still does, since the lookup is ordinary, but the
        // window is a genuine gap in the browser layer.
        //
        // Not supervision-gated: Apple's com.apple.applicationaccess schema
        // marks this key `supervised: false` with no `allowmanualinstall`
        // restriction, unlike allowDefinitionLookup next to it.
        payload["allowSpotlightInternetResults"] = false
        // allowAccountModification is deliberately absent. It would stop a
        // standard user promoting themselves to admin, but it also blocks
        // every legitimate account change -- including an ordinary password
        // change by the parent -- for as long as the profile is installed.
        // That cost was judged too high for a control that only holds against
        // someone who does not already know an admin password. See
        // docs/BYPASS-NOTES.md, which ranks this honestly.
        //
        // allowiPhoneMirroring is likewise absent: mirrored apps run on the
        // phone and are outside anything this Mac can filter, so the phone is
        // where that has to be handled.
        //
        // Verified against /System/Library/CoreServices/ManagedClient.app/
        // Contents/Resources/Supervised.plist: the only supervision-gated keys
        // in this domain are the four forceClassroom* ones, so these all apply
        // on an unsupervised Mac.
        payload["allowUIConfigurationProfileInstallation"] = false
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
        // The major-OS deferral keys are deliberately NOT set here.
        //
        // `forceDelayedMajorSoftwareUpdates` belongs to
        // com.apple.applicationaccess, not this payload — setting it here did
        // nothing at all. Apple also deprecates it as of macOS 26.0, which is
        // what these Macs run. `MajorOSManagedDeferredInstallDelay` appears in
        // no published schema.
        //
        // A surprise major upgrade could reset this configuration, but the
        // right answer is to re-run the installer after an upgrade rather than
        // to ship a deprecated key in the wrong payload.
        return payload
    }

    private func mcxPayload() -> [String: Any] {
        var payload = base("com.apple.MCX", "mcx", "System Policy")
        payload["DisableGuestAccount"] = true
        // Stops this Mac sharing its connection onward to other devices.
        payload["forceInternetSharingOff"] = true
        return payload
    }

    /// The legacy Family Controls web filter.
    ///
    /// This is the one payload that reaches **Safari**. Every Chromium browser
    /// and Firefox has its own policy payload; Safari had nothing but DNS
    /// until this, because WebKit ignores those policies entirely.
    ///
    /// Not to be confused with `com.apple.webcontent-filter`, which is a
    /// different payload and is deliberately skipped — see the note below it.
    /// This one should be usable on a manually installed profile: Apple's
    /// schema marks it `supervised: false` and `allowmanualinstall: true`.
    ///
    /// One caveat worth knowing when changing this: schema conformance has
    /// been a poor predictor of what macOS accepts. `allowSafariPrivateBrowsing`
    /// and the `webcontent-filter` payload both looked installable on paper
    /// and failed the *entire* profile with "CPDomainPlugin:101". A profile
    /// installs whole or not at all, so a rejected payload takes everything
    /// else with it — install after any change here, do not assume.
    ///
    /// `useContentFilter` turns on Apple's own heuristic adult-content
    /// classifier, which catches sites no hand-written list would. The deny
    /// list then adds the specific domains this tool blocks, so the two work
    /// together rather than either alone.
    ///
    /// `allowListEnabled` is deliberately left false. Setting it restricts
    /// browsing to `siteAllowList` only, which is a different product — fine
    /// for a six-year-old, unusable for a teenager doing homework.
    private func contentFilterPayload() -> [String: Any] {
        var payload = base("com.apple.familycontrols.contentfilter",
                           "contentfilter", "Web Content Filter")
        payload["restrictWeb"] = true
        payload["useContentFilter"] = true

        let denied = blockedSites.flatMap { site in
            ([site.domain] + site.extraHosts).map { "https://\($0)" }
        }
        // Apple renamed these keys in macOS 15.2 and deprecated the old
        // spellings. Both are emitted: the deployment target is macOS 14, and
        // an unrecognised key in this payload is ignored rather than failing
        // the install.
        payload["filterDenyList"] = denied
        payload["filterBlacklist"] = denied
        return payload
    }

    // The `com.apple.webcontent-filter` payload is deliberately NOT emitted.
    //
    // Its macOS handler (NetworkExtensionProfiles.profileDomainPlugin) does not
    // recognise `FilterType: BuiltIn` — that string, along with
    // `AutoFilterEnabled`, `BlacklistedURLs` and `PermittedURLs`, does not
    // appear in the binary at all. They are iOS-only keys. The macOS handler
    // knows only `PluginBundleID`, `UserName` and `Password`: it expects a
    // third-party filter extension and requires a signingIdentifier and
    // designatedRequirement we cannot supply.
    //
    // Including it failed the ENTIRE profile install with "unexpected error
    // CPDomainPlugin:101" rather than being ignored.
    //
    // Nothing is lost. It only ever covered Safari/WebKit, and Safari is
    // filtered by DNS plus Screen Time's Content & Privacy settings. Every
    // Chromium browser and Firefox has its own policy payload, all unaffected.

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
            payload["ExtensionInstallAllowlist"] = AllowedExtension.allowedIdentifiers
            payload["ExtensionInstallForcelist"] = AllowedExtension.forcelistEntries
        } else {
            // Google Docs Offline stays allowed regardless: the blanket block
            // would otherwise stop offline editing of schoolwork.
            payload["ExtensionInstallAllowlist"] = AllowedExtension.alwaysAllowedIdentifiers
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
        // DevTools is deliberately left available. Blocking it costs a kid
        // learning to code View Source and Inspect Element, and it buys very
        // little: the filter that matters is DNS-level, and someone able to
        // bypass it via DevTools could equally use another browser.
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
        // DisableDeveloperTools is deliberately absent, matching the Chromium
        // payload. Blocking the inspector costs a kid learning to code View
        // Source and the console, and buys little: the filter that matters is
        // DNS-level, and anyone able to bypass it that way could use another
        // browser. Leaving it set for Firefox while Chrome is open would also
        // be an inconsistency nobody reading this later could explain.
        payload["WebsiteFilter"] = [
            "Block": blockedSites.flatMap { site in
                ([site.domain] + site.extraHosts).map { "*://*.\($0)/*" }
            },
            "Exceptions": [String](),
        ]
        // Mirrors the Chromium allowlist rather than blocking everything, so a
        // password manager and an ad blocker work in whichever browser is
        // used. Default-deny with named exceptions, same shape as Chromium:
        // "*" is blocked, then each permitted add-on is allowed by ID.
        //
        // Note the IDs differ from Chrome's, and Google Docs Offline has no
        // Firefox build at all -- see AllowedExtension.
        var extensions: [String: Any] = ["*": ["installation_mode": "blocked"]]
        var permitted = [AllowedExtension.firefoxOnePassword]
        if installAdBlocker {
            permitted.append(AllowedExtension.firefoxUBlockOrigin)
        }
        for identifier in permitted {
            extensions[identifier] = ["installation_mode": "allowed"]
        }
        payload["ExtensionSettings"] = extensions
        return payload
    }
}
