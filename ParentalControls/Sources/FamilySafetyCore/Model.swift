import Foundation

/// Identifiers shared between generating the profile and removing it again.
///
/// Single source of truth: if these drift apart, revert silently stops finding
/// the profile it is supposed to remove.
public enum ProfileIdentity {
    // swiftlint:disable:next no_hardcoded_profile_identifier - canonical definition
    public static let prefix = "com.familysafety.parental"
    public static let displayName = "Family Safety"
    /// Substring used to recognise our profile in `profiles list` output.
    public static let listingMarker = "familysafety"
}

/// How much of the configuration to apply.
///
/// `family` is the shareable mode: it only installs a configuration profile and
/// writes `/etc/hosts` entries, both fully reversible. It deliberately never
/// touches user accounts, Secure Token, or FileVault, so it cannot lock anyone
/// out of their own Mac.
///
/// `advanced` adds the account separation and login hardening that make the
/// profile actually stick. Only for machines you own and can recover.
public enum RunMode: String, CaseIterable, Identifiable, Sendable {
    case family
    case advanced

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .family:   return "Family Mode"
        case .advanced: return "Advanced Mode"
        }
    }

    public var subtitle: String {
        switch self {
        case .family:
            return "Content filtering only. Fully reversible — cannot lock anyone out."
        case .advanced:
            return "Adds a standard (non-admin) account and login hardening."
        }
    }

    /// Advanced-only steps create or modify accounts, which is the one class of
    /// change that can leave someone unable to log in.
    public var touchesAccounts: Bool { self == .advanced }
}

/// Which filtering resolver to pin the machine to.
///
/// `families` needs no account and is the right default for anyone we hand this
/// to. `zeroTrust` is the same infrastructure with a policy layer on top: it
/// adds a real social-media content category, SafeSearch, custom lists, and
/// query logs — but it requires a Cloudflare account, and the endpoint embeds a
/// per-account ID, so it can't be shared blindly between families.
public enum DNSBackend: Equatable, Sendable {
    /// Cloudflare for Families 1.1.1.3 — malware + adult content. Two fixed
    /// categories, no social-media category, no custom lists.
    case families
    /// Cloudflare Zero Trust Gateway, e.g.
    /// `https://<id>.cloudflare-gateway.com/dns-query`.
    case zeroTrust(dohURL: String)

    public var dohURL: String {
        switch self {
        case .families:
            return "https://family.cloudflare-dns.com/dns-query"
        case .zeroTrust(let url):
            return url.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    /// Bootstrap addresses used to resolve the DoH hostname itself.
    ///
    /// Both IPv4 and IPv6 are required: a machine with IPv6 nameservers will
    /// happily resolve around an IPv4-only filter. Zero Trust resolves its
    /// hostname over the normal Cloudflare anycast range, so the Families
    /// addresses are not a meaningful fallback there.
    public var bootstrapAddresses: [String] {
        switch self {
        case .families:
            return ["1.1.1.3", "1.0.0.3", "2606:4700:4700::1113", "2606:4700:4700::1003"]
        case .zeroTrust:
            return []
        }
    }

    /// Zero Trust can block social media as a category; Families cannot, so
    /// there the explicit domain lists are doing all of that work.
    public var blocksSocialMediaByCategory: Bool {
        if case .zeroTrust = self { return true }
        return false
    }

    public var displayName: String {
        switch self {
        case .families:  return "Cloudflare for Families (1.1.1.3)"
        case .zeroTrust: return "Cloudflare Zero Trust Gateway"
        }
    }

    /// A Zero Trust endpoint we would refuse to write into a profile.
    public var validationError: String? {
        guard case .zeroTrust(let raw) = self else { return nil }
        let url = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if url.isEmpty { return "Enter your Zero Trust DoH endpoint." }
        guard url.hasPrefix("https://") else { return "Endpoint must start with https://" }
        guard url.contains("/dns-query") else { return "Endpoint should end with /dns-query" }
        guard URL(string: url)?.host != nil else { return "That is not a valid URL." }
        return nil
    }
}

/// A domain to block, plus the subdomains worth listing explicitly.
///
/// `/etc/hosts` has no wildcard support, so each host has to be enumerated. The
/// DNS layer is what actually generalises; these entries are belt-and-braces for
/// the specific sites named up front.
public struct BlockedSite: Identifiable, Hashable, Sendable {
    public var domain: String
    public var extraHosts: [String]

    public var id: String { domain }

    /// Every hostname to sinkhole in `/etc/hosts`.
    public var allHosts: [String] {
        [domain, "www.\(domain)"] + extraHosts
    }

    public init(_ domain: String, extraHosts: [String] = []) {
        self.domain = Self.sanitize(domain)
        self.extraHosts = extraHosts.map(Self.sanitize).filter { !$0.isEmpty }
    }

    /// Reduces input to characters legal in a hostname.
    ///
    /// This is a security boundary, not tidiness: these strings are written
    /// into `/etc/hosts` via a shell heredoc that runs as root. A newline would
    /// let a crafted "domain" inject an arbitrary hosts entry — or, if it
    /// matched the heredoc delimiter, terminate it and start a new command.
    /// Quoting cannot prevent that, so the characters are removed instead.
    public static func sanitize(_ raw: String) -> String {
        let allowed = Set("abcdefghijklmnopqrstuvwxyz0123456789.-")
        let lowered = raw.lowercased()
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "https://", with: "")
            .replacingOccurrences(of: "http://", with: "")
        // Drop any path, query, port or credentials.
        let hostOnly = lowered
            .split(separator: "/").first.map(String.init) ?? ""
        let stripped = hostOnly
            .split(separator: "?").first.map(String.init) ?? ""
        let noPort = stripped
            .split(separator: ":").first.map(String.init) ?? ""
        return String(noPort.filter { allowed.contains($0) })
    }

    /// A hostname we are willing to write to disk.
    public var isValid: Bool {
        !domain.isEmpty
            && domain.contains(".")
            && !domain.hasPrefix(".")
            && !domain.hasSuffix(".")
            && !domain.contains("..")
            && domain.count <= 253
    }
}

public extension BlockedSite {
    /// The sites the user named, with the subdomains I confirmed resolve
    /// independently (TikTok in particular serves from several).
    /// Social media, as one preset.
    ///
    /// On by default — these are the sites the whole exercise started from.
    /// Grouped rather than listed individually because a parent thinks in terms
    /// of "block social media", not in terms of nine hostnames.
    public static let socialMedia: [BlockedSite] = [
        BlockedSite("tiktok.com", extraHosts: [
            "m.tiktok.com", "vm.tiktok.com", "vt.tiktok.com", "api.tiktok.com",
        ]),
        BlockedSite("instagram.com", extraHosts: [
            "i.instagram.com", "graph.instagram.com", "cdninstagram.com",
        ]),
        BlockedSite("pinterest.com", extraHosts: [
            // pin.it is Pinterest's link shortener on a separate domain, so
            // blocking pinterest.com alone still lets shared links through.
            "pin.it", "api.pinterest.com", "i.pinimg.com",
        ]),
        BlockedSite("snapchat.com", extraHosts: [
            // web.snapchat.com is the full browser client — the one that
            // actually matters on a laptop.
            "web.snapchat.com", "accounts.snapchat.com",
            "app.snapchat.com", "my.snapchat.com",
        ]),
    ]

    /// The editable list starts empty: everything is now reached through the
    /// presets, and anything a parent types is added on top of them.
    public static let defaults: [BlockedSite] = []

    /// AI chatbots.
    ///
    /// On by default. ChatGPT lives here rather than under social media — it is
    /// a different category of concern (homework integrity and unfiltered
    /// content), and blocking only ChatGPT is close to meaningless now.
    /// `gemini.google.com` is the one to watch — schools using Google
    /// Workspace may need it, so it can be removed individually.
    public static let aiChatbots: [BlockedSite] = [
        BlockedSite("chatgpt.com", extraHosts: [
            "chat.openai.com", "openai.com", "api.openai.com",
        ]),
        BlockedSite("claude.ai"),
        BlockedSite("perplexity.ai"),
        BlockedSite("character.ai", extraHosts: ["beta.character.ai"]),
        BlockedSite("poe.com"),
        BlockedSite("deepseek.com", extraHosts: ["chat.deepseek.com"]),
        BlockedSite("x.ai", extraHosts: ["grok.com"]),
        BlockedSite("gemini.google.com"),
        BlockedSite("copilot.microsoft.com"),
    ]

    /// Chat, gaming and forum platforms — distinct from `socialMedia`.
    ///
    /// Deliberately **off** by default. Discord and Reddit have real school and
    /// club uses, and blocking them tends to produce a workaround rather than a
    /// behaviour change — better as a conversation than a silent block.
    public static let chatAndGaming: [BlockedSite] = [
        BlockedSite("discord.com", extraHosts: ["discordapp.com", "gateway.discord.gg"]),
        BlockedSite("reddit.com", extraHosts: ["old.reddit.com", "np.reddit.com"]),
        BlockedSite("roblox.com", extraHosts: ["web.roblox.com"]),
        BlockedSite("twitch.tv", extraHosts: ["m.twitch.tv"]),
        BlockedSite("telegram.org", extraHosts: ["web.telegram.org"]),
        BlockedSite("whatsapp.com", extraHosts: ["web.whatsapp.com"]),
        BlockedSite("x.com", extraHosts: ["twitter.com", "mobile.twitter.com"]),
        BlockedSite("threads.net", extraHosts: ["threads.com"]),
        BlockedSite("tumblr.com"),
        BlockedSite("bereal.com"),
    ]
}

/// Google/YouTube "restricted mode" pinning.
///
/// Google publishes special hostnames that serve SafeSearch-enforced results;
/// pointing the normal hostnames at those addresses forces safe results
/// site-wide. This filters *within* sites they will legitimately use, which
/// category blocking cannot do.
///
/// Note this works only because Google chooses to honour it — it is a
/// convenience, not a security boundary, and the addresses could change. Both
/// were resolved and confirmed against Google's DNS when this was written.
public enum SafeSearch {
    /// `forcesafesearch.google.com` and `restrict.youtube.com`.
    public static let strictAddress = "216.239.38.120"
    /// `restrictmoderate.youtube.com`.
    public static let moderateAddress = "216.239.38.119"

    public static let googleHosts = [
        "www.google.com", "google.com",
        "www.google.co.uk", "google.co.uk",
        "www.google.ca", "google.ca",
    ]

    /// YouTube endpoints, including the API hosts the apps use.
    public static let youTubeHosts = [
        "www.youtube.com", "m.youtube.com", "youtube.com",
        "youtubei.googleapis.com", "youtube.googleapis.com",
        "www.youtube-nocookie.com",
    ]

    /// How strictly to restrict YouTube.
    ///
    /// Moderate is the default deliberately: strict mode blocks a great deal of
    /// legitimate educational content, which turns into a support burden and
    /// teaches them the filter is broken.
    public enum YouTubeLevel: String, CaseIterable, Identifiable, Sendable {
        case off, moderate, strict

        public var id: String { rawValue }

        public var title: String {
            switch self {
            case .off:      "Off"
            case .moderate: "Moderate (recommended)"
            case .strict:   "Strict"
            }
        }

        /// Chrome's `ForceYouTubeRestrict`: 0 = off, 1 = moderate, 2 = strict.
        public var chromePolicyValue: Int {
            switch self {
            case .off:      0
            case .moderate: 1
            case .strict:   2
            }
        }

        public var hostsAddress: String? {
            switch self {
            case .off:      nil
            case .moderate: SafeSearch.moderateAddress
            case .strict:   SafeSearch.strictAddress
            }
        }
    }
}

/// A Chromium-family browser that reads enterprise policy from a managed
/// preference domain.
///
/// Hardening Chrome alone is close to pointless: downloading Brave is a
/// 60-second bypass. The policy key names are identical across the family, so
/// the same payload is emitted once per domain. A payload for a browser that
/// is not installed is simply inert.
public struct ChromiumBrowser: Identifiable, Sendable {
    public var name: String
    public var domain: String

    public var id: String { domain }

    public static let all: [Self] = [
        Self(name: "Google Chrome", domain: "com.google.Chrome"),
        Self(name: "Brave", domain: "com.brave.Browser"),
        Self(name: "Microsoft Edge", domain: "com.microsoft.Edge"),
        Self(name: "Vivaldi", domain: "com.vivaldi.Vivaldi"),
        // Opera's managed-preference domain could not be confirmed; included
        // because an unrecognised payload is harmless, but do not rely on it.
        Self(name: "Opera", domain: "com.operasoftware.Opera"),
    ]
}

/// Chrome extensions we deliberately permit.
///
/// The default policy blocks every extension, because a proxy or VPN extension
/// is an easier bypass than a native app. An ad blocker is the one exception
/// worth making: ad networks are a real malware delivery route, so blocking
/// them is a net security gain rather than a convenience.
public enum AllowedExtension {
    /// uBlock Origin Lite. Verified live in the Chrome Web Store.
    ///
    /// Note this is *Lite* (Manifest V3). The original uBlock Origin was
    /// delisted with the MV2 deprecation, so its ID no longer installs.
    public static let uBlockOriginLite = "ddkjiahejlhfcafbddmgiahcphecmpfh"

    /// Google Docs Offline. Verified live in the Chrome Web Store.
    ///
    /// Without it, Docs, Sheets and Slides cannot be edited without a
    /// connection — the blanket extension block would break schoolwork.
    public static let googleDocsOffline = "ghbmnnjooekpmoecnnnilnnbdlolhkhi"

    /// 1Password. Verified live in the Chrome Web Store.
    ///
    /// A password manager makes good password habits practical, which matters
    /// more at this age than the marginal risk of one more extension.
    public static let onePassword = "aeblfdkhhhdcdjpifhhbdiojplfjncoa"

    /// Chrome expects `<id>;<update-url>` in `ExtensionInstallForcelist`.
    public static let chromeWebStoreUpdateURL = "https://clients2.google.com/service/update2/crx"

    /// Extensions permitted despite the blanket block.
    ///
    /// Each is publisher-known and has no proxy or VPN capability, so none
    /// reopens the bypass the blocklist exists to close.
    public static let allowedIdentifiers = [uBlockOriginLite, googleDocsOffline, onePassword]

    /// Extensions to install automatically.
    ///
    /// Only the ad blocker: it is a security control, so it should be present
    /// whether or not anyone asks for it. Docs Offline and 1Password are
    /// permitted but left to be installed by whoever wants them.
    public static var forcelistEntries: [String] {
        ["\(uBlockOriginLite);\(chromeWebStoreUpdateURL)"]
    }

    /// Permitted even when the ad blocker is turned off, since these exist to
    /// avoid breaking legitimate use rather than to add protection.
    public static let alwaysAllowedIdentifiers = [googleDocsOffline, onePassword]
}


/// A bookmark pushed into a managed folder in Chrome.
///
/// Chrome-only: Safari keeps bookmarks in a per-user, TCC-protected plist with
/// no managed-preference equivalent, so there is no way to set them from here.
public struct ManagedBookmark: Sendable {
    public var name: String
    public var url: String
}

public extension ManagedBookmark {
    public static let folderName = "Learning"

    /// Deliberately short. A long imposed list reads as homework-by-decree and
    /// gets ignored; these are genuinely useful starting points.
    public static let educational: [ManagedBookmark] = [
        ManagedBookmark(name: "Khan Academy", url: "https://www.khanacademy.org"),
        ManagedBookmark(name: "Wikipedia", url: "https://en.wikipedia.org"),
        // Britannica was dropped: it returns 403 to non-residential clients,
        // so it could not be verified as reachable.
        ManagedBookmark(name: "MIT OpenCourseWare", url: "https://ocw.mit.edu"),
        ManagedBookmark(name: "Wolfram Alpha", url: "https://www.wolframalpha.com"),
        ManagedBookmark(name: "Desmos Graphing", url: "https://www.desmos.com/calculator"),
        ManagedBookmark(name: "Project Gutenberg", url: "https://www.gutenberg.org"),
        ManagedBookmark(name: "NASA", url: "https://www.nasa.gov"),
        ManagedBookmark(name: "BBC Bitesize", url: "https://www.bbc.co.uk/bitesize"),
    ]

    /// Chrome's `ManagedBookmarks` shape: an optional toplevel-name marker
    /// followed by folder/link dictionaries.
    public static func chromePolicyValue(_ bookmarks: [ManagedBookmark]) -> [[String: Any]] {
        [[
            "name": folderName,
            "children": bookmarks.map { ["name": $0.name, "url": $0.url] },
        ]]
    }
}
