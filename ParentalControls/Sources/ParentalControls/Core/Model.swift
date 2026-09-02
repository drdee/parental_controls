import Foundation

/// Identifiers shared between generating the profile and removing it again.
///
/// Single source of truth: if these drift apart, revert silently stops finding
/// the profile it is supposed to remove.
enum ProfileIdentity {
    // swiftlint:disable:next no_hardcoded_profile_identifier - canonical definition
    static let prefix = "com.familysafety.parental"
    static let displayName = "Family Safety"
    /// Substring used to recognise our profile in `profiles list` output.
    static let listingMarker = "familysafety"
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
enum RunMode: String, CaseIterable, Identifiable, Sendable {
    case family
    case advanced

    var id: String { rawValue }

    var title: String {
        switch self {
        case .family:   return "Family Mode"
        case .advanced: return "Advanced Mode"
        }
    }

    var subtitle: String {
        switch self {
        case .family:
            return "Content filtering only. Fully reversible — cannot lock anyone out."
        case .advanced:
            return "Adds a standard (non-admin) account and login hardening."
        }
    }

    /// Advanced-only steps create or modify accounts, which is the one class of
    /// change that can leave someone unable to log in.
    var touchesAccounts: Bool { self == .advanced }
}

/// Which filtering resolver to pin the machine to.
///
/// `families` needs no account and is the right default for anyone we hand this
/// to. `zeroTrust` is the same infrastructure with a policy layer on top: it
/// adds a real social-media content category, SafeSearch, custom lists, and
/// query logs — but it requires a Cloudflare account, and the endpoint embeds a
/// per-account ID, so it can't be shared blindly between families.
enum DNSBackend: Equatable, Sendable {
    /// Cloudflare for Families 1.1.1.3 — malware + adult content. Two fixed
    /// categories, no social-media category, no custom lists.
    case families
    /// Cloudflare Zero Trust Gateway, e.g.
    /// `https://<id>.cloudflare-gateway.com/dns-query`.
    case zeroTrust(dohURL: String)

    var dohURL: String {
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
    var bootstrapAddresses: [String] {
        switch self {
        case .families:
            return ["1.1.1.3", "1.0.0.3", "2606:4700:4700::1113", "2606:4700:4700::1003"]
        case .zeroTrust:
            return []
        }
    }

    /// Zero Trust can block social media as a category; Families cannot, so
    /// there the explicit domain lists are doing all of that work.
    var blocksSocialMediaByCategory: Bool {
        if case .zeroTrust = self { return true }
        return false
    }

    var displayName: String {
        switch self {
        case .families:  return "Cloudflare for Families (1.1.1.3)"
        case .zeroTrust: return "Cloudflare Zero Trust Gateway"
        }
    }

    /// A Zero Trust endpoint we would refuse to write into a profile.
    var validationError: String? {
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
struct BlockedSite: Identifiable, Hashable, Sendable {
    var domain: String
    var extraHosts: [String]

    var id: String { domain }

    /// Every hostname to sinkhole in `/etc/hosts`.
    var allHosts: [String] {
        [domain, "www.\(domain)"] + extraHosts
    }

    init(_ domain: String, extraHosts: [String] = []) {
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
    static func sanitize(_ raw: String) -> String {
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
    var isValid: Bool {
        !domain.isEmpty
            && domain.contains(".")
            && !domain.hasPrefix(".")
            && !domain.hasSuffix(".")
            && !domain.contains("..")
            && domain.count <= 253
    }
}

extension BlockedSite {
    /// The sites the user named, with the subdomains I confirmed resolve
    /// independently (TikTok in particular serves from several).
    static let defaults: [BlockedSite] = [
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
        BlockedSite("chatgpt.com", extraHosts: [
            "chat.openai.com", "openai.com", "api.openai.com",
        ]),
    ]

    /// AI chatbots beyond ChatGPT.
    ///
    /// On by default: blocking only ChatGPT is now close to meaningless, and
    /// these matter for both homework integrity and unfiltered content.
    /// `gemini.google.com` is the one to watch — schools using Google
    /// Workspace may need it, so it can be removed individually.
    static let aiChatbots: [BlockedSite] = [
        BlockedSite("claude.ai"),
        BlockedSite("perplexity.ai"),
        BlockedSite("character.ai", extraHosts: ["beta.character.ai"]),
        BlockedSite("poe.com"),
        BlockedSite("deepseek.com", extraHosts: ["chat.deepseek.com"]),
        BlockedSite("x.ai", extraHosts: ["grok.com"]),
        BlockedSite("gemini.google.com"),
        BlockedSite("copilot.microsoft.com"),
    ]

    /// Chat, gaming and forum platforms.
    ///
    /// Deliberately **off** by default. Discord and Reddit have real school and
    /// club uses, and blocking them tends to produce a workaround rather than a
    /// behaviour change — better as a conversation than a silent block.
    static let socialAndGaming: [BlockedSite] = [
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
enum SafeSearch {
    /// `forcesafesearch.google.com` and `restrict.youtube.com`.
    static let strictAddress = "216.239.38.120"
    /// `restrictmoderate.youtube.com`.
    static let moderateAddress = "216.239.38.119"

    static let googleHosts = [
        "www.google.com", "google.com",
        "www.google.co.uk", "google.co.uk",
        "www.google.ca", "google.ca",
    ]

    /// YouTube endpoints, including the API hosts the apps use.
    static let youTubeHosts = [
        "www.youtube.com", "m.youtube.com", "youtube.com",
        "youtubei.googleapis.com", "youtube.googleapis.com",
        "www.youtube-nocookie.com",
    ]

    /// How strictly to restrict YouTube.
    ///
    /// Moderate is the default deliberately: strict mode blocks a great deal of
    /// legitimate educational content, which turns into a support burden and
    /// teaches them the filter is broken.
    enum YouTubeLevel: String, CaseIterable, Identifiable, Sendable {
        case off, moderate, strict

        var id: String { rawValue }

        var title: String {
            switch self {
            case .off:      "Off"
            case .moderate: "Moderate (recommended)"
            case .strict:   "Strict"
            }
        }

        /// Chrome's `ForceYouTubeRestrict`: 0 = off, 1 = moderate, 2 = strict.
        var chromePolicyValue: Int {
            switch self {
            case .off:      0
            case .moderate: 1
            case .strict:   2
            }
        }

        var hostsAddress: String? {
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
struct ChromiumBrowser: Identifiable, Sendable {
    var name: String
    var domain: String

    var id: String { domain }

    static let all: [Self] = [
        Self(name: "Google Chrome", domain: "com.google.Chrome"),
        Self(name: "Brave", domain: "com.brave.Browser"),
        Self(name: "Microsoft Edge", domain: "com.microsoft.Edge"),
        Self(name: "Vivaldi", domain: "com.vivaldi.Vivaldi"),
        // Opera's managed-preference domain could not be confirmed; included
        // because an unrecognised payload is harmless, but do not rely on it.
        Self(name: "Opera", domain: "com.operasoftware.Opera"),
    ]
}
