import Foundation

/// A plain-language description of one change, for the dry-run walkthrough.
///
/// The review screen can show literal shell commands, which is right for
/// someone who wants to audit them and useless for everyone else. Dry run is
/// aimed at the second group: it answers "what will this actually do to my
/// Mac, and can I undo it?" without assuming any technical knowledge.
struct ChangeDescription: Identifiable, Sendable {
    enum Impact: Sendable {
        /// Adds or changes a setting; nothing is lost.
        case additive
        /// Restricts something that currently works.
        case restrictive
        /// Touches accounts or startup — the category that can lock someone out.
        case sensitive
    }

    var id: String { title }
    var title: String
    /// What changes, in one sentence, with no jargon.
    var whatChanges: String
    /// What the person using the Mac will notice.
    var whatTheyWillNotice: String
    /// How to put it back.
    var howToUndo: String
    var impact: Impact
    /// Files or settings touched, for anyone who wants specifics.
    var affects: [String]
}

extension ChangeDescription.Impact {
    var label: String {
        switch self {
        case .additive:    "Adds a setting"
        case .restrictive: "Restricts something"
        case .sensitive:   "Changes accounts or startup"
        }
    }

    var symbolName: String {
        switch self {
        case .additive:    "plus.circle.fill"
        case .restrictive: "hand.raised.circle.fill"
        case .sensitive:   "exclamationmark.triangle.fill"
        }
    }
}

/// Builds the dry-run walkthrough for a given configuration.
///
/// Deliberately independent of `Hardening`: this describes *everything* that
/// would change, including the profile payloads and the manual profile install,
/// not just the steps that run as shell commands.
struct ChangePlan {
    var mode: RunMode
    var backend: DNSBackend
    var blockedSites: [BlockedSite]
    var installWARP: Bool
    var youTubeLevel: SafeSearch.YouTubeLevel = .moderate
    var forceSafeSearch = true
    var installAdBlocker = true
    var blockThirdPartyCookies = true
    var educationalBookmarks = true
    var createAccount: Bool
    var accountUsername: String

    func descriptions() -> [ChangeDescription] {
        var changes: [ChangeDescription] = [dnsChange(), profileChange(), browserChange(), hostsChange()]

        if forceSafeSearch || youTubeLevel != .off {
            changes.append(safeSearchChange())
        }
        if installAdBlocker {
            changes.append(adBlockerChange())
        }
        if blockThirdPartyCookies {
            changes.append(cookieChange())
        }
        if educationalBookmarks {
            changes.append(bookmarkChange())
        }

        if installWARP {
            changes.append(warpChange())
        }
        if mode == .advanced {
            changes += [guestChange(), consoleChange(), remoteLoginChange()]
            if createAccount {
                changes.append(accountChange())
            }
        }
        return changes
    }

    /// Nothing at all is changed until the profile is installed by hand, which
    /// is worth stating up front in a dry run.
    var summaryLine: String {
        let count = descriptions().count
        let sensitive = descriptions().filter { $0.impact == .sensitive }.count
        if sensitive > 0 {
            return "\(count) changes, \(sensitive) of which affect user accounts or startup settings."
        }
        return "\(count) changes. None of them touch user accounts, passwords, or FileVault."
    }

    // MARK: - Individual descriptions

    private func dnsChange() -> ChangeDescription {
        let social = backend.blocksSocialMediaByCategory
        return ChangeDescription(
            title: "Send all web lookups through a filtering service",
            whatChanges: "This Mac will ask \(backend.displayName) to look up website addresses, over an encrypted connection, instead of whichever service the current network provides.",
            whatTheyWillNotice: social
                ? "Adult, malware, and social-media sites stop loading. Everything else is unchanged, including on other Wi-Fi networks."
                : "Adult and malware sites stop loading. Everything else is unchanged, including on other Wi-Fi networks.",
            howToUndo: "Remove the profile in System Settings › General › Device Management.",
            impact: .restrictive,
            affects: ["Network DNS settings (all network connections)"]
        )
    }

    private func profileChange() -> ChangeDescription {
        ChangeDescription(
            title: "Add a configuration profile",
            whatChanges: "A file is saved to your Downloads folder. macOS does not let apps install these, so nothing takes effect until you double-click it and approve it yourself.",
            whatTheyWillNotice: "A “Family Safety” entry appears in System Settings › General › Device Management.",
            howToUndo: "Select it in Device Management and click Remove (requires an administrator password).",
            impact: .additive,
            affects: ["~/Downloads/Family-Safety.mobileconfig"]
        )
    }

    private func browserChange() -> ChangeDescription {
        ChangeDescription(
            title: "Lock browser settings that could skip the filter",
            whatChanges: "Chrome and Firefox are told not to use their own private address-lookup feature, not to allow private/incognito windows, and not to install extensions.",
            whatTheyWillNotice: "In Chrome and Firefox some settings appear greyed out and marked as managed. Incognito and private windows are unavailable.",
            howToUndo: "Remove the profile; the browsers go back to normal on next launch.",
            impact: .restrictive,
            affects: ["Chrome policy", "Firefox policy", "Safari content filter"]
        )
    }

    private func hostsChange() -> ChangeDescription {
        let count = blockedSites.flatMap(\.allHosts).count
        return ChangeDescription(
            title: "Add \(count) sites to the system block list",
            whatChanges: "\(count) website addresses are added to the Mac's hosts file so they point nowhere. The original file is backed up first.",
            whatTheyWillNotice: "Those specific sites fail to load in every app, not just browsers.",
            howToUndo: "The app's block is marked with comments and can be deleted; a backup is kept at \(Hardening.hostsBackupPath).",
            impact: .restrictive,
            affects: ["/etc/hosts", Hardening.hostsBackupPath]
        )
    }

    private func safeSearchChange() -> ChangeDescription {
        var what: [String] = []
        if forceSafeSearch { what.append("Google searches always use SafeSearch") }
        if youTubeLevel != .off {
            what.append("YouTube runs in \(youTubeLevel == .strict ? "strict" : "moderate") restricted mode")
        }
        return ChangeDescription(
            title: "Force safe search on Google and YouTube",
            whatChanges: what.joined(separator: ", and ") + ". This filters results inside those sites rather than blocking them.",
            whatTheyWillNotice: "Explicit results and videos are hidden. Google and YouTube otherwise work normally."
                + (youTubeLevel == .strict ? " Strict mode also hides some legitimate educational videos." : ""),
            howToUndo: "Use Undo All Changes, or remove the entries from the hosts file.",
            impact: .restrictive,
            affects: ["/etc/hosts", "Chrome and other Chromium browser policies"]
        )
    }

    private func adBlockerChange() -> ChangeDescription {
        ChangeDescription(
            title: "Install an ad blocker in Chrome",
            whatChanges: "uBlock Origin Lite is installed into Chrome automatically. All other extensions remain blocked.",
            whatTheyWillNotice: "Far fewer ads, and pages load faster. Chrome will show that the extension was installed by an administrator.",
            howToUndo: "Use Undo All Changes, or remove the configuration profile.",
            impact: .additive,
            affects: ["Chrome extensions"]
        )
    }

    private func cookieChange() -> ChangeDescription {
        ChangeDescription(
            title: "Block third-party cookies in Chrome",
            whatChanges: "Chrome stops accepting cookies set by sites other than the one being visited. Safari already does this by default.",
            whatTheyWillNotice: "Less cross-site ad tracking. Signing in to sites still works normally.",
            howToUndo: "Use Undo All Changes, or remove the configuration profile.",
            impact: .restrictive,
            affects: ["Chrome cookie settings"]
        )
    }

    private func bookmarkChange() -> ChangeDescription {
        ChangeDescription(
            title: "Add educational bookmarks to Chrome",
            whatChanges: "Adds a read-only “\(ManagedBookmark.folderName)” folder containing \(ManagedBookmark.educational.count) reference sites such as Khan Academy and Wikipedia.",
            whatTheyWillNotice: "A new bookmarks folder in Chrome that they cannot delete. Nothing else changes, and nothing is blocked by this.",
            howToUndo: "Use Undo All Changes, or remove the configuration profile.",
            impact: .additive,
            affects: ["Chrome bookmarks"]
        )
    }

    private func warpChange() -> ChangeDescription {
        ChangeDescription(
            title: "Install the Cloudflare WARP app",
            whatChanges: "Downloads Cloudflare's WARP client (about 150 MB) and installs it. The download's signature is checked against Cloudflare's certificate first, and installation is refused if it does not match.",
            whatTheyWillNotice: "A new app in /Applications and a WARP icon in the menu bar. Filtering then applies on any network, including a phone hotspot.",
            howToUndo: "Uninstall “Cloudflare WARP” from /Applications.",
            impact: .additive,
            affects: ["/Applications/Cloudflare WARP.app"]
        )
    }

    private func guestChange() -> ChangeDescription {
        ChangeDescription(
            title: "Turn off the Guest account",
            whatChanges: "The Guest login option is disabled.",
            whatTheyWillNotice: "“Guest User” no longer appears at the login screen.",
            howToUndo: "System Settings › Users & Groups, or run `sysadminctl -guestAccount on`.",
            impact: .restrictive,
            affects: ["Login window"]
        )
    }

    private func consoleChange() -> ChangeDescription {
        ChangeDescription(
            title: "Turn off console login",
            whatChanges: "Stops the trick of typing “>console” at the login screen to reach a text-only root prompt.",
            whatTheyWillNotice: "Nothing during normal use.",
            howToUndo: "Delete the DisableConsoleAccess setting from the login window preferences.",
            impact: .restrictive,
            affects: ["/Library/Preferences/com.apple.loginwindow"]
        )
    }

    private func remoteLoginChange() -> ChangeDescription {
        ChangeDescription(
            title: "Turn off remote login (SSH)",
            whatChanges: "Disables connecting to this Mac remotely over SSH.",
            whatTheyWillNotice: "Nothing, unless you currently connect to this Mac from another computer.",
            howToUndo: "System Settings › General › Sharing › Remote Login, or `systemsetup -setremotelogin on`.",
            impact: .restrictive,
            affects: ["Remote Login sharing service"]
        )
    }

    /// The one change that carries real risk, described as such.
    private func accountChange() -> ChangeDescription {
        ChangeDescription(
            title: "Create a standard account “\(accountUsername)”",
            whatChanges: "Creates a new user account without administrator rights. You will be asked to set its password.",
            whatTheyWillNotice: "A new user at the login screen. That user cannot change network settings, install apps, or remove this profile — which is what keeps the rest of this in place.",
            howToUndo: "Delete the account in System Settings › Users & Groups. Existing accounts are not modified.",
            impact: .sensitive,
            affects: ["/Users/\(accountUsername)", "Local user database"]
        )
    }
}
