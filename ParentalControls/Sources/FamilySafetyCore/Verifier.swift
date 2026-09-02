import Foundation

/// One post-install verification, surfaced in the UI.
///
/// These exist because several configuration-profile keys fail *silently* on an
/// unsupervised Mac — the profile installs, reports success, and does nothing.
/// Only a functional check tells you whether filtering is actually live.
public struct Verification: Identifiable, Sendable {
    public enum Outcome: Sendable {
        case verified
        case notWorking
        case inconclusive
    }

    public var id: String { title }
    public var title: String
    public var outcome: Outcome
    public var detail: String
    /// What to do about it when it isn't working.
    public var remedy: String?
}

public struct Verifier: Sendable {
    public init(runner: any CommandRunning,
                fileSystem: any FileSystemReading = LiveFileSystem(),
                resolver: any HostResolving = SystemResolver()) {
        self.runner = runner
        self.fileSystem = fileSystem
        self.resolver = resolver
    }

    public var runner: any CommandRunning
    public var fileSystem: any FileSystemReading = LiveFileSystem()
    public var resolver: any HostResolving = SystemResolver()

    /// A domain Cloudflare's adult-content filter is known to block. Used only
    /// as a probe — comparing a filtered resolver against an unfiltered one is
    /// the only reliable way to prove filtering is active.
    private static let knownBlockedDomain = "pornhub.com"
    private static let unfilteredResolver = "1.1.1.1"
    static let managedPreferencesPath = "/Library/Managed Preferences"

    public func runAll(backend: DNSBackend, blockedSites: [BlockedSite]) -> [Verification] {
        [
            profileInstalled(),
            managedPreferencesPresent(),
            systemResolver(),
            adultContentFiltering(),
            namedSitesBlocked(blockedSites),
            screenTimeEnabled(),
            accountIsStandard(),
            fileVaultEnabled(),
        ]
    }

    // MARK: - Profile presence

    /// Whether the profile is installed.
    ///
    /// Deliberately does not use `profiles list`: without `-all` that only
    /// reports *user*-scoped profiles, and ours is device-scoped
    /// (`PayloadScope: System`), so it never appears — the check reported "not
    /// installed" on machines where the profile was installed correctly.
    /// `-all` requires root, which a verification pass should not need.
    ///
    /// `/Library/Managed Preferences/` is world-readable and is the better
    /// signal anyway: it proves the payloads actually took effect, rather than
    /// that a profile merely exists.
    private func profileInstalled() -> Verification {
        // Look for a value only this profile sets, rather than merely for the
        // domain files: a corporate MDM may manage the same domains, which
        // would otherwise read as a false positive.
        let chromePolicy = "\(Self.managedPreferencesPath)/com.google.Chrome"
        let ourMarker = runner.probe(
            "/usr/bin/defaults", ["read", chromePolicy, "DnsOverHttpsMode"]
        )
        let markerFound = ourMarker.succeeded && ourMarker.stdout.contains("off")

        let present = markerFound ? ["com.google.Chrome"] : []

        // A root-free confirmation, when it happens to be available.
        let listing = runner.probe("/usr/bin/profiles", ["list", "-type=configuration"]).output
        let listedForUser = listing.lowercased().contains(ProfileIdentity.listingMarker)

        if !present.isEmpty || listedForUser {
            return Verification(
                title: "Configuration profile installed",
                outcome: .verified,
                detail: listedForUser
                    ? "Profile is installed"
                    : "Profile is installed and its browser policy is active"
            )
        }

        return Verification(
            title: "Configuration profile installed",
            outcome: .notWorking,
            detail: "No managed preferences from this profile were found",
            remedy: "Open /Users/Shared/Family-Safety.mobileconfig, then approve it in System Settings › General › Device Management."
        )
    }

    /// A profile can install without its keys landing. If the managed-preference
    /// domains are missing, the payloads did not take effect.
    private func managedPreferencesPresent() -> Verification {
        let managed = Self.managedPreferencesPath
        let names = fileSystem.directoryContents(atPath: managed)
        let wanted = ["com.google.Chrome.plist", "org.mozilla.firefox.plist",
                      "com.apple.applicationaccess.plist"]
        let found = wanted.filter { names.contains($0) }
        return Verification(
            title: "Managed preferences applied",
            outcome: found.isEmpty ? .notWorking : (found.count == wanted.count ? .verified : .inconclusive),
            detail: found.isEmpty ? "No managed preference files found"
                                  : "Found: \(found.joined(separator: ", "))",
            remedy: found.isEmpty ? "The profile installed but its payloads did not apply. Confirm PayloadScope is System and reinstall." : nil
        )
    }

    /// Whether an encrypted resolver is actually in effect.
    ///
    /// `scutil --dns` does not report DNS-over-HTTPS at all — it lists only
    /// plaintext nameservers — so it can never confirm this. Instead this
    /// resolves a domain the filtering resolver blocks and checks the answer,
    /// which is the only observable difference.
    private func systemResolver() -> Verification {
        let blocked = resolver.addresses(for: Self.knownBlockedDomain)
        let control = resolver.addresses(for: "example.com")

        guard !control.isEmpty else {
            return Verification(
                title: "System resolver",
                outcome: .inconclusive,
                detail: "No DNS resolution at all — check the network connection",
                remedy: nil
            )
        }
        if Self.looksBlocked(blocked) {
            return Verification(
                title: "System resolver",
                outcome: .verified,
                detail: "Encrypted filtering DNS is in effect"
            )
        }
        return Verification(
            title: "System resolver",
            outcome: .notWorking,
            detail: "DNS is working but not filtering",
            remedy: "Install the configuration profile, then check System Settings › Network › DNS shows the filtering resolver."
        )
    }

    /// The load-bearing check.
    ///
    /// A mistyped Zero Trust gateway ID still answers DNS normally — any
    /// `*.cloudflare-gateway.com` hostname resolves and returns valid responses
    /// — so the endpoint cannot be validated by probing it. Comparing a
    /// known-blocked domain against an unfiltered resolver is what actually
    /// proves the filter is live.
    private func adultContentFiltering() -> Verification {
        let filtered = resolver.addresses(for: Self.knownBlockedDomain)
        // A reference lookup through dig, which bypasses DoH, tells us the
        // domain really does resolve when unfiltered — so a block is a block
        // and not just an outage.
        let unfiltered = digAddresses(Self.knownBlockedDomain, using: Self.unfilteredResolver)

        if Self.looksBlocked(filtered) {
            return Verification(
                title: "Adult content filtering",
                outcome: .verified,
                detail: "Test domain is blocked by the configured resolver"
            )
        }
        guard !unfiltered.isEmpty else {
            return Verification(
                title: "Adult content filtering",
                outcome: .inconclusive,
                detail: "Could not reach a reference resolver to compare against",
                remedy: "Check the network connection and check again."
            )
        }
        return Verification(
            title: "Adult content filtering",
            outcome: .notWorking,
            detail: "Test domain still resolves — filtering is NOT active",
            remedy: "Install the configuration profile. If you are using Zero Trust, re-check the gateway endpoint: a mistyped ID still answers DNS but applies no policy."
        )
    }

    private func namedSitesBlocked(_ sites: [BlockedSite]) -> Verification {
        guard let first = sites.first else {
            return Verification(title: "Blocked sites", outcome: .inconclusive,
                                detail: "No sites configured", remedy: nil)
        }
        let host = "www.\(first.domain)"
        let addresses = resolver.addresses(for: host)

        if Self.looksBlocked(addresses) {
            return Verification(
                title: "Named sites blocked",
                outcome: .verified,
                detail: "\(host) does not resolve to a real address"
            )
        }
        return Verification(
            title: "Named sites blocked",
            outcome: .notWorking,
            detail: "\(host) still resolves",
            remedy: "The /etc/hosts entries may not have been applied. Re-run the installer, then check again."
        )
    }

    /// Whether a set of addresses represents a block.
    ///
    /// Filtering resolvers answer with a sinkhole address rather than failing,
    /// and `/etc/hosts` entries point at 0.0.0.0, so an empty answer and a
    /// sinkholed one both mean blocked.
    static func looksBlocked(_ addresses: [String]) -> Bool {
        if addresses.isEmpty { return true }
        let sinkholes: Set<String> = ["0.0.0.0", "127.0.0.1", "::"]
        return addresses.allSatisfy(sinkholes.contains)
    }

    /// A deliberate out-of-band lookup, used only as a control.
    private func digAddresses(_ host: String, using resolverAddress: String) -> [String] {
        runner.probe("/usr/bin/dig", ["+short", "+time=3", "+tries=1", "@\(resolverAddress)", host, "A"])
            .stdout
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { $0.first?.isNumber == true }
    }

    // MARK: - Manual steps    // MARK: - Manual steps

    /// Whether Screen Time is switched on for this user.
    ///
    /// There is no API for this, so it is inferred from the Screen Time
    /// settings agent's own preferences. That makes it a hint rather than
    /// proof, which is why a negative result is `inconclusive` and not a
    /// failure — the check should never claim the parent skipped a step it
    /// cannot actually see.
    private func screenTimeEnabled() -> Verification {
        let result = runner.probe(
            "/usr/bin/defaults",
            ["-currentHost", "read", "com.apple.ScreenTimeAgent", "LastSuccessfulSyncDate"]
        )
        let familyControls = runner.probe(
            "/usr/bin/defaults",
            ["read", "/Library/Managed Preferences/com.apple.applicationaccess.new", "familyControlsEnabled"]
        )

        if familyControls.succeeded, familyControls.stdout.contains("1") {
            return Verification(
                title: "Screen Time",
                outcome: .verified,
                detail: "Screen Time restrictions are active"
            )
        }
        if result.succeeded {
            return Verification(
                title: "Screen Time",
                outcome: .inconclusive,
                detail: "Screen Time has synced, but this tool cannot confirm which restrictions are set",
                remedy: "Check Screen Time › Content & Privacy from your own device. See docs/MANUAL-STEPS.md."
            )
        }
        return Verification(
            title: "Screen Time",
            outcome: .inconclusive,
            detail: "No sign that Screen Time is set up for this user",
            remedy: "This is the highest-value step: set up Family Sharing with a Child Apple Account, then enable Screen Time from your own device so it cannot be switched off here."
        )
    }

    /// Whether the account running this is a standard user.
    ///
    /// The single most important control: an administrator can undo everything
    /// else, so a profile that installed on an admin account is far weaker than
    /// it looks.
    private func accountIsStandard() -> Verification {
        let user = NSUserName()
        let result = runner.probe("/usr/sbin/dseditgroup", ["-o", "checkmember", "-m", user, "admin"])
        let output = result.output.lowercased()

        if output.contains("yes") {
            return Verification(
                title: "Account type",
                outcome: .notWorking,
                detail: "\(user) is an administrator",
                remedy: "An admin can remove this profile and change DNS. Make a separate admin account for yourself and set this one to Standard in System Settings › Users & Groups."
            )
        }
        if output.contains("no") {
            return Verification(
                title: "Account type",
                outcome: .verified,
                detail: "\(user) is a standard user, so these settings cannot be removed here"
            )
        }
        return Verification(
            title: "Account type",
            outcome: .inconclusive,
            detail: "Could not determine whether \(user) is an administrator",
            remedy: nil
        )
    }

    /// FileVault, without which the disk can be rewritten from Recovery.
    private func fileVaultEnabled() -> Verification {
        let output = runner.probe("/usr/bin/fdesetup", ["status"]).output
        if output.contains("FileVault is On") {
            return Verification(title: "FileVault", outcome: .verified, detail: output)
        }
        return Verification(
            title: "FileVault",
            outcome: .notWorking,
            detail: output.isEmpty ? "Could not read FileVault status" : output,
            remedy: "Without FileVault the disk can be modified by booting from Recovery or a USB drive, which undoes everything here. Turn it on in System Settings › Privacy & Security."
        )
    }

    // MARK: - Helpers

}

public extension Verifier {
    /// Runs every check off the main thread. `dig` in particular can wait on a
    /// network timeout.
    public func runAllAsync(backend: DNSBackend, blockedSites: [BlockedSite]) async -> [Verification] {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: runAll(backend: backend, blockedSites: blockedSites))
            }
        }
    }
}
