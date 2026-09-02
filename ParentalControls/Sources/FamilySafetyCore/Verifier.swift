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
    public init(runner: any CommandRunning, fileSystem: any FileSystemReading = LiveFileSystem()) {
        self.runner = runner
        self.fileSystem = fileSystem
    }

    public var runner: any CommandRunning
    public var fileSystem: any FileSystemReading = LiveFileSystem()

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

    private func systemResolver() -> Verification {
        let output = runner.probe("/usr/sbin/scutil", ["--dns"]).output
        // An encrypted-DNS profile shows up as a DoH/DoT resolver entry.
        let encrypted = output.contains("cloudflare") || output.lowercased().contains("https")
        return Verification(
            title: "System resolver",
            outcome: encrypted ? .verified : .inconclusive,
            detail: encrypted ? "Encrypted DNS resolver is configured"
                              : "Could not confirm an encrypted resolver",
            remedy: encrypted ? nil : "Check System Settings › Network › Details › DNS."
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
        let filtered = resolve(Self.knownBlockedDomain, using: nil)
        let unfiltered = resolve(Self.knownBlockedDomain, using: Self.unfilteredResolver)

        let isBlocked = filtered.contains("0.0.0.0") || filtered.isEmpty
        let controlWorked = !unfiltered.isEmpty && !unfiltered.contains("0.0.0.0")

        if !controlWorked {
            return Verification(
                title: "Adult content filtering",
                outcome: .inconclusive,
                detail: "Could not reach a reference resolver to compare against",
                remedy: "Check the network connection and run verification again."
            )
        }

        return Verification(
            title: "Adult content filtering",
            outcome: isBlocked ? .verified : .notWorking,
            detail: isBlocked
                ? "Test domain is blocked by the configured resolver"
                : "Test domain still resolves — filtering is NOT active",
            remedy: isBlocked ? nil : "DNS queries are not going through the filtering resolver. If you are using Zero Trust, re-check the gateway endpoint: a mistyped ID still answers DNS but applies no policy."
        )
    }

    private func namedSitesBlocked(_ sites: [BlockedSite]) -> Verification {
        guard let first = sites.first else {
            return Verification(title: "Blocked sites", outcome: .inconclusive,
                                detail: "No sites configured", remedy: nil)
        }
        let host = "www.\(first.domain)"
        let answer = resolve(host, using: nil)
        let blocked = answer.contains("0.0.0.0") || answer.contains("127.0.0.1") || answer.isEmpty
        return Verification(
            title: "Named sites blocked",
            outcome: blocked ? .verified : .inconclusive,
            detail: blocked ? "\(host) does not resolve to a real address"
                            : "\(host) still resolves to \(answer)",
            remedy: blocked ? nil : "The DNS resolver may not block this category. Browser policy and /etc/hosts still apply — test in a browser to confirm."
        )
    }

    // MARK: - Manual steps

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

    /// Resolves `host`, optionally against a specific resolver.
    private func resolve(_ host: String, using resolver: String?) -> String {
        var arguments = ["+short", "+time=3", "+tries=1"]
        if let resolver { arguments.append("@\(resolver)") }
        arguments += [host, "A"]
        return runner.probe("/usr/bin/dig", arguments).output
            .split(separator: "\n")
            .map(String.init)
            .joined(separator: " ")
    }
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
