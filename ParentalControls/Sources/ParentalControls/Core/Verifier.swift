import Foundation

/// One post-install verification, surfaced in the UI.
///
/// These exist because several configuration-profile keys fail *silently* on an
/// unsupervised Mac — the profile installs, reports success, and does nothing.
/// Only a functional check tells you whether filtering is actually live.
struct Verification: Identifiable, Sendable {
    enum Outcome: Sendable {
        case verified
        case notWorking
        case inconclusive
    }

    var id: String { title }
    var title: String
    var outcome: Outcome
    var detail: String
    /// What to do about it when it isn't working.
    var remedy: String?
}

struct Verifier: Sendable {
    var runner: PrivilegedRunner

    /// A domain Cloudflare's adult-content filter is known to block. Used only
    /// as a probe — comparing a filtered resolver against an unfiltered one is
    /// the only reliable way to prove filtering is active.
    private static let knownBlockedDomain = "pornhub.com"
    private static let unfilteredResolver = "1.1.1.1"

    func runAll(backend: DNSBackend, blockedSites: [BlockedSite]) -> [Verification] {
        [
            profileInstalled(),
            managedPreferencesPresent(),
            systemResolver(),
            adultContentFiltering(),
            namedSitesBlocked(blockedSites),
        ]
    }

    // MARK: - Profile presence

    private func profileInstalled() -> Verification {
        let output = runner.probe("/usr/bin/profiles", ["list", "-type=configuration"]).output
        let present = output.lowercased().contains(ProfileIdentity.listingMarker)
        return Verification(
            title: "Configuration profile installed",
            outcome: present ? .verified : .notWorking,
            detail: present ? "Family Safety profile is present" : "No Family Safety profile found",
            remedy: present ? nil : "Double-click the generated .mobileconfig, then approve it in System Settings › General › Device Management."
        )
    }

    /// A profile can install without its keys landing. If the managed-preference
    /// domains are missing, the payloads did not take effect.
    private func managedPreferencesPresent() -> Verification {
        let managed = "/Library/Managed Preferences"
        let names = (try? FileManager.default.contentsOfDirectory(atPath: managed)) ?? []
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

extension Verifier {
    /// Runs every check off the main thread. `dig` in particular can wait on a
    /// network timeout.
    func runAllAsync(backend: DNSBackend, blockedSites: [BlockedSite]) async -> [Verification] {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: runAll(backend: backend, blockedSites: blockedSites))
            }
        }
    }
}
