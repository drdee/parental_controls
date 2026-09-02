import Foundation

/// One environment check, shown to the user before anything is changed.
public struct PreflightCheck: Identifiable, Sendable {
    public enum Status: Sendable {
        case pass
        case warn
        case fail
    }

    public var id: String { title }
    public var title: String
    public var status: Status
    public var detail: String
    /// Why it matters, for anything not obviously self-explanatory.
    public var rationale: String?
}

/// Inspects the machine before we touch it.
///
/// Nothing here mutates state; it exists so the user sees an accurate picture
/// (and so Advanced Mode refuses to run somewhere it could do harm).
public struct Preflight: Sendable {
    public init(runner: any CommandRunning) {
        self.runner = runner
    }

    public var runner: any CommandRunning

    public func runAll(mode: RunMode) -> [PreflightCheck] {
        var checks = [
            macOSVersion(),
            architecture(),
            isAdmin(),
            fileVault(),
            gatekeeper(),
            existingProfile(),
        ]
        if mode == .advanced {
            checks.append(applicationsPermissions())
        }
        return checks
    }

    /// True if nothing outright blocks the run.
    public func canProceed(_ checks: [PreflightCheck]) -> Bool {
        !checks.contains { $0.status == .fail }
    }

    // MARK: - Individual checks

    /// The minimum macOS this configuration needs.
    ///
    /// Driven by the payloads, not by taste: `com.apple.dnsSettings.managed`
    /// was introduced in macOS 11, and the newest key we set
    /// (`allowiPhoneMirroring`) in macOS 15. Below 15 the profile still
    /// installs — unsupported keys in an *Apple-documented* payload are
    /// ignored, unlike keys macOS does not know at all — so this is a warning
    /// rather than a hard stop.
    static let recommendedMajorVersion = 15
    static let minimumMajorVersion = 11

    private func macOSVersion() -> PreflightCheck {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        let text = "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"

        // Include the build, because Apple's build numbers and the Darwin
        // kernel version both start with a different number from the product
        // version — macOS 26 reports build 25xxx and Darwin 25.x — which is a
        // common source of confusion about which OS a Mac is running.
        let build = runner.probe("/usr/bin/sw_vers", ["-buildVersion"]).output
        let detail = build.isEmpty ? "macOS \(text)" : "macOS \(text) (build \(build))"

        if version.majorVersion < Self.minimumMajorVersion {
            return PreflightCheck(
                title: "macOS version",
                status: .fail,
                detail: detail,
                rationale: "Encrypted DNS profiles need macOS \(Self.minimumMajorVersion) or later."
            )
        }
        if version.majorVersion < Self.recommendedMajorVersion {
            return PreflightCheck(
                title: "macOS version",
                status: .warn,
                detail: detail,
                rationale: "Everything works, but a few restrictions need macOS "
                    + "\(Self.recommendedMajorVersion) or later and will be ignored on this version."
            )
        }
        return PreflightCheck(title: "macOS version", status: .pass, detail: detail, rationale: nil)
    }

    private func architecture() -> PreflightCheck {
        let arch = runner.probe("/usr/bin/uname", ["-m"]).output
        return PreflightCheck(
            title: "Architecture",
            status: .pass,
            detail: arch.isEmpty ? "unknown" : arch,
            rationale: arch == "arm64"
                ? "Apple Silicon: Recovery and boot changes require an admin password, which is what keeps this configuration in place."
                : nil
        )
    }

    private func isAdmin() -> PreflightCheck {
        let user = NSUserName()
        let result = runner.probe("/usr/sbin/dseditgroup",
                                  ["-o", "checkmember", "-m", user, "admin"])
        let isAdmin = result.output.contains("yes")
        return PreflightCheck(
            title: "Running as administrator",
            status: isAdmin ? .pass : .fail,
            detail: isAdmin ? "\(user) is an admin" : "\(user) is not an admin",
            rationale: isAdmin ? nil : "Installing a profile and changing system settings needs an admin account."
        )
    }

    private func fileVault() -> PreflightCheck {
        let output = runner.probe("/usr/bin/fdesetup", ["status"]).output
        let on = output.contains("FileVault is On")
        return PreflightCheck(
            title: "FileVault",
            status: on ? .pass : .warn,
            detail: output.isEmpty ? "unknown" : output,
            rationale: on ? nil : "Without FileVault the disk can be read and modified by booting from Recovery or a USB drive, which undoes everything here. Turn it on in System Settings › Privacy & Security."
        )
    }

    private func gatekeeper() -> PreflightCheck {
        let output = runner.probe("/usr/sbin/spctl", ["--status"]).output
        let enabled = output.contains("assessments enabled")
        return PreflightCheck(
            title: "Gatekeeper",
            status: enabled ? .pass : .warn,
            detail: output.isEmpty ? "unknown" : output,
            rationale: enabled ? nil : "Gatekeeper is disabled, so unsigned apps can run freely."
        )
    }

    /// A previous install of our own profile, so we can say "this will replace it".
    private func existingProfile() -> PreflightCheck {
        let output = runner.probe("/usr/bin/profiles", ["list", "-type=configuration"]).output
        let present = output.contains(ProfileIdentity.listingMarker)
        return PreflightCheck(
            title: "Existing profile",
            status: .pass,
            detail: present ? "A Family Safety profile is already installed" : "None installed",
            rationale: present ? "Installing again replaces the existing profile." : nil
        )
    }

    /// `/Applications` should be `root:admin` with group write and no world
    /// write — that is what actually stops a standard user installing apps.
    private func applicationsPermissions() -> PreflightCheck {
        let output = runner.probe("/usr/bin/stat", ["-f", "%Su:%Sg %Sp", "/Applications"]).output
        let expected = output.hasPrefix("root:admin") && !output.hasSuffix("w-")
        return PreflightCheck(
            title: "/Applications permissions",
            status: expected ? .pass : .warn,
            detail: output.isEmpty ? "unknown" : output,
            rationale: expected
                ? "Standard users cannot install apps here."
                : "Unexpected permissions — a standard user may be able to install apps."
        )
    }
}

public extension Preflight {
    /// Runs every check off the main thread; each one shells out.
    public func runAllAsync(mode: RunMode) async -> [PreflightCheck] {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: runAll(mode: mode))
            }
        }
    }
}
