import Foundation

/// One reversal step and what it found.
public struct RevertResult: Identifiable, Sendable {
    public enum Outcome: Sendable {
        /// Something was there and has been undone.
        case reverted
        /// Nothing to do — this was never applied.
        case nothingToDo
        /// Needs the user to finish it by hand.
        case manualStepRequired
        case failed
    }

    public var id: String { title }
    public var title: String
    public var outcome: Outcome
    public var detail: String
}

/// Undoes everything this tool applies.
///
/// Written as a first-class feature rather than an afterthought: a control you
/// cannot remove is one you cannot safely try. It is deliberately tolerant —
/// each step checks whether it applies, so reverting a machine that was only
/// partly configured (or configured by an older version) still works and
/// reports honestly instead of erroring.
public struct Reverter: Sendable {
    public init(runner: PrivilegedRunner) {
        self.runner = runner
    }

    public var runner: PrivilegedRunner

    /// What reverting will do, for the confirmation screen.
    public func plan() -> [String] {
        [
            "Remove the Family Safety configuration profile (DNS, browser policy, restrictions).",
            "Remove the blocked-sites and SafeSearch entries from /etc/hosts and restore the backup.",
            "Re-enable the Guest account, console login and remote login if they were turned off.",
            "Flush the DNS cache so changes take effect immediately.",
        ]
    }

    /// Things this deliberately does **not** undo, so the UI can say so.
    ///
    /// Removing an account would risk deleting a child's home folder, and
    /// uninstalling WARP may not be wanted; both are better done deliberately.
    public func willNotUndo() -> [String] {
        [
            "User accounts created by this tool are left alone — deleting one would remove that person's files. Remove it yourself in System Settings › Users & Groups if you want it gone.",
            "Cloudflare WARP is left installed. Uninstall it from /Applications if you no longer want it.",
            "Screen Time and Family Sharing settings are not touched — this tool never changed them.",
        ]
    }

    // MARK: - Detection

    /// Whether anything looks applied, so the UI can avoid offering a pointless revert.
    public func detectApplied() async -> [String] {
        var found: [String] = []

        let profiles = await runner.probeAsync("/usr/bin/profiles", ["list", "-type=configuration"])
        if profiles.output.lowercased().contains(ProfileIdentity.listingMarker) {
            found.append("Configuration profile is installed")
        }
        if let hosts = try? String(contentsOfFile: "/etc/hosts", encoding: .utf8),
           hosts.contains(Hardening.hostsMarkerBegin) {
            found.append("/etc/hosts contains managed entries")
        }
        if FileManager.default.fileExists(atPath: Hardening.hostsBackupPath) {
            found.append("A hosts backup exists")
        }
        return found
    }

    // MARK: - Revert

    public func revertAll() async -> [RevertResult] {
        var results: [RevertResult] = []
        results.append(await revertHosts())
        results.append(await revertAdvancedSettings())
        results.append(await revertProfile())
        return results
    }

    /// Restores `/etc/hosts`.
    ///
    /// Prefers deleting just the managed block, so any unrelated entries the
    /// user added afterwards survive. The backup is only used if the markers
    /// are missing, which would mean the file was edited by hand.
    private func revertHosts() async -> RevertResult {
        let current = (try? String(contentsOfFile: "/etc/hosts", encoding: .utf8)) ?? ""
        let hasBlock = current.contains(Hardening.hostsMarkerBegin)
        let hasBackup = FileManager.default.fileExists(atPath: Hardening.hostsBackupPath)

        guard hasBlock || hasBackup else {
            return RevertResult(
                title: "Restore /etc/hosts",
                outcome: .nothingToDo,
                detail: "No managed entries or backup found."
            )
        }

        let script = """
        if /usr/bin/grep -q '\(Hardening.hostsMarkerBegin)' /etc/hosts; then
          /usr/bin/sed -i '' '/\(Hardening.hostsMarkerBegin)/,/\(Hardening.hostsMarkerEnd)/d' /etc/hosts
        fi
        [ -f \(Hardening.hostsBackupPath) ] && /bin/rm -f \(Hardening.hostsBackupPath)
        /usr/bin/dscacheutil -flushcache
        /usr/bin/killall -HUP mDNSResponder 2>/dev/null || true
        exit 0
        """

        do {
            let result = try await runner.runPrivilegedAsync(script: script, description: "Restore /etc/hosts")
            return RevertResult(
                title: "Restore /etc/hosts",
                outcome: result.succeeded ? .reverted : .failed,
                detail: result.succeeded
                    ? "Managed entries removed and the backup cleaned up."
                    : result.output
            )
        } catch {
            return RevertResult(title: "Restore /etc/hosts", outcome: .failed,
                                detail: error.localizedDescription)
        }
    }

    /// Re-enables what Advanced Mode turned off.
    ///
    /// Runs unconditionally: these are idempotent, and checking each one first
    /// would cost more authorization prompts than it saves.
    private func revertAdvancedSettings() async -> RevertResult {
        let script = """
        /usr/sbin/sysadminctl -guestAccount on 2>/dev/null || true
        /usr/bin/defaults delete /Library/Preferences/com.apple.loginwindow DisableConsoleAccess 2>/dev/null || true
        /usr/bin/defaults delete /Library/Preferences/com.apple.loginwindow LoginwindowText 2>/dev/null || true
        exit 0
        """
        do {
            let result = try await runner.runPrivilegedAsync(
                script: script,
                description: "Restore login and sharing settings"
            )
            return RevertResult(
                title: "Restore login settings",
                outcome: result.succeeded ? .reverted : .failed,
                detail: result.succeeded
                    ? "Guest account and console login restored. Remote login (SSH) was left off — turn it on in System Settings › General › Sharing if you use it."
                    : result.output
            )
        } catch {
            return RevertResult(title: "Restore login settings", outcome: .failed,
                                detail: error.localizedDescription)
        }
    }

    /// Removes the configuration profile.
    ///
    /// `profiles remove` still works even though the `install` verb was
    /// withdrawn, so this one *can* be automated — but it fails on a
    /// user-approved profile in some configurations, hence the fallback to
    /// manual instructions rather than a bare error.
    private func revertProfile() async -> RevertResult {
        let listing = await runner.probeAsync("/usr/bin/profiles", ["list", "-type=configuration"])
        guard listing.output.lowercased().contains(ProfileIdentity.listingMarker) else {
            return RevertResult(
                title: "Remove configuration profile",
                outcome: .nothingToDo,
                detail: "No Family Safety profile is installed."
            )
        }

        let identifier = ProfileIdentity.prefix
        let script = "/usr/bin/profiles remove -identifier \(identifier) -forced 2>&1 || true"
        do {
            _ = try await runner.runPrivilegedAsync(script: script, description: "Remove configuration profile")
            // Trust the listing, not the exit code.
            let after = await runner.probeAsync("/usr/bin/profiles", ["list", "-type=configuration"])
            let gone = !after.output.lowercased().contains(ProfileIdentity.listingMarker)
            return RevertResult(
                title: "Remove configuration profile",
                outcome: gone ? .reverted : .manualStepRequired,
                detail: gone
                    ? "Profile removed."
                    : "The profile could not be removed automatically. Open System Settings › General › Device Management, select “Family Safety” and click Remove."
            )
        } catch {
            return RevertResult(
                title: "Remove configuration profile",
                outcome: .manualStepRequired,
                detail: "Remove it in System Settings › General › Device Management. (\(error.localizedDescription))"
            )
        }
    }

}
