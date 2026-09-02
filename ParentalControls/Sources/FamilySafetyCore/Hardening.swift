import Foundation

public enum HardeningError: LocalizedError {
    case invalidUsername(String)

    public var errorDescription: String? {
        switch self {
        case .invalidUsername(let name):
            return "“\(name)” is not a usable account short name. Use lowercase letters, numbers, hyphen or underscore, starting with a letter."
        }
    }
}

/// A short user name that is safe to interpolate into a root shell command.
///
/// Deliberately stricter than macOS itself allows. The value ends up in a
/// script executed with administrator privileges, and the home-directory
/// argument is an unquotable bare word, so anything outside this character set
/// is refused rather than escaped.
public struct AccountName {
    public let value: String

    /// Names macOS already uses; creating one of these would be destructive.
    public static let reserved: Set<String> = [
        "root", "daemon", "nobody", "admin", "guest", "wheel", "staff",
        "_www", "system", "localhost",
    ]

    public init?(_ raw: String) {
        let candidate = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let allowed = Set("abcdefghijklmnopqrstuvwxyz0123456789-_")
        guard !candidate.isEmpty,
              candidate.count <= 31,
              candidate.allSatisfy({ allowed.contains($0) }),
              let first = candidate.first, first.isLetter,
              !Self.reserved.contains(candidate)
        else { return nil }
        self.value = candidate
    }
}

/// One system change, described before it runs.
///
/// Every step carries the exact shell command so the review screen can show
/// precisely what will happen — nothing is applied that the user has not seen.
public struct HardeningStep: Identifiable, Sendable {
    public var id: String { title }
    public var title: String
    public var explanation: String
    public var command: String
    /// Advanced Mode only. These touch accounts or login, and a mistake here is
    /// the one thing that can leave someone unable to log in.
    public var isAdvancedOnly: Bool
    /// Reverses the step, where reversal is meaningful.
    public var undoCommand: String?
}

/// The non-profile half of the configuration.
///
/// This does more real work than the profile: many restriction keys only apply
/// to supervised (MDM-enrolled) Macs and silently do nothing here, whereas file
/// permissions and account privilege are enforced by the kernel regardless.
public struct Hardening: Sendable {
    public init(runner: PrivilegedRunner, blockedSites: [BlockedSite], youTubeLevel: SafeSearch.YouTubeLevel = .moderate, forceSafeSearch: Bool = true) {
        self.runner = runner
        self.blockedSites = blockedSites
        self.youTubeLevel = youTubeLevel
        self.forceSafeSearch = forceSafeSearch
    }

    public var runner: PrivilegedRunner
    public var blockedSites: [BlockedSite]
    public var youTubeLevel: SafeSearch.YouTubeLevel = .moderate
    public var forceSafeSearch = true

    public static let hostsMarkerBegin = "# BEGIN Family Safety — managed block list"
    public static let hostsMarkerEnd = "# END Family Safety"
    public static let hostsBackupPath = "/etc/hosts.familysafety.backup"
    /// Heredoc delimiter. Chosen so no hostname can match it, but filtered for
    /// anyway — an entry equal to the delimiter would end the heredoc early and
    /// turn the remaining lines into root commands.
    public static let hostsHeredocDelimiter = "FAMILYSAFETY_HOSTS_EOF"

    /// The exact hostnames to write: valid, sanitised, deduplicated, ordered.
    ///
    /// Deduplication matters because sites overlap — `openai.com` is listed
    /// under `chatgpt.com`, so a parent adding it explicitly would otherwise
    /// produce two identical `/etc/hosts` lines.
    public static func hostsToWrite(for sites: [BlockedSite]) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for host in sites.filter(\.isValid).flatMap(\.allHosts) {
            let clean = BlockedSite.sanitize(host)
            guard !clean.isEmpty,
                  clean.contains("."),
                  clean != hostsHeredocDelimiter,
                  seen.insert(clean).inserted
            else { continue }
            out.append(clean)
        }
        return out
    }

    // MARK: - Step list

    public func steps(for mode: RunMode) -> [HardeningStep] {
        var steps: [HardeningStep] = [hostsSinkhole()]
        if mode == .advanced {
            steps += [disableGuestAccount(), disableConsoleLogin(), disableRemoteLogin()]
        }
        return steps
    }

    // MARK: - Both modes

    /// Sinkholes the named hosts in `/etc/hosts`.
    ///
    /// Belt and braces behind DNS: it applies instantly, survives a resolver
    /// hiccup, and covers apps that ignore browser policy. It is not a
    /// substitute for DNS filtering — `/etc/hosts` has no wildcard support, so
    /// only the hostnames listed here are affected.
    public func hostsSinkhole() -> HardeningStep {
        let hosts = Self.hostsToWrite(for: blockedSites)
        var lines = hosts.map { "0.0.0.0\t\($0)" }

        // SafeSearch/YouTube pinning lives in the same managed block so a
        // single undo removes all of it.
        if forceSafeSearch {
            lines += SafeSearch.googleHosts.map { "\(SafeSearch.strictAddress)\t\($0)" }
        }
        if let address = youTubeLevel.hostsAddress {
            lines += SafeSearch.youTubeHosts.map { "\(address)\t\($0)" }
        }
        let entries = lines.joined(separator: "\n")

        // Back up once, then rewrite our block in place so re-running is safe.
        let script = """
        [ -f \(Self.hostsBackupPath) ] || cp /etc/hosts \(Self.hostsBackupPath)
        /usr/bin/sed -i '' '/\(Self.hostsMarkerBegin)/,/\(Self.hostsMarkerEnd)/d' /etc/hosts
        cat >> /etc/hosts <<'\(Self.hostsHeredocDelimiter)'
        \(Self.hostsMarkerBegin)
        \(entries)
        \(Self.hostsMarkerEnd)
        \(Self.hostsHeredocDelimiter)
        /usr/bin/dscacheutil -flushcache
        /usr/bin/killall -HUP mDNSResponder 2>/dev/null || true
        """

        return HardeningStep(
            title: "Block sites in /etc/hosts",
            explanation: hostsExplanation(blockedCount: hosts.count),
            command: script,
            isAdvancedOnly: false,
            undoCommand: """
            /usr/bin/sed -i '' '/\(Self.hostsMarkerBegin)/,/\(Self.hostsMarkerEnd)/d' /etc/hosts
            /usr/bin/dscacheutil -flushcache
            /usr/bin/killall -HUP mDNSResponder 2>/dev/null || true
            """
        )
    }

    private func hostsExplanation(blockedCount: Int) -> String {
        var parts = ["Points \(blockedCount) hostnames at nowhere so they cannot load"]
        if forceSafeSearch {
            parts.append("forces Google SafeSearch")
        }
        if youTubeLevel != .off {
            parts.append("sets YouTube to \(youTubeLevel == .strict ? "strict" : "moderate") restricted mode")
        }
        return parts.joined(separator: ", ")
            + ". The original file is backed up to \(Self.hostsBackupPath) and this is reversible."
    }

    // MARK: - Advanced only

    private func disableGuestAccount() -> HardeningStep {
        HardeningStep(
            title: "Disable the Guest account",
            explanation: "A guest session would sidestep every per-account restriction.",
            command: "/usr/sbin/sysadminctl -guestAccount off",
            isAdvancedOnly: true,
            undoCommand: "/usr/sbin/sysadminctl -guestAccount on"
        )
    }

    private func disableConsoleLogin() -> HardeningStep {
        HardeningStep(
            title: "Disable console login",
            explanation: "Blocks typing “>console” at the login window to get a root shell.",
            command: "/usr/bin/defaults write /Library/Preferences/com.apple.loginwindow DisableConsoleAccess -bool true",
            isAdvancedOnly: true,
            undoCommand: "/usr/bin/defaults delete /Library/Preferences/com.apple.loginwindow DisableConsoleAccess"
        )
    }

    private func disableRemoteLogin() -> HardeningStep {
        HardeningStep(
            title: "Turn off remote login (SSH)",
            explanation: "Removes a remote path onto the machine that bypasses the login window.",
            command: "/usr/sbin/systemsetup -setremotelogin off",
            isAdvancedOnly: true,
            undoCommand: "/usr/sbin/systemsetup -setremotelogin on"
        )
    }

    // MARK: - Accounts

    /// Creates a standard (non-admin) account.
    ///
    /// This is the single most important control in the whole configuration.
    /// A standard user cannot change DNS, write to `/Applications`, remove the
    /// configuration profile, approve a VPN system extension, or enter Recovery
    /// — all of which are otherwise trivial ways around everything else here.
    ///
    /// The password is passed interactively rather than on the command line, so
    /// it never appears in the process list.
    public func createStandardAccountScript(username: String, fullName: String) throws -> String {
        // Validate before quoting. The home-directory path is a bare shell word
        // that cannot be safely quoted around interpolation, and a newline in
        // the username would otherwise start a new command line running as
        // root. Reject rather than escape.
        guard let user = AccountName(username) else {
            throw HardeningError.invalidUsername(username)
        }
        let name = shellQuoted(fullName.replacingOccurrences(of: "\n", with: " "))
        let short = shellQuoted(user.value)
        return """
        /usr/sbin/sysadminctl -addUser \(short) -fullName \(name) \
        -home \(shellQuoted("/Users/" + user.value)) -shell /bin/zsh
        /usr/sbin/dseditgroup -o edit -d \(short) -t user admin 2>/dev/null || true
        """
    }

    /// Confirms an account is genuinely non-admin. Never assume the create
    /// worked — verify.
    public func verifyStandardAccount(username: String) -> (isStandard: Bool, detail: String) {
        let result = runner.probe("/usr/sbin/dseditgroup",
                                  ["-o", "checkmember", "-m", username, "admin"])
        let output = result.output
        if output.contains("yes") {
            return (false, "\(username) IS an admin — this must be fixed.")
        }
        if output.contains("no") {
            return (true, "\(username) is a standard user.")
        }
        return (false, "Could not determine group membership: \(output)")
    }

    /// Secure Token status, which decides whether the account can unlock a
    /// FileVault volume at boot.
    ///
    /// Worth surfacing: an account with no Secure Token may be unable to log in
    /// at the pre-boot screen, so this needs testing with a real reboot before
    /// the machine is handed over.
    public func secureTokenStatus(username: String) -> String {
        runner.probe("/usr/sbin/sysadminctl", ["-secureTokenStatus", username]).output
    }

    private func shellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

public extension Hardening {
    /// Off-main-thread variants. `dseditgroup` and `sysadminctl` both block.
    public func verifyStandardAccountAsync(username: String) async -> (isStandard: Bool, detail: String) {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: verifyStandardAccount(username: username))
            }
        }
    }

    public func secureTokenStatusAsync(username: String) async -> String {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: secureTokenStatus(username: username))
            }
        }
    }
}
