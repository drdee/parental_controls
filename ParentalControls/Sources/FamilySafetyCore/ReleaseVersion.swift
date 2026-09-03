import Foundation

/// A semantic version, for comparing what is running against what is released.
///
/// The build plugin has its own `Version` with the same parsing rules. That
/// duplication is deliberate rather than an oversight: a SwiftPM command
/// plugin cannot depend on a library target in its own package, so there is no
/// way to share the type. The plugin's copy also carries build concerns this
/// one should not have — reading and writing the VERSION file, and throwing
/// `BuildError`. Keep the parsing rules in step if either changes.
public struct ReleaseVersion: Comparable, CustomStringConvertible, Sendable {
    public var major: Int
    public var minor: Int
    public var patch: Int

    public init(major: Int, minor: Int, patch: Int) {
        self.major = major
        self.minor = minor
        self.patch = patch
    }

    /// Parses `1.2.3`, `1.2`, or a `v`-prefixed tag such as `v1.2.3`.
    ///
    /// Tolerates the `v` because that is the form GitHub reports in
    /// `tag_name`, and a leading `v` should not read as "no update".
    public init?(_ string: String) {
        var text = string.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasPrefix("v") || text.hasPrefix("V") {
            text = String(text.dropFirst())
        }
        let parts = text.split(separator: ".").map(String.init)
        guard (2...3).contains(parts.count) else { return nil }
        let numbers = parts.compactMap { Int($0) }
        guard numbers.count == parts.count, numbers.allSatisfy({ $0 >= 0 }) else { return nil }
        self.major = numbers[0]
        self.minor = numbers[1]
        self.patch = numbers.count == 3 ? numbers[2] : 0
    }

    public var description: String { "\(major).\(minor).\(patch)" }

    public static func < (lhs: ReleaseVersion, rhs: ReleaseVersion) -> Bool {
        (lhs.major, lhs.minor, lhs.patch) < (rhs.major, rhs.minor, rhs.patch)
    }

    /// The version of the running app, read from its bundle.
    ///
    /// Returns nil outside a bundle — in tests, or when the executable is run
    /// directly rather than from the .app — so callers can skip the update
    /// check instead of comparing against a fabricated version.
    public static func current(in bundle: Bundle = .main) -> ReleaseVersion? {
        guard let raw = bundle.infoDictionary?["CFBundleShortVersionString"] as? String else {
            return nil
        }
        return ReleaseVersion(raw)
    }
}
