import PackagePlugin
import Foundation

// MARK: - Errors

enum BuildError: LocalizedError, CustomStringConvertible {
    case usage(String)
    case step(String)
    case tool(name: String, status: Int32, output: String)

    /// The plugin host prints an error's `description`, not its
    /// `localizedDescription`, so both are provided.
    var description: String { errorDescription ?? "build failed" }

    var errorDescription: String? {
        switch self {
        case .usage(let message):
            return message + "\n\n" + Options.usage
        case .step(let message):
            return message
        case .tool(let name, let status, let output):
            let detail = output.trimmingCharacters(in: .whitespacesAndNewlines)
            return "\(name) failed (exit \(status))" + (detail.isEmpty ? "" : ":\n" + detail)
        }
    }
}

// MARK: - Options

/// Command-line options.
///
/// Parsed by hand rather than with ArgumentParser: a plugin dependency would
/// have to be fetched and built before the build could start, which is a poor
/// trade for a dozen flags.
struct Options {
    var mode = "family"
    var version = "1.0"
    var appIdentity: String?
    var installerIdentity: String?
    var buildPackage = true
    var notarize = false
    var appleID: String?
    var teamID: String?
    var notaryPassword: String?
    var showHelp = false

    /// Ad-hoc signing is enough to run locally. Deliberately never picks up an
    /// identity from the keychain automatically: a corporate certificate must
    /// not end up on a personal app by accident.
    var resolvedAppIdentity: String { appIdentity ?? "-" }
    var isSigned: Bool { appIdentity != nil }

    var notaryCredentials: (appleID: String, teamID: String, password: String)? {
        guard let appleID, let teamID, let notaryPassword else { return nil }
        return (appleID, teamID, notaryPassword)
    }

    static let usage = """
        USAGE: swift package build-family-safety [options]

        Builds the app bundle and the installer package.

        OPTIONS:
          --mode <family|advanced>   Which configuration the installer applies.
                                     Default: family (cannot lock anyone out).
          --version <version>        Bundle and package version. Default: 1.0.
          --identity <name>          Developer ID Application identity for the
                                     app. Omit for an ad-hoc signature.
          --installer-identity <n>   Developer ID Installer identity for the pkg.
          --skip-package             Build only the .app.
          --notarize                 Submit to Apple and staple the ticket.
                                     Requires the three options below.
          --apple-id <email>
          --team-id <id>
          --notary-password <pw>     An app-specific password.
          --help

        EXAMPLES:
          # Local build, ad-hoc signed
          swift package --allow-writing-to-package-directory build-family-safety

          # Release build for distribution
          swift package --allow-writing-to-package-directory build-family-safety \\
            --identity "Developer ID Application: Your Name (TEAMID)" \\
            --installer-identity "Developer ID Installer: Your Name (TEAMID)" \\
            --notarize --apple-id you@example.com --team-id TEAMID \\
            --notary-password "abcd-efgh-ijkl-mnop"
        """

    init(arguments: [String]) throws {
        var remaining = arguments[...]

        /// Consumes the value following a flag.
        func value(for flag: String) throws -> String {
            guard let next = remaining.first, !next.hasPrefix("--") else {
                throw BuildError.usage("\(flag) needs a value.")
            }
            remaining = remaining.dropFirst()
            return next
        }

        while let argument = remaining.first {
            remaining = remaining.dropFirst()
            switch argument {
            case "--mode":               mode = try value(for: argument)
            case "--version":            version = try value(for: argument)
            case "--identity":           appIdentity = try value(for: argument)
            case "--installer-identity": installerIdentity = try value(for: argument)
            case "--apple-id":           appleID = try value(for: argument)
            case "--team-id":            teamID = try value(for: argument)
            case "--notary-password":    notaryPassword = try value(for: argument)
            case "--skip-package":       buildPackage = false
            case "--notarize":           notarize = true
            case "--help", "-h":         showHelp = true
            default:
                throw BuildError.usage("Unknown option: \(argument)")
            }
        }

        guard ["family", "advanced"].contains(mode) else {
            throw BuildError.usage("--mode must be 'family' or 'advanced' (got '\(mode)').")
        }
        if notarize, installerIdentity == nil {
            throw BuildError.usage("--notarize requires --installer-identity: Apple will not notarize an unsigned package.")
        }
    }
}

// MARK: - Build environment

/// Paths and tool invocation for one build.
struct BuildEnvironment {
    static let productName = "ParentalControls"
    static let appName = "Family-Safety"
    static let packageIdentifier = "com.familysafety.setup.pkg"

    let plugin: PluginContext

    init(context: PluginContext) {
        self.plugin = context
    }

    /// Everything the build produces, inside the package directory so it is
    /// easy to find and covered by .gitignore.
    var artifactsDirectory: URL {
        plugin.package.directoryURL.appendingPathComponent("build")
    }

    func prepareArtifactsDirectory() throws {
        try FileManager.default.createDirectory(
            at: artifactsDirectory, withIntermediateDirectories: true
        )
    }

    // MARK: Running tools

    /// Runs a tool resolved by name through the plugin context.
    @discardableResult
    func run(_ toolName: String, _ arguments: [String], describing step: String) throws -> String {
        let tool = try plugin.tool(named: toolName)
        return try run(url: tool.url, arguments, describing: step, toolName: toolName)
    }

    /// Runs an executable at a known path.
    @discardableResult
    func run(
        url: URL,
        _ arguments: [String],
        describing step: String,
        toolName: String? = nil
    ) throws -> String {
        let process = Process()
        process.executableURL = url
        process.arguments = arguments

        let output = Pipe(), error = Pipe()
        process.standardOutput = output
        process.standardError = error
        try process.run()

        // Read before waiting: a tool that fills the pipe buffer would
        // otherwise deadlock against waitUntilExit().
        let outputData = output.fileHandleForReading.readDataToEndOfFile()
        let errorData = error.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        let combined = [outputData, errorData]
            .compactMap { String(data: $0, encoding: .utf8) }
            .joined()

        guard process.terminationStatus == 0 else {
            throw BuildError.tool(
                name: toolName ?? url.lastPathComponent,
                status: process.terminationStatus,
                output: combined
            )
        }
        Log.detail(step, "ok")
        return combined
    }

    // MARK: Reporting

    struct Artifact {
        var label: String
        var description: String
    }

    /// The artifacts that exist, with their sizes.
    func artifacts() throws -> [Artifact] {
        let candidates = [
            ("app", "\(Self.appName).app"),
            ("package", "\(Self.appName).pkg"),
        ]
        return candidates.compactMap { label, name in
            let url = artifactsDirectory.appendingPathComponent(name)
            guard FileManager.default.fileExists(atPath: url.path) else { return nil }
            return Artifact(label: label, description: url.path)
        }
    }
}

// MARK: - Info.plist

/// The app bundle's `Info.plist`.
///
/// Built as a typed value rather than a string template so a malformed key
/// cannot slip through — and `plutil -lint` still checks the result.
struct InfoPlist {
    var version: String

    var values: [String: Any] {
        [
            "CFBundleName": "Family Safety Setup",
            "CFBundleDisplayName": "Family Safety Setup",
            "CFBundleIdentifier": "com.familysafety.setup",
            "CFBundleExecutable": BuildEnvironment.productName,
            "CFBundlePackageType": "APPL",
            "CFBundleVersion": version,
            "CFBundleShortVersionString": version,
            "LSMinimumSystemVersion": "14.0",
            "LSApplicationCategoryType": "public.app-category.utilities",
            "NSHighResolutionCapable": true,
            // A setup tool has no business restoring windows on relaunch.
            "NSSupportsAutomaticTermination": false,
            "NSSupportsSuddenTermination": false,
        ]
    }

    func data() throws -> Data {
        try PropertyListSerialization.data(
            fromPropertyList: values, format: .xml, options: 0
        )
    }
}

// MARK: - Logging

/// Progress output. Kept quiet by default: a build log should show what
/// happened, not narrate every command.
enum Log {
    static func heading(_ text: String) {
        print("\n\(text)")
        print(String(repeating: "-", count: text.count))
    }

    static func step(_ text: String) {
        print("• \(text)")
    }

    static func detail(_ label: String, _ value: String) {
        print("    \(label.padding(toLength: max(14, label.count), withPad: " ", startingAt: 0)) \(value)")
    }

    static func warning(_ text: String) {
        print("\nwarning: \(text)")
    }
}
