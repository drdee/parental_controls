import PackagePlugin
import Foundation

/// `swift package build-family-safety` — the whole build, in Swift.
///
/// Replaces the previous pair of bash scripts. Everything the build needs is
/// already available to a command plugin: `context.tool(named:)` resolves
/// system tools, processes can be spawned, and the package directory is
/// writable when the permission is granted.
///
/// Steps, in order:
///   1. Build the executable in release configuration
///   2. Wrap it in an .app bundle with a generated Info.plist
///   3. Code-sign the bundle
///   4. Generate the installer's postinstall by asking the app itself
///   5. Build, sign and optionally notarize the .pkg
@main
struct BuildTool: CommandPlugin {

    func performCommand(context: PluginContext, arguments: [String]) async throws {
        var options = try Options(arguments: arguments)
        let build = BuildEnvironment(context: context)

        if options.showHelp {
            print(Options.usage)
            return
        }

        Log.heading("Family Safety build")
        Log.detail("source", context.package.directoryURL.path)
        Log.detail("mode", options.mode)
        Log.detail("artifacts", build.artifactsDirectory.path)

        try build.prepareArtifactsDirectory()

        let executable = try buildExecutable(build)
        let app = try assembleApp(build, executable: executable, options: options)
        try sign(app, build: build, options: &options)

        if options.buildPackage {
            let package = try buildInstaller(build, app: app, options: options)
            try signPackage(package, build: build, options: options)
            if options.notarize {
                try await notarize(package, build: build, options: options)
            }
        }

        Log.heading("Done")
        for artifact in try build.artifacts() {
            Log.detail(artifact.label, artifact.description)
        }
        if !options.isSigned {
            Log.warning("""
                This build is ad-hoc signed, so it will warn on other Macs. \
                Pass --identity to sign with a Developer ID.
                """)
        }
    }

    // MARK: - Steps

    /// Builds the release executable through SwiftPM itself rather than
    /// shelling out, so the plugin uses the same build graph as `swift build`.
    private func buildExecutable(_ build: BuildEnvironment) throws -> URL {
        Log.step("Building executable (release)")
        let result = try packageManager.build(
            PackageManager.BuildSubset.product(BuildEnvironment.productName),
            parameters: PackageManager.BuildParameters(
                configuration: .release,
                logging: .concise
            )
        )
        guard result.succeeded else {
            throw BuildError.step("build failed:\n" + result.logText)
        }
        guard let artifact = result.builtArtifacts.first(where: { $0.kind == .executable }) else {
            throw BuildError.step("the build produced no executable")
        }
        Log.detail("executable", artifact.url.path)
        return artifact.url
    }

    /// Lays out the `.app` bundle and writes its `Info.plist`.
    ///
    /// SwiftPM produces a bare binary; macOS needs a bundle for a
    /// double-clickable, signable, sandbox-aware app.
    private func assembleApp(
        _ build: BuildEnvironment,
        executable: URL,
        options: Options
    ) throws -> URL {
        Log.step("Assembling \(BuildEnvironment.appName)")

        let app = build.artifactsDirectory.appendingPathComponent("\(BuildEnvironment.appName).app")
        let macOS = app.appendingPathComponent("Contents/MacOS")
        try? FileManager.default.removeItem(at: app)
        try FileManager.default.createDirectory(at: macOS, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(
            at: app.appendingPathComponent("Contents/Resources"),
            withIntermediateDirectories: true
        )
        try FileManager.default.copyItem(
            at: executable,
            to: macOS.appendingPathComponent(BuildEnvironment.productName)
        )

        let plist = app.appendingPathComponent("Contents/Info.plist")
        try InfoPlist(version: options.version).data().write(to: plist)

        // A malformed Info.plist yields a bundle that silently will not launch.
        try build.run("plutil", ["-lint", plist.path], describing: "validating Info.plist")

        Log.detail("bundle", app.path)
        return app
    }

    private func sign(_ app: URL, build: BuildEnvironment, options: inout Options) throws {
        let identity = options.resolvedAppIdentity
        Log.step("Signing app with \(options.isSigned ? identity : "an ad-hoc signature")")

        // --options runtime enables the hardened runtime, which notarization
        // requires. Unlike the App Store sandbox it does not block the
        // privileged operations this app performs.
        var arguments = ["--force", "--sign", identity, "--options", "runtime"]
        if options.isSigned {
            arguments += ["--timestamp"]
        } else {
            arguments += ["--timestamp=none"]
        }
        arguments.append(app.path)
        try build.run("codesign", arguments, describing: "signing")
        try build.run("codesign", ["--verify", "--strict", app.path], describing: "verifying signature")
    }

    /// Asks the app to emit its own `postinstall`.
    ///
    /// The script must come from the same `Hardening.steps` the review screen
    /// displays, or what a parent previews and what actually runs could drift
    /// apart.
    private func buildInstaller(
        _ build: BuildEnvironment,
        app: URL,
        options: Options
    ) throws -> URL {
        Log.step("Generating installer scripts (mode: \(options.mode))")

        let scripts = build.artifactsDirectory.appendingPathComponent("scripts")
        try? FileManager.default.removeItem(at: scripts)
        try FileManager.default.createDirectory(at: scripts, withIntermediateDirectories: true)

        let executable = app.appendingPathComponent("Contents/MacOS/\(BuildEnvironment.productName)")
        try build.run(
            url: executable,
            ["--emit-package-scripts", options.mode, scripts.path],
            describing: "emitting package scripts"
        )

        let postinstall = scripts.appendingPathComponent("postinstall")
        guard FileManager.default.fileExists(atPath: postinstall.path) else {
            throw BuildError.step("the app did not emit a postinstall script")
        }
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: postinstall.path
        )

        // Check the syntax here: a broken script would otherwise fail at
        // install time, after the user has already authenticated.
        try build.run("bash", ["-n", postinstall.path], describing: "checking script syntax")

        Log.step("Building installer package")
        let output = build.artifactsDirectory.appendingPathComponent("\(BuildEnvironment.appName).pkg")
        try? FileManager.default.removeItem(at: output)
        try build.run("pkgbuild", [
            "--nopayload",                      // runs a script; installs no files
            "--scripts", scripts.path,
            "--identifier", BuildEnvironment.packageIdentifier,
            "--version", options.version,
            output.path,
        ], describing: "pkgbuild")

        Log.detail("package", output.path)
        return output
    }

    private func signPackage(_ package: URL, build: BuildEnvironment, options: Options) throws {
        guard let identity = options.installerIdentity else {
            Log.detail("package signing", "skipped (pass --installer-identity)")
            return
        }
        Log.step("Signing package with \(identity)")
        let signed = package.appendingPathExtension("signed")
        try build.run("productsign", ["--sign", identity, package.path, signed.path],
                      describing: "productsign")
        try FileManager.default.removeItem(at: package)
        try FileManager.default.moveItem(at: signed, to: package)
        try build.run("pkgutil", ["--check-signature", package.path],
                      describing: "verifying package signature")
    }

    private func notarize(_ package: URL, build: BuildEnvironment, options: Options) async throws {
        guard let credentials = options.notaryCredentials else {
            throw BuildError.usage("""
                --notarize needs --apple-id, --team-id and --notary-password \
                (an app-specific password, not your Apple Account password).
                """)
        }
        Log.step("Submitting for notarization (this waits for Apple)")
        try build.run("xcrun", [
            "notarytool", "submit", package.path,
            "--apple-id", credentials.appleID,
            "--team-id", credentials.teamID,
            "--password", credentials.password,
            "--wait",
        ], describing: "notarytool")

        Log.step("Stapling the notarization ticket")
        try build.run("xcrun", ["stapler", "staple", package.path], describing: "stapler")
        try build.run("xcrun", ["stapler", "validate", package.path], describing: "validating staple")
    }
}
