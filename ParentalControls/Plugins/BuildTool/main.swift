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

        options.resolvedVersion = try resolveVersion(
            options: options, packageDirectory: context.package.directoryURL
        )

        Log.heading("Family Safety build")
        Log.detail("source", context.package.directoryURL.path)
        Log.detail("version", options.resolvedVersion.description)
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
            if options.publish {
                try publishRelease(package, build: build, options: options)
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

    // MARK: - Version

    /// Decides the version for this build and persists it to VERSION.
    ///
    /// Not bumped for a plain local build: iterating should not churn the file.
    /// Always bumped when publishing, because two releases sharing a version
    /// leave people unable to tell which build they have.
    private func resolveVersion(options: Options, packageDirectory: URL) throws -> Version {
        let current = try Version.current(in: packageDirectory)

        if let explicit = options.explicitVersion {
            guard let version = Version(explicit) else {
                throw BuildError.usage("--version must look like 1.0.1 (got '\(explicit)').")
            }
            try version.write(to: packageDirectory)
            return version
        }

        guard options.bumpVersion else { return current }

        let next = current.nextPatch
        try next.write(to: packageDirectory)
        Log.detail("bumped", "\(current) -> \(next)")
        return next
    }

    // MARK: - Publishing

    /// Creates a GitHub release from the built package.
    ///
    /// Uses the `gh` CLI rather than the REST API directly: it already holds
    /// the user's credentials, so the plugin never handles a token.
    private func publishRelease(_ package: URL, build: BuildEnvironment, options: Options) throws {
        let version = options.resolvedVersion
        Log.step("Publishing \(version.tag) to \(options.repository)")

        guard let gh = try? build.plugin.tool(named: "gh") else {
            throw BuildError.step("""
                The GitHub CLI (gh) was not found. Install it with `brew install gh` \
                and authenticate with `gh auth login`.
                """)
        }

        // Refuse rather than clobber: overwriting a published release changes
        // what people already downloaded under that version.
        let existing = try? build.run(
            url: gh.url,
            ["release", "view", version.tag, "--repo", options.repository],
            describing: "checking for an existing release"
        )
        if existing != nil {
            throw BuildError.step("""
                \(version.tag) already exists in \(options.repository). \
                Bump the version or delete the release first.
                """)
        }

        // Checksums let people verify a download that macOS will not vouch for.
        let checksums = try checksumFile(for: package, in: build)

        let notes = try releaseNotes(options: options, in: build)
        try build.run(url: gh.url, [
            "release", "create", version.tag,
            package.path,
            checksums.path,
            "--repo", options.repository,
            "--title", "\(version.tag) — \(options.mode.capitalized) Mode installer",
            "--notes-file", notes.path,
        ], describing: "creating the release")

        Log.detail("released", "https://github.com/\(options.repository)/releases/tag/\(version.tag)")
    }

    private func checksumFile(for package: URL, in build: BuildEnvironment) throws -> URL {
        let output = try build.run(
            "shasum", ["-a", "256", package.path],
            describing: "computing the checksum"
        )
        // Rewrite the absolute path to a bare filename, which is what
        // `shasum -c SHA256SUMS.txt` expects next to the downloaded file.
        let digest = output.split(separator: " ").first.map(String.init) ?? ""
        guard digest.count == 64 else {
            throw BuildError.step("could not parse a SHA-256 digest from: \(output)")
        }
        let file = build.artifactsDirectory.appendingPathComponent("SHA256SUMS.txt")
        try "\(digest)  \(package.lastPathComponent)\n"
            .write(to: file, atomically: true, encoding: .utf8)
        return file
    }

    /// Release notes, generated so they cannot drift from what was built.
    private func releaseNotes(options: Options, in build: BuildEnvironment) throws -> URL {
        let signed = options.installerIdentity != nil
        let notarized = options.notarize

        var text = """
            ## \(options.mode.capitalized) Mode installer

            Version \(options.resolvedVersion) · macOS 14 or later.

            """

        if notarized {
            text += """

                Download `Family-Safety.pkg` and double-click it.

                """
        } else {
            // Being wrong about this once already cost a support round: the
            // right-click trick works for .app bundles, not for .pkg files.
            text += """

                ### ⚠️ Not notarized — install from Terminal

                macOS refuses to open an unsigned `.pkg` and offers no
                click-through. Right-click → Open works for apps but **not** for
                installer packages, and clearing the quarantine flag does not
                help either — the missing signature is what Gatekeeper objects
                to.

                ```bash
                shasum -a 256 ~/Downloads/Family-Safety.pkg   # compare with SHA256SUMS.txt
                sudo installer -pkg ~/Downloads/Family-Safety.pkg -target /
                ```

                `/usr/sbin/installer` does not consult Gatekeeper. Alternatively
                build from source — a locally built package is never quarantined:

                ```bash
                swift package --allow-writing-to-package-directory build-family-safety
                sudo installer -pkg build/Family-Safety.pkg -target /
                ```

                """
        }

        text += """

            ### What it installs

            - **Family Safety Setup.app** into `/Applications` — the wizard,
              with a preview mode and **Undo All Changes**
            - Encrypted DNS filtering via Cloudflare for Families (`1.1.1.3`)
            - Blocks social media and AI chatbots
            - Forces Google SafeSearch and YouTube restricted mode
            - Hardens Chrome, Brave, Edge, Vivaldi, Opera and Firefox
            - Installs uBlock Origin Lite

            ### One manual step

            macOS does not let anything install a configuration profile
            automatically. Open `/Users/Shared/Family-Safety.mobileconfig`, then
            approve it in **System Settings › General › Device Management**.

            ### Honest limitations

            A phone hotspot bypasses all of this and no macOS setting can
            prevent it. [BYPASS-NOTES.md](https://github.com/\(options.repository)/blob/main/docs/BYPASS-NOTES.md)
            ranks every bypass by likelihood and says which have no fix.

            """

        if !signed {
            text += """

                _This build is ad-hoc signed. Notarized releases will install by
                double-clicking._

                """
        }

        let file = build.artifactsDirectory.appendingPathComponent("RELEASE_NOTES.md")
        try text.write(to: file, atomically: true, encoding: .utf8)
        return file
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
        try InfoPlist(version: options.resolvedVersion.description).data().write(to: plist)

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

        // The package installs the app as well as applying the configuration.
        // Without it there is no way to verify what happened or to undo it, and
        // an installer that cannot be reversed is one nobody should be asked to
        // trust.
        let payload = build.artifactsDirectory.appendingPathComponent("payload")
        try? FileManager.default.removeItem(at: payload)
        try FileManager.default.createDirectory(at: payload, withIntermediateDirectories: true)
        try FileManager.default.copyItem(
            at: app, to: payload.appendingPathComponent(app.lastPathComponent)
        )

        let output = build.artifactsDirectory.appendingPathComponent("\(BuildEnvironment.appName).pkg")
        try? FileManager.default.removeItem(at: output)
        try build.run("pkgbuild", [
            "--root", payload.path,
            "--install-location", "/Applications",
            "--scripts", scripts.path,
            "--identifier", BuildEnvironment.packageIdentifier,
            "--version", options.resolvedVersion.description,
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
