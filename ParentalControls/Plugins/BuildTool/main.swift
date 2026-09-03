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

        // Before anything is built or the version is written, so a missing
        // credential does not cost a full release build to discover.
        try checkNotaryCredentials(options: options)

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
            signPackage(options: options)
            if options.notarize {
                Log.detail("notarization", "deferred to build/sign.sh (notarytool cannot reach the keychain or the network)")
            }
            // Always emitted when an identity was given, so that a build
            // without --publish still gets the script it points people at.
            try writeSigningScript(package, build: build, options: options)
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
        } else if options.buildPackage {
            Log.warning("""
                The artifacts above are still ad-hoc signed. The plugin sandbox \
                cannot reach the keychain, so run this to sign them for real:

                    \(build.artifactsDirectory.appendingPathComponent("sign.sh").path)
                """)
        } else {
            // --skip-package leaves no payload to sign, and sign.sh is built
            // around rebuilding the package, so none is written.
            Log.warning("""
                The .app above is ad-hoc signed and no signing script was \
                written, because --skip-package leaves no package to rebuild. \
                Sign it directly with:

                    codesign --force --options runtime --timestamp \\
                      --sign \(BuildEnvironment.shellQuoted(options.resolvedAppIdentity)) \\
                      \(BuildEnvironment.shellQuoted(app.path))
                """)
        }
    }

    /// Checks the generated profile against Apple's published schemas.
    ///
    /// Three payload keys and one whole payload have had to be removed after
    /// failing the *entire* profile install on a Mac without MDM. Every one was
    /// avoidable: Apple's device-management schemas state plainly which keys
    /// macOS supports and which require MDM delivery. This runs on every build
    /// so that class of bug cannot reach a release again.
    private func lintProfile(_ profile: URL, build: BuildEnvironment) throws {
        let linter = build.plugin.package.directoryURL
            .deletingLastPathComponent()
            .appendingPathComponent("tools/lint-profile.py")

        guard FileManager.default.fileExists(atPath: linter.path) else {
            Log.detail("profile lint", "skipped (tools/lint-profile.py not found)")
            return
        }

        let python = try build.plugin.tool(named: "python3")
        let process = Process()
        process.executableURL = python.url
        process.arguments = [linter.path, profile.path]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        let text = String(data: data, encoding: .utf8) ?? ""

        guard process.terminationStatus == 0 else {
            // A key macOS cannot handle does not degrade — it fails the whole
            // install with one opaque error. Better to fail the build.
            throw BuildError.step("the generated profile failed schema linting:\n" + text)
        }
        Log.detail("profile lint", "ok")
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

    // MARK: - Deferred signing

    /// Writes the signing and notarization commands that must run outside the
    /// plugin sandbox, in the order they need to happen.
    ///
    /// None of these can run inside the plugin. SwiftPM's sandbox cuts the
    /// plugin off from the keychain, which was verified directly rather than
    /// inferred: inside a plugin `security find-identity -v -p codesigning`
    /// reports "0 valid identities found" while the same command outside finds
    /// four, `productsign` fails with "Could not find appropriate signing
    /// identity" for an identity that is valid outside, and `notarytool` fails
    /// while reading its credentials — before it ever reaches the network.
    ///
    /// The app is re-signed *inside* `payload/` rather than at the top level of
    /// `build/`. `pkgbuild` reads the payload directory, so signing the copy in
    /// `build/` would leave the rebuilt package still wrapping the ad-hoc app —
    /// which is exactly what happened before this was fixed, and it would have
    /// failed notarization for a reason the log would not have explained.
    private func signingCommands(build: BuildEnvironment, package: URL, options: Options) -> [String] {
        guard let identity = options.appIdentity else { return [] }

        let payload = build.artifactsDirectory.appendingPathComponent("payload")
        let payloadApp = payload.appendingPathComponent("\(BuildEnvironment.appName).app")
        let scripts = build.artifactsDirectory.appendingPathComponent("scripts")
        let app = build.artifactsDirectory.appendingPathComponent("\(BuildEnvironment.appName).app")

        var commands = [
            "# Re-sign the app with your Developer ID (the plugin could not reach",
            "# the keychain). --options runtime enables the hardened runtime,",
            "# which notarization requires.",
            "codesign --force --options runtime --timestamp \\",
            "  --sign \(BuildEnvironment.shellQuoted(identity)) \\",
            "  \(BuildEnvironment.shellQuoted(payloadApp.path))",
            "codesign --verify --strict \(BuildEnvironment.shellQuoted(payloadApp.path))",
            "",
            "# Keep the standalone bundle in step with the one being packaged.",
            "rm -rf \(BuildEnvironment.shellQuoted(app.path))",
            "cp -R \(BuildEnvironment.shellQuoted(payloadApp.path)) \(BuildEnvironment.shellQuoted(app.path))",
            "",
            "# Rebuild the package so it contains the signed app",
            "pkgbuild --root \(BuildEnvironment.shellQuoted(payload.path)) \\",
            "  --install-location /Applications \\",
            "  --scripts \(BuildEnvironment.shellQuoted(scripts.path)) \\",
            "  --identifier \(BuildEnvironment.packageIdentifier) \\",
            "  --version \(options.resolvedVersion.description) \\",
            "  \(BuildEnvironment.shellQuoted(package.path))",
        ]
        if let installer = options.installerIdentity {
            commands += [
                "",
                "# Sign the package",
                "productsign --sign \(BuildEnvironment.shellQuoted(installer)) \\",
                "  \(BuildEnvironment.shellQuoted(package.path)) \(BuildEnvironment.shellQuoted(package.path + ".signed"))",
                "mv \(BuildEnvironment.shellQuoted(package.path + ".signed")) \(BuildEnvironment.shellQuoted(package.path))",
                "pkgutil --check-signature \(BuildEnvironment.shellQuoted(package.path))",
            ]
        }
        if options.notarize, let credentials = options.notaryCredentials {
            let arguments = credentials.arguments
                .map(BuildEnvironment.shellQuoted)
                .joined(separator: " ")
            commands += [
                "",
                "# Notarize and staple",
                "xcrun notarytool submit \(BuildEnvironment.shellQuoted(package.path)) --wait \(arguments)",
                "xcrun stapler staple \(BuildEnvironment.shellQuoted(package.path))",
                "xcrun stapler validate \(BuildEnvironment.shellQuoted(package.path))",
            ]
        }
        return commands
    }

    /// Writes a runnable script and returns its path.
    private func writeScript(
        _ name: String, body: [String], in build: BuildEnvironment
    ) throws -> URL {
        let script = build.artifactsDirectory.appendingPathComponent(name)
        try "#!/bin/bash\nset -euo pipefail\n\n\(body.joined(separator: "\n"))\n"
            .write(to: script, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: script.path
        )
        return script
    }

    /// Emits `build/sign.sh` when signing or notarizing was deferred.
    ///
    /// Written on every build that asked for a real identity, not only when
    /// publishing: `--identity` on its own used to log that signing had been
    /// deferred to a file that was never created.
    private func writeSigningScript(
        _ package: URL, build: BuildEnvironment, options: Options
    ) throws {
        let commands = signingCommands(build: build, package: package, options: options)
        guard !commands.isEmpty else { return }

        let script = try writeScript("sign.sh", body: commands, in: build)
        Log.step("Signing deferred outside the plugin sandbox")
        Log.detail("run", script.path)
    }

    // MARK: - Publishing

    /// Prepares everything a release needs and prints the command to publish it.
    ///
    /// The publish itself cannot happen here: SwiftPM runs command plugins in a
    /// sandbox with no network access, and there is no opt-in flag for it.
    /// Verified directly — curl inside a plugin fails with "Could not resolve
    /// host". So the plugin does every part it can (bump the version, build,
    /// checksum, generate notes) and hands over a single command to run.
    private func publishRelease(_ package: URL, build: BuildEnvironment, options: Options) throws {
        let version = options.resolvedVersion
        Log.step("Preparing release \(version.tag)")

        let checksums = try checksumFile(for: package, in: build)
        let notes = try releaseNotes(options: options, in: build)

        let command = """
            gh release create \(version.tag) \\
              \(package.path) \\
              \(checksums.path) \\
              --repo \(options.repository) \\
              --title \(BuildEnvironment.shellQuoted("\(version.tag) — \(options.mode.capitalized) Mode installer")) \\
              --notes-file \(notes.path)
            """

        // Written to a file as well as printed, so it can simply be run.
        // Signing has to happen here too, for the same sandbox reason — and it
        // has to come first, because the checksum below is of the unsigned
        // package and signing changes it. publish.sh recomputes it.
        let signing = signingCommands(build: build, package: package, options: options)
        let body = (signing.isEmpty ? [] : signing + [
            "",
            "# Refresh the checksum: signing and stapling rewrote the package.",
            "shasum -a 256 \(BuildEnvironment.shellQuoted(package.path)) \\",
            "  | awk '{ print $1 \"  \(package.lastPathComponent)\" }' > \(BuildEnvironment.shellQuoted(checksums.path))",
            "",
            "# Create the release",
        ]) + [command]
        let script = try writeScript("publish.sh", body: body, in: build)

        Log.detail("checksums", checksums.path)
        Log.detail("notes", notes.path)
        Log.detail("version", "VERSION is now \(version)")

        print("""

            Release \(version.tag) is ready, but SwiftPM's plugin sandbox blocks
            network access, so the upload has to run outside the plugin:

                \(script.path)

            or directly:

            \(command)

            """)
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

        try copyIcon(into: app, build: build)

        let plist = app.appendingPathComponent("Contents/Info.plist")
        try InfoPlist(version: options.resolvedVersion.description).data().write(to: plist)

        // A malformed Info.plist yields a bundle that silently will not launch.
        try build.run("plutil", ["-lint", plist.path], describing: "validating Info.plist")

        Log.detail("bundle", app.path)
        return app
    }

    /// Copies `AppIcon.icns` into the bundle, generating it if absent.
    ///
    /// The icon matters more here than it would for most apps: this one asks
    /// for an administrator password, and the authorization dialog shows the
    /// requesting app's icon. A generic binary icon on that prompt is exactly
    /// the wrong impression.
    ///
    /// Generated from `tools/make-app-icon.py` rather than committed as a
    /// binary blob, so it stays reviewable in a diff. Skipped with a warning
    /// rather than failing the build — a missing icon is cosmetic, and it
    /// should not stop someone building from source.
    private func copyIcon(into app: URL, build: BuildEnvironment) throws {
        let name = "\(InfoPlist.iconFileName).icns"
        let source = build.plugin.package.directoryURL
            .appendingPathComponent("Resources/Icon/\(name)")

        if !FileManager.default.fileExists(atPath: source.path) {
            let generator = build.plugin.package.directoryURL
                .deletingLastPathComponent()
                .appendingPathComponent("tools/make-app-icon.py")
            guard FileManager.default.fileExists(atPath: generator.path) else {
                Log.detail("icon", "skipped (no Resources/Icon/\(name))")
                return
            }
            Log.detail("icon", "generating from tools/make-app-icon.py")
            let iconset = build.artifactsDirectory.appendingPathComponent("AppIcon.iconset")
            let python = try build.plugin.tool(named: "python3")
            try build.run(url: python.url, [generator.path, "--iconset", iconset.path],
                          describing: "rendering iconset", toolName: "make-app-icon.py")
            try FileManager.default.createDirectory(
                at: source.deletingLastPathComponent(), withIntermediateDirectories: true
            )
            try build.run("iconutil", ["-c", "icns", iconset.path, "-o", source.path],
                          describing: "building icns")
            try? FileManager.default.removeItem(at: iconset)
        }

        try FileManager.default.copyItem(
            at: source,
            to: app.appendingPathComponent("Contents/Resources/\(name)")
        )
        Log.detail("icon", name)
    }

    /// Signs the app bundle.
    ///
    /// Real signing cannot happen inside the plugin: SwiftPM's plugin sandbox
    /// blocks keychain access, so `codesign` reports "no identity found" for an
    /// identity that works perfectly outside it. Verified directly.
    ///
    /// So an ad-hoc signature is applied here to produce a runnable bundle, and
    /// when an identity is given the real signing is emitted as a script to run
    /// outside the sandbox — the same arrangement as publishing.
    private func sign(_ app: URL, build: BuildEnvironment, options: inout Options) throws {
        // --options runtime enables the hardened runtime, which notarization
        // requires and which, unlike the App Store sandbox, does not block the
        // privileged operations this app performs.
        Log.step("Signing app (ad-hoc)")
        try build.run(
            "codesign",
            ["--force", "--sign", "-", "--options", "runtime", "--timestamp=none", app.path],
            describing: "ad-hoc signing"
        )
        try build.run("codesign", ["--verify", "--strict", app.path], describing: "verifying signature")

        guard options.isSigned else { return }
        // sign.sh is only written alongside a package, so do not name it here
        // when --skip-package means it will not exist.
        let destination = options.buildPackage ? "deferred to build/sign.sh" : "deferred (see the warning below)"
        Log.detail("app signing", "\(destination) (keychain is unreachable from the plugin sandbox)")
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

        // Use the executable inside the bundle we just assembled. It was
        // copied from this build's output moments ago, so it cannot be a stale
        // artifact from an earlier run.
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

        try lintProfile(
            scripts.appendingPathComponent("Family-Safety.mobileconfig"),
            build: build
        )

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

    /// Reports how the package will be signed.
    ///
    /// `productsign` cannot run here for the same reason `codesign` cannot: the
    /// plugin sandbox hides the keychain, and it fails with "Could not find
    /// appropriate signing identity" for an identity that is valid outside.
    /// The real command goes into `build/sign.sh`.
    private func signPackage(options: Options) {
        guard options.installerIdentity != nil else {
            Log.detail("package signing", "skipped (pass --installer-identity)")
            return
        }
        Log.detail("package signing", "deferred to build/sign.sh (keychain is unreachable from the plugin sandbox)")
    }

    /// Checks that notarization has credentials to use.
    ///
    /// Called before the build starts rather than after the package is built:
    /// a missing flag should not cost a full release build before it is
    /// reported. The submission itself is deferred to `build/sign.sh` —
    /// `notarytool` fails inside the sandbox while reading its credentials,
    /// before it even reaches the network.
    private func checkNotaryCredentials(options: Options) throws {
        guard options.notarize else { return }
        guard options.notaryCredentials != nil else {
            throw BuildError.usage("""
                --notarize needs credentials. Either:
                  --notary-profile <name>   (saved with notarytool store-credentials)
                or:
                  --apple-id <email> --team-id <id> --notary-password <app-specific-password>
                """)
        }
    }
}
