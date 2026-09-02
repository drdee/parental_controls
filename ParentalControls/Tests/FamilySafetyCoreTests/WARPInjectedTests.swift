import Testing
import Foundation
@testable import FamilySafetyCore

/// The WARP installer's privileged path.
///
/// A real run downloads 150 MB and installs a package as root, so the signature
/// gate and the failure handling are what get tested here — the gate being the
/// part that stops an arbitrary download being executed as root.
@Suite("WARP installer (injected)")
struct WARPInjectedTests {

    private func installer(_ runner: FakeRunner, installed: Bool = false) -> WARPInstaller {
        var fileSystem = FakeFileSystem.clean
        if installed {
            fileSystem.files["/Applications/Cloudflare WARP.app"] = ""
        }
        return WARPInstaller(runner: runner, fileSystem: fileSystem)
    }

    /// The signature output from a real Cloudflare package.
    private var validSignature: String {
        """
        Package "WARP.pkg":
           Status: signed by a developer certificate issued by Apple for distribution
           Notarization: trusted by the Apple notary service
           Certificate Chain:
            1. Developer ID Installer: Cloudflare Inc. (68WVV388M8)
        """
    }

    // MARK: - Detection

    @Test("An existing install is detected and its version read")
    func detectsExistingInstall() async {
        let runner = FakeRunner()
        runner.stub("defaults", stdout: "2026.7.1376.0")
        let version = await installer(runner, installed: true).installedVersionAsync()
        #expect(version == "2026.7.1376.0")
    }

    @Test("A missing install reports nil without shelling out")
    func detectsMissingInstall() async {
        let runner = FakeRunner()
        let version = await installer(runner, installed: false).installedVersionAsync()
        #expect(version == nil)
        #expect(!runner.ran("defaults"))
    }

    @Test("An install with an unreadable version still reports present")
    func handlesUnreadableVersion() async {
        let runner = FakeRunner()
        runner.stub("defaults", exitCode: 1, stderr: "does not exist")
        let version = await installer(runner, installed: true).installedVersionAsync()
        #expect(version == "unknown")
    }

    // MARK: - Signature gate

    @Test("A correctly signed and notarized package is accepted")
    func acceptsValidSignature() throws {
        let runner = FakeRunner()
        runner.stub("pkgutil", stdout: validSignature)
        #expect(throws: Never.self) {
            try installer(runner).verifySignature(of: URL(fileURLWithPath: "/tmp/x.pkg"))
        }
    }

    @Test("A package signed by anyone else is refused")
    func refusesWrongSigner() {
        let runner = FakeRunner()
        runner.stub("pkgutil", stdout: """
        Package "evil.pkg":
           Status: signed by a developer certificate issued by Apple for distribution
           Notarization: trusted by the Apple notary service
            1. Developer ID Installer: Somebody Else (ABCDE12345)
        """)
        #expect(throws: WARPInstaller.InstallError.self) {
            try installer(runner).verifySignature(of: URL(fileURLWithPath: "/tmp/x.pkg"))
        }
    }

    /// A package with the right name but the wrong team id must not pass:
    /// the team id is the actual trust anchor.
    @Test("A lookalike authority with the wrong team id is refused")
    func refusesWrongTeamID() {
        let runner = FakeRunner()
        runner.stub("pkgutil", stdout: """
           Status: signed by a developer certificate issued by Apple for distribution
           Notarization: trusted by the Apple notary service
            1. Developer ID Installer: Cloudflare Inc. (0000000000)
        """)
        #expect(throws: WARPInstaller.InstallError.self) {
            try installer(runner).verifySignature(of: URL(fileURLWithPath: "/tmp/x.pkg"))
        }
    }

    @Test("A correctly signed but un-notarized package is refused")
    func refusesUnnotarized() {
        let runner = FakeRunner()
        runner.stub("pkgutil", stdout: """
           Status: signed by a developer certificate issued by Apple for distribution
            1. Developer ID Installer: Cloudflare Inc. (68WVV388M8)
        """)
        #expect(throws: WARPInstaller.InstallError.self) {
            try installer(runner).verifySignature(of: URL(fileURLWithPath: "/tmp/x.pkg"))
        }
    }

    @Test("An unsigned package is refused")
    func refusesUnsigned() {
        let runner = FakeRunner()
        runner.stub("pkgutil", exitCode: 1, stdout: "Status: no signature")
        #expect(throws: WARPInstaller.InstallError.self) {
            try installer(runner).verifySignature(of: URL(fileURLWithPath: "/tmp/x.pkg"))
        }
    }

    // MARK: - Install

    /// The gate must run *before* anything is handed to the installer, or a
    /// hijacked download would execute as root.
    @Test("Installation is refused before running installer when unsigned")
    func doesNotInstallUnsignedPackage() async throws {
        let runner = FakeRunner()
        runner.stub("pkgutil", exitCode: 1, stdout: "no signature")

        let package = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("fake-\(UUID().uuidString).pkg")
        try "x".write(to: package, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: package) }

        await #expect(throws: WARPInstaller.InstallError.self) {
            try await installer(runner).installAsync(package: package)
        }
        #expect(!runner.ran("/usr/sbin/installer"), "installer ran on an unsigned package")
    }

    @Test("A verified package is handed to installer with its path quoted")
    func installsVerifiedPackage() async throws {
        let runner = FakeRunner()
        runner.stub("pkgutil", stdout: validSignature)

        let package = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("good-\(UUID().uuidString).pkg")
        try "x".write(to: package, atomically: true, encoding: .utf8)

        try await installer(runner).installAsync(package: package)

        let script = runner.privilegedScripts.joined()
        #expect(script.contains("/usr/sbin/installer"))
        #expect(script.contains("-target /"))
        #expect(script.contains("'\(package.path)'"), "package path is not quoted")
    }

    @Test("A failing installer is reported as a failure")
    func reportsInstallFailure() async throws {
        let runner = FakeRunner()
        runner.responses = [
            ("pkgutil", CommandResult(command: "", exitCode: 0, stdout: validSignature, stderr: "")),
            ("installer", CommandResult(command: "", exitCode: 1, stdout: "", stderr: "no space left")),
        ]
        let package = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("good-\(UUID().uuidString).pkg")
        try "x".write(to: package, atomically: true, encoding: .utf8)

        await #expect(throws: WARPInstaller.InstallError.self) {
            try await installer(runner).installAsync(package: package)
        }
    }

    /// A 150 MB file must not be left behind on a failed or rejected install.
    @Test("The downloaded package is removed even when the install fails")
    func cleansUpAfterFailure() async throws {
        let runner = FakeRunner()
        runner.stub("pkgutil", exitCode: 1, stdout: "no signature")

        let package = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("cleanup-\(UUID().uuidString).pkg")
        try "x".write(to: package, atomically: true, encoding: .utf8)

        _ = try? await installer(runner).installAsync(package: package)
        #expect(!FileManager.default.fileExists(atPath: package.path),
                "the package was left on disk")
    }

    @Test("The install command quotes a path containing an apostrophe")
    func quotesAwkwardPaths() {
        let command = WARPInstaller.installCommand(
            for: URL(fileURLWithPath: "/tmp/it's here/WARP.pkg")
        )
        #expect(command.contains("'\\''"))
        #expect(!command.contains("/tmp/it's here/WARP.pkg"), "path is unquoted")
    }

    @Test("Error messages explain what happened")
    func errorsAreDescriptive() {
        let cases: [WARPInstaller.InstallError] = [
            .untrustedPackage("detail"),
            .installFailed("detail"),
            .downloadFailed("detail"),
        ]
        for error in cases {
            #expect(error.errorDescription?.isEmpty == false)
            #expect(error.errorDescription!.contains("detail"))
        }
    }
}

/// The download path, which previously could not be exercised without pulling
/// 150 MB over the network on every run.
@MainActor
@Suite("WARP download (injected)")
struct WARPDownloadTests {

    private func state(
        downloader: any PackageDownloading,
        runner: FakeRunner
    ) -> AppState {
        var fileSystem = FakeFileSystem.clean
        fileSystem.downloads = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("warp-\(UUID().uuidString))")
        try? FileManager.default.createDirectory(at: fileSystem.downloads,
                                                 withIntermediateDirectories: true)
        let appState = AppState(runner: runner, fileSystem: fileSystem, downloader: downloader)
        appState.installWARP = true
        return appState
    }

    private var validSignature: String {
        """
           Status: signed by a developer certificate issued by Apple for distribution
           Notarization: trusted by the Apple notary service
            1. Developer ID Installer: Cloudflare Inc. (68WVV388M8)
        """
    }

    @Test("A successful download is verified and installed")
    func downloadThenInstall() async {
        let runner = FakeRunner()
        runner.stub("pkgutil", stdout: validSignature)
        let appState = state(downloader: FakeDownloader(), runner: runner)

        await appState.apply()

        let warp = appState.stepResults.first { $0.title.contains("WARP") }!
        #expect(warp.succeeded)
        #expect(warp.detail.contains("signature verified"))
        #expect(runner.privilegedScripts.contains { $0.contains("/usr/sbin/installer") })
    }

    @Test("A failed download is reported and nothing is installed")
    func downloadFailure() async {
        let runner = FakeRunner()
        let downloader = FakeDownloader(
            errorToThrow: WARPInstaller.InstallError.downloadFailed("network unreachable")
        )
        let appState = state(downloader: downloader, runner: runner)

        await appState.apply()

        let warp = appState.stepResults.first { $0.title.contains("WARP") }!
        #expect(!warp.succeeded)
        #expect(warp.detail.contains("network unreachable"))
        #expect(!runner.ran("/usr/sbin/installer"))
    }

    @Test("A download that is not from Cloudflare is never installed")
    func rejectsUntrustedDownload() async {
        let runner = FakeRunner()
        runner.stub("pkgutil", exitCode: 1, stdout: "no signature")
        let appState = state(downloader: FakeDownloader(), runner: runner)

        await appState.apply()

        let warp = appState.stepResults.first { $0.title.contains("WARP") }!
        #expect(!warp.succeeded)
        #expect(!runner.ran("/usr/sbin/installer"), "an unverified package was installed")
    }

    @Test("Download progress is reported and then cleared")
    func progressIsReported() async {
        let runner = FakeRunner()
        runner.stub("pkgutil", stdout: validSignature)
        let appState = state(downloader: FakeDownloader(progressSteps: [0, 0.25, 0.75, 1.0]),
                             runner: runner)

        await appState.apply()

        // Cleared once finished, so the UI stops showing a stale bar.
        #expect(appState.warpProgress == nil)
    }

    @Test("A WARP failure does not prevent the other steps from running")
    func warpFailureDoesNotBlockHardening() async {
        let runner = FakeRunner()
        let downloader = FakeDownloader(
            errorToThrow: WARPInstaller.InstallError.downloadFailed("offline")
        )
        let appState = state(downloader: downloader, runner: runner)

        await appState.apply()

        #expect(appState.stage == .results)
        #expect(runner.privilegedScripts.contains { $0.contains(Hardening.hostsMarkerBegin) },
                "hardening was skipped after a WARP failure")
        #expect(appState.generatedProfileURL != nil)
    }
}
