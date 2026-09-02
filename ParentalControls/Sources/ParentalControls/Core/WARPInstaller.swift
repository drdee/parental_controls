import Foundation

/// Downloads and installs the Cloudflare WARP client.
///
/// WARP matters for Zero Trust specifically. A bare DoH endpoint in a
/// configuration profile is readable and only covers DNS; WARP enrolled in a
/// Zero Trust organisation applies policy at the device level and tunnels
/// traffic on *any* network — which is the only thing here that reaches the
/// phone-hotspot gap.
struct WARPInstaller: Sendable {
    var runner: PrivilegedRunner

    /// Cloudflare's stable macOS channel. Redirects to a versioned .pkg.
    static let downloadURL = URL(string: "https://downloads.cloudflareclient.com/v1/download/macos/ga")!

    /// Team identifier on Cloudflare's Developer ID installer certificate,
    /// verified against a real download. The install refuses to proceed unless
    /// the package matches this — otherwise we would be running an arbitrary
    /// downloaded installer as root.
    static let expectedTeamID = "68WVV388M8"
    static let expectedAuthority = "Developer ID Installer: Cloudflare Inc."

    enum Step: Sendable {
        case alreadyInstalled(version: String)
        case downloading(bytesReceived: Int64, bytesExpected: Int64)
        case verifying
        case installing
        case done
    }

    // MARK: - Detection

    /// Existing install, if any. Avoids a 150 MB download for nothing.
    func installedVersion() -> String? {
        let path = "/Applications/Cloudflare WARP.app"
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        let plist = path + "/Contents/Info.plist"
        let result = runner.probe("/usr/bin/defaults", ["read", plist, "CFBundleShortVersionString"])
        let version = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
        return version.isEmpty ? "unknown" : version
    }

    // MARK: - Download

    /// Downloads the package to a temporary directory.
    ///
    /// Uses `URLSession.download`, which streams straight to disk — the package
    /// is ~150 MB, so neither buffering it in memory nor iterating it byte by
    /// byte is viable.
    func download(progress: @escaping @Sendable (Double) -> Void) async throws -> URL {
        let configuration = URLSessionConfiguration.ephemeral
        // A stalled connection should fail rather than hang the wizard forever.
        configuration.timeoutIntervalForRequest = 60
        configuration.timeoutIntervalForResource = 30 * 60
        let session = URLSession(configuration: configuration)
        defer { session.finishTasksAndInvalidate() }

        let delegate = DownloadProgressDelegate(onProgress: progress)
        let (temporaryURL, response) = try await session.download(
            from: Self.downloadURL,
            delegate: delegate
        )

        // Check the status before treating the body as a package: an error page
        // would otherwise be "downloaded" and then fail signature verification
        // with a misleading message.
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            try? FileManager.default.removeItem(at: temporaryURL)
            throw InstallError.downloadFailed("The server returned HTTP \(http.statusCode).")
        }

        let size = (try? FileManager.default.attributesOfItem(atPath: temporaryURL.path)[.size] as? Int) ?? 0
        // The real package is ~150 MB; anything tiny is an error page or a
        // truncated transfer.
        guard size > 10_000_000 else {
            try? FileManager.default.removeItem(at: temporaryURL)
            throw InstallError.downloadFailed("The download was only \(size) bytes, which is too small to be the installer.")
        }

        // The session's temporary file is removed as soon as this returns, so
        // move it somewhere we control.
        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent("Cloudflare_WARP_\(UUID().uuidString).pkg")
        try? FileManager.default.removeItem(at: destination)
        try FileManager.default.moveItem(at: temporaryURL, to: destination)
        return destination
    }

    // MARK: - Verification

    enum InstallError: LocalizedError {
        case untrustedPackage(String)
        case installFailed(String)
        case downloadFailed(String)

        var errorDescription: String? {
            switch self {
            case .untrustedPackage(let detail):
                return "The downloaded installer is not signed by Cloudflare and was not installed. \(detail)"
            case .installFailed(let detail):
                return "Installation failed: \(detail)"
            case .downloadFailed(let detail):
                return "Could not download Cloudflare WARP. \(detail)"
            }
        }
    }

    /// Refuses anything not signed by Cloudflare and notarized by Apple.
    ///
    /// This runs before the package is handed to `installer` as root, so a
    /// hijacked download or a redirected URL cannot get code executed.
    func verifySignature(of package: URL) throws {
        let result = runner.probe("/usr/sbin/pkgutil", ["--check-signature", package.path])
        let output = result.output

        guard result.succeeded else {
            throw InstallError.untrustedPackage("Signature check failed.")
        }
        guard output.contains(Self.expectedAuthority),
              output.contains(Self.expectedTeamID) else {
            throw InstallError.untrustedPackage("Expected \(Self.expectedAuthority) (\(Self.expectedTeamID)).")
        }
        guard output.contains("trusted by the Apple notary service") else {
            throw InstallError.untrustedPackage("Package is not notarized.")
        }
    }

    // MARK: - Install

    /// Installs the verified package. Requires one admin authorization.
    func install(package: URL) throws {
        // Remove the downloaded package however this exits, so a failed or
        // rejected install does not leave a 150 MB file behind.
        defer { try? FileManager.default.removeItem(at: package) }
        try verifySignature(of: package)

        let script = "/usr/sbin/installer -pkg \(shellQuoted(package.path)) -target /"
        let result = try runner.runPrivileged(script: script, description: "Install Cloudflare WARP")
        guard result.succeeded else {
            throw InstallError.installFailed(result.output)
        }
    }

    /// Single-quote a path for safe embedding in a shell command.
    private func shellQuoted(_ path: String) -> String {
        "'" + path.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

/// Reports download progress as a 0...1 fraction.
private final class DownloadProgressDelegate: NSObject, URLSessionDownloadDelegate, @unchecked Sendable {
    private let onProgress: @Sendable (Double) -> Void

    init(onProgress: @escaping @Sendable (Double) -> Void) {
        self.onProgress = onProgress
    }

    func urlSession(_ session: URLSession,
                    downloadTask: URLSessionDownloadTask,
                    didWriteData bytesWritten: Int64,
                    totalBytesWritten: Int64,
                    totalBytesExpectedToWrite: Int64) {
        guard totalBytesExpectedToWrite > 0 else { return }
        onProgress(Double(totalBytesWritten) / Double(totalBytesExpectedToWrite))
    }

    func urlSession(_ session: URLSession,
                    downloadTask: URLSessionDownloadTask,
                    didFinishDownloadingTo location: URL) {
        // Handled by the async/await return value.
    }
}

extension WARPInstaller {
    /// Off-main-thread variants. `installer` can run for tens of seconds and
    /// `pkgutil --check-signature` hashes a 150 MB file.
    func installAsync(package: URL) async throws {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(with: Result { try install(package: package) })
            }
        }
    }

    func installedVersionAsync() async -> String? {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: installedVersion())
            }
        }
    }
}
