import Foundation

/// The parts of a GitHub release this app cares about.
public struct AvailableRelease: Sendable, Equatable {
    public var version: ReleaseVersion
    public var pageURL: URL

    public init(version: ReleaseVersion, pageURL: URL) {
        self.version = version
        self.pageURL = pageURL
    }
}

/// Fetches the latest published release. Injected so tests never touch the
/// network.
public protocol ReleaseChecking: Sendable {
    func latestRelease() async throws -> AvailableRelease
}

/// Checks whether a newer version has been published, and does nothing else.
///
/// Deliberately notify-only: it never downloads and never installs. This app
/// runs privileged operations, and a tool that can silently replace its own
/// privileged binary is precisely what a parental-control tool should not be.
/// The user is shown a link and decides.
///
/// Every failure is silent. No network, GitHub rate-limiting the caller (60
/// requests an hour unauthenticated), a malformed response — all of it ends in
/// "no update to report". Greeting someone with an error because GitHub was
/// unreachable would make the app look broken when nothing is wrong.
public struct UpdateChecker: Sendable {
    public var service: any ReleaseChecking
    public var currentVersion: ReleaseVersion?

    public init(service: any ReleaseChecking = GitHubReleaseService(),
                currentVersion: ReleaseVersion? = ReleaseVersion.current()) {
        self.service = service
        self.currentVersion = currentVersion
    }

    /// The newer release, or nil when up to date, unknown, or unreachable.
    public func checkForUpdate() async -> AvailableRelease? {
        // No readable current version means every comparison is a guess.
        // Better to say nothing than to claim an update that may not apply.
        guard let currentVersion else { return nil }
        guard let latest = try? await service.latestRelease() else { return nil }
        return latest.version > currentVersion ? latest : nil
    }
}

/// Reads the latest release from GitHub's public API.
public struct GitHubReleaseService: ReleaseChecking {
    public var repository: String
    public var session: URLSession

    public init(repository: String = "drdee/parental_controls", session: URLSession? = nil) {
        self.repository = repository
        if let session {
            self.session = session
        } else {
            let configuration = URLSessionConfiguration.ephemeral
            // A version check is a courtesy, not a step anyone is waiting on,
            // so it should give up quickly rather than delay the first screen.
            configuration.timeoutIntervalForRequest = 10
            configuration.timeoutIntervalForResource = 15
            self.session = URLSession(configuration: configuration)
        }
    }

    enum ServiceError: Error {
        case badResponse
        case unparseable
    }

    public func latestRelease() async throws -> AvailableRelease {
        var request = URLRequest(
            url: URL(string: "https://api.github.com/repos/\(repository)/releases/latest")!
        )
        // GitHub asks for an explicit API version and a User-Agent; without
        // the latter it answers 403.
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        request.setValue("FamilySafetySetup", forHTTPHeaderField: "User-Agent")

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw ServiceError.badResponse
        }

        let payload = try JSONDecoder().decode(Payload.self, from: data)
        guard let version = ReleaseVersion(payload.tagName),
              let page = URL(string: payload.htmlURL) else {
            throw ServiceError.unparseable
        }
        return AvailableRelease(version: version, pageURL: page)
    }

    private struct Payload: Decodable {
        var tagName: String
        var htmlURL: String

        enum CodingKeys: String, CodingKey {
            case tagName = "tag_name"
            case htmlURL = "html_url"
        }
    }
}
