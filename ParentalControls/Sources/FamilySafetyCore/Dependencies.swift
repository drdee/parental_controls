import Foundation

/// Runs commands, with and without elevation.
///
/// Exists so the destructive paths can be tested. `Reverter` removes
/// configuration profiles and rewrites `/etc/hosts`; `WARPInstaller` downloads
/// 150 MB and installs a package as root. Neither can be exercised against the
/// real machine in a test suite, so both take a `CommandRunning` and tests
/// supply a recording fake.
public protocol CommandRunning: Sendable {
    func run(_ executable: String, _ arguments: [String]) throws -> CommandResult
    func probe(_ executable: String, _ arguments: [String]) -> CommandResult
    func runPrivileged(script: String, description: String) throws -> CommandResult
}

/// Async conveniences, so callers on the main actor never block the UI.
///
/// Default implementations hop to a background queue, so a conforming type only
/// has to provide the three synchronous primitives.
public extension CommandRunning {
    func runAsync(_ executable: String, _ arguments: [String]) async throws -> CommandResult {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(with: Result { try run(executable, arguments) })
            }
        }
    }

    func probeAsync(_ executable: String, _ arguments: [String]) async -> CommandResult {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: probe(executable, arguments))
            }
        }
    }

    func runPrivilegedAsync(script: String, description: String) async throws -> CommandResult {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(with: Result {
                    try runPrivileged(script: script, description: description)
                })
            }
        }
    }
}

/// The filesystem facts this code needs.
///
/// Deliberately tiny: only what is actually read, so a fake is trivial to
/// write and cannot drift from the real implementation.
public protocol FileSystemReading: Sendable {
    func fileExists(atPath path: String) -> Bool
    func contents(atPath path: String) -> String?
    func directoryContents(atPath path: String) -> [String]
    /// Where the generated profile is written for the user to double-click.
    var downloadsDirectory: URL { get }
}

/// Reads the real filesystem.
public struct LiveFileSystem: FileSystemReading {
    public init() {}

    public func fileExists(atPath path: String) -> Bool {
        FileManager.default.fileExists(atPath: path)
    }

    public func contents(atPath path: String) -> String? {
        try? String(contentsOfFile: path, encoding: .utf8)
    }

    public func directoryContents(atPath path: String) -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: path)) ?? []
    }

    public var downloadsDirectory: URL {
        FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
    }
}

/// Fetches the WARP installer package.
///
/// Injectable so the test suite never downloads 150 MB — and so a test can
/// simulate a truncated or failed transfer, which is otherwise impossible to
/// reproduce on demand.
public protocol PackageDownloading: Sendable {
    /// Downloads to a local file and reports progress as a 0...1 fraction.
    func download(progress: @escaping @Sendable (Double) -> Void) async throws -> URL
}

/// Resolves hostnames the way the rest of the system does.
///
/// Deliberately *not* `dig`. `dig` reads `/etc/resolv.conf` and speaks UDP/53
/// to those nameservers directly, which bypasses the system's
/// DNS-over-HTTPS configuration entirely — so a profile-installed DoH resolver
/// is invisible to it, and filtering appears not to work when it does.
///
/// `getaddrinfo` goes through mDNSResponder, which honours the encrypted-DNS
/// settings a configuration profile installs. It is the same path a browser
/// takes, so it answers the question actually being asked: will this name
/// resolve for my daughter?
public protocol HostResolving: Sendable {
    /// Resolved IPv4 addresses, or an empty array if the name does not resolve.
    func addresses(for host: String) -> [String]
}

public struct SystemResolver: HostResolving {
    public init() {}

    public func addresses(for host: String) -> [String] {
        var hints = addrinfo(
            ai_flags: 0, ai_family: AF_INET, ai_socktype: SOCK_STREAM,
            ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil
        )
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let first = result else {
            return []
        }
        defer { freeaddrinfo(first) }

        var addresses: [String] = []
        var node: UnsafeMutablePointer<addrinfo>? = first
        while let current = node {
            if let socketAddress = current.pointee.ai_addr {
                var address = socketAddress
                    .withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                    .sin_addr
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if inet_ntop(AF_INET, &address, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil {
                    addresses.append(String(cString: buffer))
                }
            }
            node = current.pointee.ai_next
        }
        return addresses
    }
}
