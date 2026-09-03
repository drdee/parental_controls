import Testing
import Foundation
@testable import FamilySafetyCore

@Suite("Release version parsing")
struct ReleaseVersionTests {

    @Test("Parses the forms GitHub and the VERSION file produce", arguments: [
        ("1.0.9", 1, 0, 9),
        ("v1.0.9", 1, 0, 9),
        ("V2.10.3", 2, 10, 3),
        ("1.2", 1, 2, 0),
        ("  1.0.9  ", 1, 0, 9),
    ])
    func parsesValidVersions(input: String, major: Int, minor: Int, patch: Int) {
        let version = ReleaseVersion(input)
        #expect(version == ReleaseVersion(major: major, minor: minor, patch: patch))
    }

    @Test("Rejects things that are not versions", arguments: [
        "", "abc", "1", "1.2.3.4", "1.x.3", "-1.0.0", "v",
    ])
    func rejectsInvalid(input: String) {
        #expect(ReleaseVersion(input) == nil)
    }

    @Test("Orders by major, then minor, then patch")
    func ordersCorrectly() {
        #expect(ReleaseVersion("1.0.8")! < ReleaseVersion("1.0.9")!)
        #expect(ReleaseVersion("1.0.9")! < ReleaseVersion("1.1.0")!)
        #expect(ReleaseVersion("1.9.9")! < ReleaseVersion("2.0.0")!)
        // The comparison that matters: 10 is greater than 9, not less as a
        // string sort would have it.
        #expect(ReleaseVersion("1.0.9")! < ReleaseVersion("1.0.10")!)
        #expect(!(ReleaseVersion("1.0.9")! < ReleaseVersion("1.0.9")!))
    }
}

/// A stand-in for GitHub, so no test touches the network.
private struct StubService: ReleaseChecking {
    var result: Result<AvailableRelease, Error>

    func latestRelease() async throws -> AvailableRelease {
        try result.get()
    }
}

private func release(_ version: String) -> AvailableRelease {
    AvailableRelease(
        version: ReleaseVersion(version)!,
        pageURL: URL(string: "https://github.com/drdee/parental_controls/releases/tag/\(version)")!
    )
}

private struct Boom: Error {}

@Suite("Update checker")
struct UpdateCheckerTests {

    @Test("A newer release is reported")
    func reportsNewer() async {
        let checker = UpdateChecker(
            service: StubService(result: .success(release("v1.1.0"))),
            currentVersion: ReleaseVersion("1.0.9")
        )
        let update = await checker.checkForUpdate()
        #expect(update?.version == ReleaseVersion("1.1.0"))
    }

    @Test("The same version is not an update")
    func ignoresSameVersion() async {
        let checker = UpdateChecker(
            service: StubService(result: .success(release("v1.0.9"))),
            currentVersion: ReleaseVersion("1.0.9")
        )
        #expect(await checker.checkForUpdate() == nil)
    }

    @Test("An older published release is not an update")
    func ignoresOlder() async {
        let checker = UpdateChecker(
            service: StubService(result: .success(release("v1.0.8"))),
            currentVersion: ReleaseVersion("1.0.9")
        )
        #expect(await checker.checkForUpdate() == nil)
    }

    @Test("A network failure is silent rather than an error")
    func failsSilently() async {
        let checker = UpdateChecker(
            service: StubService(result: .failure(Boom())),
            currentVersion: ReleaseVersion("1.0.9")
        )
        #expect(await checker.checkForUpdate() == nil)
    }

    @Test("An unknown running version reports nothing rather than guessing")
    func unknownCurrentVersionIsSilent() async {
        let checker = UpdateChecker(
            service: StubService(result: .success(release("v9.9.9"))),
            currentVersion: nil
        )
        #expect(await checker.checkForUpdate() == nil)
    }
}
