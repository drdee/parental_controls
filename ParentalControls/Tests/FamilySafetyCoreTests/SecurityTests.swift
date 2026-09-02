import Testing
import Foundation
@testable import FamilySafetyCore

/// Injection and quoting. These are the highest-severity paths: their output is
/// executed as root, and each case here corresponds to a bug that was actually
/// found and fixed rather than a hypothetical.
@Suite("Security: privileged input handling")
struct SecurityTests {

    // MARK: - AppleScript quoting

    @Test("AppleScript literals survive a round trip unchanged", arguments: [
        "plain.com",
        #"has"quote.com"#,
        #"back\slash.com"#,
        #"a" & (do shell script "touch /tmp/pwned") & "b"#,
        #"trailing\"#,
        "newline\nsecond line",
        "unicode — ünïcode",
        "",
    ])
    func appleScriptQuotingRoundTrips(_ input: String) throws {
        let literal = PrivilegedRunner.appleScriptLiteral(input)

        // The literal must be a single balanced quoted string.
        #expect(literal.hasPrefix("\""))
        #expect(literal.hasSuffix("\""))

        // Ask osascript to echo it back; anything that escaped the literal
        // would change the value or fail to parse.
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", "return \(literal)"]
        let out = Pipe(), err = Pipe()
        process.standardOutput = out
        process.standardError = err
        try process.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        _ = err.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        let echoed = String(data: data, encoding: .utf8)!
            .trimmingCharacters(in: .whitespacesAndNewlines)
        // osascript normalises interior newlines, so compare the first line.
        let expected = input.split(separator: "\n").first.map(String.init) ?? ""
        #expect(echoed.hasPrefix(expected) || echoed == input)
    }

    @Test("A shell payload embedded in a domain does not execute")
    func appleScriptInjectionDoesNotExecute() throws {
        let marker = "/tmp/familysafety-test-\(UUID().uuidString)"
        let attack = #"x" & (do shell script "touch \#(marker)") & "y"#
        let literal = PrivilegedRunner.appleScriptLiteral(attack)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", "return \(literal)"]
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        try process.run()
        process.waitUntilExit()

        #expect(!FileManager.default.fileExists(atPath: marker),
                "the embedded `do shell script` executed — quoting is broken")
    }

    // MARK: - Account names

    @Test("Unsafe account short names are rejected", arguments: [
        "kid\ntouch /tmp/pwned",   // newline injection — the original bug
        "kid;whoami",
        "kid$(id)",
        "kid`id`",
        "kid/../root",
        "has space",
        "",
        "  ",
        "1startsWithDigit",
        "root", "admin", "daemon", "nobody", "wheel",   // reserved
        String(repeating: "a", count: 32),              // too long
        "kid|pipe", "kid&amp", "kid>redirect",
    ])
    func rejectsUnsafeUsernames(_ name: String) {
        #expect(AccountName(name) == nil, "\(name.debugDescription) should be rejected")
    }

    @Test("Reasonable account short names are accepted", arguments: [
        "sophie", "emma2", "test-user", "a_b", "x", "Sophie", "SOPHIE",
    ])
    func acceptsReasonableUsernames(_ name: String) {
        let account = AccountName(name)
        #expect(account != nil, "\(name.debugDescription) should be accepted")
        // Always normalised to lowercase, since that is what is written to disk.
        #expect(account?.value == name.lowercased())
    }

    @Test("The account script refuses an invalid name rather than escaping it")
    func accountScriptRefusesInvalidNames() {
        let hardening = Hardening(runner: PrivilegedRunner(dryRun: true), blockedSites: [])
        #expect(throws: HardeningError.self) {
            _ = try hardening.createStandardAccountScript(
                username: "kid\ntouch /tmp/pwned", fullName: "x"
            )
        }
    }

    @Test("The account script quotes every interpolated value")
    func accountScriptQuotesValues() throws {
        let hardening = Hardening(runner: PrivilegedRunner(dryRun: true), blockedSites: [])
        let script = try hardening.createStandardAccountScript(
            username: "sophie", fullName: "Sophie O'Brien"
        )
        // The home path was the original injection point; it must be quoted.
        #expect(script.contains("'/Users/sophie'"))
        // An apostrophe in a full name must not break out of its quotes.
        #expect(script.contains("'\\''"))
        #expect(!script.contains("touch"))
    }

    @Test("A full name containing a newline cannot add a command")
    func accountScriptFlattensNewlinesInFullName() throws {
        let hardening = Hardening(runner: PrivilegedRunner(dryRun: true), blockedSites: [])
        let script = try hardening.createStandardAccountScript(
            username: "sophie", fullName: "Sophie\nrm -rf /"
        )
        // The dangerous string must not begin a line of its own.
        #expect(!script.contains("\nrm -rf /"))
    }

    // MARK: - Domain sanitisation

    @Test("Domains are reduced to safe hostname characters", arguments: [
        ("evil.com\n0.0.0.0 apple.com", "evil.com0.0.0.0apple.com"),
        ("http://x.com/path?q=1", "x.com"),
        ("https://y.com", "y.com"),
        ("UPPER.COM", "upper.com"),
        ("x.com:8080", "x.com"),
        ("a b.com", "ab.com"),
        ("# comment", "comment"),
        ("  spaced.com  ", "spaced.com"),
        ("semi;colon.com", "semicolon.com"),
        ("quote'.com", "quote.com"),
    ])
    func sanitizesDomains(_ input: String, _ expected: String) {
        #expect(BlockedSite.sanitize(input) == expected)
    }

    @Test("A sanitised domain can never contain shell or hosts metacharacters", arguments: [
        "a\nb", "a;b", "a b", "a\tb", "a|b", "a&b", "a$b", "a`b", "a'b", "a\"b", "a#b",
    ])
    func sanitizedDomainsHaveNoMetacharacters(_ input: String) {
        let clean = BlockedSite.sanitize(input)
        let forbidden = Set("\n\t ;|&$`'\"#\\<>()[]{}*?!~")
        #expect(!clean.contains(where: forbidden.contains),
                "sanitize left a metacharacter in \(clean.debugDescription)")
    }

    @Test("Domain validity is judged correctly", arguments: [
        ("example.com", true),
        ("sub.example.com", true),
        ("", false),
        ("nodot", false),
        (".leading.com", false),
        ("trailing.com.", false),
        ("double..dot.com", false),
    ])
    func validatesDomains(_ domain: String, _ isValid: Bool) {
        #expect(BlockedSite(domain).isValid == isValid, "\(domain.debugDescription)")
    }
}
