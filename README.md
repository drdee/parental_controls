# macOS Parental Controls

> **Not notarized yet.** macOS refuses to open an unsigned `.pkg` at all —
> right-click → Open works for apps but **not** for installer packages, and
> clearing the quarantine flag does not help either. Install with
> `sudo installer -pkg … -target /`, or build from source (one command). See
> [Installing the release](#installing-the-release).

> **`docs/BYPASS-NOTES.md` documents how to defeat this tool.** That is
> deliberate: knowing the gaps is more useful to a parent than believing the
> setup is airtight. It does mean a determined teenager who finds this repo has
> a roadmap. Judge for yourself whether to share the link or just the installer.

A native macOS app that configures content filtering and device restrictions on
a Mac. Designed so the safe subset can be handed to other families.

**Requires macOS 14 Sonoma or later.** Tested on macOS 15 Sequoia and macOS 26
Tahoe, Apple Silicon and Intel. A few restrictions need macOS 15 or later and
are simply ignored below that — the app says so in its preflight checks rather
than failing.

> Note on version numbers: macOS 26 reports **build 25xxx** and **Darwin 25.x**,
> so a Mac showing "25" somewhere is running macOS 26, not a "macOS 25" — Apple
> skipped 16 through 25 when it moved to year-based numbering. The preflight
> check prints both the product version and the build to avoid the confusion.

## Quick start

```bash
cd ParentalControls
swift package --allow-writing-to-package-directory build-family-safety
open build/Family-Safety.app
```

One command builds everything: the release binary, the `.app` bundle with a
generated and linted `Info.plist`, a hardened-runtime code signature, the
installer's `postinstall`, and the `.pkg`. It is a SwiftPM command plugin
(`Plugins/BuildTool`), not a shell script — the build uses the same build graph
as `swift build`, and `--allow-writing-to-package-directory` is SwiftPM's own
sandbox asking permission to write `build/`.

```bash
swift package build-family-safety --help          # all options
swift package --allow-writing-to-package-directory \
  build-family-safety --mode advanced --version 2.0
```

## Installing the release

Download `Family-Safety.pkg` from the
[latest release](https://github.com/drdee/parental_controls/releases/latest).

Because it is not notarized, **double-clicking fails** with _"cannot verify
this app is free of malware"_, and there is no click-through: the right-click →
Open trick works for `.app` bundles but not for `.pkg` installers. Removing the
quarantine attribute does not help — the missing signature is what Gatekeeper
objects to (`spctl -a -t install` reports `source=no usable signature` either
way).

Verify the download, then install from Terminal. `/usr/sbin/installer` does not
consult Gatekeeper:

```bash
shasum -a 256 ~/Downloads/Family-Safety.pkg   # compare against SHA256SUMS.txt
sudo installer -pkg ~/Downloads/Family-Safety.pkg -target /
```

Or build from source, which is never quarantined and avoids the issue:

```bash
swift package --allow-writing-to-package-directory build-family-safety
sudo installer -pkg build/Family-Safety.pkg -target /
```

The installer applies the DNS, browser and hosts-file changes, and leaves the
configuration profile at `/Users/Shared/Family-Safety.mobileconfig` for you to
double-click and approve — macOS does not let anything install a profile
automatically.

To undo everything, build and run the app and choose **Undo All Changes**.

## Profile linting

Apple publishes machine-readable schemas for every payload at
[apple/device-management](https://github.com/apple/device-management).
`tools/lint-profile.py` checks the generated profile against them, and the
build fails if anything is wrong:

```bash
tools/lint-profile.py ParentalControls/build/scripts/Family-Safety.mobileconfig
```

It catches the two traps that cost this project three releases:

- **`introduced: n/a`** — the key is in the schema but the platform never
  supported it (e.g. `AutoFilterEnabled` on macOS).
- **`allowmanualinstall: false`** — the key only works when the profile arrives
  over MDM (e.g. `allowSafariPrivateBrowsing`). A manually installed profile
  containing it fails outright.

Neither degrades gracefully. One unsupported key fails the *entire* profile
install with a single opaque `CPDomainPlugin` error, so DNS filtering, browser
policy and restrictions all die together.

## Testing

```bash
swift test                       # 195 tests, ~0.5s
swift test --enable-code-coverage
```

92.6% line coverage of `FamilySafetyCore`. The suite runs in the pre-commit
hook and touches nothing on the machine: no network, no `/etc/hosts` edits, no
profile installs.

Dependencies are injected through three small protocols in `Dependencies.swift`
— `CommandRunning`, `FileSystemReading` and `PackageDownloading` — with live
implementations as defaults, so production code constructs `AppState()` and
tests substitute recording fakes. That is what makes the destructive paths
testable: revert removes profiles and rewrites `/etc/hosts`, and the WARP
installer runs a package as root. Neither can be exercised for real, but both
can be checked for what they *would* do and how they handle failure.

The one deliberate gap is the real 150 MB network download in
`WARPInstaller.download`, isolated behind `PackageDownloading` so everything
around it is covered.

## Development

```bash
brew install swiftlint          # required by the pre-commit hook
git config core.hooksPath .githooks   # already set in this clone
swiftlint lint                  # 0 errors expected
swift build
```

The pre-commit hook lints staged Swift files and refuses a commit that has lint
errors or does not compile. Bypass with `git commit --no-verify`.

`.swiftlint.yml` includes three project-specific rules that encode mistakes
already made once: a `User`-scoped `PayloadScope` (which silently disables DNS
filtering), a hardcoded profile identifier (which would let generation and
revert drift apart), and an unquoted path interpolated into a privileged script
(which allowed a newline command injection).

## Browser hardening

Three options, all on by default and all Chromium-only:

- **Ad blocker** — force-installs uBlock Origin Lite
  (`ddkjiahejlhfcafbddmgiahcphecmpfh`, verified live in the Chrome Web Store).
  Ad networks are a real malware delivery route, so this is a security control
  as much as a convenience. Every other extension stays blocked, including VPN
  and proxy ones — turning the ad blocker *off* does not reopen that hole.
  Note the original uBlock Origin was delisted with MV2; only *Lite* installs.
- **Third-party cookies** — `BlockThirdPartyCookies`. Brings Chrome to parity
  with Safari, which has blocked these by default since Safari 13.1.
  Deliberately *not* `DefaultCookiesSetting = 2`, which breaks school logins.
- **Educational bookmarks** — a read-only "Learning" folder via
  `ManagedBookmarks`. Safari has no managed-bookmark payload, so this is
  Chrome-only. All eight URLs verified reachable.

## Preset categories

Blocking is grouped into checkboxes rather than a flat list, because a parent
thinks in categories, not hostnames:

| Preset | Default | Contents |
|---|---|---|
| Social media | **on** | TikTok, Instagram, Pinterest, Snapchat |
| AI chatbots | **on** | ChatGPT, Claude, Gemini, Perplexity, Character.AI, Copilot, DeepSeek, Grok, Poe |
| Chat and gaming | off | Discord, Reddit, Roblox, Twitch, Telegram, WhatsApp Web, X, Threads, Tumblr, BeReal |

ChatGPT sits with the AI chatbots rather than social media — it is a different
category of concern (homework integrity), and someone turning off social media
probably does not mean to unblock it.

Chat and gaming is off deliberately: Discord and Reddit have genuine school and
club uses, and blocking them tends to produce a workaround rather than a change
in behaviour.

With the two defaults on, 46 hostnames are blocked.

## Undo

The main screen has an **Undo All Changes** option, separate from the setup
path. It removes the configuration profile, strips the managed block from
`/etc/hosts`, and re-enables the Guest account and console login.

It removes only its own marked block from `/etc/hosts`, so unrelated entries
added afterwards survive — verified by round-trip test to be byte-identical to
the original. It deliberately does **not** delete user accounts (that would
destroy someone's home folder) or uninstall WARP, and says so on screen.

## Preview mode

A switch on the first screen walks the entire wizard and changes nothing: no
profile written, no hosts entries, no WARP download, no account created.
Instead of shell commands it shows, per change, *what changes*, *what you'll
notice*, and *how to undo it* — written for someone non-technical.

Verified as an invariant, not just intent: `PrivilegedRunner(dryRun: true)`
provably does not execute its script, and the plain-language text is checked to
contain no shell syntax.

## Two modes

|  | Family Mode | Advanced Mode |
|---|---|---|
| DNS-over-HTTPS filtering | ✅ | ✅ |
| Chrome / Firefox policy | ✅ | ✅ |
| Safari content filter | ✅ | ✅ |
| `/etc/hosts` block list | ✅ | ✅ |
| Create standard account | — | ✅ |
| Guest / console / SSH off | — | ✅ |
| Touches accounts or FileVault | **never** | yes |

Family Mode is provably incapable of locking someone out — it only writes a
profile and hosts entries, both reversible. That is the shareable artifact.

## DNS backends

- **Cloudflare for Families (`1.1.1.3`)** — no account. Blocks malware and adult
  content. Has only those two categories: no social-media category, so social
  sites rely on the explicit domain list and browser policy.
- **Cloudflare Zero Trust Gateway** — needs a Cloudflare account. Adds a real
  social-media content category, SafeSearch, custom lists, and query logs.
  Optionally installs the WARP client, which enforces policy at the device level
  and keeps filtering in place on any network.

> A mistyped Zero Trust gateway ID **still answers DNS normally** — any
> `*.cloudflare-gateway.com` host resolves and returns valid responses. So the
> endpoint cannot be validated by probing it. The app verifies *functionally*
> after install instead: it checks whether a known-blocked domain is actually
> blocked.

## Layout

```
ParentalControls/
  Sources/ParentalControls/
    Core/       profile generation, privilege, preflight, verification, hardening
    Views/      SwiftUI flow: mode → configure → review → run → results
  Plugins/BuildTool/            # the build, as a SwiftPM command plugin
  Resources/ONE-PAGE-GUIDE.md   for other parents
docs/
  MANUAL-STEPS.md   Screen Time + Family Sharing (no API exists)
  BYPASS-NOTES.md   what this stops and what it doesn't
  ROUTER-DNS.md     the real perimeter
```

## Constraints worth knowing

Verified on macOS 26.6.2:

- **`profiles` cannot install profiles** ("profiles tool no longer supports
  installs"). The app generates the file; you double-click and approve it.
  `profiles remove` still works, so teardown is one command for an admin.
- **No Screen Time API.** `FamilyControls` needs an Apple-reviewed entitlement
  *and* the signed-in user to be a child in a Family Sharing group. Documented as
  manual steps instead.
- **`PayloadScope` must be `System`** — the DNS payload handler rejects
  user-scoped profiles outright.
- **Several restriction keys need supervision** and silently do nothing on an
  unenrolled Mac (`allowAppInstallation` does nothing on macOS at all). App
  installation is actually controlled by `/Applications` being `root:admin` plus
  the user not being an admin.
- **Blocked HTTPS sites cannot be redirected** to another page. Every target
  sends HSTS `preload`, so it would require a root CA and intercepting all
  traffic. Sites fail to connect instead.

## Signing

Full walkthrough: **[docs/SIGNING.md](docs/SIGNING.md)** — enrolment,
certificates, notarization credentials and verification.

The build ad-hoc signs by default and deliberately never picks up an identity
from the keychain — a corporate certificate must not end up on a personal app
by accident. Signing and notarization are opt-in:

```bash
swift package --allow-writing-to-package-directory build-family-safety \
  --identity "Developer ID Application: Your Name (TEAMID)" \
  --installer-identity "Developer ID Installer: Your Name (TEAMID)" \
  --notarize --apple-id you@example.com --team-id TEAMID \
  --notary-password "abcd-efgh-ijkl-mnop"
```

The hardened runtime is enabled (`flags=0x10002(adhoc,runtime)`), which
notarization requires and which — unlike the App Store sandbox — does not block
the privileged operations this app performs.

## Privacy: what this sends, and where

A tool that asks for an administrator password should say what it does with
the access. This one collects nothing:

- **No analytics, telemetry, crash reporting or usage tracking.** There is no
  SDK for any of it and no code that reports anything anywhere.
- **No accounts, no sign-in, no server.** There is nothing to sign in to.
- **Nothing about your family leaves the Mac.** The child's account name, the
  chosen mode and which restrictions were applied are all applied locally and
  never transmitted.
- **No browsing history is collected or read.** The tool sets browser policy;
  it does not inspect what anyone visited.

The app makes exactly **one** kind of outbound connection: downloading the
Cloudflare WARP installer from `downloads.cloudflareclient.com`, and only in
Zero Trust mode when you ask for it. That download uses an ephemeral URL
session, so no cookies or cache persist, and the package's signature is checked
against Cloudflare's Developer ID before it is allowed to install.

Two things do involve third parties once configured, and they are worth
understanding:

| What | Who sees what |
|---|---|
| DNS filtering (`1.1.1.3`) | Cloudflare resolves the Mac's DNS queries. See [Cloudflare's privacy commitments](https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/). |
| uBlock Origin Lite | Installed from the Chrome Web Store, which means Google serves the extension update check. |

Those are properties of the services being configured, not of this tool
reporting on you. Everything above is verifiable in the source — the network
code is confined to `Sources/FamilySafetyCore/WARPInstaller.swift`.

## The honest ceiling

A phone hotspot bypasses everything here and no macOS setting can prevent it.
The three controls that do the real work are: **the child is not an
administrator**, **FileVault is on**, and **Screen Time via Family Sharing**.
See `docs/BYPASS-NOTES.md`.
