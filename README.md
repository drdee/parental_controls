# macOS Parental Controls

A native macOS app that configures content filtering and device restrictions on
a Mac. Built for two MacBook Airs (macOS 26 Tahoe, Apple Silicon), designed so
the safe subset can be handed to other families.

## Quick start

```bash
cd ParentalControls
./Scripts/build-app.sh release
open build/ParentalControls.app
```

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
  Scripts/build-app.sh
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

`build-app.sh` ad-hoc signs by default and deliberately does not pick up any
Developer ID on the machine — a corporate certificate must not end up on a
personal app. For distribution, set a personal identity:

```bash
CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" ./Scripts/build-app.sh release
```

## The honest ceiling

A phone hotspot bypasses everything here and no macOS setting can prevent it.
The three controls that do the real work are: **the child is not an
administrator**, **FileVault is on**, and **Screen Time via Family Sharing**.
See `docs/BYPASS-NOTES.md`.
