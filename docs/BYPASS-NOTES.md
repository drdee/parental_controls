# What this stops, and what it doesn't

For your eyes. The goal is *bypass is effortful and detectable*, not
*impossible*. Impossible is not reachable without enrolling the Macs in an MDM.
Anyone who tells you otherwise is selling something.

Assume a motivated 13–17-year-old will search "how to bypass parental controls"
and find most of this list.

## Ranked by what they'll actually try

| # | Vector | Covered? | Notes |
|---|---|---|---|
| 1 | Browser DNS-over-HTTPS | **Yes** | Chrome `DnsOverHttpsMode=off` + `BuiltInDnsClientEnabled=false`; Firefox `DNSOverHTTPS.Locked` + `BlockAboutConfig`. Best-covered vector. |
| 2 | Install another browser | **Partly** | Non-admin blocks `/Applications`, but an app still runs from `~/Downloads`. **Weakest point.** |
| 3 | Web proxy / "unblocker" sites | **Partly** | Filtering DNS catches many. The long tail is whack-a-mole. |
| 4 | **Phone hotspot / cellular** | **No** | **Nothing on the Mac can stop this.** Needs Screen Time on the phone. |
| 5 | iCloud Private Relay | Mostly | `allowCloudPrivateRelay=false` (may need supervision) + router-block `mask.icloud.com`. |
| 6 | VPN app | Mostly | Non-admin can't install to `/Applications`; a system VPN extension needs admin approval. Browser extension blocklists close the easier variant. |
| 7 | Change DNS in System Settings | **Yes** | Requires admin. Verified: the auth right is `authenticate-admin-nonshared`. |
| 8 | Remove the profile | **Yes** (if not admin) | `PayloadRemovalDisallowed` only greys the button; an admin can still remove it, and `sudo profiles remove` works. |
| 9 | Second admin account | **Partly** | `allowLocalUserCreation=false` blocks *creating* one, and guest is disabled. Promoting an existing account is **not** blocked — see below. |
| 10 | Recovery Mode | **Yes** (if not admin) | Apple Silicon Recovery needs an admin/Owner password. FileVault is essential. |
| 11 | Boot from USB | **Yes** (if not admin) | Needs an Owner credential; FileVault makes the internal disk unreadable. |
| 12 | Tor Browser | **No** | Self-contained, runs from a home folder. A copy from a USB stick defeats everything. |
| 13 | Terminal (`curl`, `python -m http.server`, download a browser) | **No** | No profile key exists — verified against Apple's `com.apple.applicationaccess` schema, which has nothing for Terminal or command-line access. Screen Time cannot disable it either, only time-limit it. DNS still applies to `curl`, so this is about *fetching* rather than a clean bypass. The real exposure is downloading a browser to `~/`, which is #2. |
| 14 | Spotlight web preview | **Yes** | ⌘-Space, type a URL, Enter — the page loads in Spotlight's own preview window, outside any browser, so browser policy does not apply. `allowSpotlightInternetResults=false` turns it off. DNS filtering catches it regardless, since the lookup is ordinary. |

## A deliberate gap: self-promotion to admin

`allowAccountModification` is **not** set, by choice. Setting it would stop a
standard user changing any account — including granting themselves admin — but
it also blocks every legitimate account change while the profile is installed,
down to an ordinary password change by you. That was judged too high a price.

What this means concretely: **someone who learns an admin password can promote
their own account to administrator, permanently.** Not just borrow admin for
one dialog — make it stick, then remove the profile at leisure (#8) and undo
everything else along with it.

So the linchpin below depends on the admin password staying unknown, not on
macOS enforcing anything. Practical consequences:

- Do not type an admin password in front of them, and do not reuse a password
  they might already know.
- Touch ID for admin prompts is better than typing, since there is nothing to
  shoulder-surf.
- `dscl . -read /Groups/admin GroupMembership` lists the admin accounts. Worth
  checking occasionally; a name that should not be there is the tell.

If you would rather have the enforcement than the convenience, add
`allowAccountModification` back to `restrictionsPayload()` in
`ProfileGenerator.swift` — the test asserting its absence will fail, which is
the reminder to update this section too.

## The three things that actually do the work

1. **They are not an administrator.** This is the linchpin. It blocks #7, #8,
   #10, #11 and most of #6 in one move. Everything else is secondary — and it
   rests on the admin password staying secret, per the section above.
2. **FileVault is on.** Without it the disk can be modified from Recovery or a
   USB boot and the rest is theatre.
3. **Screen Time via Family Sharing.** Enforced from your device with your
   passcode — the only layer that survives someone with local admin.

## Known-unfixable

**A phone hotspot bypasses everything here.** Your daughters' laptops will
happily join their phones' hotspots and none of this applies. There is no
setting on macOS that prevents it. The only levers are Screen Time on the phone
and an actual conversation.

Worth saying plainly: for teenagers, the visibility is often worth more than the
blocking. Zero Trust query logs will show you *what was attempted*, which is a
better conversation-starter than a silent block.

## Things that look like controls but aren't

Recording these so nobody re-adds them later believing they do something:

- **`allowAppInstallation`** — an iOS/supervised key. Does nothing on macOS.
- **`com.apple.webcontent-filter`** — **cannot be used on macOS at all**, and
  is no longer in the profile. Its handler
  (`NetworkExtensionProfiles.profileDomainPlugin`) does not contain the string
  `BuiltIn`, nor `AutoFilterEnabled`, `BlacklistedURLs` or `PermittedURLs` —
  those are iOS-only keys. macOS knows only `PluginBundleID`, `UserName` and
  `Password`: it expects a third-party filter extension with a
  `signingIdentifier` and `designatedRequirement`. Including it failed the
  entire profile install with `CPDomainPlugin:101`.
- **`PayloadRemovalDisallowed`** — advisory on a non-MDM profile.
- **`ProhibitDisablement`** — **requires MDM enrolment**, and is no longer in
  the profile. The DNS payload validator checks `installedByMDM`; without it
  the whole profile install fails. A different gate from supervision.
- **`firmwarepasswd`** — the binary exists on Apple Silicon but is an Intel-era
  no-op. Boot security is the LocalPolicy/Secure Enclave model instead.
- **Redirecting blocked sites to another page (e.g. Wikipedia)** — impossible
  over HTTPS. `/etc/hosts` maps a name to an *IP address only*; it cannot say
  "go here instead". Pointing `instagram.com` at Wikipedia's IP makes the
  browser connect to Wikipedia's server while still asking for
  `instagram.com`, and the certificate does not match. Tested directly:

  ```
  subjectAltName does not match host name instagram.com
  SSL: no alternative certificate subject name matches target host name
  ```

  Wikipedia's cert covers 41 Wikimedia domains; `instagram.com` will never be
  among them. Worse, per the HSTS preload registry `instagram.com`,
  `chatgpt.com` and `pinterest.com` are **preloaded** — the HTTPS requirement is
  compiled into the browser, so there is no "proceed anyway" link. `tiktok.com`
  and `snapchat.com` are off the preload list but still send
  `max-age=31536000`, so one prior visit pins them for a year.

  The result would be a full-page red security warning that looks like the
  network is under attack — strictly worse than a clean "cannot connect". The
  only way to truly redirect is a root CA plus intercepting all TLS, which would
  break banking and Apple services and create a key that decrypts everything.
  **Decision: keep the clean block.**

## Correction: what supervision actually gates

An earlier version of this document hedged that various
`com.apple.applicationaccess` keys "may need supervision." **That was wrong**, and
being wrong in the cautious direction cost three real controls.

macOS keeps the authoritative list at:

```
/System/Library/CoreServices/ManagedClient.app/Contents/Resources/Supervised.plist
```

`ManagedClient` strips supervision-only keys by reading **only** that file
(`readSupervisedPrefs` / `MCXD_SupervisedPrefs`). Its complete contents are eight
entries across two domains, and every one is Classroom-related:

```
com.apple.applicationaccess → forceClassroomAutomaticallyJoinClasses
                              forceClassroomRequestPermissionToLeaveClasses
                              forceClassroomUnpromptedAppAndDeviceLock
                              forceClassroomUnpromptedScreenObservation
com.apple.classroom         → (the same four)
```

So `allowCloudPrivateRelay`, `allowAirDrop`, `allowiPhoneMirroring`,
`allowUIConfigurationProfileInstallation` and the rest are **not**
supervision-gated and do apply here.

(`allowAirDrop` and `allowiPhoneMirroring` are listed as evidence about the
platform, not as things this tool sets. Both were deliberately dropped. AirDrop
restriction broke legitimate schoolwork file sharing for very little safety
gain. iPhone Mirroring runs the phone's apps and browser on the phone itself,
so nothing on this Mac filters that traffic anyway — blocking the feature here
gives an impression of coverage it cannot deliver, and Screen Time on the phone
is the only thing that actually helps.)

There is a **separate** gate, which is the one that actually bites:
`ManagedClient` also logs *"removing keys due to lack of MDM install"*. Some
payloads require an MDM enrolment channel regardless of supervision. That is why
`ProhibitDisablement` and `PayloadRemovalDisallowed` are still expected to be
advisory — a different mechanism, not this one.

The lesson worth keeping: verify the enforcement mechanism rather than trusting
folklore about "supervised-only" keys, in either direction.

## A pattern worth naming

Two payload keys had to be removed after they broke installation entirely:
`ProhibitDisablement` and the whole `com.apple.webcontent-filter` payload. Both
had already been documented here as non-functional outside MDM, and both were
shipped anyway on the assumption that a useless key would simply be ignored.

**It is not ignored.** A payload macOS cannot handle fails the *entire* profile
install — DNS filtering, browser policy and restrictions all die together, with
one opaque error. There is no partial application.

The test suite now pins the exact payload set for this reason, so adding a
payload is a deliberate decision that has to be verified against a real
un-enrolled Mac.
