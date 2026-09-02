# Signing and notarizing

Until this is done, macOS refuses to open the installer at all and the
configuration profile shows as "Unverified". Notarizing fixes both.

> **Do not use a Wealthsimple certificate.** Every signing identity currently
> on this Mac belongs to the company:
>
> ```
> Developer ID Application: Wealthsimple Financial Inc. (8994AF9LL2)
> Developer ID Installer:   Wealthsimple Financial Inc. (8994AF9LL2)
> ```
>
> Signing a personal app with one of those attributes it to Wealthsimple in
> Gatekeeper and puts the notarization record — and any future revocation — on
> the company. Use a personal account.

## 1. Enrol in the Apple Developer Program

$99/yr, on a personal Apple Account.

1. Turn on two-factor authentication for `dvanliere@gmail.com` if it is not
   already: <https://account.apple.com> → Sign-In and Security.
2. **Check the name on the Apple Account is your legal name**, in the first and
   last name fields. An alias, nickname or company name in those fields is the
   single most common cause of enrolment delays.
3. Enrol at <https://developer.apple.com/programs/enroll/> and choose
   **Individual / Sole Proprietor**.
4. Pay. Approval is usually same-day but can take a couple of days.

Note your **Team ID** once approved — a 10-character code, visible at
<https://developer.apple.com/account> under Membership Details.

## 2. Create the two certificates

Distribution outside the App Store needs both:

| Certificate | Signs |
|---|---|
| **Developer ID Application** | the `.app` bundle |
| **Developer ID Installer** | the `.pkg` |

Easiest route — let Xcode do it:

1. Xcode → Settings → Accounts → **+** → Apple ID → sign in with your personal
   Apple Account.
2. Select the account → **Manage Certificates…** → **+** →
   *Developer ID Application*, then again for *Developer ID Installer*.

Then confirm they landed in the keychain:

```bash
security find-identity -v -p codesigning | grep "Developer ID"
security find-identity -v | grep "Developer ID Installer"
```

You should see your own name rather than Wealthsimple.

## 3. Save notarization credentials

Apple needs an **app-specific password**, not your Apple Account password.

1. <https://account.apple.com> → Sign-In and Security → **App-Specific
   Passwords** → generate one, label it something like `notarytool`.
2. Store it in the keychain so it never appears in a command or shell history:

```bash
xcrun notarytool store-credentials "familysafety" \
  --apple-id dvanliere@gmail.com \
  --team-id YOUR_TEAM_ID \
  --password "xxxx-xxxx-xxxx-xxxx"
```

Check it works:

```bash
xcrun notarytool history --keychain-profile "familysafety"
```

## 4. Build a signed, notarized release

```bash
cd ParentalControls
swift package --allow-writing-to-package-directory build-family-safety \
  --identity "Developer ID Application: Your Name (TEAMID)" \
  --installer-identity "Developer ID Installer: Your Name (TEAMID)" \
  --notarize --notary-profile familysafety \
  --publish
./build/publish.sh
```

Copy the identity strings exactly as `security find-identity` prints them,
including the parenthesised Team ID.

The build stops on any failure, so a signing or notarization problem will not
produce a half-signed release.

## 5. Verify before sharing

```bash
# App: expect your name, and 'runtime' in the flags
codesign -dv --verbose=4 build/Family-Safety.app 2>&1 | grep -E "Authority|flags"

# Package: signed and notarized
pkgutil --check-signature build/Family-Safety.pkg

# The check that matters — Gatekeeper's own verdict
spctl -a -vvv -t install build/Family-Safety.pkg
```

`spctl` should say **accepted**, with `source=Notarized Developer ID`. That is
the point at which a parent can double-click the installer and it simply works.

Also confirm the ticket is stapled, so it verifies without a network round trip:

```bash
xcrun stapler validate build/Family-Safety.pkg
```

## What changes for the people you share it with

| | Unsigned (today) | Notarized |
|---|---|---|
| Installing the `.pkg` | Terminal only: `sudo installer -pkg …` | Double-click |
| Gatekeeper | refuses to open it | opens normally |
| Configuration profile | shows "Unverified" | shows your name |
| Trust | "I promise it's fine" | Apple has scanned it |

## Renewal

Membership is annual; certificates last five years but stop being issuable if
membership lapses. Already-notarized releases keep working. Set a reminder —
the failure mode is discovering it at the moment you need to ship a fix.
