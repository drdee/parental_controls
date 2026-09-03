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

It is also in any certificate you already hold, as the `OU` field. Careful:
the code in the certificate's *name* is a different value.

```bash
security find-certificate -c "Apple Development: you@example.com (XXXXXXXXXX)" -p \
  | openssl x509 -noout -subject
# subject=UID=..., CN=Apple Development: ... (67PF54ZN42), OU=2Q9U7Y5YRD, O=Your Name
#                                             ^ not the Team ID   ^ Team ID
```

## 2. Create the two certificates

> **"Apple Development" is not one of them.** That certificate type is for
> running your own builds on your own registered devices. Gatekeeper rejects it
> on anyone else's Mac, and the notary service will not accept it — verified
> directly: an app signed with `Apple Development: dvanliere@gmail.com` gets
> `spctl: rejected`.
>
> Tell them apart by the issuer:
>
> | Certificate | Issued by |
> |---|---|
> | Apple Development | Apple Worldwide Developer Relations CA |
> | **Developer ID** | **Developer ID Certification Authority** |
>
> ```bash
> security find-certificate -c "<cert name>" -p | openssl x509 -noout -issuer
> ```


Distribution outside the App Store needs both:

| Certificate | Signs |
|---|---|
| **Developer ID Application** | the `.app` bundle |
| **Developer ID Installer** | the `.pkg` |

### If Xcode does not offer "Developer ID"

The **+** menu only lists certificate types Xcode believes your team is
entitled to, and it caches that judgement. Check what it currently thinks:

```bash
defaults read com.apple.dt.Xcode IDEProvisioningTeamByIdentifier \
  | grep -E "teamID|teamName|teamType|isFree"
```

`teamType = "Personal Team"` with `isFreeProvisioningTeam = 1` means Xcode sees
a **free** Apple ID. A free team can only issue *Apple Development* certificates
— which is precisely the symptom. A paid membership reports
`isFreeProvisioningTeam = 0`.

Three causes, in order of likelihood:

1. **Xcode has cached stale team data.** Quit Xcode, remove the account under
   Settings → Accounts, reopen and sign in again. Refreshing alone is often not
   enough.
2. **Enrolment is still processing.** Check Membership Details at
   <https://developer.apple.com/account>. "Pending" means wait; approval is
   usually hours but can be a couple of days.
3. **The paid membership is on a different Apple ID** from the one Xcode is
   signed into. Confirm the email on the developer portal matches.

**Bypass Xcode entirely** — this works as soon as the membership is active and
avoids the caching problem:

```bash
tools/make-csr.sh "Diederik van Liere" dvanliere@gmail.com
```

Then upload the request at
<https://developer.apple.com/account/resources/certificates/add>, once for
*Developer ID Application* and once for *Developer ID Installer*. Download each
`.cer` and double-click to install.

If that page does not offer "Developer ID Application", the membership is not
active — no amount of local fiddling will help, and that is the thing to fix.

### Easiest route — let Xcode do it:

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

**Signing runs outside the plugin.** SwiftPM's plugin sandbox blocks keychain
access — `codesign` reports "no identity found" for an identity that works
fine outside it. So the plugin ad-hoc signs to produce a runnable bundle and
writes the real signing, notarization and publish steps into `build/publish.sh`
for you to run. Same arrangement as publishing, and for the same reason.

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
