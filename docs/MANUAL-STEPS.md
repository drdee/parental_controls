# Manual steps

Two things cannot be automated, and between them they matter more than
everything the app does. macOS has no Screen Time API and no way for an app to
install a configuration profile, so these are click-through.

## 1. Install the configuration profile

The app writes `Family-Safety.mobileconfig` to your Downloads folder. macOS
requires a human to approve it.

1. Double-click the profile (the app has an **Open Profile** button).
2. **System Settings › General › Device Management**.
3. Select **Family Safety** → **Install** → authenticate as an admin.
4. Return to the app and press **Verify Again**.

If the profile is missing from Device Management, it did not install — reopen the
file and try again.

## 2. Family Sharing + Screen Time

**This is the highest-leverage step in the whole setup.** Screen Time configured
through Family Sharing is enforced from *your* device with *your* passcode, so it
cannot be switched off on their Mac even by someone who knows their own password.
Everything the app does locally can, in principle, be undone by an admin. This
cannot.

### Create a Child Apple Account

1. On **your** Mac: **System Settings › Family**.
2. **Add Member › Create Child Account**.
3. Enter their name and date of birth. Get the birth date right — it drives
   age-based restrictions.
4. Set up their account, then sign in with it on their MacBook.

### Turn on Screen Time for them

From your own device: **System Settings › Screen Time**, pick the child, then:

| Setting | Value |
|---|---|
| **Content & Privacy** | On |
| Content Restrictions › Web Content | **Limit Adult Websites** |
| — Restricted list | add `tiktok.com`, `instagram.com`, `chatgpt.com` |
| App Store › In-app purchases | **Don't Allow** |
| App Store › Installing Apps | **Don't Allow** |
| **Ask to Buy** | On |
| **Screen Time passcode** | Set one — not their login password, not guessable |

The "Installing Apps → Don't Allow" setting is what actually stops new apps.
The `allowAppInstallation` profile key does nothing on macOS; it is an iOS key.

## 3. Router DNS

Set the router's DNS to your filtering resolver so it covers every device and
survives a Mac being wiped. See `ROUTER-DNS.md`.

## 4. Test before handing the Mac over

Especially if you used Advanced Mode:

1. **Reboot.** Log in as the child account. With FileVault on, an account
   without a Secure Token may not be able to unlock the disk — find that out now,
   not at bedtime.
2. From their account, confirm they **cannot**:
   - change DNS in System Settings › Network
   - drag an app into `/Applications`
   - remove the profile in Device Management
3. Confirm they **can** still do schoolwork: Google Docs, school sites,
   printing, Messages.
