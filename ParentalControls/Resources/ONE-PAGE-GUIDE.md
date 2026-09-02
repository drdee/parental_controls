# Family Safety Setup — for parents

A small app that configures content filtering on a Mac. It takes about five
minutes.

## What it does

- Points the Mac at a **filtering DNS service** that blocks adult content and
  malware, encrypted so it works on any Wi-Fi network.
- Blocks **TikTok, Instagram, and ChatGPT** (you can edit the list).
- Locks **Chrome and Firefox settings** so they can't route around the filter.

## What it does NOT do

- It does not read anything private, and it sends no data anywhere.
- In **Family Mode** it does not touch user accounts, passwords, or FileVault.
  **It cannot lock anyone out of their Mac.** Everything it changes is reversible.

## Try it without changing anything first

On the first screen there is a switch: **"Preview only — don't change anything."**
Turn it on and walk all the way through. You'll get a plain-English list of every
change, what you'd notice, and how to undo each one. Nothing is modified and no
files are saved. When you're happy, press **Apply These Changes For Real**.

If you're unsure about running an app someone handed you on your family's Mac,
start here.

## How to run it

1. Open **Family Safety Setup**.
2. Choose **Family Mode**.
3. Press **Continue**, then **Review Changes** — this shows you exactly what
   will change before anything happens.
4. Press **Apply**. Enter your Mac password when asked.
5. The app saves a **profile** to your Downloads folder. Double-click it, then go
   to **System Settings › General › Device Management** and click **Install**.
6. Back in the app, press **Verify Again** to confirm filtering is live.

## The two things that matter more than this app

**1. Screen Time through Family Sharing.** On your own Mac or iPhone, go to
**System Settings › Family**, create a **Child Account** for your child, then
turn on **Screen Time** for them from your device. Set a Screen Time passcode
that is not their login password.

This is the important one: configured this way, it is enforced from *your*
device and cannot be turned off on their Mac.

In Screen Time, set:
- Content & Privacy → **On**
- Web Content → **Limit Adult Websites**
- App Store → Installing Apps → **Don't Allow**

**2. Give them a standard account, not an administrator account.**
System Settings › Users & Groups. An administrator can undo everything above; a
standard user cannot. If their account is currently an admin, make a separate
admin account for yourself and switch theirs to standard.

## Honest limitations

- **A phone hotspot bypasses all of this.** If they connect the Mac to their
  phone's hotspot, none of the filtering applies. No Mac setting can prevent
  that — it needs Screen Time on the phone.
- Blocked sites show a "cannot connect" error rather than a friendly message.
  Redirecting them elsewhere isn't possible over HTTPS without intercepting all
  traffic, which would be far worse for your family's security.
- Filtering is very good, not perfect. New proxy sites appear constantly.

## To undo everything

Remove the profile in **System Settings › General › Device Management**, and
restore the hosts file backup at `/etc/hosts.familysafety.backup`.
