# Router-level DNS

The app configures one Mac. The router covers every device on the network and
survives that Mac being erased and reinstalled. If you only do one thing beyond
the app, do this.

## What to set

**Cloudflare for Families** (malware + adult content, no account):

```
IPv4:  1.1.1.3, 1.0.0.3
IPv6:  2606:4700:4700::1113, 2606:4700:4700::1003
```

Set **both** families. A device with IPv6 nameservers will resolve straight past
an IPv4-only filter.

**Cloudflare Zero Trust** — if you have it configured, point the router at your
gateway instead. You get a real social-media content category, SafeSearch, custom
lists, and query logs.

## Where

Router admin → DHCP or LAN settings → DNS servers. Set them as the *DHCP-advertised*
resolvers so every device inherits them. Then reboot a device and confirm.

## Also worth blocking at the router

These close bypasses no Mac setting can reach:

| Block | Why |
|---|---|
| Outbound TCP/UDP **:53** except to your resolver | Defeats hardcoded DNS |
| Outbound TCP **:853** (DoT) | Defeats DNS-over-TLS clients |
| `mask.icloud.com`, `mask-h2.icloud.com` | iCloud Private Relay tunnels DNS |
| Known public DoH hostnames | Browsers with their own resolver |

Egress-blocking port 53 is the single most effective control on this list, and it
is only possible at the router.

## The limit

Router DNS applies **only on your Wi-Fi**. It does nothing on a phone hotspot,
on cellular, or at a friend's house. Nothing you configure on the network or the
laptop changes that — see `BYPASS-NOTES.md`.
