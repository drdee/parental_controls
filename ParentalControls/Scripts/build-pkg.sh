#!/bin/bash
#
# Builds, signs and notarizes the installer package.
#
# The package's postinstall runs as root under `installer`, so the app itself
# needs no privilege escalation. Signing and notarization live here rather than
# in the app: a tool a parent runs should not carry signing behaviour.
#
# Usage:
#   ./Scripts/build-pkg.sh                      # unsigned, for local testing
#   INSTALLER_IDENTITY="Developer ID Installer: Your Name (TEAMID)" \
#   APPLE_ID=you@example.com TEAM_ID=TEAMID \
#   NOTARY_PASSWORD=app-specific-password \
#     ./Scripts/build-pkg.sh                    # signed + notarized
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build"
STAGE="$BUILD/pkgroot"
PKG="$BUILD/Family-Safety.pkg"
IDENTIFIER="com.familysafety.setup.pkg"
VERSION="${VERSION:-1.0}"

MODE="${MODE:-family}"
if [ "$MODE" != "family" ] && [ "$MODE" != "advanced" ]; then
  echo "MODE must be 'family' or 'advanced' (got '$MODE')." >&2
  exit 1
fi

echo "==> Generating postinstall for MODE=$MODE"
rm -rf "$STAGE"
mkdir -p "$STAGE/scripts"

# The app is the single source of truth for what the script does, so ask it.
# --emit-package-scripts prints the postinstall and the profile it needs.
swift build -c release --package-path "$ROOT" >/dev/null
BIN="$(swift build -c release --package-path "$ROOT" --show-bin-path)/ParentalControls"
"$BIN" --emit-package-scripts "$MODE" "$STAGE/scripts"

chmod +x "$STAGE/scripts/postinstall"

echo "==> Checking generated script syntax"
# A broken script would otherwise fail silently at install time, after the
# user has already authenticated.
bash -n "$STAGE/scripts/postinstall"

echo "==> Building package"
rm -f "$PKG"
pkgbuild --nopayload \
  --scripts "$STAGE/scripts" \
  --identifier "$IDENTIFIER" \
  --version "$VERSION" \
  "$PKG" >/dev/null

if [ -n "${INSTALLER_IDENTITY:-}" ]; then
  echo "==> Signing with: $INSTALLER_IDENTITY"
  productsign --sign "$INSTALLER_IDENTITY" "$PKG" "$PKG.signed"
  mv "$PKG.signed" "$PKG"
  pkgutil --check-signature "$PKG" | sed 's/^/    /'
else
  echo "==> Unsigned (set INSTALLER_IDENTITY to sign)"
  echo "    An unsigned package warns on other Macs; fine for local testing."
fi

if [ -n "${NOTARY_PASSWORD:-}" ] && [ -n "${APPLE_ID:-}" ] && [ -n "${TEAM_ID:-}" ]; then
  echo "==> Notarizing (this waits for Apple, usually a few minutes)"
  xcrun notarytool submit "$PKG" \
    --apple-id "$APPLE_ID" \
    --team-id "$TEAM_ID" \
    --password "$NOTARY_PASSWORD" \
    --wait
  echo "==> Stapling the notarization ticket"
  xcrun stapler staple "$PKG"
  xcrun stapler validate "$PKG"
else
  echo "==> Not notarized (set APPLE_ID, TEAM_ID and NOTARY_PASSWORD to notarize)"
fi

echo ""
echo "Built: $PKG"
ls -lh "$PKG" | awk '{print "    " $5, $9}'
