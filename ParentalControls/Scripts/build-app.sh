#!/bin/bash
# Builds ParentalControls.app from the SPM executable.
#
# SPM produces a bare binary; macOS needs a bundle with an Info.plist for a
# double-clickable, code-signable app.
set -euo pipefail

CONFIG="${1:-release}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/build/ParentalControls.app"

cd "$ROOT"
swift build -c "$CONFIG"
BIN="$(swift build -c "$CONFIG" --show-bin-path)/ParentalControls"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/ParentalControls"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>              <string>Family Safety Setup</string>
  <key>CFBundleDisplayName</key>       <string>Family Safety Setup</string>
  <key>CFBundleIdentifier</key>        <string>com.familysafety.setup</string>
  <key>CFBundleVersion</key>           <string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleExecutable</key>        <string>ParentalControls</string>
  <key>CFBundlePackageType</key>       <string>APPL</string>
  <key>LSMinimumSystemVersion</key>    <string>14.0</string>
  <key>LSApplicationCategoryType</key> <string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key>   <true/>
</dict>
</plist>
PLIST

plutil -lint "$APP/Contents/Info.plist"

# Ad-hoc signing is enough to run locally. Distribution needs a personal
# Developer ID — deliberately not defaulting to any identity found on the
# machine, which may belong to an employer.
IDENTITY="${CODESIGN_IDENTITY:--}"
codesign --force --deep --sign "$IDENTITY" \
  --options runtime --timestamp=none "$APP" 2>&1 | sed 's/^/  /'

echo "Built: $APP"
codesign -dv "$APP" 2>&1 | grep -E "Identifier|Signature|TeamIdentifier" | sed 's/^/  /'
