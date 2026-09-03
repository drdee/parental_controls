#!/bin/bash
#
# Generates a Certificate Signing Request for a Developer ID certificate.
#
# Xcode's "Manage Certificates" only offers certificate types it thinks your
# team is entitled to, and it caches that judgement. When it shows a free
# "Personal Team" it will not offer Developer ID at all, even after you have
# paid. Uploading a CSR through the web portal sidesteps Xcode completely.
set -euo pipefail

NAME="${1:-}"
EMAIL="${2:-}"
if [ -z "$NAME" ] || [ -z "$EMAIL" ]; then
  cat >&2 <<USAGE
Usage: tools/make-csr.sh "Your Legal Name" you@example.com

Creates:
  ~/Desktop/DeveloperID.certSigningRequest   upload this to Apple
  ~/Desktop/DeveloperID.key                  keep this; it is the private key
USAGE
  exit 2
fi

OUT="$HOME/Desktop"
KEY="$OUT/DeveloperID.key"
CSR="$OUT/DeveloperID.certSigningRequest"

echo "==> Generating a 2048-bit RSA key (Apple's requirement)"
openssl genrsa -out "$KEY" 2048

echo "==> Generating the signing request"
openssl req -new -key "$KEY" -out "$CSR" \
  -subj "/emailAddress=$EMAIL/CN=$NAME/C=US"

chmod 600 "$KEY"

cat <<NEXT

Done.

  request : $CSR
  key     : $KEY   (private — do not share, do not commit)

Next:
  1. https://developer.apple.com/account/resources/certificates/add
  2. Choose "Developer ID Application", upload the .certSigningRequest
  3. Download the .cer and double-click it to add it to your keychain
  4. Repeat from step 1 for "Developer ID Installer"
     (you can reuse the same CSR)
  5. Confirm both arrived:
       security find-identity -v | grep "Developer ID"

If "Developer ID Application" is not offered on that page, the paid
membership is not active on this Apple ID — check Membership Details at
https://developer.apple.com/account
NEXT
