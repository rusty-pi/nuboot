#!/bin/sh
# Generate the Secure Boot keys in keys/ (never committed) that are missing:
#
#   pk   the platform key, built into the firmware and never changeable
#   kek  signs updates to db and dbx
#   db   signs what the firmware boots: boot loaders, kernels and modules
#
# Each has a .key (private), .crt (PEM) and .der (what the firmware embeds).
# An existing key is left alone. Keep keys/ out of CI; CI needs the .der files
# only (scripts/build-uefi.sh reads PI4_PK_CERT, PI4_KEK_CERT and PI4_DB_CERT).
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
keys="${PI4_KEYS:-$root/keys}"
mkdir -p "$keys"
chmod 700 "$keys"

# name, subject, bits, days
generate() {
  [ -f "$keys/$1.key" ] && [ -f "$keys/$1.der" ] && return
  openssl req -x509 -newkey "rsa:$3" -sha256 -nodes -days "$4" \
    -subj "/CN=pi4-server-firmware $2" \
    -keyout "$keys/$1.key" -out "$keys/$1.crt" 2>/dev/null
  openssl x509 -in "$keys/$1.crt" -outform DER -out "$keys/$1.der"
  chmod 600 "$keys/$1.key"
  echo "keys/$1: generated"
}

generate pk "platform key" 4096 18250
generate kek "key exchange key" 4096 7300
generate db "signing key" 3072 7300
