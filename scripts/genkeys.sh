#!/bin/sh
# Generate the Secure Boot keys in keys/ (never committed) that are missing:
#
#   pk   the platform key, built into the firmware and never changeable
#   kek  signs updates to db and dbx
#   db   signs what the firmware boots: boot loaders, kernels and modules
#   update  signs the bundles that update the firmware without the board
#        owner's signature (below)
#
# Each has a .key (private), .crt (PEM) and .der (what the firmware embeds).
# One whose .der is there is left alone, with or without its .key: a build host
# that keeps the private keys elsewhere holds the .der files only, and must not
# get a new platform key because a .key is not there. A .key with no .der is an
# error. Keep keys/ out of CI; CI needs the .der files only
# (scripts/build-uefi.sh reads PI4_PK_CERT, PI4_KEK_CERT and PI4_DB_CERT).
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
keys="${PI4_KEYS:-$root/keys}"
mkdir -p "$keys"
chmod 700 "$keys"

# name, subject, bits, days
generate() {
  if [ -f "$keys/$1.der" ]; then
    if [ -f "$keys/$1.crt" ] && ! openssl x509 -in "$keys/$1.crt" -outform DER | cmp -s - "$keys/$1.der"; then
      echo "keys/$1: $1.crt and $1.der are not the same certificate" >&2
      exit 1
    fi
    return
  fi
  if [ -f "$keys/$1.key" ]; then
    echo "keys/$1: $1.key is there and $1.der is not; refusing to make a new $1 beside it" >&2
    exit 1
  fi
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

# The update key is a P-256 key: update.key (PEM) signs the bundles, and
# update.pub, the 64 bytes of the public point, is what the firmware carries.
if [ ! -f "$keys/update.pub" ]; then
  if [ -f "$keys/update.key" ]; then
    echo "keys/update: update.key is there and update.pub is not; refusing to make a new update key beside it" >&2
    exit 1
  fi
  openssl ecparam -name prime256v1 -genkey -noout -out "$keys/update.key"
  openssl ec -in "$keys/update.key" -pubout -outform DER 2>/dev/null | tail -c 64 >"$keys/update.pub"
  chmod 600 "$keys/update.key"
  echo "keys/update: generated"
fi
