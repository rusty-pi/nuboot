#!/usr/bin/env bash
# Check out CrabEFI at the pinned revision into third_party/crabefi and apply
# this tree's patches to it. Run once before building uefi/; running it again
# leaves a matching checkout as it is.
set -euo pipefail

CRABEFI_URL="${CRABEFI_URL:-https://github.com/ArthurHeymans/CrabEFI.git}"
CRABEFI_REV="${CRABEFI_REV:-3ba0ab88ac21fae8d516935dd2b2940ea8247ed7}"

here="$(cd "$(dirname "$0")/.." && pwd)"
dst="$here/third_party/crabefi"
stamp="$dst/.pi4-patched"
want="$CRABEFI_REV $(cat "$here"/patches/crabefi/*.patch | sha256sum | cut -d' ' -f1)"

if [[ -f "$stamp" && "$(cat "$stamp")" == "$want" ]]; then
  exit 0
fi

if [[ ! -d "$dst/.git" ]]; then
  mkdir -p "$dst"
  git -C "$dst" init -q
  git -C "$dst" remote add origin "$CRABEFI_URL"
fi
git -C "$dst" fetch -q --depth 1 origin "$CRABEFI_REV"
git -C "$dst" checkout -q --force FETCH_HEAD
git -C "$dst" clean -qfdx
for p in "$here"/patches/crabefi/*.patch; do
  git -C "$dst" apply "$p"
done
echo "$want" > "$stamp"
echo "CrabEFI $CRABEFI_REV with $(ls "$here"/patches/crabefi | wc -l) patch(es) in $dst"
