#!/bin/bash
# Drive the firmware's TPM with tpm2-tools through tpm-sim: seal a secret to a
# primary key, to a PCR policy and with HMAC sessions, and check what comes
# back and what is refused.
#
#     tpm2-tools-test.sh PATH-TO-tpm-sim [TOOLS-DIR]
#
# TOOLS-DIR holds the tpm2_* tools; they come from $PATH without it. Without a
# resource manager between the tools and the TPM a tool leaves the objects it
# loaded behind, so the objects are flushed after each tool, as the tools' own
# tests do.
set -u

sim="$1"
tools="${2:-}"
port=$((20000 + RANDOM % 20000))
work="$(mktemp -d)"
trap 'kill "$sim_pid" 2>/dev/null; rm -rf "$work"' EXIT

"$sim" --fused "$port" 2>"$work/sim.log" &
sim_pid=$!
sleep 1
export TPM2TOOLS_TCTI="mssim:host=127.0.0.1,port=$port"
cd "$work" || exit 1

failures=0
tool() {
  local name="$1"
  shift
  "${tools:+$tools/}$name" "$@"
  local rc=$?
  "${tools:+$tools/}tpm2_flushcontext" -t >/dev/null 2>&1
  return $rc
}
check() {
  local what="$1"
  shift
  if "$@" >"$work/out.txt" 2>&1; then
    echo "ok: $what"
  else
    echo "FAILED: $what"
    sed 's/^/    /' "$work/out.txt" | tail -8
    failures=$((failures + 1))
  fi
}
refused() {
  local what="$1"
  shift
  if "$@" >"$work/out.txt" 2>&1; then
    echo "FAILED: $what was accepted"
    failures=$((failures + 1))
  else
    echo "ok: $what refused"
  fi
}

echo "top secret" >secret.txt

check "properties" tool tpm2_getcap properties-fixed
check "create the primary storage key" tool tpm2_createprimary -C o -G ecc -c prim.ctx
tool tpm2_readpublic -c prim.ctx -n name1.bin >/dev/null 2>&1
tool tpm2_createprimary -C o -G ecc -c prim2.ctx >/dev/null 2>&1
tool tpm2_readpublic -c prim2.ctx -n name2.bin >/dev/null 2>&1
check "primary keys are deterministic" cmp name1.bin name2.bin

check "seal a secret under the primary" tool tpm2_create -C prim.ctx -i secret.txt -u seal.pub -r seal.priv
check "load it" tool tpm2_load -C prim.ctx -u seal.pub -r seal.priv -c seal.ctx
check "unseal it" tool tpm2_unseal -c seal.ctx -o unsealed.txt
check "the secret is what went in" cmp secret.txt unsealed.txt

# A policy over PCRs 0 and 7: a trial session computes its digest, a policy
# session proves it.
check "a trial session" tool tpm2_startauthsession -S trial.ctx
check "the trial policy" tool tpm2_policypcr -S trial.ctx -l sha256:0,7 -L pcr.policy
tool tpm2_flushcontext trial.ctx >/dev/null 2>&1
check "seal under the PCR policy" tool tpm2_create -C prim.ctx -i secret.txt -L pcr.policy -a "fixedtpm|fixedparent|noda" -u pseal.pub -r pseal.priv
check "load the sealed object" tool tpm2_load -C prim.ctx -u pseal.pub -r pseal.priv -c pseal.ctx
unseal_with_policy() {
  tool tpm2_startauthsession --policy-session -S pol.ctx || return 1
  tool tpm2_policypcr -S pol.ctx -l sha256:0,7 || return 1
  tool tpm2_unseal -c pseal.ctx -p session:pol.ctx -o "$1"
}
check "unseal with the PCRs as they were" unseal_with_policy pol-out.txt
check "the policy-sealed secret is what went in" cmp secret.txt pol-out.txt
refused "unseal without the policy" tool tpm2_unseal -c pseal.ctx
tool tpm2_pcrextend 7:sha256=0000000000000000000000000000000000000000000000000000000000000001 >/dev/null 2>&1
refused "unseal after PCR 7 changed" unseal_with_policy pol-out2.txt

# An HMAC session salted to the primary key, which also encrypts the secret on
# its way in.
check "a salted HMAC session" tool tpm2_startauthsession --hmac-session -c prim.ctx -S hmac.ctx
check "encrypt and decrypt with it" tool tpm2_sessionconfig hmac.ctx --enable-encrypt --enable-decrypt
check "seal through the session" tool tpm2_create -C prim.ctx -i secret.txt -u hseal.pub -r hseal.priv -P session:hmac.ctx
check "load the object sealed through the session" tool tpm2_load -C prim.ctx -u hseal.pub -r hseal.priv -c hseal.ctx
check "unseal it" tool tpm2_unseal -c hseal.ctx -o hout.txt
check "the secret is what went in" cmp secret.txt hout.txt

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
