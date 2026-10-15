#!/bin/bash
# Boots the named scenarios in pimu, JOBS at a time (default: one a CPU), and
# prints each one's output as a group once it has finished.
#
#   scripts/run-scenarios.sh uefi-hello linux persist
#
# Exits 1 if any scenario failed.
set -u
cd "$(dirname "$0")/.."

[ $# -gt 0 ] || { echo "usage: $0 <scenario>..." >&2; exit 2; }

results=$(mktemp -d)
export results

run_one() {
    name=$1
    start=$SECONDS
    if pimu boot --scenario "scenarios/$name.yaml" >"$results/$name.out" 2>&1; then
        status=pass
    else
        status=fail
    fi
    seconds=$((SECONDS - start))
    echo "$status $seconds" >"$results/$name.result"
    printf '%-4s %-28s %5ss\n' "$status" "$name" "$seconds"
}
export -f run_one

printf '%s\n' "$@" | xargs -P "${JOBS:-$(nproc)}" -I{} bash -c 'run_one {}'

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '| scenario | result | time |\n| --- | --- | --- |\n' >>"$GITHUB_STEP_SUMMARY"
fi

failed=0
for name in "$@"; do
    read -r status seconds <"$results/$name.result" || { status=fail; seconds=0; }
    echo "::group::$status  $name  ${seconds}s"
    cat "$results/$name.out" 2>/dev/null
    echo "::endgroup::"
    if [ "$status" != pass ]; then
        echo "::error title=scenario $name failed::scenarios/$name.yaml"
        failed=$((failed + 1))
    fi
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        echo "| $name | $status | ${seconds}s |" >>"$GITHUB_STEP_SUMMARY"
    fi
done

echo "$# scenarios, $failed failed"
[ "$failed" -eq 0 ]
