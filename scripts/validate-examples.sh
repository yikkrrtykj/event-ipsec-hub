#!/usr/bin/env bash
# Offline validation for the public sample and all fictional fixtures.
set -u

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." || exit 1
shopt -s nullglob
fixtures=(tests/fixtures/*.yaml)
if (( ${#fixtures[@]} != 3 )); then
    printf '%s\n' 'FAIL Expected three fictional event fixtures.' >&2
    exit 1
fi
status=0
for profile in config/event.example.yaml "${fixtures[@]}"; do
    printf '%s\n' "$profile"
    if ! ipsecvpn validate -c "$profile"; then
        status=1
    fi
done
exit "$status"
