#!/usr/bin/env bash
# A disposable QEMU guest. Host sudo installs tooling only, with no host network changes.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
pidfile="$work/qemu.pid"
known_hosts="$work/known_hosts"
ssh_options=(-i "$work/key" -o "UserKnownHostsFile=$known_hosts" -o StrictHostKeyChecking=accept-new
             -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=5)

guest() { ssh "${ssh_options[@]}" -p 2222 ubuntu@127.0.0.1 "$@"; }
cleanup() {
    code=$?
    trap - EXIT
    guest 'sudo cat /var/tmp/ipsecvpn-acceptance.jsonl' 2>/dev/null || true
    if [[ -s "$pidfile" ]]; then kill -- "$(cat "$pidfile")" 2>/dev/null || true; fi
    rm -rf -- "$work"
    exit "$code"
}
trap cleanup EXIT

sudo apt-get -qq update
sudo apt-get -qq install -y --no-install-recommends qemu-system-x86 qemu-utils cloud-image-utils dpkg-dev
mkdir -p "$work/payload/apt" "$work/payload/wheels" "$work/apt-archives"
sudo apt-get -qq -y --download-only --no-install-recommends \
    -o Dir::State::status=/dev/null -o "Dir::Cache::archives=$work/apt-archives" \
    install charon-systemd strongswan-swanctl nftables iproute2 python3-venv iptables ufw
cp "$work"/apt-archives/*.deb "$work/payload/apt/"
(cd "$work/payload/apt" && dpkg-scanpackages -m . /dev/null > Packages)
python -m pip wheel --wheel-dir "$work/payload/wheels" "$root"
cp "$root"/scripts/pr2-vm/{guest.sh,verify.py} "$work/payload/"
cp "$root/config/event.example.yaml" "$work/payload/example.yaml"

image=noble-server-cloudimg-amd64.img
origin=https://cloud-images.ubuntu.com/noble/current
curl --fail --silent --show-error --location --retry 3 "$origin/$image" -o "$work/$image"
curl --fail --silent --show-error --location --retry 3 "$origin/SHA256SUMS" -o "$work/SHA256SUMS"
(cd "$work" && awk -v name="$image" '$2 == "*" name || $2 == name {print}' SHA256SUMS | sha256sum -c -)
qemu-img resize "$work/$image" 10G
ssh-keygen -q -t ed25519 -N '' -f "$work/key"
printf '#cloud-config\nssh_authorized_keys:\n  - %s\npackage_update: false\npackage_upgrade: false\n' \
    "$(cat "$work/key.pub")" > "$work/user-data"
printf 'instance-id: ipsecvpn-pr2-lab\nlocal-hostname: ipsecvpn-pr2-lab\n' > "$work/meta-data"
cat > "$work/network-config" <<'EOF'
version: 2
ethernets:
  labwan:
    match:
      macaddress: "52:54:00:12:34:56"
    set-name: labwan
    addresses: [10.0.2.15/24]
    routes:
      - to: default
        via: 10.0.2.2
EOF
cloud-localds --network-config="$work/network-config" "$work/seed.img" "$work/user-data" "$work/meta-data"

accel=tcg
if [[ -r /dev/kvm && -w /dev/kvm ]]; then accel=kvm; fi
qemu-system-x86_64 -accel "$accel" -machine q35 -smp 2 -m 3072 -display none \
    -daemonize -pidfile "$pidfile" -serial "file:$work/console.log" \
    -drive "file=$work/$image,if=virtio,format=qcow2" \
    -drive "file=$work/seed.img,if=virtio,format=raw,readonly=on" \
    -netdev user,id=isolated,restrict=on,ipv6=off,hostfwd=tcp:127.0.0.1:2222-:22 \
    -device virtio-net-pci,netdev=isolated,mac=52:54:00:12:34:56

wait_ssh() {
    local _
    for _ in {1..100}; do
        if guest 'true' 2>/dev/null; then return 0; fi
        sleep 3
    done
    printf '%s\n' 'STOP: isolated Ubuntu guest SSH did not come up.' >&2
    return 1
}
wait_ssh
guest 'cloud-init status --wait'
scp "${ssh_options[@]}" -P 2222 -r "$work/payload" ubuntu@127.0.0.1:lab
guest 'sudo bash /home/ubuntu/lab/guest.sh'
before="$(guest 'cat /proc/sys/kernel/random/boot_id')"
guest 'sudo systemctl reboot --no-block'
for _ in {1..100}; do
    after="$(guest 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)"
    if [[ -n "$after" && "$before" != "$after" ]]; then break; fi
    sleep 3
done
if [[ -z "$after" || "$before" == "$after" ]]; then
    printf '%s\n' 'FAIL V17: an actual guest reboot was not observed.' >&2
    exit 1
fi
guest 'sudo /opt/ipsecvpn-lab/venv/bin/python /opt/ipsecvpn-lab/verify.py after-reboot'
