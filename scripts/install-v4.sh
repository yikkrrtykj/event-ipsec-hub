#!/usr/bin/env bash
# Thin bootstrap installer for event-ipsec-hub V4 single-binary Go gateway on Ubuntu 24.04.
# All configuration validation, strongSwan management, and transactions stay inside Go.
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: run as root on Ubuntu 24.04." >&2
    exit 1
fi

BIN_SRC="${1:-./ipsecvpn}"
WEB_PORT="${IPSECVPN_WEB_PORT:-18443}"
PUBLIC_IP="${IPSECVPN_PUBLIC_IP:-}"

if [[ -z "$PUBLIC_IP" ]]; then
    PUBLIC_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' || true)"
    if [[ -z "$PUBLIC_IP" ]]; then
        PUBLIC_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    fi
fi

if [[ ! -f "$BIN_SRC" ]]; then
    echo "ERROR: binary not found at $BIN_SRC (usage: sudo $0 /path/to/ipsecvpn)" >&2
    exit 2
fi

if ! id -u ipsecvpn-web >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin ipsecvpn-web
fi

WEB_UID="$(id -u ipsecvpn-web)"
WEB_GID="$(id -g ipsecvpn-web)"

install -d -m 0755 /usr/local/sbin
install -d -m 0750 -o root -g ipsecvpn-web /run/ipsecvpn
# Keep /var/lib/ipsecvpn strictly root-only (0700) for secureio transaction records;
# isolate shared SQLite WAL & Web TLS data under /var/lib/ipsecvpn-web.
install -d -m 0700 -o root -g root /var/lib/ipsecvpn /etc/ipsecvpn /etc/ipsecvpn/profiles /etc/ipsecvpn/secrets /etc/ipsecvpn/tls
install -d -m 2770 -o root -g ipsecvpn-web /var/lib/ipsecvpn-web
install -d -m 0700 -o ipsecvpn-web -g ipsecvpn-web /var/lib/ipsecvpn-web/tls
if [[ "$(realpath -m "$BIN_SRC")" != "/usr/local/sbin/ipsecvpn" ]]; then
    install -m 0755 -o root -g root "$BIN_SRC" /usr/local/sbin/ipsecvpn
else
    chown root:root /usr/local/sbin/ipsecvpn
    chmod 0755 /usr/local/sbin/ipsecvpn
fi

cat > /etc/tmpfiles.d/ipsecvpn.conf <<EOF
d /run/ipsecvpn 0750 root ipsecvpn-web -
EOF
systemd-tmpfiles --create /etc/tmpfiles.d/ipsecvpn.conf

cat > /etc/systemd/system/ipsecvpn-agent.service <<EOF
[Unit]
Description=event-ipsec-hub V4 privileged Hub Agent (root)
After=network-online.target strongswan.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/ipsecvpn agent serve --db /var/lib/ipsecvpn-web/gateway.db --allow-uid ${WEB_UID} --socket-gid ${WEB_GID}
Restart=on-failure
RestartSec=3s
UMask=0007

[Install]
WantedBy=multi-user.target
EOF

EXTRA_IP_FLAG=""
if [[ -n "$PUBLIC_IP" ]]; then
    EXTRA_IP_FLAG="--public-ip ${PUBLIC_IP}"
fi

cat > /etc/systemd/system/ipsecvpn-web.service <<EOF
[Unit]
Description=event-ipsec-hub V4 Web Console (non-root)
After=network-online.target ipsecvpn-agent.service
Wants=ipsecvpn-agent.service

[Service]
Type=simple
User=ipsecvpn-web
Group=ipsecvpn-web
ExecStart=/usr/local/sbin/ipsecvpn web serve --listen :${WEB_PORT} --db /var/lib/ipsecvpn-web/gateway.db --failover-state /var/lib/ipsecvpn-web/failover-state.json --cert /var/lib/ipsecvpn-web/tls/cert.pem --key /var/lib/ipsecvpn-web/tls/key.pem ${EXTRA_IP_FLAG}
Restart=on-failure
RestartSec=3s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
CapabilityBoundingSet=
ReadWritePaths=/var/lib/ipsecvpn-web /run/ipsecvpn
UMask=0007

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ipsecvpn-agent.service
for _ in {1..30}; do
    if [[ -S /run/ipsecvpn/agent.sock && -f /var/lib/ipsecvpn-web/gateway.db ]]; then
        break
    fi
    sleep 0.2
done
systemctl enable --now ipsecvpn-web.service

DISPLAY_IP="${PUBLIC_IP:-<VPS_IP>}"
echo "event-ipsec-hub V4 installed."
echo "Detected host IP: ${DISPLAY_IP}"
echo "Next steps:"
echo "  1. Check initial admin password via: journalctl -u ipsecvpn-web.service -n 20 --no-pager | grep BOOTSTRAP_ADMIN"
echo "  2. Open https://${DISPLAY_IP}:${WEB_PORT} and change password + set IP allowlist."
echo "  3. After tournament ends, stop Web console anytime: sudo systemctl disable --now ipsecvpn-web.service"
