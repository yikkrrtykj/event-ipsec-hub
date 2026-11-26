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

if [[ ! -f "$BIN_SRC" ]]; then
    echo "ERROR: binary not found at $BIN_SRC (usage: sudo $0 /path/to/ipsecvpn)" >&2
    exit 2
fi

if ! id -u ipsecvpn-web >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin ipsecvpn-web
fi

install -d -m 0755 /usr/local/sbin /run/ipsecvpn
install -d -m 0750 -o root -g ipsecvpn-web /var/lib/ipsecvpn
install -d -m 0700 -o root -g root /etc/ipsecvpn /etc/ipsecvpn/profiles /etc/ipsecvpn/secrets /etc/ipsecvpn/tls
install -m 0755 -o root -g root "$BIN_SRC" /usr/local/sbin/ipsecvpn

WEB_UID="$(id -u ipsecvpn-web)"

cat > /etc/systemd/system/ipsecvpn-agent.service <<EOF
[Unit]
Description=event-ipsec-hub V4 privileged Hub Agent (root)
After=network-online.target strongswan.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/ipsecvpn agent serve --allow-uid ${WEB_UID}
Restart=on-failure
RestartSec=3s
UMask=0077

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
ExecStart=/usr/local/sbin/ipsecvpn web serve --listen :${WEB_PORT} --cert /var/lib/ipsecvpn/tls-cert.pem --key /var/lib/ipsecvpn/tls-key.pem ${EXTRA_IP_FLAG}
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
ReadWritePaths=/var/lib/ipsecvpn
UMask=0027

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ipsecvpn-agent.service ipsecvpn-web.service

echo "event-ipsec-hub V4 installed."
echo "Next steps:"
echo "  1. Check initial admin password via: journalctl -u ipsecvpn-web.service -n 20"
echo "  2. Open https://<VPS_IP>:${WEB_PORT} and change password + set IP allowlist."
echo "  3. After tournament ends, stop Web console anytime: sudo systemctl disable --now ipsecvpn-web.service"
