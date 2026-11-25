# 生产部署与真机验收手册（Ubuntu 24.04 VPS/物理机 + 山石 StoneOS + 腾讯云 VPN 互备）

本手册用于将 `event-ipsec-hub` 部署到真实生产 VPS / 物理机（Ubuntu 24.04），对接多路山石（Hillstone）防火墙 OB 站点与中心比赛服务器，并与腾讯云托管 VPN（或第二台自建 Hub）组成**自动无感切备 + 人工确认回切**架构。

## 1. Hub 主机准入与初始化（Ubuntu 24.04）

1. **开启内核 IPv4 转发并关闭 rp_filter 严格模式（双 ISP 对称回程必备）**：
   ```bash
   cat <<'EOF' | sudo tee /etc/sysctl.d/99-ipsecvpn.conf
   net.ipv4.ip_forward = 1
   net.ipv4.conf.all.rp_filter = 2
   net.ipv4.conf.default.rp_filter = 2
   EOF
   sudo sysctl --system
   ```
2. **创建生产授权标记（解除 QEMU 实验室限制）**：
   ```bash
   sudo install -d -m 0700 /etc/ipsecvpn /etc/ipsecvpn/secrets /etc/ipsecvpn/profiles
   printf 'ipsecvpn-prod-v1\n' | sudo tee /etc/ipsecvpn/host-authorized >/dev/null
   sudo chmod 0600 /etc/ipsecvpn/host-authorized
   ```
3. **准备高强度 PSK 与飞书 Webhook 密钥（严格 `0600`）**：
   ```bash
   # 每个站点生成独立 64 位十六进制 PSK
   openssl rand -hex 32 | sudo tee /etc/ipsecvpn/secrets/server-core.psk >/dev/null
   openssl rand -hex 32 | sudo tee /etc/ipsecvpn/secrets/ob-venue-1.psk >/dev/null
   openssl rand -hex 32 | sudo tee /etc/ipsecvpn/secrets/ob-venue-2.psk >/dev/null
   # 飞书告警机器人配置（严格 0600，仅生产模式放行 open.feishu.cn HTTPS 出网）
   openssl rand -hex 32 | sudo tee /etc/ipsecvpn/secrets/monitor-signing >/dev/null
   openssl rand -hex 24 | sudo tee /etc/ipsecvpn/secrets/monitor-bearer >/dev/null
   printf 'https://open.feishu.cn/open-apis/bot/v2/hook/<YOUR_HOOK_ID>\n' | sudo tee /etc/ipsecvpn/secrets/feishu-webhook >/dev/null
   cat <<'EOF' | sudo tee /etc/ipsecvpn/monitor-bridge.json >/dev/null
   {
     "enabled": true,
     "port": 9815,
     "feishu_webhook_ref": "file:/etc/ipsecvpn/secrets/feishu-webhook"
   }
   EOF
   sudo chmod 0600 /etc/ipsecvpn/secrets/* /etc/ipsecvpn/monitor-bridge.json
   ```

## 2. 生成配置并离线渲染校验

基于 `config/esports-multi-ob-hillstone.example.yaml` 替换为真实公网 IP、网卡名、内网 CIDR 和双 ISP `route_table`，执行：

```bash
ipsecvpn validate -c /etc/ipsecvpn/profiles/match.yaml
ipsecvpn render -c /etc/ipsecvpn/profiles/match.yaml --json
ipsecvpn export-peer -c /etc/ipsecvpn/profiles/match.yaml --site server-core --format md
ipsecvpn export-peer -c /etc/ipsecvpn/profiles/match.yaml --site ob-venue-1 --format md
```

## 3. 山石（StoneOS）防火墙对接要点（路由型 `route_based` 推荐）

1. **IKEv2 Peer & 提议**：与导出参数单完全一致（`AES256-SHA256-DH14`，关闭 NAT 转换豁免内网互访，开启 DPD 30s）。
2. **绑定 `tunnel` 接口（路由型）**：Phase 2 代理 ID 设为 `0.0.0.0/0 <-> 0.0.0.0/0`，将 IPsec 隧道绑定至 `tunnel1`（主 Hub）和 `tunnel2`（备 Hub / 腾讯云 VPN）。
3. **精确静态路由与主备优先级**：
   - 仅将授权服务器网段指向 `tunnel1`（高优先级，例如 metric `10`），备链路 `tunnel2` 设为低优先级（例如 metric `30`）。
   - 配置山石 `track` 对象探测主隧道远端可达性，主隧道断开时自动失效主路由，无感切入 `tunnel2`。
4. **安全策略与 NAT 豁免**：
   - 在 `LAN -> VPN` 与 `VPN -> LAN` 方向仅放行授权网段；
   - 在公网 SNAT 规则之前添加 `LAN <-> 远端授权网段` 的 `NO-NAT` 规则，保证原始源 IP 透传。

## 4. Hub 上线部署与多 OB 隔离验收

```bash
# 1. 安装 strongSwan 托管服务
sudo ipsecvpn install --confirm

# 2. 先 dry-run 检查差异，再 apply 上线
sudo ipsecvpn apply -c /etc/ipsecvpn/profiles/match.yaml --dry-run
sudo ipsecvpn apply -c /etc/ipsecvpn/profiles/match.yaml --confirm

# 3. 核验隧道、XFRM 策略、双 ISP 策略路由与 nftables
sudo ipsecvpn status --json
sudo ip -4 rule show
sudo nft list table ip ipsecvpn

# 4. 按需启动只读监控与飞书告警桥
sudo ipsecvpn monitor serve --with-bridge --confirm
```

**赛前必测 4 项验收清单**：
- [ ] **正向互通**：`OB-1 <-> Server` 与 `OB-2 <-> Server` 双向 UDP/TCP 延迟、丢包、原始源 IP 正常。
- [ ] **OB 间强制隔离**：从 `OB-1` 访问 `OB-2` 任意 IP，确认在 Hub `chain forward` 被 `drop`（计数递增、无回包）。
- [ ] **自动切备 + 隧道门控锁死（防赛中自动抢占回切）**：人为断开主链路或触发探针评估，确认连续失败后自动切备并锁定 `BACKUP_LOCKED`，`--apply-gate` 将 Hub 侧 XFRM 接口置为 `DOWN`（阻止主线闪断恢复后山石 `track` 自动抢占回切），同时飞书群收到告警：
  ```bash
  sudo ipsecvpn failover evaluate --primary-unhealthy --backup-healthy --apply-gate --send-feishu --json
  ```
- [ ] **人工确认回切**：恢复主链路外层连通并观察满 180 秒（进入 `PRIMARY_RECOVERY_READY`），确认系统**未自动回切**；待中场休息由运维人工确认解锁 XFRM 门控并回切：
  ```bash
  sudo ipsecvpn failover status --json
  sudo ipsecvpn failover failback --operator <your-name> --apply-gate --send-feishu --confirm
  ```
