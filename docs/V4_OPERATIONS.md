# event-ipsec-hub V4 运维与上线手册

本文档面向在授权 **Ubuntu 24.04 LTS** VPS 上部署单文件 Go VPN 网关（`ipsecvpn`）的运维与赛事网络工程师。

---

## 1. 部署前准备（VPS 基线）

1. 准备一台全新或无现有 IPsec 服务的 **Ubuntu 24.04 (`amd64`)** 主机，确认 SSH 端口与安全组已放行：
   - `UDP 500`、`UDP 4500`（IKEv2 / NAT-T）
   - `ESP (IP protocol 50)`（如云厂商安全组支持放行）
   - `TCP 18443`（Web 管理台 HTTPS，**建议安全组仅放行运维来源 IP**）
2. 启用内核转发与非对称回程兼容（双线必须）：
   ```bash
   sudo tee /etc/sysctl.d/90-ipsecvpn.conf <<'EOF'
   net.ipv4.ip_forward = 1
   net.ipv4.conf.all.rp_filter = 2
   net.ipv4.conf.default.rp_filter = 2
   EOF
   sudo sysctl -p /etc/sysctl.d/90-ipsecvpn.conf
   ```
3. 创建授权主机标记（root-only `0600`）：
   ```bash
   sudo install -d -m 0700 /etc/ipsecvpn
   printf 'ipsecvpn-prod-v1\n' | sudo tee /etc/ipsecvpn/host-authorized >/dev/null
   sudo chmod 0600 /etc/ipsecvpn/host-authorized
   ```

---

## 2. 安装单文件网关与控制台

从 GitHub Release（或本地构建 `bin/ipsecvpn-linux-amd64`）拷贝单文件二进制与 `scripts/install-v4.sh` 到 VPS 后执行：

```bash
chmod +x ./ipsecvpn-linux-amd64
# 1) 由 Go 二进制安装 strongSwan (charon-systemd) 与开机防泄露/自恢复单元
sudo ./ipsecvpn-linux-amd64 install --dry-run --json
sudo ./ipsecvpn-linux-amd64 install --confirm --json

# 2) 安装权限分离的 systemd 服务（root Agent + 非 root Web 控制台）
sudo IPSECVPN_PUBLIC_IP=<VPS公网IP> IPSECVPN_WEB_PORT=18443 \
  bash scripts/install-v4.sh ./ipsecvpn-linux-amd64
```

安装完成后检查服务与初始管理员密码：

```bash
sudo systemctl status ipsecvpn-agent.service ipsecvpn-web.service strongswan.service
sudo journalctl -u ipsecvpn-web.service -n 30 --no-pager | grep BOOTSTRAP_ADMIN
```

---

## 3. 首次登录与安全加固

1. 浏览器访问 `https://<VPS公网IP>:18443`（首次为自动生成的 IP-SAN TLS 1.3 自签名证书，信任后进入）。
2. 使用日志中打印的 `admin` 初始密码登录。
3. 立即进入 **系统设置**：
   - 修改管理员强密码，建议开启 **两步验证 (TOTP)**；
   - 配置 **管理来源 IP / 网段白名单**；
   - 设置 **控制台自动停用时间**（例如赛事结束后次日 06:00 自动拒绝公网访问）。

---

## 4. 配置 VPN 通道、写入密钥并下发生效

1. 进入 **VPN 通道 → 通道列表**：
   - 点 **编辑网关参数** 填写本端公网 IP 与标识（默认 `IPv4 地址` 留空即跟随公网 IP）；
   - 点 **+ 新建通道** 在右侧抽屉填写各演播室/机房站点信息（对端公网 IP、内网网段、厂商、协商模式、`if_id`）；
   - 在 **站点互通策略** 中只放行需要互通的站点对（未配置站点默认经 `nftables` 隔离）；
   - 按需调整 **IKE / IPsec 安全参数**（仅允许 IKEv2 强加密套件）。
2. 切到 **预共享密钥 (PSK)** 子页签，为每个站点点击 **随机生成 → 写入密钥**（仅写入 `/etc/ipsecvpn/secrets/*.psk` `0600`，不落库、不明文回显）。
3. 回到 **通道列表**：
   - 点击 **保存配置** → **变更预检 (Dry-Run)** → 确认无误后点 **应用生效**。
4. 进入 **配置导出**（或通道行上的「导出配置」）：
   - 选择对端站点与格式（`标准 JSON 配置 (IKEv2)` / `山石参数单` / `通用参数单` / `山石 CLI 参考` / `strongSwan 参考`）；
   - 默认 PSK 脱敏为 `<SEND_SEPARATELY>`；如需一次性交付含明文 PSK 的文件，勾选「包含预共享密钥明文」并二次验证管理员密码（全量记入操作日志）。

---

## 5. 配置飞书告警与四层监控

1. 进入 **告警管理**：
   - 填入官方飞书机器人 Webhook（`https://open.feishu.cn/open-apis/bot/v2/hook/...`）与可选加签密钥；
   - 点击 **发送测试消息** 验证群内送达，再点 **保存通道配置**（完整凭证仅存于 `/etc/ipsecvpn/secrets/feishu-channel.json` `0600`，Agent 热加载生效）。
   - 也可以在 SSH 中直接用命令行验证：
     ```bash
     /usr/local/sbin/ipsecvpn alert test-feishu --webhook "https://open.feishu.cn/open-apis/bot/v2/hook/<TOKEN>"
     ```
2. 进入 **链路监控** 查看外层公网、IKE/IPsec 隧道、通道带宽与拦截、内网端到端探针四层联动波形；赛期值守可打开右上角 **15 秒自动刷新**。
3. 进入 **事件日志** 按精确时间段、站点、级别、层级或关键词检索历史事件，点击任意站点事件的 **查看波形** 即可回看该时刻前后 30 分钟波形。

---

## 6. 主备切换演练与单条隧道排障

- **单条隧道排障**：在 **概览** 页的隧道列表中，可直接对异常站点点击 **重连** 或 **重协商 (Child SA)**，无需 SSH 执行 `swanctl`。
- **主备门控切换**：在 **主备切换** 页点击 **切换至备路**（勾选联动关闭本端 XFRM 通道），网关锁定 `BACKUP_LOCKED` 防止对端自动抢占回切；主线稳定满 180 秒后人工点击 **确认回切主路**。
- **赛前核对单**：在 **系统设置** 右上角点击 **导出上线核对单**，用于赛前逐项签收。

---

## 7. 赛后停服与干净卸载

- **保留隧道但关闭 Web 控制台（推荐）**：
  ```bash
  sudo systemctl disable --now ipsecvpn-web.service
  ```
- **完整卸载恢复主机基线**：
  ```bash
  sudo systemctl disable --now ipsecvpn-web.service ipsecvpn-agent.service
  sudo /usr/local/sbin/ipsecvpn uninstall --dry-run --json
  sudo /usr/local/sbin/ipsecvpn uninstall --confirm --json
  ```
  卸载过程仅移除本工具托管的 `strongSwan` 配置、XFRM 接口与 `table ip ipsecvpn`，不会影响主机原有 SSH、默认路由及其他防火墙表。
