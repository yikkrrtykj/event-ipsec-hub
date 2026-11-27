# event-ipsec-hub

把一台普通的 **Ubuntu 24.04 云服务器**，一键变成带网页管理后台的 **自建 IPsec VPN 中心网关**。

适合电竞赛事、多场馆转播（OB）、机房与分部组网：各个站点的硬件防火墙（山石网科、华为、飞塔、strongSwan 等）连到这台中心服务器，即可安全加密互通，同时自带四层链路监控、实时握手日志、主备切换和飞书卡片告警。

```text
  [赛场 / 机房 A 防火墙] ── IPsec (IKEv2) ──┐
                                             ├──► [ Ubuntu 24.04 中心网关 ] (自带网页控制台)
  [演播室 / 分部 B 防火墙] ── IPsec (IKEv2) ─┘       支持先连 1 个站点单独测试，随时扩展多站点
```

---

## 核心特点

- **单文件零依赖**：Go 后端 + Vue 3 网页控制台打包成一个独立 Linux 可执行文件，**不装 Docker、不装 Python**，下载即用。
- **开箱即用，像云厂商一样配 VPN**：
  - 自动检测服务器公网 IP 与默认网卡，支持 **先建 1 个站点单独联调**，打通后实时显示「已连通 / 未连接」，添加第 2 个站点自动配对互通。
  - 默认 **山石路由型（route_based）**，并自动为隧道口设置 **MTU 1400 + TCP MSS 1360**，避免 PPPoE / NAT 场景下大包卡顿。
  - 可选填 `/30` 隧道接口 IP 与内网探活目标，自动监测端到端真实通断与延迟。
- **一键导出对端参数**：自动生成 **山石 Hillstone 参数单 / CLI 草稿**、腾讯云风格 JSON 与 strongSwan 配置，发给现场网工照抄就能通。
- **实时排查与四层监控**：
  - 后台一键查看 strongSwan 实时 SA 状态与握手日志，快速定位 PSK、IKE ID 或算法不匹配问题。
  - 四层同步波形图（外层公网延迟/丢包 → IKE/IPsec 状态 → 隧道带宽/拦截 → 内网探活），自动区分运营商波动与隧道故障。
  - 内置 **飞书彩色交互卡片告警**，支持后台直接发测试消息。
- **极简明暗界面 & 默认安全**：默认浅色极简风（支持一键切深色）；Web 控制台（非 root）与网络代理（root）权限分离，强制 HTTPS、2FA 两步验证、来源 IP 白名单（带防自锁校验）和完整审计日志。

---

## 准备条件

- 一台 **Ubuntu 24.04** 服务器（`amd64` 或 `arm64`，建议纯净系统，具备 `root` 权限）。
- 云厂商安全组放行以下端口：
  - `UDP 500`、`UDP 4500`（IPsec 隧道协商与数据加密）
  - `TCP 18443`（网页控制台端口，建议仅对管理员 IP 放行）

---

## 3 步全新安装

在 Ubuntu 24.04 服务器上以 `root` 执行（ARM 服务器把 `amd64` 改为 `arm64`）：

### 第 1 步：下载程序并开启内核转发

```bash
# 下载最新单文件程序与安装脚本
curl -LO https://github.com/yikkrrtykj/event-ipsec-hub/releases/latest/download/ipsecvpn-linux-amd64
curl -LO https://github.com/yikkrrtykj/event-ipsec-hub/releases/latest/download/install-v4.sh
chmod +x ipsecvpn-linux-amd64 install-v4.sh

# 开启 Linux 路由转发与松散反向路径检查
cat <<'EOF' > /etc/sysctl.d/90-ipsecvpn.conf
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
EOF
sysctl -p /etc/sysctl.d/90-ipsecvpn.conf

# 创建本机授权标记（防止误在非目标机器上改动网络）
install -d -m 0700 /etc/ipsecvpn /etc/ipsecvpn/profiles /etc/ipsecvpn/secrets
printf 'ipsecvpn-prod-v1\n' > /etc/ipsecvpn/host-authorized
chmod 0600 /etc/ipsecvpn/host-authorized
```

### 第 2 步：安装 strongSwan 并启动控制台

```bash
install -m 0755 -o root -g root ./ipsecvpn-linux-amd64 /usr/local/sbin/ipsecvpn
/usr/local/sbin/ipsecvpn install --confirm
bash ./install-v4.sh /usr/local/sbin/ipsecvpn
```

> 若服务器绑定了云厂商弹性公网 IP（本机网卡上只有内网 IP），第 3 行改成：
> `IPSECVPN_PUBLIC_IP=<你的公网IP> bash ./install-v4.sh /usr/local/sbin/ipsecvpn`

### 第 3 步：查初始密码并登录

```bash
journalctl -u ipsecvpn-web.service -n 20 --no-pager | grep BOOTSTRAP_ADMIN
```

浏览器访问 **`https://<服务器公网IP>:18443`**（自签名证书点「继续访问」），用 `admin` 和上面打印的密码登录即可。

---

## 网页后台 4 步上手

1. **账号与白名单（系统设置）**：先改掉初始密码，扫码绑定两步验证（TOTP），点击 **+ 当前管理访问 IP** 把自己加入白名单。
2. **新建第 1 条通道（VPN 通道）**：点击 **+ 新建通道**，填对端公网 IP、对端内网网段，抽屉会自动生成高强度预共享密钥（PSK）；填完后点顶部 **保存并应用** 立即下发。
3. **导出参数并看连通状态（配置导出 → 概览）**：把生成的山石/通用参数单发给对端配置；回到 **概览** 看到状态变为绿点 **已连通** 即打通（没通可直接点 **诊断日志** 看实时报错）。
4. **扩展多站点与告警**：随时再加第 2、第 3 个站点（2 个站点会自动配对互通，3 个及以上按规则隔离）；在 **告警管理** 填入飞书机器人 Webhook 并点 **发送测试消息** 验证。

---

## 无损升级到最新版

已安装过的服务器，执行下面 3 行即可平滑升级（原有配置、密钥、TOTP 和飞书告警全部保留）：

```bash
curl -fsSL https://github.com/yikkrrtykj/event-ipsec-hub/releases/latest/download/ipsecvpn-linux-amd64 -o /tmp/ipsecvpn
install -m 0755 -o root -g root /tmp/ipsecvpn /usr/local/sbin/ipsecvpn && rm -f /tmp/ipsecvpn
systemctl restart ipsecvpn-agent ipsecvpn-web && ipsecvpn --version
```

升级后浏览器按 **`Ctrl + Shift + R`** 强制刷新页面即可。

---

## 常用运维命令

| 想做什么 | 执行命令 |
| :--- | :--- |
| 查看当前版本 | `ipsecvpn --version` |
| 查看隧道与内核状态 | `/usr/local/sbin/ipsecvpn status` |
| 查看服务日志 | `journalctl -u ipsecvpn-web -u ipsecvpn-agent -n 50 --no-pager` |
| 临时关掉网页后台（**不影响已通隧道**） | `systemctl disable --now ipsecvpn-web.service` |
| 彻底卸载并恢复宿主机网络 | `systemctl disable --now ipsecvpn-web ipsecvpn-agent && /usr/local/sbin/ipsecvpn uninstall --confirm --maintenance` |

---

## 本地自行编译

需要 Go 1.24+ 和 Node.js 22+：

```bash
(cd web && npm ci && npm run build)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/ipsecvpn-linux-amd64 ./cmd/ipsecvpn
```

## 进阶文档

- [山石网科防火墙对接实操指南](docs/PRODUCTION_VPS_HILLSTONE_RUNBOOK.md)
- [生产部署、安全加固与排障手册](docs/V4_OPERATIONS.md)
- [系统架构设计说明](docs/V4_ARCHITECTURE.md)
