# event-ipsec-hub

把一台普通的 **Ubuntu 24.04 云服务器**，一键变成带网页管理后台的 **IPsec VPN 中心网关**。

适合电竞赛事、多场馆转播（OB）、多机房或分部互联：各站点防火墙（山石网科、华为、飞塔、strongSwan 等）统一连到这台中心服务器，由中心网关负责加密转发、站点隔离、主备容灾和飞书告警。

---

## 主要功能

- **单文件极简部署**：后端（Go）与网页控制台（Vue 3）打包成一个独立的 Linux 可执行文件，**不依赖 Python、不依赖 Docker**，传到服务器直接跑。
- **网页化配置隧道**：不用手写复杂的配置文件，在网页里填对端公网 IP、内网网段、协商模式（路由型 / 策略型 / 多子网拆分）和互通规则，支持预检（Dry-Run）确认后再下发。
- **一键导出对端参数**：自动生成标准 JSON（IKEv2）、山石网科命令行草稿、strongSwan 配置草稿和通用对接参数单，直接发给现场网络工程师照着配。
- **四层链路监控与事件日志**：实时查看公网通断与延迟、IPsec 隧道状态、加解密流量速率、防火墙拦截和内网连通性，自动判断是运营商抖动还是隧道异常；支持按时间和关键字检索历史事件并跳转对应时刻波形。
- **主备切换与飞书告警**：内置主备网关切换控制（切备后锁定门禁防抖动抢占，回切需人工确认）和飞书机器人告警，支持直接在后台配置 Webhook 和签名密钥。
- **默认安全加固**：管理网页（非 root）与网络执行代理（root）权限彻底分离；强制 HTTPS（TLS 1.3）、初始随机密码、登录防爆破、两步验证（2FA）、来源 IP 白名单，以及所有高危操作审计日志。

---

## 环境要求

- 一台 **Ubuntu 24.04** 服务器（`amd64` 或 `arm64`，建议全新纯净系统，拥有 `root` 权限）。
- 云服务器安全组放行：
  - `UDP 500`、`UDP 4500`（IPsec 协商与封装流量）
  - `TCP 18443`（Web 控制台管理端口，建议仅对管理员公网 IP 放行）

---

## 快速上手（3 步上线）

### 第 1 步：下载程序并做主机初始化

在 Ubuntu 24.04 服务器上以 `root` 执行（ARM 服务器请把 `amd64` 换成 `arm64`）：

```bash
# 1. 从 GitHub Release 下载最新程序和安装脚本
curl -LO https://github.com/yikkrrtykj/event-ipsec-hub/releases/latest/download/ipsecvpn-linux-amd64
curl -LO https://github.com/yikkrrtykj/event-ipsec-hub/releases/latest/download/install-v4.sh
chmod +x ipsecvpn-linux-amd64 install-v4.sh

# 2. 开启 Linux 内核转发与松散反向路径过滤
cat <<'EOF' > /etc/sysctl.d/90-ipsecvpn.conf
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
EOF
sysctl -p /etc/sysctl.d/90-ipsecvpn.conf

# 3. 创建主机授权标记（防止误在非目标机器上修改网络）
install -d -m 0700 /etc/ipsecvpn /etc/ipsecvpn/profiles /etc/ipsecvpn/secrets
printf 'ipsecvpn-prod-v1\n' > /etc/ipsecvpn/host-authorized
chmod 0600 /etc/ipsecvpn/host-authorized
```

### 第 2 步：安装 strongSwan 并启动网关控制台

```bash
# 1. 安装并托管 Ubuntu 官方 strongSwan (charon-systemd) 及开机防泄漏守护
./ipsecvpn-linux-amd64 install --confirm

# 2. 注册并启动后台 Agent 与 HTTPS Web 控制台（将 <服务器公网IP> 替换为实际 IP）
IPSECVPN_PUBLIC_IP=<服务器公网IP> bash ./install-v4.sh ./ipsecvpn-linux-amd64
```

### 第 3 步：获取初始密码并登录网页后台

```bash
journalctl -u ipsecvpn-web.service -n 20 --no-pager | grep BOOTSTRAP_ADMIN
```

浏览器打开 **`https://<服务器公网IP>:18443`**（首次打开自签名证书点“继续访问”即可），使用账号 `admin` 和上面查到的初始密码登录：

1. 进入 **安全与审计**：修改管理员密码、配置你的办公网 IP 白名单（可选开启两步验证）。
2. 进入 **VPN 通道**：填写各站点公网 IP、内网网段、生成预共享密钥（PSK），点击 **预检** → **确认下发**。
3. 进入 **对端导出**：给每个场馆/机房导出一份对接参数单发给对端管理员配置，隧道即可自动建立。
4. 进入 **告警配置**：填入飞书自定义机器人 Webhook 并点 **发送测试告警** 验证通知。

> 赛后或平时不需要网页管理时，可以随时关停 Web 服务，**不会影响已经建立的 VPN 隧道**：
> `systemctl disable --now ipsecvpn-web.service`

---

## 常用运维命令

| 用途 | 命令 |
| :--- | :--- |
| 查看全部隧道与内核状态 | `/usr/local/sbin/ipsecvpn status` |
| 查看 Web / Agent 运行日志 | `journalctl -u ipsecvpn-web.service -u ipsecvpn-agent.service -n 50` |
| 命令行测试飞书通知 | `/usr/local/sbin/ipsecvpn alert test-feishu --webhook <你的飞书Hook>` |
| 手动重连某个站点 | `/usr/local/sbin/ipsecvpn reconnect --site <站点ID> --confirm` |
| 停用 Web 控制台（保持隧道运行） | `systemctl disable --now ipsecvpn-web.service` |
| 彻底干净卸载（恢复宿主机网络） | `systemctl disable --now ipsecvpn-web.service ipsecvpn-agent.service && /usr/local/sbin/ipsecvpn uninstall --confirm --maintenance` |

---

## 从源码自行编译

需要 Go 1.24+ 和 Node.js 22+：

```bash
# 1. 编译前端页面（会自动打包进 Go 程序）
(cd web && npm ci && npm run build)

# 2. 编译 Linux 静态单文件
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/ipsecvpn-linux-amd64 ./cmd/ipsecvpn
```

---

## 详细文档

- [生产部署、安全加固与故障排查手册](docs/V4_OPERATIONS.md)
- [山石网科防火墙对接实操指南](docs/PRODUCTION_VPS_HILLSTONE_RUNBOOK.md)
- [系统架构设计说明](docs/V4_ARCHITECTURE.md)
