# ipsecVPN — 通用电竞赛事 Site-to-Site IPsec 中转工具开发规格

- 规格版本：V2.0（2026-11-06）
- 目标仓库：https://github.com/yikkrrtykj/ipsecVPN
- 语言：中文文档，英文代码/指标名
- 开发流程：分支开发、Draft PR、审核后再合并；未经授权不运行生产部署
- **产品定位**：可复用的赛事网络交付工具，而非某一场 PUBG、某一国家、某台 VPS 的一次性部署脚本。

## 0. 需求澄清与最高优先级原则

每场比赛，OB/制作/场馆/游戏服务器的位置都可能改变；实际公网 IP、私网 CIDR、ISP、VPS 地域/供应商、站点数量、防火墙品牌、网关及主备架构均可能不同。**以上都属于项目配置，不允许写死在程序逻辑、目录名、模板字段或测试结论中。**

仓库提供：自建 Linux IPsec Hub 的安全部署与回滚、站点参数生成和对接、状态诊断、可选监控告警、主备方案的交付与验收。支持三层私网互通，不做二层桥接或远程客户端代理。

**当前可验证的示例部署，仅用来指导第一场上线，不能充当全局默认值：**
- 业务可为 PUBG 远程 OB，或未来其他赛事的有线/UDP/TCP 专用网络；不假定游戏/客户端协议与端口。
- 某次赛事可能使用上海 OB 与伊斯坦布尔游戏服务器，示例网段 `192.168.50.0/24` 与 `192.168.141.0/24`；**这两个值不进入代码默认、CI fixtures 或配置模板**。
- 某次可能以 V.PS 法兰克福作为自建主 Hub、腾讯云 VPN 网关作为可选备 Hub；未来可变更地点、商家、主备角色，或完全不启用备 Hub。
- 当前两端可能均为 Hillstone StoneOS 5.5 系列；具体设备版本待现场核验。未来对端设备不必为山石。
- 当前项目分工：Hub 和一端场馆设备由维护者操作，另一端网络团队收到参数单后自行配置；将来交付人/对象可变。
- 现有跨洲测试 RTT 仅属于该场赛事的测量资料，**不能形成软件功能默认阈值或 SLA**。

## 1. 版本范围与能力边界

### P0：第一版真正支持的范围（必须通用、不得冒充无限多站点）
1. **一个活动部署 profile、一个自建 Linux IPsec Hub、恰好两个外部站点**。站点 ID、名称、位置、角色、网段、Peer IP、设备类型、ISP 均任意且可配置；可保存多个赛事 profile，但生产部署时要明确选择一个。禁止静默切换活动 profile。
2. 每站可配置一个或多个 IPv4 LAN CIDR，显式声明允许互通的网段对；重叠、默认路由泄漏、错误路由或无明确授权的网段必须拒绝。大规模多站点 Hub-and-spoke、并行多赛事、网段重叠 NAT 留到后续扩展，首版显式 `UNSUPPORTED` 而非假成功。
3. 一台 Ubuntu 24.04 LTS Linux Hub，`charon-systemd` + `strongswan-swanctl` + VICI、两个独立 IKE/CHILD SA 与独立 XFRM 接口；验证双向跨隧道 ESP 解密—路由—再加密，且源 IP 不变。
4. `ipsecvpn validate/check/plan/render/install/apply/status/doctor/export-peer/backup/rollback/uninstall`；所有写入操作要有 dry-run、确认、变更审计及本项目范围内回滚。
5. **可按任意站点导出** Markdown 和机器可读 JSON 的 IPsec 对接参数。优先制作 Hillstone 模板，另提供厂商中立模板；不可宣称 JSON 能被山石或腾讯云直接导入。
6. 主备不是必需。支持配置 `backup.enabled: false`，或仅将外部备 VPN 记作 `external_managed` 并生成两端路由/Track 交接说明；不在 Linux Hub 上自动控制其它服务商/防火墙的实际路由。
7. Ubuntu 网络安全、密钥脱敏、故障诊断、可回滚、测试和 CI 为 P0 必选；不能只验证 IKE SA UP。

### P1：监控与运行保障
- VICI/内核 XFRM 指标、Prometheus exporter（默认仅 localhost）、Grafana 模板、飞书 Webhook 去重告警（可全关）。
- 分清：Linux 主机在线 / IKE SA 在线 / CHILD SA 在线 / XFRM 计数增长 / 跨站点业务探测成功。
- 可配置 ICMP/UDP echo 探针和分路径测试（需独立测试目标与固定路径）；告警只提示，不直接操作生产防火墙路由。
- 可选外部备 Hub 的状态可通过**独立探针**表示其可达性，但不能假装从主 Hub 直接查询出腾讯云健康状态。

### P2：后续扩展（不阻塞首版）
- N 个外部站点、站点与站点之间的授权路由矩阵、并行多赛事运行及网络命名隔离、多个自建 Hub。
- 更多防火墙品牌专用交接模板、供应商 API（由用户单独授权）、网页管理界面。
- 经过实验验证的高级自动故障协调；当前只做文档/对接建议。

### 非目标
- 不实现 SSL/AnyConnect/WireGuard/Clash/SRT Relay、EVPN/VXLAN、二层桥接；不提供客户端翻墙服务。
- 不默认购买云实例、不自动修改山石或腾讯云设备、不承诺 PUBG 业务会话无缝切换。
- 不将任意公网/私网/密钥/告警阈值写成赛事永久默认。

## 2. 配置模型：赛事与网络完全分离

一个可读配置文件对应一个**赛事部署 profile**。结构至少包含：

| 对象 | 必需字段 | 说明 |
|---|---|---|
| `event` | `id`, `name` | 比赛/项目的可读标识，不参与网络选路 |
| `hub` | `id`, `public_endpoint`, `platform`, `provider_label`, `location_label` | provider/location 只是显示信息，不应触发专有逻辑 |
| `sites[]` | `id`, `display_name`, `public_endpoint`, `lan_cidrs[]`, `ike_identity`, `firewall.vendor` | 两个站点 ID 任意，角色如 `ob`、`venue`、`production` 仅为元数据 |
| `site_links[]` | `site_id`, `secret_ref`, `ike_proposal`, `esp_proposal`, `if_id`, `outer_path` | 每个站点一条独立 IPsec，if_id 唯一 |
| `traffic_policy` | `allowed_site_pairs` | 显式控制跨站点路由和安全策略，P0 两站点可多 CIDR |
| `backup` | `enabled`, `type`, `peer_profile_ref`（可选） | `type: external_managed` 只输出对接及验收说明 |
| `monitoring` | enabled/探针/阈值/渠道（可选） | 完全配置化，告警不影响数据平面 |

请使用稳定 schema 版本、明确属性校验、清晰 migration 机制。动态变量在每次部署写入用户本地文件，示例只用文档保留公网地址。

### 可交给 Codex 的 V2 YAML 示例（示意，不可直接部署）

```yaml
schema_version: "2.0"
event:
  id: demo-match
  name: Example Tournament
hub:
  id: hub-a
  platform: ubuntu-24.04
  public_endpoint: 203.0.113.10
  provider_label: Example Provider
  location_label: Region A
sites:
  - id: observer-a
    display_name: Observer Site
    role: observer
    public_endpoint: 192.0.2.10
    ike_identity: 192.0.2.10
    firewall: {vendor: hillstone, os_version: unknown}
    lan_cidrs: [10.10.50.0/24]
  - id: venue-b
    display_name: Venue Site
    role: venue
    public_endpoint: 198.51.100.10
    ike_identity: 198.51.100.10
    firewall: {vendor: hillstone, os_version: unknown}
    lan_cidrs: [10.20.141.0/24]
site_links:
  - site_id: observer-a
    if_id: 101
    outer_path: {interface: auto, isp_label: Provider-1}
    secret_ref: file:/etc/ipsecvpn/secrets/observer-a.psk
  - site_id: venue-b
    if_id: 102
    outer_path: {interface: auto, isp_label: Provider-2}
    secret_ref: file:/etc/ipsecvpn/secrets/venue-b.psk
traffic_policy:
  allowed_site_pairs:
    - {a: observer-a, b: venue-b}
backup:
  enabled: false
monitoring:
  enabled: false
```

**实现说明：** proposals 可在 profile 的共享安全策略下配置并允许 per-link override；字段解析器须区分 `file:` secret ref 是本机 root-owned 路径，不尝试读取 Git 工作树内密钥。示例中的接口 `auto` 只代表非生产模板占位；安装前必须发现并明确选择实际出口，不可直接静默 apply。

### Traffic Selector 推导（P0）
- Hub 面向站点 A 的 CHILD：Hub 端 `local_ts = B 的授权 LAN CIDRs`，`remote_ts = A 的授权 LAN CIDRs`；站点 A 则本端 A、远端 B。
- Hub 面向站点 B 的 CHILD：Hub 端 `local_ts = A 的授权 LAN CIDRs`，`remote_ts = B 的授权 LAN CIDRs`；站点 B 则本端 B、远端 A。
- 若 StoneOS route-based 模式必须使用通配 Traffic Selectors，则提供**显式高级兼容模式**和单独验收；不能默默降为 `0.0.0.0/0`。
- 多 LAN 或多 selector 的具体 CHILD_SA 行为必须通过隔离实验确认；无法兼容时拒绝启用并给出可执行修正办法，不能只显示配置成功。
- XFRM if_id、内外层路由、防火墙策略、源地址保持、反向路由必须由工具生成并可诊断；不允许默认路由泄漏或误把 VPN Peer 公网 IP 送进 XFRM。

## 3. Linux Hub 强制技术要求

- Ubuntu 24.04 LTS，strongSwan 官方发行版包：`charon-systemd`、`strongswan-swanctl`、VICI。预检实际版本/服务名；不能并行启动 legacy starter。
- 独立 CHILD SA、XFRM interface、唯一 if_id；明确内核 XFRM policy/SA 和接口映射。系统允许 `net.ipv4.ip_forward=1` 但需检查已有 sysctl 与 `rp_filter`；不得无范围禁用其他安全保护。
- 使用本项目独立 nftables chain/table 和精确 FORWARD ACL；禁止 `nft flush ruleset`、禁止覆盖用户现有 netplan/ufw/默认路由/SSH。若冲突，FAIL 并停止，不能冒险覆盖。
- 仅授权 Peer 的 UDP 500/4500、必要时 ESP proto 50，仍需验证云平台安全组/机房封锁情况。默认无不必要的管理公网入口。
- `swanctl` 配置生成支持 IKEv2、明确 IKE encryption/PRF/integrity/DH 与 CHILD ESP encryption/integrity/PFS、lifetime、DPD、IKE ID、PSK per-link；初始兼容性建议 AES-256-CBC/SHA256/DH14，但必须双方确认；不复用 IKEv1/DH1/SHA1/弱 PSK。
- 对外层 Peer 设明确源接口/路由，防止配置两个 ISP 后错误走默认出口；不修改设备默认公网网关。
- 保证 Linux 对两个站点的 `lan_cidrs` 有精确、无循环路由；禁止意外向公网泄漏内网业务；不做 SNAT（除非未来显式 NAT feature 并有测试）。
- 强制探测真正的双向 UDP/TCP 跨站点转发，不以 Ping/SA UP 代替业务证明。检查重协商、路由回程、分片/MTU、UDP 和多 CIDR。
- `install/apply` 原子更新、真实校验、失败自动恢复；变更前快照系统与受控文件，回滚只处理项目拥有对象。
- 一台 Linux 同时运行多个 profile 在 P0 中禁止；列出已保存 profile 与活动 profile，切换需要明确审批、停机窗口和回滚。
- 不要使用 `set -e` 配裸 `test` 伪造判定；诊断输出 PASS/FAIL/SKIP，标注依据，未实际测量的项目不能 PASS。

## 4. 安全与密钥

- 模板不含真实 IP、真实域名/密钥；仓库若公开，所有站点地址、接口、PSK、飞书 Webhook、SSH 私钥均不得被提交。
- `/etc/ipsecvpn/profiles/` root-only，配置文件 0600；`/etc/ipsecvpn/secrets/` 0700；每个 site link 用独立强随机 PSK，提供 root 权限下的安全交付流程，默认导出报告只写 `<SEND_SEPARATELY>`。
- `.gitignore` 包括用户 profiles、secrets、exports、backups、diagnostics、环境文件、自动生成的真实参数。
- `plan/check` 必须只读；`install/apply/uninstall/rollback` 必须明确授权（dry-run + confirm）；运行期间保持 SSH/带外访问，必要时输出 STOP。
- 不自动接入任何云厂商 API、不远程登录防火墙、不替用户推送参数或重启设备。
- 只支持用户已获授权的企业/赛事网络环境，交付文档提示跨境网络服务合规与服务商条款检查。

## 5. CLI 设计（命令保持短）

```
ipsecvpn profiles list
ipsecvpn validate -c profiles/demo-match.yaml
ipsecvpn check
ipsecvpn plan -c profiles/demo-match.yaml
ipsecvpn render -c profiles/demo-match.yaml
ipsecvpn install --dry-run
ipsecvpn install --confirm
ipsecvpn apply -c /etc/ipsecvpn/profiles/<event-id>.yaml --dry-run
ipsecvpn apply -c /etc/ipsecvpn/profiles/<event-id>.yaml --confirm
ipsecvpn status
ipsecvpn status --json
ipsecvpn doctor
ipsecvpn export-peer --site observer-a --format md
ipsecvpn export-peer --site venue-b --format json
ipsecvpn backup
ipsecvpn rollback --to <backup-id> --confirm
ipsecvpn uninstall --dry-run
```

- `export-peer` 以 **目标 site 自身视角**生成，输出文件由 site ID 派生，例如 `exports/observer-a-hillstone.md`，不得出现硬编码 `shanghai`/`istanbul`。
- JSON 是通用参数交换 Schema，非腾讯云或山石原生导入 API。必须附带 IKE ID、公网端点、加密算法、完整本/远端网段数组、各条站点互通授权、路由/NAT/策略、监控及测试说明。
- 每条 CLI 都要有明确 exit code、可选 JSON、脱敏日志和 PASS/FAIL/SKIP；未部署场景显示 SKIP 而不是成功。

## 6. 主备与外部网关（完全可选）

- `backup.enabled=false` 为合法、必须通过的完整 P0 配置。不可因无腾讯云而报错。
- 若 `backup.type=external_managed`，可填写 provider_label（如腾讯云 VPN 网关）、每站外层 Peer 和 Tunnel 名、业务网段、优先级及 Track 目标，**只产出山石/通用交接说明**。是否为腾讯云、是否采用 CCN、地域均不进入核心代码判断。
- 两站主备业务路由由站点防火墙执行：主 Hub 与备 Hub 各有独立外层路由/隧道，保持原始源 IP，禁止逐包 ECMP。自动 Track、单侧故障、回程不对称、恢复回切需人工验收；无法可靠同步时采用受控人工切换。
- 独立监控 A/B 路径时，每一路探测要固定到该路，避免备路径成功让主路径误判恢复；日志区分 SA / Track / End-to-End UDP 三层健康。
- 一次切换可中断现有游戏会话，不能宣称无感；切换秒数不是系统常量，由项目验收得到。

## 7. 监控与告警

- P1 exporter 使用 VICI 与 Linux XFRM 计数：IKE、CHILD、rekey、字节包数、报错、接口、业务探针状态；metrics 默认 localhost，不公开无鉴权端口。
- 配置化 Prometheus/Grafana 资源，按事件 ID/site ID/Hub ID 作为有限维度标签；避免每包/每秒唯一 label。
- 业务质量探针支持 ICMP 和 UDP echo、明确样本窗口、包数与路径绑定；PUBG/其他游戏体验仍需人工验收；ICMP 丢包不能替代 UDP。
- 飞书 webhook 可选，DOWN/RECOVERED/DEGRADED 去重与降噪、时间、事件、客户端/站点、原因，密钥不入日志。监控故障不应影响 VPN 转发。

## 8. 文件与目录建议

```
ipsecVPN/
├── README.md
├── .gitignore
├── install.sh
├── config/
│   ├── schema.json
│   ├── event.example.yaml         # 文档用 IP、虚构事件，公开安全
│   └── security-defaults.yaml
├── ipsecvpn/                    # CLI、数据模型、渲染、状态、快照、诊断
├── templates/
│   ├── strongswan/
│   ├── linux-network/
│   ├── handoff-generic/
│   └── handoff-hillstone/
├── monitoring/
│   ├── exporter/
│   ├── grafana/
│   ├── prometheus/
│   └── feishu/
├── docs/
│   ├── SPEC.md
│   ├── architecture.md
│   ├── event-lifecycle.md
│   ├── install.md
│   ├── handoff.md
│   ├── monitoring.md
│   ├── failover.md
│   ├── rollback.md
│   └── acceptance.md
├── tests/{unit,integration,fixtures}/
└── .github/workflows/ci.yml
```

项目 profile 建议只存在本机 `/etc/ipsecvpn/profiles/<event-id>.yaml`；仓库 `config/event.example.yaml` 用虚构数据。是否添加 LICENSE 由仓库所有人决定。

## 9. 测试与验收门槛

### P0 自动化 CI（不能接触真实赛事设备）
- 修改 `event.name`、`site.id`、站点角色、国家/区域/厂商标签、全部公网 IP/私网 CIDR 后，配置、渲染、导出、检测依然正确；源代码/自动输出无 `shanghai`、`istanbul`、`pubg`、`v.ps`、`tencent` 的**必选固定依赖**。
- 两个站点 ID 使用任意值，`export-peer` 使用动态 ID 与正确的本/远端视角，生成 Markdown/JSON 一致；密钥永不出现在 stdout、CI artifact 和导出文件。
- 多 CIDR 校验、重复/重叠、非法 IP、if_id 重复、无 Peer、错误路由、未批准全流量 selector、非法配置 schema 应 FAIL；备份关闭为合法 PASS。
- 三套虚构赛事 fixture：① 亚洲场馆 + 欧洲 OB；② 欧洲场馆 + 美洲 OB；③ 两站有多 VLAN。不能因地点和赛制不同失败。
- `check/plan` 真正只读；apply 失败后恢复所有本项目管理文件/规则，保持 SSH、默认路由、既有 nftables 安全规则。
- Mock VICI/down 不会使 `business=UP`；无运行环境的真实公网 IPsec / Hillstone 对接必须 `SKIP`。
- Python `pytest`、`ruff`、ShellCheck、YAML/JSON Schema、秘密扫描，所有评估 PASS/FAIL/SKIP。

### 隔离实验环境
- Linux namespaces/隔离 VM 做双 peer 强加密 ESP 转发，UDP/TCP 双向、多 CIDR、保留原始 IP；SA rekey、重启、路由泄漏、拒绝未经授权站点和回滚。
- 无法在 CI 权限中完成的测试明确 SKIP，不能输出恒真 verdict。

### 每场赛事的真实上线流程（由负责人执行）
1. 收集活动 profile：地点、业务网段、ISP/固定公网、实际防火墙版本、VPS 地域与供应商、对端负责人、维护窗口、带外管理方案。
2. `validate` → `plan` → 备份 → `render` → 通过只读检测；在测试主机/精确 `/32` 路由先验证，不抢占生产 `/24`。
3. 通过 `export-peer --site <id>` 把参数发给对端（PSK 单独安全交付），对端完成防火墙配置并回传 SA/路由/计数。
4. 验证 SA + 真正 UDP/TCP 双向转发 + MTU + 全路径 RTT/p95/p99/丢包/抖动；游戏/制作业务做完整流程演练。
5. 如有备 Hub，独立验证备路径和两端切换；不能可靠双端收敛时禁止自动切换。
6. 记录最终 PASS/FAIL/SKIP、现场的基线性能、路由与回滚快照；比赛结束后清理该赛事配置但不误删其他资源。

## 10. Codex 分 PR 开发顺序

- **PR #1（当前任务，仅设计与只读工具）**：README、通用 schema、虚构 fixtures、CLI `profiles list`/`validate`/`check`/`plan`/`export-peer`、对应单元测试与 CI；全程 Draft，不在生产部署。
- **PR #2**：Ubuntu/strongSwan 安装、模板渲染、XFRM、事务 apply/rollback/backup；隔离验证且不修改默认路由。
- **PR #3**：真实双端 IPsec 转发、diagnostics、UDP、MTU、重协商与异常处理。
- **PR #4**：可选监控、告警、导出 Dashboard。
- **PR #5**：山石与通用对接运行手册、外部备 Hub 对接、赛事生命周期和真实验收模板。

每个 PR 必须保留 Draft 等待审查，不自动 merge；本轮 PR #1 完成后停止，不自行推进后续 PR。遇到协议、StoneOS 或内核限制，记录真实问题并 STOP，不以替代的未经授权网络操作绕过验收。
