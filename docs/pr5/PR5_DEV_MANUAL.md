# PR #5 — 设备对接、外部备路径及赛事验收开发手册

> 基线：`6aacc03514ee98bea91e26bbba46a72451211715`（event-ipsec-hub 的 main，PR #4 Merge commit）。本手册是**开发合同**而不是已验收报告。仓库包名/CLI 仍是 `ipsecvpn`。

## 0. 本期结论与边界

- 本期交付：Hillstone/StoneOS 与厂商中立的**人工对接运行手册**、可由既有 V2 Profile 派生的离线 handoff、外部备用 VPN **可行性检查及交接流程**、主备切换/回切的标准实验和人工验收模板、脱敏的 CI/模拟测试。
- 强制保留 P0：一个活动赛事 profile、一个 Ubuntu Hub、**恰好两个**任意 ID 外部站点、多 IPv4 CIDR 与显式授权站点对；不擅自改成 N 站点；**三层私网路由**，不是同 VLAN 的二层打通。
- `backup.enabled: false` 完全合法。`backup.type: external_managed` 是**由外部管理员负责的备路径**，不能由 Linux Hub 自行接管对端防火墙、云路由或供应商 API。
- `export-peer` 的 `PASS` 仅代表**离线参数单生成成功**；`backup.readiness=COMPLETE` 仅代表字段齐全；**真实 IKE/CHILD、双端数据、Track、自动/人工切换及现场适配一律 SKIP，直到证据覆盖**。
- 不自动执行任何生产变更，不登陆防火墙、不连实际腾讯云 API、不购买资源、不分发 PSK、不连接真实飞书。不得为了文档要求放开 PR #2–#4 的 root-only QEMU lab marker。
- **强制安全原则**：任何预检发现路由不对称、ECMP、未验证云端中转、未知 SA/所有权、未确认的 Proxy ID / TS 行为、缺带外访问或回滚条件 => `STOP`，而非“默认尝试自动切换”。

## 1. 直接复用的仓库实现（必须读代码）

- `config/schema.json` V2.0：`sites[]`/`site_links[]`/`traffic_policy.allowed_site_pairs[]`/`backup`/`monitoring`。
- `ipsecvpn/profile.py`：`authorized_lans` 是授权 CIDR 的单一事实来源；`backup_readiness` 两站字段及路由优先级必须齐全才能 COMPLETE；`_validate_optional_paths` 已检查备地址、备路由 CIDR 子集、uplink 引用及路由优先级方向。
- `ipsecvpn/handoff.py`：`_connections`/`build_plan`/`peer_parameters`/`render_peer_markdown` 是输出事实来源；site 视角 `local_ts=本站授权 LAN`、`remote_ts=对站授权 LAN`；PSK 只输出 `<SEND_SEPARATELY>`；已有 Hillstone/Generic Markdown/JSON 支持，不应重写并产生分叉。
- `ipsecvpn/renderer.py`：`external_backup` 仅输出外部交接状态，不触发网络写入。
- `ipsecvpn/monitoring`：仅本地监控自己拥有的 IKE/CHILD/XFRM 和有独立回执的主路径 UDP；**不可**把主路径探针直接复用为备路径健康结果。
- `docs/pr3/LIVE_OPERATIONS.md`：DPD S05 的恢复靠显式 `initiate`，无人值守自动重连未证实；业务恢复不能仅凭 SA 配置恢复声明 PASS。

### 兼容状态与可接受变更

A. 保留 `schema_version: 2.0`、旧 Profile 的解析与输出兼容性。优先新增文档模板与独立报告校验器；若必须加字段：全部可选、无旧值默认为不确定、schema/fixture/JSON/Markdown 同步更新并说明 migration；禁止将外部备 Hub 变必需。

B. 提供 machine-readable 交接数据与人类 Markdown、现场验收模板的可追溯映射。可新增 `ipsecvpn handoff` / `ipsecvpn acceptance` 子命令，若增加需只读、受控路径、`--format md|json`、明确 exit code、输出脱敏和稳定 schema。不得引入与 `export-peer` 冲突的第二套 selector 计算；不需要为了满足本手册必须增加命令。

C. 当前不输出未经设备型号/版本验证的、可直接粘贴生产的 StoneOS CLI。对型号、StoneOS 精确 build、HA/虚拟路由、IPsec route-based/policy-based 的差异列出“确认步骤—配置项目—现场证据—STOP 条件”，**不凭网上其他版本的截图宣称兼容**。

## 2. 设备对接参数与签收合同

应为每站独立生成一份参数单，并包含清晰的 `site_id`、远端业务 `site_id`、profile 摘要、修订时间、交付责任人/签收时间（不泄露真实身份时可保留占位）。每份至少包含：

1. 公网 Outer：本地固定公网、站点 ISP/uplink、出接口及回程；Hub 公网、UDP/500、4500、NAT-T 与是否需 ESP50；说明云防火墙/ACL 限制；Peer IP 的 /32 外层路由不应进入 XFRM。
2. IKE：严格 IKEv2，双方各自的身份类型/值、PSK **单独渠道**、proposal/PRF/DH/lifetime/DPD、重协商策略、谁主动建立连接，禁用弱兼容降级。
3. CHILD：ESP proposal/PFS/lifetime、Hub 与 site 的真实 local/remote TS **互为镜像**，多 CIDR 的协商能力和 Phase 2 ID 数量；只允许授权的 CIDR，通配 `0.0.0.0/0` 必须另开风险评审和独立测试，默认 STOP。
4. 路由/策略：相同的远端授权 CIDR 在两端的路由条目、优先级/VR/策略路由、独立 tunnel interface、LAN→IPsec 与 IPsec→LAN 安全策略；明确 **NAT 豁免在互联网 SNAT 之前生效**，双向保持原始源 IP；避免逐包 ECMP 和跨站点回程非对称。
5. 精确验收：本站发起与对站发起的各 CIDR 组合 UDP/TCP、源地址、SA SPI/计数、DF/MTU、rekey 和 ACL 非授权阻断；记录测试来源和真实包回执/抓包证据。
6. 交付分工：Hub owner、Site A admin、Site B admin、Backup provider owner；跨团队双向签收，不以“对方确认配置完成”代替实测。

### Hillstone 专用核验（以真实设备为准）

- 必须提供 `device model / serial masked / StoneOS full version / HA role / virtual-router or vsys / tunnel mode`。特别检查 5.5 系列不同补丁版本的具体 UI/CLI 和多 Traffic Selector/Proxy ID 行为。
- 先核验 route-based（tunnel interface）与 policy-based 的部署模式；两者不可套用相同的静态路由、策略和 NAT 步骤。明确 IKEv2 的 P1/P2 协商，Proxy ID 方向、数量和是否拆分 CHILD。
- 如采用多 VLAN/CIDR，必须**逐项证明** TS 配对且隔离不同网段，没有把全量互联网默认路由或非授权网段送入隧道。若设备只能通过通配 TS 与 Hub 互通，**不可静默改写** Hub `local_ts/remote_ts`，需 STOP 并另立兼容设计。
- 区分“静态路由优先级配置好”和“Track/NQA 能正确识别业务故障”。Tunnel interface UP、IKE UP、DPD 正常都**不保证**端到端双向业务畅通。
- 源码中的 `if_id` 属于 Linux XFRM 标识，不是 StoneOS tunnel interface 编号；交接文档应明确此区别。
- 正式防火墙操作由授权管理员依据**真实版本的官方资料**完成，生成文件必须标明 `NOT_APPLYABLE_CONFIG`（仅手工参数核验），不得声称自动推送或一键导入。

## 3. 外部备 Hub / 云 VPN 的拓扑可行性门槛

- 外部备路径不是“两个站点分别建立到云 VPN 的隧道”这么简单：必须证明实际产品和网络架构**允许 Site A LAN ↔ Backup Hub ↔ Site B LAN 的跨隧道转发**，含云侧路由/网络 ACL/安全组/站点到站点 transit、反向路径、路径优先级、费用及承载容量。某些云 VPN 网关主要用于 IDC↔云 VPC，**不能推定**其可作为两个外部 LAN 的任意 transit Hub。
- 若该云 VPN 产品或当前租户/VPC 路由约束不支持这种中转：明确 `STOP/UNSUPPORTED_BACKUP_TRANSIT`，保留独立的第二个自建 Hub 或经过批准的其他拓扑作为备选；不自动引入 CCN/BGP/API 或购买云带宽。
- Tencent Cloud 仅作为**可选供应商示例**：其 VPN 网关模式、NQA/Health Check、静态/SPD 路由、BGP 支持与限制依产品/地域/版本变化，必须在实际开通前核验官方文档与供应商支持意见；不能生成虚假的参数、速率或停机时间承诺。
- 一旦备路径可行，分别准备 Site A→Backup、Site B→Backup 的 Outer endpoint、独立 PSK、IKE/CHILD proposal、完整 TS、各云网络安全策略、接口/路由、精确 Track 目标及双端返回流量证明；不能复用生产主 Hub 的 PSK。
- 各端配置明确“主路由 preference 更高 / 备用更低”，**实际路由优先级大小方向以厂商设备为准**，本仓库整数仅表达排序契约，不证明实际设备配置。确保新路由本身不会覆盖管理流量或 peer 公网可达路由。

## 4. 主备切换设计：保守、可证据化

### 4.1 初始状态

- 主、备 SA 均可能已建立（热备），但只有明确选中的业务路由转发；不允许逐包 ECMP 和无签收的双活。
- Track 必须从**本端**出发，绑定**唯一** WAN/tunnel/VR 与明确测试源，依次验证主 Hub 是否能收到/返回真实业务探针；两站各自状态必须可独立审计。
- 主与备探针有独立身份、目标、时间窗、TTL 与回执；未能证明绑定到指定路径 => `UNKNOWN`，不可把另一条可达性当作本路径可达性。

### 4.2 切换/回切的最小实验顺序

1. **仅备链路 UP，不让业务切换**：先验证两端备 SA+云中转+UDP/TCP 双向及原始源 IP。否则不得启用自动 Track。
2. **受控主断链**：Site A 先失主路由但 Site B 未更新，观测临时黑洞/不对称并记录。必须具备协调双端切换顺序；如果无法防止长期非对称，采用受控人工切换。
3. **两端同向收敛**：两端都走备通道后，按各 CIDR 测量双向 UDP/TCP、有效源 IP、业务中断与丢包、证据时间戳。
4. **单侧复通**：验证不会因一端恢复造成一端主、一端备长期不对称；设置回切延迟、抖动抑制与人工审批（具体计时必须由现场测得，不能在软件写死）。
5. **双端回切**：有一致、受控的恢复条件；失败时回滚到明确的已验证安全状态。
6. **双故障与监控故障**：主/备都不可信、丢失 Track 或探针证据时显示 `STOP/UNKNOWN`，绝不选择公网默认路由输送私网数据。

### 4.3 状态机（**仅作为交接/模拟，不是自动执行器**）

`PRIMARY_VERIFIED`、`BACKUP_VERIFIED`、`SINGLE_SIDE_TRANSITION`、`ASYMMETRIC_STOP`、`BOTH_UNAVAILABLE`、`MANUAL_CUTOVER_REQUIRED`、`RECOVERY_PENDING`、`UNKNOWN`。状态只有在**双方**业务回执与路由表均对应时才能断言已安全切换；任何一次 SA-UP 的观测不应升级为路径业务 UP。

## 5. 交付件与代码约束

建议在 `docs/pr5/` 提交：

- `PR5_DEV_MANUAL.md`、`PR5_ACCEPTANCE.md`、`PR5_VENDOR_MATRIX.md`、`PR5_FAILOVER_RUNBOOK.md`、`PR5_SITE_ACCEPTANCE_TEMPLATE.md`、`PR5_REVIEW_CHECKLIST.md`。
- 更新 README 指向 PR5 交接入口；更新 `docs/roadmap.md` 使 PR1–PR4 已完成、PR5 进行中且生产 SKIP，清除“当前 Draft PR #1”等陈旧状态。
- **小范围**增加 `ipsecvpn/handoff.py` Markdown/JSON 改进或离线 report validator（如需求必要）；所有报告从 `authorized_lans`/`_connections`/`_backup` 推导，不得硬编码某次赛事地点/地址/StoneOS 型号。
- 任何现场核对、对端签收模板，都不存真实 credential/PSK、未脱敏序列号、公网地址、真实敏感拓扑的 Git 版本。文档可用 RFC5737 `192.0.2.0/24` / `198.51.100.0/24` / `203.0.113.0/24` 和 RFC1918 私网。
- 出站调度/自动路由动作不是 PR5 的隐性目标，**不得**新增 `ssh` 推送防火墙、Tencent API、`systemctl` 修改备网关或开公网管理端口。

## 6. 实验/CI 交付标准

- 离线 schema/JSON/Markdown golden tests；三套已有虚构赛事、多 CIDR、站点对调、两站备配置全/缺失、不同 vendor、PSK 不泄露；旧 106 pytest 不回退。
- 隔离 Ubuntu 24.04 QEMU 保留 PR2/PR3/PR4 所有回归；PR5 如有模拟双出口、备路径或故障状态机，必须**明确证据是 SIMULATED**；不能称为 Tencent/StoneOS 互操作 PASS。
- PR5 文档/报告验收可 PASS；真实硬件/云连接/主备自动切换只能标 `SKIP`，留待用户明确批准现场网络测试。不能为了获得全绿而连接真实设备或编造捕获值。
- 所有结果用 `PASS|FAIL|SKIP|STOP`，证据附 `head_sha`/case/time/observed/proof_refs。配置不完整是 `SKIP/INCOMPLETE`，安全冲突是 `STOP`，实际测量不合格是 `FAIL`。需要长期 SLO 时另设项目验收。

## 7. 官方资料使用规范

- Hillstone 官方网络产品资料说明部分 StoneOS 5.5 系列支持 IKEv2、基于路由/策略的 IPsec 与冗余，但**不能将 5.5R10/旧版文档当作 5.5R11P2-v6 的精确配置依据**。本次应输出“确认路径”和证据空栏，不输出未经版本核验的 CLI。
- Tencent Cloud VPN 网关功能限制及 Healthy Check/SPA/路由模式依产品版本演进；以客户实际购买的服务、租户区域和当日官方资料为准；不推定“云双隧道就能站点间 transit”。
- 参考（仅供人工验证，不是设备实测）：
  - https://www.hillstonenet.com/solutions/stoneos-5-5r10-enterprise-cybersecurity-hillstone-networks/
  - https://www.hillstonenet.com/support/5.0/en/SG2/config_policy_intro.html
  - https://www-sg.tencentcloud.com/document/product/1037/32682
  - https://www-sg.tencentcloud.com/document/product/1037/53821
