# ipsecVPN · PR #2 开发手册（强制交付合同）

- **版本**：PR2-1.0 / 2026-11-06
- **仓库**：https://github.com/yikkrrtykj/ipsecVPN
- **精确基线**：`main` 的 merge commit `5f6ac250043c37d97cc375dae2250c89257b7ca2`
- **PR 分支建议**：`codex/pr2-deployment-transaction`
- **开发结果**：一个独立 **Draft PR**，严禁自动 merge；不接触生产 VPS、山石、腾讯云。
- **上位规格**：`docs/SPEC.md` V2.0；本手册细化 PR #2 的实现和测试，不改变 PR #1 公共输出语义。

## 0. 本阶段目标与完成定义

在 PR #1 已完成的 **通用赛事 profile + 只读 CLI** 上，为 **Ubuntu 24.04 LTS** 实现可审计、可撤销的 **strongSwan IKEv2 + 双独立 XFRM 接口** 配置部署。站点/地域/VPS/ISP/网段/防火墙均来自 profile，不可写死。支持**一台 Linux Hub、恰好两个远端站点、每站一个主 IPsec 链路、每站多授权 IPv4 CIDR**。仅一个活动部署 profile。

本 PR 达到的 PASS 必须指：**配置正确渲染、依赖和本机网络准备在隔离 Ubuntu 环境实际完成、可幂等应用、可恢复、不可破坏现有公网和 SSH 路径**。不能因为生成了配置就声称端到端 IPsec 已可用。

**明确不做**：不建设真实上海/海外链路、不配置任何山石、腾讯云 API、CCN、主备自动切换、不接入 Prometheus/Grafana/飞书、不开发浏览器 UI。真实 IKE/CHILD SA 建链、跨两条隧道转发、UDP/TCP、重协商、MTU、现场 Track 分别留给 PR #3/#5；这些运行验收一律 `SKIP`，除非对应的隔离证据真实产生且在报告里注明边界。

## 1. 依赖与既有接口（必须向后兼容）

Codex 开发前必须重新读取：

- `config/schema.json`、`ipsecvpn/profile.py`：两个任意站点、`site_links[].if_id`、`outer_path`、`secret_ref`、`traffic_policy.allowed_site_pairs`、`backup`。
- `ipsecvpn/handoff.py`：`authorized_lans()`、站点与 Hub 的流量选择器推导。**同一拓扑模型**产生 Hub 端 `swanctl`、内层路由、nft ACL 和 peer handoff，禁止四份独立计算。
- `ipsecvpn/cli.py`：不得破坏 `profiles list`、`validate`、`check`、`plan`、`export-peer` 的参数、只读和 PASS/FAIL/SKIP 约定。
- `docs/SPEC.md`、`docs/architecture.md`、`docs/roadmap.md`：当前范围和后续阶段。

特别保留 PR #1 的备用状态：`backup.enabled=true` 但未完整填写时，`validate` 为格式 PASS 且备用 `SKIP/INCOMPLETE`；`plan` 仍输出主链路；`export-peer` 暂缓参数单。**PR #2 不应因外部备用资料缺失而误阻断合法主 Hub 的本机渲染/隔离部署**，但必须在输出和审计里说明 `external backup SKIP`，不得对备用报 READY。若设计有不同选择，先建立显式兼容性测试并在 PR 中解释。

## 2. 组件与推荐目录

建议将核心逻辑拆开，而不是写一个几千行 shell 脚本：

```text
ipsecvpn/
  cli.py                    # 命令分发，保持向后兼容
  renderer.py               # 从经过验证的 profile 产生不可变资源清单
  host.py                   # OS/包/服务/网络冲突/权限检查
  transaction.py            # 加锁、快照、journal、apply、rollback
  resources.py              # 接口、路由、sysctl、nft、服务的所有权管理
  secrets.py                # 受保护的 file: 引用和 PSK 处理
  models.py                 # 已验证资源清单、运行状态和错误类别
  templates/                # 纯模板，无真实环境数据
scripts/
  install.sh                # **薄包装**，转发至 Python CLI
  validate-examples.sh     # PR #1 原有脚本不回归
docs/
  pr2/PR2_DEV_MANUAL.md
  pr2/PR2_ACCEPTANCE.md
  install.md                # 运维部署与升级（仅实验环境为已验收）
  rollback.md
  network-ownership.md
  security.md
```

所有交付文件兼容 wheel 安装：安装后不依赖仓库工作目录或 `git`、测试 fixtures。使用 Python 模块内资源或 `importlib.resources`；CI 必须再次做仓库外 wheel smoke test。

## 3. 资源所有权与零破坏承诺

项目只管理 **明确登记的自有对象**，包括：

- 由工具生成并登记的 strongSwan connections/CHILD、项目私有配置 include、项目 PSK 运行配置（root-only）。
- 命名前缀 `ivp...` 的两个 XFRM 接口，独立 `if_id`，和只属于该项目的内层精确路由/可证明的 fallback 阻断。
- 单独命名的 `nft` 表/链/规则及可回滚的项目专用启动单元/配置文件。
- 显式登记的项目专用 sysctl 文件及其本次受影响运行时值（如果确需修改）。

**不能修改或删除**：主网卡地址、默认路由、已有 SSH 端口、现有 UFW/iptables/nftables 全局规则、Netplan/NetworkManager、其他 strongSwan 连接/凭据、其他项目的 XFRM/路由及系统已有 VPN。不得 `nft flush ruleset`、`iptables -F`、`ip route flush`、整文件覆盖 `/etc/swanctl/swanctl.conf`、盲目 `systemctl restart` 已有共享 IKE 服务。

**硬性 STOP 规则**：发现现有 IKE 服务被另一应用使用；XFRM `if_id`/名字或 CIDR 路由冲突；现有转发安全链阻断而无法无破坏集成；公网 Peer 路由依赖将要被改动的对象；无法证明回滚；无法保留 SSH/公网连接；版本与预期不同。返回 `FAIL/STOP`，不要尝试“顺手修好”其他工具。

## 4. 预检、系统包与服务

- 目标系统仅 Ubuntu **24.04**，内核需要支持 XFRM interfaces、`ip`、`nft`、systemd；先用只读探测而非凭 OS 名称假设全部功能可用。
- 官方包优先采用发行版 `charon-systemd`、`strongswan-swanctl`，并验证实际已安装 package、daemon、VICI socket、unit 名称和状态。不与 legacy `strongswan-starter`/其他 charon 实例并行竞争 UDP 500/4500。
- `install --dry-run` 仅输出软件包和资源变更计划；`install --confirm` 只允许在授权的隔离实验 VM；包管理需要明确报告新增包清单与版本，不私自卸载已存在包。
- 若 OS 包安装/daemon 启动会影响现有 VPN，**拒绝自动安装**并提示需要专用 VM，不因 `--confirm` 绕过冲突。
- 服务启动、`swanctl --load-*`、VICI 命令的成功码要检查，错误必须触发失败/回滚，不可捕获后仍记 PASS。
- 进程和运行时检查使用 subprocess 参数数组（`shell=False`），超时、stdout/stderr 脱敏；禁止将 PSK 传作 argv/env/日志。

## 5. swanctl 渲染（P0 两个 peer）

### 5.1 唯一数据源

应用 `validate_profile()` 和 PR #1 的授权子网推导，再生成 `DeploymentManifest`（配置文件列表、预期 sha256、两个 IPsec connections、接口、路由、安全规则、启动顺序、需要的权限和回滚镜像）。`render` 默认只读：输出**不含明文密钥**的资源摘要及结构化 `--json`；如要落地渲染文件，要求单独的明确 `--output-dir`，只允许本地受限目录、拒绝 symlink、使用原子写入、权限 0600，且**不能因此自动应用**。

### 5.2 IKE/ESP 及 TS

对每个站点分别生成独立命名的 IKEv2 connection 和 CHILD；站点连接使用自己的 `public_endpoint`、`ike_identity`、per-link PSK 引用、相应 `if_id`、IKE/ESP proposal、lifetime 和 DPD。

**从 Hub 视角**：

| CHILD | Hub `local_ts` | Hub `remote_ts` | `if_id_in` / `if_id_out` |
| --- | --- | --- | --- |
| Hub ↔ 站点 A | 站点 B 的授权 CIDRs | 站点 A 的授权 CIDRs | A 链路的固定 `if_id` |
| Hub ↔ 站点 B | 站点 A 的授权 CIDRs | 站点 B 的授权 CIDRs | B 链路的固定 `if_id` |

每条链路的 in/out XFRM ID **相同**、不同链路之间不同。XFRM 接口是 Hub **本机接口**，不要求山石具有同名 XFRM。不能误把两端本端/远端 TS 方向颠倒；不自动扩展为 `0.0.0.0/0`；多 CIDR 的实际对端协商行为留给 PR #3/现场验收。

默认建议 `start_action=none` 作为安全的离线/隔离首次启动策略，运行时只有明确的隔离测试或经批准的操作才触发实际协商；PR #2 不为了给 CI 看“在线”而连接真实 peer。`dpd_action` / `close_action` / `start_action` 的组合要按安装的 strongSwan 5.9.x 官方文档及实验环境验证，不能凭想象叠加导致重连风暴。正式持续建链策略属于 PR #3 验证后启用。

### 5.3 密钥和配置文件

仅在 root 受控路径 `/etc/ipsecvpn/secrets/` 引用 per-link PSK 文件。真实运行时需生成 strongSwan 可解析的 `secrets { ike-... {} }` 条目，确保 IKE ID 与特定 peer 绑定；**不能将 `file:/...` 字样原样充当 `secret` 传入 swanctl**，也不能在公开 `render`、shell 输出、测试快照中显示 PSK。

实现者必须查证发行版 5.9.x 支持的 include 布局、load 时序与凭据配置形式，不覆盖其它项目的 swanctl 配置。没有可证明的独立管理边界时 STOP，而不是重写总配置。PSK 生成优先使用高熵随机；不得接受旧示例密码作为默认值。

## 6. XFRM、路由、转发与安全（关键）

### 6.1 接口、ID、路由

- 创建两个固定 `if_id` 的 XFRM 接口（接口名 <= Linux IFNAMSIZ 限制，经过严格命名规则），无需给它们分配内层点对点 IP。
- 将每个站点**已授权** CIDR 的路由显式指向对应 XFRM 接口；采用明确的本项目所有权，禁止覆盖已有冲突路由。
- `charon.plugins.kernel-netlink.install_routes_xfrmi` 必须和项目路由管理策略一致；本 PR 推荐由工具统一管理精确路由，禁用会与其重复的自动路由装载（先验证实际版本语义）。
- 外层 IKE Peer 的 `/32` 公网路由只要能通过已存在的 WAN 默认路由安全到达，就**不必强制新增**；如显式设置源接口/下一跳，校验所选地址、WAN 当前路由/网卡及下一跳确实匹配。任何自动新增的 `/32` 都要登记、可精确撤销，不能跨接口劫持管理流量。
- `outer_path.interface: auto` 是**离线占位**，在真实 `apply` 时 **STOP**；不能自动猜网卡然后悄悄部署。

### 6.2 Fail closed：避免隧道断开后私网经默认路由泄漏

对每个授权远端 CIDR，设计并证明**精确的不可泄漏路由策略**：

1. 正常时只经匹配的 XFRM 接口发送。
2. SA 失效、XFRM 接口被删或服务重启的过程中，不能因此掉到 VPS 默认公网路由；必须有**受管控的 fallback blackhole/unreachable 路由或等价明确的阻断机制**，并且测试实际内核查路由行为。
3. 对已有同前缀或更具体路由、其它策略路由表和规则进行冲突检查。不能简单宣称装了黑洞就万无一失；先建立隔离实验且给出证据。
4. 回滚时仅清除本次安装的新路由对象；若清除黑洞会使服务器原有业务风险增加，则按 pre-state 恢复原状而不是瞎删。

不要动默认路由；不要对所有私网做 `10.0.0.0/8` 的全局黑洞；仅作用于声明的授权 CIDR，拒绝与原有路由冲突的部署。

### 6.3 nftables 与 sysctl

- `net.ipv4.ip_forward=1` 是否需要修改必须记录 before/after，并考虑其他依赖。`rp_filter` 根据内层路径和接口逐项检查；不准全局粗暴关闭。
- 仅对 XFRM A ↔ XFRM B 的获准源/目的 CIDR 组合做双向 FORWARD ACL；不做 SNAT/MASQUERADE。
- 采用项目私有 nftables table/chain，拒绝覆盖其他 table；**注意不同 base chain 的 `accept` 不能覆盖另一个 chain 的 `drop`**，检测到其它规则阻断时必须失败退出或提供经过用户批准的明确集成方案。
- 非授权 XFRM 流量必须 DROP；其它 VPS 业务不可受本项目链的默认策略影响。
- 项目专用规则的加载必须能独立更新/移除，并通过 `nft -c -f` 或等效机制检查语法，不能 `nft flush ruleset`。
- 云厂商安全组/上游 UDP 500、4500、ESP 的开放要求只出现在手册；不得自动调用供应商 API，也不得自动放宽 VPS 管理端口。

## 7. CLI 契约与退出码

保留 PR #1 原始命令行为。新增：

```bash
ipsecvpn render -c /path/to/event.yaml --json       # 脱敏资源清单，只读
ipsecvpn install --dry-run                            # 只输出系统依赖/风险
ipsecvpn install --confirm                            # 显式写入，仅隔离 Ubuntu
ipsecvpn apply -c /path/to/event.yaml --dry-run       # 资源 diff，不写系统
ipsecvpn apply -c /path/to/event.yaml --confirm       # 写入，前置全量 preflight
ipsecvpn backup                                       # 只备份项目拥有资源/元数据
ipsecvpn rollback --to <backup-id> --dry-run
ipsecvpn rollback --to <backup-id> --confirm
ipsecvpn uninstall --dry-run
ipsecvpn uninstall --confirm                          # 精确移除本项目对象
```

CLI 若增加 `--json` 或 `--output-dir`，保持统一结构并测试。`--confirm` 必须是交互之外**显式执行者的授权**，但并非无条件绕过预检。没有 root/权限不足、版本不符、对象冲突、不能保证回滚、操作系统不受支持，全部 `FAIL/STOP`；如果只是未执行真人场馆联调则 `SKIP`，不能拿 `SKIP` 代替严重风险。

建议 `--confirm` 只在无 CI 生产凭据的隔离 VM 测试中运行。`check` 不应因为强制功能尚未交付而冒充运行 PASS。

## 8. 事务（核心门槛）

必须实现 **串行加锁 + durable journal + pre-state snapshot + 可验证恢复**，不是只写一个 `cp config.bak`。

### 8.1 状态机

```text
NEW → PREFLIGHT_OK → SNAPSHOTTED → STAGED → APPLYING → VERIFIED → COMMITTED
                       ↘ FAILED/INTERRUPTED → RESTORING → RESTORED / STOP_FOR_MANUAL
```

- 只有一笔 apply/install/rollback/uninstall 可以操作资源；使用系统级锁；重复命令不能并发覆盖。
- 预检全部成功后才开始写入；对 profile、渲染资源和 `pre-state` 做 digest；journal 记录每一步、开始完成时间、对象 ownership、操作者、执行结果；不得记录 PSK/凭据。
- 保存系统状态证据：公网默认路由及相关 `ip rule`、公网/SSH 连接信息（只记录必要信息并脱敏）、现有接口和 XFRM ID、现有路由/策略、项目 nft 对象、strongSwan 服务、受控文件权限/哈希、sysctl 旧值。
- 配置文件使用临时文件、权限/属主校验、fsync/原子 rename；网络对象按可回滚顺序变更。严禁在尚未检查的情况下抢占其它对象。
- verify 不止检查命令返回 0：检查预期配置、接口、路由、ACL 与 baseline 守恒；上线级业务可达性不在本 PR 冒充验证。
- 如果失败，按反向依赖顺序恢复本次拥有对象及原始状态。**进程意外退出/VM 中断后下次启动必须发现未完成 journal**，禁止继续应用新配置，需由明确的 recover/rollback 流程处理。
- 如无法证明恢复成功，`FAIL/STOP_FOR_MANUAL` 并保留诊断证据；不能打印 `PASS rollback`。
- 定义 crash 后恢复路线：状态持久化并明确操作选择；**不能在未经批准或未验证时自动改动当前生产网络**。

### 8.2 升级/卸载与幂等

- 相同 profile 二次 `apply`：资源无变化，输出 `PASS NOOP`，不重复启动、不重复新增规则。
- 有差异时仅操作项目对象；不允许 `apply` 偷换活动 profile。项目支持多保存 profile，但每台 Hub 只允许一个活动 profile。
- `uninstall` 只移除本项目对象及本次安装拥有的启用状态；绝不能因为是工具安装的包就擅自删除系统共享包。
- 重启后能恢复项目拥有的必要接口/路由/ACL，不能依赖手动 SSH 输入；用明确 systemd 单元/可核对的配置，测试服务启动先后与异常处理。
- 没有备份或者备份损坏时禁止破坏性 rollback；给出可操作的人工恢复步骤但不要伪恢复。

## 9. 测试与验收要求（必须看另一文件）

在 PR 内附 `docs/pr2/PR2_ACCEPTANCE.md`，至少满足：

- PR #1 62 项（或新数量）全部继续 PASS。
- pytest、Ruff、ShellCheck、JSON schema、Gitleaks、wheel 仓库外安装继续 PASS。
- 在**无公网、无赛事凭据的专用 Ubuntu 24.04 VM** 上真实运行 install/apply/rollback/uninstall；如仅在 mock 中运行，不能把 VM 验收标成 PASS。
- 模拟冲突、失败中断、重启、重复 apply、外层路由变化、iptables/UFW/nft 共存、已有 strongSwan 实例、缺失密钥、软链接攻击和权限不足。
- 通过脚本对比**操作前后**默认路由、现有 SSH/管理链路、其它 table/规则、非项目接口与受管对象；执行次数、状态和异常均入证据。
- 即使 SA/接口被移除，授权远端 CIDR 不能退回公网默认路由（隔离真实路由查找验证）。
- 生成的 `swanctl` 配置在目标版本由真实 daemon 加载并可被 `swanctl --list-conns` 列出，双链路 SA 可以全部处于未连接状态；这不是 PR #3 的业务可达验收。
- 真实两站 IPsec 协商、UDP/TCP/MTU/真实山石/腾讯云切换，全部继续明确 `SKIP`。

## 10. 仓库和 PR 提交约定

1. 从 `5f6ac250043c37d97cc375dae2250c89257b7ca2` 的 `main` 新建开发分支，base/merge-base 与 main 对齐；不要把本手册直接当作对生产机执行的命令。
2. 先审读技术设计与权责表，再实现纯渲染；后实现预检和快照，最后引入明确确认的有副作用操作。
3. 每条重要执行动作有单测、隔离集成测试、故障注入和“不会影响第三方资源”的负面测试；文档声称与证据必须一致。更新 `README.md` 中“当前 Draft PR #1”的过时描述，明确 PR #1 已合并而 PR #2 仍属实验阶段。
4. 不产生未授权 GitHub 资源或修改其它仓库；PR 必须 Draft，不合并、不推生产；任何强制停止事项用 `STOP` 报告原因与建议。
5. 提交结尾报告：head SHA、base/merge-base、文件列表、变化摘要、所有 CI job 链接、每项 PASS/FAIL/SKIP、缺失环境和未解决风险、手工恢复路径。禁止把未执行的测试写成“已验证”。

## 11. 官方技术依据（Codex 应以部署时实际版本再次核对）

- strongSwan 5.9 Route-based VPN / XFRM：<https://docs.strongswan.org/docs/5.9/features/routeBasedVpn.html>
- strongSwan `swanctl.conf`（`if_id_in/out`、Traffic Selectors、`start_action`）：<https://docs.strongswan.org/docs/5.9/swanctl/swanctlConf.html>
- strongSwan `charon-systemd`、systemd 单元：<https://docs.strongswan.org/docs/latest/daemons/charon-systemd.html>
- Ubuntu 24.04 `charon-systemd` 包：<https://packages.ubuntu.com/noble-updates/charon-systemd>

**特别提醒**：官方文档可以证明功能语义，不等于具体 Ubuntu 镜像、网关、山石厂商版本、既有 host firewall 的实际行为。所有写系统动作必须在隔离实验机实测。
