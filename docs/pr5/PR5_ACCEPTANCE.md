# PR #5 验收合同（开发时执行，不是当前 PASS 报告）

> Base / merge-base `6aacc03514ee98bea91e26bbba46a72451211715`。提交时将每项结果与完整当前 HEAD 关联。固定使用独立的 C/H/B/F/L 编号，避免与 PR2/PR3/PR4 的历史验收混淆。

## 证据字段

`case,time_utc,head_sha,environment,action,expected,observed,status,proof_refs`。不包含真实密钥、Webhook、公网 IP 或未授权设备配置；历史 FAIL 必须保留。真实外部设备在未授权时=SKIP，不得 mock 冒充 PASS。

## C — schema、离线报告和回归（C01–C14）

| ID | 必须验证 | PASS 判断 |
|---|---|---|
| C01 | PR1–PR4 现有离线 CI | 106 项以上原 pytest、Ruff、ShellCheck、wheel、Gitleaks 不退化 |
| C02 | 旧 V2 Profile | 三套虚构赛事和 `backup.enabled:false` 不变 |
| C03 | 双站 ID 更名与角色互换 | 交接从授权 topology 推导，方向一致 |
| C04 | 多 CIDR 与授权子集 | Site A 的 local/remote TS 精确镜像 Hub；不扩大授权 |
| C05 | Hillstone / Generic 两种出口 | 两份输出同源，字段不丢、不额外添加运行时承诺 |
| C06 | JSON / Markdown 一致 | IKE/CHILD/ID、CIDR、外层 Peer、NAT 与备元信息一致 |
| C07 | `secret_ref` 和输出 | PSK 始终 `<SEND_SEPARATELY>`，诊断不包含 secret |
| C08 | 无备路径 | 本站手册正常导出，不误报 INCOMPLETE |
| C09 | 启用但缺一端备资料 | 明确 `SKIP/INCOMPLETE` 且列出两站各缺失字段 |
| C10 | 两端完整备资料 | `PASS/COMPLETE` 仅表示资料齐备，真实验收仍 SKIP |
| C11 | 错误 route priority | 离线拒绝不安全/无效顺序，无静默 ECMP |
| C12 | 备 CIDR 过宽或备 Peer/primary 重复 | STOP/FAIL，不能越权或冲突 |
| C13 | 脱敏、格式与确定性 | 受控模板可复现，无赛事名/IP/云商写死 |
| C14 | 默认模式 / 无设备环境 | 所有导出和 plan 只读；不尝试设备/公网写入 |

## H — Hillstone/通用交接核对（H01–H12）

| ID | 验证 | PASS / STOP |
|---|---|---|
| H01 | 设备型号、完整 StoneOS patch、HA/VR | 手册预留真实证据签收；缺证据现场 SKIP |
| H02 | route-based vs policy-based | 明确分支；选择不明 STOP |
| H03 | IKEv2 PSK、Peer ID 类型和值 | 双方参数对照，无自动降级 |
| H04 | IKE/ESP/PFS/lifetime/DPD | 每条链路明确一致；不宣称厂商已经支持 |
| H05 | Proxy ID / Traffic Selector | exact TS，方向反向匹配；通配 selector STOP |
| H06 | 多 CIDR/多 Phase2 | 生成核对矩阵；设备能力未知保持 SKIP |
| H07 | 外层 ISP/Peer /32 路由 | 避免隧道自己递归或误入 XFRM |
| H08 | 内层静态路由/VR/PBR | 目标仅授权 remote CIDRs；回程正确 |
| H09 | 双方向安全区域与 NAT 豁免 | 本端/回程策略齐全，源 IP 不改 |
| H10 | WAN IKE ACL / NAT-T | 限定 Peer，记录必要端口与 ESP 条件 |
| H11 | 参数和现场实测区分 | report `PASS` 不冒充真实 SA/业务 PASS |
| H12 | 两位站点管理员签收 | 分别核验且 PSK 独立安全交付，不提交仓库 |

## B — 外部备网关与路由（B01–B14）

| ID | 实验/演练 | PASS 标准 |
|---|---|---|
| B01 | 云备路径拓扑可行性 | 必须有 A↔Backup↔B 的双向 transit/ACL/路由能力说明；否则 STOP/UNSUPPORTED |
| B02 | 仅两个云侧 SA 在线 | 明确 NOT ENOUGH / SKIP，绝不等于站间可达 |
| B03 | 云侧路由/网络隔离、带宽与费用 | 版本、地域和配额核对模板，未知 SKIP |
| B04 | 主备不同外层 Endpoint | 精确路由与不同密钥；冲突 STOP |
| B05 | 主备独立 Track 目标 | 目标/源/出口/VR/TTL 独立，可证明确实沿指定路径 |
| B06 | 仅备路径预演（模拟） | 两站备数据平面双向、源 IP 保留；模拟不能称云实测 |
| B07 | 主路径故障 | 两侧 route/Track 变更按顺序记录，未经允许不写实机 |
| B08 | 单侧主掉线 | 可见非对称并进入 STOP 或经过授权的协调机制 |
| B09 | 主备双断线 | 无公网私网明文泄漏，状态 UNKNOWN/STOP |
| B10 | 双端备路径稳定 | 双向 UDP/TCP+多 CIDR 证明，SA-UP 不够 |
| B11 | 主路径一侧提前恢复 | 不能提前 GREEN 或自动不对称回切 |
| B12 | 双端回切 | 路由恢复一致且有业务回执；中断实测，不承诺零中断 |
| B13 | flap/抖动 | 测试滞回/人工审批的设计，不写死秒数 |
| B14 | 自动切换 | 没有授权厂商实机环境时必须 SKIP；模拟通过不能声称生产自动 Track PASS |

## F — 故障、越权、安全（F01–F12）

| ID | 故障 | 期望 |
|---|---|---|
| F01 | 未授权站点/CIDR | STOP，拒绝扩大通信范围 |
| F02 | 不允许的 `0/0` selectors | STOP，不退化到 wildcard |
| F03 | 路由冲突/Peer 误路由 | STOP，不触碰现有默认路由 |
| F04 | 反向路由不一致 | 报不对称，业务不冒充 UP |
| F05 | 双端 NAT 豁免缺失 | 明确失败/未知和排查项 |
| F06 | Track 走错路 | 备路径返回不能作为主路径 PASS |
| F07 | 只有 IKE/CHILD 活跃 | 无真实回执时 data_path=SKIP/UNKNOWN |
| F08 | 设备 OS 版本未知 | 不输出可执行山石 CLI，兼容性 SKIP |
| F09 | 云商网关不支持站点中转 | 备方案 STOP/UNSUPPORTED，不默认改 CCN/API |
| F10 | 真实公网/实际设备未授权 | 模板只读，所有 live 检查 SKIP |
| F11 | 敏感报告文件泄露风险 | 检测拒绝不安全输出路径/环境，secret 不出日志 |
| F12 | 监控或备侧不可用 | 不修改主 Hub 服务/非项目路由和防火墙 |

## L — 现场生命周期/文档可操作性（L01–L10）

| ID | 验收内容 | 结果与证据 |
|---|---|---|
| L01 | 双方信息收集与 sign-off | 模板完整、责任方清楚；未填实测时现场 SKIP |
| L02 | 变更前快照、带外管理 | 必须列出手段和 STOP gate |
| L03 | 多 CIDR 验收矩阵 | 每个授权源/目标组合双向记录 |
| L04 | MTU/PMTUD/分片 | 记录真实业务包大小，空白=SKIP |
| L05 | SRT/游戏/制作业务 | 功能演练模板，无现场真实数据=SKIP |
| L06 | rekey/DPD 重连 | 明确无人值守 DPD 尚未验证 |
| L07 | 故障切换时间与丢包 | 只填实测，不默认零丢包 |
| L08 | 回切/回滚演练 | 双端回程一致、业务恢复，独立记录 |
| L09 | 赛事结束清理 | 只清理本赛事项目拥有资源、撤销密钥/访问 |
| L10 | PR 文档流程 | 先 Draft、完整 CI、Review，不自动 merge/部署 |

## 必须继续执行的旧验收

- PR #2 QEMU：V01–V20、F01–F14、L01–L04 = 38 unique cases。
- PR #3 三节点 QEMU：原真实 IKE/CHILD、UDP/TCP、MTU、S/T/N/F/I 实验。
- PR #4 监控 QEMU：采集、主动 UDP、Alertmanager mock、VICI/XFRM 基线及实际重启。
- 新报告验收若只改变 Markdown/模板可以在 offline CI PASS；旧 QEMU 仍应在同一 HEAD 复跑。实机厂商/公网结果必须 SKIP，不要求 Codex 为全绿而连接生产设备。

**合并门槛**：离线与 QEMU 同一 HEAD 全绿，审查无 P0/P1，Review Threads 解决；外部硬件/腾讯云公网/主备 Track 的生产验收仍 SKIP，有真实授权后另走现场变更批准。
