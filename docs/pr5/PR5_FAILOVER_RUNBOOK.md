# 主备路径交接与故障切换/回切运行手册

> 文档供授权的两端网络管理员执行。**本仓库不自动改变任何现场山石、第三方防火墙、腾讯云或备 Hub 路由。**

## 0. 演练准入（全部勾选才可进行）

- [ ] 两端实际设备型号、固件、HA/VR、接口和 WAN/Peer /32 路由已核实
- [ ] 主路径的 A↔Hub↔B 多 CIDR UDP/TCP 双向可用并记录真实源 IP
- [ ] 备路径已被证明支持 A↔Backup↔B **跨隧道转发**（不只是两条 IKE UP），两端方向和回程都通
- [ ] 主备两套独立 Outer/IKE/CHILD/Track 目标、各自的凭据和 ACL 具备
- [ ] 每一端保留带外管理、配置快照、已知安全回退路径与独立操作员
- [ ] Track 探测固定本地源、出口、路由表/VR 和远端响应端；验证故意绕路不会返回 PASS
- [ ] 两端计划不会产生逐包 ECMP、长期不对称回程、默认公网私网泄漏、NAT 错配
- [ ] 已确定切换责任、监控值班、测试窗口及撤销阈值；未经授权只做模拟

任一项缺失：`STOP / NO_CUTOVER`，不得把外部参数齐备当作演练通过。

## 1. 责任矩阵

| 角色 | 责任 | 不负责 |
|---|---|---|
| Hub owner | 本机 SA/路由/XFRM/ACL、监控、回滚 | 对端设备外部路由自动调整 |
| Site A admin | Site A 主/备隧道、路由、Track/ACL/NAT | Site B 路由 |
| Site B admin | Site B 主/备隧道、路由、Track/ACL/NAT | Site A 路由 |
| Backup/cloud admin | 云端两个 Peer/Transit、云路由、ACL/容量 | 假设站点间 transit 天然成立 |
| Observer | 证据归档、测试源/目的/方向、失败时间 | 将 `IKE_UP` 当 `BUSINESS_UP` |

## 2. 统一观测格式

每次记录：UTC 时间、site_id、path=primary|backup、WAN/VR/tunnel name、外层 Peer IP（私密记录）、IKE/CHILD、两端 route lookup / FIB、独立双向 UDP/TCP nonce 收发、NAT 原始地址、丢包/RTT/抖动/中断时长、Track 状态、可回退状态和证据 hash。

**注意：**主 Hub 的 PR4 UDP 证据只能证明**指定主 Hub 路径**，不能对外部备路径冒用。备路径必须有在其 ingress/egress 或备端 FIB 侧的独立可靠证据。

## 3. 推荐的保守实验步骤（不是可直接粘贴的设备命令）

| 阶段 | 操作（真实设备需变更批准） | 必须观察 | 决策 |
|---|---|---|---|
| 0 | 冻结 baseline、双端快照 | SSH / console / 原有业务仍可达 | 任一不可达 STOP |
| 1 | 在不切走业务前分别检查主和备 | 双路径各自 SA/路由/UDP/TCP/源 IP | 备路径无中转能力 STOP |
| 2 | 注入 Site A 的主路径故障 | Site A 选路变化、Site B 尚未变化的非对称窗口 | 长期非对称 STOP |
| 3 | 按批准计划协调 Site B 切换 | 双端 FIB 一致、原业务源 IP、UDP/TCP | 失败回滚 |
| 4 | 让 Site A 主链路提前恢复（Site B 未恢复） | Track 状态不等于双方选择同一路径 | 未同步则保持备用/人工处理 |
| 5 | 双方主路径稳定再受控回切 | 两端路由、业务、MTU、丢包和中断窗口 | 失败回滚 |
| 6 | 主备双故障或监控中断 | 私网不出公网默认路由、健康 UNKNOWN | 不切换/手工诊断 |

## 4. 抖动、故障检测、无人值守重连

- Track interval / NQA / hold-down / recovery hold / route priority 由两站**各自设备**和项目实际业务测量决定，没有“通用 5 秒切换”承诺。
- 当仅一个站点切换时，不能推断另一站也切换；监控与日志必须明确区分“单侧变更/双端稳定”。
- 现有 strongSwan Hub 在 PR3 仅验证 DPD clear 后显式 `initiate` 恢复，**无人值守断线自动重连未验证**；纳入现场风险。自动 Track 的 enable 条件包括备路径真实稳定、双站同步及恢复后的去抖/回切测试。
- SRT / 游戏 / UDP 长连接可能因切换或短期非对称断开；不能声称业务无感。报告需分别记录 SA 恢复时间、路径业务恢复时间和客户端重新建立会话时间。

## 5. 立即停止与人工恢复

触发：未知 SA/路由对象、管理口不可达、主备都未知、返回互联网默认路由、明文私网泄漏、未授权 CIDR 通过、连续抖动、站点 FIB 不一致且业务损失超过批准容忍度。

停止变更 → 维持/恢复已验证的安全路由或停发受保护流量 → 独立控制台检查双方 FIB/HA/NAT/ACL/Peer → 与对端管理员确认更改 → 按各自配置备份回滚 → 复核**两端**真实业务再关闭事件。不自动删除未归属的 SA/Route、不得 `nft flush ruleset`。

## 6. 签收模板

`test_id | before_hash | after_hash | UTC | site-A route/path | site-B route/path | cloud/backup route | A→B UDP/TCP | B→A UDP/TCP | MTU | max_loss | outage_s | failback_s | PASS/FAIL/SKIP/STOP | evidence_ref | signoff`

未执行或无法测量填 `SKIP`，失败和超时填 `FAIL/STOP`，禁止留空后输出 PASS。
