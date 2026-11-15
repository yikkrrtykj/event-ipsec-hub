# 赛事 Site-to-Site IPsec 现场验收与交接记录（复制到受控环境填写）

> **空白即未验收 / SKIP**。本模板不包含真实赛事资料，不可将填有真实公网、PSK、人员信息的版本提交公开 Git 仓库。

## A. 项目与授权

| 字段 | 填写 |
|---|---|
| event_id / profile_SHA / repo HEAD | `_____` |
| 日期/时区/维护窗口 / 实施审批 | `_____` |
| Hub owner / Site A admin / Site B admin / Backup admin | `_____` |
| 只读 observer / 带外管理/紧急联络 | `_____` |
| site IDs / 精确业务 CIDRs（仅内部副本） | `_____` |
| 现网配置备份 ID 与测试回滚人 | `_____` |

## B. 外层路径与协议对账

| 证据字段 | Primary Hub → Site A | Primary Hub → Site B | Backup Site A | Backup Site B |
|---|---|---|---|---|
| 路由/出口/ISP/固定公网 | SKIP | SKIP | SKIP | SKIP |
| Peer IP / IKE ID 类型和值 | SKIP | SKIP | SKIP | SKIP |
| Device model / OS full build / HA / VR | SKIP | SKIP | SKIP | SKIP |
| IKEv2/PSK 独立交付/Proposal/DPD | SKIP | SKIP | SKIP | SKIP |
| CHILD/ESP/PFS/Selectors/Proxy IDs | SKIP | SKIP | SKIP | SKIP |
| NAT exemption / 安全区域 / 双向 ACL | SKIP | SKIP | SKIP | SKIP |
| IKE SA 和 CHILD SA + 核对 SPI 证据 | SKIP | SKIP | SKIP | SKIP |
| 路由优先级与本地/远端精确 CIDR | SKIP | SKIP | SKIP | SKIP |
| 独立 Track 源/出口/目标/TTL | SKIP | SKIP | SKIP | SKIP |
| 已核实的 route-based / policy-based 与多 Proxy ID 能力 | SKIP | SKIP | SKIP | SKIP |

### 外部备网关中转能力

| 核对项 | 记录 | 结果 |
| --- | --- | --- |
| 供应商 / 产品与精确模式 / 地域 / 版本 / 支持依据 | `_____` | SKIP |
| A→备→B 及 B→备→A 的入口、出口、ACL 和回程路由 | `_____` | SKIP |
| 路由表及隔离域 / 准确的远端网段 / 源地址保持 | `_____` | SKIP |
| 最大隧道数与路由数 / 实际可用带宽 / 计费与出流量 | `_____` | SKIP |
| 不经主 Hub 的两端独立转发证据 / 备网关负责人签收 | `_____` | SKIP |

无法提供支持证据则 `STOP/NO_CUTOVER`。确认不支持双向跨隧道转发记 `STOP/UNSUPPORTED_BACKUP_TRANSIT`。

## C. 每对允许 CIDR 的业务实测（按授权 pairs 复制行）

| src CIDR/测试主机 | dst CIDR/测试主机 | path | 方向 | 协议 | 发送/接收 | 原始源 IP | RTT / Loss / Jitter | MTU | PCAP/签名摘要 | PASS/FAIL/SKIP/STOP |
|---|---|---|---|---|---|---|---|---|---|---|
| `_____` | `_____` | primary | A→B | UDP | `_____` | `_____` | `_____` | `_____` | `_____` | SKIP |
| `_____` | `_____` | primary | B→A | UDP | `_____` | `_____` | `_____` | `_____` | `_____` | SKIP |
| `_____` | `_____` | primary | A→B | TCP | `_____` | `_____` | `_____` | `_____` | `_____` | SKIP |
| `_____` | `_____` | primary | B→A | TCP | `_____` | `_____` | `_____` | `_____` | `_____` | SKIP |
| `_____` | `_____` | backup | A→B | UDP | `_____` | `_____` | `_____` | `_____` | `_____` | SKIP |
| `_____` | `_____` | backup | B→A | UDP | `_____` | `_____` | `_____` | `_____` | `_____` | SKIP |
| `_____` | `_____` | backup | A→B | TCP | `_____` | `_____` | `_____` | `_____` | `_____` | SKIP |
| `_____` | `_____` | backup | B→A | TCP | `_____` | `_____` | `_____` | `_____` | SKIP |

每对网段、方向及路径另填业务实际包大小、最大成功 DF 长度、PMTUD 反馈、分片结果、TCP MSS 和回执号。未执行填 `SKIP`。

## D. 主备/故障与回切

| case | 故障注入与观察 | 双端路由一致性 | 业务丢包/中断/回切 | 真实证据 | 结果 |
|---|---|---|---|---|---|
| PRIM-LOSS-A | A 端主链路故障 | `_____` | `_____` | `_____` | SKIP |
| PRIM-LOSS-B | B 端主链路故障 | `_____` | `_____` | `_____` | SKIP |
| BACKUP-ONLY | 两端在备路径双向可用 | `_____` | `_____` | `_____` | SKIP |
| ASYMMETRY | 只有一端切换 | `_____` | `_____` | `_____` | SKIP |
| FAILBACK | 一端先恢复，两端协调回切 | `_____` | `_____` | `_____` | SKIP |
| BOTH-DOWN | 主备双断，私网不可明文外泄 | `_____` | `_____` | `_____` | SKIP |
| DPD-RECONNECT | 无人值守断线恢复（需另行验证） | `_____` | `_____` | `_____` | SKIP |
| REKEY | IKE/CHILD 重协商和业务持续性 | `_____` | `_____` | `_____` | SKIP |
| FLAP | 单端持续抖动，观察稳定窗口重置 | `_____` | `_____` | `_____` | SKIP |
| NO-NAT | 检查双端 NAT 豁免和未授权网段阻断 | `_____` | `_____` | `_____` | SKIP |

业务中断、丢包、首个恢复回执、受控回切及会话恢复分别计时。没有实测不得填零。

## E. 赛事功能验证

| 场景 | 验证人 | 实测结果 | 备注 |
|---|---|---|---|
| SRT 双向实时贡献业务 | `_____` | SKIP | 帧丢失、端到端 RTT、抖动、码率、重连 |
| 游戏/制作系统通信 | `_____` | SKIP | 游戏服务器/OB 业务实际收发 |
| QoS/ISP 主备对业务影响 | `_____` | SKIP | 本项目不自动修改站点 QoS |
| 监控及告警（真实飞书需单独授权） | `_____` | SKIP | SA/业务路径须独立显示 |

## F. 停止/回滚与最终签收

- 未解除的 FAIL/STOP：`_____`
- 证据缺失与 SKIP 清单：`_____`
- 对端设备配置备份哈希、Hub backup_id：`_____`
- 恢复后的 route/SA/业务重新检查：`_____`
- 撤销计划（完成后仅本项目对象）、PSK 轮换：`_____`
- 复核撤销后原有管理、默认路由和非赛事防火墙：`_____`
- 双方签收：Site A `_____`、Site B `_____`、Hub `_____`、Backup `_____`
- **结果**：`PASS / FAIL / SKIP / STOP`（只有范围内所有必需证据都通过才能 PASS）
