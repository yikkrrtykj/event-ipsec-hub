# 历史任务文档的处置与要求保留位置

基线 `d8f20f546dd02b01b6a9862451bd2f81c9fc11e3`。迁移对应
[清理 Issue #15](https://github.com/yikkrrtykj/event-ipsec-hub/issues/15)。
表内原文件均可在[固定基线](https://github.com/yikkrrtykj/event-ipsec-hub/tree/d8f20f546dd02b01b6a9862451bd2f81c9fc11e3)复核。
V2.0 已完成的任务保留在 [PR #1–#5](https://github.com/yikkrrtykj/event-ipsec-hub/pulls?q=is%3Apr+is%3Amerged)。
未完成的开发需求集中在 [V3.0 Epic #6](https://github.com/yikkrrtykj/event-ipsec-hub/issues/6)。

| 原文件 | 处置 | 技术要求、任务和证据的保留位置 |
| --- | --- | --- |
| `CODEX_TASK.md` | 删除历史任务 | V2 通用配置、精确授权、只读 CLI、凭据和样本约束见 [SPEC](../SPEC.md)、[安全](../security.md) 与 PR #1。N 站扩展见 [#7](https://github.com/yikkrrtykj/event-ipsec-hub/issues/7)。 |
| `CODEX_PR2_TASK.md` | 删除历史任务 | [安装](../install.md)、[所有权](../network-ownership.md)、[回滚](../rollback.md)、[验收矩阵](../pr2/PR2_ACCEPTANCE.md) 与 [技术手册 §3–9](../pr2/PR2_DEV_MANUAL.md)保留目标平台、预检、`auto` STOP、有限写入、黑洞及事务门槛。生产准入见 [#14](https://github.com/yikkrrtykj/event-ipsec-hub/issues/14)。 |
| `CODEX_PR3_TASK.md` | 删除历史任务 | [活动 SA 归属](../pr3/SA_OWNERSHIP_DESIGN.md)、[三节点拓扑](../pr3/PR3_LAB_TOPOLOGY.md)、[技术手册 §1–8](../pr3/PR3_DEV_MANUAL.md)、[活动操作](../pr3/LIVE_OPERATIONS.md)、[验收矩阵](../pr3/PR3_ACCEPTANCE.md)保留生命周期、真实双向收发、MTU 和防泄漏。回滚时序 [#10](https://github.com/yikkrrtykj/event-ipsec-hub/issues/10)、自动重连 [#11](https://github.com/yikkrrtykj/event-ipsec-hub/issues/11)。 |
| `CODEX_PR4_TASK.md` | 删除历史任务 | [PR #4 技术手册 §2–10](../pr4/PR4_DEV_MANUAL.md)、[指标合同](../pr4/PR4_METRICS_ALERTS.md)、[运行手册](../pr4/OPERATIONS.md)及[验收矩阵](../pr4/PR4_ACCEPTANCE.md)保留可选、回环、只读、按路径探测、TTL、UNKNOWN 与告警安全。多站告警见 [#9](https://github.com/yikkrrtykj/event-ipsec-hub/issues/9)。 |
| `CODEX_PR5_TASK.md` | 删除历史任务 | [PR #5 技术手册 §2–6](../pr5/PR5_DEV_MANUAL.md)、[验收矩阵](../pr5/PR5_ACCEPTANCE.md)、[回切手册](../pr5/PR5_FAILOVER_RUNBOOK.md)和 [PR #5](https://github.com/yikkrrtykj/event-ipsec-hub/pull/5)保留独立 Draft、L10 验收、备用中转及停止条件。双 ISP [#8](https://github.com/yikkrrtykj/event-ipsec-hub/issues/8)、托管 VPN [#12](https://github.com/yikkrrtykj/event-ipsec-hub/issues/12)、切备 [#13](https://github.com/yikkrrtykj/event-ipsec-hub/issues/13)。 |
| `docs/roadmap.md` | 更新为能力和验收索引 | 阶段施工计划在合并 PR，后续优先级及进度在 Epic #6。并行赛事、重叠网段 NAT 和其他厂商/协议的范围留待另行批准。 |
| `docs/pr2/PR2_ACCEPTANCE.md` | 保留 | C/V/F 保持原编号和断言，补录最终人工复审及 VM 已执行的 L01–L04。 |
| `docs/pr2/PR2_DEV_MANUAL.md` | 保留技术章节 | 幂等、安装和服务、精确路由、接口与 ACL、持久事务、文件安全和测试技术条件；历史分支和最终汇报指令留在固定基线。 |
| `docs/pr2/PR2_EVIDENCE.md` | 保留 | 初始 FAIL、路由与 XFRM 修复历程；最终包清单与人工恢复证据见 PR #2 与[证据归档](README.md)。 |
| `docs/pr3/CODE_ACCEPTANCE.jsonl` | 原样保留 | 14 条历史代码验收回执及原执行 SHA。 |
| `docs/pr3/LIVE_OPERATIONS.md` | 保留 | 活动隧道、显式 initiate、维护、故障诊断。 |
| `docs/pr3/PR3_ACCEPTANCE.md` | 保留 | C/T/S/N/F 保持原编号和断言；补录最终已执行 I01–I03。 |
| `docs/pr3/PR3_DEV_MANUAL.md` | 保留技术章节 | 联合所有权、活动 SA 生命周期、数据平面、MTU、诊断、维护及保护；历史分支和交付指令留在固定基线。 |
| `docs/pr3/PR3_EVIDENCE.md` | 保留 | 三节点实测、MTU、各轮失败和修复；最新与重跑见[证据归档](README.md)。 |
| `docs/pr3/PR3_LAB_TOPOLOGY.md` | 保留 | 隔离拓扑、独立 WAN 抓包、防泄漏验证。 |
| `docs/pr3/PR3_REVIEW_CHECKLIST.md` | 删除重复阶段清单 | 通用门槛见 [SPEC 的审查与交付](../SPEC.md#10-审查与交付)，技术断言在 [PR #3 验收矩阵](../pr3/PR3_ACCEPTANCE.md)、[活动 SA 归属](../pr3/SA_OWNERSHIP_DESIGN.md)和[实验拓扑](../pr3/PR3_LAB_TOPOLOGY.md)。 |
| `docs/pr3/SA_OWNERSHIP_DESIGN.md` | 保留 | 稳定/过渡/外来/未知 SA、禁止全局重载及严格维护互斥。 |
| `docs/pr4/OPERATIONS.md` | 保留 | 安全启停、只读采样、mock 告警、主路径证明及排错。告警桥依赖此文件的路径。 |
| `docs/pr4/PR4_ACCEPTANCE.md` | 保留 | C/M/P/A/R 编号、原始验证及拒绝条件。 |
| `docs/pr4/PR4_DEV_MANUAL.md` | 保留技术章节 | 可选监控、严格回环、有限标签和只读权限、UDP 探针、指标、告警投递、线上禁区；历史开发入口留在固定基线。 |
| `docs/pr4/PR4_EVIDENCE.md` | 保留 | 采样权限/超时、旁路等历史 FAIL 与原始计时。 |
| `docs/pr4/PR4_LAB_TOPOLOGY.md` | 保留并修复链接 | 改用实际离线运行与证据索引，保持独立拓扑及脱敏验收。 |
| `docs/pr4/PR4_METRICS_ALERTS.md` | 保留 | 分层状态、有限标签、Gauge、TTL 与 UNKNOWN 告警合同。 |
| `docs/pr4/PR4_REVIEW_CHECKLIST.md` | 删除重复阶段清单 | 共性审查保留在 [SPEC](../SPEC.md#10-审查与交付)，[监控技术手册](../pr4/PR4_DEV_MANUAL.md)、[指标合同](../pr4/PR4_METRICS_ALERTS.md)和[验收矩阵](../pr4/PR4_ACCEPTANCE.md)保留所有权、探针、桥、脱敏和故障隔离门槛。 |
| `docs/pr4/README_START.md` | 删除开发包入口 | PR #4 首提交与固定基线保留原解包和施工入口；现用导航在 [README](../../README.md) 和 [运行手册](../pr4/OPERATIONS.md)。 |
| `docs/pr5/PR5_ACCEPTANCE.md` | 保留 | 62 个 C/H/B/F/L 编号及原矩阵表形；为 L10 指定持久证据源。 |
| `docs/pr5/PR5_DEV_MANUAL.md` | 保留技术章节 | 保留参数、固件能力、真实中转、独立 Track、状态机、配置安全和完整验证条件；施工顺序在原 PR。 |
| `docs/pr5/PR5_EVIDENCE.md` | 保留 | 隔离模拟范围、原始 FAIL/STOP、修正与重跑。 |
| `docs/pr5/PR5_FAILOVER_RUNBOOK.md` | 保留 | 切换准入、操作责任、回切与撤销。 |
| `docs/pr5/PR5_REVIEW_CHECKLIST.md` | 删除重复阶段清单 | [SPEC](../SPEC.md#10-审查与交付)、[验收矩阵](../pr5/PR5_ACCEPTANCE.md)、[厂商核验](../pr5/PR5_VENDOR_MATRIX.md)、[回切手册](../pr5/PR5_FAILOVER_RUNBOOK.md)保留独立路径证据、手工准入、无真实设备授权时 SKIP 等条款。 |
| `docs/pr5/PR5_SITE_ACCEPTANCE_TEMPLATE.md` | 保留 | 现场身份、权限、业务、隔离、回滚和签收证据模板。 |
| `docs/pr5/PR5_VENDOR_MATRIX.md` | 保留 | 精确设备版本、HA/VR、TS、双端 Track、中转与签收。 |
| `docs/pr5/README_START.md` | 删除开发包入口 | PR #5 首提交及固定基线保留原文；现用入口为 [README](../../README.md) 和各自技术文档。 |

关键验收证据、历史失败和重跑均在[归档索引](README.md)核对。
