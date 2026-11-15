# PR #5 验收证据索引

[Draft PR #5](https://github.com/yikkrrtykj/event-ipsec-hub/pull/5) 的基线为
`6aacc03514ee98bea91e26bbba46a72451211715`。人工审查以 PR 描述中的最终 HEAD、
该 HEAD 触发的工作流链接及未过期 Artifact 为准。索引只描述如何找到证据。

| 环境 | 验收范围 | 原始脱敏证据 |
| --- | --- | --- |
| Offline validation | C01–C14、H01–H12、B01–B05、F01–F11、L01–L10 | `ipsecvpn-pr5-offline-evidence` 内逐项 JSONL |
| PR #2 isolated VM | 原安装、幂等、事务、回滚和主机基线 | VM 工作流 JSONL 与日志 |
| PR #3 isolated lab | 真实 IKEv2、CHILD、XFRM、跨站 UDP/TCP 和活动 SA 保护 | 三节点工作流 JSONL 与日志 |
| PR #4 isolated monitoring | VICI/XFRM、独立 UDP 探针、告警 mock、重启与主机基线 | 监控工作流 JSONL 与日志 |
| PR5 isolated failover simulation | B06–B14、F12 | `ipsecvpn-pr5-simulation` 内逐项 JSONL |

## 模拟边界

PR #5 在同一台可销毁的 Ubuntu 24.04 QEMU 客体内运行两站、主/备用中转和 WAN
观测网络命名空间。验证依据为各源网段的实际 FIB 查询、分路径流量计数、UDP/TCP 收发
和原始源 IP、WAN 对照包及防泄漏计数，以及根命名空间的 SSH、默认路由、现有
nftables 和其他基线。受控回切的示例计时为收齐全部回执的耗时。B08、B09 的
测试预期是安全状态 `STOP`，JSONL 将断言结果与观测状态分别记录。

## 现场 SKIP 与准入 STOP

- B14 真实厂商自动 Track 切换与回切、Hillstone 及其他防火墙的精确型号和固件兼容性、实际外部备网关的双向中转、真实飞书和赛事业务均为 `SKIP`。
- 未获独立证据或确认不支持备中转时，切换准入为 `STOP`。两条 SA 在线仍须证明每对授权网段的双向业务。
- 生产无人值守 DPD 自动重连仍为 `SKIP`。PR #3 已验证显式 `initiate` 的隔离恢复。

## 开发中的失败记录

- 首次本地实现检查发现原交接回归要求 `backup.links` 保持原结构，结果为 105 PASS、1 FAIL。已保留原字段，新增派生数据放在 `backup.handoff`。同一轮 Ruff 发现一处未用导入和一处超长行，均已修正。
- 首次扩展测试为 161 PASS、2 FAIL。更名测试漏改监控探针引用，通配测试提前触发成对字段约束。已修正两个测试输入，使其覆盖指定场景。Windows 本机 ShellCheck 可执行文件启动时返回 DLL 重定位错误，使用 Linux CI 验证相同脚本。
- 后续失败与修复使用 PR 下对应提交的 Actions 日志和 Artifact 留档，最终结果见 PR 描述。
