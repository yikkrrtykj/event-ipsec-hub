# Codex 开发任务：event-ipsec-hub PR #4

目标仓库：`https://github.com/yikkrrtykj/event-ipsec-hub`

**唯一 base / merge-base：`9fa763d40e0b81f7600f601e8b30c32f8d671233`**。

你是本项目开发工程师。先仔细读取 `docs/SPEC.md`、当前 `ipsecvpn/diagnostics.py`、`ipsecvpn/live.py`、`ipsecvpn/sa.py`、`ipsecvpn/host.py`、`ipsecvpn/transaction.py`、原 `scripts/pr3-lab` 和 PR #3 最终验收及其风险边界，然后读取本次开发包：

- `docs/pr4/PR4_DEV_MANUAL.md`（主要技术合同）
- `docs/pr4/PR4_METRICS_ALERTS.md`（指标语义）
- `docs/pr4/PR4_ACCEPTANCE.md`（新增/继承验收）
- `docs/pr4/PR4_LAB_TOPOLOGY.md`（隔离测试设计）
- `docs/pr4/PR4_REVIEW_CHECKLIST.md`（人工审查标准）

先在**独立 Draft PR #4 分支**提交这些开发合同。随后按下面顺序持续开发同一个 Draft PR，不做多个未经审查的巨大修改，也不推进 PR #5：

1. 明确原模型向后兼容、monitoring 默认关闭、一个活动 Hub+任意两站点、独立监控状态模型。新增单元测试与安全边界。
2. 复用 PR #3 已验证的 VICI/XFRM/host 只读联合证据，实现有界快照采集和监控专用 reason/TTL/UNKNOWN。不得调用部署/SA 变更操作。
3. 实现仅 localhost 绑定的 Prometheus exporter、严格的 métrics family + labels + gauge 语义、缓存新鲜度。提供可选 systemd 安装/停用及安全恢复，不改 strongSwan.service。
4. 用真实隔离 A/B LAN 测试主机实现可选 UDP echo 双方向验证、主 Hub 路径绑定、时效/丢包/单向故障判断；无真实 proof 一律 UNKNOWN。默认不要求现场部署任何测试 agent。
5. 提供 Grafana 可导入 Dashboard、Prometheus scrape/alert rules（经 `promtool` 验证），以及 Alertmanager→Feishu 安全桥（本机 mock、签名、去重/退避、重启、恢复）。所有启用可选。
6. 同步维护 `README.md` 的 PR #1–#3 阶段状态与仓库新名称（目前 README 仍提到 Draft PR #3），保留历史规格文件的审计价值；新增 PR #4 监控安装、停用、故障/人工运行手册。
7. 运行完整离线 CI + 既有 PR2 QEMU + 既有 PR3 三节点 QEMU + PR4 新的 exporter/probe/alert 故障场景。整理脱敏 JSONL、日志和简短 PASS/FAIL/SKIP/STOP。

**不得改变**：活动 SA 所有权、XFRM 黑洞、防明文泄漏、事务及显式 maintenance、root-only Lab 授权、默认路由、SSH、外部 nft/服务、DPD 当前需要显式 initiate 的事实。

**严格禁止**：任何生产部署、操作用户 Prometheus/Grafana/飞书群、外网公开监控端口、向真实飞书 Webhook 发送测试通知、自动操作山石/腾讯云/站点主备、自动修复/restart VPN、自动调整 MTU/MSS 或大范围改动系统配置。`monitoring.enabled=false` 应完全可用。

最终交付：

```
PR #4: <URL> (Draft)
Base/merge-base: 9fa763d40e0b81f7600f601e8b30c32f8d671233
Head: <SHA>
PASS: Cxx Mxx Pxx Axx Rxx ... [evidence]
FAIL: ...
SKIP: ...
STOP: ...
Runtime: Ubuntu/kernel/strongSwan/Prometheus/Grafana/bridge versions
Observability: daemon/SA/child/kernel/business separation + TTL evidence
Safety: localhost, secret scan, no production writes, no changes to existing Hub
CI/QEMU: workflow links and artifact IDs
```

PR 保持 Draft，不自动 merge。等待人工技术审查，不能以 CI 全绿取代审查。
