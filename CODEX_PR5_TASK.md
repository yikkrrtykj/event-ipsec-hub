# Codex PR #5 开发任务

Repository: https://github.com/yikkrrtykj/event-ipsec-hub
Base / expected merge-base: `6aacc03514ee98bea91e26bbba46a72451211715`

1. 校验仓库 main、PR4 合并提交、两个父提交以及合并 CI；不得从更旧基线继续。不创建 PR #5 之外的多余 PR。
2. 建立分支 `codex/pr5-handoff-failover`（不覆盖已有分支）。**首提交**纳入 docs/pr5 的开发合同和操作模板；创建独立 Draft PR #5。
3. 读取 `docs/SPEC.md`、`docs/roadmap.md`、`ipsecvpn/profile.py`、`ipsecvpn/handoff.py`、`config/schema.json`、`docs/pr3/LIVE_OPERATIONS.md`、`docs/pr4/OPERATIONS.md`，以现有 V2.0 为数据合同。
4. 实现/完善山石和通用参数单，外部 backup 的 offline readiness、两端 ID/多 CIDR/路由/Track、精确证据模板、赛事完整交接/撤销步骤；代码小而明确，不得复制第二套 topology 计算。
5. 不确定的 Hillstone CLI/版本支持及 Tencent Cloud transitive routing 必须 `SKIP/STOP`，不要编造、不要调用供应商 API、不得放宽 root-only QEMU 网络写入门禁。
6. 新增 C01–C14、H01–H12、B01–B14、F01–F12、L01–L10 的离线/模板测试与必要的 QEMU route/failover **模拟**；真实厂商及云商测试保持 SKIP，并且明确模拟与现实的区别。
7. 重新执行：离线 CI（原 106 pytest+新增测试、Ruff、ShellCheck、schema、wheel、Gitleaks）、PR2 QEMU、PR3 三节点 QEMU、PR4 监控 QEMU，全部同一最终 HEAD。报告 `PASS/FAIL/SKIP/STOP`，保留失败历史和原始证据。
8. 更新 README、roadmap、事件生命周期和 PR5 证据汇总。仅提交公开安全的虚构示例，不要写入真实地址、PSK、Token、Webhook、序列号或客户名称。
9. PR 保持 Draft，等人工 Review；禁止 merge/rebase/squash/force-push、生产部署/实机路由修改、真实飞书与 PR6。

交付：Draft PR URL、完整 HEAD/base/merge-base、变更摘要、CI URL/Artifacts、独立 QEMU JSONL、具体 SKIP、阻塞说明。若测试环境不支持厂商实机验收，明确 SKIP；**不能以 mock 代替真实云端中转验收**。
