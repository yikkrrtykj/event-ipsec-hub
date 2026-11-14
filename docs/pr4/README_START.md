# PR #4 开发包说明

仓库：`https://github.com/yikkrrtykj/event-ipsec-hub`
基线：`9fa763d40e0b81f7600f601e8b30c32f8d671233`

## 文件清单

- `CODEX_PR4_TASK.md`：给 Codex 的任务单
- `docs/pr4/PR4_DEV_MANUAL.md`：完整开发手册
- `docs/pr4/PR4_METRICS_ALERTS.md`：指标类型、PATH UNKNOWN、告警语义
- `docs/pr4/PR4_ACCEPTANCE.md`：新增 + 全量回归的逐项验收
- `docs/pr4/PR4_LAB_TOPOLOGY.md`：实验设计、抓包与脱敏证据
- `docs/pr4/PR4_REVIEW_CHECKLIST.md`：合并前人工审核表

## 用法

将这些文件放入 Codex 的项目工作区（不要直接写入 `main`），发送 `CODEX_PR4_TASK.md` 中的任务。要求 Codex 从上述基线建立 Draft PR #4，先提交规范，再按模块实际开发与 QEMU 验收。

现在这些只是**开发文档**，不是 PR #4 的代码或测试通过证据。GitHub 仓库、生产 VPS、Grafana、Prometheus、飞书未被本包修改。
