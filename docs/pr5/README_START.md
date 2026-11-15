# event-ipsec-hub · PR #5 开发包

基线：`6aacc03514ee98bea91e26bbba46a72451211715`。

这是开发说明与验收合同，**不是已部署的 PR #5 代码**。仓库仍由维护者和 Codex 按 Draft PR 流程开发。

## 解压后如何使用

1. 交给 Codex 完整 ZIP 中的各个 `docs/pr5/*.md` 和 `CODEX_PR5_TASK.md`。相对路径与 Git 仓库一致。
2. 让 Codex 先读取 `CODEX_PR5_TASK.md` 和 `PR5_DEV_MANUAL.md`，首个提交把文档加入新分支。
3. 保持 PR Draft，持续检查离线+PR2/PR3/PR4 QEMU，等待人工代码 Review。
4. 真正 StoneOS/腾讯云互操作与现场 Track 自动切换仍需要用户另行授权和真实设备，**不得标为已通过**。

## 本包文件

- `docs/pr5/PR5_DEV_MANUAL.md`：总体开发合同与安全边界
- `docs/pr5/PR5_ACCEPTANCE.md`：62 项新验收与前序回归
- `docs/pr5/PR5_VENDOR_MATRIX.md`：设备型号/固件兼容性核对表
- `docs/pr5/PR5_FAILOVER_RUNBOOK.md`：主备路径及回切的操作与 STOP 门槛
- `docs/pr5/PR5_SITE_ACCEPTANCE_TEMPLATE.md`：现场模板（空白初始 SKIP）
- `docs/pr5/PR5_REVIEW_CHECKLIST.md`：人工 Review 清单
- `CODEX_PR5_TASK.md`：Codex 直接执行的任务单
- `README_START.md`：本文件
