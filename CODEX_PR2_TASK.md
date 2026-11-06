# 交给 Codex 的 PR #2 开发指令

仓库：`https://github.com/yikkrrtykj/ipsecVPN`

**先核对基线**：`main` HEAD 必须是 `5f6ac250043c37d97cc375dae2250c89257b7ca2`，否则停止并报告差异；不要从旧开发分支沿用未审核提交。然后从该提交新建分支 `codex/pr2-deployment-transaction`，创建独立 **Draft PR #2**。不要自动 merge、不要操作任何生产 VPS/山石/腾讯云。

## 0. 规范与范围

请先完整阅读：

1. 仓库既有 `docs/SPEC.md`（V2.0，最高优先级）、`docs/roadmap.md`、`docs/architecture.md`、PR #1 已合并的 `ipsecvpn/profile.py`、`handoff.py`、`cli.py` 和 schema。
2. **本任务随附的** `docs/pr2/PR2_DEV_MANUAL.md` 和 `docs/pr2/PR2_ACCEPTANCE.md`，将它们作为 PR #2 的技术合同、验收矩阵纳入新分支。若两份文件尚未复制到工作目录，先请求文件/检查内容，禁止凭记忆自行补造或跳过其要求。

**产品定位**：通用赛事 Site-to-Site IPsec Hub，不能写死 PUBG、上海、伊斯坦布尔、V.PS、腾讯云。第一版只有一个 Linux Hub、两个任意站点、每站多 IPv4 CIDR、可选外部备用网关。

本阶段只做 **Ubuntu 24.04 + strongSwan / swanctl + VICI 的安装、渲染、XFRM、精确内外层路由、项目专用防火墙规则、事务应用/回滚/卸载、隔离 VM 测试**。PR #3 才做真实双站 IKE/CHILD SA 与双向 UDP/TCP/MTU；PR #4 才做监控飞书；PR #5 才做设备与主备现场验收。

## 1. 实现顺序（不得跳过安全阶段）

1. 先实现纯函数 `DeploymentManifest`、`render` 与可证明的配置差异计算；共享 PR #1 的 authorized CIDR 和 TS 推导，不另写一份规则。
2. 做只读 preflight：系统版本、服务冲突、已有 VPN、接口 if_id、路由、netfilter、sysctl、root 权限、密钥文件安全、WAN 管理链路和默认路由。
3. 实现项目对象所有权、文件/路由/nft/systemd 状态快照、串行锁、durable journal、失败后恢复和幂等更新。
4. 实现 `install --dry-run/--confirm`、`apply --dry-run/--confirm`、`backup`、`rollback`、`uninstall`；每个有副作用步骤都应可以失败注入和撤销。
5. 在专用 Ubuntu 24.04 隔离 VM 实测载入 2 个连接、创建 2 个 XFRM 接口、精确路由、双向 ACL、fail closed、重复 apply、更新、崩溃恢复、重启、回滚和卸载。
6. 完成全部离线/VM 测试、中文安装/回滚/ownership 文档与 Draft PR 报告后停止。

## 2. 不得违反的底线

- `render`、`plan`、`validate`、`check` 必须保持只读（`render` 的明确受限输出目录除外，且不得改变系统）。
- 使用 Ubuntu 发行版 `charon-systemd`、`strongswan-swanctl` / VICI；不得和 starter/已有 charon 服务并行冲突，也不得覆盖其它 swanctl 连接。
- XFRM `if_id_in`、`if_id_out` 必须与每条 site_link `if_id` 一致；站点 A/B 分离。只允许授权 CIDR，不自动使用 `0.0.0.0/0`。
- 隧道 SA、XFRM 接口消失时，远端私网流量不得顺着默认 WAN 路由明文泄漏；必须有经过隔离验证的精确 fail-closed 机制。
- 不改默认公网路由、主网卡、Netplan、SSH、UFW/iptables 全局配置；严禁 `nft flush ruleset`；对现有状态无法安全隔离时 `STOP`。
- 只操作本项目登记的对象。备份回滚须有 fsync/原子替换、持久化 journal、崩溃识别、反向依赖恢复、实测基线守恒。
- 每个站点独立强随机 PSK；绝不打印 PSK、Webhook、私钥，不放入参数导出或 Git；不得将 `file:` 引用直接当作 strongSwan 明文 secret；拒绝 symlink 和权限不当文件。
- `outer_path.interface: auto` 是离线占位，真实 apply 必须 STOP；不自动猜测公网网卡。
- 外部备用网关可以不开启。开启但参数不完整，主 Hub 的部署计划可以保留，但必须明确 `SKIP/INCOMPLETE`，不能谎称备用就绪；更不允许自动改动山石或腾讯云。
- 不得把 mock tests 的通过冒充真实 VM/协议/业务测试。

## 3. CLI 和文档

新增/完成 `render`, `install`, `apply`, `backup`, `rollback`, `uninstall`，保留 PR #1 的所有 CLI 和退出码约定；所有写入均要求 explicit `--confirm`，支持安全 `--dry-run`。实现 `docs/install.md`、`docs/rollback.md`、`docs/network-ownership.md`、`docs/security.md` 和验收证据文件；顺便更新 `README.md` 里已过时的“PR #1 仍为 Draft”描述。`install.sh` 若存在，只做很短的包装调用。

## 4. 验收并停止

逐项执行 `docs/pr2/PR2_ACCEPTANCE.md` 的 C/V/F 用例；不能运行的列 `SKIP`，任何失败列 `FAIL`，不允许恒真 verdict。保留 PR #1 的所有测试和仓库外 wheel smoke test；CI 为 pytest、Ruff、ShellCheck、Schema、Gitleaks。不要强行在普通 GitHub runner 上做有副作用 root 网络修改；使用独立专用 VM 并提供真实证据。

最终输出：

- Draft PR URL；base/main HEAD、merge-base、head SHA；修改文件；CI run/job 链接。
- 全部 PASS/FAIL/SKIP/STOP 及实测证据；Ubuntu/内核/strongSwan 版本。
- apply 前后 SSH/默认路由/非项目 nft 和路由的差异；注入失败、重启、回滚、fail-closed 的证据。
- 所有仍未解决的风险与后续 PR #3 的验收范围。
- 明确声明 **未部署生产环境、未合并 main**。

只在此 PR 范围内工作，完成后停止，等待人工审查。
