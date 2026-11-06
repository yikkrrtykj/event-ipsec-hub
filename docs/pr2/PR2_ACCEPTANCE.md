# ipsecVPN · PR #2 验收矩阵与证据模板

> 基线：`5f6ac250043c37d97cc375dae2250c89257b7ca2`。本文件与 `PR2_DEV_MANUAL.md` 同时作为 Codex 交付门槛。

## 1. 证据与 verdict 规则

- `PASS`：确实执行了该测试，并且观测值、日志和前后对比满足预期；写明测试环境。
- `FAIL`：已执行而结果不满足预期，或者发生未能自动安全恢复的修改。
- `SKIP`：无测试环境、需现场、超出 PR #2 作用域。绝不能将模拟返回值当作真实网络验收。
- `STOP`：存在破坏 SSH/公网路由/其他 VPN/密钥或安全策略的风险，禁止 apply。

**每条证据至少包含**：用例 ID、日期时间、Ubuntu/内核/strongSwan/nft 版本、隔离 VM 标识、命令（必须脱敏）、预期、实际、是否触及系统、结果、证据文件相对路径。公网使用 RFC5737 示例，不存事件真实公网、PSK、Webhook、用户账号。

## 2. CI 与只读回归（不需要 root）

| ID | 测试 | 判定 |
| --- | --- | --- |
| C01 | PR #1 全部 62 项回归及新 pytest | PASS / FAIL |
| C02 | Ruff、ShellCheck、schema、Gitleaks，且输出不含 PSK/secret 文件名 | PASS / FAIL |
| C03 | 在仓库外安装构建好的 wheel，运行 validate、plan、export-peer、render | PASS / FAIL |
| C04 | 3 个通用 fixtures：任意 ID、国别、厂商、IP、多 CIDR 生成两条正确连接和反向 ACL | PASS / FAIL |
| C05 | `render` 同一 profile 重复输出 byte-for-byte 一致（密钥不显示） | PASS / FAIL |
| C06 | 禁止 `0.0.0.0/0` 和重复/重叠 CIDR、XFRM if_id、冲突 Peer | PASS / FAIL |
| C07 | 禁止把 `outer_path.interface: auto` 当作可 apply 的真实出口 | PASS / FAIL |
| C08 | backup disabled、backup complete、backup incomplete 均能正确生成**主 Hub**渲染与状态说明，外部备用绝不误报可用 | PASS / FAIL |
| C09 | 只读命令不写文件、不调用网络变更命令、不接触真实 PSK 内容 | PASS / FAIL |
| C10 | 未安装 root 系统依赖时写命令必须 FAIL/STOP，不能出现伪 PASS | PASS / FAIL |

## 3. Ubuntu 24.04 隔离 VM：强制集成验证

> 使用独立、允许销毁的 VM（建议与 CI runner 分开）；无真实赛事和客户 IP，无云厂商生产安全组。应提供 VM 创建/销毁步骤和 VM 的执行记录。namespace 测试可补充，但不得代替真实 systemd/apt/重启验证。

| ID | 场景 | 预期 |
| --- | --- | --- |
| V01 | 初始 host preflight：发行版、内核、XFRM、ip/nft、systemd、VICI 检测 | 版本和特性有证据；不符合 STOP |
| V02 | `install --dry-run` | 系统状态及资源零变化 |
| V03 | `install --confirm`（干净 VM） | 仅所需包和工具拥有资源变更；版本清晰 |
| V04 | 装载两条 `swanctl` connection/CHILD 配置，离线 `swanctl --list-conns` | daemon 可解析；没有实际对公网发起 IKE |
| V05 | 新建两个 XFRM 接口，每个 if_id 唯一且正确匹配配置 | 两接口存在且标识正确 |
| V06 | 对每个授权远端 LAN 加精确 XFRM 路由 | 对应 `ip route get` 指向预期接口，不改变默认路由 |
| V07 | 两方向 FORWARD ACL + 无 SNAT；其它原有转发不受影响 | 双向授权规则存在，未授权流量规则严格拒绝 |
| V08 | `apply --dry-run` | 只有 diff，无任何系统写入 |
| V09 | `apply --confirm`（干净 VM） | 全部项目对象正确，journal COMMITTED |
| V10 | 同配置再次 apply | NOOP，状态/哈希/条目数量不变 |
| V11 | 不同配置安全更新（仅 CIDR、Peer、if_id 可控差异） | 仅项目对象变动，新旧无残留，快照可恢复 |
| V12 | rollback 到某指定备份 | 恢复本次改变的所有项目对象，且其它资源与基线一致 |
| V13 | 模拟 `nft`/`ip`/`swanctl` 失败 | journal FAILED→RESTORED，或真实 STOP_FOR_MANUAL，不能假 PASS |
| V14 | apply 过程中模拟崩溃/kill/重启 | 下次启动识别未完成事务，先进入安全恢复路径，不盲目继续 |
| V15 | 禁止同时两个 apply/rollback | 第二个获得明确 LOCKED/STOP，不出现互相覆盖 |
| V16 | `uninstall --confirm` | 精确删自己对象，未删除系统共享 strongSwan、SSH 或其它规则 |
| V17 | 重启 VM（成功 apply 后） | 自动恢复必要 XFRM/路由/ACL，或明确处于安全阻断并可恢复状态 |
| V18 | 备份损坏/缺失 | 禁止破坏性 rollback，输出明确 FAIL/STOP |
| V19 | stdout、journal、审计文件、错误日志扫描 | 无 PSK、Webhook 或秘密原值 |
| V20 | project 加载前后对比默认路由、SSH、主 IP、现有 nft table、其它服务 | 非项目状态无未授权变化 |

**V04 限定**：可以使用 RFC5737 虚构 IP 的离线加载配置，但不能真的向这些地址发包。实际 IKE/CHILD 协商由 PR #3 使用隔离双 peer 完成。

## 4. 故障/安全注入（负面测试必须执行）

| ID | 注入条件 | 预期 |
| --- | --- | --- |
| F01 | 已有另一 strongSwan/starter 或占用 UDP 500/4500 | 不夺占端口、不杀服务，STOP |
| F02 | 已有同名 XFRM / 相同 if_id | STOP，旧接口不变 |
| F03 | 授权 CIDR 在路由表中已有冲突路由 | STOP，旧路由不变 |
| F04 | WAN/Peer `/32` 出口错误或依赖已修改对象 | STOP，不修改默认路由 |
| F05 | 现有 UFW/iptables/nft base chains 会 DROP 授权 FORWARD | 不假报可用；STOP 或经隔离验证的兼容方案 |
| F06 | 试图通过 profile 修改 SSH、netplan、默认路由或全局 nft | 无代码路径，拒绝 |
| F07 | PSK 不存在、不是 0600、非 root 持有、文件为 symlink/hardlink、路径逃逸 | STOP，不读取/泄露、不部署 |
| F08 | /etc 中已有非项目拥有的 swanctl 配置 | 不覆盖，若无法安全 include STOP |
| F09 | 无 root、Ubuntu 版本不符、缺失功能 | STOP 且系统不变 |
| F10 | SA 失效、删除项目 XFRM，或 systemd 服务停止 | 原本须加密的站点私网流量不得从默认公网 WAN 漏发（**用真实包观察/路由查找证明**） |
| F11 | 删除任何资源前操作因权限错误失败 | 不遗留部分清除造成的公网泄漏；安全恢复/STOP |
| F12 | 路由表出现更具体前缀或已有 `ip rule` | 校验 fail-closed 真有效；不成立 STOP |
| F13 | 注入非法符号到站点名/出口/配置字段 | 绝无命令注入、路径穿越或不可信模板语法逃逸 |
| F14 | backup.enabled=true 但备用信息不完整 | 主 Hub 资源可以明确验证，外部备用为 SKIP，不发虚假的备用就绪结果 |

## 5. 技术行为单独验证

1. 核对 `if_id_in/if_id_out` 与 `ip -d link show type xfrm` 精确一致；每条接口和对应 CHILD 不冲突。
2. `swanctl --list-conns` 与生成 manifest 内容一致；密钥只从 root-only secret 路径注入；无真实 secrets 印在记录中。
3. 路由只包含每个站点 **authorized** 子网，不应因声明了未授权 VLAN 而顺带开放。
4. 有可证明的 fail-closed 行为，避免无 XFRM/SA 时经默认 WAN 发送明文私网流量。
5. `nft` 多 base chain 的过滤语义被证明；单独 table 的 `accept` 不等于覆盖其他 chain 的 `drop`。
6. `ip_forward/rp_filter` 的实际改动有 ownership、审计和回滚，绝不全局无差别调整。
7. 检测 WAN 的 Peer `/32` 路由独立于私网路由；没有隧道递归。
8. 服务重启或整个 VM reboot 后，既有管理连接与默认路由仍可到达。

## 6. 不应被判定 PASS 的项目（继续 SKIP）

- 上海/海外**真实**山石 IKEv2 Phase 1/Phase 2 协商及双端 WAN 线路。
- 真正跨两个 IPsec SA 的 UDP/TCP 双向吞吐和源地址保持。
- 重协商、生产级 DPD 时间、真实 MTU/PMTUD/分片及比赛网络性能。
- 腾讯云备用网关/主备 Track、跨区域故障/路由收敛。
- Prometheus/Grafana、Feishu 实时告警，以及任何业务质量 SLA。

这些是 PR #3–#5 的明确范围。**不能用合成样例中 `PASS` 的字段代替网络实测。**

## 7. Codex 最终报告格式

```text
PR #2: <URL>  (Draft)
base: 5f6ac250043c37d97cc375dae2250c89257b7ca2
merge-base: <sha>
head: <sha>

PASS: Cxx / Vxx / Fxx (说明、证据路径)
FAIL: ... / none
SKIP: ... （理由与下一阶段）
STOP: ... / none

OS/kernel/strongSwan version:
Files changed:
CI jobs:
VM integration evidence:
Baseline route/SSH/firewall diff:
Crash rollback evidence:
Security scan:
Open risks:
Explicitly NOT deployed to production.
```
