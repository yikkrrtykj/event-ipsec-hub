# PR #2 验收记录

基线及 merge-base 均为 `5f6ac250043c37d97cc375dae2250c89257b7ca2`。本记录逐项使用 [验收矩阵](PR2_ACCEPTANCE.md) 的定义。所有写入测试的目标均为独立 QEMU 客户机 `ipsecvpn-pr2-lab`。宿主 runner 只负责取得 Ubuntu 镜像、准备离线软件包和启动客户机，管理通道是回环地址上的 SSH 转发。

## 已完成的离线验证

| 用例 | 结果 | 证据 |
| --- | --- | --- |
| C01 | PASS | 73 项 pytest，包括 PR #1 的 62 项回归和 iproute2 数字类型测试。 |
| C02 | PASS | Ruff、ShellCheck、四份公开配置校验、Gitleaks，以及渲染输出脱敏断言。 |
| C03 | PASS | 仓库外创建独立 venv，安装构建的 wheel，并执行 validate、plan、export-peer 和 render。 |
| C04–C06 | PASS | 三个虚构赛事渲染、方向与选择器一致性、重复渲染和非法拓扑回归。 |
| C07–C10 | PASS | 离线占位 WAN 停止、外部备用与主 Hub 隔离、只读渲染及非目标平台写入停止。 |

离线证据对应提交 `217fa3aa43f38cd4291f0a9a8405f9c3d5467e7d`。 [GitHub 离线 CI](https://github.com/yikkrrtykj/ipsecVPN/actions/runs/42220411612)

## VM 执行记录

- 首轮启动了独立客户机，测试因客户机缺少预期默认路由停止。后续用 NoCloud 为客户机提供固定实验 WAN 和默认路由。 [首轮 VM 日志](https://github.com/yikkrrtykj/ipsecVPN/actions/runs/42212880283/job/127875583443)
- 第二轮在 Ubuntu 24.04、Linux `6.8.0-147-generic`、nftables `1.0.9` 上执行。V01 和 V02 为 PASS，确认了目标平台、XFRM/nft 探测及 dry-run 前后的包清单和基线摘要相同。F01 和 F08 为 PASS，UDP 500 被占用或已有 swanctl 配置时，程序正确停止并保留原对象。V03 的真实 `install --confirm` 退出 1，判为 FAIL。该轮 V04–V20、F02–F07 和 F09–F14 未执行。 [第二轮 VM 日志与 JSONL 分项证据](https://github.com/yikkrrtykj/ipsecVPN/actions/runs/42213926644)
- `55e1e07` 复测再次得到 V01、V02、F01 和 F08 PASS。V03 在 APT 和 daemon 启动后发现 IPv4 策略规则变化而返回 FAIL，停止 daemon 后基线验证通过，事务记录为 `RESTORED`。本轮 V04–V20 的正式用例及剩余 F 项尚未执行。 [失败与恢复的 VM 记录](https://github.com/yikkrrtykj/ipsecVPN/actions/runs/42215661430)
- 依据 strongSwan 5.9.13 内核插件代码，非零路由表配置会在 daemon 初始化时注册策略路由，即使禁用自动路由安装。修复将项目 daemon 的 `routing_table` 置零，保留策略路由守恒检查。 [strongSwan 5.9.13 内核插件](https://github.com/strongswan/strongswan/blob/5.9.13/src/libcharon/plugins/kernel_netlink/kernel_netlink_net.c)
- `ebad8ba` 实测 V01–V03 为 PASS，安装事务 `COMMITTED`，strongSwan 软件包为 `5.9.13-2ubuntu4.24.04.5`，默认路由、策略规则、SSH 和非项目防火墙摘要与安装前一致。F01–F04、F08 和 F12 也通过。该轮在 F05 的外部阻断规则测试夹具创建阶段失败，未执行 F05 断言或后续事务用例。日志末尾的额外 V03 FAIL 行来自错误归类，实际安装状态仍为 `COMMITTED`。已修正夹具语法和归类。 [安装成功与夹具失败日志](https://github.com/yikkrrtykj/ipsecVPN/actions/runs/42216693304)
- `2c371fc` 实测 V01–V03、V08、F01–F09、F12、F13 为 PASS。F05 此轮验证了独立 nftables 拒绝链，UFW 和 iptables 前端子场景仍待运行。V09 首次真实 apply 为 FAIL，事务发出 `STOP_FOR_MANUAL`，所以 V04–V07 和 V10–V20、F10、F11、F14 仍为 SKIP。 [分项日志](https://github.com/yikkrrtykj/ipsecVPN/actions/runs/42217436609)
- `d027a9c` 诊断复现了 V09。日志确认私有 nftables 保护已加载，三条精确 blackhole 路由命令成功。旧解析把 `ip -N` 返回的数字路由类型判为未登记，应用和恢复均按所有权门禁停止。后续修复同时接受内核数字类型和文字类型，继续严格匹配前缀、类型、设备、优先级、协议和路由表。 [VM 事务诊断](https://github.com/yikkrrtykj/ipsecVPN/actions/runs/42218721328) · [iproute2 路由类型代码](https://github.com/iproute2/iproute2/blob/v6.1.0/ip/rtm_map.c)
- `217fa3a` 与仅更新文档的 `95cc5bd` 均通过原有安装和 dry-run 检查，并越过黑洞路由所有权校验。两次 V09 均在创建两条 XFRM 后以 `STOP_FOR_MANUAL` 结束。Linux 6.8 的创建路径不应用接口 alias，修复改为创建后用独立的 `ip link set` 设置所有权标记并启用接口。 [首次复测](https://github.com/yikkrrtykj/ipsecVPN/actions/runs/42220411594) · [重复复测](https://github.com/yikkrrtykj/ipsecVPN/actions/runs/42222752430) · [Linux rtnetlink 创建与更新](https://github.com/torvalds/linux/blob/v6.8/net/core/rtnetlink.c)

真实双端 IKE/CHILD SA、UDP/TCP、MTU、现场防火墙和外部备用切换属于后续 PR，标记为 SKIP。PR 保持 Draft，所有部署操作限于实验客户机。
