# 隔离 Ubuntu VM 安装与应用

PR #2 的写操作以专用、可销毁的 Ubuntu 24.04 VM 为验证范围。先确认带外控制台可用，VM 只有实验网和独立的 SSH 管理入口。离线 apt 仓库和 wheelhouse 由隔离实验脚本准备。运行记录和未执行项见 [验收矩阵](pr2/PR2_ACCEPTANCE.md)。

1. 在 VM 安装 `iproute2`、`nftables`、Python venv 等环境依赖并准备 Ubuntu 发行版的 apt 软件包索引。预检要求专用 strongSwan 运行边界，如已有 IKE 监听、starter 或其他 strongSwan 配置则停止。
2. 在 root 拥有的目录中建立 venv 并安装构建好的 wheel，例如 `/opt/ipsecvpn/venv`。启动单元使用该安装的 Python 路径，部署期间需保留它。
3. 按 [安全说明](security.md) 在 root 专用目录内准备实验授权标记、虚构 profile 和两个独立 PSK。按 [网络所有权](network-ownership.md) 核对 VM 预先配置的转发和 WAN 路径。
4. 先执行 `render` 和 `install --dry-run`。核对将新增的软件包与版本后，再在 VM 内运行 `install --confirm`。
5. 比较 `apply --dry-run` 输出中的增删改与计划。准备可验证的 SSH 会话和带外管理后，在 VM 内运行 `apply --confirm`。记录输出的备份 ID，并用 `swanctl --list-conns --uri unix:///run/charon.vici`、`ip -d link show type xfrm`、`ip -4 route show` 和 `nft list table ip ipsecvpn` 核对本机资源。

```bash
vpn=/opt/ipsecvpn/venv/bin/ipsecvpn
profile=/etc/ipsecvpn/profiles/lab.yaml
sudo "$vpn" render -c "$profile" --json
sudo "$vpn" install --dry-run
sudo "$vpn" install --confirm
sudo "$vpn" apply -c "$profile" --dry-run
sudo "$vpn" apply -c "$profile" --confirm
```

每条外层链路必须指定真实 WAN 接口。若 Hub 公网地址由上游 NAT 提供，请显式填写绑定在该 WAN 上的本地 `outer_path.source_ip`。声明了 `gateway` 时，内核对端路径必须使用同一下一跳。

应用同一 profile 前会核对运行资源与凭据摘要，完整一致时返回 `NOOP`。同一赛事可以在核对变更后更新，切换赛事须先清理现有活动 profile。外部备网关只报告交接状态。双端协商、跨隧道业务、MTU 和现场设备验收为 `SKIP`。

卸载后的 `install --dry-run` 会验证已提交的卸载记录、保留包的版本和状态、发行版文件及已停用的服务。核验通过时，`install --confirm` 用新的安装标记启用服务，无需重新运行 APT。发现额外配置、运行中的外部 daemon、包版本变化或无法核实来源时返回 STOP。

实验 VM 的创建、隔离和销毁由 `scripts/pr2-vm/run.sh` 驱动。它启动独立 QEMU 客户机，限制客户机向外访问，仅将 SSH 转发到 runner 的本地回环地址。Ubuntu 包和 wheel 经本地通道传入 VM，所有部署网络命令均在客户机执行。
