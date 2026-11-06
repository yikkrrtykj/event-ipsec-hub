# 备份、故障恢复与卸载

```bash
sudo ipsecvpn backup --dry-run
sudo ipsecvpn backup --confirm
sudo ipsecvpn rollback --to "$backup_id" --dry-run
sudo ipsecvpn rollback --to "$backup_id" --confirm
sudo ipsecvpn uninstall --dry-run
sudo ipsecvpn uninstall --confirm
```

应用和回滚前均为旧活动状态建立快照。备份 ID 对应 `/var/lib/ipsecvpn/backups/` 下有摘要保护的记录，依赖原有 PSK 引用及其摘要。密钥轮换时，旧密钥应保存在原有受控路径，直到该快照退出保留周期。

操作先获取系统锁，再执行预检、快照和持久事务。失败时恢复本次拥有的资源，并核对非项目状态。若下一次启动发现未完成 journal，工具会返回 `STOP` 并提示恢复 ID。

1. 保留带外管理连接。检查 `/var/lib/ipsecvpn/journal.json` 的 `phase`、`action` 和 `steps`。检查 `ip -4 rule`、`ip -4 route`、`ip -d link show type xfrm` 与项目 nftables 表，先保留已有保护。
2. 确认故障原因已排除，按日志提示先运行 `rollback --to <id> --dry-run`，再在隔离 VM 内显式确认恢复。
3. 若出现 `STOP_FOR_MANUAL`，保留 journal 和快照。根据所有权标记核查接口、规则、服务文件和密钥引用。先恢复项目的闭锁保护和一致的系统状态，再尝试恢复。安装故障按下方的包状态步骤处理。
4. 复查恢复后的 SSH、默认路由、现有规则和 VICI 连接。卸载会移除登记的网络和启动资源，并保留 Ubuntu 发行版安装的软件包与审计记录。

历史状态包含内部网段、对端配置和密钥引用，应留在 VM 的 root 专用存储。公开证据只保留脱敏操作记录和摘要。

## 安装故障与 dpkg 状态

`install` 在运行 APT 前记录全量包版本和 dpkg 状态。即使项目服务、SSH、默认路由和既有防火墙已验证恢复，包状态不同或审计未通过时仍返回 `STOP_FOR_MANUAL`。工具保留包，阻止新安装，等待当前事务解决。

1. 在隔离 VM 保留带外访问和原始 journal。查看事务 ID、`install.before_package_state`、`install_failure_packages`、`package_recovery` 和 `steps`。使用 `sudo dpkg --audit`，并用 `dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n'` 对照安装前记录，包含 `iU`、`iF` 和残留配置等状态。
2. 若能证明只有本次新装的包变化，先模拟移除审计中逐一确认的新包。核对模拟未移除或修改原有包、依赖和其他服务后，再由管理员用确认后的精确清单恢复。仅执行 `dpkg --configure -a` 可能把部分安装变成完整安装，仍与原清单不同。涉及原有包、来源不明或缺少安装前证据时，使用已知的 VM 快照或重建隔离 VM。
3. 清理完成后，使用同一事务 ID 执行 `rollback --to <id> --confirm`。只有全量包状态与安装前一致、`dpkg --audit` 干净且保护基线匹配，才记录 `RESTORED`。成功后可重新安装。首次失败的包差异仍保留在 `install_failure_packages`。
