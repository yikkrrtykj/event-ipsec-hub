# 网络资源所有权

| 对象 | 管理边界 |
| --- | --- |
| strongSwan | 使用 Ubuntu 的 `charon-systemd` 服务及发行版 VICI socket。项目私有配置和一个专用 systemd drop-in 将 daemon 限制在独占运行边界。 |
| XFRM | 接口名从 `if_id` 派生，另带安装标记。创建、验证和删除均核对名称、类型、ID 与所有权。 |
| IPv4 内层路由 | 每个授权 LAN 有一条精确 XFRM 路由和同前缀、更高 metric 的 blackhole。路由以协议编号 242 及完整属性登记。 |
| IPv4 外层路由 | 读取实际内核 Peer 查找结果，校验接口、源地址和可选下一跳。保留原有 WAN 路径。 |
| nftables | 仅管理 `table ip ipsecvpn`。事务期间先原子加载闭锁规则，再更新内层对象，最后安装正式规则。正式规则仅允许两条 XFRM 之间的双向授权网段组合。IKE 采用 UDP 封装，按接口、源、目的和端口匹配。 |
| 启动恢复 | 早期 guard 建立保护前缀的阻断。WAN 上线后 restore 单元核对运行边界，再恢复已提交的部署。发现未完成事务时保留阻断并等待显式恢复。 |

IPv4 转发是 VM 的前置条件。Linux 在切换全局 `ip_forward` 时可能重置其它 IPv4 参数，因此本工具读取并记录其状态，由实验环境管理员预先设置。严格反向路径过滤需要单独评估。 [Linux IP sysctl 文档](https://docs.kernel.org/networking/ip-sysctl.html)

现有 IPv4 策略规则、重叠路由、同名接口、同 ID 的 XFRM、不可验证的外层路径或可能干预的其他防火墙链会触发 `STOP`。独立 nftables base chain 的 ACCEPT 无法覆盖其他链的 DROP，因此支持范围以可证明的现有策略为限。应用前后比较默认路由、非项目路由、地址、接口、SSH 单元、sysctl 和非项目规则摘要。

SA 不存在时 XFRM 内核路径会丢弃无法加密的流量。接口丢失时，由同前缀 blackhole 和 nftables egress 保护阻断回退到默认 WAN。精确内核查找和重启验收以独立 VM 记录为准。 [strongSwan 5.9 XFRM 文档](https://docs.strongswan.org/docs/5.9/features/routeBasedVpn.html)
