# V2.0 能力与验收索引

| 交付 | 实际验证 | 保留的边界 |
| --- | --- | --- |
| [只读配置与交接](https://github.com/yikkrrtykj/event-ipsec-hub/pull/1) | 一台 Hub、两个可配置站点、IPv4 多 CIDR、可选备网关。离线校验、授权方向、厂商中立和山石交接及 PSK 脱敏。 | V2.0 配置保持单活动 profile。 |
| [隔离 Hub 安装与事务](https://github.com/yikkrrtykj/event-ipsec-hub/pull/2) | [Ubuntu 24.04 QEMU 验收](pr2/PR2_ACCEPTANCE.md)，覆盖精确路由、XFRM、独立 nft 表、重启、失败闭锁、事务和卸载重装。 | 生产部署 SKIP。 |
| [IKE/CHILD 与业务数据面](https://github.com/yikkrrtykj/event-ipsec-hub/pull/3) | [三节点验收](pr3/PR3_ACCEPTANCE.md)，覆盖双向 UDP/TCP、源 IP、MTU/PMTUD、rekey、活动 SA 所有权及非授权流量拒绝。 | DPD 恢复已验证显式 initiate，无人值守重连 SKIP。 |
| [可选监控与告警](https://github.com/yikkrrtykj/event-ipsec-hub/pull/4) | [隔离监控验收](pr4/PR4_ACCEPTANCE.md)，覆盖回环 Exporter、主路径双向探针、UNKNOWN/TTL、Alertmanager 和飞书 mock。 | 真实飞书、外部失联和持续备线验证待验收。 |
| [设备交接与备路径模拟](https://github.com/yikkrrtykj/event-ipsec-hub/pull/5) | [交接与模拟验收](pr5/PR5_ACCEPTANCE.md)，覆盖备中转准入、双端 FIB、单侧不对称、双断、回切和签收模板。 | 实际厂商设备、外部中转、自动切换和真实赛事 SKIP。 |

[长期证据归档](evidence/README.md)保留原执行环境、失败、重跑和各项验收边界。
V3.0 需求、依赖和关闭条件在 [Epic #6](https://github.com/yikkrrtykj/event-ipsec-hub/issues/6) 跟踪。
并行赛事、重叠网段 NAT、其他品牌与协议仍按 [V2.0 规范](SPEC.md)的扩展范围单独确认。
