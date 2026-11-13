# 可选监控的隔离运行手册

监控默认关闭。旧 V2 profile 可继续使用。在已获授权的 Ubuntu 24.04 QEMU 实验 Hub 中，用现有事务流程启用活动 profile 的监控设置。可以先离线验证。

```yaml
monitoring:
  enabled: true
  exporter:
    bind: 127.0.0.1
    port: 9814
    interval_seconds: 15
    timeout_seconds: 5
    ttl_seconds: 30
  udp_path:
    enabled: false
```

```sh
ipsecvpn monitor validate -c event.yaml
sudo ipsecvpn monitor snapshot --json
sudo ipsecvpn monitor serve --dry-run
sudo ipsecvpn monitor serve --confirm
curl --fail http://127.0.0.1:9814/metrics
sudo ipsecvpn monitor stop --dry-run
sudo ipsecvpn monitor stop --confirm
```

监控服务使用独立的 systemd 单元。采集子进程有总时限，采集失败立即撤下旧健康值。回环 scrape 可交给同机 Prometheus，隔离管理端也可经已授权的 SSH 转发读取。发生异常时查看监控单元的 journal，先停监控，再使用原有 `status`、`doctor` 和 [活动隧道手册](../pr3/LIVE_OPERATIONS.md)核对 VPN。S05 的 DPD 恢复仍需要显式 `initiate`，无人值守自动重连为 SKIP。

## 业务与告警

`udp_path.enabled` 只启用验证已有 UDP 证明。三节点脚本在独立 LAN 端启动有界的签名 echo helper，比较两个主 Hub XFRM 上的报文摘要和 SA 代际，再写入仅 root 可写的监控路径记录。缺少该证明、发生 rekey 或超过 TTL 时，业务状态为 UNKNOWN。当前 CHILD 指标是 Gauge，重协商会重置。

Prometheus 片段、告警规则及 Grafana JSON 位于 `monitoring/`。导入面板时选择 Prometheus datasource UID。灰色和无数据表示 UNKNOWN。启用告警前先运行 `promtool check rules`、`promtool test rules` 和 `amtool check-config`。

告警桥需要独立显式启用。实验将 `/etc/ipsecvpn/monitor-bridge.json` 设为 root-only 0600 文件，使用 `enabled: true`、`port: 9815`、`mock_endpoint: http://127.0.0.1:9816/mock` 的等价 JSON。在受保护的 secrets 目录生成独立的 `monitor-signing` 与 `monitor-bearer` 文件，再用 `monitor serve --with-bridge --confirm` 启用。外发限定本机 mock。恢复要求已记录的 firing 和当前有效的正常指标。

停用命令撤销项目监控单元和缓存。测试配置和密钥由操作者从实验目录删除。现场设备、真实公网、外部备用路径、真实飞书发送与生产部署为 SKIP。
