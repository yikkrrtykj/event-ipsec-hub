# PR #4 人工 Review Checklist

- [ ] base / merge-base 均为 `9fa763d40e0b81f7600f601e8b30c32f8d671233`；PR 保持 Draft、普通分支；不擅自修改 main。
- [ ] 规范文档作为首提交进入 PR；所有变更围绕一套 V2 事件/站点模型，无 `shanghai/istanbul`、供应商或赛事固定依赖。
- [ ] 不削弱 PR #3 的 daemon+VICI+SAD/SPD 联合所有权；缺证据时 UNKNOWN/STOP，采集器没有清除 SA 的权限或代码路径。
- [ ] collector 与 exporter `monitoring.enabled=false` 完全不触发网络请求/服务启动；缺配置时离线 CLI 合理返回 SKIP。
- [ ] `/metrics` 仅 127.0.0.1，严格拒绝公网/通配绑定，外部监控通过 tunnel/私有代理且不暴露秘密。
- [ ] status/doctor、exporter、Grafana、alert 统一使用可信快照；收集失败、TTL 过期、外来 SPD 时旧 PASS 不可冒充实时正常。
- [ ] IKE、CHILD、内核状态、路由/ACL、真实业务五层独立；只有独立 A→B/B→A UDP 且路径归属正确，才可 `business=UP`。
- [ ] 不以 Hub Ping、同一方向的 reply、IPsec 计数增长或者备路径成功冒充主业务链路成功。
- [ ] 探针默认关，测试 Agent 只能在可销毁网络内启动，限制速率、IP/端口、payload、nonce replay 与反射风险；生产 agent 部署不在 PR4 授权范围。
- [ ] SA byte/packet 指标类型正确：当前 CHILD gauge 在 rekey 可重置，不以 `_total`/Counter 或 Grafana `rate()` 假算历史连续流量。
- [ ] Grafana JSON、Prometheus alert rules 真正可解析；`promtool check/test rules` 实测；panel 缺数据呈 UNKNOWN，所有监控可选且不覆盖现有环境。
- [ ] Alertmanager 的 firing/resolved、去重/限频/重启、采集丢失、4xx/5xx/超时和飞书签名本地 mock 都有真实实验；无真实外部 POST。
- [ ] webhook、签名密钥、profile、PSK 不在日志、metrics、截图、alert message、代码及 artifacts；Gitleaks 和自定义脱敏回归通过。
- [ ] exporter/bridge 无 route/nft/xfrm/sysctl/daemon 变更 API；监控失败和卸载时 SSH、默认路由、既有防火墙、外来服务和两条 SA 不受影响。
- [ ] 不修改 `reconnect.json` 或声称无人值守自动重连；S05 仍要求显式 initiate，外部自动主备为 SKIP。
- [ ] PR #1/#2/#3 离线、38 项 PR2 QEMU、PR3 原测试（包含 I01–I03）全部复跑且证据 HEAD 与 CI 对应。
- [ ] Grafana/Prometheus/飞书在本 PR 中只提供文件/隔离实测，不在用户现有监控系统中写入配置或发送群消息。
- [ ] 每个 FAIL/STOP 有完整事实与安全处理；正式审查通过前不合并，不碰生产。

**合并阻塞示例**：采集丢失仍报 business UP；未知 kernel SA 被清理或忽略；exporter 面向公网开放；重协商后的 SA gauge 冒充准确历史 Mbps；监控进程停止 VPN 服务；没有真实 A/B 双向测试却记录业务 PASS；飞书机器人泄露或向真实群发送未经授权测试告警。
