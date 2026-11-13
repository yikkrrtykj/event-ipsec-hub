# PR #4 技术开发手册 — 可观测性、真实业务探针及飞书告警

- 仓库：`yikkrrtykj/event-ipsec-hub`（以前名称 `ipsecVPN`）。
- 唯一基线与预期 merge-base：`9fa763d40e0b81f7600f601e8b30c32f8d671233`。
- 交付方式：一个独立 Draft PR；规范文档先提交，然后代码、测试、证据；不自动合并。
- 适用范围：**一个活动赛事 profile、一台 Ubuntu 24.04 strongSwan Hub、两个任意命名站点**；生产写入继续禁止。
- 系统限制：PR #2/#3 的 `lab-authorized`、systemd、SSH/路由/防火墙基线保护和 SA 所有权检查不可弱化。

## 1. 目标和非目标

目标是让工程师看见、区分、告警并追溯：采集器本身是否可靠；Hub/daemon 是否存活；各站 IKE 是否 established；CHILD/内核策略是否匹配；受保护路由和防泄漏 ACL 是否正常；两方向独立业务测试是否真的经过**指定主 Hub**；是否出现故障/恢复、长时间无流量或身份不明。

必须给出安装完全可选的 Prometheus 指标端点、Grafana 面板、Prometheus 规则、Alertmanager→飞书机器人桥接、测试与配置撤销。**监控失效不得阻断 IPsec/SSH 或自动变更业务设备。**

不做：自动 `initiate`、路由 Track、切主备、自动修复/restart、对接腾讯云 API、推送山石配置、用 Hub 自己 ping 证明 A↔B、生产公网开口、SRT QoE 结论、任意 N 站点/IPv6、长期性能 SLO。以上均 `SKIP`，在 PR #5 或单独后续阶段处理。DPD 目前经显式 `initiate` 恢复，**不得宣传无人值守自动重连**。

## 2. 总体架构与故障边界

```
  [项目状态/活动配置/已归属服务]  [VICI IKE/CHILD]  [kernel SAD/SPD, routes, nft]
             \                 |                 /
                [只读采集器 / 统一 snapshot]
                    |                 \
             [本机指标缓存]       [独立业务探针结果 (可选)]
                    |                 /
      http://127.0.0.1:<显式端口>/metrics
                    |
          [本地或 SSH/Tunnel Prometheus]
                    |                    \
             [Grafana]             [Prometheus rules]
                                           |
                                    [Alertmanager]
                                           |
                                [本机 Feishu bridge]
                                           |
                                    [HTTPS 飞书]
```

- 默认 `monitoring.enabled=false`：不能启动 exporter、主动探测或连接飞书。`backup.enabled=false` 必须是合法配置。
- exporter 与 IPsec 配置/事务分离：只能读项目已有 `status/doctor` 的底层证据及有界补充的 XFRM 计数。**任何失败不能调用 Deployment 的变更路径**。
- HTTP 默认绑定 `127.0.0.1`，只能配置回环地址；同机 Prometheus 直接抓取，远端通过经授权的 SSH tunnel 或本地安全代理。不得自动开放防火墙、UFW、云安全组。无 HTTP 鉴权时尤其不可公开绑定 `0.0.0.0` 或公网。
- Feishu bridge 默认关闭且只接受 `127.0.0.1` 的本机 Alertmanager webhook；外发 HTTPS 仅到明确配置的官方飞书机器人 URL，不能跟随非预期重定向。不得将 URL、签名密钥或 payload 的私密信息写到 stdout/metrics/CI artifact。
- **不改** IPsec 原服务启动顺序、`/etc/ipsecvpn/lab-authorized` 授权保护、默认 route、nft、iptables、sysctl、XFRM、swanctl 配置、`reconnect.json`。

## 3. 代码边界和兼容性

1. 复用 `ipsecvpn.diagnostics.status_report()`、`ipsecvpn.live.owned_resources()`、`ipsecvpn.sa.inventory()` 的**只读**行为。采集器检查状态必须尊重状态文件、`installed_record()`、VICI peer PID、两次 VICI 夹读 SAD/SPD；拒绝不完整或外来 SA。避免从 `swanctl --list-sas` 字符串做第二套低质量 parser。
2. `status_report` 本身可能执行有界系统查询；采集调度必须有超时、非重入保护和明确成功时间。如果某次读失败，不把上次 PASS 继续当成本次事实。
3. 独立数据模型 `Observation` 建议包含 `schema_version`、`event_id`、`hub_id`、`collected_at`、`monotonic_age`、`collector_valid`、`reason_code`、站点状态、采集子层状态和可选路径证明。各状态同时暴露原始事实和来源；不创建第二份权威部署状态。
4. 允许将监控 profile 做为既有 schema 的**兼容向后扩展**；`monitoring: {enabled: false}` 的旧样例、当前安装记录及 wheel 均必须继续通过。禁止为了监控要求用户变更赛事 peer IP/PSK/已建立 SA。
5. 编排和配置启停**仅在隔离授权 Ubuntu VM**，新建独立 `event-ipsec-hub-exporter.service` 和可选 `...-feishu.service`，绝不修改 strongswan.service 依赖或主动启停。`start/stop/reload` 必须有预检、显式确认和本项目范围撤销，最好使用独立命令空间 `ipsecvpn monitor ...`。
6. 监控服务不持有可执行部署命令权限；确因读取 SAD/SPD 需要 root 的 collector 应只使用严密 systemd sandbox（NoNewPrivileges、受限读权限、ProtectSystem、PrivateTmp 等，按实际可运行性逐项验证），不要盲目设定会破坏 netlink/VICI 读的 capability 限制。`systemd-analyze security` 可作提示，不得替代实测。出口与桥接尽量拆为非特权进程，明确最小权限及 Unix socket 访问边界。

## 4. 单一快照和语义约束

**五层状态必须独立：**

| 层 | 事实来源 | 允许的状态 | 禁止的捷径 |
| --- | --- | --- | --- |
| collector | 最近一次完整读取、超时、快照年龄 | GOOD/ERROR/STALE | 采集失败后仍显示上次 GREEN |
| hub / daemon | systemd、PID、VICI peer UID、管理基线 | UP/DOWN/UNKNOWN | 只看 TCP 端口 |
| IKE | 已归属 VICI IKE+身份、proposal 等 | UP/DOWN/UNKNOWN | 有同名 SA 就标 UP |
| CHILD/data control | VICI CHILD + 双 SPI + 内核 SAD/SPD + if_id/reqid + 路由、ACL | UP/DOWN/UNKNOWN | 只看 IKE UP |
| business path | 双站点独立目标/源 LAN 的**真实双向**应用载荷和路径证明 | UP/DOWN/UNKNOWN | Hub Ping、SA packet counter 上涨即业务 UP |

- 明确 DOWN 需有足够观察证据；权限错误、外来 SA、解析失败或无效/超时探针是 UNKNOWN + reason，不应被误报为健康。监控可单独告警 UNKNOWN/STALE。
- `data_path=UNKNOWN` 是**安全默认**；未配置探针、未完成两方向探测、路径证明不足、TTL 过期、探针接入失败、只通一方向、被备用链路绕过，均不得产生业务 `UP`。
- 本 PR 若实现两个方向独立状态，应定义 A→B、B→A 的状态及一个整体判定：只有两方向均 UP 且采样时间窗相同、主链路归属成立才整体 UP；任一方向明确 DOWN 则整体 DOWN，其余 UNKNOWN。测试粒度、TTL、轮询周期必须配置化。
- 健康快照不写进部署事务 `journal.json`、`active.json`。监控自己的缓存/去重状态独立存于 root-owned 或服务用户私有目录；删除监控不能删除原 IPsec 记录。

## 5. 业务 UDP echo / ICMP 探针

- 不在 Hub 发送一个本机 Ping 就声称 A↔B 成功。必须在独立的**站点 A LAN 测试主机和 B LAN 测试主机**上，分别主动发起 A→B 和 B→A 的 UDP echo 事务；可复用 PR #3 的 `scripts/pr3-lab/traffic.py` fixture，但产品采集与 fixture 分开。
- 探针**可选、默认关闭**；不强制在赛事现场服务器部署常驻 Agent。若现场无可用独立测试端，业务结果保持 UNKNOWN/SKIP。在 PR #4 隔离 VM 可提供受控轻量 probe helper。
- 使用随机 nonce、序列、时间戳、有效 payload digest、回复校验、配置化源/目的 LAN IP 与端口、限制最大速率/包长、超时和 1-2 次连续采样。不能在 probe 服务上建立公网无鉴权 echo 反射器；仅允许测试 LAN/指定地址且有验证机制和速率限制。
- 路径绑定：在实验中通过业务测试机路由/源接口、Hub 当前 XFRM ID 与 SPI 计数变化、探针前后的两侧 VICI/内核归属，证明观察的是**主 Hub**而非备用。原则上独立路径必须有独立路由与探测端；不能用备链路成功掩盖主链路 DOWN。线上尚无可执行路径绑定证据则 `PATH_UNVERIFIED`。
- 业务探针判定与 IPsec 控制层指标保持独立；模拟“SA 在线但 ACL 断、路由错误、单向通、备用网关路径绕行、证据过期”的场景。延迟/抖动/丢包均标清观察样本与时间窗；不把 ICMP 指标等同 UDP/SRT 性能。
- 不实现自动 MTU/MSS 修改；继续提供 PR #3 的诊断结果，自动调优仍 SKIP。

## 6. Prometheus exporter

- 使用 Python `prometheus_client` 或等价兼容实现，但应确认 Python 3.11+ / Ubuntu 24.04 离线 wheel 可安装；CollectorRegistry 隔离，禁用不必要的默认 process/Python 细节泄漏。
- 监听地址强制 loopback；端口可配置且与已占用端口冲突时 STOP。`GET /metrics` 有总超时，返回合法文本格式；`/healthz` 只证明 HTTP 服务存活，不能暗示 SA/业务已 UP。不提供更改网络的 HTTP API。
- 通过调度器有界刷新，而不是每个 Prometheus scrape 都执行全部高权限命令；读失败/快照过期时暴露健康=0、age 与 UNKNOWN 状态。快照不可在没有采集时间的情况下缓存为永久 PASS。
- 站点、event、hub 标签来自受控 schema；禁止 label 使用 SPI、reqid、密钥、对端公网 IP、nonce、日志原文、每次事件/采样唯一标识。两站点维度上界可验证。
- `bytes/packets` 定义为 **当前 CHILD SA 观察值的 Gauge**，rekey 会重置；不得误标为单调 Counter，也不能未经正确累计就宣称连续出口 Mbps。Grafana 面板必须标记“当前 CHILD，重协商会重置”。若需要连续速率，必须额外设计可追溯、处理重启/rekey 的累计层并用跨代际实测确认，不能用 `rate` 对 gauge 硬凑。
- 指标命名、类型、UNKNOWN 编码和警报建议见 `PR4_METRICS_ALERTS.md`；确保无重复收集注册或无限 label cardinality。

## 7. Grafana / Prometheus / Alertmanager

- 提供可导入 Grafana dashboard JSON 与明确的 datasource UID 输入，不将用户现有 Grafana、Prometheus 配置覆盖。默认面板：Hub 基线、各站 IKE/CHILD/内核一致性、当前 CHILD 包/字节、双向 UDP 探测与 RTT/p95/丢包、数据新鲜度、最近错误和事件、外部备用状态 **UNVERIFIED**。
- 提供可选 Prometheus scrape 配置片段（localhost 示例）、alerting rules、`promtool check rules` 的 CI 校验，以及可选 Alertmanager receiver+route 示例（不覆盖用户现有 Alertmanager）。
- Alert 规则至少覆盖：CollectorMissing/Stale、OwnershipUnknown、IkeDown、ChildDown、KernelMismatch、BusinessPathDown、BusinessProbeUnknown、OneWay、FrequentRekey（必须有可靠信号）、NoTraffic（只能提示/可选，避免低业务时误判断网）。所有规则有 `for` 抗抖与明确恢复逻辑，按事件+站点/方向去重。
- 缺数据不能自动判 recovered；UNKNOWN 不得被渲染成绿色。`absent` 和 stale 必须明确处理，抑制数据失联期间的误发 RECOVERED。

## 8. Alertmanager→Feishu bridge

- 建议使用本地 Alertmanager webhook receiver→最小 bridge→飞书官方自定义机器人 webhook；复用 Alertmanager 的分组与发送策略，而不是造第二套独立告警判定。
- 入站只监听 loopback，配置单独的固定 bearer token 或等价认证（与飞书 webhook secret 分离），限制大小/速率；不得直接让公网访问。对 `firing` 和 `resolved` 分别处理，且**只有有过真实 firing 的告警**才能宣布恢复；Prometheus 采集丢失不可伪造恢复。
- 根据信号标识 `event_id + hub_id + site_id/direction + alertname + fingerprint` 做有界去重；重启后去重状态可靠持久化，有限重试+退避，HTTP 429 或 5xx 异常可重试，4xx 身份错误须失败可见并停止重复轰炸，网络失败不能阻塞 IPsec。
- 支持飞书自定义机器人的签名校验以及可选关键词/IP 白名单；`timestamp + "\n" + secret` 的 HMAC-SHA256 计算应以官方接口说明为准。签名凭据只从 root-only secret file/受保护环境取得，禁止在配置示例及 CI 中真实发送。
- 飞书消息：赛事标签、Hub、站点、方向、告警级别、状态/时间（Asia/Shanghai 与 UTC 明确区分）、reason code、持续时间、受影响前缀简要概述、runbook 链接。不能直接附 PSK、公网真实地址、VICI 原始 dump 或脱敏失败日志。
- 告警桥接默认禁用。离线 CI 仅访问本机模拟飞书 endpoint；**真实飞书群与外网通知必须 SKIP**，待用户授权测试。

## 9. 配置、CLI 与权限

建议产品内独立配置 `monitoring`，参数可变、默认关闭。配置例子仅在文档中，用虚构事件/地址；时间窗口以参数命名且不写死任何赛事地域。新文件优先：

```
ipsecvpn/monitoring/{model,collector,exporter,probes,alerts,feishu,service}.py
monitoring/prometheus/{scrape.example.yml,rules.yml}
monitoring/grafana/event-ipsec-hub.json
monitoring/alertmanager/receiver.example.yml
monitoring/feishu/{bridge.example.yml,README.md}
scripts/pr4-lab/{run.sh,guest.sh,verify.py,...}
docs/pr4/{PR4_DEV_MANUAL.md,PR4_METRICS_ALERTS.md,PR4_ACCEPTANCE.md,...}
```

建议命令：`ipsecvpn monitor validate -c ...`、`ipsecvpn monitor snapshot --json`、`ipsecvpn monitor serve --dry-run|--confirm`、`ipsecvpn monitor stop --dry-run|--confirm`、`ipsecvpn monitor test-alert --dry-run`（仅本机验证，不发外网）、`ipsecvpn monitor doctor --json`。具体实现应遵循项目现有 CLI 风格，不强制引入破坏已有命令的全新 CLI 框架。

- 如果启动服务作为持久变更，保留项目专属 systemd unit/状态文件、只写项目目录、可撤销且回滚；单纯生成 Grafana/Prometheus 片段不修改用户现有服务。
- Linux collector 在带 `lab-authorized` 的隔离 QEMU VM 上实测；普通 Windows/Linux 无授权环境下离线校验可以运行，但任何启动/绑定/网络探测/本机部署变更必须 STOP。
- 适配用户已经存在的 Prometheus/Grafana，不能擅自安装另一套 Grafana/Prometheus 或开放公共 Dashboard；允许透过现有 SSH tunnel 读取本机指标。

## 10. 测试、交付和发布限制

严格执行 `PR4_ACCEPTANCE.md`：原 85 pytest 及 PR2 38 VM case、PR3 三节点全部回归；新增读模式、采集失败/超时/未知 SA、探针路径证明、失联与恢复、hook 认证/重复通知、Feishu stub、监控服务重启、监控移除后配置/SSH/路由不变。系统安全性见人工 checklist。

PR #4 可以提交的结论：**在授权隔离环境中，监控指标、独立路径探针、Grafana 文件和告警桥接经过验证**。不能宣称线上 SRT 质量、自动故障切换、腾讯云备网关、外部强制穿透或 DPD 无人值守自愈。

## 11. 文档一致性

当前 `main` 的 `README.md` 仍把 PR #3 写为 Draft，而 `docs/SPEC.md` 使用仓库改名前的 URL。PR #4 应更新 README 的实际阶段状态、明确新仓库 URL；历史规格中的原始 URL 可以保留并注明迁移，不要改写旧验收证据或误称 PR4 已上线。

## 12. 官方参考（访问时再次核对版本）

- Prometheus Python Client：`https://prometheus.github.io/client_python/collector/custom/`、`https://prometheus.github.io/client_python/exporting/http/`
- Prometheus alerting rules：`https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/`
- Grafana provisioning：`https://grafana.com/docs/grafana/latest/administration/provisioning/`
- 飞书自定义机器人安全、签名：`https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot?lang=zh-CN`
