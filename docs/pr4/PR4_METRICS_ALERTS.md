# PR #4 指标与告警语义合同

本文件是接口合同，不是声称这些指标当前已存在。**先设计和实现，后用真实 VM 验证**。

## 一、标签策略

有限集合：`event_id`、`hub_id`、`site_id`；仅 path 指标可使用 `src_site_id`,`dst_site_id`；对于诊断错误用有界 `reason_code` 枚举（UNKNOWN、UNOWNED_SA、VICI_UNAVAILABLE、NO_PROBE、STALE、CHILD_MISSING、PATH_UNVERIFIED 等）。禁止 SPI、动态 reqid、nonce、PSK、用户地址、时间戳成为 label。单活 profile、最多两站点，验证全部 exporter metric series 数量有上限。

## 二、建议 metric families

| 名称 | 类型 | 语义 |
| --- | --- | --- |
| `event_ipsec_collector_healthy` | Gauge 0/1 | 最近一份完整快照是否有效且未过期；0 不可视为业务 DOWN |
| `event_ipsec_collector_last_success_timestamp_seconds` | Gauge | 最后一次完整快照成功的 Unix 时间，失败不得推进 |
| `event_ipsec_snapshot_age_seconds` | Gauge | 当前快照年龄，定期增加；超 TTL 业务须 UNKNOWN |
| `event_ipsec_profile_active` | Gauge 0/1 | 是否有可验证的活动 profile |
| `event_ipsec_site_ike_state` | Gauge -1/0/1 | -1 UNKNOWN / 0 已验证 DOWN / 1 已验证 UP |
| `event_ipsec_site_child_state` | Gauge -1/0/1 | 与 IKE 分开；仅完整 VICI/内核联合校验可为 1 |
| `event_ipsec_site_kernel_verified` | Gauge -1/0/1 | SA、SPD、if_id、reqid 与活动 profile 是否一致 |
| `event_ipsec_site_protected_route_ok` | Gauge -1/0/1 | 受保护路由与黑洞、实际接口及 ACL 是否验证 |
| `event_ipsec_site_sa_rx_bytes` | Gauge | 当前 CHILD SA inbound bytes，rekey 会重置，不是连续总流量 |
| `event_ipsec_site_sa_tx_bytes` | Gauge | 当前 CHILD SA outbound bytes，rekey 会重置 |
| `event_ipsec_site_sa_rx_packets` | Gauge | 当前 CHILD SA inbound packets；非累计 |
| `event_ipsec_site_sa_tx_packets` | Gauge | 当前 CHILD SA outbound packets；非累计 |
| `event_ipsec_path_state` | Gauge -1/0/1 | src→dst 的**指定主 Hub**业务路径，未探测/失败证明缺失 -1 |
| `event_ipsec_path_last_probe_timestamp_seconds` | Gauge | 该方向最后一次经核验 probe 完成时间，失败也需按语义记录 |
| `event_ipsec_path_rtt_seconds` | Gauge | 最近完成的真实 UDP echo RTT；无有效证明时不要复用旧成功值 |
| `event_ipsec_path_probe_loss_ratio` | Gauge | 固定采样窗口丢包比例，[0,1]；窗口样本数需另有 Gauge |
| `event_ipsec_path_probe_sent_packets` | Gauge | 该窗口发出包数，帮助解读 loss ratio |
| `event_ipsec_alert_bridge_delivery_failures_total` | Counter | 告警桥本身送达失败次数，不影响隧道 |

`-1` 仅用于上表明确定义的三值状态；其它 Gauge 永远不能用“0”代表未知。若 exporter 失败且无法取到活动站点维度，整体 `collector_healthy=0`，不能遗留可被解释为当前 UP 的旧 `1`；Grafana/PromQL 必须 gate collector 健康与 freshness。

`SA bytes` 是当前 CHILD 的 **Gauge**，不能套用 `rate()` 当作跨 rekey 连续流量。若未来要做可靠连续吞吐，应由独立、测试过代际迁移的累计器提供名为 `_total` 的 Counter，否则 dashboard 只能展示当前 CHILD bytes/packet 与定性趋势。

## 三、PromQL 告警规则合同

- `HubExporterDown`：Prometheus `up{job="event-ipsec-hub"} == 0`，或者 `absent`，告警时间窗可配置；避免 exporter 不见即误宣告 IKE DOWN。
- `HubCollectorStale`：collector healthy==0 或最后成功时间超过阈值；UNKNOWN 不自动 recovered。
- `IpsecOwnershipUnknown`：采集明确发现 `UNOWNED_SA` 或内核不符；必须优先突出 STOP（需要 reason_code，禁止无限自定义 label）。
- `IpsecIkeDown`：collector healthy==1 且 `site_ike_state == 0` 持续；UNKNOWN 另报。
- `IpsecChildDown`：collector healthy==1 且 `site_child_state == 0` 持续，区分 IKE UP/CHILD DOWN。
- `IpsecPathDown`：有启用、绑定主链路且在时效内的双端 UDP 探针确定失败，持续多样本；只有当前失败有效才能判 DOWN。
- `IpsecPathUnverified`：探针关闭、路由未固定、agent 不可达或 TTL 超时，显示 UNKNOWN（可以仅提醒，不触发夜间高优先级）。
- `IpsecOneWay`：其中一方向成功另一方向明确失败，且两份证据时效一致；不可用单向 echo 回包冒充反向主动成功。
- `IpsecNoTraffic`：可选 informative；低业务或无播出窗口可能正常，绝不能当成隧道 DOWN 的唯一证据。

Alertmanager 用 label 分组和 `group_wait/group_interval/repeat_interval` 配置去重；bridge 仅进行送达安全、接口适配与跨重启重放保护。提供规则 `promtool check rules`、`promtool test rules`，覆盖断网、未知、持续 DOWN、恢复、失去采集和 flapping。

## 四、Grafana 面板设计

默认按 `event_id`、`site_id` 选择站点（可选 `hub_id`），不显示真实公网 IP。第一屏优先:

1. 采集新鲜度与错误 / ownership 是否可信（不得因为上个周期绿而持续绿）。
2. 站点 A/B IKE、CHILD、内核、路由/ACL，各自独立 indicator。
3. A→B、B→A 真实业务 probe：UP / DOWN / UNKNOWN、时间窗、RTT/丢包；未授权 probe 显示 UNKNOWN 而不是绿。
4. 当前 CHILD 收/发包与字节（注明 rekey reset），允许临时诊断。
5. 告警历史及恢复、最后有效证据时间；备用网关只显示 `EXTERNAL_UNVERIFIED`，绝不主动宣称健康。

`dashboard.json` 是纯导入文件；所有 datasource UID、变量与接入方式可配置，不能直接写入用户现有 Grafana 实例。提供 README 说明如何在私有网络接入。

## 五、飞书告警交付

例：`[CRITICAL] Event X / Hub A / Site B : CHILD_DOWN`；内容含首次异常时间、UTC/本地时间、最近证据时间、受影响方向和诊断码。恢复消息只有在从确认过的 firing 状态转为确定正常且指标新鲜时发送。UNKNOWN/STALENESS 的状态转换不得伪造业务恢复。

Feishu webhook、签名密钥、Alertmanager bridge bearer token 都从部署端受限 secret file 读取；消息 HTML/Markdown 需转义任意用户输入，禁止注入任意 URL。所有 POST 使用合理 TLS 校验、超时和指数退避上限；飞书返回非成功业务 code 不可按 HTTP 200 误判成功。
