# PR #4 验收合同 — 监控、路径探针与告警

> Base/merge-base: `9fa763d40e0b81f7600f601e8b30c32f8d671233`。本文件的 PASS 条件是**未来开发目标**，不是本轮已经通过的项目。

## 证据标准

每项至少记录：`case`、`time_utc`、`head_sha`、`environment`、`action`、`expected`、`observed`、`status=PASS|FAIL|SKIP|STOP`、`proof_refs`。真实系统操作必须从隔离 Ubuntu 24.04 QEMU 来；不得以 Python mock 假装完成强制真实实验。完整失败历史不抹除；最终无未解除 FAIL/STOP。JSONL 只含虚构地址、摘要和脱敏片段。单一 HEAD CI 与 VM 一一对应。

## C — 继承回归与离线单测

| ID | 实验 | PASS 条件 |
| --- | --- | --- |
| C01 | 既有 pytest | 保留原 85 项及全部旧断言，新增监控 tests 独立运行 |
| C02 | Ruff/ShellCheck/Schema/wheel/Gitleaks | 所有工具全绿，wheel 在 checkout 外可离线导入 monitor 模块 |
| C03 | V2 模型兼容 | `monitoring.enabled=false` 和旧三份赛事 fixture 不需要新必填字段 |
| C04 | 无生产写入 API | 采集器代码不调用 install/apply/rekey/initiate/rollback/uninstall/网络变更 |
| C05 | 所有权 | `owned_resources` 和 VICI/XFRM 失败时监控报不可信，不误报 UP |
| C06 | 安全启动门禁 | 无 marker、非 QEMU、非 root/无适当只读权限下持久服务启动 STOP；离线 validate 可读 |
| C07 | 标签基数 | event/hub/site 标签限定，SPI/reqid/nonce/公网 IP/时间戳不作为标签 |
| C08 | Secret 安全 | webhook/PSK 不在 stdout、logs、metrics、PCAP/JSONL、Dashboard、Git 历史 |
| C09 | 本机 bind | 禁止 `0.0.0.0`、公网、IPv6 wildcard；端口占用和非授权请求均 fail-closed |
| C10 | disabled/no profile | 监控关闭无服务、无主动探针、无飞书发包；无活动 profile 时 UNKNOWN |
| C11 | 指标语义 | `-1/0/1` 与 collector 失效/TTL 的一致性；当前 CHILD bytes 必须 Gauge |
| C12 | Grafana 文件 | dashboard JSON 可解析、UID 变量正确、缺数据不呈现绿色 |
| C13 | Prometheus 文件 | `promtool check rules` + `promtool test rules`，采集缺失/恢复/抖动不会伪报 |
| C14 | 告警消息 | 输入转义、无敏感数据、时区正确、状态码和业务码均校验 |
| C15 | PR 流程 | Draft、独立分支、符合 merge-base，不创建 PR #5、不部署生产 |

## M — exporter/采集器真实隔离测试

| ID | 实验 | PASS 条件 |
| --- | --- | --- |
| M01 | exporter 仅回环 | `ss` + 隔离网外探测证明不能从其他接口访问 |
| M02 | scrape 成功 | 本地 Prometheus 文本格式合法，指标/站点标签均正确 |
| M03 | 两 CHILD 正常 | 当前独立 VICI/内核可核对，所有权/状态准确，无业务探测则路径 UNKNOWN |
| M04 | 只有 IKE 无 CHILD | IKE 与 CHILD 分层，业务不假报 UP |
| M05 | 单站掉线 | 另站不被错误标 DOWN；跨站业务状态按双方向判定 |
| M06 | 权限/daemon/套接字不可读 | collector healthy=0，已缓存 PASS 不能继续作当前事实 |
| M07 | 未知 SA/SPD 或额外 listener | 显式 UNKNOWN/STOP 原因，exporter 不尝试清理对象 |
| M08 | 采样超时与卡死 | 有界超时、非重入保护，HTTP 不长期阻塞，后续可恢复采样 |
| M09 | 重协商 | IKE/CHILD 新旧代际稳定后采样；计数变化语义不误标累计总量 |
| M10 | 缓存过期/重启 | age/last_success 正确，缺上次样本时显示 UNKNOWN |
| M11 | ipsecvpn 本身故障 | exporter 故障不影响 SSH、daemon、XFRM、业务流程 |
| M12 | exporter 重启/卸载 | 对比非项目 nft、默认 route、SSH、SA、原有 VM 服务基线 |

## P — 独立 A↔B 业务 UDP 探针

| ID | 实验 | PASS 条件 |
| --- | --- | --- |
| P01 | 关闭时无探针 | 默认不发任何业务包，数据路径 `UNKNOWN/NO_PROBE` |
| P02 | A→B UDP | A LAN host 主动发 nonce+seq，B 验证源 IP/port 与 digest；XFRM 归属正确 |
| P03 | B→A UDP | 反向**独立主动**发起，不用 A 的回包冒充 |
| P04 | 双向都通 | 相同有效窗口、路径固定主 Hub，才整体 UP |
| P05 | IKE/CHILD UP 但转发 ACL 故障 | UDP DOWN 或 UNKNOWN（据证据判断），不得靠 SA=UP 变绿 |
| P06 | 单向被阻断 | A→B 与 B→A 状态分别正确，overall 非 UP |
| P07 | WAN/XFRM 掉线 | 数据失败、正确 PATH_DOWN/UNKNOWN；WAN 无私网明文 payload |
| P08 | 测试绕备用路由 | 没有主 XFRM path proof 必须 `PATH_UNVERIFIED`，不得误判主 Hub UP |
| P09 | probe 证据 TTL 过期 | 立即停止显示业务 UP；时间窗、样本数准确 |
| P10 | nonce 重放/错误回执 | 必须拒绝，不能计入成功；速率与 payload 限制有效 |
| P11 | UDP RTT/丢包 | 有可复核样本、计时与分母；禁用/无样本不导出假 0% loss |
| P12 | 非项目测试源 | 禁止接收未授权地址反射包，测试服务不会暴露为开放 UDP reflector |

## A — Alertmanager/飞书 bridge（只允许本机假 webhook）

| ID | 实验 | PASS 条件 |
| --- | --- | --- |
| A01 | 关闭告警 | 没有 HTTP 外发，且不影响 exporter 和业务数据 |
| A02 | 有效 firing | 本地 webhook 接收、消息字段完整、时间正确、规范脱敏 |
| A03 | 重复 firing | 同 fingerprint 去重及限频；重启后去重证据可恢复 |
| A04 | resolved | 只有真实 firing 且采集已恢复才发 RECOVERED |
| A05 | stale/no data | 不误发 RECOVERED，改为数据不可用类别 |
| A06 | 抖动 | rules 的 for/group/repeat 控制，无大量重复消息 |
| A07 | 入站鉴权 | 缺 token、错误 token、过大 payload、非法 JSON 拒绝 |
| A08 | Feishu 签名 | 本地捕获 timestamp/sign 并校验 HMACSHA256/Base64 正确 |
| A09 | 429/5xx/超时 | 有界重试、退避、监控失败可见，不阻断 IPsec |
| A10 | 非成功业务 code/4xx | 不假报 delivered，限频且不泄露 webhook |
| A11 | 恢复后再次故障 | 新 firing 可以重发，已恢复状态不会永久压制新告警 |
| A12 | stop/uninstall | 仅删本项目 monitor/bridge 资源，不动 Prometheus/Grafana/SA/路由 |

## R — 完整前序回归与实机边界

| ID | 实验 | PASS 条件 |
| --- | --- | --- |
| R01 | PR #1/#2/#3 离线 | 原 85 pytest，lint/security/smoke 全保留 |
| R02 | PR #2 QEMU | V01–V20、F01–F14、L01–L04 继续完整运行（38 unique cases） |
| R03 | PR #3 三节点 QEMU | T01–T14、S01–S10、N01–N06、F01–F16、I01–I03 保留原断言及数据平面 |
| R04 | 同时运行 exporter + 双向业务 | A/B UDP/TCP 与 rekey/维护/故障恢复不受额外采集影响 |
| R05 | exporter/bridge 故障注入 | 只影响监控；业务 route/SA/SSH 不变；没有线上副作用 |
| R06 | QEMU 重启 | 仍执行现有 Hub guard/恢复流程；monitoring 故障不会放宽保护 |
| R07 | 资源占用与低采样频率 | 采样/metrics 抓取有界，不依赖高 CPU/大量进程；实测记录样本 |
| R08 | 一键撤销 PR4 资源 | 监控独有 systemd 与配置可完全撤销，独立 baseline 对比通过 |

## 保持 SKIP（不得误报 PASS）

- 真实飞书群 Webhook 外发、生产服务器、现场山石/其它设备、跨国 ISP 质量、赛事 SRT/游戏体验。
- 现场无额外探针端点时的真实端到端业务状态、外部腾讯云/其它备用 Hub 健康、自动主备切换。
- DPD 断线后的无人值守自动重连（PR #3 仅证明显式 `initiate`）、长期稳定性 SLO、系统资源规模扩展、IPv6/N 站点。

**交付**：Draft PR URL、base/merge-base/head、完整 PASS/FAIL/SKIP/STOP、实际 3 workflows 日志、脱敏 JSONL、Prometheus `promtool`/dashboard/bridge 工具验证、网络所有权安全摘要，以及独立可审查的操作/回滚说明。主分支不得自动 merge。
