# PR #4 实验拓扑与证据采集

复用 PR #3 已经过验收的一个可销毁 Ubuntu 24.04 QEMU 客户机及其 Hub / Peer A / Peer B 独立 network namespaces、VICI socket、SAD/SPD、LAN hosts、WAN switch 网络隔离。**不能将 Python 对象互发当成真正隔离流量**。

增加 3 个互不干扰的可观测性组件：

1. Hub 本机出口（127.0.0.1:<显式测试端口>）：只读采集缓存与 Prometheus `/metrics`；隔离网 WAN 和 LAN 侧用真实连接证明无法访问。
2. 专用 A/B LAN 受控 UDP probe fixture（必须有明确端口、鉴权、源绑定和速率限制），A→B、B→A 两方向完成独立事务；CI 收集层次化快照、正反向 payload 哈希与主 XFRM 计数对应关系。
3. 本机 Alertmanager fixture + Feishu mock receiver，捕获 JSON、签名、状态码、去重次数、断电重启后状态。不向真实飞书域名发包。

## 测试顺序

- 建立无 monitoring 的 Hub+双 Peer，确认 PR3 基线全部 PASS；采集 exporter 前/后资源和 CPU 时间/内存的有界窗口数据。
- `monitoring.enabled=false`：证明无常驻服务/UDP 发包；配置启用后检查端口仅回环绑定。Local Prometheus 测试 scraper 可在同 namespace 读取。禁止从 WAN switch/LAN 访问 exporter。
- 在 SA 正常、单站断线、CHILD DOWN、未知 SPD、rekey、daemon 重启、采集 socket timeout、VM reboot 下采样。每次既保存结构化状态，也检查 `metrics` 的可用性/真实性；对 UNKNOWN 不得显示 UP。
- 开启两方向 UDP echo。记录源/目的 LAN 地址（文档保留网段）、随机 nonce 摘要、请求及回复时间、被测方向、测试 XFRM/SPI 包计数前后差值、路由归属、WAN 线侧的加密保护信息；不要输出 ESP key。
- 模拟主路径故障而备用路径仍有通达性的情形（可通过隔离 fixture 假设备/额外路径模拟）；若主 Hub 的 XFRM 不参与，path 必须 UNKNOWN，不能用备用成功令主路径 UP。明确此仅是 **lab path-fencing 证明**，不是腾讯云真实备份自动切换。
- 向本机 bridge 注入 firing→重复 firing→resolved、stale、飞书 mock 429/500/401、签名错误、重启重放；检查阻断外网和本机幂等持久化。
- 停掉/删除监控服务，保留 Hub SA/VICI 与所有非项目路由/防火墙/SSH 基线；重跑双向 UDP/TCP。

## 证据结构

`docs/pr4/PR4_EVIDENCE.md`，`docs/pr4/CODE_ACCEPTANCE.jsonl` 和两个 VM 产出的脱敏 JSONL 仅提供已运行证据；执行前不提交虚假 PASS。每个案例包含截图或 `ss` 的采样，promtool/Grafana parser 结果、path nonce 的 SHA-256 和时间窗、业务 Packet proof、Alertmanager bridge 发包/重试次数/响应 code、`main` 比较快照。不得导出真实 PSK、飞书 webhook、密钥或未经脱敏的 raw kernel dump。

如果执行环境缺少 Prometheus / Alertmanager 测试工具：可以提供可复现的隔离安装（带校验和）并在 VM 实际运行；若做不到必须记录 `SKIP`，不得用单测模拟替代实际集成验收。禁止为了凑 PASS 自动关闭系统安全设置。
