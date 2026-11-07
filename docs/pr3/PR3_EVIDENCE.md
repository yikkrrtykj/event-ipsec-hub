# PR #3 隔离验收记录

基线与 merge-base 为 `1bdfdb7fe17a2c959a0859856824eadf8f1ceae6`，首提交 `41c1583` 收录开发合同。实验为独立 Ubuntu 24.04 QEMU 客户机，Hub 使用客户机自己的网络栈，两个 Linux Peer 和两端 LAN 测试主机各使用独立网络命名空间。实验 WAN 交换机另有命名空间，只有实验节点相连。管理口使用 QEMU `restrict=on` 和 loopback SSH。未接触生产服务器或现场设备。

## 已实际完成的阶段

提交 `1b799ef7d2d827643c2b78b9861bda0860963af1` 在 Linux `6.8.0-147-generic`、strongSwan `5.9.13-2ubuntu4.24.04.5`、iproute2 `6.1.0-1ubuntu6.4`、nftables `1.0.9` 上运行。 [离线 CI](https://github.com/yikkrrtykj/ipsecVPN/actions/runs/42264998437) · [PR #2 VM 回归](https://github.com/yikkrrtykj/ipsecVPN/actions/runs/42264998411) · [三节点日志](https://github.com/yikkrrtykj/ipsecVPN/actions/runs/42264998676) · [逐项 JSONL](https://github.com/yikkrrtykj/ipsecVPN/actions/runs/42264998676/artifacts/13527257145)

| 用例 | 实际结果 |
| --- | --- |
| T01–T04、T12 | PASS。三个 daemon 与网络栈，独立 VICI。两条 IKEv2/CHILD 的相反 SPI 在 Hub 与各 Peer 对应。Hub 有 4 个内核状态和 24 条 ESP 策略，每个 Peer 有 12 条策略。内外路由核对通过。 |
| T05–T11、T14 | PASS。双向各自发起 UDP 和 TCP，四对授权 CIDR 双向覆盖。接收端原源 IP、源端口和逐包负载摘要一致，两个 Hub XFRM 均有收发和对应捕获，WAN 只观察到加密业务。活动 SA 同配置 apply 为 NOOP，journal 与 SA ID 一致。 |
| S01–S04、F14 | PASS。Hub 主动 IKE 与 CHILD rekey、Peer 发起、两侧同时请求均有实际代际和流量记录。并发 apply 受快照门禁保护。此轮未测试定时 rekey。 |
| F01–F06、F13 | PASS。错误 PSK/ID、ESP proposal、disjoint selectors，真实外来 SA、同 if_id 的未登记内核策略、未确认维护均被拒绝。 |
| S07 | FAIL，运行时为 `STOP_FOR_MANUAL`。维护闭锁挡住了终止回执，实际已撤除首条 SA，但 VICI 返回超时失败。事务 `4345613f44a449459e3f7fca694edd93` 保留闭锁并停止。后续修复只放通已授权 Peer 的控制报文，每次终止后核验精确的剩余 SA 集合。 |
| T13、S05–S06、S08–S10、N01–N06、F07–F12、F15–F16 | SKIP。该轮在维护变更处停止，后续用例尚未执行。 |

更早两轮分别发现实验 profile 缺少现有 schema 必填字段，以及实验交换机的运行属性引起 Hub 基线差异。修复保留 schema，交换机隔离到独立命名空间。抓包初次遗漏末尾一个采集点，修复立即采集及有界等待后，以上轮次完整通过了抓包核对。现场厂商设备、真实业务公网、外部备用切换和监控仍为 SKIP。
