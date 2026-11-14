# PR #4 隔离验收记录

基线及 merge-base 为 `9fa763d40e0b81f7600f601e8b30c32f8d671233`。逐项 JSONL 与当前 HEAD 的四套工作流在 Draft PR #4 描述中更新。

## 历史失败

| HEAD | 观察 | 原始证据 |
| --- | --- | --- |
| `be381a5` | HTTP 测试函数遮蔽标准库。采集抓取未执行。 | [JSONL](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43473818499/artifacts/14062004187) |
| `f96716e` | 独立采集为 READY，systemd 内的采集为 UNVERIFIED_RUNTIME。 | [JSONL](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43550327558/artifacts/14096370914) |
| `97d2f83` | DAEMON_ENV/PERMISSION_DENIED。采集进程的 capabilities 未覆盖 strongSwan 进程读取所需范围。 | [JSONL](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43551828419/artifacts/14095998037) |
| `0b1a0db` | 独立采样器通过进程环境读取，采样工作进程触及总时限。 | [JSONL](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43552589429/artifacts/14096119157) |
| `bebdd2e` | 预加载工作进程通过此前的读取阶段，报告 HOST_BASELINE 检查失败。 | [JSONL](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43553494390/artifacts/14097013518) |
| `3a43aeb` | 确认采样器看到与独立采集相同数量的 TCP 监听，但无 SSH 进程标签。 | [JSONL](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43554362728/artifacts/14097358758) |
| `f6fa0d8`、`f465f20` | 原采样时限下分别在主机基线与路由核验阶段超时。 | [f6fa0d8](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43555159003/artifacts/14098226611) · [f465f20](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43574955927/artifacts/14105504254) |
| `359304d` | 批处理降低查询开销，但 systemd 重复的 Listen 字段被折叠，SSH 摘要不匹配。 | [JSONL](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43575969753/artifacts/14106129535) |
| `5c9f555` | 采集启动、双向真实 UDP 及 TTL 失效通过。隔离 LAN 的单向丢包夹具在载入 nft 规则时失败。 | [JSONL](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43576748484/artifacts/14107540646) |
| `ab1db84` | 独立采集为 READY。systemd 采集耗尽四秒总预算，最后阶段为 ROUTING。此证据没有单条命令耗时。 | [JSONL](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43577551928/artifacts/14107686820) |
| `e9180d8` | systemd 三轮采样均在六秒内成功，随后双向 UDP 路径断言 FAIL。 | [JSONL](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43617974906/artifacts/14123776085) |

## 采样时限

`e9180d8` 三轮实测分别为 4.853、4.733、4.765 秒，每轮 35 个外部命令。systemd 查询 9 次、合计 1.090–1.157 秒，VICI 进程和协议读取合计 0.791–0.852 秒，路由查询 13 次、合计 0.761–0.857 秒。路由是旧运行超时所处的阶段，耗时分布显示整个串行采样超出了四秒。测试配置使用六秒总时限、八秒周期和十八秒 TTL，并分别验证超时撤销和证据过期。

现场设备、真实公网、真实备用网关、真实飞书 Webhook 与生产部署保持 SKIP。DPD 无人值守自动重连未验证。
