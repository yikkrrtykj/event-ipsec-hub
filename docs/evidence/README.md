# 验收证据归档

[文件处置与要求保留位置](document-migration.md) · [归档摘要清单](archive/manifest.json)

本目录长期保存已审核的结构化隔离验收回执。15 份历史 Artifact 共 625 条记录，保留
原有编号、结果、顺序和主要观测值，包括 FAIL、预期 STOP、SKIP 和重跑。
归档仅从官方 Artifact 内的单份脱敏 JSONL 提取，去除凭据字段并规范为 UTF-8 JSONL。
原始 ZIP、整机日志和抓包留在原存储。

清单分别记录原始 ZIP、提取的原始 JSONL 和归档文件的 SHA-256。可对归档文件运行
`sha256sum` 与 `archive_sha256` 比对。历史 PR #2 的回执没有客体执行 SHA。
清单只记录 GitHub 为该 run 关联的 HEAD，`reported_head_sha` 留空。
新 PR #2 回执由宿主 checkout、提交生成的载荷清单和客体执行回执共同验证。

| 长期副本 | 工作流 | 原 Artifact |
| --- | --- | --- |
+| [pr2-final](archive/pr2-final.jsonl) | [42251240160](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/42251240160) | [13521777287](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/42251240160/artifacts/13521777287) |
| [pr3-final](archive/pr3-final.jsonl) | [43416607390](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43416607390) | [14033538445](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43416607390/artifacts/14033538445) |
| [pr3-restart-fail](archive/pr3-restart-fail.jsonl) | [42332206806](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/42332206806) | [13558353867](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/42332206806/artifacts/13558353867) |
| [pr4-final](archive/pr4-final.jsonl) | [43673246033](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43673246033) | [14145369062](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43673246033/artifacts/14145369062) |
| [pr4-startup-fail](archive/pr4-startup-fail.jsonl) | [43550327558](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43550327558) | [14096370914](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43550327558/artifacts/14096370914) |
| [pr4-timeout-fail](archive/pr4-timeout-fail.jsonl) | [43577551928](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43577551928) | [14107686820](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43577551928/artifacts/14107686820) |
| [pr5-offline](archive/pr5-offline.jsonl) | [43707877274](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43707877274) | [14159670429](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43707877274/artifacts/14159670429) |
| [pr5-pr2](archive/pr5-pr2.jsonl) | [43707877244](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43707877244) | [14159592359](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43707877244/artifacts/14159592359) |
| [pr5-pr3-stop](archive/pr5-pr3-stop.jsonl) | [43707877249](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43707877249) | [14159832947](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43707877249/artifacts/14159832947) |
| [pr5-pr3-retry](archive/pr5-pr3-retry.jsonl) | [43707877249](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43707877249) | [14167945414](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43707877249/artifacts/14167945414) |
| [pr5-pr4](archive/pr5-pr4.jsonl) | [43707877239](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43707877239) | [14159018683](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43707877239/artifacts/14159018683) |
| [pr5-final](archive/pr5-final.jsonl) | [43707877267](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43707877267) | [14159601123](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43707877267/artifacts/14159601123) |
| [pr5-route-fail](archive/pr5-route-fail.jsonl) | [43703342153](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43703342153) | [14157339196](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43703342153/artifacts/14157339196) |
| [pr5-recovery-fail](archive/pr5-recovery-fail.jsonl) | [43704719048](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43704719048) | [14158242344](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43704719048/artifacts/14158242344) |
| [pr5-observation-fix](archive/pr5-observation-fix.jsonl) | [43706758070](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43706758070) | [14159250703](https://github.com/yikkrrtykj/event-ipsec-hub/actions/runs/43706758070/artifacts/14159250703) |

PR #5 中三节点回归的首轮 `STOP_FOR_MANUAL` 和同一 SHA 重跑各自留档。
维护时序风险继续在 [#10](https://github.com/yikkrrtykj/event-ipsec-hub/issues/10) 跟踪。
真实厂商、云端中转、飞书和现场生产的证据须经过独立授权。

其他历史运行与未执行项保留在
[安装和回滚](../pr2/PR2_EVIDENCE.md)、[IPsec 数据面](../pr3/PR3_EVIDENCE.md)、
[监控](../pr4/PR4_EVIDENCE.md)及[备线切换](../pr5/PR5_EVIDENCE.md)的证据记录中。
