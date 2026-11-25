# event-ipsec-hub 通用赛事网关工具

ipsecVPN 面向电竞赛事、场馆和制作团队的三层站点互通。每场赛事通过独立 profile 定义一台 Linux Hub、两个外部站点及获准互通的 IPv4 网段。站点名称和角色、国家和地区、地址、VPS 供应商、运营商及防火墙型号随 profile 变化。外部备网关可以留空，也可登记为人工交接对象。

[V2.0](docs/SPEC.md) 已交付离线工具、隔离 Linux Hub 部署与回滚、双站 IKEv2/CHILD 与数据路径、可选监控告警，以及厂商中立交接和备用选路模拟。CLI 名称为 `ipsecvpn`。现场厂商设备、真实赛事链路、真实飞书和外部备用切换继续为 SKIP。后续需求在 [V3.0 Epic #6](https://github.com/yikkrrtykj/event-ipsec-hub/issues/6) 跟踪。

## 本地试用

使用 Python 3.11 或更新版本。以下命令使用仓库中的 RFC 5737 文档公网地址和虚构 LAN。

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install .

ipsecvpn profiles list --directory tests/fixtures
ipsecvpn validate -c config/event.example.yaml
ipsecvpn check --json
ipsecvpn plan -c config/event.example.yaml
ipsecvpn export-peer -c config/event.example.yaml --site production-a --format md
ipsecvpn export-peer -c config/event.example.yaml --site stage-b --format json
```

山石设备默认生成 Hillstone / StoneOS 参数单，其他厂商使用通用参数单。可用 `--template hillstone` 或 `--template generic` 明确选择模板。JSON 用于交接和后续系统处理，设备配置由双方管理员按各自版本完成。省略导出的 `-c` 时，须先显式设置 `IPSECVPN_CONFIG`。

两种模板均标为 `NOT_APPLYABLE_CONFIG`，包含 profile 摘要、IKE 身份类型、WAN Peer /32、精确选择器、双向安全区域与 NAT 豁免、逐网段验收和签收栏。导出只写 stdout。含真实拓扑的报告请在受控目录保存和传递。

| 命令 | 输出与判定 |
| --- | --- |
| `profiles list` | 读取指定目录，默认 `/etc/ipsecvpn/profiles`。显示已保存的赛事和校验结果，活动 profile 为 `SKIP`。 |
| `validate -c` | 检查 YAML、V2 schema 和拓扑约束。 |
| `check` | 读取本机发行版信息并查找依赖命令。VICI、SA、XFRM 和真实业务流量为 `SKIP`。 |
| `status` / `doctor` | 在授权 VM 比对当前 VICI、内核 SA/策略、路由和项目 ACL。默认不发包，业务结果为 `SKIP`。 |
| `plan -c` | 打印 JSON 拓扑计划，包括两条 XFRM、内外层路由意图及双向 ACL。 |
| `export-peer` | 向 stdout 输出选定站点视角的 Markdown 或 JSON。现场验收为 `SKIP`。 |

`profiles list`、`validate` 和 `check` 支持 `--json`。退出码 `0` 表示命令完成，结果可含 `PASS` 或 `SKIP`。退出码 `1` 表示发现错误或检查失败，`2` 表示命令行用法有误。请同时查看退出码和各检查项。

启用外部备网关时，离线交接要求两站各有唯一备链路，并填写备 Peer 公网地址、隧道名、授权备路由、主备路由优先级和 Track 目标。资料缺失时，`validate` 可对配置格式和拓扑返回 `PASS`，同时报告备用交接 `SKIP/INCOMPLETE`。此时 `plan` 保留主链路计划，`export-peer` 仅输出缺项诊断，两者状态均为 `SKIP`。备用资料齐全时显示 `PASS/COMPLETE`，现场验收仍为 `SKIP`。

旧 profile 可直接使用。可选的 `backup.transit_support` 接受 `unknown`（默认）、`supported` 或 `unsupported`。在 `plan` 和 `export-peer` 的 `backup.feasibility` 中查看中转核验、业务路径和切换准入。供应商能力声明为 `supported` 后，现场仍须独立验证两站之间的备线路业务。中转不可用、证据缺失或备路由覆盖不全时，切换准入为 `STOP`。

## 配置与验证

- [通用架构和配置约束](docs/architecture.md)
- [赛事配置生命周期与安全](docs/event-lifecycle.md)
- [V2.0 能力与验收索引](docs/roadmap.md)及[长期验收证据](docs/evidence/README.md)
- [隔离 VM 安装](docs/install.md)、[网络所有权](docs/network-ownership.md)、[备份回滚](docs/rollback.md)与[密钥安全](docs/security.md)
- [活动 SA 所有权](docs/pr3/SA_OWNERSHIP_DESIGN.md)与 [三节点验收矩阵](docs/pr3/PR3_ACCEPTANCE.md)
- [可选监控与隔离运行手册](docs/pr4/OPERATIONS.md)
- [主备切换与回切](docs/pr5/PR5_FAILOVER_RUNBOOK.md)、[设备兼容性核对](docs/pr5/PR5_VENDOR_MATRIX.md)及[现场验收记录](docs/pr5/PR5_SITE_ACCEPTANCE_TEMPLATE.md)

```bash
python -m pip install '.[dev]'
python -m pytest -q
ruff check .
ruff format --check .
shellcheck scripts/validate-examples.sh
bash scripts/validate-examples.sh
```

公开仓库只放虚构配置。真实 profile、计划和导出文件应通过受控渠道保存和传输。参数单中的 PSK 始终显示为 `<SEND_SEPARATELY>`。
