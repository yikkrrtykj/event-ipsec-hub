# 给 Codex 的第一个任务（V2：通用赛事模板）

目标仓库：`https://github.com/yikkrrtykj/ipsecVPN`。请完整阅读仓库内 `docs/SPEC.md`，该文件是 **V2.0 的最高优先级开发合同**；V1 里针对上海/伊斯坦布尔/V.PS/腾讯云/PUBG 的硬编码需求均已废弃。

**定位：** 构建可供今后不同国家/场馆/赛事重复使用的 **Site-to-Site IPsec Hub 工具**。国家、业务、站点 ID/数量、LAN CIDR、双 ISP、VPS 厂商/地域、对端防火墙型号、主备网关选择、告警阈值全部应由每场赛事 profile 配置。当前 Frankfurt V.PS 和 Istanbul 只是可选实例，**不得出现在程序必选字段、固定路径或测试常量中**。腾讯云仅为可选外部备网关，不应是运行前提。

**只完成 PR #1（Draft PR，不能合并、不能运行真实 VPS/防火墙）**：

1. 中文 README、通用赛事架构、配置生命周期和安全说明。
2. `config/event.example.yaml` + `config/schema.json`，实例使用 RFC5737 文档公网 IP 和虚构 LAN，站点名称任意；P0 **一个 Hub + 两个任意站点**，每站可多 CIDR。未来多站点需支持扩展的数据结构，但不要假装 P0 已经支持 N 站点上线。
3. 开发只读命令：`ipsecvpn profiles list`、`validate -c`、`check`、`plan -c`、`export-peer --site <任意site-id> --format md|json`。按站点本端视角输出山石及厂商中立参数单；PSK 只能占位提示独立交付。
4. 对两站任意 ID、任意国家/角色、变更公网和私网 IP、多 CIDR、Traffic Selector 方向、schema 校验、脱敏、无备 Hub 以及对端交换视角建立测试。
5. 三套**不同地区与用途**的虚构赛事 fixtures；最小 CI：pytest、ruff、shellcheck、配置 schema 校验、秘密扫描。
6. 输出 P0/P1/P2 可验证能力表和 PR #2–#5 计划，不冒充完成未经实测的 IPsec/UDP 或防火墙现场测试。

**强制安全条件：** 不要在公共仓库提交真实公网 IP、PSK、Webhook、登录凭据、赛事敏感参数。不允许改默认路由、SSH、全局 nftables，或自动操作山石/腾讯云；PR #1 绝不能执行生产部署。后续计划必须使用 Ubuntu 24.04 + strongSwan swanctl/charon-systemd + VICI + 两条独立 XFRM，且保证可回滚、PASS/FAIL/SKIP 真实判定。

开发分支提交 **Draft PR**，测试后回报修改文件、测试证据与未解决问题。**停在 PR #1，等待人工审查，禁止自动 merge。**
