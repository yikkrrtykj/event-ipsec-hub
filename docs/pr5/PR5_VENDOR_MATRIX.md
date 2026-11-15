# 设备兼容性矩阵（需现场填写，任何“支持”都须核验）

> 这是**交接核验模板**；不是 Hillstone StoneOS 5.5R11P2-v6 或其它型号的认证结果。

| 维度 | Hillstone/StoneOS 本端 | 其他防火墙本端 | Linux 主 Hub | 外部备 Hub/云 |
|---|---|---|---|---|
| 设备型号/完整固件 | `UNKNOWN`，现场签收 | `UNKNOWN`，现场签收 | Ubuntu 24.04 QEMU 已通过 PR3 | `SKIP` |
| IKE 版本/身份/PSK | IKEv2 / 双方核验身份类型 | 同左 | strongSwan 已有离线+QEMU | 由供应商核实 |
| Proposal/PRF/DH/PFS | 与报告逐项比对，不能自动降级 | 同左 | Profile 派生 | 精确到 VPN 产品版本 |
| Route-based / policy-based | 先决定具体模式 | 先决定具体模式 | XFRM route-based | 先确认产品/功能 |
| Multiple Proxy ID / TS | 不应凭旧版资料假设 | 逐型号核对 | 多 CIDR 已 QEMU 通过 | 需确认精确网段和云端限制 |
| Local/remote TS 对称 | 本端=本站，远端=对站 | 同左 | 两端报告镜像 | 可能与云侧 CIDR 模型不同，STOP 核验 |
| Dual ISP 外层路由 | 各站点出口固定 /32 | 同左 | 显式 WAN | 云侧 Endpoint/ASN/地域受约束 |
| NAT 豁免 | 先于公网 SNAT | 同左 | 本项目不对 LAN 做 SNAT | 云 VPC/IDC 是否支持 transit |
| 安全区域/ACL | 双向明确 allow | 双向明确 allow | 本项目独立 nft ACL | 云网络 ACL、安全组、路由 |
| Static route priority | 验证设备优先级方向、VR | 同左 | 本机不代理设备路由 | 实际产品静态路由优先级 |
| Track/health-check | 证明路径绑定与失败时路由变更 | 同左 | 只读监控不切换设备路由 | 供应商配置 + 实测 |
| 单端失败与回切 | `SKIP` 直到协调演练 | `SKIP` | 主路径失效可监控 | 必须证实独立数据路径 |
| 真实 SSH/HA 基线保护 | 设备管理员提供回滚与 console | 同左 | PR2–PR4 QEMU 基线验证 | API/云资源不自动更改 |

## 单台设备现场核验记录（复制每个 site 一份，不能写入公网仓库）

- 赛事 ID / site_id / Site Role: `________`
- Admin/签收人及日期/维护窗口: `________`
- Model / StoneOS full build / VSYS / VR / HA role: `________`
- Route-based / policy-based / tunnel interface / zone: `________`
- Local identity 类型和值、Remote ID 类型和值: `________`
- IKE/CHILD Proposal 与 lifetime，PFS/DPD: `________`
- Phase2 / Proxy ID 项数、协商返回选择器、SPI/SA 证据: `________`
- Site WAN/ISP、peer outer route、UDP500/4500/ESP50、NAT-T: `________`
- 双方向 CIDR ACL / NAT exemption / RPF / 回程路由: `________`
- 备 WAN / 备 Peer / 独立 PSK / 备隧道 / 备 route/Track: `________`
- 业务测试主机、真实 UDP/TCP、MTU、失联后的回切测试: `________`
- 配置备份 ID / 安全撤销方式 / 管理口 console: `________`
- 可提供的脱敏证据路径（勿交付真实密钥）：`________`
- 结果：`PASS / FAIL / SKIP / STOP`；原因和责任人：`________`

## 特别提醒

- `Hillstone` 是 profile 中的 vendor 标签，**不是**设备配置自动化引擎。其 `if_id` 与 Linux XFRM 对象属于不同编号空间。
- 对 StoneOS 5.5R11P2-v6 的 exact CLI、Phase2 组合、Track/NQA、HA 行为，仅现场版本及官方对应资料才能确认。
- 云 VPN 拥有到两个 customer gateway 的两条隧道，不证明两个 customer LAN 可以通过云 VPN 互相转发；须核对 transit 路由与产品约束。
- StoneOS 官方手册可用于识别 route-based 和 policy-based 两个配置入口。按现场完整 build 取得适用手册后再核对字段。[Hillstone StoneOS WebUI 指南](https://kb.hillstonenet.com/en/wp-content/uploads/2023/01/StoneOS_WebUI_User_Guide_X_5.5R10-1.pdf)
- 腾讯云公开文档描述了 VPC 和 CCN 两类场景。需逐项核对所选产品、地域、隧道模式、路由及安全策略，再通过独立的备线路收发确认是否符合本站中转要求。当前仓库未验收任何云端产品实例。[应用场景](https://www-sg.tencentcloud.com/document/product/1037/39702) · [IPsec 网关常见问题](https://www-sg.tencentcloud.com/document/product/1037/53821)
