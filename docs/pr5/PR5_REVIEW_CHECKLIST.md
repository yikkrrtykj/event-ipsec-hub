# PR #5 人工 Review 检查清单

- [ ] HEAD/base/merge-base 为 `6aacc03514ee98bea91e26bbba46a72451211715` 所派生分支，无异常 rebase/force-push。
- [ ] PR Draft，未自动 merge/未启动后续范围，所有实际设备及生产环境没有网络写入。
- [ ] 旧 106 pytest / Ruff / ShellCheck / JSON schema / wheel / Gitleaks PASS；PR2+PR3+PR4 三套 QEMU 对同一 HEAD 完整成功。
- [ ] 补充的离线 handoff 与状态机测试有真实断言、报告可重复生成；没有恒真 verdict。
- [ ] 参数单仍由 `authorized_lans` 和现有 `handoff.py` 生成；A/B 方向镜像、CIDR、IKE ID、ESP、NAT/Outer 不漂移。
- [ ] `backup.enabled:false` 输出正常；启用但字段不全 => `SKIP/INCOMPLETE`；齐全只表示 `COMPLETE`，不提升现场验收为 PASS。
- [ ] 文档明确 Hillstone 不同固件/HA/route vs policy 模式的核验，未声称自动生成即真实兼容；未知多 CIDR/Proxy ID STOP。
- [ ] 云 VPN 备方案验证是否**真的支持 A↔Backup↔B transit**，不可因两侧 IKE UP 直接 PASS。
- [ ] 测试单侧故障、回程非对称、备路径反向、回切与 fail-closed，提供可现场填写的独立证据模板；无现场证据 SKIP。
- [ ] 每条路径独立 Track 源/出口/目标，不能使用主路径成功冒充备路径；路由优先级方向以具体设备确认。
- [ ] 不新增生产推送接口、不自动登录 StoneOS/Tencent、不新增密钥/真实公网/Webhook/人员资料，不修改 Hub 外部资源与默认路由。
- [ ] 真实现场山石、云 VPN、自动切换、无人值守 DPD、自适应 MTU/MSS、真实飞书全部明确 SKIP。
- [ ] README/roadmap/交接文档不留下已过时“PR1 当前 Draft”或“PR4 未验收”误导。
- [ ] Review Threads 0 未解决、CI 最新 HEAD 通过；最终给普通 Merge commit 建议，而非 Squash/Rebase；**不因文档 PASS 声称生产上线**。
