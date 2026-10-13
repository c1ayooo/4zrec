---
name: security-research-hack
description: >-
  安全研究总入口与执行编排：场景自动路由（CTF/漏洞分析/渗透/代码审计/应急/逆向/密码学/工具开发）、现象→攻击面路由表、渗透状态机（五阶段+回退，状态落平台黑板）、成果自动检测、失败分类策略切换、47 攻击专题索引、2025-2026 payload 与 CVE 速查、SRC 实战链（GraphQL/OIDC/WAF/ATO）。触发词：漏洞、渗透、CTF、XSS、SQLi、SSRF、IDOR、JWT、RCE、exploit、PoC、payload、pentest、bug bounty、赏金、注入、绕过、WAF bypass、提权、后渗透、审计、逆向、取证、应急响应、GraphQL、OIDC、OAuth、SSO、ATO、账户接管、id_token、client_secret。
metadata:
  roles: [渗透测试]
  stages: [web, vuln, exploit, src]
  tags: [渗透测试, penetration-testing, 红队, CTF, 安全研究]
---

# 安全研究上下文注入与全套 Hack Skills（总路由）

> **协同体系**: 场景路由 → **状态机编排** → **工具决策树** → 攻击知识库 → **成果检测** → 结构化输出
> 本文件只做路由与编排。重内容（决策树/payload/CVE/SRC/知识索引）在 `references/` 按需加载。

## 1. 场景路由与输出规范

| 场景 | 标签 | 输出重点 |
|------|------|---------|
| CTF | `[security:ctf]` | 题型判断 → 利用思路 → 验证步骤 → 脚本 |
| 漏洞研究 | `[security:vuln]` | 根因 → 触发条件 → 影响 → PoC → 修复建议 |
| 渗透测试 | `[security:pentest]` | 攻击面 → 验证步骤 → 结果记录 → 风险说明 |
| 代码审计 | `[security:audit]` | 入口点 → 危险数据流 → 漏洞点 → 修复建议 |
| 应急响应 | `[security:ir]` | 证据保全 → 时间线 → IOC → 处置建议 |
| 逆向分析 | `[security:reverse]` | 关键函数 → 保护机制 → 行为推断 → 验证步骤 |
| 密码分析 | `[security:crypto]` | 算法 → 缺陷 → 利用条件 → 验证思路 |
| 工具开发 | `[security:tool]` | 目标 → 输入输出 → 模块划分 → 验证方式 |

**通用输出结构**: ① 威胁/漏洞概述 → ② 技术分析（根因/触发条件/攻击面）→ ③ 验证步骤/PoC（可复现）→ ④ 影响评估 → ⑤ 防御建议

**质量标准**: PoC 可复现（完整环境+依赖+步骤）；解释攻击原理不堆命令；每个攻击技术配套防御/检测视角；只输出场景相关分析不发散。

## 2. 现象 → 攻击面路由表

```
新目标 → Recon（资产发现、技术识别）→ 验证（漏洞确认、PoC）→ 利用（数据提取、提权）→ 组合链（多漏洞串联）
推荐测试顺序: ① Recon/方法论 → ② API/Auth/IDOR（认证授权边界）→ ③ XSS/SQLi/SSRF/SSTI/XXE（注入类）→ ④ 业务逻辑/竞态 → ⑤ 组合链与提权
```

| 现象 | 优先方向 | 核心技术 |
|------|---------|---------|
| 输入反射到 HTML/JS | XSS / SSTI | Context-aware payload, WAF bypass |
| 服务端会主动访问 URL | SSRF | 云元数据、DNS 重绑定、Gopher 协议 |
| 接收 XML/Office/SVG | XXE | 本地 DTD、盲 XXE、OOB |
| 路径/文件名/下载接口可控 | Path Traversal / LFI | PHP wrapper、pearcmd、日志包含 |
| API 中大量对象 ID | IDOR / BOLA / BFLA | A/B 账号切换重放 |
| 登录/找回密码/2FA/Session | Auth Bypass / JWT / OAuth | 算法混淆、密钥混淆、流程劫持 |
| 多步骤交易/优惠券/价格/库存 | Business Logic | 支付篡改、状态机绕过、竞态 |
| MongoDB/JSON 查询语法暴露 | NoSQL Injection | 操作符注入、盲注自动化 |
| 命令行工具/图像处理/导入器 | Command Injection | 通配符/xor/base64 绕过 |
| HTTP 请求解析异常 | Request Smuggling | CL.TE/TE.CL/HTTP2 降级 |
| Node.js `__proto__` 可控 | Prototype Pollution | EJS/Kibana Gadget 链 |
| PHP 弱比较 / 0e hash | Type Juggling | Magic Hash、HMAC 0e |
| .git/.svn/.env 可访问 | Insecure SCM | 源码恢复、备份文件 |
| WebSocket 协议升级 | WebSocket Security | CSWSH、Origin 验证绕过 |
| 内部包名/供应链清单 | Dependency Confusion | 公共注册表劫持 |
| CSV/Excel 导出功能 | CSV Formula Injection | DDE/rundll32 payload |
| 一次性操作(优惠券/库存/重置) | Race Condition | HTTP/2 单包攻击 |
| 同名参数重复/解析不一致 | HTTP Parameter Pollution | 服务器行为差异利用 |
| GraphQL 端点可达 | GraphQL 未授权 + 信息泄露 | 内省→高价值字段→Alias批量枚举→ATO |
| OIDC/SSO/Authing/IAM 认证 | OIDC Token 滥用 + ATO | interaction 端点 id_token 注入、secret 泄露 |
| WAF 拦截 403/特定路径 | WAF 路径规范化绕过 | 双斜杠/点斜杠/编码差异（深度用 search_knowledge_base 检索 srcall：waf 绕过） |

## 3. 渗透测试状态机（执行编排）

```
RECON ──▶ ENUMERATION ──▶ EXPLOITATION ──▶ PRIVESC ──▶ POST-EXPLOIT
   ▲            ▲                 │              │
   └────────────┴──── 回退 ────────┴──────────────┘
```

| 阶段 | 目标 | 完成标志 |
|------|------|---------|
| RECON | 发现攻击面、识别技术栈 | 端口扫描完成 + ≥2 个服务识别 |
| ENUMERATION | 深度枚举、发现漏洞入口 | ≥1 个漏洞确认（PoC 级证据，非猜测） |
| EXPLOITATION | 利用漏洞获取访问权 | 初始 shell 或敏感数据读取 |
| PRIVESC | 提升权限到最高 | root/SYSTEM/admin |
| POST-EXPLOIT | 数据提取、横向、持久化 | 完成数据获取或报告 |

**转换/回退**: 端口+服务+技术栈确认 → 进 ENUMERATION；漏洞确认 → 进 EXPLOITATION；拿到 shell → 进 PRIVESC；最高权限 → 进 POST-EXPLOIT。
EXPLOITATION 连续 5 次失败 → 回退 ENUMERATION 扩面；PRIVESC 受阻 → 回退 EXPLOITATION；任何阶段 30 分钟无进展 → 重新评估攻击面。

**Session 状态持久化**——黑板是**平台框架机制，不是本 skill 的自建状态**：以下字段一律落平台工具（不在磁盘/对话上下文自建 yaml 或状态文件），跨会话续作靠黑板天然继承：

```yaml
# 这是黑板内容的组织视图（落点=平台工具，勿在磁盘建此文件）：
pentest_session:
  target: "<目标>"              # → upsert_project_fact（target/<host>）
  phase: "enumeration"          # → 任务板/plantask 计划项状态（in_progress/completed）
  findings: {...}               # → 事实黑板 upsert_project_fact（finding/chain/exploit/poc/）+ record_vulnerability
  attempted: [{action, result}] # → attempt_record 负知识（幂等键=资产+手法+前置）
  next_actions: []              # → 本轮计划 / info_entry_upsert（fp/ 功能点清单）
  blocked_by: ""                # → attempt_record（verdict=blocked）+ blocked 上报
  flags_found: []               # → upsert_project_fact（poc/ 或 finding/）
```

## 4. 高价值专家直觉

1. **同一套过滤逻辑往往复用在多个页面** — 一个点可绕过，类似页面通常也能绕过
2. **参数名本身也是攻击面** — WAF 经常只盯参数值，不盯参数名
3. **二阶漏洞非常常见** — 存储时安全 ≠ 读取后进入危险上下文时安全
4. **BOLA 的本质是"有认证、无授权"** — A/B 账号切换重放是核心验证方法
5. **老版本接口最容易漏补丁** — v2 修了不代表 v1 下线了
6. **业务逻辑漏洞回报最高** — 难以被扫描器发现，容易长期存在
7. **Race Condition 优先测"一次性"操作** — 优惠券、领取、重置、邀请、试用、库存扣减
8. **JWT 攻击先看密钥与算法上下文** — 不盲试 payload，先确认 alg/kid/JWKS/密钥来源
9. **Filter 存在 = 漏洞存在** — 开发者尝试修补说明该点曾有问题，追踪整个应用的同类过滤
10. **优先攻击边界交叉点** — 不同系统/模块/权限级别的交接处最容易出问题

## 5. references 按需加载索引

| 需要什么 | 加载 |
|---|---|
| 端口/漏洞/提权 → 工具自动路由 | `references/tool-decision-trees.md` |
| Flag/凭据/Shell 自动识别 + 失败分类与策略切换 | `references/loot-and-failure.md` |
| First-Pass payload + 2025-2026 WAF bypass（XSS/SQLi/SSRF/SSTI/命令注入/JWT/竞态/反序列化） | `references/payloads-2025-2026.md` |
| 2025-2026 高危 CVE 速查 + OWASP 2025 + 攻防趋势 | `references/cve-fast-table-2025-2026.md` |
| SRC 实战链（WAF 路径规范化/GraphQL 未授权/OIDC ATO/Token 跨域/报告方法论） | `references/src-playbook.md` |
| 47 攻击专题索引 + 本仓库技能映射 | `references/skill-index.md` |

> WAF 绕过的完整知识库（协议层/编码/分漏洞类型/各 WAF 弱点地图/Ghost Bits）用 search_knowledge_base（risk_type=srcall）检索。
> 深度专题（47 包）优先用本仓库同名技能（映射表见 skill-index.md），未导入的再考虑补齐。
