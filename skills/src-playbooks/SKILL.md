---
name: src-playbooks
description: |
  Web 渗透测试漏洞验证手法库：「打穿短表」一行一枪索引 + 48 篇模块（越权/IDOR、注入、XSS、SSRF、文件上传与对象存储、业务逻辑、竞态、请求走私、GraphQL、OAuth/JWT、WebSocket、缓存投毒、WAF 绕过、JS 逆向、云 IDE RCE 链等），每篇带「认什么/打哪/出什么算成/什么算假点」四栏对照。任务进入漏洞测试与验证阶段时调用：不知道下一枪打哪、按目标特征挑手法、验证可疑点、需要假点甄别时都用本库。进站先读短表，对得上再开对应模块，禁止整库通读。
mcps: browser, js-reverse
---

# SRC 漏洞验证手法库（打穿短表 + 48 篇模块）

你是当前任务授权范围内的渗透测试执行者。本技能是手法参考库：先查索引、对得上再开模块，不要每站通读。

## 授权边界（ARTEX 项目围栏 · 不可违反）

1. **一切目标以当前任务所属项目的授权范围为准。** 项目围栏拒绝了某个出网目标 = 该目标不在授权范围内：立即停手，换范围内的资产继续，**不要**尝试绕过、换工具重试或自行扩面。确需放宽范围，向操作者说明理由，由人在项目页调整授权范围后继续。
2. 任务未挂项目（无授权根）时只做被动侦察与分析，不做主动漏洞验证。
3. 禁止破坏性利用、禁止真实资损操作、禁止批量改删他人数据。
4. FOFA/测绘类查询只用于核对授权范围内资产；范围外关联资产（子公司、同皮壳站）记录并上报操作者，不在本任务自动扩打。

## 伤害最小化红线（涉及写操作时）

- 默认用**读/列表差分**证明跨用户/跨租户（优先 GET/查询类探针）。
- 写越权仍要测，顺序：**先添加**（挂到自己名下）→ **再删除自己刚加的那条**。不改/删别人已存在的订单、地址、密码、角色。
- 只能动现成对象时：只改自己能改回去的测试字段，打一次就停，过了立刻改回；改不回就停在回包留证。
- **禁止登出/注销/吊销令牌**（`/logout`、`/signout`、`/revoke` 一律不调），保持操作者提供的会话全程有效。

## 进站打法

1. **先说清这摊**：目标是什么业务、什么架构、有哪些入口（主站/小程序/App API/后台）。
2. **JS 抽接口和钥匙**：不只抽 `/api/` path——盐、密文 id 公钥、hidden/admin 路由、写死的演示号都进清单（细节见 `references/js-reverse-guide.md`）。
3. **回包进队列**：发现的接口/路径/参数记录进任务清单，逐个消化。
4. **有号走对象图/换 id**：拿到会话后画对象图（自己的订单/地址/资料），换 id、哨兵值（`0`/`-1`/空）、密文 id 相邻数；**没号打未登录的差分面**（认证绕过、未授权读、注入、SSRF、上传）。
5. **全类型矩阵过一遍**：越权/未授权敏感读/逻辑/凭证/弱口令/认证会话/上传链……现场有什么打什么。注入/SSRF/XSS/RCE 是「有差分面必须真打」，**不是**只测这四类，也不是每个 path 喷 `'`。

## 优先级

力气先砸在**有差分面**的地方：能看出条数/内容/状态变化的口。中危升链、深挖优先；空窗时回短表换枪，不空转。发现需要扩大范围才能继续时，回到「授权边界」第 1 条处理。

## 按目标特征挑模块（references/）

| 目标特征 | 优先模块 |
|---------|------------|
| 有用户体系（注册/登录） | `idor-test.md`（越权）+ `authbypass-test.md`（任意登录/接管） |
| 有搜索/筛选功能 | `injection-test.md`（注入） |
| 有文件上传 | `file-upload-test.md`（含对象存储 STS/桶策略/签名链） |
| 有内容请求/预览功能 | `ssrf-test.md` |
| 有评论/留言/富文本 | `xss-test.md` |
| 有支付/优惠券/积分 | `logic-test.md` + `race-condition-test.md` |
| 接口返回字段多 | `info-leak-test.md` |
| GraphQL 接口 | `graphql-test.md` |
| OAuth/JWT/SAML 认证 | `oauth-jwt-test.md` |
| WebSocket 实时通信 | `websocket-test.md` |
| API 网关/微服务架构 | `api-gateway-test.md` |
| CDN/缓存服务 | `cache-poisoning-test.md` |
| AI/LLM 功能 | 对话口工具真执行走 `agent-tool-exec-test.md`；**不开** `llm-security-test.md` 越狱教材 |
| 云 IDE / Codex / AI 编程台 | `cloud-ide-codex-rce-chain.md`（弱口令→RPC RCE→集群/API Key 链） |
| 前后端分离架构 | `http-smuggling-test.md` |
| 返回 401/403 | 先分清登录页还是业务 API：登录页按「进站打法」找业务面，**不磨登录 HTML**（401-403-bypass 已收成一行）；业务 API 的 401/403 现场改 path/METHOD/头自己打 |
| 公网已见 Redis/rsync/FPM/AJP/YARN/2375/h2-console | `info-leak-test.md`（见了才打，不先 nmap 全端口）+ 对应 `ssrf`/`jndi`/`path-traversal` |
| 有 CORS / 跨域接口 | **跳过**（本库约定：SRC 不挖 CORS，不开 `cors-test.md`）；转注入/越权等 |
| 有状态变更写操作 | `csrf-test.md` |
| 有 WAF 拦截 | 有差分面的参被拦再开 `waf-bypass.md` 换编码/换位置；禁止开场对每个 path 丢 `'` 当 WAF 检测 |
| 路径/下载/读文件 | `path-traversal-lfi-test.md` |
| XML / 文件解析 | `xxe-test.md` |
| Java 反序列化 / 中间件 | `deserialization-test.md` + `jndi-injection-test.md` |
| 子域/资产接管线索 | `subdomain-takeover-test.md` |
| Host / 缓存 CDN | `http-host-header-test.md` + `cache-poisoning-test.md` |

**nuclei 是辅助不是主路径**：只在需要已知 CVE/暴露面（actuator、swagger、已知中间件）时收窄模板用；禁止「全量模板扫一遍」当测试矩阵或进度。

## 用法约定

- 模块文件都在 `${SKILL_DIR}/references/`，模块间互链直接跟随；完整清单见 `${SKILL_DIR}/references/README.md`。
- 文件不长整篇开；超长篇先开点名节，不够再继续。短表点名的手法用标题搜。
- 短表和四件套都不是上限：表上没有的手法照样挖。实战中验证成立的新手法、新「假点」可以补充进短表（保持一行一枪格式）。
- 报告：确认的漏洞走平台报告流程（report-generation）；写清「认什么/打哪/出什么算成/假点」对照，密钥/token 实值只进报告不进短表。

---

> 来源：社区分享的 Grok CLI SRC 挖掘技能包知识库部分（2026-08 版），2026-10-16 移植适配 ARTEX 项目围栏语境。原文的自动化节奏、FOFA 扩面、默认授权与反盘问措辞已移除——一切范围决策以项目授权范围与平台人工审批为准。
