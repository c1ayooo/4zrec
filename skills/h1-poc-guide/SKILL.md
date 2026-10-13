---
name: h1-poc-guide
description: "H1 PoC 实战索引：按触发信号定位攻击打法。基于 HackerOne 已披露赏金报告提炼的类型优先级、场景速查表、八大攻击模式与近年新趋势（2023-2026）。"
version: 1.0.0
author: c1ayoo
platforms: [linux, macos, wsl]
metadata:
  roles: [渗透测试]
  stages: [web, api, exploit, src]
  hermes:
    tags: [cybersecurity, poc, hackerone, methodology, signal-map, pentest]
    category: cybersecurity
---

# H1-PoC 实战索引

> 来源：HackerOne 全部已披露赏金报告（8,436 份，2013–2026，含完整 PoC 正文）提炼。
> 数据全集统计：resolved 84.5% / informative 9.8% / duplicate 2.6%；有赏金 5,558 份（65.9%）；含 CVE 报告 1,386 份（1,557 个 CVE）。
> 用法：实战中先对照「场景速查表」定位信号 → 看对应 § 的 PoC 精选 → 提炼变体思路（PoC 会过时，变体思路不会）。
> 全套文档在平台知识库 `poc-h1-summary` 分类（00_索引 ~ 08_CVE反查表 9 项，已向量化）。

## 类型优先级（赏金率 × 高危率综合）

- 第一梯队（主动投入）：IDOR(84%)、访问控制(77%)、SSRF(76%)、反序列化(78%)、竞态(77%)、RCE(高危53%)、SQLi(高危62%)
- 第二梯队（靠链式升级拿高分）：XSS、信息泄露——单独提交定级低，必须打到 ATO 或实际数据（H1 high 以上 XSS 100% 演示了账号接管）
- 第三梯队（只作链条组件，不单独提交）：开放重定向、CRLF、CORS、安全配置缺失

## 场景速查表（实战信号 → 定位）

- 上传 jpg/tiff 后服务端剥离 EXIF → 03 §A（ExifTool DjVu payload）
- "从 GitHub/其他平台导入项目"功能 → 03 §B（假源服务器 + Redis 注入 + authorized_keys 覆写）
- Wiki/Markdown 渲染、图表（Kroki/Mermaid）→ 03 §C + 04 §B（Kramdown 选项 + 渲染过滤器 XSS）
- GraphQL/搜索 API 有自由字符串参数 → 03 §D（Painless/sift $where）+ 07 §C（Django ORM 结构注入）
- Java 栈、Kafka Connect REST、PHP 文件操作 → 03 §E（log4shell/Kafka JAAS/Phar）
- 解压 tar/zip、缓存 key、文件路径拼接 → 03 §F（symlink + Zip Slip + CI 缓存投毒）
- 爬虫/sitemap/文档解析功能 → 03 §G（OOB 参数实体 XXE）
- cookie 值回显进 HTML/JS → 04 §A（cookie 走私 + 持久化 XSS）
- IdP 登录、OAuth 回调、postMessage → 04 §D（response_mode 切换 + state 预制）+ 06 §I
- 更新接口带对象 ID、报错页回显对象 → 04 §F（删参数触发泄露分支）
- 模板/复制/导出导入项目数据 → 04 §G（权限继承 + 特权标志位）
- 改邮箱/手机号、OTP 登录 → 04 §H（响应篡改 + OTP 无限枚举）+ 07 §A（0-click/SCIM 错绑）
- 密码重置/MFA 流程带 JWT/state/设备指纹 → 07 §A（认证状态错绑 0-click ATO）
- SaaS 平台管理后台、GraphQL operation 名 → 07 §B（IDOR 2.0：业务动作造关联再回读）
- Django/ORM 动态 filter key → 07 §C（_connector/Q 对象/JSON path 注入）
- AI 助手抓网页/diff 作上下文 → 07 §D（LLM 提示注入，Brave Leo 案例）
- 富文本编辑器（Trix/CKEditor）+ sanitizer → 07 §D（mXSS 二次解析逃逸）
- CDN 后可缓存 .js 资源反射 cookie → 07 §D（拆分标签绕 WAF 缓存投毒）
- webhook/头像/import_url 等服务端代访 URL → 05 §A（DNS rebinding + git config 注入）
- CDN/反代后面、多动词接口 → 05 §D（CL.TE/TE.TE 走私矩阵 + 绝对 URI 外带）
- 列表接口 order/sort 参数、UA 头入库 → 05 §C（order by 盲注 + 算术验证时间盲注）
- 兑换码/邮箱确认/转账两步逻辑 → 05 §E（竞态窗口并发）
- 支付跳转包、订单 quantity 可改 → 05 §F（拼接签名重排 + 小数数量）
- 管理后台写 SMTP/DSN/路径配置 → 05 §G（配置文件注入 → RCE）
- 员工 GitHub 仓库、公开 CI 日志 → 06 §A/B（搜索语法 + token 验证 API）
- CNAME 指向 Vercel/Heroku/S3 的 404 子域 → 06 §C（接管指纹对照）
- 距离/最近的人功能 → 06 §E（三边测量翻转点定位）
- Node 应用 JSON filter 参数 → 06 §F（constructor.prototype 绕过黑名单）
- 老版本 Apache/Squid/Node 基础设施 → 06 §H（固定缓冲区/int 截断/realloc 野指针）
- 公网暴露的 Flower/Airflow/Jupyter/Grafana → 07 §D（运维面未授权清单）
- 遇到已知 CVE/Nday 想找利用细节 → 08_CVE反查表（1,483 CVE → 报告 ID）

## 八大高价值攻击模式

1. **解析差异链（Parser Differential）**：同一数据两层组件解析不一致。HTTP 走私（CL.TE/TE.CL/头名歧义）、Cookie 走私（按空格切分）、路径规范化差异。收益：劫持受害者请求窃凭据 → 批量 ATO。适用一切 CDN/网关+源站、多层中间件架构。
2. **OAuth/SSO 流程攻击**：response_type/response_mode 切换（IdP 未禁用）、state 攻击者预制、postMessage 伪造、redirect_uri 匹配缺陷、子域接管打认证域、`.json` 后缀路由绕过 CSRF。token 进 fragment 时排查所有读 `location.hash` 的同域 iframe。
3. **导入/渲染面 RCE**：GitLab 系列验证的黄金面：import（GitHub import、归档导入、BulkImports）+ 解析链（ExifTool/ImageMagick/Kroki/Kramdown）+ 文件名注入。测试姿势：自建假源服务器（ngrok + Flask 模拟第三方 API）。
4. **凭据泄露 → 横向渗透**：GitHub 员工仓库 → Slack token → 全内部频道；CI 日志 → Netlify/AWS 密钥；客户端二进制内嵌私钥。单点凭据 + "它能解锁什么"的横向演示 = high 升 critical 的写法。
5. **IDOR → 凭据升级**：IDOR 拿到"别人能看的"是 medium；拿到 API token/密钥/可写权限直接升 critical。同一对象多个入口（编辑/预览/summary/移动/复制）逐个测归属校验；"删参数触发不同校验分支"是经典手法。
6. **缓存投毒与同源跳板**：走私 X-Forwarded-Host 打缓存、登录 CSRF + datasource proxy 端点做二级同源跳板、text/plain + no-cors 绕 JSON API Content-Type 校验。
7. **协议级/内存级攻击**（IBB 基础软件专项）：Steam Server Query 缓冲区溢出、Apache 堆溢出、Node 资源耗尽。三件套：固定缓冲区 + 外部长度输入；int 截断（0x80000000）；realloc 后未刷新指针缓存。
8. **客户端攻击面**：Electron 桌面客户端、游戏 UI 引擎（Panorama XSS→RCE）、移动端 WebView（UXSS/会话恢复绕证书）、浏览器扫码/深链。客户端内置浏览器 JS 权限远超沙箱，XSS 即 RCE。

## 近年新趋势（2023–2026，打现代目标先看）

迁移路径：认证状态错绑（0-click）→ 业务动作造关联再回读（IDOR 2.0）→ ORM 查询结构注入 → 内容摄取管线攻击（AI/富文本二次解析/边缘缓存）。

- **0-click ATO**：找回密码/MFA 同时携带设备指纹、JWT/state；SSO/SCIM 将 username/email 分字段处理；复合 key 可拆分（`bot_key.split("-")` 空右值 → 命中空字段）。对每个认证流程分别替换 cookie/设备ID/JWT/state 验证跨账户拼接。
- **IDOR 2.0**：用自建低权限租户把全局用户 ID 接入奖励/邀请/评论/导出/审计事件，再从 GraphQL/审计日志回读资料。修复验证覆盖 API 响应、后台审计、邮件邀请、历史记录、缓存。
- **ORM 结构注入**：审计所有 `**request.data`、动态 lookup、`annotate/aggregate/values/order_by` 的字段名与 alias，不只审计值参数。迁移：Sequelize order 数组、TypeORM where key、Rails reorder。
- **AI 提示注入**：对 AI 功能分别测网页、附件、代码 diff、检索文档中的间接提示词，验证能否驱动工具调用、越权读取或外带（Brave Leo 案例：恶意 PR patch → 模型上下文劫持）。
- **mXSS**：富文本 sanitizer 必测"解析—清洗—序列化—再次插入"的 namespace mutation，不只看首次 DOM（Trix data-trix-attachment → math/mglyph → img onerror）。
- **缓存投毒拆分标签**：服务端移除引号而 WAF 未匹配拆分标签（`<svg/onloa"d=...`），HttpOnly 会话仍可从 `window.INITIAL_STATE` 取得。
- **运维面未授权**：Celery Flower、Airflow、Jupyter、Grafana（匿名面板）、K8s Dashboard 清单排查。

## 报告公式（付费报告共同结构）

```
标题 = 具体功能 + 漏洞类型 + 业务影响
正文 = 复现步骤（可复制粘贴请求）→ 实际拿到什么数据/权限 → 规模化演示（批量/一键/无交互）→ 修复建议
```

高分三硬指标：**可复制**（每步请求贴出）、**有实锤**（截图展示 token/数据）、**能放大**（批量影响或完整 ATO 链）。避免 informative 通病——只证明"存在"不证明"影响"。

## 必测功能 / 必查资产清单

- 必测：导入/导出、模板复制、文件解析预览、图表/公式渲染、webhook/回调配置、密码改绑流程、OAuth 绑定流程、支付回调、优惠码/提现接口、站点爬虫/sitemap 解析、CI 日志、头像/图片转码
- 必查：员工 GitHub（Releases/Gist/npm 误发包）、公开 CI 日志、失陷子域（can-i-take-over-xyz 指纹）、云元数据端点、客户端二进制（asar extract / strings）、非生产环境域名、`.json` 后缀路由变体、GraphQL filter/sort 参数

## 知识库检索

全套文档在平台知识库 `poc-h1-summary` 分类：
- 00_索引（速查表全集）/ 01_方法论 / 02_分类总览（26 类型统计+代表报告）/ 03-06 PoC 精选 / 07 近年趋势 / 08_CVE反查表（1,483 CVE → 报告 ID）
- 语义检索：按触发信号提问（如"webhook 导入 SSRF 变体"），命中对应 § 后回读原文核对 payload 特征串。
- CVE 反查：`08_CVE反查表.md` 中搜 CVE 号定位原报告 ID。

## 学习路径

fransrosen（OAuth 系列 25 篇）→ defparam（HTTP 走私）→ GitLab 全部 critical（现代 web RCE 模式库）→ vinnievan（协议 fuzzing）。类型目录 → 高票排序 → 逐篇读原文。
