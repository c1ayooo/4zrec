# 攻击知识索引（47 Skills）与本地技能映射

> 本仓库已导入的主题技能对照：反序列化→`deserialization-testing`，命令注入→`command-injection-testing`，API→`api-security-testing`，LDAP→`ldap-injection-testing`，XPath→`xpath-injection-testing`，Java 生态→`spring-exploitation`/`fastjson-exploitation`/`shiro-exploitation`/`log4shell-exploitation`，认证/JWT/OAuth/SAML→`web-attack-methods`。SQLi/XSS/SSRF/XXE/文件上传/IDOR/业务逻辑/CSRF/WAF 等通用漏洞类的专项 skill 已收敛（打法统一从知识库检索：`search_knowledge_base` risk_type=srcall 按类取，如「sql 注入」「xss 存储」「ssrf 元数据」「上传 STS 桶策略」「idor 越权 换id」）；未列出的 47 深度包条目需要时导入。

## 3. 核心攻击知识索引（47 Skills）

### 3.1 侦察与方法论

| Skill | 核心能力 |
|-------|---------|
| **hack** | 总路由器、现象到技能映射、专家直觉 |
| **recon-for-sec** | 侦察阶段分类路由 |
| **recon-and-methodology** | 方法论框架、Java 中间件指纹矩阵、泄露检测清单 |

### 3.2 API 安全

| Skill | 核心能力 |
|-------|---------|
| **api-sec** | API 测试分类路由(REST/GraphQL/移动端) |
| **api-recon-and-docs** | API 发现、OpenAPI/Swagger、隐藏端点 |
| **api-authorization-and-bola** | BOLA/BFLA、批量赋值、对象级授权 |
| **api-auth-and-jwt-abuse** | JWT 攻击、API 密钥滥用、令牌操控 |
| **graphql-and-hidden-parameters** | GraphQL 内省、批量查询、隐藏参数 |

### 3.3 认证与授权

| Skill | 核心能力 |
|-------|---------|
| **auth-sec** | 认证测试分类路由 |
| **authbypass-authentication-flaws** | 密码重置 22 模式、验证码绕过 20 方法、不安全随机数 |
| **jwt-oauth-token-attacks** | JWT 算法混淆、密钥混淆、JWKS 滥用 |
| **oauth-oidc-misconfiguration** | OAuth 流程劫持、OIDC 配置错误 |
| **saml-sso-assertion-attacks** | SAML 断言篡改、SSO 绕过 |
| **idor-broken-object-authorization** | 8 类系统化 IDOR 测试、ORM 过滤链泄露 |

### 3.4 注入攻击

| Skill | 核心能力 |
|-------|---------|
| **injection-checking** | 注入测试分类路由 |
| **xss-cross-site-scripting** | Polyglot payload、WAF 绕过(Cloudflare/Akamai)、CSP bypass、DOM Clobbering |
| **sqli-sql-injection** | 多 DB 覆盖(MySQL/MSSQL/Oracle/PG/SQLite)、WAF bypass 矩阵、CTF 技巧 |
| **ssrf-server-side-request-forgery** | 云元数据 6 平台、DNS 重绑定、Gopher/Redis RCE 链 |
| **ssti-server-side-template-injection** | 15+ 引擎(Jinja2/Twig/EJS/Razor...)、盲注 SSTI、Flask PIN |
| **cmdi-command-injection** | WAF 绕过(通配符/xor)、PHP disable_functions 6 路径、组件级 RCE |
| **nosql-injection** | 盲注自动化、聚合管道注入、$where JS 执行 |
| **xxe-xml-external-entity** | 本地 DTD(Win/Linux/JAR)、盲 XXE、Gopher/FTP OOB |
| **deserialization-insecure** | Java/PHP/Python/Ruby/.NET/Node.js 反序列化链 |
| **expression-language-injection** | SpEL、OGNL、Java EL 注入及 RCE 链 |
| **jndi-injection** | JNDI/LDAP/RMI 利用、Log4Shell 模式 |
| **crlf-injection** | 头注入、HTTP 响应拆分 |
| **request-smuggling** | CL.TE/TE.CL/TE.TE 8 种混淆、HTTP/2 降级走私 |
| **prototype-pollution** | Express 黑盒探测、EJS/Kibana Gadget 链 |
| **type-juggling** | PHP 松散比较表、Magic Hash、HMAC 0e 暴力 |
| **http-parameter-pollution** | 9 平台服务器行为矩阵、HPP+WAF 组合 |
| **xslt-injection** | 三条 RCE 链(PHP/Java/.NET)、EXSLT 写文件 |
| **csv-formula-injection** | DDE/rundll32 payload、Google Sheets 外带 |

### 3.5 文件与路径攻击

| Skill | 核心能力 |
|-------|---------|
| **file-access-vuln** | 文件访问测试分类路由 |
| **path-traversal-lfi** | LFI→RCE 7 路径、PHP Wrapper 矩阵、pearcmd 四法 |
| **upload-insecure-files** | 编辑器路径矩阵、验证缺陷五维分类、解析技巧 |

### 3.6 业务逻辑与会话

| Skill | 核心能力 |
|-------|---------|
| **business-logic-vuln** | 业务逻辑测试分类路由 |
| **business-logic-vulnerabilities** | 支付篡改 10 种攻击、状态机绕过、优惠券竞态 |
| **race-condition** | TOCTOU、HTTP/2 单包攻击、Turbo Intruder 模板 |
| **csrf-cross-site-request-forgery** | JSON CSRF 三技术、Multipart CSRF、CSPT2CSRF |
| **clickjacking** | Frame 攻击、X-Frame-Options/CSP 绕过 |
| **cors-cross-origin-misconfiguration** | Origin 反射、null origin、子域信任滥用 |
| **open-redirect** | 重定向链滥用、Tabnabbing |
| **web-cache-deception** | 路径混淆、缓存键操控 |

### 3.7 基础设施与供应链

| Skill | 核心能力 |
|-------|---------|
| **unauthorized-access-common-services** | 服务暴露清单、Nginx off-by-slash、X-Forwarded-For 信任 |
| **insecure-source-code-management** | .git/.svn/.hg 恢复、备份文件模式 |
| **dependency-confusion** | npm/pip/gem 公共注册表劫持 |
| **websocket-security** | CSWSH、Origin 验证、wsrepl 工具链 |

---

---

## 8. 深度 Skill 加载指引

当需要某个攻击类型的深度知识（完整 payload 库、WAF bypass 矩阵、场景化利用链）时，加载对应深度文档：

```
skills/<skill-name>/SKILL.md（47 深度包未导入的条目需先放入 skills/ 同名目录）
```

例如：
- XSS 深度：`xss-cross-site-scripting/SKILL.md`（368行 + SCENARIOS.md 278行）
- SQLi 深度：`sqli-sql-injection/SKILL.md`（475行 + SCENARIOS.md 575行）
- SSRF 深度：`ssrf-server-side-request-forgery/SKILL.md`（314行 + SCENARIOS.md 226行）
- 反序列化：`deserialization-insecure/SKILL.md`（714行，覆盖 Java/PHP/Python/.NET/Node.js）
- 路径穿越：`path-traversal-lfi/SKILL.md`（603行，LFI→RCE 完整路径）

完整 47 个 skill 目录位于：
```
skills/
```

---
