---
name: 4zrec-api
description: 通过 4zrec 的 HTTP API 管理授权项目与范围、创建/暂停/恢复任务、批量审批与探活资产、导出漏洞与报告。供 Hermes 等外部调度 agent 操作 4zrec 平台使用。
allowed-tools: Bash(curl:*)
---

# 4zrec API 操作手册（Hermes）

4zrec 是授权渗透测试平台。外部 agent 只走 HTTP API，不直接碰数据库/文件系统。

## 0. 连接与安全

- `BASE_URL` 默认 `http://127.0.0.1:8787`（API 与 Web 同端口）。**8788 是流量录制代理，不是 API。**
- 除 `/api/auth/*`、`/api/health` 外，所有 `/api/*` 都要 `Authorization: Bearer <JWT 或持久 API Key>`。
- **推荐 Hermes 用持久 API Key**（不过期或长有效期），不要长期持有登录 JWT；项目级 key 只能访问绑定项目。
- token/密码只放环境变量；不要写进日志、报告、聊天记录或代码提交。
- 只操作明确授权的项目。范围外目标会被平台围栏拦截，不要尝试绕过。

```bash
BASE="${4ZREC_BASE:-http://127.0.0.1:8787}"
TOKEN="${4ZREC_TOKEN:?需要 4ZREC_TOKEN（JWT 或 zrec_ 开头的 API Key）}"
AUTH="Authorization: Bearer $TOKEN"
JSON="Content-Type: application/json"
```

## 1. 健康检查与登录

```bash
curl -s "$BASE/api/health"            # {"ok":true,"service":"4zrec","version":"..."}
curl -s "$BASE/api/auth/status"       # {"initialized":true,"username":"4zrec"}

# 账号密码登录（JWT 有效期 7 天；用 python3 解析，避免依赖 jq）
TOKEN=$(curl -s -X POST "$BASE/api/auth/login" -H "$JSON" \
  -d '{"username":"4zrec","password":"<PASSWORD>"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
```

401 = token 过期/未带；重新登录。浏览器直接打开下载链接时走 `artex_token` cookie，脚本用 Bearer 头。

### 1.1 持久 API Key（Hermes 推荐）

用登录 JWT 创建一次，之后 Hermes 长期持有 `zrec_…` 明文（库里只存哈希）：

```bash
# scope=project 只能访问 project_id 绑定项目；scope=global 全平台
curl -s -X POST "$BASE/api/api-keys" -H "$AUTH" -H "$JSON" -d '{
  "name":"hermes-huya",
  "scope":"project",
  "project_id":7,
  "expires_in_days":365
}'
# → {"key":{...},"token":"zrec_..."}   token 只返回这一次，立即保存
```

- 使用：`Authorization: Bearer zrec_...` 或 `X-API-Key: zrec_...`。
- 前端也可手工创建：**系统 → 平台配置 → API 密钥**（`/system/api-keys`），支持全局/项目级、有效期与撤销。
- 管理（仅全局 JWT/全局 key 可用）：`GET /api/api-keys`、`DELETE /api/api-keys/{id}`。
- 项目级 key 的边界：
  - 只能看/操作绑定项目的 `projects / tasks / assets / findings / intercept`；
  - 跨项目任务返回 404，跨项目审批/资产/导出返回 404/403；
  - LLM/设置/Agent/工具/MCP/API Key 管理一律 403。

## 2. 项目 = 授权根

项目持有授权范围（围栏白名单），任务/对话/资产都挂在项目下。

```bash
curl -s "$BASE/api/projects" -H "$AUTH"
curl -s -X POST "$BASE/api/projects" -H "$AUTH" -H "$JSON" \
  -d '{"name":"虎牙src","description":"huya.com 授权测试"}'

# 录入授权范围：一行一条，换行分隔；返回 {added,skipped,invalid,errors,claimed}
curl -s -X POST "$BASE/api/projects/7/scope" -H "$AUTH" -H "$JSON" \
  -d '{"scope":"huya.com\n47.98.195.217","reason":"委托范围"}'
```

范围语法与语义：

| 输入 | 含义 |
|---|---|
| `example.com` | 根域 + 全部子域（`a.b.example.com` 也算） |
| `1.2.3.4` | 单 IP（内部按 /32） |
| `10.0.0.0/16` | CIDR；IPv4 必须 ≥ /16，IPv6 ≥ /32 |
| `京ICP备...` / 关键词 | 仅提示，不参与围栏 |

- 追加范围会把**本项目已有 pending 资产中命中新范围的**自动翻成 approved（响应里的 `claimed`）。
- 其他接口：`GET /api/projects/{id}/scope/candidates`、`POST /api/projects/{id}/scope/import {domains:[...]}`、`DELETE /api/projects/{id}/scope/{sid}`。
- 范围是**主机级**，不含端口；端口写在任务目标/描述里。

## 3. 创建与控制任务

```bash
curl -s -X POST "$BASE/api/tasks" -H "$AUTH" -H "$JSON" -d '{
  "name":"虎牙src",
  "description":"对 huya.com 授权资产做渗透测试，先探活确认归属",
  "goal":"确认资产归属并获取可复现有效漏洞",
  "project_id":7,
  "seed_first_intent":false
}'
```

- `project_id` 必填才是“挂项目”；任务创建时把项目范围**快照**进 `task_scope`（source=project）。
- `seed_first_intent=true` 会跳过首轮 planner 直接派种子意图（适合 CTF/单意图）。
- 返回的 `id` 是字符串；创建后异步启动，无需额外 start。

```bash
curl -s "$BASE/api/tasks" -H "$AUTH"                  # {tasks:[...], active}
curl -s "$BASE/api/tasks/167" -H "$AUTH"
curl -s -X POST "$BASE/api/tasks/control/batch" -H "$AUTH" -H "$JSON" \
  -d '{"task_ids":["167"],"action":"pause"}'          # action=pause|resume

# 任务级范围（kind=root_domain|subdomain|ip|cidr|company）
curl -s "$BASE/api/tasks/167/scope" -H "$AUTH"
curl -s -X POST "$BASE/api/tasks/167/scope" -H "$AUTH" -H "$JSON" \
  -d '{"kind":"subdomain","value":"api.huya.com","reason":"人工补充"}'
```

注意：任务范围是**创建时快照**；之后改项目范围不会自动同步到已建任务。worker 插入新资产时会自动累积 `source=auto` 的 task_scope。

## 4. 资产、待审批与探活

```bash
# 资产列表（type=root_domain|ip|subdomain|service|app|endpoint；project_id 为归属筛选）
curl -s "$BASE/api/assets?project_id=7&type=ip&limit=100&offset=0" -H "$AUTH"

# 待审批队列（范围外发现的资产；批准前不可测）
curl -s "$BASE/api/assets/pending?project_id=7&limit=500&offset=0" -H "$AUTH"
```

每个资产的关键字段：

| 字段 | 用途 |
|---|---|
| `authz` | `approved` / `pending` / `rejected`；空=视为 approved |
| `source` | 出处：`Quake` / `FOFA` / `agent` / `manual` |
| `extra.source_query` | 测绘查询语法，如 `cert:"huya.com"`（新导入才有） |
| `bound_domains` | 解析到该 IP 的域名 |
| `task_ids` | 发现它的任务 |

### 探活 / 归属线索（批准前必做）

```bash
curl -s -X POST "$BASE/api/assets/probe" -H "$AUTH" -H "$JSON" \
  -d '{"ids":[15263,17934],"project_id":7}'
```

返回每个资产：`alive`、`ports`、`ptr`、`cert_names`、`http_status`、`server`、`title`、`ownership`。

- 只做无害探测：TCP connect（80/443 + 记录端口）、TLS 证书 CN/SAN、PTR、`GET /`。
- `ownership` 非空（如「证书 SAN 含授权域 huya.com」）是强归属线索；只有存活没有归属线索的（CDN 未绑定节点）谨慎批准。

### 批量批准 / 拒绝入库

```bash
# approve = 授权入库并归属项目（project_id 可选，0=只授权不归属）
curl -s -X POST "$BASE/api/assets/authz" -H "$AUTH" -H "$JSON" \
  -d '{"ids":[15263,17940],"action":"approve","project_id":7}'
# reject / 退回待审批：action=reject|pending
```

不变量：范围命中=approved；范围外=pending；**rejected 是终态**，范围命中也不会翻回；批准/归属只升不降。

## 5. 围栏审批（agent 执行时挂起的 ask）

```bash
curl -s "$BASE/api/intercept/pending?project_id=7" -H "$AUTH"
curl -s "$BASE/api/intercept/project/7" -H "$AUTH"       # 项目维度审批历史
curl -s -X POST "$BASE/api/intercept/pending/139/decide" -H "$AUTH" -H "$JSON" \
  -d '{"decision":"allowed","targets":["aiface.fanyunedu.com"]}'
```

- `targets` 是围栏审批里的**未授权目标子集**：勾选哪些就授权哪些；不传=全部登记 approved；显式 `[]`=一个都不授权（本次仍允许执行）。
- 在资产待审批队列批准资产后，因该目标挂起的围栏 ask 会自动放行（无需二次审批）。

## 6. 漏洞与导出

```bash
curl -s "$BASE/api/exploration/findings?task=167" -H "$AUTH"          # 某任务
curl -s "$BASE/api/exploration/findings?page=1&limit=50" -H "$AUTH"   # 全局分页
curl -s "$BASE/api/exploration/findings/273" -H "$AUTH"

# 单条导出 md/docx（脚本用 Bearer；浏览器直链用登录 cookie）
curl -s -OJ "$BASE/api/exploration/findings/273/export?format=md" -H "$AUTH"

# 批量导出：scope=selected&ids=1,2 或 scope=filtered&severity=high...
# format = md-single | md-zip | csv | json（单条导出的 format 才是 md|docx）
curl -s -OJ "$BASE/api/exploration/findings/export?format=md-single&scope=selected&ids=273,274" -H "$AUTH"
```

报告（任务级）：

```bash
curl -s "$BASE/api/report/status?task=167" -H "$AUTH"
curl -s -X POST "$BASE/api/report/generate?task=167" -H "$AUTH"
curl -s -OJ "$BASE/api/report/download?task=167" -H "$AUTH"
```

## 7. 执行侧规则（Hermes 必须知道）

- **资产围栏**：任务挂项目后，agent 的 Bash/WebFetch 出网命令逐目标判定——项目范围 ∪ 本项目 approved 资产放行；范围外合成审批（阻塞）；黑名单硬阻断。回环/本机地址按设计不拦。
- **平台工具 RoE**：`http_probe`、`port_scan`、`unauth_probe` 等与围栏同源（范围 ∪ approved 资产），不要以为“工具比 curl 严”。
- **pending 资产不可测**：意图绑定、命令执行都会被拦；先在第 4 节批准。
- **http_probe 是 HTTP 首选**：单发/批量/`template+matrix|range`/`extract` 串行链/`cookie_jar`/`save_to_file` 都支持；curl 只在流式、原始报文、任意脚本处理、mTLS、非 HTTP 协议时使用，并说明原因。
- **测绘噪音过滤**：空间测绘导入会丢弃公共 DNS/基础设施（1.1.1.1、8.8.8.8…）、私网、回环、组播、保留/文档/基准网段；它们不会进待审批。
- **任务范围快照**：项目范围改后，已建任务不自动同步；需要时用第 3 节的 task scope 接口。

## 8. Hermes 推荐编排流程

1. `GET /api/health` → 使用持久 API Key（`zrec_…`，见 1.1）或登录拿 JWT。
2. `GET /api/projects` 找目标项目；没有就 `POST /api/projects` + `POST /api/projects/{id}/scope`。
3. `GET /api/assets/pending?project_id=` 拉待审批；`POST /api/assets/probe` 批量探活。
4. 按 `ownership` / `source` / `bound_domains` / `source_query` 判归属：
   - 强归属或范围命中 → `POST /api/assets/authz` 批量 approve；
   - 无归属线索的 CDN/公共 IP → reject 或保留待人工。
5. `POST /api/tasks` 建任务（project_id）。
6. 轮询 `GET /api/tasks`、`GET /api/intercept/pending?project_id=`；有 ask 按第 5 节决定。
7. 任务完成后 `GET /api/exploration/findings?task=`，需要时导出 md/docx 或生成报告。

## 9. 常见错误

| 现象 | 原因 / 处理 |
|---|---|
| `401 未授权` | 未带 Bearer / token 过期；重新登录或换 API Key。浏览器直链需 `artex_token` cookie |
| `403 项目级 API Key 无权访问该接口` | 该接口属于全局配置面；换全局 key 或 JWT |
| `404 task/finding not found`（项目 key） | 目标不属于 key 绑定的项目（平台不泄漏存在性） |
| `400 范围无效` | 裸 TLD、IPv4 小于 /16、IP 段写成 `a-b`（请用 CIDR） |
| `400 missing required property "url"`（http_probe） | 旧库 schema 残留；升级后已修复，批量模式可直接用 `requests`/`template` |
| 任务一直 `created` | 没配可用 LLM；`GET /api/llm/profiles` 检查激活配置 |
| pending 资产测不了 | 先批准；不要尝试绕过围栏 |
| 测绘 IP 只有 `Quake` 无查询 | 旧数据未记录 `source_query`；重跑同一 `space_search`（auto_import）会补全，不会重复建资产 |
