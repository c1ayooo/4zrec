---
name: attack-surface-decompose
description: >-
  七层攻击面树分解（docs/深度与覆盖统一增强方案 §七）：把扁平目标拆成 L1 资产→L2 服务→L3 接口→L4 参数→L5 身份→L6 业务流→L7 组合 七层，每层产出落信息黑板（info_entries functional_point）+ 事实黑板（upsert_project_fact surface 分层）+ 假设（info_hypothesis_gen）。Use when starting a new target, building the attack surface inventory, or before deep testing — 测站第一步建清单。
metadata:
  roles: [信息收集, 渗透测试]
  stages: [recon]
  tags: [渗透测试, 信息收集, 攻击面, 分解]
---

## 七层攻击面树（目标分解器）

**为什么必须先分解**：多数「深度不够」是 L3/L4 层从未被枚举——目录爆破出了路径，但没人把路径里的每个参数当独立目标测。把参数级与业务流级显式化，深度自然下沉。

**硬约束**：没有明确目标与范围边界 ⇒ 禁止执行，先返回缺失字段清单（目标标识 URL/IP:Port/域名、授权范围、成功标准）。授权范围外的目标只记 Fact 供扩范围，不探测。

**分板纪律**：清单进信息黑板（info_entry_upsert，fp/<host><path>）、结论进事实黑板（upsert_project_fact，surface=asset/service/endpoint/param/identity/flow/chain）、可交付漏洞进 record_vulnerability。每枚举一个功能点落一条 fp/ 项（测一个回填一个）。

### 分解流程（每层做什么 → 产出什么）

```
L1 资产     域名/IP/网段/代码仓库/云账号/移动包 → target_scope 确认 + tgt/ 分母
            ★ 主动枚举主力：subfinder/amass/dnsx/httpx/naabu + traffic_endpoints 流量派生
            ★ 云资产特征（OSS/S3/云函数域名）命中 → info_hypothesis_gen 生成对象存储等假设
L2 服务     端口·协议·产品·版本·中间件·管理后台 → 每服务 fp/<host>:<port> 项
            ★ 指纹命中组件 → 按栈选探针（Spring/Tomcat→spring-exploitation...）
            ★ 中间件/控制台/数据库面 → info_hypothesis_gen（actuator/druid/nacos/ES/Redis...）
L3 接口     HTTP 路由·API·GraphQL·WebSocket·RPC·上传点·消息端点 → 每接口 fp/<host><path> 项
            ★ 来源三条（按成本）：traffic_endpoints 流量派生（现成种子）→ 主动枚举（dirsearch/
              ffuf/arjun/katana）→ 模型推导（JS 提取/页面导航 web_navigate）
            ★ 高价值接口（认证/越权/上传/支付/回调）优先落清单，不做全站无差别入库
L4 参数     每个入参/header/cookie/JWT claim/反序列化点/模板注入点 → fp/<host><path>?<param> 项
            ★ arjun/paramspider 补隐藏参数；http_probe 多包对比测每个参数
            ★ 注入面（url/next/redirect/file/path 参数）→ info_hypothesis_gen（ssrf/path_traversal/...）
L5 身份     匿名·普通用户·管理员·服务间·跨租户·云角色 → auth/<host>/<identity> 事实 + 假设
            ★ 登录墙/SSO/OAuth/JWT → info_hypothesis_gen（login_wall/jwt/oauth/sso）
L6 业务流   注册→登录→下单→支付→审批→导出：越权·竞态·幂等·金额/状态篡改 → flow/<host>/<chain> 项
            ★ 模型推导（最值钱）：跨接口业务流程，目录爆破永远发现不了
            ★ 每段业务流按顺序枚举功能点（注册→登录→改密→下单→支付→退款）
L7 组合     finding 组合升级·凭据复用·内网横向·持久化 → chain/<host>/<name> 项
            ★ 命中链式前置（heapdump/.git 可读/未授权中间件/可上传）→ info_hypothesis_gen 整条链
            ★ 深度阶梯：L1 存在→L2 可达→L3 可利用→L4 影响→L5 链式→L6 横向（授权+HITL）
```

### 工具映射（对号入座，优先专用工具）

| 层 | 专用工具 | 兜底 |
| --- | --- | --- |
| L1 资产 | subfinder/amass/dnsx/httpx/naabu/recon_run/port_scan | exec |
| L2 服务 | fingerprint_scan/nmap/whatweb/component-vuln-intel | exec |
| L3 接口 | web_navigate/katana/dirsearch/ffuf/arjun/api-schema-analyzer | exec |
| L4 参数 | arjun/paramspider/http_probe/sqlmap/dalfox | exec |
| L5 身份 | jwt-analyzer/graphql-scanner/http_probe | exec |
| L6 业务流 | http_probe（多包对比）/browser_interact（表单流） | exec |
| L7 组合 | 各利用工具 + attempt_record（死路记账） | exec |

### 清单来源三条（按成本升序）

1. **流量派生（最省，种子现成）**：`traffic_endpoints` 的 `method + host + path_norm + query_keys` 转成 `functional_point` 项。
2. **主动枚举（主力）**：dirsearch/ffuf/arjun/katana 的产出归一落库。不新建能力，只把现成工具接上落库。
3. **模型推导（最值钱，最晚做）**：跨接口业务流程（下单→支付→退款、注册→登录→改密）——目录爆破永远发现不了。

### 导入纪律

- **首版只灌高价值功能点**（认证/越权/上传/支付/回调类），**不要把 dirsearch 输出无差别倒进信息黑板**——清单被噪声淹没后模型同样不看。
- 每枚举一个功能点落一条 fp/ 项（批量 info_entry_upsert，勿逐条散打被迭代上限卡死）。
- 每 host 功能点数合理上限：高价值面优先，宁少勿滥。

### 收口与交接

- 分区收口：每 host 的 fp/ 项测完回填（info_entry_update tested/skipped/blocked），该 host 全收口才进下一个。
- 假设验证：「有假设没验证」也是漏——info_hypothesis_gen 生成的假设逐条验证回填。
- 交接包四要素：已完成（已枚举层/端口/接口结论）/ 本轮只做 / 素材路径 / 专家匹配（验证/利用交对应专项子代理）。
