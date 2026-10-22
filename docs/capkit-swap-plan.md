# 漏洞情报能力迁到 capkit：分阶段切换方案

> 状态：**方案 + 已完成的接入部分**。下面的阶段 1 已落地；阶段 2 起是待执行项，
> 每阶段都可独立回滚。
>
> 背景：`internal/capability/vuln/vulnintel/` 目前自己实现抓取（`grab/`）、
> 分析（`analyzer.go`）、模板（`tplgen.go`）、指纹（`fpgen.go`）、PoC（`pocgen.go`）。
> capkit 侧已有对应能力（`kits/vulnintelkit`、`kits/pockit`、`kits/bindingkit`）。
> 目标是把实现收敛到 capkit 一份，4zrec 只留适配层。

## 为什么不能直接删掉本地实现

四条事实（都是可验证的，不是感觉）：

1. ~~capkit 的 9 个源没有对真实网络验证过~~ **已更新（2026-10-20）**：加了
   `go test -tags live -run TestLiveSources` 对真实端点验证，首跑 4/9 可用，
   修完后 **8/9 可用**（两次复跑一致）。唯一不可用的是 aliyun-avd——该站对所有路径
   返回反爬 JS 挑战页，非浏览器拿不到数据。所以「源能用」这条不再是阻塞项，但
   **AVD 必须先决定怎么处理**（见阶段 2）。
2. **两边的 `unique_key` 生成规则不同**。`vuln_intel.unique_key` 有唯一约束，
   `UpsertVulnIntel` 走 `ON CONFLICT (unique_key) DO UPDATE`。键一变，同一份情报
   在新旧两套里就是两行；如果新键推导不出来（见下表 seebug/venustech），还会
   每轮抓取都插一行。
3. **capkit 的 PoC 此前比本地弱**（已修正，见阶段 0）。本地 `pocgen.go` 是「模型填
   要素、代码拼脚本」；capkit 原本让模型直接写整段脚本。
4. 本地实现此刻正被并发修改（`git status` 里 `analyzer.go`/`fpgen.go`/`tplgen.go`/
   `pocgen.go` 都是 M/A 状态），边改边删会丢别人的工作。

## 阶段 0（DONE）：capkit 的 PoC 补齐到同等强度

- `poc_generate` 改为只向模型要 `poc_spec`（入口/方法/参数/判定特征），脚本由
  `kits/pockit/pocscript.go` 拼装。
- 接地校验：入口路径与响应特征必须能在情报原文里找到出处，否则不产出脚本
  （`poc: null` + `poc_note`）；参数名不接地只降级为提示。
- 骨架只用标准库 `urllib`（不依赖 `requests`），并有 `python3 -m py_compile` 实编译测试。
- 新增 `poc_script_build`：人工改完要素后不调模型重建，接地规则同样生效。
- 与本地 `pocgen.go` 的差异：capkit 版本多了 `body_format: json`（本地只有 form）、
  判定要求**全部** marker 命中（本地是任一命中），更保守。

**这一阶段的结论：capkit 的生成能力已不弱于本地，可以开始谈替换。**

## 阶段 1（DONE）：capkit 以原生工具形式接入

- `go.mod` 加 `replace github.com/c1ayooo/capkit => /home/c1ay/capkit`（**本地开发用，
  发布前必须换成已发布版本号**，例如 `v0.5.0`，并删掉 replace）。
- `internal/capkitbridge/bridge.go`：按端口条件注册——有 `Fetcher`+`Intel` 才注册
  `vulnintelkit`，有 `Completer`+`Artifacts` 才注册 `pockit`，`bindingkit` 无条件注册。
  这样没配模型的环境不会连带丢掉会话工具。
- 适配层：
  - `internal/platform/server/capkit_intel_store.go` — `core.IntelStore` 落到
    `vuln_intel` 表（tags/refs 存 JSON 文本，检索映射到 `ListVulnIntel`）。
  - `internal/platform/server/capkit_artifacts.go` — `Completer` 包
    `vulnPipelineComplete`；`ArtifactStore` 是文件系统，根在 `data/intel-drafts`，
    `resolve()` 拒绝绝对路径、`..` 和任何逃出根目录的名字。
- 验证：`internal/capkitbridge/intel_bridge_test.go` 5 条集成测试（工具暴露、
  端口缺失时不注册、`binding_check` 折叠产品名、`vulnintel_poll` 写穿到宿主 store、
  通用指纹被拒）。

此时 capkit 的工具和本地流水线**并存**，互不影响。这是有意的：下一步要拿它跟
现网数据比对。

## 阶段 2（DONE，2026-10-20）：源层对真实端点验证

`capkit/kits/vulnintelkit/live_test.go`（`//go:build live`）用真实 `httpx.Fetcher`
对 9 个源各抓 10 条，逐源报告可用性。运行：

```bash
cd /home/c1ay/capkit
go test -tags live -run TestLiveSources -v ./kits/vulnintelkit/
```

首跑结果 **4/9 可用**，查真因后修了 8 个问题，复跑两次一致 **8 可用 / 0 降级 /
1 不可用**：

| 源 | 首跑 | 真因 | 现状 |
| --- | --- | --- | --- |
| kev | OK | — | OK |
| oscs | OK | — | OK |
| chaitin | 465 | 分页循环触发 WAF | 单页 + 退避重试，OK |
| qianxin-ti | status=10000 | 成功码当错误码 | OK |
| threatbook | 无严重度 | 不认「高风险」写法 | OK |
| aliyun-avd | 未解析到条目 | 全站反爬 JS 挑战页 | 宿主提供（见 2.1） |
| seebug | 未解析到条目 | 链接/标题/等级三处标记全错 | OK |
| venustech | 无严重度 | 详情页已无等级字段 | OK（等级 unknown） |
| struts2 | 未解析到条目 | Confluence 改版 | OK |

同时发现并修正了 `uniqueKey` 的参数顺序 bug：它原本产出 `chaitin_CT-...`，
而宿主现有数据是 `CT-..._chaitin`，直接切换会给每条情报新建一行。

**这一步的结论：源层已可切换。** capkit 内置 8 个源全部 live 通过；AVD 由宿主
通过 `core.IntelSource` 接入，走同一条入库路径。

### 2.1 AVD：已决策 —— 留在宿主，经 `core.IntelSource` 接入（DONE）

**决定：AVD 的实现留在 4zrec，通过 capkit 新开的 `core.IntelSource` 端口接进
capkit 的 poll 循环。**

依据（都实测过）：

- `avd.aliyun.com` 的列表页、详情页和试出来的 `/api/*` 全部返回同一个约 27KB 的
  JS 混淆挑战页；真实数据由脚本算出的签名参数 `?timestamp__NNNN=` 现场拼出，
  响应里没有。**不是解析问题，是拿不到数据。**
- 没有可用的 RSS/feed/sitemap/公开 API（逐个探过，404 或挑战页）。
- 本地 `grab/avd.go` **今天仍然可用**：用 `dop251/goja`（纯 Go，MIT）跑那段脚本，
  多带一个签名字段就能拿到数据。实测一次 `GetUpdate(ctx, 1)` 返回 30 条，7.7 秒。
- 所以不需要 headless 浏览器，也不需要求官方 API。

**为什么不搬进 capkit**：跑这段脚本要一个 JS 引擎，而且要执行远端下发的不透明代码。
capkit 是 Apache-2.0 的契约/算法库，依赖面一直很轻（唯有 yaml.v3）；为一个源引入
解释器，等于让每个宿主都承担这个运行时依赖和执行面。这个取舍不该替下游做。

**现在的做法**：

1. capkit 新增 `core.IntelSource`（`Name() string` + `Fetch(ctx, limit) ([]IntelItem, error)`）
   和 `core.Deps.ExtraIntel`。vulnintelkit 把宿主源并进自己的源列表，**共用**
   同一个 store、同一个去重键、同一个严重度门槛、同一份 `vulnintel_sources` 报告。
2. capkit 删掉内置的 AVD 实现（它永远只能报错，是死代码），`source_html.go`
   顶部保留说明和接入方式。
3. 4zrec 新增 `internal/platform/server/capkit_avd_source.go`：把 `grab.NewAVDCrawler()`
   包成 `core.IntelSource`，键格式沿用存量数据 `AVD-xxxx_aliyun-avd`。
4. `capkit_tools.go` 用 `ExtraIntel: []capkit.IntelSource{newAVDIntelSource()}` 注入。

**验证**：`capkitbridge` 的 `TestHostSourceJoinsThePollLoop` 证明宿主源会被 poll、
条目会进宿主 store；一次临时 live 探针抓到 5 条真实 AVD 情报，键/等级/标题/URL 都对。

**注意**：挑战脚本会变。它现在用的参数名是 `timestamp__1384`，改名或改算法时
本地实现要跟着调——这是**宿主侧**的维护点，不再是 capkit 的。

## 阶段 3（TODO）：unique_key 迁移

### 现在是怎样的

本地键取自 `grab/<源>.go`，capkit 键取自 `kits/vulnintelkit/source_*.go` 里的
`uniqueKey(...)` 调用（格式统一是 `<主体>_<source>`）：

| 源 | 本地 `grab/` | capkit `vulnintelkit` | 关系 |
| --- | --- | --- | --- |
| KEV | `CVE-xxxx-yyyy_KEV` | `CVE-xxxx-yyyy_KEV` | ✅ **完全一致** |
| 长亭 chaitin | `d.CtId` | `d.CtID_chaitin` | 加后缀 |
| 奇安信 qianxin-ti | `d.QvdCode` | `d.QvdCode_qianxin-ti` | 加后缀 |
| 微步 threatbook | `v.Id` | `v.ID_threatbook` | 加后缀 |
| OSCS | `data.VulnNo` | `VulnNo_oscs` | 加后缀 |
| AVD | 源内 id（`avd` 变量） | `<id>_aliyun-avd` | 加后缀 |
| Struts2 | 标题里的 `S2-xxx` | `e.ID_Struts2` | 加后缀 |
| Seebug | 表格首列文本（形如 `SSV-xxxxx`） | **详情页 URL** `_seebug` | ⚠️ 主体不同 |
| 启明星辰 | 文件名去扩展名 + `_venustech` | **通告链接 URL** `_venustech` | ⚠️ 主体不同 |

所以：7 个源可以机械迁移（加/改后缀），2 个源（Seebug、启明星辰）主体本身就不同，
**必须先建立映射再切**。

### 迁移步骤（按此顺序，每步可回滚）

1. **先归一后缀，不动主体**：逐源加后缀，别一把梭。

   ```sql
   -- 其余 6 个「主体相同、缺后缀」的源，按源逐个执行
   UPDATE vuln_intel SET unique_key = unique_key || '_chaitin'
    WHERE source = '长亭漏洞库' AND unique_key NOT LIKE '%\_chaitin';
   ```

   KEV 已经是 `_KEV`，与 capkit 一致，**不要动**；其余源的 `source` 过滤值用
   本地写入的 `DisplayName`（见下方提醒）。
2. **Seebug / 启明星辰先建映射**：这两边主体不同，不能靠 SQL 拼。做法是拿本地
   `SourceURL` 与 capkit 的 `UniqueKey`（就是 URL）对齐：

   ```sql
   -- 先看能不能靠 URL 对齐，能对齐才继续
   SELECT count(*) FROM vuln_intel
    WHERE source = 'Seebug 漏洞平台' AND source_url LIKE 'https://www.seebug.org%';
   ```

   `unique_key` 写成 `unique_key = source_url || '_seebug'` 只在这条 SQL 命中数
   等于该源总行数时才安全；否则让这两个源**暂时继续走本地 `grab/`**，其余 7 个先切。
3. **切换后观察一轮**（至少一个抓取周期）：
   ```sql
   SELECT source, count(*), count(DISTINCT unique_key) FROM vuln_intel GROUP BY 1;
   ```
   总数不应因切换上涨；上涨说明键没对齐。旧行仍在，把 `UPDATE` 的 `||` 后缀去掉
   即可回滚。

> 提醒：本地 `vulnintel` 的 `Source` 列存的是 `DisplayName`（"阿里云漏洞库"），
> capkit 的 `IntelItem.Source` 是 slug（`aliyun-avd`）。若要按源统计，**先用 slug**；
> 想继续显示中文，在 `capkitIntelStore` 里做一次 slug → DisplayName 映射，
> 不要两边各存一套。

## 阶段 4（TODO）：删重复实现

只有阶段 2 全部源验证通过、阶段 3 迁移完成并观察一轮之后，才做这步。

删除清单（按依赖顺序）：

1. `internal/capability/vuln/vulnintel/grab/` — 整包。
2. `analyzer.go` / `tplgen.go` / `fpgen.go` / `pocgen.go` 及其测试 — 能力已在
   `pockit`。**保留** `manager.go` 的调度、`enrich.go`、`localize.go`、`triage/`。
3. `manager.go` 里对 `grab.Grabber` 的引用改为调 `rt.Call("vulnintel_poll", ...)`；
   `fingerprintSink` 保留（那是宿主侧写 `fingerprint_rules` 的钩子，capkit 不该知道
   fingerprint 表的形状）。
4. `server/vulnintel.go` 的「确认入库」端点继续存在——它调 `poc_publish` 或本地
   `ConfirmFingerprint`，两条都说清楚了再动。

删除时注意：`tplgen`/`fpgen`/`pocgen` 里有线上积累的**接地校验**细节（
`usableMatcherWord`、`patternGrounded`、`intelCorpus`），capkit 侧已有等价实现
（`matcherWords`、`pathGrounded`/`grounded`、`intelCorpus`），但**语义不完全相同**：
本地 matcher 允许「至少一个词元命中」，capkit 的 `matcherWords` 用整词比较。
删之前跑一遍阶段 2 的比对，确认产出的模板数量没有显著下降。

## 未纳入本次迁移的已知问题

这三条是读代码时发现的，与迁移无关，记在这里免得忘：

1. **`fingerprint.ActiveRules` 的回退会吞掉内置规则** —— **已修（2026-10-20）**。
   原条件是「规则表为空」才回退内置快照（7,831 条），于是「确认入库」写一条
   `source='custom'` 的规则就会让表从 0 变 1，内置规则全部不再参与匹配。
   现在按「上游是否同步过」判断（`fingerprint_sources` 非空），未同步时把库里的
   规则**叠加**到内置快照上，并用 `name+expression` 去重。单测见
   `fingerprint/active_rules_test.go`。
2. **`requireSearchFingerprint` 用子串做产品绑定** —— **已修（2026-10-20）**。
   `QueryMatches` 原来是双向 `strings.Contains`，已识别 `OA` 就能批准 `通达OA`，
   已识别 `BlueKing` 就能批准 `King`。现在先走 capkit 的 binding 表解析成规范产品键，
   否则只接受词元边界匹配（`fingerprint/evidence.go`）。残留限制：`Spring` 与
   `SpringBootAdmin` 这类「短名恰好是长名的词元前缀」只能靠绑定表区分，已在
   `TestQueryMatchesKnownLimitations` 里记为已知限制。
3. **`docs/` 下没有本文件的先例**——这份是第一个纯迁移方案文档，格式按需再统一。
