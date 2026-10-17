# 报告撰写 Agent 提示词修订与执行层缺口

**状态**：待实施
**涉及模块**：`agent/promptcatalog.go`、`agent/tools.go`、`server/orchestration.go`、`agent/finding_workflow.go`
**平台版本**：4zrec 0.4.1-30

---

## 一、漏洞报告的生成链路

报告不是 worker 直接写的，由独立 agent `reporter`（名称「报告撰写」）生成。

```text
worker 验证出漏洞
  └─ 调 report_finding（vulnclass / name / severity / summary / evidence / reproduction / traffic_refs）
       └─ 返回 finding_id（独立漏洞记录）+ finding_node_id（探索节点）
            └─ 触发器 OnToolCall=report_finding 唤起 reporter
                 ├─ get_task_node_detail        读节点完整证据 / PoC
                 ├─ get_finding_traffic         读绑定流量与 version
                 ├─ traffic_search/get/blob     检索、读取请求响应正文
                 ├─ list_task_worker_traces     列出该任务的 work
                 ├─ get_task_worker_trace       还原发现与验证过程
                 ├─ search_task_worker_traces   按关键词检索执行记录
                 ├─ get_task_graph              看整体态势
                 ├─ list_task_findings          看关联漏洞
                 └─ update_finding_report       写回 Markdown + evidence_version
```

关键约束：

- reporter 不亲自渗透，工具面只有只读证据与写报告，没有 `http_probe`、没有 Bash。
- 一次调用处理一个 finding，不批量。
- 流量绑定可选，空清单不阻断写报告。
- `evidence_version` 为乐观锁，版本冲突需重读重写，不得换版本硬塞。
- finding 先登记、报告后生成，报告失败不丢漏洞记录，可重新触发。

prompt 迭代至此为 v5：V2 按任务性质选口径、V3 统一 SRC 四段、V4 发现方式写真实路径、V5 加入证据深度定级标尺与措辞红线。

---

## 二、已完成的改动

### 2.1 reporter prompt v5

已落库，`GET /api/agents/reporter` 返回的 `prompt` 为 4086 字符，包含：

- 正文首行 `# <漏洞名称>`
- 四段结构（漏洞描述与发现方式 / 复现过程 / 测试源信息 / 修复方案 + 附录）
- 定级标尺：critical / high / medium / low 四级判据，取「影响范围」与「证据深度」较低一档
- 铁律：400/500 类部分验证最高 medium 并标注「（未端到端验证）」；数据泄露须抽样读完整实体；定级理由须写「为什么不是上一级」
- 证据分级：已验证 / 部分验证 / 推断，推断只能进附录
- 措辞红线：不写「SRC 漏洞挖掘」「批量扫描」「自动化发现」，不做外推式影响结论
- 交付前自检五项

### 2.2 report_finding 的 severity 描述

`agent/tools.go` 中 `report_finding` 的 `severity` 参数描述已同步同一套标尺，worker 上报阶段即按证据深度定级，与 reporter 侧口径一致。

若不改这一处，会出现 worker 报 high、reporter 按标尺写 medium 的直接冲突。

---

## 三、两个执行层缺口

### 3.1 reporter 无发请求能力，「必须抽样读完整实体」无法执行

现状：reporter 绑定工具为 `update_finding_report`、`get_task_node_detail`、`list_task_findings`、三个 worker trace 工具、`get_task_graph`、`get_finding_traffic`、`bind_finding_traffic`、`traffic_search/get/blob`。全部只读，无法自行发包。

后果：当 worker 只上报 `totalCount` 与字段名、未把完整实体写入 evidence 时，reporter 只能写「未抽样确认」，标尺第 2 条落空。

实例：finding 293（`Abp.TenantId` 跨租户读 CMS）只记录 38476 条与列表字段，未取正文，定级停在 medium，而正文是否含未公开招标标底无从判断。

### 3.2 reporter 改不了 severity

现状：`update_finding_report` 参数为 `finding_id`、`report`、`evidence_version`，无 `severity`。

后果：reporter 按标尺判定 A 级，只写进报告正文；finding 记录的 severity 仍是 worker 登记值。列表显示 medium、报告写 high，交付时口径不一致。

### 3.3 证据截断导致关键信息丢失

现状：`report_finding` 的 `evidence` 描述要求结构化复现（`## N. 标题`、bash/json 围栏），但未规定长请求与长响应的截断方式，也未禁止静默省略。

后果：worker 为控制体积自行裁剪，可能裁掉用于定级的字段（正文片段、状态位、金额、作者），reporter 拿到残缺证据后只能凭列表字段判断，等级失真；report 里引用残缺报文时也无从判断哪些是原文、哪些被删。

---

## 四、提示词修订

### 4.1 替换 `report_finding` 的 `evidence` 参数描述

位置：`agent/tools.go`，`report_finding` 的 schema 中 `evidence` 字段。

```text
证据/PoC。Markdown 固定规范(详情页按此渲染,必须遵守):按复现步骤组织,每步以单独一行「## N. 标题」开始(N=1,2,…);命令放 ```bash 围栏、响应/输出放 ```json(纯文本输出用无语言围栏);命令与响应不得和说明文字混写在一行,禁止用「→」连接命令与响应;结尾的对照/影响面/合规说明写成引用行,如「> **对照**: …」。复现过程同时填写 reproduction 结构化字段(权威渠道),evidence 保留同内容的步骤化呈现。

数据泄露类必须附至少一条完整实体样本：从结果集中取一条记录，保留全部字段（content/正文/附件名/状态/作者/时间/金额等），脱敏后以 json 围栏贴出。实体过大时保留前 2000 字符，并在截断处写明「...（已截断，原长 N 字节）」，用于定级的字段不得省略。

请求/响应过长时按「关键行保留」截断：请求保留方法、URL、全部请求头、body 前 1000 字符；响应保留状态行、Content-Type、Content-Length 与支持结论的字段片段。任何截断都必须显式标注「...（已截断，原长 N 字节）」，禁止静默省略；定级依据涉及的字段不得被截断掉。证据被截断导致无法判断数据敏感程度的，按 medium 上报并在 summary 注明「证据截断，敏感度未确认」。
```

### 4.2 追加到 reporter prompt 的「证据分级」之后

```text
━━ 截断证据的处理 ━━
读取节点证据或流量正文时，遇到「已截断」标注、正文明显不完整、或 items 只有列表字段没有实体内容：
1. 不得把截断后的内容当作完整事实下结论，也不得据此上调等级。
2. 先用 get_finding_traffic 按 binding_id 分段读取完整正文；仍不完整时，在 1.4 与附录写明「证据在 X 处截断，完整内容未取得」，并说明这是否影响定级。
3. 截断导致无法判断是否含未公开正文的，一律按 medium 处理，不得上调；确需上调的，在附录标注「需人工补验」。
4. 报告中的请求/响应引用同样遵守截断标注规则：省略处写「...（已截断，原长 N 字节）」，不得用省略号掩盖关键字段的缺失。
```

### 4.3 `update_finding_report` 增加 severity 参数

```text
给 update_finding_report 加可选参数 severity（enum: critical|high|medium|low），语义为「仅允许下调」：当 reporter 按标尺判定的等级低于 finding 原登记值时才写入，高于原值时忽略并在报告附录注明「建议上调为 X，需人工确认」。保存后返回实际生效的 severity，报告正文与 finding 记录必须一致。
```

---

## 五、实施顺序

1. 改 `agent/tools.go` 的 `evidence` 描述（4.1），worker 侧先具备完整实体与截断标注。
2. 改 `agent/promptcatalog.go` 的 `ReporterDefaultPrompt`，追加 4.2 章节。
3. 新增 `reseedReporterPromptV6`（flag `reporter_prompt_truncation_v1`），沿用 V5 的 `ResetPromptToDefault` 模式，存量库一次性重刷。
4. 给 `update_finding_report` 加 `severity` 参数与「仅降不升」逻辑（4.3），同步 `refreshBuiltinToolSchemas` 的 flag 版本号，使旧库 schema 刷新。
5. 重新编译，`rebuild-platform.sh --restart` 生效。
6. 用一个新 finding 走完整链路，检查报告标题、定级、截断标注、severity 是否与 finding 记录一致。

---

## 六、验收清单

- [ ] 数据泄露类 finding 的 evidence 中含至少一条完整实体样本，且用于定级的字段未被截断
- [ ] 长响应带「...（已截断，原长 N 字节）」标注，无静默省略
- [ ] reporter 遇到截断证据时不定上调级，并在附录写明截断位置
- [ ] finding 记录的 severity 与报告正文等级一致
- [ ] reporter 上调建议仅出现在附录，未直接改写 finding
- [ ] 存量 finding 的旧报告不自动重写，需人工重新触发；已知 293 定级偏低、294 将 400/500 当结论

---

## 七、遗留问题

- 存量报告（293、294 等）仍是 v4 及更早口径的产物，V5/V6 只影响新生成的报告。是否批量重新生成需单独决策。
- 若后续允许 reporter 上调等级，必须同时引入人工确认环节，否则等于把定级权交给生成模型。
