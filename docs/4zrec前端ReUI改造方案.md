# 4zrec 前端 ReUI 改造方案

> 编写日期：2026-10-19　基线版本：v0.5.0（`0daca31`）
> 性质：方案文档，未排期、未派单。所有现状数据来自仓库实测，非估算。

---

## 0. 一句话结论

ReUI 值得引入，但**不是"用它把前端调整一遍"**，而是用它补齐三个缺失的界面形态：数据表格、对话消息流、仪表盘图表。改造收益的大头不在组件库，在于先把 `tasks/page.tsx` 这种 3,525 行的单文件拆开，并统一密度与字号基线。没有这两步，换任何组件库都只是换皮。

---

## 1. 现状实测

### 1.1 技术栈

| 项 | 值 |
|---|---|
| 框架 | Next.js 16.2.9（App Router，RSC） |
| React | 19.2.7 |
| 样式 | Tailwind CSS 4.1.5（`@tailwindcss/postcss`） |
| 组件体系 | shadcn，`components.json` 中 `style: radix-nova`、`baseColor: neutral`、`cssVariables: true` |
| 无头原语 | `radix-ui ^1.6.0` **与** `@base-ui/react ^1.6.0` 两套并存 |
| 图标 | `lucide-react` |
| 主题 | `next-themes` + 三套 preset（`brutalist` / `soft-pop` / `tangerine`） |

结论：技术前提与 ReUI 完全对齐（React 19 + Tailwind v4 + 已初始化的 shadcn 工程）。

### 1.2 页面与体量

- 页面路由：**39 个**（`src/app/**/page.tsx`）
- `page.tsx` 总行数：**24,980 行**
- `tsx` 文件总数：172

体量 TOP 5：

| 文件 | 行数 | 说明 |
|---|---:|---|
| `(main)/function/tasks/page.tsx` | 3,525 | 列表 + 筛选 + 批量操作 + 详情入口塞在一个文件 |
| `(main)/chat/page.tsx` | 1,703 | 对话主界面 |
| `(main)/function/findings/page.tsx` | 1,340 | 漏洞列表 |
| `(main)/dashboard/page.tsx` | 1,279 | 仪表盘 |
| `(main)/system/skills/page.tsx` | 1,163 | 技能管理 |

单文件 3,525 行是本次改造的**第一障碍**：组件库解决的是"零件好不好看"，解决不了"一个文件里五种布局各写一套间距"。

### 1.3 组件面

- `src/components/ui/`：**61 个** shadcn 组件（accordion / alert / button / card / dialog / table / sidebar / chart 等，覆盖完整）
- `src/components/`：业务组件约 20 个（`exploration-graph.tsx`、`evidence-viewer.tsx`、`asset-dsl-search.tsx`、`mention-textarea.tsx` 等）
- 已有 `@xyflow/react`（探索图）、`@fullcalendar/react`、`embla-carousel`、`recharts`（经 `chart.tsx`）

结论：**组件不缺**。缺的是"结构化程度高的形态"和"统一的密度语言"。

### 1.4 三处结构性缺口

**（1）数据表格全是手写 `Table`**

10 个页面直接引用 `@/components/ui/table` 自行拼装：

```
(main)/function/tasks/page.tsx
(main)/function/tasks/detail/_tabs/assets-tab.tsx
(main)/function/findings/_components/findings-table.tsx
(main)/function/llm-records/page.tsx
(main)/function/commands/page.tsx
(main)/function/workspace/page.tsx
(main)/function/traffic/page.tsx
(main)/function/nuclei-templates/page.tsx
(main)/function/projects/page.tsx
(main)/function/projects/detail/page.tsx
```

后果：没有排序、没有列固定、没有密度切换、没有 URL 化筛选状态，每个页面的分页逻辑各写一遍。

**（2）僵尸依赖**

`package.json` 声明了 `@tanstack/react-table ^8.21.3`，但全仓 `src/` 内 **0 处引用**。装了没用，表格能力白放着。

**（3）对话页没有消息组件**

`src/components/` 下搜不到任何 bubble / message / chat 相关组件，`chat/page.tsx` 用基础容器手写消息流。对话是 4zrec 的主界面，却是视觉上最原始的一页。

### 1.5 "不好看"的归因

按影响排序：

1. **密度与字号不统一**（占大头）：39 个页面各自的 padding、行高、字号没有基线，单看都不难看，放在一起不像一套产品。
2. **数据页形态原始**（其次）：基础 Table 撑不起"任务 / 漏洞 / 资产 / 连接台账"这类高信息密度页面。
3. **对话页缺层次**（第三）：没有角色区分、没有工具调用气泡、没有消息分组，长对话读起来累。

配色与圆角**不是**问题，现有 shadcn neutral 体系是干净的，不需要动。

---

## 2. ReUI 是什么、不是什么

### 2.1 是 registry，不是 npm 包

- 通过 shadcn CLI 把组件源码**复制进仓库**（copy-and-own），不产生版本锁定，不引入新的运行时依赖。
- 安装形式：`npx shadcn@latest add @reui/<name>`。
- 底层第三方依赖（如 `@tanstack/react-table`、`@dnd-kit/core`、`recharts`）会按需拉取——4zrec 已有 react-table，正好复用。

### 2.2 免费与付费边界

| 层 | 内容 | 授权 |
|---|---|---|
| Components | 27 个自有 primitive（Data Grid、Filters、Kanban、Event Calendar、Gantt、Stepper、Timeline、Tree、Cascader、File Upload、Sortable、Rating、Scrollspy 等） | 免费 |
| Examples | 1,264 个组件示例 | 免费 |
| Blocks | 654 个整块布局（Application / Data Grid / Charts / Solutions / AI & Agents / eCommerce / Marketing） | 付费 |
| Icons / Templates | 667 图标 4 种风格、整页模板 | 付费 |

**本方案只用免费层**。付费 blocks 等样板验证完再评估。

### 2.3 双版本

每个组件同时提供 **Radix UI 版**与 **Base UI 版**，样式一致，仅无头原语不同。4zrec 两套都有，取 Radix 版与现有 `radix-nova` 体系保持一致。

> ⚠️ 待验证项：ReUI 官方 registry 示例写的是 `style: base-nova`，而 4zrec 是 `radix-nova`。安装第一步先用 `npx shadcn@latest view @reui/data-grid` 试取，确认 `{style}` 段是否接受 `radix-nova`；不接受则改走其 Radix UI 版的显式 registry 路径。**此项未实测，标注为待验证，不作为已确认结论。**

### 2.4 它不是设计系统

ReUI 不会自动让界面变好看。它提供的是"结构更完整的零件"，视觉质量仍取决于 token 基线（间距、字号、圆角、密度）与页面信息架构。这一点决定了下面的实施顺序。

---

## 3. 目标与不做什么

### 3.1 目标

1. 数据密集页具备排序、筛选、列固定、密度切换，筛选状态可分享（URL 化）。
2. 对话页具备角色气泡、工具调用折叠、消息分组。
3. 全站密度与字号统一到一套基线。
4. 大文件拆分：`page.tsx` 超过 800 行的单个页面必须拆成 `_components/` + hooks。

### 3.2 不做什么

- 不改配色体系，不动现有三套 preset 的主色。
- 不换掉 `components/ui/` 下 61 个组件。
- 不把 `components.json` 的 `style` 改成 `base-nova`（会把现有 Radix 组件全部打乱）。
- 不引入 ReUI 的 button / card / dialog / input（与现有重复，会出现两套按钮样式）。
- 不做暗色主题专项适配（现有 `next-themes` 已覆盖，改造中只需保证不破坏）。

---

## 4. 视觉基线（先定数，再换件）

在 `src/app/globals.css` 的 `@theme inline` 中补齐语义 token，**不覆盖**现有 preset 文件：

```css
@theme inline {
  /* 密度：三档，默认 comfortable */
  --density-row-h: 36px;          /* 表格行高 */
  --density-cell-x: 12px;         /* 单元格横向内边距 */
  --density-cell-y: 8px;          /* 单元格纵向内边距 */
  --density-card-p: 16px;         /* 卡片内边距 */

  /* 字号：四级 */
  --text-meta: 12px;              /* 辅助信息、时间戳 */
  --text-body: 13px;              /* 正文、表格单元格 */
  --text-title: 15px;             /* 区块标题 */
  --text-display: 24px;           /* 页面主标题 */

  /* 行高 */
  --leading-meta: 16px;
  --leading-body: 20px;
  --leading-title: 22px;
}
```

三个决定改造成败的数字：

| 项 | 取值 | 理由 |
|---|---|---|
| 表格行高 | 36px | 信息密集页一屏能多看 5–6 行；低于 32px 会挤，高于 40px 浪费 |
| 正文 | 13px | 现有页面混用 12/14/16，13 是表格与正文的公约数 |
| 圆角 | 沿用 `--radius`（默认 8px） | 不再引入新的圆角档位 |

密度切换用 `data-density="compact|comfortable|spacious"` 挂在 `<html>`，配合 `[data-density=compact] { --density-row-h: 30px }` 覆盖，不改组件源码。

---

## 5. 分阶段实施

### 阶段 0：拆 `tasks/page.tsx`（前置，1–2 天）

3,525 行不拆，ReUI 组件塞进去只会让文件更长。目标结构：

```
(main)/function/tasks/
├── page.tsx                    ← 只保留页面装配（目标 <200 行）
├── _components/
│   ├── task-table.tsx          ← 替换为 ReUI Data Grid
│   ├── task-filters.tsx        ← ReUI Filters
│   ├── task-bulk-actions.tsx
│   └── task-detail-sheet.tsx
├── _hooks/
│   ├── use-task-query.ts       ← 查询参数、URL 状态
│   └── use-task-mutations.ts
└── _lib/
    └── columns.tsx             ← 列定义（ColumnDef[]）
```

验收：`page.tsx` < 200 行，`_components/` 每个文件 < 400 行，页面行为与拆分前一致。

### 阶段 1：接 ReUI（0.5 天）

1. `components.json` 增加 registry：

```json
{
  "registries": {
    "@reui": "https://reui.io/r/{style}/{name}.json"
  }
}
```

2. 先试取一个组件验证链路（见 §2.3 待验证项）。
3. 只安装本方案需要的 6 个：`data-grid`、`filters`、`bubble`、`message`、`message-scroller`、`chart`。

### 阶段 2：三个样板页（3–5 天）

| 页面 | 替换内容 | 用到的 ReUI 组件 |
|---|---|---|
| `function/tasks` | 手写 Table → Data Grid（排序 / 列固定 / 行选择 / 分页），筛选 → Filters（URL 状态），密度切换 | `data-grid`、`filters` |
| `function/findings` | `findings-table.tsx` 换 Data Grid；严重度配色沿用现有 `--destructive` / `--warning` | `data-grid`、`filters` |
| `chat` | 消息流换 Bubble + Message Scroller；工具调用块用可折叠 Message | `bubble`、`message`、`message-scroller` |

样板验收标准：

- 三页在 compact / comfortable 两档密度下都不溢出、不换行错位。
- findings 的严重度颜色与改动前一致（不允许出现新的红/黄）。
- chat 长对话（>50 条）滚动不卡顿，工具调用默认折叠。

### 阶段 3：铺开（按样板模板，5–8 天）

优先顺序（按信息密度）：

1. `function/assets`、`function/connections`、`function/traffic`
2. `function/llm-records`、`function/commands`、`function/vuln-kb`、`function/nuclei-templates`
3. `system/tools`、`system/skills`、`system/logs`、`system/recon-schedules`
4. `dashboard`（Chart 组件，放最后，因为它依赖数据接口稳定）

`spacemap` 已有 `@xyflow/react`，不纳入本次表格改造；只在密度与字号上对齐。

---

## 6. 红线

1. **不动 `components.json` 的 `style`**：`radix-nova` 保持不变。
2. **不装重复组件**：button / card / dialog / input / select / table 一律不装 ReUI 版。
3. **不改配色 token**：`--primary`、`--destructive` 等语义色保持现有值；ReUI 新增的 `--info` / `--success` / `--warning` 只在需要时补，且必须与现有语义色不冲突。
4. **一次只改一类页面**：不允许表格和对话在同一分支里混改，出问题无法二分定位。
5. **每个阶段独立提交**：阶段 0 的拆分单独 commit，阶段 2 的每页单独 commit，便于回滚。
6. **不碰 `proxy.ts` / 数据层**：本次只改视图层。

---

## 7. 验收标准

| 项 | 标准 | 取证方式 |
|---|---|---|
| 构建 | `npm run build` 通过，无新增 TS 错误 | 构建日志 |
| 类型 | 无 `any` 新增（除第三方回调） | `git diff` 人工核 |
| 密度 | compact / comfortable 两档三页均无溢出 | 两个视口截图（1440 / 1920） |
| 一致性 | 全站表格行高来自 `--density-row-h`，无硬编码 px | `grep -rn 'h-\[.*px\]' src/app` 应为 0 |
| 大文件 | 所有 `page.tsx` < 800 行 | `find src/app -name page.tsx -exec wc -l {} +` |
| 僵尸依赖 | `@tanstack/react-table` 至少被 Data Grid 真实引用 | `grep -rl '@tanstack/react-table' src/` 非空 |
| 回滚 | 每个阶段可单独 revert，不牵连其他阶段 | 分支结构 |

---

## 8. 风险与回滚

| 风险 | 影响 | 处置 |
|---|---|---|
| ReUI registry 不接受 `radix-nova` | 阶段 1 卡住 | 走 Radix 显式 registry；仍不通则只用免费示例的源码手工复制 |
| Data Grid 与现有 `Table` 样式冲突 | 视觉不一致 | 先在一个非关键页（`system/logs`）试，再上 tasks |
| copy-and-own 后续无自动更新 | 上游修复需手工同步 | 记录安装版本日期，半年内不追更新 |
| 拆分 `tasks/page.tsx` 引入回归 | 任务页功能破坏 | 阶段 0 完成后先跑一轮真实任务创建/筛选/批量操作再进阶段 1 |
| 付费 blocks 诱导 | 成本失控 | 本方案锁定免费层，付费项需单独立项评估 |

---

## 9. 工作量汇总

| 阶段 | 内容 | 预估 |
|---|---|---:|
| 0 | 拆 `tasks/page.tsx` | 1–2 天 |
| 1 | 接 ReUI registry + 试取 | 0.5 天 |
| 2 | 三个样板页 | 3–5 天 |
| 3 | 铺开 10 个数据页 + dashboard | 5–8 天 |
| — | 回归与截图验收 | 1–2 天 |
| **合计** | | **11–18 天** |

生成与验证分开计：生成（写代码）约 6–9 天，验证（构建、两档密度截图、真实任务回归）约 5–9 天。验证占比高，是因为本次改的是视图层，错都在细节里。

---

## 附：待验证项清单

以下三项在文档编写时**未实测**，进入阶段 1 必须逐条确认后才可继续：

1. ReUI registry 的 `{style}` 段是否接受 `radix-nova`。
2. ReUI Data Grid 免费版是否包含列固定与列拖拽（部分能力标注为 Pro）。
3. `message-scroller` 与 4zrec 现有的流式输出（SSE）是否兼容，是否需要包一层虚拟滚动。

这三项任一不成立，阶段 2 的对应页面需重新选型，不要让整个方案卡在一个组件上。
