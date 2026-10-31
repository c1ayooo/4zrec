// 4zrec domain model — types used across the UI.
// Derived from the functional spec (section 7: 关键数据形状).

export type TaskStatus = "created" | "queued" | "running" | "paused" | "done" | "failed" | "timeout";
export type EngineMode = "exploring" | "paused" | "stalled" | "idle";

export interface Task {
  id: string;
  name?: string; // 可选任务名称;空/缺省=未命名,展示时回退到描述
  category_id?: number;
  category_name?: string;
  project_id?: number; // 归属项目(授权根);缺省=未挂项目
  pinned?: boolean;
  pinned_at?: string | null;
  description: string;
  goal: string;
  status: TaskStatus;
  created_at: string;
  created_unix?: number; // created_at as unix seconds (run-duration calc)
  completed_at?: string; // RFC3339 finish time (done/failed); "" if unfinished
  completed_unix?: number; // completed_at as unix seconds (0/undef if unfinished)
  last_activity_unix?: number; // unix seconds of the last activity (0/undef if none)
  paused?: boolean;
  queued?: boolean;
  active?: boolean;
  in_flight?: number;
  findings?: { critical: number; high: number; medium: number; low: number }; // 已登记漏洞数(按严重度分档)
  last_activity?: string;
  stalled?: boolean;
  goals_total?: number;
  goals_met?: number;
  engine_mode?: EngineMode;
  tokens?: TokenTotal; // whole-task token consumption
  llm_profile_id?: number; // LLM profile used; absent = default profile
  llm_profile_ids?: number[]; // ordered task-level failover chain
  active_llm_profile_id?: number; // profile used by the next LLM call
  llm_failover_state?: "default" | "ready" | "chain_exhausted" | string;
  llm_failover_reason?: string;
  source_task_ids?: string[]; // directly related tasks inherited as read-only context
  archive_blocked_by_task_id?: string; // live direct dependent that must be archived first
  company_ids?: number[]; // associated company scopes; current company assets join the task at creation
  coverage_enabled?: boolean; // 资产覆盖度功能开关(创建时定,默认开)；false=不计算/不展示覆盖度
}

export interface TaskCategory {
  id: number;
  name: string;
  task_count: number;
  created_at: string;
  updated_at: string;
}

export interface TaskTemplate {
  id: number;
  name: string;
  description: string;
  goal: string;
  category_id?: number | null; // 预设分类；null/缺省=无
  intercept_rules?: AssetInterceptRuleInput[]; // 预设的任务级拦截/允许规则
  created_at: string;
  updated_at: string;
}

export interface DeleteTaskOptions {
  delete_assets: boolean;
  delete_traffic: boolean;
  delete_files: boolean;
  delete_findings: boolean;
  delete_llm_records: boolean;
}

export interface DeleteTaskResult {
  deleted: string;
  assets_deleted: number;
  assets_detached: number;
  traffic_deleted: number;
  files_deleted: boolean;
  findings_deleted: number;
  llm_records_deleted: number;
  cleanup_warning?: string;
}

export type TaskArchiveState =
  | "archive_queued"
  | "archiving"
  | "archive_failed"
  | "ready"
  | "restore_queued"
  | "restoring"
  | "restore_failed"
  | "delete_queued"
  | "deleting"
  | "delete_failed";

export interface TaskArchiveTokenStats {
  calls?: number;
  input_tokens?: number;
  output_tokens?: number;
  cache_read_tokens?: number;
  cache_write_tokens?: number;
}

export interface TaskArchive {
  id: number;
  task_id: number;
  state: TaskArchiveState;
  phase: string;
  progress: number;
  error?: string;
  warnings?: string[];
  format_version: number;
  sha256?: string;
  original_size: number;
  compressed_size: number;
  task_name: string;
  task_description: string;
  task_goal: string;
  original_status: TaskStatus;
  category_id?: number;
  category_name?: string;
  source_task_ids: number[];
  remaining_timeout_seconds: number;
  data_counts: Record<string, number>;
  aggregate_stats: {
    tokens?: TaskArchiveTokenStats;
    skills?: Record<string, number>;
    tools?: Record<string, number>;
    findings?: Record<string, number>;
  };
  archived_at?: string;
  requested_at: string;
  created_at: string;
  updated_at: string;
}

export interface TaskArchivePage {
  items: TaskArchive[];
  total: number;
  page: number;
  size: number;
}

export interface ArchiveBatchItem {
  id: string;
  archive_id?: number;
  ok: boolean;
  queued: boolean;
  error?: string;
}

// ---- Asset graph (global, shared across tasks) ----
export type AssetType =
  | "company"
  | "domain"
  | "ip"
  | "port"
  | "service"
  | "site"
  | "endpoint"
  | "parameter"
  | "tech"
  | "credential"
  | "data";

export type NodeState = "observed" | "confirmed" | "tombstoned";

export interface AssetNode {
  id: string;
  type: AssetType;
  name: string;
  key: string; // nkey
  value?: string;
  company_id?: string; // 归属公司资产 id；空=未归属
  state: NodeState;
  confidence: number; // 0..1
  attrs?: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
}

export type AssetRel =
  | "owns"
  | "resolves"
  | "exposes"
  | "runs"
  | "serves"
  | "has_endpoint"
  | "has_param"
  | "fingerprinted"
  | "authenticates_as"
  | "reachable"
  | "has_subdomain";

export interface Edge {
  src: string;
  dst: string;
  rel: AssetRel | ExploreRel;
}

// Task asset view — server-side enriched, paginated.
export interface TaskAssetRef {
  id: string;
  name?: string;
  key: string;
  attrs?: Record<string, unknown>;
}

export interface TaskAssetItem extends AssetNode {
  techs?: TaskAssetRef[];
  auth?: TaskAssetRef[];
  params?: TaskAssetRef[];
}

export interface TaskAssetView {
  counts: Record<string, number>;
  total: number;
  items: TaskAssetItem[];
}

// ---- New unified asset model (new backend) ----
export type NewAssetType = "root_domain" | "ip" | "subdomain" | "app" | "service" | "endpoint";

export interface Asset {
  id: number;
  type: NewAssetType;
  company_id?: number;
  task_ids: number[];
  domain?: string;
  root_domain?: string;
  ip?: string;
  c_segment?: string;
  port?: number;
  icp?: string;
  bound_domains?: string[];
  open_ports?: { port: number; service?: string }[];
  record_type?: string;
  record_value?: string[] | string;
  bundle_id?: string;
  app_name?: string;
  category?: string;
  app_description?: string;
  app_icp?: string;
  url?: string;
  service_type?: string;
  service_name?: string;
  favicon_mmh3?: string;
  status_code?: number;
  content_length?: number;
  page_title?: string;
  technologies?: string[];
  auth?: Record<string, unknown>[];
  method?: string;
  params?: Record<string, unknown>[];
  extra?: Record<string, unknown>;
  /** 资产出处:空间测绘引擎(Quake/FOFA...)、agent、manual 等 */
  source?: string;
  last_seen: string;
  task_source?: string;
  task_source_summary?: string;
  task_source_node_id?: number;
  project_id?: number;
  /** 授权状态:approved|pending|rejected;空=未打标(视为已授权) */
  authz?: string;
}

// 待审批资产轻量探活结果(POST /api/assets/probe)。
export interface AssetProbeResult {
  id: number;
  alive: boolean;
  ports?: number[];
  ptr?: string[];
  cert_names?: string[];
  http_status?: number;
  server?: string;
  title?: string;
  /** 像是本项目授权面的线索:PTR/证书 SAN 命中授权域 */
  ownership?: string[];
  error?: string;
}

// ---- 4zreark 资产同步 ----

/** 4zreark MCP list_projects 返回的项目。 */
export interface AssetSyncSourceProject {
  id: number;
  code: string;
  name: string;
  asset_count?: number;
  lost_count?: number;
  record_count?: number;
  collection_paused?: boolean;
}

export interface AssetSyncRequest {
  base_url?: string;
  api_key?: string;
  source_project_id?: number;
  target_project_id?: number;
  catalog?: "all" | "verified";
  limit?: number;
  dry_run?: boolean;
  /** 同时拉取站点路由（4zreark site_routes → 4zrec endpoint 资产）。 */
  include_routes?: boolean;
}

// ---- 4zreark 平台集成 ----

/** GET /api/assets/zreark/config：连接配置回显（key 只回掩码）。 */
export interface ZrearkConfig {
  base_url: string;
  api_key_masked: string;
  configured: boolean;
  from_env: boolean;
}

export interface ZrearkDispatchRequest {
  base_url?: string;
  api_key?: string;
  source_project_id: number;
  name: string;
  type: string;
  targets: string[];
  target_type: "domain" | "ip" | "url" | "cidr";
  description?: string;
  auto_start?: boolean;
}

export interface ZrearkDispatchResult {
  task_id: string;
  status: string;
  targets: number;
  started: boolean;
  start_error?: string;
}

/** POST /api/assets/zreark/tasks：4zreark 远端任务归一化视图。 */
export interface ZrearkTask {
  id: string;
  name: string;
  type: string;
  status: "pending" | "running" | "paused" | "completed" | "failed" | "cancelled";
  progress: number;
  target_count: number;
  target_type: string;
  discovered_assets: number;
  discovered_ports: number;
  last_error?: string;
  created_at?: string;
  completed_at?: string;
}

export interface ZrearkTaskResultsRequest {
  base_url?: string;
  api_key?: string;
  task_id: string;
  include?: ("service" | "crawler")[];
  target_project_id?: number;
  limit?: number;
  dry_run?: boolean;
}

export interface ZrearkTaskResultsResult {
  task_id: string;
  fetched: number;
  /** 指纹结果落库数（service 资产，含技术栈/指纹合并）。 */
  services: number;
  /** 爬虫路由落库数（endpoint 资产）。 */
  endpoints: number;
  assigned: number;
  skipped: number;
  errors: string[];
  dry_run: boolean;
}

export interface AssetSyncSample {
  host: string;
  url: string;
  status_code?: number;
  title?: string;
  ip?: string;
}

export interface AssetSyncResult {
  total: number;
  fetched: number;
  would_import: number;
  imported: number;
  assigned: number;
  routes: number;
  skipped: number;
  errors: string[];
  sample: AssetSyncSample[];
  dry_run: boolean;
}

export interface IntentAsset {
  intent_id: number | string;
  asset_id: number;
  type: NewAssetType;
  label: string;
  source: string;
  source_summary: string;
  source_node_id?: number;
  source_task_id: number;
  inherited: boolean;
}

export interface TaskAssetMutation {
  requested: number;
  attached: number;
  existing: number;
}

export interface TaskAssetScopeMutation {
  requested: number;
  assets_linked: number;
  assets_existing: number;
  scopes_added: number;
  scopes_existing: number;
}

// ---- Asset coverage graph (per task) ----
// 力导向「资产覆盖图」的一个节点。key 唯一：资产="a:<id>"、公司="c:<id>"、
// 无资产行的根域名="r:<domain>"。in_scope=false 的是仅用于连线的灰色上下文节点。
export interface CoverageGraphNode {
  key: string;
  kind: "company" | "root_domain" | "subdomain" | "ip" | "service" | "app" | "endpoint";
  label: string;
  tested: boolean;
  in_scope: boolean;
  asset_id?: number;
  company_id?: number;
  domain?: string;
  root_domain?: string;
  ip?: string;
  url?: string;
  port?: number;
  service_type?: string;
  app_name?: string;
  page_title?: string;
  status_code?: number;
}

export interface CoverageGraphEdge {
  src: string;
  dst: string;
}

export interface CoverageGraphData {
  nodes: CoverageGraphNode[];
  edges: CoverageGraphEdge[];
}

// 某资产在本任务探索图里关联到的意图/事实/发现（覆盖图节点抽屉用）。
export interface CoverageAssetRef {
  id: number;
  kind: string;
  state: string;
  summary: string;
  source_task_id?: string;
  inherited?: boolean;
}
export interface CoverageAssetRefs {
  intents: CoverageAssetRef[];
  facts: CoverageAssetRef[];
  findings: CoverageAssetRef[];
}

// ---- Workspace file manager (workDir) ----
export interface WorkspaceEntry {
  name: string;
  path: string; // workspace-relative, forward slashes
  dir: boolean;
  size: number;
  mtime: number; // unix millis
}
export interface WorkspaceListing {
  path: string;
  entries: WorkspaceEntry[];
}
export interface WorkspaceFile {
  path: string;
  size: number;
  binary: boolean;
  too_large?: boolean;
  content?: string;
}

// 任务测试范围的一条（覆盖度分母 + 授权边界）。
export interface TaskScopeRow {
  id: number;
  task_id: number;
  kind: "company" | "root_domain" | "subdomain" | "ip" | "cidr" | "icp" | "keyword";
  company_id?: number;
  company_name?: string; // 后端 JOIN companies 解析，仅 kind=company 有值
  domain?: string;
  net?: string;
  value?: string;
  source: "auto" | "agent" | "manual";
  reason?: string;
}

export type CompanyScopeKind = "domain" | "ip" | "cidr" | "icp" | "keyword";

// 新增企业时提交的结构化资产范围规则。
export interface CompanyScopeRule {
  kind: CompanyScopeKind;
  value: string;
}

// 资产范围写入的结果。errors 是本次提交里不合法的行；warnings 是与本次提交无关、
// 但会让归属结果不符合预期的既有数据问题（如 ip 字段存了主机名的资产）。
export interface CompanyScopeMutation {
  added: number;
  skipped: number;
  invalid: number;
  errors?: string[];
  warnings?: string[];
}

// 公司资产范围规则的一条（归属唯一真值来源）。
export interface ScopeRow {
  id: number;
  company_id: number;
  kind: CompanyScopeKind;
  domain?: string; // kind=domain 时有值
  net?: string; // kind=ip|cidr 时有值
  value?: string; // kind=icp|keyword 时可能由后端直接返回
  raw: string; // 原始用户输入，用于显示和回填
  reason?: string;
}

// 企业：type=company 的资产节点 + 图标 + 资产计数 + 资产范围规则。
export interface ProjectScope {
  id: number;
  project_id: number;
  kind: "domain" | "ip" | "cidr" | "icp" | "keyword";
  domain?: string;
  net?: string;
  value?: string;
  raw: string;
  reason?: string;
  created_at: string;
}

export interface Project {
  id: number;
  name: string;
  company_id?: number;
  company_name?: string;
  description?: string;
  status: "active" | "archived";
  asset_count: number;
  pending_count: number;
  task_count: number;
  scope: ProjectScope[];
  created_at: string;
  updated_at: string;
}

export interface Company {
  id: number;
  name: string;
  logo?: string; // 远程图标 URL；空则前端用名称首字母
  asset_count: number;
  scope?: ScopeRow[];
}

// ---- Exploration graph (per task) ----
export type ExploreKind = "task" | "begin" | "goal" | "intent" | "fact" | "finding" | "hint" | "digest";
export type GoalState = "open" | "met" | "abandoned";
export type IntentState = "open" | "running" | "paused" | "done" | "blocked" | "exhausted" | "stopped";
export type FindingState = "confirmed" | "dismissed";
export type HintState = "active" | "consumed";
export type ExploreRel = "spawns" | "derived_from" | "yields" | "proves" | "covers";

export interface TaskNode {
  id: string;
  type: ExploreKind;
  payload?: string;
  priority: number; // 0..10
  state: string; // GoalState | IntentState | FindingState | HintState
  origin: string;
  ts: string;
  source_task_id?: string;
  inherited?: boolean;
  delete_reason?: string; // 意图假删除(state='deleted')时的删除原因
}

// 播报板一页:按创建顺序分页的节点 + 这一页涉及的边 + 边另一端的节点(refs,按 id 索引),
// 这样每条播报都能说清「从哪来、产出了什么」,而不用把整张图拉下来。
export interface ExplorationNodePage {
  items: TaskNode[];
  total: number;
  page: number;
  size: number;
  edges: Edge[];
  refs: Record<string, TaskNode>;
  // 节点 id → 该节点锚定的资产(播报板展开时顺带展示,含本页节点与其邻居)。
  assets: Record<string, FindingAsset[]>;
}

export interface ExplorationNodeQuery {
  page?: number;
  size?: number;
  kinds?: ExploreKind[];
  states?: string[];
  q?: string;
  order?: "asc" | "desc";
}

// 目标管理卡片用的目标(后端已把 payload 拆成 text/vulnclass)。
export interface TaskGoal {
  id: string;
  text: string;
  vulnclass?: string;
  state: string; // GoalState
  origin?: string;
  ts: string;
}

// 约束管理卡片用的操作约束(allow=允许 / deny=禁止)。
export type ConstraintKind = "allow" | "deny";
export interface TaskConstraint {
  id: string;
  kind: ConstraintKind;
  text: string;
  origin?: string;
  ts?: string;
}

// ---- Findings ----
export type Severity = "critical" | "high" | "medium" | "low";

// 漏洞处置状态:待处理 / 处理中 / 已确认 / 已处理 / 已修复 / 误报 / 忽略 / 重复 / 风险接受。
export type FindingStatus =
  | "pending"
  | "in_progress"
  | "confirmed"
  | "resolved"
  | "fixed"
  | "false_positive"
  | "ignored"
  | "duplicate"
  | "risk_accepted";

// FindingAsset 是一个漏洞绑定的资产(已在后端预渲染 label)。
export interface FindingAsset {
  id: string;
  type: string;
  label: string;
}

// FindingReproduction 是 agent report_finding 时上报的结构化复现过程
// (与工具 schema 对齐;steps 的 request/expected 逐字取自真实请求响应)。
export interface FindingReproduction {
  entry_point?: string;
  prerequisites?: string[];
  steps?: { request: string; expected: string; proves?: string }[];
  provenance?: string;
}

export interface Finding {
  // enrichment summary(列表合并展示;AI 分析产出)
  enr_name?: string;
  enr_target?: string;
  enriched?: boolean;
  traffic_count?: number;
  evidence_version?: number;
  report_evidence_version?: number;
  report_stale?: boolean;
  id: string;
  finding_id?: string; // 独立 findings 表的行 id,状态更新的句柄(任务内旧节点可能缺失)
  vulnclass: string;
  name?: string; // 漏洞名称;为空时展示回退到 vulnclass
  severity: Severity;
  status: FindingStatus;
  // 服务端证据等级：verified 已验证 / partial 部分验证 / inferred 推断。
  confidence?: "verified" | "partial" | "inferred";
  summary: string;
  evidence: string;
  report?: string; // 详细报告(Markdown);仅详情接口返回,列表为空
  reproduction?: FindingReproduction; // 结构化复现过程;详情页优先按此渲染,空=未记录
  intent_id?: string;
  param_id?: string;
  task_id?: string;
  task_description?: string;
  source_task_id?: string;
  inherited?: boolean;
  assets?: FindingAsset[];
  ts: string;
}

// FindingsPage 是发现列表的服务端分页响应。
export interface FindingsPage {
  items: Finding[];
  total: number;
  page: number;
  page_size: number;
}

export interface FindingGroup {
  task_id: string | number | null;
  task_name?: string; // 可选任务名称;空/缺省=未命名
  task_description: string;
  task_status: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  last_found_at: string;
}

export interface FindingGroupsPage {
  items: FindingGroup[];
  total: number;
  finding_total: number;
  page: number;
  page_size: number;
}

export interface FindingDeepenResponse {
  task_id: string;
  intent_id: string;
  state: IntentState;
  queued: boolean;
}

// FindingStats 是发现全表聚合(统计卡 + 漏洞类型下拉),服务端计算,不受分页影响。
export interface FindingStats {
  total: number;
  pending: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  vulnclasses: string[];
  tasks: FindingTaskOption[];
}

// FindingTaskOption 是发现页「按任务」筛选下拉的一项:有漏洞的任务(描述为空表示任务已删除,
// 前端回退展示 id)及其漏洞条数。
export interface FindingTaskOption {
  id: string | number;
  name?: string; // 可选任务名称;空/缺省=未命名
  description: string;
  count: number;
}

// FindingQuery 是发现列表分页/筛选/排序参数。
export interface FindingQuery {
  page: number;
  pageSize: number;
  severity?: "all" | Severity;
  status?: "all" | FindingStatus;
  vulnclass?: string;
  task?: string; // 任务 id;"all"/空 = 不按任务筛选
  query?: string;
  sort?: "severity" | "time";
  // 资产树节点 key;选中一个节点 = 选中它的整棵子树。空 = 不按资产筛选。
  assetScope?: string;
  // 项目 id;>0 = 按项目筛选(finding 经任务归属项目)。项目详情页用。
  projectId?: number;
}

// ---- Findings by asset (资产视图) ----
export type FindingAssetKind = "company" | "root_domain" | "subdomain" | "ip" | "service" | "app" | "endpoint" | "none";

// FindingAssetNode 是资产树的一个节点。key 形如 a:<id>(资产)、c:<id>(企业)、
// r:<domain>(库里没有资产行的根域名)、__none__(未关联资产)。
export interface FindingAssetNode {
  key: string;
  parent?: string;
  kind: FindingAssetKind;
  label: string;
  asset_id?: number;
  company_id?: number;
  self: number; // 直接挂在该资产上的发现数
  total: number; // 含子孙、按发现去重
  critical: number;
  high: number;
  medium: number;
  low: number;
  last_found_at: string;
}

export interface FindingAssetTree {
  nodes: FindingAssetNode[];
  finding_total: number;
  truncated: boolean;
  dropped_kinds?: string[];
}

// FINDING_UNASSIGNED_ASSET 与后端 db.FindingUnassignedAsset 对应。
export const FINDING_UNASSIGNED_ASSET = "__none__";

// ---- Activity / sessions ----
export type ActivityKind =
  | "tool_use"
  | "tool_result"
  | "text"
  | "thinking"
  | "result"
  | "user"
  | "intent" // LLM-generated exploration objective leading a worker session (UI-synthesized)
  | "round" // planner round boundary marker (engine-emitted)
  | "usage" // live cumulative token usage (per model turn); not rendered
  | "llm_switch" // automatic/manual task-level LLM switch
  | "llm_failover" // task-level provider switch / chain exhaustion audit event
  | "intercept_request"; // user-approval request from the intercept layer

// ChatAttachment 是一次上传的文件:path 相对该会话/任务工作目录(即 agent 的 CWD)。
export interface ChatAttachment {
  name: string;
  path: string;
  size: number;
  abs?: string; // 绝对路径(scope=staging 暂存上传时返回;建任务前把它写进描述)
}

export interface Activity {
  seq: number;
  intent_id?: string;
  worker: string; // session owner: planner | mainagent | work#1 ...
  ts: string;
  kind: ActivityKind;
  tool?: string;
  tool_use_id?: string;
  is_error?: boolean;
  summary: string;
  detail?: string;
  metadata?: {
    llm_transition?: LLMTransition;
  };
  source_task_id?: string;
  inherited?: boolean;
  main_seg?: number; // main-agent conversation segment (present only on worker="mainagent" rows)
  // token usage (present only on kind='result')
  input_tokens?: number;
  output_tokens?: number;
  cache_read_tokens?: number;
  cache_write_tokens?: number;
}

export interface LLMAuditProfile {
  id: number;
  name: string;
  format: string;
  model: string;
}

export interface LLMTransition {
  mode: "automatic" | "manual" | "exhausted";
  reason: string;
  previous?: LLMAuditProfile;
  next?: LLMAuditProfile;
}

export interface TaskLLMResolution {
  profile_id?: number;
  name: string;
  format: string;
  model: string;
  source: "task_chain" | "agent_binding" | "global_profile" | "environment" | "global";
  available: boolean;
  reason?: string;
}

export interface TaskLLMResolutions {
  mainagent: TaskLLMResolution;
  planner: TaskLLMResolution;
  worker: TaskLLMResolution;
}

// ---- Agent triggers (P3 调度，仅自定义 agent) ----
export interface AgentTrigger {
  id: number;
  agent_key: string;
  enabled: boolean;
  interval_sec: number; // 定时:每 N 秒(0=不定时)
  on_finding: boolean; // 任意任务发现 finding 时触发
  on_goal_met: boolean; // 任意任务达成目标时触发
  on_task_timeout: boolean; // 任意任务超时时触发
  on_tool_call: boolean; // 选中工具被调用(执行完成)时触发
  on_task_create: boolean; // 任意任务被创建时触发
  interval_message: string; // 各触发条件的独立用户消息
  finding_message: string;
  goal_message: string;
  task_timeout_message: string;
  tool_call_message: string;
  task_create_message: string;
  tool_names: string[]; // on_tool_call 选中的工具 key(至少一个)
  last_fire?: string;
}

// ---- Conversations (chat page) ----
export interface ActiveFindingRetest {
  id: number;
  finding_id: string;
  conversation_id: number;
  status: "pending" | "running";
}

export interface FindingRetest {
  id: number;
  finding_id: number;
  conversation_id: number | null;
  status: "pending" | "running" | "completed" | "failed" | "stopped";
  verdict: "" | "reproduced" | "fixed" | "inconclusive";
  notes: string;
  summary: string;
  evidence: string;
  error: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface Conversation {
  id: number;
  running?: boolean; // live server state, returned with the conversation list
  agent_key: string;
  title: string;
  llm_profile_id?: number;
  project_id?: number; // 归属项目(挂载后资产围栏生效)
  task_id?: number; // 关联任务(设置时通常同时把 project_id 对齐到任务所属项目)
  pinned?: boolean;
  pinned_at?: string | null;
  created_at: string;
  updated_at: string;
}

// ---- Backend logs (/logs page) ----
export interface LogLine {
  seq: number;
  db_id?: number; // server_logs.id; present for DB-persisted lines
  ts: string;
  level: "info" | "warn" | "error";
  tag: string;
  text: string;
}

export type SessionRole = "mainagent" | "planner" | "worker" | "system";
export type SessionStatus = "running" | "paused" | "done" | "blocked" | "exhausted" | "pending" | "stopped" | "deleted";

// Daily token aggregate bucket (GET /api/tokens/daily).
export interface DailyTokenBucket {
  date: string; // "YYYY-MM-DD"
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

// Per-worker token usage (GET /api/exploration/tokens).
export interface TokenUsage {
  worker: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

export interface SessionTokenUsage {
  session: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

export interface BatchControlItem {
  id: string;
  ok: boolean;
  status?: string;
  queued?: boolean;
  error?: string;
}

// 批量改分类的逐任务结果。失败只可能是任务已被删除，分类本身的写入是原子的。
export interface BatchCategoryItem {
  id: string;
  ok: boolean;
  error?: string;
}

// Whole-task (all agents) token aggregate.
export interface TokenTotal {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

// Global per-profile token spend from the llm_usage ledger (GET /api/tokens/usage).
export interface ProfileUsage {
  profile_name: string;
  calls: number;
  tasks: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  // 费用(按 llm_pricing 单价算;仅在线账本,归档聚合无 model 维度不计价)
  cost?: number;
}

// One (profile, UTC day) token bucket for the dashboard's daily chart (new source).
export interface ProfileDayUsage {
  profile_name: string;
  date: string; // YYYY-MM-DD
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cost?: number;
}

// 模型单价(每 1M tokens);model_pattern 支持精确名与 "prefix*" 通配。
export interface LLMPricing {
  model_pattern: string;
  input_per_mtok: number;
  output_per_mtok: number;
  cache_read_per_mtok: number;
  cache_write_per_mtok: number;
  currency: string;
}

// 账本里实际出现的模型(用于单价编辑弹窗预填)。
export interface ModelUsageLite {
  model: string;
  profile_name: string;
  calls: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

// Response of GET /api/llm/pricing.
export interface LLMPricingBook {
  rules: LLMPricing[];
  models: ModelUsageLite[];
}

// Response of GET /api/tokens/usage — the dashboard's "new" (llm_usage) token view.
export interface UsageStats {
  by_profile: ProfileUsage[];
  daily: ProfileDayUsage[];
  // 全局去重任务数(命中 llm_usage 账本 + 归档聚合);「全部」Tab 用它,
  // 不能把各 profile 的 tasks 相加(同一任务可能用过多个 profile)。
  tasks: number;
  // 费用合计与币种;unpriced_models 是账本里有消耗但没配单价的模型。
  cost: number;
  currency: string;
  unpriced_models: string[];
}

// 持久 API Key(元数据,不含明文;明文只在创建响应里出现一次)。
export interface APIKeyRecord {
  id: number;
  name: string;
  prefix: string;
  scope: "global" | "project";
  project_id?: number;
  enabled: boolean;
  expires_at?: string;
  last_used_at?: string;
  created_at: string;
}

// Per-model token usage for one task (GET /api/llm/records/by-model), from the
// always-on llm_usage metering ledger. calls = number of LLM calls on this model.
export interface ModelTokenStat {
  model: string;
  calls: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

export interface Session {
  id: string;
  role: SessionRole;
  title: string;
  status: SessionStatus;
  live: boolean;
  last_activity: string;
  intent_id?: string;
  source_task_id?: string;
  inherited?: boolean;
  seg?: number; // main-agent session: which conversation segment (0 = original)
}

// ---- Security ----
export interface AuditEntry {
  ts: string;
  tool: string;
  action: "allow" | "block";
  reason?: string;
  command?: string;
}

export interface Audit {
  entries?: AuditEntry[];
  attributions?: Record<string, number>;
}

// ---- Traffic ----
export interface TrafficExchange {
  id: string;
  ts: string;
  host: string;
  method: string;
  url: string;
  status: number;
  content_type: string;
  resp_len: number;
}

export interface TrafficResp {
  enabled: boolean;
  proxy?: string;
  count?: number; // global total (unfiltered)
  total?: number; // rows matching the current filter (for pagination)
  page?: number;
  size?: number;
  exchanges?: TrafficExchange[];
}

// Full raw request/response of one exchange (lazy-loaded on row select).
export interface TrafficDetail {
  req: string;
  resp: string;
}

// One distinct recorded host with its exchange count (target picker).
export interface TrafficHost {
  host: string;
  count: number;
}

// ---- 代理库 ----
export interface ProxyProfile {
  id: string;
  name: string;
  url: string;
  note?: string;
}

export interface ProxySelections {
  global: string;
  web_search: string;
  nuclei: string;
  fingerprint: string;
  update: string;
}

export interface ProxyGallery {
  profiles: ProxyProfile[];
  selections: ProxySelections;
  urls: ProxySelections;
}

// ---- App settings (runtime toggles) ----
export interface Settings {
  traffic_capture: boolean;
  agent_traffic_binding: boolean; // Agent 自动绑定流量证据，默认关闭；不影响人工绑定
  llm_record: boolean; // LLM 录制开关（默认关）；关闭时不记录任何 LLM 调用
  // Web search. brave_key_set / tavily_key_set reflect whether a key is stored
  // (the values are never returned). On PUT, send the corresponding field to set/clear.
  web_search_enabled: boolean;
  web_search_backend: string; // "ddgs" | "brave-free" | "tavily" | "deepseek"
  brave_key_set: boolean;
  tavily_key_set: boolean;
  // write-only: only sent on PUT to store/clear the key.
  brave_search_api_key?: string;
  tavily_search_api_key?: string;
  // 独立出口代理(http/https/socks5)，用于访问搜索端点；与记录流量的 MITM 代理无关。空=直连。
  web_search_proxy?: string;
  // 全局出口代理(http/https/socks5，可带 user:pass)，所有目标流量走它。开启流量捕获时作为
  // MITM 上游；关闭捕获时直接注入 agent 的 bash/WebFetch。空=直连。
  global_proxy?: string;
  python_interpreter?: string; // 自定义脚本工具的 python 解释器路径(空=运行时检测)
  workers?: number; // 并发工作 agent 数(默认3)；对之后启动的任务生效
  // 任务并发上限:同时「运行中」的任务数上限。关闭=不限;开启后新建任务超限则排队,有空位自动启动。
  task_concurrency_enabled?: boolean; // 默认 false
  task_concurrency_limit?: number; // 开启后默认 5
  // LLM 轮询(故障转移)。默认关；开启后「未指定模型」的 agent 在当前配置不可用
  // （余额不足/key 失效/限流/服务异常）时自动切到下一个配置。
  llm_pool_enabled?: boolean; // 默认 false
  // 绑定了指定配置的 agent/任务失败时是否也回落到轮询链。默认 false = 绑定即独占。
  llm_pool_bind_fallback?: boolean;
  // 操作约束注入范围(默认都开):把任务的 allow/deny 约束拼进对应 agent 的系统提示。
  constraints_inject_planner?: boolean;
  constraints_inject_worker?: boolean;
  // 实验功能:noa 模型驱动上下文压缩(默认关)。开启后平台接入的四类 agent(planner/
  // worker/主 agent/对话)由 noa 接管上下文压缩,取代内置 compaction;每 run 读一次,对
  // 之后启动的 run 生效。
  noa_compaction?: boolean;
  // ---- nuclei（项目自带外部二进制，见 data/nuclei）----
  nuclei_enabled?: boolean; // 工具总开关，默认 true
  nuclei_auto_update?: boolean; // 扫描前/后台自动更新，默认 true
  nuclei_update_interval_hours?: number; // 更新间隔，默认 24 小时
  nuclei_version?: string; // 首次下载的引导版本，默认 3.11.1
  nuclei_interactsh?: boolean; // 是否启用 interactsh，默认 false
  nuclei_max_scan_seconds?: number; // 默认扫描时长上限，默认 600 秒
  nuclei_proxy?: string; // 下载/更新 nuclei 二进制与模板使用的代理；空=直连
  // ---- 代理库（命名代理 + 每个用途的手动选择）----
  proxy_profiles?: ProxyProfile[];
  proxy_selections?: ProxySelections;
  proxy_urls?: ProxySelections;
  update_proxy?: string; // 平台自更新代理；空=直连
  // ---- 漏洞 IM 推送（渠道本身是独立资源，见 /api/notify/*，这里只有三项全局配置）----
  notify_enabled?: boolean; // 推送总开关，默认开；用于维护期一键止血
  notify_public_base_url?: string; // 漏洞详情回链的外部访问地址；空=消息不带回链
  notify_digest_interval_min?: number; // 汇总模式周期（分钟），默认 30
  // ---- IM 接入网关（对话式绑定：IM 里 /bond 绑定项目任务、/new 新会话）----
  im_bot?: ImBotSettings;
}

// IM 接入各平台的凭据回显：密钥类只回 *_set（值永不返回）；PUT 时对应字段
// 省略=不改、空串=清除。
export interface ImBotSettings {
  agent_key: string;
  feishu: { enabled: boolean; app_id: string; app_secret_set: boolean };
  dingtalk: { enabled: boolean; client_id: string; client_secret_set: boolean };
  telegram: { enabled: boolean; bot_token_set: boolean; proxy: string };
  wecom: {
    enabled: boolean;
    corp_id: string;
    corp_secret_set: boolean;
    agent_id: number;
    callback_token_set: boolean;
    encoding_aes_key_set: boolean;
    callback_url: string;
    base_url_set: boolean;
  };
}

// PUT /settings 里 im_bot 的写入形状（write-only 密钥字段）。
export interface ImBotSettingsInput {
  agent_key?: string;
  feishu?: { enabled: boolean; app_id?: string; app_secret?: string };
  dingtalk?: { enabled: boolean; client_id?: string; client_secret?: string };
  telegram?: { enabled: boolean; bot_token?: string; proxy?: string };
  wecom?: {
    enabled: boolean;
    corp_id?: string;
    corp_secret?: string;
    agent_id?: number;
    callback_token?: string;
    encoding_aes_key?: string;
  };
}

// nuclei_status 接口返回：项目内二进制的安装/更新状态。
export interface NucleiStatus {
  root: string;
  binary_path: string;
  binary_exists: boolean;
  binary_version?: string;
  templates_dir: string;
  custom_templates_dir?: string;
  templates_exists: boolean;
  custom_templates_exists?: boolean;
  template_count: number;
  custom_template_count?: number;
  version_setting: string;
  auto_update: boolean;
  update_interval_hours: number;
  last_update?: string;
  interactsh: boolean;
  warnings?: string[];
}

export interface NucleiTemplateMeta {
  id: string;
  name: string;
  severity: string;
  tags?: string[];
  cve?: string[];
  type: string;
  path: string;
  source: "official" | "custom";
  author?: string;
  description?: string;
}

export interface NucleiTemplateList {
  items: NucleiTemplateMeta[];
  total: number;
  page: number;
  size: number;
  warning?: string;
}

export interface NucleiTemplateDetail {
  meta: NucleiTemplateMeta;
  content: string;
  editable: boolean;
}

export interface NucleiUpdateJob {
  running: boolean;
  phase?: string;
  percent?: number;
  message?: string;
  started_at?: string;
  finished_at?: string;
  error?: string;
  result?: {
    binary_version?: string;
    template_count?: number;
    custom_template_count?: number;
    warnings?: string[];
  };
}

// ---- 漏洞 IM 推送 ----

// NotificationFilter 是渠道的过滤条件，字段全部可选，缺省即不过滤。
// 后端对所有字段都不加校验：配置畸形时按「命中」处理（宁可多推不可漏推）。
export interface NotificationFilter {
  min_severity?: string; // "" | low | medium | high | critical
  task_ids?: number[]; // 空=不限；非空则要求与漏洞所属任务有交集
  asset_ids?: number[]; // 空=不限；非空则要求与漏洞锚定资产有交集
  vulnclass_include?: string[]; // 空=全收；非空则要求漏洞类型命中任一关键词（大小写不敏感子串）
  vulnclass_exclude?: string[]; // 命中任一关键词即排除（排除优先于包含）
  event_kinds?: string[]; // 订阅的事件类型；空=旧行为（发现漏洞 + 可选状态变更）
  on_status_change?: boolean; // 旧字段，仅 event_kinds 为空时生效
}

// NotificationChannel 是一个渠道实例。config 的字段随 kind 而异，
// 且凭据字段在读取时被替换成 "__masked__" 开头的掩码值——原样回传即表示「不改」。
export interface NotificationChannel {
  id: number;
  name: string;
  kind: string;
  enabled: boolean;
  mode: "realtime" | "digest";
  config: Record<string, unknown>;
  filter: NotificationFilter;
  rate_per_min: number;
  created_at: string;
  updated_at: string;
  // secret_keys 由后端按渠道类型给出，前端据此渲染密码框与「留空即不改」提示，
  // 不硬编码任何渠道知识。
  secret_keys: string[];
}

// NotificationKind 是 /api/notify/meta 返回的渠道类型元数据。
export interface NotificationKind {
  kind: string;
  default_rate_per_min: number;
  secret_keys: string[];
}

export interface NotificationEventKind {
  kind: string;
  label: string;
  category: string;
  default: boolean;
  description?: string;
}

export interface NotificationMeta {
  kinds: NotificationKind[];
  event_kinds: NotificationEventKind[];
  default_event_kinds: string[];
  enabled: boolean;
  public_base_url: string;
  digest_interval_min: string;
  defaults: { digest_interval_min: number };
  stats: {
    channels: number;
    channels_on: number;
    pending: number;
    failed: number;
    sent_today: number;
    backlog_age_ms: number;
  };
}

// NotificationDelivery 是一条投递记录，用于投递历史与失败重发。
export interface NotificationDelivery {
  id: number;
  finding_id: string;
  event_kind: string; // finding_created | finding_status_changed
  channel_id: number;
  channel_name: string;
  channel_kind: string;
  state: "pending" | "sending" | "sent" | "failed" | "skipped";
  attempts: number;
  last_error: string;
  batch_id?: number;
  created_at: string;
  sent_at?: string;
  next_attempt_at: string;
  title: string;
  severity: string;
}

// ---- LLM config ----
export interface LLMProfile {
  id: string;
  name: string;
  format: "openai" | "anthropic" | "openai-responses";
  base_url?: string;
  proxy?: string;
  model: string;
  api_key_hint?: string;
  rate_per_second: number;
  rate_per_minute: number;
  context_window_k?: number;
  // 思考开关(thinking.type): ""=不发送(默认) | "disabled"=关闭 | "enabled"=开启
  thinking_type?: string;
  // 思考强度: ""=不发送(默认) | "low"/"medium"/"high"/"xhigh"/"max"
  reasoning_effort?: string;
  is_default: boolean;
  // 轮询顺位：越大越先被选中。激活配置恒为链首，与本值无关。
  priority?: number;
  // true = 不作为故障转移目标（仍可被 agent/任务显式绑定使用）。
  pool_exclude?: boolean;
  // true（默认）= 流式(SSE) | false = 真·非流式(stream:false，一次性返回)。
  streaming?: boolean;
  // 单次回复的输出上限(token)。0 = 不发送该字段，由服务端默认值决定。
  // 注意与 context_window_k 区分：后者是模型总容量，只在本地用于压缩阈值。
  max_tokens?: number;
  // 上限用哪个请求字段名，仅 format="openai" 有意义：
  // ""=max_tokens(默认) | "max_completion_tokens"(OpenAI 推理模型只认它)
  max_tokens_field?: string;
  // 自定义会话头名：非空时每次请求带该 HTTP 头，头值=当前会话/意图的 session id。
  // ""=不发送。用于按 session-id 头做提示缓存/粘性路由的网关。
  session_header_key?: string;
  // 本配置对重试的覆盖（建连/空响应/同 provider 安全窗口）。留空/全 0 = 跟随全局策略。
  retry?: LLMRetryOverride;
}

// ---- LLM 重试策略 ----
// 一层重试的两个旋钮。两者都是「0 = 未配置」：
//   attempts    0=用默认次数 | -1=关闭该层重试 | >0=重试次数
//   interval_ms 0=用默认的指数退避 | >0=改用这个固定毫秒间隔
export interface LLMRetryRule {
  attempts: number;
  interval_ms: number;
}

// 单个 LLM 配置能覆盖的三层（都是「跟着端点走」的重试）。
export interface LLMRetryOverride {
  connect: LLMRetryRule; // 建连重试：连接重置/超时/429/5xx，流开始前
  empty: LLMRetryRule; // 空响应重试：完成但没有任何内容（仅 openai 格式）
  stream: LLMRetryRule; // 同 provider 安全窗口重试：未交付输出前的断流重放
}

// 全局策略 = 上面三层的默认值 + 两层只有全局的：
//   breaker 轮询熔断（attempts=连续几次瞬时失败熔断，interval_ms=固定冷却时长）
//   intent  意图重跑（worker 以 model_error 收场后整条意图重跑）
export interface LLMRetryPolicy extends LLMRetryOverride {
  breaker: LLMRetryRule;
  intent: LLMRetryRule;
}

// ---- LLM 轮询（故障转移）----
// 一个配置在轮询链中的位置与健康状态。state:
//   ok       正常
//   degraded 有连续失败但未达熔断阈值
//   tripped  已熔断，冷却期内被跳过（cooldown_secs 为剩余秒数）
export interface LLMPoolMember {
  profile_id: string;
  name: string;
  model: string;
  format: string;
  priority: number;
  active: boolean; // 是否为当前激活配置（恒为链首）
  excluded: boolean; // pool_exclude：不参与轮询
  state: "ok" | "degraded" | "tripped";
  fails: number;
  trips: number;
  cooldown_secs: number;
  last_error?: string;
  last_at?: string;
}

export interface LLMPoolStatus {
  enabled: boolean;
  bind_fallback: boolean;
  chain: LLMPoolMember[];
}

// ---- Agents ----
export interface Agent {
  id: string;
  key: string; // 内置为 goals/planner/mainagent/worker；自定义为用户自定 key
  name: string;
  description?: string;
  role: string;
  builtin: boolean;
  enabled: boolean;
  llm_profile_id?: number | null; // 绑定的 LLM 配置；null/absent = 跟随任务/会话/全局
  max_turns?: number; // 0 = 无限制
  run_seconds?: number; // worker 单次运行墙钟上限(秒)；0 = 无限制
  web_search?: boolean; // 是否启用网络搜索(受系统全局开关门控)
  interactive_shell?: boolean; // 是否启用交互式 shell(持久 PTY 会话工具族)
  // P3 触发后处理策略(仅自定义 agent 有意义)
  trigger_run_mode?: "serial" | "parallel"; // 串行排队 / 每次触发各自并发一个会话
  trigger_merge_mode?: "by_task" | "all" | "none"; // 仅 serial：同任务合并 / 全部合并 / 不合并
  trigger_max_parallel?: number; // 仅 parallel：每 agent 并发上限；0=不限
  // 绑定数量(仅列表接口返回)：可见 MCP / 可见 Skill / 绑定工具
  mcp_count?: number;
  skill_count?: number;
  tool_count?: number;
}

export interface PromptVar {
  name: string;
  description: string;
  example: string;
  source: "exploration" | "runtime" | "distilled";
}

export interface PromptVersion {
  version: number;
  ts: string;
  note: string;
  template_text: string;
}

export interface AgentDetail {
  agent: Agent;
  prompt: string;
  variables: PromptVar[];
  versions: PromptVersion[];
  visibility: { mcp: number[]; skill: string[] };
  // 可绑定的 LLM 配置候选(供「默认模型」下拉)；当前绑定见 agent.llm_profile_id
  llm_profiles?: { id: number; name: string; model: string; is_default: boolean }[];
  wrapup_prompt?: string; // 已保存的收尾提示词(空=用内置默认)
  wrapup_default?: string; // 内置默认收尾提示词(占位/恢复默认)
  wrapup_max_turns?: number; // 已保存的收尾轮数(0=用内置默认)
  wrapup_max_turns_default?: number; // 内置默认收尾轮数(供 "0=默认N" 提示)
  // 任务级超时收尾词(仅 worker/planner，task_timeout_wrapup_supported=true 时才显示该分区)
  task_timeout_wrapup_supported?: boolean;
  task_timeout_wrapup_prompt?: string;
  task_timeout_wrapup_default?: string;
  task_timeout_wrapup_max_turns?: number;
  task_timeout_wrapup_max_turns_default?: number;
}

// ---- MCP ----
export interface MCPServer {
  id: number;
  name: string;
  transport: "stdio" | "http" | "sse";
  command?: string;
  args: string[];
  env: Record<string, string>;
  url?: string;
  enabled: boolean;
  insecure?: boolean; // http: skip TLS cert verification (self-signed servers)
  tools?: string[]; // mcp_tools_cache (names only, for the count)
}

// ---- 空间测绘搜索行(引擎原始返回归一化,不落库) ----
export interface SpacemapSearchRow {
  host: string;
  domain: string;
  ip: string;
  port: number;
  title: string;
  protocol: string;
  server: string;
  country: string;
  city: string;
}

// ---- 空间测绘结果 ----
export interface SpacemapResultRow {
  id: number;
  type: string;
  label: string;
  port?: number;
  title: string;
  source: string;
  authz?: string | null;
  technologies: string[];
  project_id?: number | null;
  last_seen: string;
}

// ---- 企业采集任务/候选 ----
export interface EntJob {
  id: string;
  project_id: string;
  provider: string;
  keyword: string;
  status: string;
  depth: number;
  max_nodes: number;
  nodes: number;
  entities: number;
  domains: number;
  imported: number;
  error: string;
  created_at: string;
}

export interface EntCandidate {
  id: string;
  job_id: string;
  source: string;
  job_name: string;
  value: string;
  entity_name: string;
  status: string;
  fingerprint_status: string;
}

// ---- 指纹规则库 ----
export interface FingerprintRule {
  id: string;
  name: string;
  category: string;
  expression: string;
  source: string;
  enabled: boolean;
}

export interface FingerprintSource {
  name: string;
  upstream_url: string;
  rule_count: number;
  fetched_at: string;
}

export interface FingerprintStatus {
  sources: FingerprintSource[];
  total: number;
  enabled: number;
  syncing: boolean;
  proxy: string;
}

export interface FingerprintSyncOutcome {
  source: string;
  changed: boolean;
  content_hash?: string;
  imported?: number;
  reason: string;
  error?: string;
}

export interface FingerprintSyncJob {
  running: boolean;
  phase?: string;
  percent?: number;
  message?: string;
  started_at?: string;
  finished_at?: string;
  error?: string;
  outcomes?: FingerprintSyncOutcome[];
}

// ---- 被动源凭据(VT/GitHub) ----
export interface IntelKey {
  key: string;
  label: string;
  env: string;
  from_env: boolean;
  configured: boolean;
  masked: string;
}

// ---- 连接台账 ----
export interface Connection {
  id: number;
  project_id: number;
  project_name?: string;
  kind: string;
  host: string;
  port: number;
  username: string;
  secret: string;
  extra: Record<string, unknown> | null;
  source: "manual" | "discovered";
  status: "unknown" | "alive" | "dead";
  last_checked_at?: string | null;
  note: string;
  created_at: string;
  updated_at: string;
}

// ---- 企业数据源 ----
export interface EntProvider {
  name: string;
  label: string;
  auth: string;
  available: boolean;
  hint: string;
  configured: boolean;
}

// ---- 测绘流水线运行记录 ----
export interface ReconRun {
  id: number;
  project_id?: number | null;
  schedule_id?: number | null;
  domains: string[];
  config: Record<string, unknown> | null;
  status: "running" | "done" | "failed";
  stage: string;
  stats: {
    candidates?: number;
    live?: number;
    new_assets?: number;
    open_ports?: number;
    http_alive?: number;
    levels?: Record<string, number>;
    errors?: string[];
  } | null;
  error: string;
  created_at: string;
  finished_at?: string | null;
}

// ---- 周期采集任务 ----
export interface ReconSchedule {
  id: number;
  name: string;
  kind: "engine" | "pipeline" | "zreark";
  config: Record<string, unknown> | null;
  interval_sec: number;
  project_id?: number | null;
  enabled: boolean;
  last_run_at?: string | null;
  next_run_at: string;
  auth_failures: number;
  backoff_until?: string | null;
  last_result: string;
  last_new: number;
  created_at: string;
}

// ---- 空间测绘引擎 ----
export interface SpacemapEngine {
  provider: string;
  display: string;
  configured: boolean;
  key_masked: string;
  from_env: boolean;
  base_url: string;
  default_query: string;
}

export interface MCPTool {
  name: string;
  description: string;
}

// ---- Skills ----
// Fields align with the agentskills.io open specification.
// description covers both "what the skill does" and "when to use it".
export interface SkillItem {
  name: string; // unique key = directory name
  description?: string; // required per spec; covers what + when to use
  license?: string; // optional: SPDX identifier or free text
  compatibility?: string; // optional: environment requirements
  mcps?: string[]; // MCP server names this skill unlocks on load
  files: string[]; // files in the skill directory
  // 调用统计（skill_usage 账本）。从未被调用过的 skill：calls=0、last_used 缺省。
  calls: number;
  tasks: number; // 加载过它的任务数（chat 会话不计入）
  usage_agents: string[]; // 加载过它的 agent key
  last_used?: string;
}

// SkillCall 是一次 Skill() 调用（单个 skill 的最近调用列表）。
export interface SkillCall {
  ts: string;
  agent_key: string;
  task_id: number; // 0 = 非任务场景（对话会话）
  session_id: string;
  args_len: number;
}

// MissingSkill 是被点名但不存在的 skill —— "想用但没有"的缺口。
export interface MissingSkill {
  skill: string;
  calls: number;
  agents: string[];
  last_used?: string;
}

// ---- Tools (内置工具目录) ----
// key + handler live in Go; only these fields are page-editable. system tools lock
// the key and the parameter *structure* (name/type/required) — the per-param
// description/default and the agent binding are what move.
export interface Tool {
  key: string;
  system: boolean;
  description: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  schema: Record<string, any>; // full JSON-Schema (object with properties)
  agents: string[]; // bound agent keys
  enabled: boolean;
  kind?: "builtin" | "shell" | "command" | "script" | "http"; // 自定义工具类型
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  exec?: Record<string, any>; // 自定义工具执行规格(kind!=builtin)
  deferred?: boolean; // schema 延迟(SearchExtraTools/ExecuteExtraTool)
  calls?: number; // persistent runtime invocation count (older APIs may omit it)
}

// ---- 功能调用历史（漏洞库 / nuclei 模板 / 指纹规则库）----
export type FeatureCallFeature = "vulnkb" | "nuclei" | "fingerprint";
export type FeatureCallSource = "web" | "agent" | "schedule" | "system";
export type FeatureCallStatus = "ok" | "error" | "denied";

export interface FeatureCall {
  id: number;
  ts: string;
  feature: FeatureCallFeature;
  action: string;
  source: FeatureCallSource;
  status: FeatureCallStatus;
  actor?: string;
  task_id?: number;
  exploration_id?: number;
  intent_id?: number;
  session_id?: string;
  project_id?: number;
  ref_type?: string;
  ref_id?: string;
  query?: string;
  summary: string;
  request?: unknown;
  result?: unknown;
  error?: string;
  duration_ms: number;
}

export interface FeatureCallStats {
  total: number;
  ok: number;
  error: number;
  denied: number;
  avg_duration_ms: number;
  last_at?: string;
}

// ---- Stats ----
export interface Stats {
  assets: number;
  engine_mode: EngineMode;
  llm_configured: boolean;
  roe_enabled: boolean;
  findings_confirmed: number;
  active_task?: Partial<Task>;
}

// ---- Intercept Rules ----
export type InterceptAction = "allow" | "deny" | "ask";
export type InterceptMatchTarget = "tool_name" | "tool_input";
export type InterceptMatchType = "string" | "regex";

export interface InterceptRule {
  id: number;
  name: string;
  enabled: boolean;
  priority: number;
  match_target: InterceptMatchTarget;
  match_type: InterceptMatchType;
  pattern: string;
  action: InterceptAction;
  message: string;
  timeout_enabled: boolean;
  timeout_seconds: number;
  timeout_action: "deny" | "allow";
  created_at: string;
  updated_at: string;
}

// ---- Asset Intercept Rules（资产拦截：全局黑名单） ----
export type AssetInterceptKind =
  | "exact_domain"
  | "exact_ip"
  | "exact_url"
  | "fuzzy_domain"
  | "fuzzy_ip"
  | "fuzzy_url"
  | "cidr";

// action 仅用于任务级规则：block=拦截(禁止测试) allow=允许(白名单)。
export type AssetInterceptAction = "block" | "allow";

// 任务级资产拦截/允许规则的录入项（创建任务、任务详情编辑使用）。
export interface AssetInterceptRuleInput {
  action: AssetInterceptAction;
  kind: AssetInterceptKind;
  pattern: string;
  note: string;
  enabled: boolean;
}

export interface AssetInterceptRule {
  id: number;
  enabled: boolean;
  action?: AssetInterceptAction; // 全局规则不带此字段（恒为拦截）；任务级规则区分 block/allow
  kind: AssetInterceptKind;
  pattern: string;
  note: string;
  builtin: boolean;
  created_at: string;
  updated_at: string;
}

export interface InterceptPending {
  decision_source?: "rule" | "model" | "unknown" | "";
  id: number;
  rule_id?: number;
  conversation_id?: number;
  task_id?: string;
  agent_name: string;
  tool_name: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  tool_input: Record<string, any>;
  status: "pending" | "allowed" | "denied" | "timeout";
  reason: string; // 规则 message 或模型判定理由(模型判定带 [模型] 前缀)
  // 资产围栏审批的结构化目标(未授权子集,决定时按勾选子集授权);规则/模型审批为空。
  targets?: { domains?: string[]; ips?: string[] } | null;
  // 服务端按工具输入静态提取的展示目标(不落库,围栏审批为空):审批列表第一眼
  // 看到「命令打谁」,不用读整条原始命令。仅展示,不参与授权判定。
  tool_targets?: { domains?: string[]; ips?: string[] } | null;
  decided_at?: string;
  created_at: string;
}

// JudgeConfig: 模型兜底审批(仅当没有任何拦截规则命中时由模型判断)的全局配置。
export interface JudgeConfig {
  enabled: boolean;
  profile_id: number; // 0 = 跟随激活/默认配置
  prompt: string; // 判定提示词;GET 未设置时后端回填内置模板全文
  timeout_seconds: number; // 模型调用超时
  fail_action: "allow" | "ask" | "deny"; // 模型出错/超时/不可解析时的回退
  ask_timeout_seconds: number; // 模型判 ask 转人工后的审批等待超时
  ask_timeout_action: "allow" | "deny"; // 审批超时后的默认动作
}

// JudgeUsage: 模型兜底审批(judge 通道)的累计 token 用量 + 近 N 天每日序列。
export interface JudgeDayUsage {
  date: string; // YYYY-MM-DD (UTC)
  calls: number;
  input_tokens: number;
  output_tokens: number;
}
export interface JudgeUsage {
  calls: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  daily: JudgeDayUsage[];
}

export interface InterceptApprovalFilter {
  status?: InterceptPending["status"];
  decision_source?: "rule" | "model" | "unknown";
}

// InterceptApprovalRow enriches InterceptPending with conversation/task and rule context.
export interface InterceptApprovalRow extends InterceptPending {
  conv_title: string; // "" if no linked conversation
  conv_agent_key: string; // "" if no linked conversation
  rule_name: string; // "" if rule was deleted
}

// ConvTokenSummary — one conversation's token total (+ profile/date) for merging
// chat usage into the dashboard token stats. GET /api/tokens/conversations.
export interface ConvTokenSummary {
  llm_profile_id: number | null;
  created_at: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

// ---- Command recording (Bash execution history) ----
export interface CommandRecord {
  id: number;
  exploration_id: number;
  worker: string;
  tool: string;
  command: string; // raw tool input (JSON)
  output: string;
  is_error: boolean;
  created_at: string;
}

// 单个工具的调用统计（/commands/stats）；errors 为其中失败的次数。
export interface ToolStat {
  tool: string;
  total: number;
  errors: number;
}

// ---- LLM recording ----
export interface LLMRecordItem {
  id: number;
  ts: string;
  model: string;
  profile_name: string;
  session_id: string;
  task_id: string;
  worker: string;
  latency_ms: number;
  input_tokens: number;
  output_tokens: number;
  cache_read: number;
  cache_write: number;
  status: string;
  error?: string;
}

export interface LLMRecordDetail extends LLMRecordItem {
  request_body: string;
  response_body: string;
  // provider 实际收发的 HTTP 原文：请求为 buildBody() 发出的完整 body（含工具
  // schema），响应为原始 SSE 帧。上面的 request_body/response_body 是归一化视图，
  // 丢弃了工具 schema 与 tool_use 块。旧记录为空。
  raw_request?: string;
  raw_response?: string;
}

// One distinct task with its LLM-record count (task picker on the records page).
export interface LLMTask {
  task_id: string;
  count: number;
}

// The exact JSON sent to the review model, retained for all model verdicts.
export interface InterceptReviewInput {
  version: number;
  background?: {
    // worker_summary is retained only for immutable v2/v3 snapshots.
    source: "user_message" | "worker_summary";
    text: string;
    truncated?: boolean;
  };
  // Version 1 snapshots are immutable and remain readable in historical audits.
  task?: {
    task_id: number;
    description: string;
    goal: string;
    constraints: { id: number; kind: string; text: string; origin: string; created_at: number }[];
    truncated?: boolean;
  };
  working_directory?: string;
  worker_intent?: string;
  turn_input?: string;
  background_truncated?: boolean;
  // Legacy v1/v2 snapshots only; v3 never sends execution history.
  history?: {
    tool_use_id: string;
    tool: string;
    arguments_preview: string;
    result: string;
    status: "succeeded" | "failed";
    truncated?: boolean;
  }[];
  history_truncated?: boolean;
  correlation?: "exact" | "ambiguous" | "unavailable";
  tool_name: string;
  arguments: Record<string, unknown>;
}

// Immutable review snapshot plus separately recorded execution outcome.
export interface InterceptAudit {
  model_input?: InterceptReviewInput;
  model_input_digest?: string;
  run_id?: string;
  tool_use_id?: string;
  correlation: "exact" | "ambiguous" | "unavailable";
  input_digest: string;
  user_message: string;
  user_truncated?: boolean;
  context:
    | { kind: string; tool?: string; tool_use_id?: string; text: string; is_error?: boolean; truncated?: boolean }[]
    | null;
  context_truncated?: boolean;
  captured_at: string;
  model_fallback?: boolean;
  initial_action: "allow" | "ask" | "deny";
  initial_reason: string;
  effective_action?: "allow" | "deny";
  decision_reason?: string;
  rule_name?: string;
  config_digest?: string;
  profile_id?: number;
  execution_status: "not_started" | "not_executed" | "awaiting_result" | "succeeded" | "failed" | "unknown";
  output?: string;
  output_truncated?: boolean;
  execution_ended_at?: string;
}
export interface InterceptDetail extends InterceptApprovalRow {
  audit: InterceptAudit | null;
}

export type TrafficEvidenceRole = "baseline" | "proof" | "verification" | "supporting";
export interface TrafficEvidenceRef {
  traffic_id: string;
  role?: TrafficEvidenceRole;
  note?: string;
}
export interface TrafficEvidenceSnapshot {
  id: string;
  source_traffic_id: string;
  captured_at: number;
  url: string;
  method: string;
  status: number;
  content_type: string;
  req_head?: string;
  resp_head?: string;
  req_hash: string;
  resp_hash: string;
  req_len: number;
  resp_len: number;
}
export interface FindingTrafficBinding {
  id: string;
  finding_id: string;
  snapshot_id: string;
  role: TrafficEvidenceRole;
  note: string;
  position: number;
  created_at: string;
  snapshot: TrafficEvidenceSnapshot;
}
export interface FindingTraffic {
  finding_id: string;
  version: number;
  report_version: number;
  bindings: FindingTrafficBinding[];
}
export interface EvidenceBodyPreview {
  content: string;
  offset: number;
  total: number;
  next_offset: number;
  truncated: boolean;
  binary: boolean;
}
export interface FindingTrafficDetail {
  binding: FindingTrafficBinding;
  request: EvidenceBodyPreview;
  response: EvidenceBodyPreview;
}

/** GET /api/update/check —— 当前版本与 GitHub 最新正式版的比较结果。 */
export interface UpdateCheck {
  /** 当前运行的版本；开发构建为 "dev" 或 git describe 的带后缀形式。 */
  current: string;
  /** 运行形态。docker 下换装只作用于容器可写层，重建容器会退回镜像版本。 */
  mode: "docker" | "binary";
  os: string;
  arch: string;
  repo: string;
  /** 是否存在可回滚的上一版本（4zrec.old）。 */
  has_backup: boolean;
  /** 本次启动时自更新自举的结论（换装失败 / 已回滚等），无事发生时为空。 */
  boot_notice?: string;
  rolled_back?: boolean;
  /** 查询 GitHub 失败时给出原因，此时下面的字段都不会有。 */
  error?: string;
  latest?: string;
  notes?: string;
  html_url?: string;
  published_at?: string;
  /** 当前平台对应的发布包名，以及该 Release 是否真的带了它。 */
  asset?: string;
  asset_available?: boolean;
  size?: number;
  has_update?: boolean;
  /** 双方版本号是否可比较；开发构建为 false，此时禁用一键更新。 */
  comparable?: boolean;
  /** comparable 为 false 时的说明。 */
  reason?: string;
}

/** /api/update/stream 推送的一条更新进度。 */
export interface UpdateProgress {
  phase: "idle" | "downloading" | "verifying" | "extracting" | "staged" | "failed";
  /** 仅下载阶段有意义（0-100）；其余阶段为 -1。 */
  percent: number;
  message: string;
  version?: string;
  error?: string;
}

// Original execution selected from an approval, never submitted to the reviewer.
export interface InterceptExecution {
  conversation_id: number | null;
  task_id: string | null;
  session: string;
  seq: number;
  items: Activity[];
}

/** 漏洞知识库(1day 库)的一条记录。列表接口不带 body。 */
export interface VulnKBEntry {
  id: number;
  title: string;
  product: string;
  vuln_type: string;
  cve: string;
  fingerprint: string;
  request_line: string;
  headers: string;
  payload: string;
  response_sig: string;
  expected: string;
  body?: string;
  source_path: string;
}

/** 漏洞库概览统计。 */
export interface VulnKBStats {
  total: number;
  products: number;
  with_cve: number;
  with_payload: number;
  with_fingerprint: number;
  types: { name: string; count: number }[];
}

/** 统一漏洞库列表条目(1day 库 + 自动抓取情报流)。 */
export interface VulnLibraryEntry {
  source: "1day" | "intel";
  id: number;
  title: string;
  product?: string;
  vuln_type?: string;
  severity?: string;
  cve?: string;
  fingerprint?: string;
  disclosure?: string;
  source_name?: string;
  created_at: string;
}

/** 自动抓取的漏洞情报一条记录(含富化字段)。 */
export interface VulnIntelEntry {
  id: number;
  title: string;
  description?: string;
  severity: string;
  cve: string;
  disclosure: string;
  solutions?: string;
  source: string;
  source_url: string;
  tags: string;
  refs: string;
  created_at: string;
  updated_at: string;
  /** 富化字段(GitHub PoC / GHSA+NVD 元数据 / triage 结论)。 */
  github_poc: string;
  cvss_score: number | null;
  cvss_vector: string;
  cwes: string;
  affected: string;
  lab_only: boolean;
  enriched_at: string | null;
  /** AI 分析流水线状态位;详情接口额外带 analysis(长文本)。 */
  title_zh?: string;
  analyzed_at: string | null;
  localized_at: string | null;
  nuclei_tpl_id?: string;
  /** 已入库的指纹规则 id(空 = 只有草稿或未生成)。 */
  fingerprint_id?: string;
  fingerprint_at?: string | null;
  nuclei_tpl_at: string | null;
  analysis_error?: string;
  analysis?: IntelAnalysis | null;
}

/** AI 分析产物(中文简介 / 漏洞原理 / 攻击范围 / PoC / 生成的 nuclei 模板)。 */
export interface IntelAnalysis {
  vuln_intel_id: number;
  principle: string;
  attack_scope: string;
  description_zh: string;
  poc_code: string;
  poc_lang: string;
  /** ai(模型生成) / upstream(源里已有) / none */
  poc_origin: string;
  /** 未生成/不能直接用 PoC 的原因(要素不全、参数为推测等)。 */
  poc_note?: string;
  nuclei_template: string;
  /** 指纹规则草稿(JSON 文本)。 */
  fingerprint?: string;
  fingerprint_id?: string;
  model: string;
  updated_at: string;
}

/** 情报分析流水线的开关与进度。 */
export interface VulnPipelineStatus {
  analyze_enabled: boolean;
  auto_translate: boolean;
  auto_nuclei: boolean;
  auto_fingerprint: boolean;
  notify_enabled: boolean;
  llm_ready: boolean;
  running: boolean;
  last_run: string;
  last_done: number;
  last_failed: number;
  pending: number;
  analyzed: number;
  /** 待人工确认的模板草稿数。 */
  drafts: number;
}

/** 一条待人工确认的流水线产物草稿(模板与指纹各自独立确认)。 */
export interface IntelDraft {
  vuln_intel_id: number;
  title: string;
  title_zh?: string;
  severity?: string;
  cve?: string;
  source?: string;
  /** nuclei 模板草稿 YAML(空 = 没生成)。 */
  nuclei_yaml: string;
  nuclei_tpl_id: string;
  /** 模板 matcher 是否可用;不可用时 nuclei_issue 说明原因。 */
  nuclei_usable: boolean;
  nuclei_issue?: string;
  /** 指纹规则草稿(JSON 文本)。 */
  fingerprint: string;
  fingerprint_id: string;
  fingerprint_name?: string;
  fingerprint_category?: string;
  fingerprint_expression?: string;
  fingerprint_usable: boolean;
  fingerprint_issue?: string;
  updated_at: string;
}

/** github_poc 数组里的一项。 */
export interface VulnIntelPOC {
  full_name: string;
  url: string;
  description?: string;
  stars: number;
  pushed_at?: string;
  verdict?: string;
  triage_score?: number;
  triage_reasons?: string[];
}

/** 情报轮询状态。 */
export interface VulnIntelStatus {
  polling: boolean;
  last: string;
  result: { New: number; Updated: number; Sources: number; Failed: number };
  sources: number;
}

// ---- AI 报告生成(docx 管线)----
export interface ReportJob {
  status: "idle" | "generating" | "done" | "failed";
  filename?: string;
  error?: string;
  started_at?: string;
}

export interface ReportPersonnel {
  name: string;
  role: string;
  contact: string;
}

export interface ReportSettings {
  company_name: string;
  company_name_en: string;
  logo_path: string;
  personnel: ReportPersonnel[];
  cvss_version: string;
  updated_at?: string;
}

export interface ReportRecord {
  id: number;
  task_id?: number;
  task_desc: string;
  filename: string;
  size: number;
  company: string;
  created_at: string;
}

export interface ReportTemplate {
  id: number;
  name: string;
  company_name: string;
  company_name_en: string;
  logo_path: string;
  personnel: ReportPersonnel[];
  cvss_version: string;
  locale: string;
  created_at?: string;
  updated_at?: string;
}

// ---- capkit 会话（桥接的 foothold：webshell/ssh/winrm/smb/cli）----
// 后端 /api/capkit/sessions/*；项目级 Key 只能看到本项目打开的会话。
export interface CapkitSession {
  id: string;
  kind: string;
  host?: string;
  port?: number;
  user?: string;
  os?: string;
  arch?: string;
  elevated?: boolean;
  labels?: string[];
  meta?: Record<string, string>;
  project_id?: number;
}

// 会话类型目录：后端按“实际注册了哪些传输”给出可用性，前端据此决定表单字段。
export interface CapkitKind {
  id: string;
  label: string;
  category: string;
  available: boolean;
  hint?: string;
  /** 该类型需要哪些输入：url/host/port/user/secret/domain/share/shell_type/cmd_param/method/password */
  fields: string[];
}

export interface CapkitSessionList {
  sessions: CapkitSession[];
  enabled: boolean;
  kinds?: CapkitKind[];
}

export interface CapkitExecResult {
  session_id: string;
  command: string;
  stdout: string;
  stderr: string;
  exit_code: number;
  duration_ms: number;
  truncated?: boolean;
  summary?: string;
  evidence?: { id?: string; kind?: string; size?: number; sha256?: string; preview?: string }[];
}
