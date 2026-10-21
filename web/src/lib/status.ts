// Centralised status → color/label semantics, reused across the whole app.
// Spec §8.3: 意图 / 覆盖 / 任务 / 严重度 each have a consistent color set.

export type Tone = "neutral" | "blue" | "green" | "amber" | "red" | "rose" | "sky" | "slate";

// Pale tint + same-hue ink, per the app-screen rules. Ink tones are one step
// darker than the usual 500/600 so every label clears 4.5:1 on white.
export const toneClasses: Record<Tone, string> = {
  neutral: "bg-muted text-muted-foreground border-transparent",
  blue: "bg-blue-500/10 text-blue-700 dark:text-blue-300 border-blue-500/20",
  green: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/20",
  amber: "bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/25",
  red: "bg-red-500/10 text-red-700 dark:text-red-300 border-red-500/20",
  // 「严重」只比「高危」重一档：深红描边与更深的字，不再用实心红块。
  rose: "bg-red-700/10 text-red-800 dark:text-red-300 border-red-700/30 dark:border-red-400/30",
  sky: "bg-sky-500/10 text-sky-700 dark:text-sky-300 border-sky-500/20",
  slate: "bg-slate-500/10 text-slate-700 dark:text-slate-300 border-slate-500/20",
};

export const toneDot: Record<Tone, string> = {
  neutral: "bg-muted-foreground",
  blue: "bg-blue-600",
  green: "bg-emerald-600",
  amber: "bg-amber-600",
  red: "bg-red-600",
  rose: "bg-red-700",
  sky: "bg-sky-600",
  slate: "bg-slate-500",
};

interface StatusMeta {
  label: string;
  tone: Tone;
}

const intent: Record<string, StatusMeta> = {
  open: { label: "待领", tone: "slate" },
  running: { label: "执行中", tone: "blue" },
  paused: { label: "已暂停", tone: "amber" },
  done: { label: "已完成", tone: "green" },
  // blocked = 模型/API/网络故障重试用尽，这条意图基本没真正探成（非目标拦截）。
  blocked: { label: "执行出错", tone: "red" },
  // exhausted = 达到步数/时间预算被中途掐断、只写回部分结果（非方向已探尽）。
  exhausted: { label: "预算耗尽", tone: "sky" },
  // stopped = 历史软删除状态（保留,历史数据）。
  stopped: { label: "已停止", tone: "slate" },
  // deleted = 用户假删除了该意图（保留节点与血缘，删除原因见 delete_reason 字段）。
  deleted: { label: "已删除", tone: "slate" },
};

const task: Record<string, StatusMeta> = {
  created: { label: "已创建", tone: "slate" },
  queued: { label: "排队中", tone: "amber" },
  running: { label: "运行中", tone: "blue" },
  paused: { label: "已暂停", tone: "amber" },
  done: { label: "已完成", tone: "green" },
  failed: { label: "失败", tone: "red" },
  timeout: { label: "已超时", tone: "amber" },
};

const severity: Record<string, StatusMeta> = {
  critical: { label: "严重", tone: "rose" },
  high: { label: "高危", tone: "red" },
  medium: { label: "中危", tone: "amber" },
  low: { label: "低危", tone: "slate" },
};

const finding: Record<string, StatusMeta> = {
  pending: { label: "待处理", tone: "amber" },
  in_progress: { label: "处理中", tone: "blue" },
  confirmed: { label: "已确认", tone: "red" },
  resolved: { label: "已处理", tone: "green" },
  fixed: { label: "已修复", tone: "green" },
  false_positive: { label: "误报", tone: "slate" },
  ignored: { label: "忽略", tone: "neutral" },
  duplicate: { label: "重复", tone: "neutral" },
  risk_accepted: { label: "风险接受", tone: "sky" },
};

const engine: Record<string, StatusMeta> = {
  exploring: { label: "探索中", tone: "blue" },
  paused: { label: "已暂停", tone: "amber" },
  stalled: { label: "停滞", tone: "red" },
  idle: { label: "空闲", tone: "neutral" },
};

const goal: Record<string, StatusMeta> = {
  open: { label: "进行中", tone: "blue" },
  met: { label: "已达成", tone: "green" },
  abandoned: { label: "已放弃", tone: "slate" },
};

const audit: Record<string, StatusMeta> = {
  allow: { label: "放行", tone: "green" },
  block: { label: "拦截", tone: "red" },
};

const node: Record<string, StatusMeta> = {
  observed: { label: "观测", tone: "slate" },
  confirmed: { label: "确认", tone: "green" },
  tombstoned: { label: "废弃", tone: "neutral" },
};

// 推送投递状态。sending 用 blue 而不是 amber：它不是「有问题」，
// 而是「已被领取、正在发」，与 pending 的等待语义要能区分开。
const delivery: Record<string, StatusMeta> = {
  pending: { label: "待发送", tone: "amber" },
  sending: { label: "发送中", tone: "blue" },
  sent: { label: "已送达", tone: "green" },
  failed: { label: "失败", tone: "red" },
  skipped: { label: "已跳过", tone: "neutral" },
};

const maps = {
  intent,
  task,
  severity,
  finding,
  engine,
  goal,
  audit,
  node,
  delivery,
} as const;

export type StatusDomain = keyof typeof maps;

export function statusMeta(domain: StatusDomain, key: string): StatusMeta {
  return maps[domain][key] ?? { label: key, tone: "neutral" };
}
