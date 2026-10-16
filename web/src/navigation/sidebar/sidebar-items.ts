import {
  Activity,
  Ban,
  BellRing,
  BookOpenText,
  Bot,
  Brain,
  Bug,
  Building2,
  CalendarClock,
  ClipboardList,
  Compass,
  FileText,
  Fingerprint,
  FolderOpen,
  LayoutDashboard,
  type LucideIcon,
  Briefcase,
  MessageSquare,
  Network,
  Plug,
  Radar,
  Radio,
  ScrollText,
  Settings2,
  ShieldAlert,
  Sparkles,
  Target,
  Terminal,
  Wrench,
  Zap,
} from "lucide-react";

export type NavBadge = "new" | "soon";

export interface NavSubItem {
  id: string;
  title: string;
  url: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

interface NavItemBase {
  id: string;
  title: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

export interface NavMainLinkItem extends NavItemBase {
  url: string;
  subItems?: never;
}

export interface NavMainParentItem extends NavItemBase {
  subItems: NavSubItem[];
}

export type NavMainItem = NavMainLinkItem | NavMainParentItem;

export interface NavGroup {
  id: number;
  label?: string;
  items: NavMainItem[];
}

// 侧边栏分组:高频入口保持一级,同域低频页收进可折叠二级(子项命中自动展开
// 高亮,侧栏收起时父项变下拉)。信息收集归"功能"——空间测绘/周期采集/企业
// 数据源是收集的配置面,资产/漏洞库是收集的产出面,同属一条作业线。
export const sidebarItems: NavGroup[] = [
  {
    id: 1,
    label: "功能",
    items: [
      { id: "dashboard", title: "仪表盘", url: "/dashboard", icon: LayoutDashboard },
      { id: "chat", title: "对话", url: "/chat", icon: MessageSquare },
      { id: "tasks", title: "任务", url: "/function/tasks", icon: Target },
      { id: "findings", title: "发现", url: "/function/findings", icon: Bug },
      { id: "projects", title: "项目", url: "/function/projects", icon: Briefcase },
      {
        id: "info-collect",
        title: "信息收集",
        icon: Compass,
        subItems: [
          { id: "assets", title: "资产", url: "/function/assets", icon: Network },
          { id: "vuln-kb", title: "漏洞库", url: "/function/vuln-kb", icon: BookOpenText },
          { id: "spacemap", title: "空间测绘", url: "/function/spacemap", icon: Radar },
          { id: "recon-schedules", title: "周期采集", url: "/system/recon-schedules", icon: CalendarClock },
          { id: "enterprise", title: "企业采集", url: "/function/enterprise", icon: Building2 },
        ],
      },
      {
        id: "exec",
        title: "流量与执行",
        icon: Zap,
        subItems: [
          { id: "traffic", title: "流量", url: "/function/traffic", icon: Activity },
          { id: "commands", title: "工具执行", url: "/function/commands", icon: Terminal },
          { id: "llm-records", title: "LLM 录制", url: "/function/llm-records", icon: Radio },
        ],
      },
      { id: "workspace", title: "工作空间", url: "/function/workspace", icon: FolderOpen },
    ],
  },
  {
    id: 2,
    label: "系统",
    items: [
      {
        id: "platform",
        title: "平台配置",
        icon: Wrench,
        subItems: [
          { id: "llm", title: "LLM", url: "/system/llm", icon: Brain },
          { id: "agents", title: "Agent", url: "/system/agents", icon: Bot },
          { id: "mcp", title: "MCP", url: "/system/mcp", icon: Plug },
          { id: "skills", title: "Skill", url: "/system/skills", icon: Sparkles },
          { id: "tools", title: "工具", url: "/system/tools", icon: Wrench },
        ],
      },
      {
        id: "security",
        title: "安全与审批",
        icon: ShieldAlert,
        subItems: [
          { id: "intercept", title: "拦截规则", url: "/system/intercept", icon: ShieldAlert },
          { id: "asset-intercept", title: "资产拦截", url: "/system/intercept/assets", icon: Ban },
          { id: "approvals", title: "审批记录", url: "/system/intercept/approvals", icon: ClipboardList },
        ],
      },
      { id: "notify", title: "通知推送", url: "/system/notify", icon: BellRing },
      { id: "reports", title: "报告管理", url: "/system/reports", icon: FileText },
      {
        id: "ops",
        title: "系统管理",
        icon: Settings2,
        subItems: [
          { id: "spacemap-config", title: "空间测绘配置", url: "/system/spacemap", icon: Radar },
          { id: "fingerprint", title: "指纹规则库", url: "/system/fingerprint", icon: Fingerprint },
          { id: "enterprise-config", title: "企业数据源", url: "/system/enterprise", icon: Building2 },
          { id: "logs", title: "日志", url: "/system/logs", icon: ScrollText },
          { id: "settings", title: "系统配置", url: "/system/settings", icon: Settings2 },
        ],
      },
    ],
  },
];
