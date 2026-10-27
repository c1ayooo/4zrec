"use client";

import * as React from "react";

import { Loader2Icon, RefreshCwIcon, RocketIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { AssetSyncSourceProject, ZrearkDispatchResult, ZrearkTask } from "@/lib/types";

import { ZrearkConnectionBar } from "./zreark-connection-bar";

// 允许下发的任务类型（与后端白名单一致，均为资产收集类）。
const TASK_TYPES: { value: string; label: string }[] = [
  { value: "asset_discovery", label: "资产发现" },
  { value: "full", label: "综合采集" },
  { value: "subdomain", label: "子域名枚举" },
  { value: "port_scan", label: "端口扫描" },
  { value: "fingerprint", label: "指纹识别" },
  { value: "crawler", label: "Web 爬虫" },
  { value: "dir_scan", label: "目录扫描" },
];

const TARGET_TYPES: { value: string; label: string }[] = [
  { value: "domain", label: "域名" },
  { value: "ip", label: "IP" },
  { value: "url", label: "URL" },
  { value: "cidr", label: "CIDR" },
];

const STATUS_STYLES: Record<string, string> = {
  pending: "text-muted-foreground",
  running: "text-info",
  paused: "text-warning",
  completed: "text-success",
  failed: "text-destructive",
  cancelled: "text-muted-foreground",
};

const STATUS_LABELS: Record<string, string> = {
  pending: "待启动",
  running: "运行中",
  paused: "已暂停",
  completed: "已完成",
  failed: "失败",
  cancelled: "已取消",
};

// 下发采集任务弹窗：把资产收集任务派给 4zreark 执行（create_task + start_task），
// 并可查看远端任务状态；结果用「资产同步」拉回 4zrec。
export function ZrearkDispatchDialog() {
  const [open, setOpen] = React.useState(false);
  const [configured, setConfigured] = React.useState(false);
  const [sourceProjects, setSourceProjects] = React.useState<AssetSyncSourceProject[]>([]);
  const [name, setName] = React.useState("资产采集");
  const [type, setType] = React.useState("asset_discovery");
  const [targetType, setTargetType] = React.useState("domain");
  const [targetsText, setTargetsText] = React.useState("");
  const [sourceProjectID, setSourceProjectID] = React.useState("");
  const [busy, setBusy] = React.useState<"projects" | "dispatch" | "tasks" | null>(null);
  const [syncingTask, setSyncingTask] = React.useState<string | null>(null);
  const [dispatched, setDispatched] = React.useState<ZrearkDispatchResult | null>(null);
  const [tasks, setTasks] = React.useState<ZrearkTask[]>([]);
  const [error, setError] = React.useState("");

  const working = busy !== null;
  const targets = targetsText
    .split(/\n|,/)
    .map((t) => t.trim())
    .filter(Boolean);
  const canDispatch = configured && name.trim() !== "" && sourceProjectID !== "" && targets.length > 0 && !working;

  function resetForm() {
    setDispatched(null);
    setTasks([]);
    setError("");
  }

  async function loadProjects() {
    if (!configured || working) return;
    setBusy("projects");
    setError("");
    try {
      const res = await api.assetSyncProjects({});
      const items = res.projects ?? [];
      setSourceProjects(items);
      if (items.length === 1) setSourceProjectID(String(items[0].id));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  async function loadTasks() {
    if (!configured || working) return;
    setBusy("tasks");
    setError("");
    try {
      const res = await api.zrearkTasks({
        source_project_id: Number(sourceProjectID) || undefined,
      });
      setTasks(res.tasks ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  async function syncTaskResults(taskID: string) {
    if (!configured || syncingTask) return;
    setSyncingTask(taskID);
    setError("");
    try {
      const res = await api.zrearkTaskResults({ task_id: taskID });
      toast.success(`任务 ${taskID.slice(0, 8)}…：指纹 ${res.services} 条、路由 ${res.endpoints} 条落库`);
      if (res.errors.length > 0) {
        toast.warning(`部分条目跳过（${res.skipped}），首个错误：${res.errors[0]}`);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSyncingTask(null);
    }
  }

  async function dispatch() {
    if (!canDispatch) return;
    setBusy("dispatch");
    setError("");
    setDispatched(null);
    try {
      const res = await api.zrearkDispatch({
        source_project_id: Number(sourceProjectID),
        name: name.trim(),
        type,
        targets,
        target_type: targetType as "domain" | "ip" | "url" | "cidr",
      });
      setDispatched(res);
      if (res.started) toast.success(`任务已下发并启动（${res.task_id}）`);
      else if (res.start_error) toast.warning("任务已创建，但启动失败");
      else toast.success(`任务已创建（${res.task_id}），可在 4zreark 中启动`);
      void loadTasks();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) resetForm();
      }}
    >
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          <RocketIcon className="size-4" /> 下发采集任务
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>向 4zreark 下发采集任务</DialogTitle>
          <DialogDescription>
            通过 4zreark 的 MCP
            接口创建并启动资产收集任务；目标必须在源项目的站点/种子范围内。跑完后用「资产同步」拉回结果。
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4">
          <ZrearkConnectionBar
            onChanged={(cfg) => {
              setConfigured(cfg.configured);
              if (!cfg.configured) {
                setSourceProjects([]);
                setSourceProjectID("");
                setTasks([]);
              }
            }}
          />

          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => void loadProjects()} disabled={!configured || working}>
              {busy === "projects" ? (
                <Loader2Icon className="size-4 animate-spin" />
              ) : (
                <RefreshCwIcon className="size-4" />
              )}
              读取项目
            </Button>
            <span className="text-muted-foreground text-xs">
              在 4zreark「系统设置 → MCP 接入」创建带 tasks:write 的 Key，填到上方连接配置。
            </span>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="zreark-task-name">任务名</Label>
              <Input id="zreark-task-name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label>源项目</Label>
              <Select
                value={sourceProjectID}
                onValueChange={(value) => {
                  setSourceProjectID(value);
                  setTasks([]);
                }}
              >
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="先读取项目" />
                </SelectTrigger>
                <SelectContent>
                  {sourceProjects.map((project) => (
                    <SelectItem key={project.id} value={String(project.id)}>
                      {project.name}
                      {typeof project.asset_count === "number" ? ` · ${project.asset_count} 资产` : ""}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label>任务类型</Label>
              <Select value={type} onValueChange={setType}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {TASK_TYPES.map((t) => (
                    <SelectItem key={t.value} value={t.value}>
                      {t.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label>目标类型</Label>
              <Select value={targetType} onValueChange={setTargetType}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {TARGET_TYPES.map((t) => (
                    <SelectItem key={t.value} value={t.value}>
                      {t.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="zreark-task-targets">目标（每行一个，自动去重）</Label>
            <Textarea
              id="zreark-task-targets"
              rows={4}
              className="font-mono text-xs"
              placeholder={"example.com\napi.example.com"}
              value={targetsText}
              onChange={(e) => setTargetsText(e.target.value)}
            />
            {targets.length > 0 ? <p className="text-muted-foreground text-xs">共 {targets.length} 个目标</p> : null}
          </div>

          {dispatched ? (
            <div className="bg-muted/20 rounded-lg border p-3 text-sm">
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
                <span className="font-medium">任务 {dispatched.task_id}</span>
                <Badge variant="outline">{dispatched.started ? "已启动" : "待启动"}</Badge>
                <span className="text-muted-foreground tabular-nums">{dispatched.targets} 个目标</span>
              </div>
              {dispatched.start_error ? (
                <p className="text-warning mt-1 text-xs">启动失败：{dispatched.start_error}</p>
              ) : null}
            </div>
          ) : null}

          {tasks.length > 0 ? (
            <div className="rounded-lg border">
              <div className="text-muted-foreground flex items-center justify-between border-b px-3 py-2 text-xs">
                <span>4zreark 最近任务</span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 px-2"
                  onClick={() => void loadTasks()}
                  disabled={working}
                >
                  {busy === "tasks" ? (
                    <Loader2Icon className="size-3 animate-spin" />
                  ) : (
                    <RefreshCwIcon className="size-3" />
                  )}
                  刷新
                </Button>
              </div>
              <div className="max-h-44 overflow-y-auto">
                {tasks.map((t) => (
                  <div key={t.id} className="flex items-center gap-2 border-b px-3 py-1.5 text-xs last:border-b-0">
                    <span className="w-40 truncate font-medium">{t.name}</span>
                    <Badge variant="outline" className="shrink-0">
                      {TASK_TYPES.find((x) => x.value === t.type)?.label ?? t.type}
                    </Badge>
                    <span className={`shrink-0 ${STATUS_STYLES[t.status] ?? ""}`}>
                      {STATUS_LABELS[t.status] ?? t.status}
                      {t.status === "running" ? ` ${t.progress}%` : ""}
                    </span>
                    <span className="text-muted-foreground ml-auto shrink-0 tabular-nums">
                      {t.discovered_assets > 0 ? `发现 ${t.discovered_assets} 资产` : ""}
                    </span>
                    {t.status === "failed" && t.last_error ? (
                      <span className="w-40 truncate text-destructive" title={t.last_error}>
                        {t.last_error}
                      </span>
                    ) : null}
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 shrink-0 px-2"
                      disabled={syncingTask !== null}
                      onClick={() => void syncTaskResults(t.id)}
                    >
                      {syncingTask === t.id ? <Loader2Icon className="size-3 animate-spin" /> : null}
                      同步结果
                    </Button>
                  </div>
                ))}
              </div>
              {tasks.some((t) => t.status === "completed") ? (
                <p className="text-muted-foreground border-t px-3 py-2 text-xs">
                  已完成的任务可用「资产同步」把新增站点拉回 4zrec。
                </p>
              ) : null}
            </div>
          ) : null}

          {error ? <p className="text-destructive text-sm">{error}</p> : null}
        </div>

        <DialogFooter>
          <Button onClick={() => void dispatch()} disabled={!canDispatch}>
            {busy === "dispatch" ? <Loader2Icon className="size-4 animate-spin" /> : null}
            下发任务
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
