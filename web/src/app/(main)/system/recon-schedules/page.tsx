"use client";

import * as React from "react";

import {
  CalendarClockIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  HistoryIcon,
  Loader2Icon,
  PlayIcon,
  PlusIcon,
  Trash2Icon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import type { ReconRun, ReconSchedule } from "@/lib/types";

// 周期采集任务管理:engine=五引擎按域采集,pipeline=主动测绘流水线(周期版默认
// 只跑被动+解析),zreark=定时从 4zreark 平台拉取站点资产。与 LLM/空间测绘设置页
// 同风格;鉴权失败自动退避,新资产走通知。
export default function ReconSchedulesPage() {
  const [list, setList] = React.useState<ReconSchedule[] | null>(null);
  const [busy, setBusy] = React.useState<string | null>(null);
  const [openRuns, setOpenRuns] = React.useState<number | null>(null);
  const [runs, setRuns] = React.useState<Record<number, ReconRun[]>>({});
  // 新建表单
  const [name, setName] = React.useState("");
  const [kind, setKind] = React.useState<"engine" | "pipeline" | "zreark">("engine");
  const [interval, setInterval] = React.useState("1800");
  const [domains, setDomains] = React.useState("");
  const [projectID, setProjectID] = React.useState("");
  // zreark 形态专属
  const [sourceProjectID, setSourceProjectID] = React.useState("");
  const [catalog, setCatalog] = React.useState<"all" | "verified">("all");
  const [syncLimit, setSyncLimit] = React.useState("1000");

  const load = React.useCallback(async () => {
    try {
      setList(await api.reconSchedules());
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const create = async () => {
    if (!name.trim()) {
      toast.error("名称必填");
      return;
    }
    let config: Record<string, unknown>;
    if (kind === "zreark") {
      const sourceID = Number(sourceProjectID) || 0;
      if (sourceID <= 0) {
        toast.error("4zreark 源项目 ID 必填（在 4zreark 资产页查看）");
        return;
      }
      config = {
        source_project_id: sourceID,
        target_project_id: Number(projectID) || 0,
        catalog,
        limit: Math.max(1, Number(syncLimit) || 1000),
      };
    } else {
      const doms = domains
        .split(/[\n,，]/)
        .map((d) => d.trim())
        .filter(Boolean);
      if (doms.length === 0) {
        toast.error("目标主域必填");
        return;
      }
      config = { domains: doms };
    }
    try {
      await api.createReconSchedule({
        name: name.trim(),
        kind,
        interval_sec: Math.max(60, Number(interval) || 1800),
        project_id: projectID ? Number(projectID) : undefined,
        config,
      });
      toast.success("任务已创建");
      setName("");
      setDomains("");
      setSourceProjectID("");
      await load();
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    }
  };

  const toggleRuns = async (id: number) => {
    if (openRuns === id) {
      setOpenRuns(null);
      return;
    }
    setOpenRuns(id);
    try {
      const rs = await api.reconRuns(id, 5);
      setRuns((prev) => ({ ...prev, [id]: rs }));
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    }
  };

  const act = async (key: string, fn: () => Promise<unknown>, okMsg?: string) => {
    setBusy(key);
    try {
      await fn();
      if (okMsg) toast.success(okMsg);
      await load();
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">周期采集</h1>
        <p className="text-muted-foreground mt-1 text-sm">
          定时跑五引擎按域采集、主动测绘流水线，或从 4zreark 平台同步站点资产（默认 30 分钟一轮，最小 60
          秒）。只通知增量新资产；
          引擎/平台鉴权失败自动退避降频，成功一次即恢复。周期流水线默认只跑被动面，主动探测需在配置里显式开启。
        </p>
      </div>

      <Card>
        <CardContent className="grid gap-4 md:grid-cols-5">
          <div className="space-y-2 md:col-span-1">
            <Label htmlFor="sched-name">名称</Label>
            <Input
              id="sched-name"
              placeholder="如:某集团资产增量"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label>形态</Label>
            <Select value={kind} onValueChange={(v) => setKind(v as "engine" | "pipeline" | "zreark")}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="engine">五引擎采集</SelectItem>
                <SelectItem value="pipeline">测绘流水线</SelectItem>
                <SelectItem value="zreark">4zreark 同步</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="sched-interval">周期(秒)</Label>
            <Input id="sched-interval" type="number" value={interval} onChange={(e) => setInterval(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="sched-project">项目 ID(可选)</Label>
            <Input
              id="sched-project"
              type="number"
              placeholder="认领/范围校验"
              value={projectID}
              onChange={(e) => setProjectID(e.target.value)}
            />
          </div>
          {kind === "zreark" ? (
            <>
              <div className="space-y-2">
                <Label htmlFor="sched-source-project">4zreark 源项目 ID</Label>
                <Input
                  id="sched-source-project"
                  type="number"
                  placeholder="4zreark 项目 ID"
                  value={sourceProjectID}
                  onChange={(e) => setSourceProjectID(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label>同步范围</Label>
                <Select value={catalog} onValueChange={(v) => setCatalog(v as "all" | "verified")}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">全部站点</SelectItem>
                    <SelectItem value="verified">仅已确认站点</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="sched-sync-limit">单轮最多同步条数</Label>
                <Input
                  id="sched-sync-limit"
                  type="number"
                  value={syncLimit}
                  onChange={(e) => setSyncLimit(e.target.value)}
                />
              </div>
            </>
          ) : (
            <div className="space-y-2 md:col-span-5">
              <Label htmlFor="sched-domains">目标主域(逗号或换行分隔)</Label>
              <textarea
                id="sched-domains"
                className="border-input bg-background min-h-16 w-full rounded-md border px-3 py-2 text-sm"
                placeholder={"example.com\nexample.cn"}
                value={domains}
                onChange={(e) => setDomains(e.target.value)}
              />
            </div>
          )}
          <div className="md:col-span-5">
            <Button size="sm" onClick={() => void create()}>
              <PlusIcon className="size-4" /> 创建任务
            </Button>
          </div>
        </CardContent>
      </Card>

      {list === null ? (
        <div className="text-muted-foreground flex items-center gap-2 text-sm">
          <Loader2Icon className="size-4 animate-spin" /> 加载中…
        </div>
      ) : list.length === 0 ? (
        <p className="text-muted-foreground text-sm">还没有周期采集任务。</p>
      ) : (
        <div className="grid gap-4">
          {list.map((sc) => (
            <Card key={sc.id}>
              <CardContent className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex w-full items-center gap-1">
                  {sc.kind === "pipeline" ? (
                    <button
                      type="button"
                      className="text-muted-foreground hover:text-foreground flex items-center gap-1 text-xs"
                      onClick={() => void toggleRuns(sc.id)}
                    >
                      {openRuns === sc.id ? (
                        <ChevronDownIcon className="size-3.5" />
                      ) : (
                        <ChevronRightIcon className="size-3.5" />
                      )}
                      <HistoryIcon className="size-3.5" />
                      运行历史
                    </button>
                  ) : null}
                </div>
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <CalendarClockIcon className="text-muted-foreground size-4" />
                    <span className="font-medium">{sc.name}</span>
                    <Badge variant="outline">
                      {sc.kind === "engine" ? "五引擎" : sc.kind === "pipeline" ? "流水线" : "4zreark 同步"}
                    </Badge>
                    <Badge variant="outline">每 {Math.round(sc.interval_sec / 60)} 分钟</Badge>
                    {sc.enabled ? <Badge>启用</Badge> : <Badge variant="outline">停用</Badge>}
                    {sc.backoff_until ? <Badge variant="destructive">退避中</Badge> : null}
                  </div>
                  <div className="text-muted-foreground truncate text-xs">
                    {sc.last_result || "尚未运行"}
                    {sc.last_run_at ? ` · 上轮 ${new Date(sc.last_run_at).toLocaleString()}` : ""}
                    {sc.last_new > 0 ? ` · 新资产 ${sc.last_new}` : ""}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Switch
                    checked={sc.enabled}
                    onCheckedChange={(v) => void act(`t-${sc.id}`, () => api.toggleReconSchedule(sc.id, v))}
                  />
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy === `r-${sc.id}`}
                    onClick={() =>
                      void act(`r-${sc.id}`, () => api.runReconScheduleNow(sc.id), "已标记到期,worker 30 秒内拾取")
                    }
                  >
                    {busy === `r-${sc.id}` ? (
                      <Loader2Icon className="size-4 animate-spin" />
                    ) : (
                      <PlayIcon className="size-4" />
                    )}
                    立即跑
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy === `d-${sc.id}`}
                    onClick={() => void act(`d-${sc.id}`, () => api.deleteReconSchedule(sc.id))}
                  >
                    <Trash2Icon className="size-4" />
                  </Button>
                </div>
              </CardContent>
              {openRuns === sc.id ? (
                <CardContent className="border-t pt-3">
                  {(runs[sc.id] ?? []).length === 0 ? (
                    <p className="text-muted-foreground text-xs">暂无运行记录(每轮流水线执行落一行)。</p>
                  ) : (
                    <div className="space-y-1">
                      {(runs[sc.id] ?? []).map((run) => (
                        <div key={run.id} className="text-muted-foreground flex flex-wrap items-center gap-2 text-xs">
                          <span className="font-mono">#{run.id}</span>
                          <Badge
                            variant={
                              run.status === "done" ? "default" : run.status === "failed" ? "destructive" : "outline"
                            }
                          >
                            {run.status}
                          </Badge>
                          <span>{new Date(run.created_at).toLocaleString()}</span>
                          {run.stats ? (
                            <span>
                              候选 {run.stats.candidates ?? 0} · 活 {run.stats.live ?? 0} · 新{" "}
                              {run.stats.new_assets ?? 0} · 端口 {run.stats.open_ports ?? 0} · http{" "}
                              {run.stats.http_alive ?? 0}
                            </span>
                          ) : null}
                          {run.error ? <span className="text-destructive">{run.error}</span> : null}
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              ) : null}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
