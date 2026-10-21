"use client";

import * as React from "react";

import { ClockIcon, Loader2Icon, RefreshCwIcon, SearchIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { FeatureCall, FeatureCallFeature, FeatureCallSource, FeatureCallStats } from "@/lib/types";

const PAGE_SIZE = 50;

const ACTION_LABELS: Record<string, string> = {
  search: "搜索",
  list: "列表",
  view: "查看",
  lookup: "Agent 查询",
  scan: "扫描",
  sync: "同步",
  refresh: "刷新",
  create: "新建",
  update: "更新",
  delete: "删除",
  validate: "校验",
  template_search: "模板检索",
};

const SOURCE_LABELS: Record<FeatureCallSource, string> = {
  web: "页面",
  agent: "Agent",
  schedule: "定时",
  system: "系统",
};

const STATUS_LABELS: Record<string, string> = {
  ok: "成功",
  error: "失败",
  denied: "拒绝",
};

const EMPTY_HINT: Record<FeatureCallFeature, string> = {
  vulnkb: "Agent 调用 search_vuln_kb，或在页面搜索、查看漏洞后，记录会出现在这里。",
  nuclei: "Agent 调用 nuclei_scan / nuclei_template_search，或在页面搜索、查看、编辑模板后，记录会出现在这里。",
  fingerprint: "Agent 调用 fingerprint_scan，或在页面搜索规则、同步规则库后，记录会出现在这里。",
};

type Range = "24h" | "7d" | "30d" | "all";

function rangeFrom(range: Range): string | undefined {
  if (range === "all") return undefined;
  const ms = range === "24h" ? 24 * 3600_000 : range === "7d" ? 7 * 24 * 3600_000 : 30 * 24 * 3600_000;
  return new Date(Date.now() - ms).toISOString();
}

function fmtTime(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function fmtDuration(ms: number): string {
  if (!ms || ms < 0) return "—";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

function pretty(value: unknown): string {
  if (value == null) return "—";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function statusTone(status: string): string {
  if (status === "ok") return "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400";
  if (status === "denied") return "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400";
  return "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400";
}

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-lg border bg-card px-3 py-2">
      <p className="text-muted-foreground text-[11px]">{label}</p>
      <p className="mt-0.5 text-lg font-semibold tabular-nums">{value}</p>
    </div>
  );
}

export function FeatureCallHistory({ feature }: { feature: FeatureCallFeature }) {
  const [items, setItems] = React.useState<FeatureCall[]>([]);
  const [total, setTotal] = React.useState(0);
  const [page, setPage] = React.useState(1);
  const [action, setAction] = React.useState("all");
  const [source, setSource] = React.useState("all");
  const [status, setStatus] = React.useState("all");
  const [range, setRange] = React.useState<Range>("7d");
  const [query, setQuery] = React.useState("");
  const [search, setSearch] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [stats, setStats] = React.useState<FeatureCallStats | null>(null);
  const [selected, setSelected] = React.useState<FeatureCall | null>(null);
  const [detail, setDetail] = React.useState<FeatureCall | null>(null);
  const [detailLoading, setDetailLoading] = React.useState(false);

  const from = React.useMemo(() => rangeFrom(range), [range]);
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [list, stat] = await Promise.all([
        api.featureCalls({
          feature,
          action: action === "all" ? undefined : action,
          source: source === "all" ? undefined : source,
          status: status === "all" ? undefined : status,
          q: search.trim() || undefined,
          from,
          page,
          size: PAGE_SIZE,
        }),
        api.featureCallStats({ feature, from }),
      ]);
      setItems(list.items ?? []);
      setTotal(list.total ?? 0);
      setStats(stat.stats ?? null);
    } catch (err) {
      toast.error("读取调用历史失败：" + (err instanceof Error ? err.message : String(err)));
      setItems([]);
      setTotal(0);
      setStats(null);
    } finally {
      setLoading(false);
    }
  }, [feature, action, source, status, search, from, page]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const changeFilter = (setter: (v: string) => void) => (v: string) => {
    setter(v);
    setPage(1);
  };

  const openDetail = async (call: FeatureCall) => {
    setSelected(call);
    setDetail(null);
    setDetailLoading(true);
    try {
      const r = await api.featureCall(call.id);
      setDetail(r.call);
    } catch {
      setDetail(call);
    } finally {
      setDetailLoading(false);
    }
  };

  const shown = detail ?? selected;

  return (
    <div className="space-y-4">
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="调用次数" value={stats?.total ?? 0} />
        <Stat
          label="成功率"
          value={stats && stats.total > 0 ? `${Math.round((stats.ok / stats.total) * 100)}%` : "—"}
        />
        <Stat label="平均耗时" value={stats ? fmtDuration(stats.avg_duration_ms) : "—"} />
        <Stat
          label="最近调用"
          value={stats?.last_at ? <span className="text-sm font-medium">{fmtTime(stats.last_at)}</span> : "—"}
        />
      </div>

      <Card>
        <CardContent className="space-y-3 p-4">
          <div className="flex flex-wrap items-center gap-2">
            <Select value={range} onValueChange={changeFilter((v) => setRange(v as Range))}>
              <SelectTrigger className="w-28">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="24h">近 24 小时</SelectItem>
                <SelectItem value="7d">近 7 天</SelectItem>
                <SelectItem value="30d">近 30 天</SelectItem>
                <SelectItem value="all">全部时间</SelectItem>
              </SelectContent>
            </Select>
            <Select value={action} onValueChange={changeFilter(setAction)}>
              <SelectTrigger className="w-32">
                <SelectValue placeholder="动作" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部动作</SelectItem>
                {Object.entries(ACTION_LABELS).map(([k, v]) => (
                  <SelectItem key={k} value={k}>
                    {v}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={source} onValueChange={changeFilter(setSource)}>
              <SelectTrigger className="w-28">
                <SelectValue placeholder="来源" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部来源</SelectItem>
                {Object.entries(SOURCE_LABELS).map(([k, v]) => (
                  <SelectItem key={k} value={k}>
                    {v}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={status} onValueChange={changeFilter(setStatus)}>
              <SelectTrigger className="w-28">
                <SelectValue placeholder="状态" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部状态</SelectItem>
                <SelectItem value="ok">成功</SelectItem>
                <SelectItem value="error">失败</SelectItem>
                <SelectItem value="denied">拒绝</SelectItem>
              </SelectContent>
            </Select>
            <div className="relative min-w-52 flex-1">
              <SearchIcon className="text-muted-foreground absolute top-2.5 left-2.5 size-4" />
              <Input
                className="pl-8"
                placeholder="搜查询词 / 参数 / 调用者 / 错误"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    setSearch(query);
                    setPage(1);
                  }
                }}
              />
            </div>
            <Button
              variant="outline"
              onClick={() => {
                setSearch(query);
                setPage(1);
              }}
            >
              <SearchIcon className="size-4" /> 搜索
            </Button>
            <Button variant="ghost" onClick={() => void load()} disabled={loading}>
              {loading ? <Loader2Icon className="size-4 animate-spin" /> : <RefreshCwIcon className="size-4" />}
              刷新
            </Button>
          </div>

          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[9%]">时间</TableHead>
                  <TableHead className="w-[7%]">来源</TableHead>
                  <TableHead className="w-[8%]">动作</TableHead>
                  <TableHead className="w-[13%]">调用者</TableHead>
                  <TableHead>对象 / 参数</TableHead>
                  <TableHead className="w-[24%]">结果</TableHead>
                  <TableHead className="w-[8%]">耗时</TableHead>
                  <TableHead className="w-[7%]">状态</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-muted-foreground h-32 text-center">
                      <Loader2Icon className="mx-auto mb-2 size-5 animate-spin" />
                      加载中…
                    </TableCell>
                  </TableRow>
                ) : items.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-muted-foreground h-32 text-center">
                      <p>暂无调用记录。</p>
                      <p className="mt-1 text-xs">{EMPTY_HINT[feature]}</p>
                    </TableCell>
                  </TableRow>
                ) : (
                  items.map((c) => (
                    <TableRow key={c.id} className="cursor-pointer" onClick={() => void openDetail(c)}>
                      <TableCell className="text-muted-foreground text-xs tabular-nums">{fmtTime(c.ts)}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-[11px]">
                          {SOURCE_LABELS[c.source] ?? c.source}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs">{ACTION_LABELS[c.action] ?? c.action}</TableCell>
                      <TableCell className="text-xs">
                        <div className="truncate" title={c.actor || c.session_id || ""}>
                          {c.actor || "—"}
                        </div>
                        {c.task_id ? (
                          <div className="text-muted-foreground text-[11px]">task #{c.task_id}</div>
                        ) : c.session_id ? (
                          <div className="text-muted-foreground truncate text-[11px]">{c.session_id}</div>
                        ) : null}
                      </TableCell>
                      <TableCell className="max-w-0">
                        <div className="truncate text-xs" title={c.query || c.ref_id || ""}>
                          {c.query || c.ref_id || "—"}
                        </div>
                        {c.ref_type ? (
                          <div className="text-muted-foreground truncate text-[11px]">
                            {c.ref_type}
                            {c.ref_id ? ` · ${c.ref_id}` : ""}
                          </div>
                        ) : null}
                      </TableCell>
                      <TableCell className="max-w-0">
                        <div className="truncate text-xs" title={c.summary}>
                          {c.summary || "—"}
                        </div>
                      </TableCell>
                      <TableCell className="text-muted-foreground text-xs tabular-nums">
                        {fmtDuration(c.duration_ms)}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={`text-[11px] ${statusTone(c.status)}`}>
                          {STATUS_LABELS[c.status] ?? c.status}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>

          <div className="flex items-center justify-between gap-2">
            <p className="text-muted-foreground text-xs">
              共 {total} 条 · 第 {page} / {totalPages} 页
            </p>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={page <= 1 || loading}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                上一页
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={page >= totalPages || loading}
                onClick={() => setPage((p) => p + 1)}
              >
                下一页
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <Sheet open={selected !== null} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent className="flex w-full flex-col gap-0 overflow-hidden sm:max-w-xl">
          <SheetHeader className="border-b px-6 py-4">
            <SheetTitle className="flex items-center gap-2 text-left text-base">
              <ClockIcon className="size-4 text-muted-foreground" />
              {shown ? `${ACTION_LABELS[shown.action] ?? shown.action} · ${shown.summary}` : "调用详情"}
            </SheetTitle>
            <SheetDescription className="text-left">
              {shown
                ? `${fmtTime(shown.ts)} · ${SOURCE_LABELS[shown.source] ?? shown.source} · ${fmtDuration(shown.duration_ms)}`
                : ""}
            </SheetDescription>
          </SheetHeader>
          <div className="flex-1 space-y-4 overflow-y-auto px-6 py-4">
            {detailLoading ? (
              <div className="flex justify-center py-8">
                <Loader2Icon className="size-5 animate-spin text-muted-foreground" />
              </div>
            ) : shown ? (
              <>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-muted-foreground">状态：</span>
                    <Badge variant="outline" className={`text-[11px] ${statusTone(shown.status)}`}>
                      {STATUS_LABELS[shown.status] ?? shown.status}
                    </Badge>
                  </div>
                  <div>
                    <span className="text-muted-foreground">调用者：</span>
                    {shown.actor || "—"}
                  </div>
                  <div>
                    <span className="text-muted-foreground">任务：</span>
                    {shown.task_id ? (
                      <a
                        className="text-primary underline-offset-4 hover:underline"
                        href={`/function/tasks/detail?id=${shown.task_id}`}
                      >
                        task #{shown.task_id}
                      </a>
                    ) : (
                      "—"
                    )}
                  </div>
                  <div>
                    <span className="text-muted-foreground">会话：</span>
                    {shown.session_id || "—"}
                  </div>
                  <div>
                    <span className="text-muted-foreground">对象：</span>
                    {shown.ref_type || "—"}
                    {shown.ref_id ? ` · ${shown.ref_id}` : ""}
                  </div>
                  <div>
                    <span className="text-muted-foreground">项目：</span>
                    {shown.project_id ? `#${shown.project_id}` : "—"}
                  </div>
                </div>

                {shown.query ? (
                  <div className="grid gap-1">
                    <span className="text-xs font-medium text-muted-foreground">查询 / 参数</span>
                    <pre className="bg-muted/50 max-h-32 overflow-auto rounded-md border p-2 font-mono text-xs whitespace-pre-wrap break-all">
                      {shown.query}
                    </pre>
                  </div>
                ) : null}

                <div className="grid gap-1">
                  <span className="text-xs font-medium text-muted-foreground">请求</span>
                  <pre className="bg-muted/50 max-h-64 overflow-auto rounded-md border p-2 font-mono text-xs whitespace-pre-wrap break-all">
                    {pretty(shown.request)}
                  </pre>
                </div>

                <div className="grid gap-1">
                  <span className="text-xs font-medium text-muted-foreground">结果</span>
                  <pre className="bg-muted/50 max-h-64 overflow-auto rounded-md border p-2 font-mono text-xs whitespace-pre-wrap break-all">
                    {pretty(shown.result)}
                  </pre>
                </div>

                {shown.error ? (
                  <div className="grid gap-1">
                    <span className="text-xs font-medium text-red-500">错误</span>
                    <pre className="max-h-40 overflow-auto rounded-md border border-red-500/30 bg-red-500/5 p-2 font-mono text-xs whitespace-pre-wrap break-all text-red-600 dark:text-red-400">
                      {shown.error}
                    </pre>
                  </div>
                ) : null}
              </>
            ) : null}
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
