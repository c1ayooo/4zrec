"use client";

import * as React from "react";

import Link from "next/link";

import { CheckIcon, RefreshCwIcon, ShieldAlertIcon, XIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import { assetProvenance } from "@/lib/asset-provenance";
import type { Asset, AssetProbeResult } from "@/lib/types";
import { useProjectStore } from "@/stores/project/project-provider";

function fmtTime(iso: string): string {
  const t = new Date(iso).getTime();
  if (!t) return "-";
  return new Date(t).toLocaleString("zh-CN", {
    year: "2-digit",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function assetTarget(a: Asset): string {
  return a.domain || a.url || a.ip || `#${a.id}`;
}

// ProbeCell 探活结果:存活端口/HTTP、归属线索(PTR/证书 SAN 命中授权域)。
function ProbeCell({ result }: { result?: AssetProbeResult }) {
  if (!result) return <span className="text-muted-foreground text-xs">—</span>;
  if (result.error) return <span className="text-muted-foreground text-xs">{result.error}</span>;
  return (
    <div className="flex min-w-0 flex-col gap-0.5 text-[11px]">
      <span className={result.alive ? "font-medium text-success" : "text-muted-foreground"}>
        {result.alive ? "存活" : "无响应"}
        {result.ports?.length ? ` · ${result.ports.join("/")}` : ""}
        {result.http_status ? ` · HTTP ${result.http_status}` : ""}
      </span>
      {result.ownership?.map((hint) => (
        <span key={hint} className="truncate text-success" title={hint}>
          {hint}
        </span>
      ))}
      {result.ptr?.length ? (
        <span className="truncate text-muted-foreground" title={result.ptr.join(", ")}>
          PTR {result.ptr[0]}
        </span>
      ) : null}
      {result.title ? (
        <span className="truncate text-muted-foreground" title={result.title}>
          {result.title}
        </span>
      ) : null}
    </div>
  );
}

// 资产审批页：项目范围外的渗透发现在这里批准/驳回（批准后才能测试）。
// 从项目详情页拆出独立入口，支持跨项目聚合 + 按全局项目过滤 + 批量探活/审批。
export default function ApprovalsPage() {
  const projects = useProjectStore((s) => s.projects);
  const status = useProjectStore((s) => s.status);
  const reloadProjects = useProjectStore((s) => s.reloadProjects);

  // 过滤范围默认跟全局项目；"all" = 全部项目（审批是跨项目职责，允许临时全局看）。
  // 支持 ?project_id= 深链（项目卡片「待审批 N」跳转），用掉即清。
  const [filter, setFilter] = React.useState<"all" | number>("all");
  React.useEffect(() => {
    const q = new URLSearchParams(window.location.search);
    const pid = Number(q.get("project_id")) || 0;
    if (pid > 0) {
      setFilter(pid);
      window.history.replaceState(null, "", window.location.pathname);
    }
  }, []);
  const [pending, setPending] = React.useState<Asset[]>([]);
  const [pendingTotal, setPendingTotal] = React.useState(0);
  const [loading, setLoading] = React.useState(true);
  const [selected, setSelected] = React.useState<Set<number>>(new Set());
  const [probeResults, setProbeResults] = React.useState<Record<number, AssetProbeResult>>({});
  const [probing, setProbing] = React.useState(false);
  const [bulkBusy, setBulkBusy] = React.useState(false);
  const [bulkAction, setBulkAction] = React.useState<"approve" | "reject" | null>(null);

  const activeFilter = status === "ready" ? filter : "all";
  const queryProject = activeFilter === "all" ? 0 : activeFilter;

  const load = React.useCallback(async (projectID: number) => {
    setLoading(true);
    try {
      // 待审批可能几百条:一次拉满(上限 500),配合全选/批量审批/批量探活。
      const r = await api.pendingAssets(projectID, 500, 0);
      setPending(r.assets);
      setPendingTotal(r.total);
      setSelected((prev) => {
        if (prev.size === 0) return prev;
        const ids = new Set(r.assets.map((a) => a.id));
        const next = new Set([...prev].filter((id) => ids.has(id)));
        return next.size === prev.size ? prev : next;
      });
    } catch (e) {
      toast.error(`加载待审批失败: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    if (status !== "ready") return;
    void load(queryProject);
  }, [status, queryProject, load]);

  const projectNameOf = (id?: number) => projects.find((p) => p.id === id)?.name ?? "-";

  const decide = async (ids: number[], action: "approve" | "reject") => {
    try {
      await api.setAssetAuthz(ids, action, queryProject);
      toast.success(action === "approve" ? "已批准，资产可测试" : "已拒绝");
      setSelected((prev) => {
        const next = new Set(prev);
        for (const id of ids) next.delete(id);
        return next;
      });
      await load(queryProject);
      // 批准/驳回会改变项目 pending_count，顺手刷新全局项目统计。
      void reloadProjects();
    } catch (e) {
      toast.error(`操作失败: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const askBulk = (action: "approve" | "reject") => {
    if (selected.size === 0) {
      toast.error("先勾选要处理的资产");
      return;
    }
    setBulkAction(action);
  };

  const confirmBulk = async () => {
    if (!bulkAction) return;
    const ids = [...selected];
    setBulkBusy(true);
    try {
      await decide(ids, bulkAction);
      setBulkAction(null);
    } finally {
      setBulkBusy(false);
    }
  };

  const probe = async (ids: number[]) => {
    if (ids.length === 0) {
      toast.error("先勾选要探活的资产");
      return;
    }
    setProbing(true);
    try {
      const results = await api.probeAssets(ids, queryProject);
      setProbeResults((prev) => {
        const next = { ...prev };
        for (const r of results) next[r.id] = r;
        return next;
      });
      const alive = results.filter((r) => r.alive).length;
      toast.success(`探活完成：${alive}/${results.length} 存活`);
    } catch (e) {
      toast.error(`探活失败: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setProbing(false);
    }
  };

  const allSelected = pending.length > 0 && pending.every((a) => selected.has(a.id));
  const toggleAll = () => setSelected(allSelected ? new Set() : new Set(pending.map((a) => a.id)));
  const toggleOne = (id: number) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">资产审批</h1>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-muted-foreground text-sm">按项目</span>
          <Select
            value={activeFilter === "all" ? "all" : String(activeFilter)}
            onValueChange={(v) => setFilter(v === "all" ? "all" : Number(v))}
          >
            <SelectTrigger className="h-8 w-40" aria-label="按项目过滤待审批">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部项目</SelectItem>
              {projects.map((p) => (
                <SelectItem key={p.id} value={String(p.id)}>
                  {p.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" size="sm" onClick={() => void load(queryProject)} disabled={loading}>
            <RefreshCwIcon className={loading ? "animate-spin" : undefined} />
            刷新
          </Button>
        </div>
      </div>

      <div className="flex flex-col gap-3">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <ShieldAlertIcon className="size-4 text-warning" />
            <span className="font-medium">待审批资产</span>
            <Badge variant={pendingTotal > 0 ? "destructive" : "secondary"}>{pendingTotal}</Badge>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <Button
              size="sm"
              variant="outline"
              onClick={() => void probe([...selected])}
              disabled={probing || selected.size === 0}
              title="对选中资产做轻量探活：PTR、证书 SAN、TCP、GET /，用于判断归属"
            >
              {probing ? "探活中…" : `探活选中 (${selected.size})`}
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => askBulk("approve")}
              disabled={bulkBusy || selected.size === 0}
            >
              <CheckIcon className="text-success" />
              批准选中
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => askBulk("reject")}
              disabled={bulkBusy || selected.size === 0}
            >
              <XIcon className="text-destructive" />
              拒绝选中
            </Button>
          </div>
        </div>
        {loading ? (
          <div className="flex flex-col gap-3 py-2">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        ) : pending.length === 0 ? (
          <Empty>
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <ShieldAlertIcon />
              </EmptyMedia>
              <EmptyTitle>没有待审批资产</EmptyTitle>
              <EmptyDescription>扫描发现范围外资产后，将在这里等待审批。</EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8">
                    <Checkbox checked={allSelected} onCheckedChange={toggleAll} aria-label="全选待审批资产" />
                  </TableHead>
                  <TableHead>目标</TableHead>
                  <TableHead>类型</TableHead>
                  <TableHead>出处</TableHead>
                  <TableHead>探活 / 归属线索</TableHead>
                  <TableHead>项目</TableHead>
                  <TableHead>发现时间</TableHead>
                  <TableHead className="text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pending.map((a) => (
                  <TableRow key={a.id} className={selected.has(a.id) ? "bg-muted/40" : undefined}>
                    <TableCell className="w-8 pr-0">
                      <Checkbox
                        checked={selected.has(a.id)}
                        onCheckedChange={() => toggleOne(a.id)}
                        aria-label={`选择资产 ${assetTarget(a)}`}
                      />
                    </TableCell>
                    <TableCell className="font-mono text-sm">{assetTarget(a)}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{a.type}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground max-w-48 truncate text-xs" title={assetProvenance(a)}>
                      {assetProvenance(a)}
                    </TableCell>
                    <TableCell className="max-w-56">
                      <ProbeCell result={probeResults[a.id]} />
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {a.project_id ? (
                        <Link href={`/function/projects/detail?id=${a.project_id}`} className="hover:underline">
                          {projectNameOf(a.project_id)}
                        </Link>
                      ) : (
                        "-"
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">{fmtTime(a.last_seen)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button size="sm" variant="ghost" disabled={probing} onClick={() => void probe([a.id])}>
                          探活
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => void decide([a.id], "approve")}>
                          <CheckIcon className="text-success" />
                          批准
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => void decide([a.id], "reject")}>
                          <XIcon className="text-destructive" />
                          拒绝
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>

      {/* 批量操作确认 */}
      <AlertDialog open={!!bulkAction} onOpenChange={(o) => !o && setBulkAction(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{bulkAction === "approve" ? "批量批准" : "批量拒绝"}</AlertDialogTitle>
            <AlertDialogDescription>
              {bulkAction === "approve"
                ? `批准选中的 ${selected.size} 条资产后即可对其测试；批准只升不降，不会覆盖已批准状态。`
                : `拒绝选中的 ${selected.size} 条资产，后续同一资产再次发现不会重新弹出。`}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={bulkBusy}>取消</AlertDialogCancel>
            <AlertDialogAction
              className={bulkAction === "reject" ? "bg-destructive/15 text-destructive hover:bg-destructive/20" : undefined}
              disabled={bulkBusy}
              onClick={(e) => {
                e.preventDefault();
                void confirmBulk();
              }}
            >
              {bulkBusy ? "处理中…" : "确认"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
