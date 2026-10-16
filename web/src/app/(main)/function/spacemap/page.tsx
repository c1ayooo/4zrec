"use client";

import * as React from "react";

import { Loader2Icon, RadarIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api } from "@/lib/api";
import type { Project, SpacemapResultRow } from "@/lib/types";
import { cn } from "@/lib/utils";

// 空间测绘结果页:五引擎采集入库的资产,按引擎筛选(来源标注写在资产上,
// 配置面在 系统管理 → 空间测绘配置)。
const typeLabels: Record<string, string> = {
  root_domain: "根域名",
  subdomain: "子域名",
  ip: "IP",
  service: "服务",
  app: "App",
  endpoint: "端点",
};

export default function SpacemapResultsPage() {
  const [rows, setRows] = React.useState<SpacemapResultRow[] | null>(null);
  const [total, setTotal] = React.useState(0);
  const [engines, setEngines] = React.useState<{ provider: string; display: string }[]>([]);
  const [projects, setProjects] = React.useState<Project[]>([]);
  const [engine, setEngine] = React.useState("");
  const [typ, setTyp] = React.useState("");
  // 项目为主轴:按项目拆开看,信息收集结果自动归属对话挂载的项目。
  const [projectID, setProjectID] = React.useState("");
  const [page, setPage] = React.useState(1);
  const [loading, setLoading] = React.useState(false);
  const pageSize = 50;

  React.useEffect(() => {
    api
      .projects()
      .then(setProjects)
      .catch(() => {});
  }, []);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.spacemapResults({
        engine,
        type: typ,
        projectId: projectID ? Number(projectID) : undefined,
        page,
        size: pageSize,
      });
      setRows(res.results);
      setTotal(res.total);
      if (res.engines.length) setEngines(res.engines);
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    } finally {
      setLoading(false);
    }
  }, [engine, typ, projectID, page]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const authzBadge = (authz?: string | null) => {
    if (authz === "pending") return <Badge variant="outline">待审批</Badge>;
    if (authz === "rejected") return <Badge variant="destructive">已拒绝</Badge>;
    return <Badge variant="default">已授权</Badge>;
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">空间测绘</h1>
        <p className="text-muted-foreground mt-1 text-sm">
          五引擎（FOFA / ZoomEye / Quake / Shodan / Hunter）采集入库的资产，按引擎筛选。引擎 Key 在{" "}
          <span className="text-foreground">系统管理 → 空间测绘配置</span> 维护；agent 的 space_search /
          space_search_batch 采集结果实时落在这里。
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Button
          variant={engine === "" ? "default" : "outline"}
          size="sm"
          onClick={() => {
            setEngine("");
            setPage(1);
          }}
        >
          全部引擎
        </Button>
        {engines.map((e) => (
          <Button
            key={e.provider}
            variant={engine === e.display ? "default" : "outline"}
            size="sm"
            onClick={() => {
              setEngine(e.display);
              setPage(1);
            }}
          >
            {e.display}
          </Button>
        ))}
        <div className="ml-auto flex items-center gap-2">
          <Select
            value={projectID || "all"}
            onValueChange={(v) => {
              setProjectID(v === "all" ? "" : v);
              setPage(1);
            }}
          >
            <SelectTrigger className="w-44">
              <SelectValue placeholder="项目" />
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
          <Select
            value={typ || "all"}
            onValueChange={(v) => {
              setTyp(v === "all" ? "" : v);
              setPage(1);
            }}
          >
            <SelectTrigger className="w-32">
              <SelectValue placeholder="资产类型" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部类型</SelectItem>
              {Object.entries(typeLabels).map(([k, v]) => (
                <SelectItem key={k} value={k}>
                  {v}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <Card>
        <CardContent className="px-0">
          {rows === null || loading ? (
            <div className="text-muted-foreground flex items-center justify-center gap-2 py-10 text-sm">
              <Loader2Icon className="size-4 animate-spin" /> 加载中…
            </div>
          ) : rows.length === 0 ? (
            <div className="text-muted-foreground flex flex-col items-center gap-2 py-12 text-sm">
              <RadarIcon className="size-6 opacity-40" />
              暂无测绘结果——在对话里让 agent 跑 space_search / space_search_batch，或等周期采集任务执行。
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-muted-foreground border-b text-left">
                    <th className="px-4 py-2 font-medium">类型</th>
                    <th className="px-4 py-2 font-medium">目标</th>
                    <th className="px-4 py-2 font-medium">端口</th>
                    <th className="px-4 py-2 font-medium">标题</th>
                    <th className="px-4 py-2 font-medium">授权</th>
                    <th className="px-4 py-2 font-medium">引擎</th>
                    <th className="px-4 py-2 font-medium">指纹</th>
                    <th className="px-4 py-2 font-medium">最近更新</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.id} className="border-b last:border-0">
                      <td className="px-4 py-2 whitespace-nowrap">{typeLabels[r.type] ?? r.type}</td>
                      <td className="max-w-72 truncate px-4 py-2 font-mono">{r.label}</td>
                      <td className="px-4 py-2">{r.port || "-"}</td>
                      <td className="max-w-60 truncate px-4 py-2">{r.title || "-"}</td>
                      <td className="px-4 py-2">{authzBadge(r.authz)}</td>
                      <td className="px-4 py-2">
                        <Badge variant="outline" className={cn("font-mono")}>
                          {r.source}
                        </Badge>
                      </td>
                      <td className="max-w-48 truncate px-4 py-2 text-muted-foreground">
                        {(r.technologies ?? []).length ? r.technologies.slice(0, 3).join(", ") : "-"}
                      </td>
                      <td className="text-muted-foreground px-4 py-2 whitespace-nowrap">
                        {new Date(r.last_seen).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {total > pageSize ? (
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">
            共 {total} 条 · 第 {page} / {Math.ceil(total / pageSize)} 页
          </span>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled={page <= 1 || loading} onClick={() => setPage((p) => p - 1)}>
              上一页
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={page >= Math.ceil(total / pageSize) || loading}
              onClick={() => setPage((p) => p + 1)}
            >
              下一页
            </Button>
          </div>
        </div>
      ) : (
        <p className="text-muted-foreground text-right text-xs">共 {total} 条</p>
      )}
    </div>
  );
}
