"use client";

import * as React from "react";

import { Building2Icon, Loader2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api } from "@/lib/api";
import type { EntCandidate, EntJob, Project } from "@/lib/types";

// 企业采集页:关联采集任务(BFS 进度)与候选域名池(授权→导入资产库)。
// 数据源会话配置在 系统管理 → 企业数据源;未配置时仅 ICP 反查路径可用。
const jobStatusLabels: Record<string, { label: string; variant: "default" | "outline" | "destructive" }> = {
  running: { label: "进行中", variant: "default" },
  done: { label: "已完成", variant: "default" },
  waiting_authorization: { label: "待授权确认", variant: "outline" },
  error: { label: "失败", variant: "destructive" },
  canceled: { label: "已取消", variant: "outline" },
};

const candStatusLabels: Record<string, string> = {
  candidate: "待授权",
  authorized: "已授权",
  imported: "已导入",
  rejected: "已忽略",
};

export default function EnterprisePage() {
  const [jobs, setJobs] = React.useState<EntJob[] | null>(null);
  const [candidates, setCandidates] = React.useState<EntCandidate[] | null>(null);
  const [total, setTotal] = React.useState(0);
  // 项目为主轴:任务与候选都按项目拆开看。
  const [projects, setProjects] = React.useState<Project[]>([]);
  const [projectFilter, setProjectFilter] = React.useState("");
  const [statusFilter, setStatusFilter] = React.useState("");
  const [page, setPage] = React.useState(1);
  const [projectID, setProjectID] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [importing, setImporting] = React.useState(false);

  React.useEffect(() => {
    api
      .projects()
      .then(setProjects)
      .catch(() => {});
  }, []);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const pf = projectFilter ? Number(projectFilter) : undefined;
      const [j, c] = await Promise.all([
        api.entJobs(pf),
        api.entCandidates(statusFilter, page, pf),
      ]);
      setJobs(j);
      setCandidates(c.candidates);
      setTotal(c.total);
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    } finally {
      setLoading(false);
    }
  }, [statusFilter, page, projectFilter]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const importAll = async () => {
    if (!projectID) {
      toast.error("先填目标项目 ID(资产导入后按项目范围授权)");
      return;
    }
    setImporting(true);
    try {
      const res = await api.entImportCandidates(Number(projectID));
      toast.success(`已导入 ${res.imported}/${res.total} 个候选域名(范围内自动授权,范围外待审批)`);
      await load();
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    } finally {
      setImporting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">企业采集</h1>
        <p className="text-muted-foreground mt-1 text-sm">
          企业关联采集（BFS：分支机构 + 对外投资 → 候选域名池）。agent 的 enterprise_collect
          发起任务后，进度与候选在这里看；数据源会话在{" "}
          <span className="text-foreground">系统管理 → 企业数据源</span> 配置。
        </p>
      </div>

      <Card>
        <CardContent className="px-0">
          <div className="flex items-center justify-between px-4 pb-2">
            <h2 className="text-sm font-medium">采集任务</h2>
            <div className="flex items-center gap-2">
              <Select
                value={projectFilter || "all"}
                onValueChange={(v) => {
                  setProjectFilter(v === "all" ? "" : v);
                  setPage(1);
                }}
              >
                <SelectTrigger className="h-8 w-44">
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
              {loading ? <Loader2Icon className="text-muted-foreground size-4 animate-spin" /> : null}
            </div>
          </div>
          {jobs === null ? (
            <p className="text-muted-foreground px-4 pb-4 text-sm">加载中…</p>
          ) : jobs.length === 0 ? (
            <p className="text-muted-foreground px-4 pb-4 text-sm">
              暂无任务——在对话里让 agent 用 enterprise_company_search 找到企业后 enterprise_collect 发起。
            </p>
          ) : (
            <div className="grid gap-2 px-4 pb-4">
              {jobs.map((j) => {
                const st = jobStatusLabels[j.status] ?? { label: j.status, variant: "outline" as const };
                return (
                  <div key={j.id} className="flex flex-wrap items-center gap-2 text-sm">
                    <Building2Icon className="text-muted-foreground size-4" />
                    <span className="font-medium">{j.keyword || j.id}</span>
                    <Badge variant={st.variant}>{st.label}</Badge>
                    <Badge variant="outline">{j.provider}</Badge>
                    <span className="text-muted-foreground text-xs">
                      节点 {j.nodes}/{j.max_nodes} · 实体 {j.entities} · 域名 {j.domains} · 已导入 {j.imported}
                    </span>
                    {j.error ? <span className="text-destructive text-xs">{j.error}</span> : null}
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardContent className="px-0">
          <div className="flex flex-wrap items-center gap-2 px-4 pb-3">
            <h2 className="text-sm font-medium">候选域名池</h2>
            <div className="ml-auto flex flex-wrap items-center gap-2">
              <Input
                className="h-8 w-40"
                placeholder="目标项目 ID"
                type="number"
                value={projectID}
                onChange={(e) => setProjectID(e.target.value)}
              />
              <Button size="sm" disabled={importing} onClick={() => void importAll()}>
                {importing ? <Loader2Icon className="size-4 animate-spin" /> : null}
                导入资产库
              </Button>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 px-4 pb-3">
            {[
              { v: "", label: "全部" },
              { v: "candidate", label: "待授权" },
              { v: "authorized", label: "已授权" },
              { v: "imported", label: "已导入" },
            ].map((f) => (
              <Button
                key={f.v}
                size="sm"
                variant={statusFilter === f.v ? "default" : "outline"}
                onClick={() => {
                  setStatusFilter(f.v);
                  setPage(1);
                }}
              >
                {f.label}
              </Button>
            ))}
            <span className="text-muted-foreground text-xs">共 {total} 条</span>
          </div>
          {candidates === null ? (
            <p className="text-muted-foreground px-4 pb-4 text-sm">加载中…</p>
          ) : candidates.length === 0 ? (
            <p className="text-muted-foreground px-4 pb-4 text-sm">暂无候选域名。</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-muted-foreground border-b text-left">
                    <th className="px-4 py-2 font-medium">域名</th>
                    <th className="px-4 py-2 font-medium">关联实体</th>
                    <th className="px-4 py-2 font-medium">任务</th>
                    <th className="px-4 py-2 font-medium">状态</th>
                    <th className="px-4 py-2 font-medium">指纹</th>
                  </tr>
                </thead>
                <tbody>
                  {candidates.map((c) => (
                    <tr key={c.id} className="border-b last:border-0">
                      <td className="px-4 py-2 font-mono">{c.value}</td>
                      <td className="px-4 py-2">{c.entity_name || "-"}</td>
                      <td className="text-muted-foreground px-4 py-2 text-xs">{c.job_name || c.job_id}</td>
                      <td className="px-4 py-2">
                        <Badge variant={c.status === "candidate" ? "outline" : "default"}>
                          {candStatusLabels[c.status] ?? c.status}
                        </Badge>
                      </td>
                      <td className="text-muted-foreground px-4 py-2 text-xs">{c.fingerprint_status || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {total > 50 ? (
            <div className="flex items-center justify-between px-4 pt-3 text-sm">
              <span className="text-muted-foreground">
                第 {page} / {Math.ceil(total / 50)} 页
              </span>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                  上一页
                </Button>
                <Button variant="outline" size="sm" disabled={page >= Math.ceil(total / 50)} onClick={() => setPage((p) => p + 1)}>
                  下一页
                </Button>
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
