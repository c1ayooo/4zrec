"use client";

import * as React from "react";

import { FingerprintIcon, Loader2Icon, RefreshCwIcon, SearchIcon, Trash2Icon, UploadCloudIcon } from "lucide-react";
import { toast } from "sonner";

import { FeatureCallHistory } from "@/components/feature-call-history";
import { ProxySlotSelect } from "@/components/proxy-slot-select";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { FingerprintRule, FingerprintStatus, FingerprintSyncJob } from "@/lib/types";

// 指纹规则库(只读展示):规则由 24h 上游自动同步维护(wappalyzergo/webanalyze/dddd
// 三源 + 快照兜底),本页提供搜索、来源分布与同步状态;fingerprint_scan 工具读这里。
export default function FingerprintPage() {
  const [rules, setRules] = React.useState<FingerprintRule[] | null>(null);
  const [enabled, setEnabled] = React.useState(0);
  const [total, setTotal] = React.useState(0);
  const [page, setPage] = React.useState(1);
  const [query, setQuery] = React.useState("");
  const [search, setSearch] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [status, setStatus] = React.useState<FingerprintStatus | null>(null);
  const [syncJob, setSyncJob] = React.useState<FingerprintSyncJob | null>(null);
  const [syncing, setSyncing] = React.useState(false);
  const [deleting, setDeleting] = React.useState<string | null>(null);

  // removeRule 只允许删 custom 来源(上游来源的规则由 24h 同步维护,删了下轮
  // 还会回来)。漏洞情报确认入库的指纹就是 custom。
  const removeRule = async (id: string) => {
    setDeleting(id);
    try {
      await api.fingerprintRuleDelete(id);
      await load();
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    } finally {
      setDeleting(null);
    }
  };

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.fingerprintRules({ query: search, page });
      setRules(res.rules);
      setTotal(res.total);
      setEnabled(res.enabled);
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    } finally {
      setLoading(false);
    }
  }, [search, page]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const loadStatus = React.useCallback(async () => {
    try {
      setStatus(await api.fingerprintStatus());
    } catch {
      setStatus(null);
    }
  }, []);

  React.useEffect(() => {
    void loadStatus();
  }, [loadStatus]);

  React.useEffect(() => {
    if (!status?.syncing) return;
    const timer = setInterval(() => {
      void loadStatus();
    }, 5000);
    return () => clearInterval(timer);
  }, [status?.syncing, loadStatus]);

  const runSync = async () => {
    setSyncing(true);
    setSyncJob(null);
    try {
      setSyncJob(await api.fingerprintSync());
      for (let i = 0; i < 600; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        const job = await api.fingerprintSyncStatus();
        setSyncJob(job);
        if (!job.running) {
          if (job.error) toast.error("更新失败：" + job.error);
          else {
            const imported = (job.outcomes ?? []).reduce((n, o) => n + (o.imported ?? 0), 0);
            toast.success(`指纹规则库已更新（导入 ${imported} 条）`);
          }
          break;
        }
      }
      await Promise.all([load(), loadStatus()]);
    } catch (e) {
      toast.error("更新失败：" + (e instanceof Error ? e.message : String(e)));
    } finally {
      setSyncing(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">指纹规则库</h1>
        <p className="text-muted-foreground mt-1 text-sm">
          统一指纹规则库(启用 {enabled} 条,多源归一存储)。规则由上游自动同步(24h 周期,失败走内置快照兜底),
          也可以手动更新;fingerprint_scan 工具与 enrich 指纹链路读这里。
        </p>
      </div>

      <Card>
        <CardContent className="space-y-3 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="text-sm">
              启用 {status?.enabled ?? enabled} / 共 {status?.total ?? total}
              {status?.sources?.length ? ` · 来源 ${status.sources.length}` : ""}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <ProxySlotSelect slot="fingerprint" label="同步代理" />
              <Button onClick={() => void runSync()} disabled={syncing || !!status?.syncing}>
                {syncing || status?.syncing ? (
                  <Loader2Icon className="size-4 animate-spin" />
                ) : (
                  <UploadCloudIcon className="size-4" />
                )}
                {status?.syncing ? "自动同步中…" : syncing ? "更新中…" : "更新规则库"}
              </Button>
            </div>
          </div>
          {status?.sources?.length ? (
            <div className="flex flex-wrap gap-2">
              {status.sources.map((source) => (
                <Badge key={source.name} variant="outline" className="text-xs">
                  {source.name} · {source.rule_count} 条
                  {source.fetched_at ? ` · ${source.fetched_at.slice(0, 10)}` : ""}
                </Badge>
              ))}
            </div>
          ) : null}
          {syncJob ? (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium">{syncJob.phase ?? "准备中"}</span>
                <span className="text-muted-foreground">{syncJob.percent ?? 0}%</span>
              </div>
              <Progress value={syncJob.percent ?? 0} />
              <p className="text-muted-foreground text-xs">
                {syncJob.message || (syncJob.running ? "正在同步上游规则…" : syncJob.error || "完成")}
              </p>
              {syncJob.error ? <p className="text-xs text-red-500">{syncJob.error}</p> : null}
              {syncJob.outcomes?.length ? (
                <div className="flex flex-wrap gap-2">
                  {syncJob.outcomes.map((outcome) => (
                    <Badge
                      key={outcome.source}
                      variant={outcome.error ? "destructive" : "secondary"}
                      className="text-xs"
                    >
                      {outcome.source}: {outcome.error ? "失败" : outcome.reason}
                      {outcome.imported ? ` (${outcome.imported})` : ""}
                    </Badge>
                  ))}
                </div>
              ) : null}
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Tabs defaultValue="rules" className="space-y-4">
        <TabsList>
          <TabsTrigger value="rules">规则列表</TabsTrigger>
          <TabsTrigger value="history">调用历史</TabsTrigger>
        </TabsList>
        <TabsContent value="rules">
          <Card>
            <CardContent className="px-0">
              <div className="flex flex-wrap items-center gap-2 px-4 pb-3">
                <div className="relative flex-1 min-w-56">
                  <SearchIcon className="text-muted-foreground absolute top-2.5 left-2.5 size-4" />
                  <Input
                    className="pl-8"
                    placeholder="搜产品名/类别/表达式"
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
                  size="sm"
                  onClick={() => {
                    setSearch(query);
                    setPage(1);
                  }}
                >
                  <RefreshCwIcon className="size-4" /> 搜索
                </Button>
                <span className="text-muted-foreground text-xs">共 {total} 条</span>
                {loading ? <Loader2Icon className="size-4 animate-spin" /> : null}
              </div>
              {rules === null ? (
                <p className="text-muted-foreground px-4 pb-4 text-sm">加载中…</p>
              ) : rules.length === 0 ? (
                <p className="text-muted-foreground px-4 pb-4 text-sm">无匹配规则。</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-muted-foreground border-b text-left">
                        <th className="px-4 py-2 font-medium">产品</th>
                        <th className="px-4 py-2 font-medium">类别</th>
                        <th className="px-4 py-2 font-medium">匹配表达式</th>
                        <th className="px-4 py-2 font-medium">状态</th>
                        <th className="px-4 py-2 font-medium" />
                      </tr>
                    </thead>
                    <tbody>
                      {rules.map((r) => (
                        <tr key={r.id} className="border-b last:border-0">
                          <td className="px-4 py-2 font-medium">{r.name}</td>
                          <td className="text-muted-foreground px-4 py-2">{r.category || "-"}</td>
                          <td className="max-w-96 truncate px-4 py-2 font-mono text-xs">{r.expression}</td>
                          <td className="px-4 py-2">
                            {r.enabled ? <Badge variant="default">启用</Badge> : <Badge variant="outline">停用</Badge>}
                          </td>
                          <td className="px-4 py-2">
                            {r.source === "custom" ? (
                              <Button
                                variant="ghost"
                                size="sm"
                                disabled={deleting === r.id}
                                onClick={() => removeRule(r.id)}
                              >
                                {deleting === r.id ? (
                                  <Loader2Icon className="size-3.5 animate-spin" />
                                ) : (
                                  <Trash2Icon className="size-3.5" />
                                )}
                              </Button>
                            ) : null}
                          </td>
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
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={page >= Math.ceil(total / 50)}
                      onClick={() => setPage((p) => p + 1)}
                    >
                      下一页
                    </Button>
                  </div>
                </div>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="history">
          <FeatureCallHistory feature="fingerprint" />
        </TabsContent>
      </Tabs>
    </div>
  );
}
