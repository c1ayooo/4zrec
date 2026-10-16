"use client";

import * as React from "react";

import { FingerprintIcon, Loader2Icon, RefreshCwIcon, SearchIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type { FingerprintRule, FingerprintSource } from "@/lib/types";

// 指纹规则库(只读展示):规则由 24h 上游自动同步维护(wappalyzergo/webanalyze/dddd
// 三源 + 快照兜底),本页提供搜索、来源分布与同步状态;fingerprint_scan 工具读这里。
export default function FingerprintPage() {
  const [rules, setRules] = React.useState<FingerprintRule[] | null>(null);
  const [sources, setSources] = React.useState<FingerprintSource[]>([]);
  const [enabled, setEnabled] = React.useState(0);
  const [total, setTotal] = React.useState(0);
  const [page, setPage] = React.useState(1);
  const [query, setQuery] = React.useState("");
  const [search, setSearch] = React.useState("");
  const [loading, setLoading] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.fingerprintRules({ query: search, page });
      setRules(res.rules);
      setTotal(res.total);
      setEnabled(res.enabled);
      setSources(res.sources);
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    } finally {
      setLoading(false);
    }
  }, [search, page]);

  React.useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">指纹规则库</h1>
        <p className="text-muted-foreground mt-1 text-sm">
          Web 指纹规则(启用 {enabled} 条)。规则由上游自动同步(24h 周期,失败走内置快照兜底),无需手工维护;
          fingerprint_scan 工具与 enrich 指纹链路读这里。
        </p>
      </div>

      {sources.length > 0 ? (
        <div className="grid gap-4 md:grid-cols-3">
          {sources.map((s) => (
            <Card key={s.name}>
              <CardContent className="space-y-1">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <FingerprintIcon className="text-muted-foreground size-4" />
                    <span className="font-medium">{s.name}</span>
                  </div>
                  <Badge variant="outline">{s.rule_count} 条</Badge>
                </div>
                <p className="text-muted-foreground truncate text-xs">
                  {s.fetched_at ? `最近同步 ${new Date(s.fetched_at).toLocaleString()}` : "尚未同步"}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : null}

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
                    <th className="px-4 py-2 font-medium">来源</th>
                    <th className="px-4 py-2 font-medium">状态</th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map((r) => (
                    <tr key={r.id} className="border-b last:border-0">
                      <td className="px-4 py-2 font-medium">{r.name}</td>
                      <td className="text-muted-foreground px-4 py-2">{r.category || "-"}</td>
                      <td className="max-w-96 truncate px-4 py-2 font-mono text-xs">{r.expression}</td>
                      <td className="px-4 py-2">
                        <Badge variant="outline">{r.source}</Badge>
                      </td>
                      <td className="px-4 py-2">
                        {r.enabled ? <Badge variant="default">启用</Badge> : <Badge variant="outline">停用</Badge>}
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
