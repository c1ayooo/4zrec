"use client";

import * as React from "react";

import {
  BookOpenTextIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  Loader2Icon,
  RefreshCwIcon,
  RssIcon,
  SearchIcon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { VulnIntelEntry, VulnIntelPOC, VulnIntelStatus, VulnKBEntry, VulnKBStats } from "@/lib/types";

const PAGE_SIZES = [25, 50, 100];
const FP_MAX_LEN = 48;

// severityTone 按漏洞类型给徽章配色:高危语义类偏红,注入类偏琥珀,其余中性。
function typeTone(v: string): string {
  if (/rce|命令|代码执行/i.test(v)) return "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400";
  if (/注入|sql|inject|上传|deserial|反序列/i.test(v))
    return "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400";
  if (/绕过|未授权|泄露|信息泄露/i.test(v))
    return "border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-400";
  return "";
}

function intelTone(v: string): string {
  if (v.includes("严重") || v.includes("critical")) return "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400";
  if (v.includes("高危") || v.includes("high")) return "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400";
  if (v.includes("中危") || v.includes("medium")) return "border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-400";
  return "";
}

function truncate(s: string, maxLen: number): string {
  const first = s.split("\n")[0];
  if (first.length <= maxLen) return first;
  return first.slice(0, maxLen) + "…";
}

function verdictTone(v: string): string {
  if (v === "act") return "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400";
  if (v === "watch") return "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400";
  return "";
}

function parseJSONPOC(s: string): VulnIntelPOC[] {
  try {
    const v = JSON.parse(s);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

function parseJSONArr(s: string): string[] {
  try {
    const v = JSON.parse(s);
    return Array.isArray(v) ? v.filter((x) => typeof x === "string") : [];
  } catch {
    return [];
  }
}

// FieldRow 是详情 Sheet 里的一行结构化字段。
function FieldRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  if (!value) return null;
  return (
    <div className="grid gap-1">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      <pre
        className={
          mono
            ? "max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-md border bg-muted/50 p-2 font-mono text-xs"
            : "whitespace-pre-wrap break-all text-sm"
        }
      >
        {value}
      </pre>
    </div>
  );
}

export default function VulnKbPage() {
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <BookOpenTextIcon className="size-5 text-muted-foreground" />
        <h1 className="text-lg font-semibold">漏洞库</h1>
      </div>
      <Tabs defaultValue="kb">
        <TabsList>
          <TabsTrigger value="kb">1day 库</TabsTrigger>
          <TabsTrigger value="intel">情报流</TabsTrigger>
        </TabsList>
        <TabsContent value="kb">
          <KBTab />
        </TabsContent>
        <TabsContent value="intel">
          <IntelTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function KBTab() {
  const [page, setPage] = React.useState(0);
  const [size, setSize] = React.useState(50);
  // 初始查询串支持 ?q= 预填(资产页技术徽章联动入口)。
  const [query, setQuery] = React.useState(() => {
    if (typeof window === "undefined") return "";
    return new URLSearchParams(window.location.search).get("q") ?? "";
  });
  const [queryQ, setQueryQ] = React.useState(() => {
    if (typeof window === "undefined") return "";
    const q = new URLSearchParams(window.location.search).get("q") ?? "";
    return q.trim();
  });
  const [typeFilter, setTypeFilter] = React.useState("");

  const [entries, setEntries] = React.useState<VulnKBEntry[]>([]);
  const [total, setTotal] = React.useState(0);
  const [stats, setStats] = React.useState<VulnKBStats | null>(null);
  const [loading, setLoading] = React.useState(false);

  const [selected, setSelected] = React.useState<VulnKBEntry | null>(null);
  const [detail, setDetail] = React.useState<VulnKBEntry | null>(null);
  const [detailLoading, setDetailLoading] = React.useState(false);

  React.useEffect(() => {
    const t = setTimeout(() => setQueryQ(query.trim()), 300);
    return () => clearTimeout(t);
  }, [query]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: filter change resets pagination.
  React.useEffect(() => {
    setPage(0);
  }, [queryQ, typeFilter]);

  React.useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api
      .vulnKb({ q: queryQ, type: typeFilter, page, size })
      .then((r) => {
        if (cancelled) return;
        setEntries(r.entries ?? []);
        setTotal(r.total ?? 0);
      })
      .catch(() => {
        if (!cancelled) setEntries([]);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [queryQ, typeFilter, page, size]);

  React.useEffect(() => {
    api
      .vulnKbStats()
      .then((r) => setStats(r.stats))
      .catch(() => setStats(null));
  }, []);

  React.useEffect(() => {
    if (!selected) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    setDetailLoading(true);
    api
      .vulnKbEntry(selected.id)
      .then((r) => {
        if (!cancelled) setDetail(r.entry);
      })
      .catch(() => {
        if (!cancelled) setDetail(null);
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selected]);

  const totalPages = Math.max(1, Math.ceil(total / size));

  return (
    <div className="space-y-4">
      {stats && (
        <p className="text-xs text-muted-foreground">
          {stats.total.toLocaleString()} 条 · {stats.products.toLocaleString()} 产品 ·{" "}
          {stats.with_fingerprint.toLocaleString()} 带指纹
        </p>
      )}

      <Card className="p-4">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
          <div className="relative flex-1">
            <SearchIcon className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="搜索标题 / 产品 / CVE / 指纹表达式…"
              className="pl-8"
            />
          </div>
          <Select value={typeFilter || "all"} onValueChange={(v) => setTypeFilter(v === "all" ? "" : v)}>
            <SelectTrigger className="w-full sm:w-44">
              <SelectValue placeholder="漏洞类型" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部类型</SelectItem>
              {(stats?.types ?? []).map((t) => (
                <SelectItem key={t.name} value={t.name}>
                  {t.name}（{t.count}）
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </Card>

      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[26%]">漏洞</TableHead>
              <TableHead className="w-[18%]">产品</TableHead>
              <TableHead className="w-[13%]">类型</TableHead>
              <TableHead className="w-[12%]">CVE</TableHead>
              <TableHead>指纹</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={5} className="h-32 text-center text-muted-foreground">
                  <Loader2Icon className="mr-2 inline size-4 animate-spin" />
                  加载中…
                </TableCell>
              </TableRow>
            ) : entries.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="h-32 text-center text-muted-foreground">
                  {total === 0 && !queryQ && !typeFilter
                    ? "漏洞库为空——把 1day 库目录(vulnkb/)放到服务目录后重启即可自动导入"
                    : "无匹配记录"}
                </TableCell>
              </TableRow>
            ) : (
              entries.map((e) => (
                <TableRow key={e.id} className="cursor-pointer" onClick={() => setSelected(e)}>
                  <TableCell className="max-w-0 truncate font-medium" title={e.title}>
                    {truncate(e.title, 40)}
                  </TableCell>
                  <TableCell className="max-w-0 truncate text-muted-foreground" title={e.product}>
                    {truncate(e.product, 24)}
                  </TableCell>
                  <TableCell>
                    {e.vuln_type ? (
                      <Badge variant="outline" className={typeTone(e.vuln_type)}>
                        {e.vuln_type}
                      </Badge>
                    ) : null}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{e.cve || "—"}</TableCell>
                  <TableCell className="max-w-0 truncate font-mono text-xs text-muted-foreground" title={e.fingerprint}>
                    {e.fingerprint ? truncate(e.fingerprint, FP_MAX_LEN) : "—"}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </Card>

      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">
          共 {total.toLocaleString()} 条 · 第 {page + 1}/{totalPages} 页
        </span>
        <div className="flex items-center gap-2">
          <Select
            value={String(size)}
            onValueChange={(v) => {
              setSize(Number(v));
              setPage(0);
            }}
          >
            <SelectTrigger className="h-8 w-20">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PAGE_SIZES.map((s) => (
                <SelectItem key={s} value={String(s)}>
                  {s} 条/页
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" size="icon" className="size-8" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
            <ChevronLeftIcon className="size-4" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="size-8"
            disabled={page + 1 >= totalPages}
            onClick={() => setPage((p) => p + 1)}
          >
            <ChevronRightIcon className="size-4" />
          </Button>
        </div>
      </div>

      <Sheet open={selected !== null} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent className="flex w-full flex-col gap-0 overflow-hidden sm:max-w-xl">
          <SheetHeader className="border-b px-6 py-4">
            <SheetTitle className="text-left text-base leading-snug">{selected?.title}</SheetTitle>
            <SheetDescription className="text-left">
              {[selected?.product, selected?.vuln_type, selected?.cve || null].filter(Boolean).join(" · ")}
            </SheetDescription>
          </SheetHeader>
          <div className="flex-1 space-y-4 overflow-y-auto px-6 py-4">
            {detailLoading ? (
              <div className="flex justify-center py-8">
                <Loader2Icon className="size-5 animate-spin text-muted-foreground" />
              </div>
            ) : detail ? (
              <>
                <FieldRow label="指纹" value={detail.fingerprint} mono />
                <FieldRow label="请求" value={detail.request_line} mono />
                <FieldRow label="关键头" value={detail.headers} mono />
                <FieldRow label="Payload" value={detail.payload} mono />
                <FieldRow label="响应特征" value={detail.response_sig} mono />
                <FieldRow label="预期" value={detail.expected} />
                <FieldRow label="原始文档" value={detail.body ?? ""} mono />
                <p className="text-right font-mono text-[10px] text-muted-foreground">{detail.source_path}</p>
              </>
            ) : (
              <p className="py-8 text-center text-sm text-muted-foreground">加载失败</p>
            )}
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}

function IntelTab() {
  const [page, setPage] = React.useState(0);
  const [size, setSize] = React.useState(50);
  const [query, setQuery] = React.useState("");
  const [queryQ, setQueryQ] = React.useState("");
  const [sevFilter, setSevFilter] = React.useState("");

  const [entries, setEntries] = React.useState<VulnIntelEntry[]>([]);
  const [total, setTotal] = React.useState(0);
  const [status, setStatus] = React.useState<VulnIntelStatus | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [refreshing, setRefreshing] = React.useState(false);

  const [selected, setSelected] = React.useState<VulnIntelEntry | null>(null);

  React.useEffect(() => {
    const t = setTimeout(() => setQueryQ(query.trim()), 300);
    return () => clearTimeout(t);
  }, [query]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: filter change resets pagination.
  React.useEffect(() => {
    setPage(0);
  }, [queryQ, sevFilter]);

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .vulnIntel({ q: queryQ, severity: sevFilter, page, size })
      .then((r) => {
        setEntries(r.entries ?? []);
        setTotal(r.total ?? 0);
      })
      .catch(() => setEntries([]))
      .finally(() => setLoading(false));
  }, [queryQ, sevFilter, page, size]);

  React.useEffect(() => {
    load();
  }, [load]);

  React.useEffect(() => {
    api
      .vulnIntelStatus()
      .then((r) => setStatus(r))
      .catch(() => setStatus(null));
  }, []);

  const totalPages = Math.max(1, Math.ceil(total / size));

  const refresh = async () => {
    setRefreshing(true);
    try {
      await api.vulnIntelRefresh();
      // 轮询在后台跑,几秒后拉一次结果。
      setTimeout(() => {
        load();
        api
          .vulnIntelStatus()
          .then((r) => setStatus(r))
          .catch(() => {});
      }, 8000);
    } catch {
      /* 失败静默,状态区会体现 */
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <RssIcon className="size-3.5" />
          {status
            ? `${status.sources} 个公开源自动轮询${status.result?.New !== undefined ? ` · 上轮新增 ${status.result.New}` : ""}`
            : "9 个公开情报源自动轮询"}
        </p>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={refresh} disabled={refreshing}>
            {refreshing ? <Loader2Icon className="mr-1 size-4 animate-spin" /> : <RefreshCwIcon className="mr-1 size-4" />}
            立即抓取
          </Button>
        </div>
      </div>

      <Card className="p-4">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
          <div className="relative flex-1">
            <SearchIcon className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="搜索标题 / CVE / 来源…"
              className="pl-8"
            />
          </div>
          <Select value={sevFilter || "all"} onValueChange={(v) => setSevFilter(v === "all" ? "" : v)}>
            <SelectTrigger className="w-full sm:w-32">
              <SelectValue placeholder="等级" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部等级</SelectItem>
              <SelectItem value="严重">严重</SelectItem>
              <SelectItem value="高危">高危</SelectItem>
              <SelectItem value="中危">中危</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </Card>

      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[10%]">等级</TableHead>
              <TableHead>标题</TableHead>
              <TableHead className="w-[13%]">CVE</TableHead>
              <TableHead className="w-[14%]">来源</TableHead>
              <TableHead className="w-[16%]">披露</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={5} className="h-32 text-center text-muted-foreground">
                  <Loader2Icon className="mr-2 inline size-4 animate-spin" />
                  加载中…
                </TableCell>
              </TableRow>
            ) : entries.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="h-32 text-center text-muted-foreground">
                  暂无情报——点「立即抓取」跑一轮,或等定时轮询(默认 30 分钟)
                </TableCell>
              </TableRow>
            ) : (
              entries.map((e) => (
                <TableRow key={e.id} className="cursor-pointer" onClick={() => setSelected(e)}>
                  <TableCell>
                    {e.severity ? (
                      <Badge variant="outline" className={intelTone(e.severity)}>
                        {e.severity}
                      </Badge>
                    ) : null}
                  </TableCell>
                  <TableCell className="max-w-0 truncate font-medium" title={e.title}>
                    {truncate(e.title, 56)}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{e.cve || "—"}</TableCell>
                  <TableCell className="max-w-0 truncate text-muted-foreground">{e.source}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{e.disclosure || "—"}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </Card>

      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">
          共 {total.toLocaleString()} 条 · 第 {page + 1}/{totalPages} 页
        </span>
        <div className="flex items-center gap-2">
          <Select
            value={String(size)}
            onValueChange={(v) => {
              setSize(Number(v));
              setPage(0);
            }}
          >
            <SelectTrigger className="h-8 w-20">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PAGE_SIZES.map((s) => (
                <SelectItem key={s} value={String(s)}>
                  {s} 条/页
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" size="icon" className="size-8" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
            <ChevronLeftIcon className="size-4" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="size-8"
            disabled={page + 1 >= totalPages}
            onClick={() => setPage((p) => p + 1)}
          >
            <ChevronRightIcon className="size-4" />
          </Button>
        </div>
      </div>

      <Sheet open={selected !== null} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent className="flex w-full flex-col gap-0 overflow-hidden sm:max-w-xl">
          <SheetHeader className="border-b px-6 py-4">
            <SheetTitle className="text-left text-base leading-snug">{selected?.title}</SheetTitle>
            <SheetDescription className="text-left">
              {[selected?.severity, selected?.cve || null, selected?.source].filter(Boolean).join(" · ")}
            </SheetDescription>
          </SheetHeader>
          <div className="flex-1 space-y-4 overflow-y-auto px-6 py-4">
            {selected ? (
              <>
                <FieldRow label="描述" value={selected.description ?? ""} />
                <FieldRow label="处置建议" value={selected.solutions ?? ""} />
                <FieldRow label="披露时间" value={selected.disclosure} />
                {selected.cvss_score ? (
                  <FieldRow
                    label={`CVSS ${selected.cvss_score.toFixed(1)}`}
                    value={selected.cvss_vector || "—"}
                    mono
                  />
                ) : null}
                {parseJSONArr(selected.affected).length > 0 ? (
                  <div className="grid gap-1">
                    <span className="text-xs font-medium text-muted-foreground">受影响包</span>
                    <div className="flex flex-wrap gap-1">
                      {parseJSONArr(selected.affected).map((a, i) => (
                        <Badge key={i} variant="outline" className="font-mono text-[10px]">
                          {a}
                        </Badge>
                      ))}
                    </div>
                  </div>
                ) : null}
                {selected.lab_only ? (
                  <Badge variant="outline" className="border-muted-foreground/30 text-muted-foreground">
                    仅实验室(无可实际利用 PoC)
                  </Badge>
                ) : null}
                {parseJSONPOC(selected.github_poc).length > 0 ? (
                  <div className="grid gap-1.5">
                    <span className="text-xs font-medium text-muted-foreground">
                      PoC 仓库({parseJSONPOC(selected.github_poc).length},经五档体检)
                    </span>
                    {parseJSONPOC(selected.github_poc).map((r) => (
                      <div key={r.full_name} className="rounded-md border p-2 text-xs">
                        <div className="flex items-center gap-2">
                          <a
                            href={r.url}
                            target="_blank"
                            rel="noreferrer"
                            className="font-mono font-medium text-primary underline-offset-4 hover:underline"
                          >
                            {r.full_name}
                          </a>
                          <span className="text-muted-foreground">★ {r.stars}</span>
                          {r.verdict ? (
                            <Badge variant="outline" className={verdictTone(r.verdict)}>
                              {r.verdict.toUpperCase()}
                            </Badge>
                          ) : null}
                        </div>
                        {r.description ? (
                          <p className="mt-1 line-clamp-2 text-muted-foreground">{r.description}</p>
                        ) : null}
                        {r.triage_reasons?.length ? (
                          <p className="mt-1 text-[10px] text-muted-foreground/70">{r.triage_reasons.join(" · ")}</p>
                        ) : null}
                      </div>
                    ))}
                  </div>
                ) : null}
                {selected.source_url ? (
                  <div className="grid gap-1">
                    <span className="text-xs font-medium text-muted-foreground">来源</span>
                    <a
                      href={selected.source_url}
                      target="_blank"
                      rel="noreferrer"
                      className="break-all text-sm text-primary underline-offset-4 hover:underline"
                    >
                      {selected.source_url}
                    </a>
                  </div>
                ) : null}
                {parseJSONArr(selected.refs).length > 0 ? (
                  <div className="grid gap-1">
                    <span className="text-xs font-medium text-muted-foreground">参考</span>
                    <ul className="space-y-1">
                      {parseJSONArr(selected.refs).map((r, i) => (
                        <li key={i} className="break-all text-xs">
                          <a href={r} target="_blank" rel="noreferrer" className="text-primary underline-offset-4 hover:underline">
                            {r}
                          </a>
                        </li>
                      ))}
                    </ul>
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
