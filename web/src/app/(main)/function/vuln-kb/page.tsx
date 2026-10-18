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

import { FeatureCallHistory } from "@/components/feature-call-history";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { VulnIntelEntry, VulnIntelPOC, VulnIntelStatus, VulnKBEntry, VulnLibraryEntry } from "@/lib/types";

const PAGE_SIZES = [25, 50, 100];
const FP_MAX_LEN = 48;

// typeTone 按漏洞类型给徽章配色:高危语义类偏红,注入类偏琥珀,其余中性。
function typeTone(v: string): string {
  if (/rce|命令|代码执行/i.test(v)) return "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400";
  if (/注入|sql|inject|上传|deserial|反序列/i.test(v))
    return "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400";
  if (/绕过|未授权|泄露|信息泄露/i.test(v)) return "border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-400";
  return "";
}

function intelTone(v: string): string {
  if (v.includes("严重") || v.includes("critical"))
    return "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400";
  if (v.includes("高危") || v.includes("high"))
    return "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400";
  if (v.includes("中危") || v.includes("medium"))
    return "border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-400";
  return "";
}

function sourceTone(source: string): string {
  if (source === "intel") return "border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-400";
  return "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400";
}

function sourceLabel(source: string): string {
  return source === "intel" ? "情报流" : "1day 库";
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
      <Tabs defaultValue="library" className="space-y-4">
        <TabsList>
          <TabsTrigger value="library">漏洞列表</TabsTrigger>
          <TabsTrigger value="history">调用历史</TabsTrigger>
        </TabsList>
        <TabsContent value="library">
          <LibraryTab />
        </TabsContent>
        <TabsContent value="history">
          <FeatureCallHistory feature="vulnkb" />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function LibraryTab() {
  const [page, setPage] = React.useState(0);
  const [size, setSize] = React.useState(50);
  // 初始查询串支持 ?q= 预填(资产页技术徽章联动入口)。
  const [query, setQuery] = React.useState(() => {
    if (typeof window === "undefined") return "";
    return new URLSearchParams(window.location.search).get("q") ?? "";
  });
  const [queryQ, setQueryQ] = React.useState(() => {
    if (typeof window === "undefined") return "";
    return (new URLSearchParams(window.location.search).get("q") ?? "").trim();
  });
  const [source, setSource] = React.useState("");

  const [entries, setEntries] = React.useState<VulnLibraryEntry[]>([]);
  const [total, setTotal] = React.useState(0);
  const [status, setStatus] = React.useState<VulnIntelStatus | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [refreshing, setRefreshing] = React.useState(false);

  const [selected, setSelected] = React.useState<VulnLibraryEntry | null>(null);
  const [kbDetail, setKbDetail] = React.useState<VulnKBEntry | null>(null);
  const [intelDetail, setIntelDetail] = React.useState<VulnIntelEntry | null>(null);
  const [detailLoading, setDetailLoading] = React.useState(false);

  React.useEffect(() => {
    const t = setTimeout(() => setQueryQ(query.trim()), 300);
    return () => clearTimeout(t);
  }, [query]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: filter change resets pagination.
  React.useEffect(() => {
    setPage(0);
  }, [queryQ, source]);

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .vulnLibrary({ q: queryQ, source, page, size })
      .then((r) => {
        setEntries(r.entries ?? []);
        setTotal(r.total ?? 0);
      })
      .catch(() => setEntries([]))
      .finally(() => setLoading(false));
  }, [queryQ, source, page, size]);

  React.useEffect(() => {
    load();
  }, [load]);

  React.useEffect(() => {
    api
      .vulnIntelStatus()
      .then((r) => setStatus(r))
      .catch(() => setStatus(null));
  }, []);

  React.useEffect(() => {
    if (!selected) {
      setKbDetail(null);
      setIntelDetail(null);
      return;
    }
    let cancelled = false;
    setKbDetail(null);
    setIntelDetail(null);
    setDetailLoading(true);
    const req =
      selected.source === "intel"
        ? api.vulnIntelEntry(selected.id).then((r) => {
            if (!cancelled) setIntelDetail(r.entry);
          })
        : api.vulnKbEntry(selected.id).then((r) => {
            if (!cancelled) setKbDetail(r.entry);
          });
    req
      .catch(() => {
        if (!cancelled) {
          setKbDetail(null);
          setIntelDetail(null);
        }
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selected]);

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

  const isIntel = selected?.source === "intel";
  const detailBits = isIntel
    ? [
        intelDetail?.severity ?? selected?.severity,
        intelDetail?.cve ?? selected?.cve,
        intelDetail?.source ?? selected?.source_name,
      ]
    : [
        kbDetail?.product ?? selected?.product,
        kbDetail?.vuln_type ?? selected?.vuln_type,
        kbDetail?.cve ?? selected?.cve,
      ];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <RssIcon className="size-3.5" />
          {status
            ? `${status.sources} 个公开源自动轮询${status.result?.New !== undefined ? ` · 上轮新增 ${status.result.New}` : ""}`
            : "9 个公开情报源自动轮询"}
        </p>
        <Button variant="outline" size="sm" onClick={refresh} disabled={refreshing}>
          {refreshing ? (
            <Loader2Icon className="mr-1 size-4 animate-spin" />
          ) : (
            <RefreshCwIcon className="mr-1 size-4" />
          )}
          立即抓取情报
        </Button>
      </div>

      <Card className="p-4">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
          <div className="relative flex-1">
            <SearchIcon className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="搜索标题 / 产品 / CVE / 指纹 / 来源…"
              className="pl-8"
            />
          </div>
          <Select value={source || "all"} onValueChange={(v) => setSource(v === "all" ? "" : v)}>
            <SelectTrigger className="w-full sm:w-40">
              <SelectValue placeholder="来源" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部来源</SelectItem>
              <SelectItem value="1day">1day 库</SelectItem>
              <SelectItem value="intel">情报流</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </Card>

      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[9%]">来源</TableHead>
              <TableHead>漏洞</TableHead>
              <TableHead className="w-[16%]">产品 / 等级</TableHead>
              <TableHead className="w-[16%]">类型 / 来源</TableHead>
              <TableHead className="w-[12%]">CVE</TableHead>
              <TableHead className="w-[18%]">指纹 / 披露</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={6} className="h-32 text-center text-muted-foreground">
                  <Loader2Icon className="mr-2 inline size-4 animate-spin" />
                  加载中…
                </TableCell>
              </TableRow>
            ) : entries.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="h-32 text-center text-muted-foreground">
                  {total === 0 && !queryQ && !source
                    ? "漏洞库为空——把 1day 库目录(vulnkb/)放到服务目录后重启，或点「立即抓取情报」拉取情报"
                    : "无匹配记录"}
                </TableCell>
              </TableRow>
            ) : (
              entries.map((e) => {
                const intel = e.source === "intel";
                return (
                  <TableRow key={`${e.source}-${e.id}`} className="cursor-pointer" onClick={() => setSelected(e)}>
                    <TableCell>
                      <Badge variant="outline" className={sourceTone(e.source)}>
                        {sourceLabel(e.source)}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-0 truncate font-medium" title={e.title}>
                      {truncate(e.title, 48)}
                    </TableCell>
                    <TableCell>
                      {intel ? (
                        e.severity ? (
                          <Badge variant="outline" className={intelTone(e.severity)}>
                            {e.severity}
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )
                      ) : (
                        <span className="text-muted-foreground">{truncate(e.product || "—", 24)}</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {intel ? (
                        <span className="text-muted-foreground">{truncate(e.source_name || "—", 20)}</span>
                      ) : e.vuln_type ? (
                        <Badge variant="outline" className={typeTone(e.vuln_type)}>
                          {e.vuln_type}
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{e.cve || "—"}</TableCell>
                    <TableCell
                      className="max-w-0 truncate font-mono text-xs text-muted-foreground"
                      title={intel ? e.disclosure : e.fingerprint}
                    >
                      {intel ? e.disclosure || "—" : e.fingerprint ? truncate(e.fingerprint, FP_MAX_LEN) : "—"}
                    </TableCell>
                  </TableRow>
                );
              })
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
          <Button
            variant="outline"
            size="icon"
            className="size-8"
            disabled={page === 0}
            onClick={() => setPage((p) => p - 1)}
          >
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
            <SheetDescription className="text-left">{detailBits.filter(Boolean).join(" · ")}</SheetDescription>
          </SheetHeader>
          <div className="flex-1 space-y-4 overflow-y-auto px-6 py-4">
            {detailLoading ? (
              <div className="flex justify-center py-8">
                <Loader2Icon className="size-5 animate-spin text-muted-foreground" />
              </div>
            ) : isIntel ? (
              intelDetail ? (
                <IntelDetail entry={intelDetail} />
              ) : (
                <p className="py-8 text-center text-sm text-muted-foreground">加载失败</p>
              )
            ) : kbDetail ? (
              <KbDetail entry={kbDetail} />
            ) : (
              <p className="py-8 text-center text-sm text-muted-foreground">加载失败</p>
            )}
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}

function KbDetail({ entry }: { entry: VulnKBEntry }) {
  return (
    <>
      <FieldRow label="指纹" value={entry.fingerprint} mono />
      <FieldRow label="请求" value={entry.request_line} mono />
      <FieldRow label="关键头" value={entry.headers} mono />
      <FieldRow label="Payload" value={entry.payload} mono />
      <FieldRow label="响应特征" value={entry.response_sig} mono />
      <FieldRow label="预期" value={entry.expected} />
      <FieldRow label="原始文档" value={entry.body ?? ""} mono />
      <p className="text-right font-mono text-[10px] text-muted-foreground">{entry.source_path}</p>
    </>
  );
}

function IntelDetail({ entry }: { entry: VulnIntelEntry }) {
  return (
    <>
      <FieldRow label="描述" value={entry.description ?? ""} />
      <FieldRow label="处置建议" value={entry.solutions ?? ""} />
      <FieldRow label="披露时间" value={entry.disclosure} />
      {entry.cvss_score ? (
        <FieldRow label={`CVSS ${entry.cvss_score.toFixed(1)}`} value={entry.cvss_vector || "—"} mono />
      ) : null}
      {parseJSONArr(entry.affected).length > 0 ? (
        <div className="grid gap-1">
          <span className="text-xs font-medium text-muted-foreground">受影响包</span>
          <div className="flex flex-wrap gap-1">
            {parseJSONArr(entry.affected).map((a, i) => (
              <Badge key={i} variant="outline" className="font-mono text-[10px]">
                {a}
              </Badge>
            ))}
          </div>
        </div>
      ) : null}
      {entry.lab_only ? (
        <Badge variant="outline" className="border-muted-foreground/30 text-muted-foreground">
          仅实验室(无可实际利用 PoC)
        </Badge>
      ) : null}
      {parseJSONPOC(entry.github_poc).length > 0 ? (
        <div className="grid gap-1.5">
          <span className="text-xs font-medium text-muted-foreground">
            PoC 仓库({parseJSONPOC(entry.github_poc).length},经五档体检)
          </span>
          {parseJSONPOC(entry.github_poc).map((r) => (
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
              {r.description ? <p className="mt-1 line-clamp-2 text-muted-foreground">{r.description}</p> : null}
              {r.triage_reasons?.length ? (
                <p className="mt-1 text-[10px] text-muted-foreground/70">{r.triage_reasons.join(" · ")}</p>
              ) : null}
            </div>
          ))}
        </div>
      ) : null}
      {entry.source_url ? (
        <div className="grid gap-1">
          <span className="text-xs font-medium text-muted-foreground">来源</span>
          <a
            href={entry.source_url}
            target="_blank"
            rel="noreferrer"
            className="break-all text-sm text-primary underline-offset-4 hover:underline"
          >
            {entry.source_url}
          </a>
        </div>
      ) : null}
      {parseJSONArr(entry.refs).length > 0 ? (
        <div className="grid gap-1">
          <span className="text-xs font-medium text-muted-foreground">参考</span>
          <ul className="space-y-1">
            {parseJSONArr(entry.refs).map((r, i) => (
              <li key={i} className="break-all text-xs">
                <a
                  href={r}
                  target="_blank"
                  rel="noreferrer"
                  className="text-primary underline-offset-4 hover:underline"
                >
                  {r}
                </a>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </>
  );
}
