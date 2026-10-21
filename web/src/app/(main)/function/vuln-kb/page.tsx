"use client";

import * as React from "react";

import {
  BookOpenTextIcon,
  CheckIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  FileCode2Icon,
  FingerprintIcon,
  Loader2Icon,
  RefreshCwIcon,
  RssIcon,
  SearchIcon,
  SparklesIcon,
  Trash2Icon,
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
import type {
  IntelAnalysis,
  VulnIntelEntry,
  VulnIntelPOC,
  VulnIntelStatus,
  VulnKBEntry,
  VulnLibraryEntry,
} from "@/lib/types";

import { IntelDraftsTab } from "./_components/intel-drafts-tab";
import { IntelPipelineTab } from "./_components/intel-pipeline-tab";

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
      <div className="flex items-start gap-2.5">
        <BookOpenTextIcon className="mt-0.5 size-5 text-muted-foreground" />
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">漏洞库</h1>
          <p className="text-muted-foreground mt-1 text-sm">1day 库与公开情报流，按来源、产品和 CVE 检索。</p>
        </div>
      </div>
      <Tabs defaultValue="library" className="space-y-4">
        <TabsList>
          <TabsTrigger value="library">漏洞列表</TabsTrigger>
          <TabsTrigger value="drafts">产物待确认</TabsTrigger>
          <TabsTrigger value="pipeline">流水线</TabsTrigger>
          <TabsTrigger value="history">调用历史</TabsTrigger>
        </TabsList>
        <TabsContent value="library">
          <LibraryTab />
        </TabsContent>
        <TabsContent value="drafts">
          <IntelDraftsTab />
        </TabsContent>
        <TabsContent value="pipeline">
          <IntelPipelineTab />
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
  // detailNonce 让详情重新拉取(分析/模板是后台任务,完成后要刷新)。
  const [detailNonce, setDetailNonce] = React.useState(0);
  const [analyzing, setAnalyzing] = React.useState(false);
  const [tplBusy, setTplBusy] = React.useState(false);
  const [actionError, setActionError] = React.useState("");

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

  // biome-ignore lint/correctness/useExhaustiveDependencies: detailNonce 是显式的重取信号，不在 effect 体内直接读取。
  React.useEffect(() => {
    if (!selected) {
      setKbDetail(null);
      setIntelDetail(null);
      return;
    }
    setActionError("");
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
  }, [selected, detailNonce]);

  const totalPages = Math.max(1, Math.ceil(total / size));

  // 分析是后台任务(LLM 调用可能几十秒),POST 只负责派发,轮询详情等结果。
  const runAnalyze = async () => {
    if (!selected || selected.source !== "intel") return;
    const id = selected.id;
    setAnalyzing(true);
    setActionError("");
    try {
      await api.vulnIntelAnalyze(id);
      for (let i = 0; i < 30; i++) {
        await new Promise((r) => setTimeout(r, 3000));
        const r = await api.vulnIntelEntry(id);
        if (r.entry?.analyzed_at || r.entry?.analysis_error) {
          setIntelDetail(r.entry);
          break;
        }
      }
      load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setAnalyzing(false);
    }
  };

  // 两步走:先出草稿,人工看过 YAML 再确认入库。
  const runDraft = async () => {
    if (!selected || selected.source !== "intel") return;
    const id = selected.id;
    setTplBusy(true);
    setActionError("");
    try {
      await api.vulnIntelNucleiDraft(id);
      setDetailNonce((n) => n + 1);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setTplBusy(false);
    }
  };

  const runConfirm = async () => {
    if (!selected || selected.source !== "intel") return;
    const id = selected.id;
    setTplBusy(true);
    setActionError("");
    try {
      await api.vulnIntelNucleiConfirm(id);
      setDetailNonce((n) => n + 1);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setTplBusy(false);
    }
  };

  const runDiscard = async () => {
    if (!selected || selected.source !== "intel") return;
    const id = selected.id;
    setTplBusy(true);
    setActionError("");
    try {
      await api.vulnIntelNucleiDiscard(id);
      setDetailNonce((n) => n + 1);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setTplBusy(false);
    }
  };

  const runFpDraft = async () => {
    if (!selected || selected.source !== "intel") return;
    const id = selected.id;
    setTplBusy(true);
    setActionError("");
    try {
      await api.vulnIntelFingerprintDraft(id);
      setDetailNonce((n) => n + 1);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setTplBusy(false);
    }
  };

  const runFpConfirm = async () => {
    if (!selected || selected.source !== "intel") return;
    const id = selected.id;
    setTplBusy(true);
    setActionError("");
    try {
      await api.vulnIntelFingerprintConfirm(id);
      setDetailNonce((n) => n + 1);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setTplBusy(false);
    }
  };

  const runFpDiscard = async () => {
    if (!selected || selected.source !== "intel") return;
    const id = selected.id;
    setTplBusy(true);
    setActionError("");
    try {
      await api.vulnIntelFingerprintDiscard(id);
      setDetailNonce((n) => n + 1);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setTplBusy(false);
    }
  };

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
          .catch(() => {
            // 状态条刷新失败不阻塞列表；保留上一次的轮询状态。
          });
      }, 8000);
    } catch {
      /* 失败静默,状态区会体现 */
    } finally {
      setRefreshing(false);
    }
  };

  const isIntel = selected?.source === "intel";
  const sourceCount = status?.sources ?? status?.result?.Sources;
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
            ? `${sourceCount && sourceCount > 0 ? `${sourceCount} 个公开源自动轮询` : "公开源自动轮询"}${status.result?.New !== undefined ? ` · 上轮新增 ${status.result.New}` : ""}`
            : "公开情报源自动轮询"}
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
        {loading ? (
          <div className="text-muted-foreground flex h-40 items-center justify-center gap-2 text-sm">
            <Loader2Icon className="size-4 animate-spin" />
            加载中…
          </div>
        ) : entries.length === 0 ? (
          <div className="px-6 py-10 text-center">
            <div className="mx-auto flex max-w-xl flex-col items-center gap-3">
              <p className="text-muted-foreground text-sm">
                {total === 0 && !queryQ && !source
                  ? "漏洞库为空——把 1day 库目录(vulnkb/)放到服务目录后重启，或立即抓取公开情报。"
                  : "没有匹配的记录，调整关键词或来源后再试。"}
              </p>
              {total === 0 && !queryQ && !source ? (
                <Button size="sm" variant="outline" onClick={refresh} disabled={refreshing}>
                  {refreshing ? <Loader2Icon className="size-4 animate-spin" /> : <RefreshCwIcon className="size-4" />}
                  立即抓取情报
                </Button>
              ) : null}
            </div>
          </div>
        ) : (
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
              {entries.map((e) => {
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
                      className="text-muted-foreground max-w-0 truncate font-mono text-xs"
                      title={intel ? e.disclosure : e.fingerprint}
                    >
                      {intel ? e.disclosure || "—" : e.fingerprint ? truncate(e.fingerprint, FP_MAX_LEN) : "—"}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
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
                <IntelDetail
                  entry={intelDetail}
                  analyzing={analyzing}
                  tplBusy={tplBusy}
                  actionError={actionError}
                  onAnalyze={runAnalyze}
                  onDraft={runDraft}
                  onConfirm={runConfirm}
                  onDiscard={runDiscard}
                  onFpDraft={runFpDraft}
                  onFpConfirm={runFpConfirm}
                  onFpDiscard={runFpDiscard}
                />
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
      <p className="text-right font-mono text-[11px] text-muted-foreground">{entry.source_path}</p>
    </>
  );
}

// pocOriginLabel 说明 PoC 的来源:模型生成 / 上游仓库(只有链接)/ 无。
// parseFpDraft 解析后端存的指纹草稿 JSON(展示用;解析不了就返回 null)。
function parseFpDraft(
  raw: string | undefined,
): { name: string; category: string; expression: string; reason?: string } | null {
  if (!raw) return null;
  try {
    const obj = JSON.parse(raw);
    if (obj && typeof obj === "object" && typeof obj.expression === "string") {
      return {
        name: String(obj.name ?? ""),
        category: String(obj.category ?? ""),
        expression: obj.expression,
        reason: obj.reason ? String(obj.reason) : undefined,
      };
    }
  } catch {
    return null;
  }
  return null;
}

function pocOriginLabel(origin: string): string {
  if (origin === "ai") return "AI 生成";
  if (origin === "upstream") return "上游仓库已有";
  return "无";
}

function IntelDetail({
  entry,
  analyzing,
  tplBusy,
  actionError,
  onAnalyze,
  onDraft,
  onConfirm,
  onDiscard,
  onFpDraft,
  onFpConfirm,
  onFpDiscard,
}: {
  entry: VulnIntelEntry;
  analyzing: boolean;
  tplBusy: boolean;
  actionError: string;
  onAnalyze: () => void;
  onDraft: () => void;
  onConfirm: () => void;
  onDiscard: () => void;
  onFpDraft: () => void;
  onFpConfirm: () => void;
  onFpDiscard: () => void;
}) {
  const a: IntelAnalysis | null | undefined = entry.analysis;
  const analyzed = Boolean(entry.analyzed_at);
  const confirmed = Boolean(entry.nuclei_tpl_id);
  const hasDraft = Boolean(a?.nuclei_template);
  const fpConfirmed = Boolean(entry.fingerprint_id);
  const hasFpDraft = Boolean(a?.fingerprint);
  const fpDraft = React.useMemo(() => parseFpDraft(a?.fingerprint), [a?.fingerprint]);

  return (
    <>
      {/* 流水线操作区:分析 → 出模板草稿 → 人工确认入库。 */}
      <div className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/30 p-2.5">
        <Button size="sm" variant="outline" onClick={onAnalyze} disabled={analyzing}>
          {analyzing ? (
            <Loader2Icon className="mr-1 size-3.5 animate-spin" />
          ) : (
            <SparklesIcon className="mr-1 size-3.5" />
          )}
          {analyzing ? "分析中…" : analyzed ? "重新分析" : "AI 分析"}
        </Button>
        <Button size="sm" variant="outline" onClick={onDraft} disabled={tplBusy}>
          {tplBusy ? (
            <Loader2Icon className="mr-1 size-3.5 animate-spin" />
          ) : (
            <FileCode2Icon className="mr-1 size-3.5" />
          )}
          {hasDraft && !confirmed ? "重新生成模板草稿" : "生成模板草稿"}
        </Button>
        {hasDraft && !confirmed ? (
          <>
            <Button size="sm" onClick={onConfirm} disabled={tplBusy}>
              <CheckIcon className="mr-1 size-3.5" />
              确认入库
            </Button>
            <Button size="sm" variant="ghost" onClick={onDiscard} disabled={tplBusy}>
              <Trash2Icon className="mr-1 size-3.5" />
              丢弃草稿
            </Button>
          </>
        ) : null}
        <Button size="sm" variant="outline" onClick={onFpDraft} disabled={tplBusy}>
          {tplBusy ? (
            <Loader2Icon className="mr-1 size-3.5 animate-spin" />
          ) : (
            <FingerprintIcon className="mr-1 size-3.5" />
          )}
          {hasFpDraft && !fpConfirmed ? "重新生成指纹草稿" : "生成指纹草稿"}
        </Button>
        {hasFpDraft && !fpConfirmed ? (
          <>
            <Button size="sm" onClick={onFpConfirm} disabled={tplBusy}>
              <CheckIcon className="mr-1 size-3.5" />
              指纹入库
            </Button>
            <Button size="sm" variant="ghost" onClick={onFpDiscard} disabled={tplBusy}>
              <Trash2Icon className="mr-1 size-3.5" />
              丢弃
            </Button>
          </>
        ) : null}
        <span className="text-[11px] text-muted-foreground">
          {analyzed ? `已分析${a?.model ? ` · ${a.model}` : ""}` : "尚未分析"}
        </span>
      </div>

      {actionError ? (
        <p className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive">
          {actionError}
        </p>
      ) : null}
      {entry.analysis_error ? (
        <p className="rounded-md border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-600 dark:text-amber-400">
          上次分析失败：{entry.analysis_error}（下一轮会自动重试，也可点上方按钮立即重试）
        </p>
      ) : null}

      {entry.title_zh && entry.title_zh !== entry.title ? <FieldRow label="原文标题" value={entry.title} /> : null}

      {a?.description_zh || a?.principle || a?.attack_scope ? (
        <>
          <FieldRow label="中文简介" value={a?.description_zh ?? ""} />
          <FieldRow label="漏洞原理" value={a?.principle ?? ""} />
          <FieldRow label="攻击范围" value={a?.attack_scope ?? ""} />
        </>
      ) : null}

      {a?.poc_code ? (
        <div className="grid gap-1">
          <span className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
            验证 PoC
            <Badge variant="outline" className="text-[11px]">
              {a.poc_lang || "python"} · {pocOriginLabel(a.poc_origin)}
            </Badge>
          </span>
          <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-md border bg-muted/50 p-2 font-mono text-xs">
            {a.poc_code}
          </pre>
          {a.poc_note ? <p className="text-[11px] text-amber-600 dark:text-amber-400">{a.poc_note}</p> : null}
        </div>
      ) : a && a.poc_origin === "upstream" ? (
        <p className="text-xs text-muted-foreground">上游仓库已有 PoC（见下方仓库列表），未另行生成代码。</p>
      ) : a?.poc_note ? (
        <p className="text-xs text-muted-foreground">
          未生成 PoC：{a.poc_note}（情报没有给出可核验的入口/参数时不会硬凑脚本）
        </p>
      ) : null}

      {hasDraft || confirmed ? (
        <div className="grid gap-1">
          <span className="flex flex-wrap items-center gap-2 text-xs font-medium text-muted-foreground">
            {confirmed ? "nuclei 模板（已入库）" : "nuclei 模板草稿（待确认）"}
            {confirmed ? (
              <Badge variant="outline" className="font-mono text-[11px]">
                {entry.nuclei_tpl_id}
              </Badge>
            ) : (
              <Badge className="bg-amber-500/15 text-[11px] text-amber-600 dark:text-amber-400">未写入模板库</Badge>
            )}
          </span>
          {a?.nuclei_template ? (
            <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-md border bg-muted/50 p-2 font-mono text-xs">
              {a.nuclei_template}
            </pre>
          ) : null}
        </div>
      ) : null}

      {hasFpDraft || fpConfirmed ? (
        <div className="grid gap-1">
          <span className="flex flex-wrap items-center gap-2 text-xs font-medium text-muted-foreground">
            {fpConfirmed ? "资产指纹（已入库）" : "资产指纹草稿（待确认）"}
            {fpConfirmed ? (
              <Badge variant="outline" className="font-mono text-[11px]">
                {entry.fingerprint_id}
              </Badge>
            ) : (
              <Badge className="bg-amber-500/15 text-[11px] text-amber-600 dark:text-amber-400">未写入指纹库</Badge>
            )}
          </span>
          {fpDraft ? (
            <>
              <FieldRow label="规则名" value={fpDraft.name} />
              <FieldRow label="分类" value={fpDraft.category} mono />
              <FieldRow label="匹配表达式" value={fpDraft.expression} mono />
              {fpDraft.reason ? <FieldRow label="判定依据" value={fpDraft.reason} /> : null}
            </>
          ) : null}
        </div>
      ) : null}

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
              <Badge key={i} variant="outline" className="font-mono text-[11px]">
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
                <p className="mt-1 text-[11px] text-muted-foreground/70">{r.triage_reasons.join(" · ")}</p>
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
