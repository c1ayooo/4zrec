"use client";

import * as React from "react";

import {
  BookOpenTextIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  Loader2Icon,
  SearchIcon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { VulnKBEntry, VulnKBStats } from "@/lib/types";

const PAGE_SIZES = [25, 50, 100];
const FP_MAX_LEN = 48;

// severityTone 按漏洞类型给徽章配色:高危语义类偏红,注入类偏琥珀,其余中性。
function typeTone(v: string): string {
  if (/rce|命令|代码执行/i.test(v)) return "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400";
  if (/注入|sql|inject|上传|deserial|反序列/i.test(v))
    return "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400";
  if (/绕过|未授权|泄露|泄露|信息泄露/i.test(v))
    return "border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-400";
  return "";
}

function truncate(s: string, maxLen: number): string {
  const first = s.split("\n")[0];
  if (first.length <= maxLen) return first;
  return first.slice(0, maxLen) + "…";
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
  const [page, setPage] = React.useState(0);
  const [size, setSize] = React.useState(50);
  const [query, setQuery] = React.useState("");
  const [queryQ, setQueryQ] = React.useState("");
  const [typeFilter, setTypeFilter] = React.useState("");

  const [entries, setEntries] = React.useState<VulnKBEntry[]>([]);
  const [total, setTotal] = React.useState(0);
  const [stats, setStats] = React.useState<VulnKBStats | null>(null);
  const [loading, setLoading] = React.useState(false);

  const [selected, setSelected] = React.useState<VulnKBEntry | null>(null);
  const [detail, setDetail] = React.useState<VulnKBEntry | null>(null);
  const [detailLoading, setDetailLoading] = React.useState(false);

  // Debounce search input.
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

  // 详情按需拉取(带 body 的大记录)。
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
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <BookOpenTextIcon className="size-5 text-muted-foreground" />
          <h1 className="text-lg font-semibold">漏洞库</h1>
          {stats && (
            <span className="text-xs text-muted-foreground">
              {stats.total.toLocaleString()} 条 · {stats.products.toLocaleString()} 产品 ·{" "}
              {stats.with_fingerprint.toLocaleString()} 带指纹
            </span>
          )}
        </div>
      </div>

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
                    {e.vuln_type ? <Badge variant="outline" className={typeTone(e.vuln_type)}>{e.vuln_type}</Badge> : null}
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
