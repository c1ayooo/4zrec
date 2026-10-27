"use client";

import * as React from "react";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { ArrowLeftIcon, ArrowUpRightIcon, DownloadIcon, PencilIcon, ShieldAlertIcon } from "lucide-react";
import { toast } from "sonner";

import { CopyButton } from "@/components/copy-button";
import { EvidenceViewer } from "@/components/evidence-viewer";
import { FindingRetestPanel } from "@/components/finding-retest-panel";
import { FindingTrafficPanel } from "@/components/finding-traffic-panel";
import { Markdown } from "@/components/markdown";
import { StatusBadge } from "@/components/status-badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import { statusMeta } from "@/lib/status";
import type { Finding, FindingStatus, Severity } from "@/lib/types";

import { FindingLineageView } from "./lineage";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const FINDING_STATUSES: FindingStatus[] = [
  "pending",
  "in_progress",
  "confirmed",
  "resolved",
  "fixed",
  "false_positive",
  "ignored",
  "duplicate",
  "risk_accepted",
];

function fmtTime(ts: string) {
  return new Date(ts).toLocaleString("zh-CN");
}

// FieldRow is one label/value line in the right-hand status panel.
function FieldRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 py-2.5">
      <span className="shrink-0 pt-0.5 text-xs text-muted-foreground">{label}</span>
      <div className="flex min-w-0 flex-col items-end gap-1 text-right text-sm">{children}</div>
    </div>
  );
}

function FindingDetailInner() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id") ?? "";
  const contextTaskId = searchParams.get("context_task") ?? "";
  const [finding, setFinding] = React.useState<Finding | null>(null);
  const [loaded, setLoaded] = React.useState(false);
  const [tab, setTab] = React.useState("overview");
  const [reportOpen, setReportOpen] = React.useState(false);
  const [reportDraft, setReportDraft] = React.useState("");
  const [reportSaving, setReportSaving] = React.useState(false);

  const load = React.useCallback(() => {
    if (!id) {
      setLoaded(true);
      return;
    }
    api
      .getFinding(id, contextTaskId || undefined)
      .then((f) => setFinding(f))
      .catch(() => setFinding(null))
      .finally(() => setLoaded(true));
  }, [contextTaskId, id]);
  React.useEffect(() => {
    load();
  }, [load]);

  const changeSeverity = React.useCallback(
    async (next: Severity) => {
      if (!finding || finding.inherited || next === finding.severity) return;
      const prev = finding.severity;
      setFinding({ ...finding, severity: next });
      try {
        const updated = await api.setFindingSeverity(id, next);
        setFinding(updated);
        toast.success(`严重等级已改为「${statusMeta("severity", next).label}」`);
      } catch (e) {
        setFinding((cur) => (cur ? { ...cur, severity: prev } : cur));
        toast.error("更新失败：" + (e as Error).message);
      }
    },
    [finding, id],
  );

  const changeStatus = React.useCallback(
    async (next: FindingStatus) => {
      if (!finding || finding.inherited || next === finding.status) return;
      const prev = finding.status;
      setFinding({ ...finding, status: next });
      try {
        const updated = await api.setFindingStatus(id, next);
        setFinding(updated);
        toast.success(`处理状态已改为「${statusMeta("finding", next).label}」`);
      } catch (e) {
        setFinding((cur) => (cur ? { ...cur, status: prev } : cur));
        toast.error("更新失败：" + (e as Error).message);
      }
    },
    [finding, id],
  );

  const saveReport = React.useCallback(async () => {
    if (!finding || finding.inherited) return;
    setReportSaving(true);
    try {
      const updated = await api.updateFinding(finding.id, { report: reportDraft });
      setFinding(updated);
      setReportOpen(false);
      toast.success("报告已保存，Word / PDF 导出将使用修改后的 Markdown");
    } catch (e) {
      toast.error("保存失败：" + (e as Error).message);
    } finally {
      setReportSaving(false);
    }
  }, [finding, reportDraft]);

  if (!finding) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-10 text-center">
        {loaded ? (
          <>
            <p className="text-muted-foreground">未找到发现 {id}</p>
            <Button asChild variant="outline">
              <Link href="/function/findings">
                <ArrowLeftIcon /> 返回发现列表
              </Link>
            </Button>
          </>
        ) : (
          <div className="flex w-full max-w-xl flex-col gap-3">
            <Skeleton className="h-6 w-64" />
            <Skeleton className="h-48 w-full" />
          </div>
        )}
      </div>
    );
  }

  const title = finding.name || finding.vulnclass || "未分类";

  return (
    <Tabs value={tab} onValueChange={setTab} className="flex flex-1 flex-col gap-0">
      {/* Sticky header */}
      <header className="sticky top-0 z-10 flex flex-col gap-2 border-b bg-background/95 px-4 py-2.5 backdrop-blur lg:px-6">
        <div className="flex flex-wrap items-center gap-2">
          <SidebarTrigger className="-ml-1" />
          <Button asChild variant="ghost" size="icon" className="size-7">
            <Link href="/function/findings">
              <ArrowLeftIcon />
            </Link>
          </Button>
          <ShieldAlertIcon className="size-4 text-muted-foreground" />
          <h1 className="max-w-md truncate text-sm font-semibold" title={title}>
            {title}
          </h1>
          <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">#{finding.id}</code>
          <Separator orientation="vertical" className="mx-1 h-4" />
          <StatusBadge domain="severity" value={finding.severity} dot />
          <StatusBadge domain="finding" value={finding.status} dot />
          {finding.confidence && (
            <Badge variant="outline" title="服务端按证据深度标注的可信度">
              证据：
              {finding.confidence === "verified" ? "已验证" : finding.confidence === "partial" ? "部分验证" : "推断"}
            </Badge>
          )}
          {finding.inherited && finding.source_task_id && (
            <Badge variant="outline">来源任务 #{finding.source_task_id} · 只读</Badge>
          )}
          {/* 单条漏洞导出:md 即时;docx 走报告管线(无 AI,复用持久化富化) */}
          <div className="ml-auto">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <DownloadIcon data-icon="inline-start" /> 导出
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem asChild>
                  <a href={api.findingExportUrl(finding.id, "pdf")}>PDF 报告(.pdf)</a>
                </DropdownMenuItem>
                <DropdownMenuItem asChild>
                  <a href={api.findingExportUrl(finding.id, "docx")}>Word 报告(.docx)</a>
                </DropdownMenuItem>
                <DropdownMenuItem asChild>
                  <a href={api.findingExportUrl(finding.id, "md")}>Markdown(.md)</a>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
        <TabsList>
          <TabsTrigger value="overview">概览</TabsTrigger>
          <TabsTrigger value="lineage">链路图</TabsTrigger>
        </TabsList>
      </header>

      {/* Tab content */}
      <div className="flex-1 p-4 lg:p-6">
        {/* 概览：左（摘要 + 证据）/ 右（状态区） */}
        <TabsContent value="overview" className="mt-0">
          <div className="grid gap-4 lg:grid-cols-3">
            {/* 左栏 */}
            <div className="flex flex-col gap-4 lg:col-span-2">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">摘要</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm leading-relaxed whitespace-pre-wrap">{finding.summary || "（无摘要）"}</p>
                </CardContent>
              </Card>
              <FindingRetestPanel key={id} findingId={id} readOnly={finding.inherited} onCompleted={load} />
              <Card>
                <CardHeader className="flex-row items-center justify-between">
                  <CardTitle className="text-sm">证据 / PoC</CardTitle>
                  {finding.evidence && <CopyButton text={finding.evidence} successMessage="已复制证据" />}
                </CardHeader>
                <CardContent>
                  {finding.evidence ? (
                    <EvidenceViewer text={finding.evidence} reproduction={finding.reproduction} />
                  ) : (
                    <p className="text-sm text-muted-foreground">（无证据）</p>
                  )}
                </CardContent>
              </Card>
              <FindingTrafficPanel
                key={id}
                findingId={id}
                contextTask={contextTaskId || undefined}
                readOnly={finding.inherited}
                onChanged={load}
              />
              {/* 证据下方：详细报告(Markdown 渲染) */}
              <Card>
                <CardHeader className="flex-row items-center justify-between">
                  <CardTitle className="text-sm">详细报告</CardTitle>
                  <div className="flex items-center gap-1">
                    {finding.report && !finding.inherited && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          setReportDraft(finding.report || "");
                          setReportOpen(true);
                        }}
                      >
                        <PencilIcon data-icon="inline-start" /> 编辑
                      </Button>
                    )}
                    {finding.report && <CopyButton text={finding.report} successMessage="已复制详细报告" />}
                  </div>
                </CardHeader>
                <CardContent>
                  {finding.report_stale ? (
                    <Alert>
                      <AlertDescription>流量证据已变更，详细报告待更新。</AlertDescription>
                    </Alert>
                  ) : null}
                  {finding.report ? (
                    <Markdown text={finding.report} />
                  ) : (
                    <p className="text-sm text-muted-foreground">暂无详细报告。</p>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* 右栏：状态区 */}
            <Card className="h-fit lg:sticky lg:top-24">
              <CardHeader>
                <CardTitle className="text-sm">状态</CardTitle>
              </CardHeader>
              <CardContent className="divide-y">
                {/* 漏洞 ID */}
                <FieldRow label="漏洞 ID">
                  <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
                    #{finding.id}
                  </code>
                </FieldRow>

                {/* 严重等级 */}
                <FieldRow label="严重等级">
                  {finding.inherited ? (
                    <StatusBadge domain="severity" value={finding.severity} dot />
                  ) : (
                    <Select value={finding.severity} onValueChange={(v) => changeSeverity(v as Severity)}>
                      <SelectTrigger size="sm" className="h-7 w-auto border-none px-1 shadow-none focus-visible:ring-0">
                        <StatusBadge domain="severity" value={finding.severity} dot />
                      </SelectTrigger>
                      <SelectContent position="popper" align="end">
                        <SelectGroup>
                          {SEVERITIES.map((sv) => (
                            <SelectItem key={sv} value={sv}>
                              {statusMeta("severity", sv).label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  )}
                </FieldRow>

                {/* 处理状态 */}
                <FieldRow label="处理状态">
                  {finding.inherited ? (
                    <StatusBadge domain="finding" value={finding.status} dot />
                  ) : (
                    <Select value={finding.status} onValueChange={(v) => changeStatus(v as FindingStatus)}>
                      <SelectTrigger size="sm" className="h-7 w-auto border-none px-1 shadow-none focus-visible:ring-0">
                        <StatusBadge domain="finding" value={finding.status} dot />
                      </SelectTrigger>
                      <SelectContent position="popper" align="end">
                        <SelectGroup>
                          {FINDING_STATUSES.map((st) => (
                            <SelectItem key={st} value={st}>
                              {statusMeta("finding", st).label}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  )}
                </FieldRow>

                {/* 漏洞类型 */}
                <FieldRow label="漏洞类型">
                  {finding.vulnclass ? (
                    <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">{finding.vulnclass}</code>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </FieldRow>

                {/* 涉及资产 */}
                <FieldRow label="涉及资产">
                  {finding.assets && finding.assets.length > 0 ? (
                    <div className="flex flex-wrap justify-end gap-1">
                      {finding.assets.map((a) => (
                        <code
                          key={a.id}
                          className="max-w-[16rem] truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs"
                          title={`${a.type} · ${a.label}`}
                        >
                          {a.label}
                        </code>
                      ))}
                    </div>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </FieldRow>

                {/* 所属任务 */}
                <FieldRow label="所属任务">
                  {finding.task_id ? (
                    <Link
                      href={`/function/tasks/detail?id=${finding.task_id}`}
                      className="inline-flex max-w-[16rem] items-center gap-1 text-primary hover:underline"
                      title={finding.task_description}
                    >
                      <span className="truncate">{finding.task_description || `#${finding.task_id}`}</span>
                      <ArrowUpRightIcon className="size-3 shrink-0" />
                    </Link>
                  ) : (
                    <span className="text-muted-foreground">—（任务已删除）</span>
                  )}
                </FieldRow>

                {/* 发现时间 */}
                <FieldRow label="发现时间">
                  <span className="tabular-nums">{fmtTime(finding.ts)}</span>
                </FieldRow>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* 链路图：从任务初始节点回溯到本漏洞节点的攻击链路 */}
        <TabsContent value="lineage" className="mt-0">
          <FindingLineageView findingId={finding.id} />
        </TabsContent>
      </div>

      <Dialog open={reportOpen} onOpenChange={setReportOpen}>
        <DialogContent className="max-w-5xl">
          <DialogHeader>
            <DialogTitle>编辑详细报告（Markdown）</DialogTitle>
            <DialogDescription>
              保存后，Word / PDF 导出会直接使用这份修改后的 Markdown（包括图片、表格与四段 SRC 结构）。
            </DialogDescription>
          </DialogHeader>
          <Textarea
            value={reportDraft}
            onChange={(e) => setReportDraft(e.target.value)}
            className="min-h-[60vh] resize-y font-mono text-xs leading-relaxed"
            spellCheck={false}
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setReportOpen(false)}>
              取消
            </Button>
            <Button onClick={saveReport} disabled={reportSaving}>
              {reportSaving ? "保存中…" : "保存"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Tabs>
  );
}

// useSearchParams must sit under a Suspense boundary for static export.
export default function FindingDetailPage() {
  return (
    <React.Suspense fallback={null}>
      <FindingDetailInner />
    </React.Suspense>
  );
}
