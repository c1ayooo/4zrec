"use client";

import * as React from "react";

import {
  CopyIcon,
  Loader2Icon,
  PencilIcon,
  PlusIcon,
  RefreshCwIcon,
  SearchIcon,
  Trash2Icon,
  UploadCloudIcon,
} from "lucide-react";
import { toast } from "sonner";

import { FeatureCallHistory } from "@/components/feature-call-history";
import { ProxySlotSelect } from "@/components/proxy-slot-select";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { NucleiStatus, NucleiTemplateMeta, NucleiUpdateJob } from "@/lib/types";

const PAGE_SIZE = 20;

const STARTER_TEMPLATE = `id: custom-check
info:
  name: Custom Check
  author: 4zrec
  severity: info
  tags: custom
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
`;

type Source = "official" | "custom" | "history";
type EditorMode = "view" | "edit" | "create";

interface EditorState {
  mode: EditorMode;
  meta?: NucleiTemplateMeta;
  yaml: string;
}

export default function NucleiTemplatesPage() {
  const [source, setSource] = React.useState<Source>("official");
  const [items, setItems] = React.useState<NucleiTemplateMeta[]>([]);
  const [total, setTotal] = React.useState(0);
  const [page, setPage] = React.useState(1);
  const [query, setQuery] = React.useState("");
  const [search, setSearch] = React.useState("");
  const [severity, setSeverity] = React.useState("all");
  const [type, setType] = React.useState("all");
  const [tags, setTags] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [warning, setWarning] = React.useState("");
  const [status, setStatus] = React.useState<NucleiStatus | null>(null);
  const [editor, setEditor] = React.useState<EditorState | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [updating, setUpdating] = React.useState(false);
  const [updateJob, setUpdateJob] = React.useState<NucleiUpdateJob | null>(null);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const refreshStatus = React.useCallback(async () => {
    try {
      setStatus(await api.nucleiStatus());
    } catch {
      setStatus(null);
    }
  }, []);

  const load = React.useCallback(async () => {
    if (source === "history") return;
    setLoading(true);
    try {
      const res = await api.nucleiTemplates({
        q: search.trim() || undefined,
        severity: severity === "all" ? undefined : severity,
        type: type === "all" ? undefined : type,
        tags: tags.trim() || undefined,
        source,
        page,
        size: PAGE_SIZE,
      });
      setItems(res.items ?? []);
      setTotal(res.total ?? 0);
      setWarning(res.warning ?? "");
    } catch (err) {
      toast.error("读取模板失败：" + (err instanceof Error ? err.message : String(err)));
    } finally {
      setLoading(false);
    }
  }, [search, severity, type, tags, source, page]);

  React.useEffect(() => {
    void load();
  }, [load]);

  React.useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  const applySearch = () => {
    setSearch(query);
    setPage(1);
  };

  const switchSource = (v: string) => {
    setSource(v as Source);
    setPage(1);
  };

  const openTemplate = async (t: NucleiTemplateMeta) => {
    setEditor({ mode: "view", yaml: "" });
    try {
      const detail = await api.nucleiTemplate(t.id);
      setEditor({ mode: "view", meta: detail.meta, yaml: detail.content });
    } catch (err) {
      setEditor(null);
      toast.error("读取模板失败：" + (err instanceof Error ? err.message : String(err)));
    }
  };

  const openCreate = () => {
    setEditor({ mode: "create", yaml: STARTER_TEMPLATE });
  };

  const copyToCustom = () => {
    if (!editor?.meta) return;
    const yaml = editor.yaml.replace(/^id:\s*.*$/m, `id: ${editor.meta.id}-custom`);
    setEditor({ mode: "create", yaml });
  };

  const validateDraft = async () => {
    if (!editor) return;
    try {
      const res = await api.nucleiTemplateValidate(editor.yaml);
      if (res.ok && res.meta) {
        toast.success(`校验通过：${res.meta.id}（${res.meta.severity}/${res.meta.type}）`);
      } else {
        toast.error(res.error || "校验失败");
      }
    } catch (err) {
      toast.error("校验失败：" + (err instanceof Error ? err.message : String(err)));
    }
  };

  const saveDraft = async () => {
    if (!editor) return;
    setSaving(true);
    try {
      if (editor.mode === "create") {
        const meta = await api.nucleiTemplateCreate(editor.yaml);
        toast.success(`已创建自定义模板：${meta.id}`);
        setSource("custom");
        setPage(1);
      } else if (editor.mode === "edit" && editor.meta) {
        await api.nucleiTemplateUpdate(editor.meta.id, editor.yaml);
        toast.success(`已保存：${editor.meta.id}`);
      }
      setEditor(null);
      await Promise.all([load(), refreshStatus()]);
    } catch (err) {
      toast.error("保存失败：" + (err instanceof Error ? err.message : String(err)));
    } finally {
      setSaving(false);
    }
  };

  const deleteTemplate = async () => {
    if (!editor?.meta || editor.meta.source !== "custom") return;
    if (!window.confirm(`确认删除自定义模板 ${editor.meta.id}？`)) return;
    setSaving(true);
    try {
      await api.nucleiTemplateDelete(editor.meta.id);
      toast.success(`已删除：${editor.meta.id}`);
      setEditor(null);
      await Promise.all([load(), refreshStatus()]);
    } catch (err) {
      toast.error("删除失败：" + (err instanceof Error ? err.message : String(err)));
    } finally {
      setSaving(false);
    }
  };

  const runUpdate = async () => {
    setUpdating(true);
    setUpdateJob(null);
    try {
      const started = await api.nucleiUpdate();
      setUpdateJob(started);
      for (let i = 0; i < 900; i++) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        const job = await api.nucleiUpdateStatus();
        setUpdateJob(job);
        if (!job.running) {
          if (job.error) toast.error("更新失败：" + job.error);
          else toast.success(`官方模板已更新（${job.result?.template_count ?? 0} 个模板）`);
          break;
        }
      }
      await Promise.all([load(), refreshStatus()]);
    } catch (err) {
      toast.error("更新失败：" + (err instanceof Error ? err.message : String(err)));
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">nuclei 模板</h1>
        <p className="text-muted-foreground mt-1 text-sm">
          官方模板由 nuclei 自动更新，只读；自定义模板保存在独立目录，不会被模板更新覆盖。扫描时未显式选模板，
          tags/severity/type 会同时作用于两个目录。
        </p>
      </div>

      <Card>
        <CardContent className="flex flex-wrap items-center justify-between gap-3 p-4">
          <div className="text-muted-foreground text-sm">
            {status ? (
              <>
                二进制 {status.binary_exists ? status.binary_version || "已安装" : "未安装"}
                {" · "}官方模板 {status.template_count}
                {" · "}自定义 {status.custom_template_count ?? 0}
                {status.last_update ? ` · 上次更新 ${status.last_update.slice(0, 10)}` : ""}
              </>
            ) : (
              "读取 nuclei 状态失败（可点刷新重试）"
            )}
          </div>
          <div className="flex flex-wrap items-center justify-end gap-2">
            <ProxySlotSelect slot="nuclei" label="更新代理" />
            <Button variant="outline" onClick={() => void refreshStatus()}>
              <RefreshCwIcon className="size-4" /> 刷新状态
            </Button>
            <Button onClick={() => void runUpdate()} disabled={updating}>
              {updating ? <Loader2Icon className="size-4 animate-spin" /> : <UploadCloudIcon className="size-4" />}
              {updating ? (updateJob?.running ? "更新中…" : "收尾中…") : "更新官方模板"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {updateJob && (
        <Card>
          <CardContent className="space-y-2 p-4">
            <div className="flex items-center justify-between text-xs">
              <span className="font-medium">{updateJob.phase ?? "准备中"}</span>
              <span className="text-muted-foreground">{updateJob.percent ?? 0}%</span>
            </div>
            <Progress value={updateJob.percent ?? 0} />
            <p className="text-muted-foreground text-xs">
              {updateJob.message ||
                (updateJob.running
                  ? "正在下载/更新，请稍候…"
                  : updateJob.error ||
                    `已完成：官方模板 ${updateJob.result?.template_count ?? 0} 个 / 自定义 ${updateJob.result?.custom_template_count ?? 0} 个`)}
            </p>
            {updateJob.error && <p className="text-xs text-red-500">{updateJob.error}</p>}
          </CardContent>
        </Card>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <Tabs value={source} onValueChange={switchSource}>
          <TabsList>
            <TabsTrigger value="official">官方模板</TabsTrigger>
            <TabsTrigger value="custom">自定义模板</TabsTrigger>
            <TabsTrigger value="history">调用历史</TabsTrigger>
          </TabsList>
        </Tabs>
        {source !== "history" && (
          <Button onClick={openCreate}>
            <PlusIcon className="size-4" /> 新建自定义模板
          </Button>
        )}
      </div>

      {source === "history" ? (
        <FeatureCallHistory feature="nuclei" />
      ) : (
        <Card>
          <CardContent className="space-y-3 px-4 pb-4">
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative min-w-56 flex-1">
                <SearchIcon className="text-muted-foreground absolute top-2.5 left-2.5 size-4" />
                <Input
                  className="pl-8"
                  placeholder="搜 ID / 名称 / 标签 / CVE"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") applySearch();
                  }}
                />
              </div>
              <Select
                value={severity}
                onValueChange={(v) => {
                  setSeverity(v);
                  setPage(1);
                }}
              >
                <SelectTrigger className="w-36">
                  <SelectValue placeholder="等级" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部等级</SelectItem>
                  <SelectItem value="critical">critical</SelectItem>
                  <SelectItem value="high">high</SelectItem>
                  <SelectItem value="medium">medium</SelectItem>
                  <SelectItem value="low">low</SelectItem>
                  <SelectItem value="info">info</SelectItem>
                </SelectContent>
              </Select>
              <Select
                value={type}
                onValueChange={(v) => {
                  setType(v);
                  setPage(1);
                }}
              >
                <SelectTrigger className="w-32">
                  <SelectValue placeholder="类型" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部类型</SelectItem>
                  <SelectItem value="http">http</SelectItem>
                  <SelectItem value="dns">dns</SelectItem>
                  <SelectItem value="tcp">tcp</SelectItem>
                  <SelectItem value="file">file</SelectItem>
                  <SelectItem value="headless">headless</SelectItem>
                  <SelectItem value="ssl">ssl</SelectItem>
                  <SelectItem value="websocket">websocket</SelectItem>
                  <SelectItem value="whois">whois</SelectItem>
                  <SelectItem value="workflow">workflow</SelectItem>
                </SelectContent>
              </Select>
              <Input
                className="w-44"
                placeholder="标签，逗号分隔"
                value={tags}
                onChange={(e) => {
                  setTags(e.target.value);
                  setPage(1);
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") setPage(1);
                }}
              />
              <Button onClick={applySearch}>
                <SearchIcon className="size-4" /> 搜索
              </Button>
            </div>
            {warning && <p className="text-xs text-amber-500">{warning}</p>}

            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>ID</TableHead>
                    <TableHead>名称</TableHead>
                    <TableHead>等级</TableHead>
                    <TableHead>类型</TableHead>
                    <TableHead>标签</TableHead>
                    <TableHead>来源</TableHead>
                    <TableHead className="text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {loading && (
                    <TableRow>
                      <TableCell colSpan={7} className="text-muted-foreground py-8 text-center">
                        <Loader2Icon className="mx-auto mb-2 size-5 animate-spin" />
                        加载中…
                      </TableCell>
                    </TableRow>
                  )}
                  {!loading && items.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={7} className="text-muted-foreground py-8 text-center">
                        暂无模板。
                        {source === "official" ? "可点右上角「更新官方模板」下载。" : "点「新建自定义模板」添加。"}
                      </TableCell>
                    </TableRow>
                  )}
                  {!loading &&
                    items.map((t) => (
                      <TableRow
                        key={`${t.source}:${t.id}`}
                        className="cursor-pointer"
                        onClick={() => void openTemplate(t)}
                      >
                        <TableCell className="font-mono text-xs">{t.id}</TableCell>
                        <TableCell>{t.name}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{t.severity}</Badge>
                        </TableCell>
                        <TableCell className="text-muted-foreground text-xs">{t.type}</TableCell>
                        <TableCell className="text-muted-foreground max-w-56 truncate text-xs">
                          {(t.tags ?? []).join(", ")}
                        </TableCell>
                        <TableCell>
                          <Badge variant={t.source === "custom" ? "default" : "secondary"}>
                            {t.source === "custom" ? "自定义" : "官方"}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              void openTemplate(t);
                            }}
                          >
                            查看
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                </TableBody>
              </Table>
            </div>

            <div className="flex items-center justify-between gap-2">
              <p className="text-muted-foreground text-xs">
                共 {total} 条 · 第 {page} / {totalPages} 页
              </p>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page <= 1 || loading}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                >
                  上一页
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page >= totalPages || loading}
                  onClick={() => setPage((p) => p + 1)}
                >
                  下一页
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <Dialog
        open={editor !== null}
        onOpenChange={(open) => {
          if (!open) setEditor(null);
        }}
      >
        <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-4xl">
          <DialogHeader>
            <DialogTitle>
              {editor?.mode === "create"
                ? "新建自定义模板"
                : editor?.mode === "edit"
                  ? `编辑 ${editor.meta?.id ?? ""}`
                  : (editor?.meta?.id ?? "模板详情")}
            </DialogTitle>
            <DialogDescription>
              {editor?.mode === "create"
                ? "保存后写入 custom-templates/，不会随官方模板更新被覆盖。"
                : editor?.meta
                  ? `${editor.meta.name} · ${editor.meta.severity}/${editor.meta.type} · ${editor.meta.source === "custom" ? "自定义" : "官方只读"}`
                  : "加载中…"}
            </DialogDescription>
          </DialogHeader>

          {editor && (
            <div className="space-y-3">
              {editor.mode === "view" && editor.meta && (
                <div className="text-muted-foreground flex flex-wrap gap-x-4 gap-y-1 text-xs">
                  <span>ID: {editor.meta.id}</span>
                  <span>
                    路径: {editor.meta.source}/{editor.meta.path}
                  </span>
                  {editor.meta.author ? <span>作者: {editor.meta.author}</span> : null}
                  {editor.meta.tags?.length ? <span>标签: {editor.meta.tags.join(", ")}</span> : null}
                  {editor.meta.cve?.length ? <span>CVE: {editor.meta.cve.join(", ")}</span> : null}
                </div>
              )}

              {editor.mode === "view" ? (
                <pre className="bg-muted/30 max-h-[60vh] overflow-auto rounded-md border p-3 font-mono text-xs whitespace-pre-wrap">
                  {editor.yaml}
                </pre>
              ) : (
                <div className="space-y-2">
                  <Label htmlFor="nuclei-template-yaml">YAML</Label>
                  <Textarea
                    id="nuclei-template-yaml"
                    className="min-h-[50vh] font-mono text-xs"
                    value={editor.yaml}
                    onChange={(e) => setEditor((cur) => (cur ? { ...cur, yaml: e.target.value } : cur))}
                  />
                </div>
              )}
            </div>
          )}

          <DialogFooter className="flex flex-wrap items-center justify-between gap-2 sm:justify-between">
            <div className="flex items-center gap-2">
              {editor?.mode === "view" && editor.meta?.source === "custom" && (
                <>
                  <Button variant="outline" onClick={() => setEditor((cur) => (cur ? { ...cur, mode: "edit" } : cur))}>
                    <PencilIcon className="size-4" /> 编辑
                  </Button>
                  <Button variant="destructive" onClick={() => void deleteTemplate()} disabled={saving}>
                    <Trash2Icon className="size-4" /> 删除
                  </Button>
                </>
              )}
              {editor?.mode === "view" && editor.meta?.source === "official" && (
                <Button variant="outline" onClick={copyToCustom}>
                  <CopyIcon className="size-4" /> 复制为自定义模板
                </Button>
              )}
              {(editor?.mode === "edit" || editor?.mode === "create") && (
                <Button variant="outline" onClick={() => void validateDraft()}>
                  验证
                </Button>
              )}
            </div>
            <div className="flex items-center gap-2">
              {(editor?.mode === "edit" || editor?.mode === "create") && (
                <Button onClick={() => void saveDraft()} disabled={saving}>
                  {saving ? <Loader2Icon className="size-4 animate-spin" /> : null} 保存
                </Button>
              )}
              <Button variant="outline" onClick={() => setEditor(null)}>
                关闭
              </Button>
            </div>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
