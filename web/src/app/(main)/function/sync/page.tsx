"use client";

import * as React from "react";

import { AlertCircleIcon, CheckCircle2Icon, DownloadIcon, PlugZapIcon, RefreshCwIcon, SearchIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { ReconProject, ReconTask } from "@/lib/types";

type ReconSyncState = {
  asset_type: string;
  watermark: string;
  last_run_at: string | null;
  last_result: string;
  truncated: boolean;
};

type ReconStatus = {
  exists: boolean;
  configured: boolean;
  enabled: boolean;
  reachable: boolean;
  url?: string;
  tools: string[];
  sync_state?: ReconSyncState[];
};

type Dimension = "project" | "task";

const typeLabels: Record<string, string> = {
  subdomain: "子域名",
  root_domain: "根域名",
  service: "服务",
  app: "App",
  ip: "IP",
};

const ASSET_TYPES: { key: string; label: string }[] = [
  { key: "subdomain", label: "子域名" },
  { key: "root_domain", label: "根域名" },
  { key: "service", label: "服务" },
  { key: "app", label: "App" },
];

export default function AssetSyncPage() {
  return (
    <div className="p-4 md:p-6">
      <div className="mb-4">
        <h1 className="font-semibold text-xl">资产同步</h1>
        <p className="text-muted-foreground text-sm">从 4zrecon 同步资产入库</p>
      </div>
      <Tabs defaultValue="4zrecon">
        <TabsList>
          <TabsTrigger value="4zrecon">4zrecon</TabsTrigger>
        </TabsList>
        <TabsContent value="4zrecon" className="mt-4">
          <ReconPanel />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function ReconPanel() {
  const [status, setStatus] = React.useState<ReconStatus | null>(null);
  const [loadingStatus, setLoadingStatus] = React.useState(true);

  const loadStatus = React.useCallback(() => {
    setLoadingStatus(true);
    api
      .reconStatus()
      .then(setStatus)
      .catch((e) => toast.error(`读取数据源状态失败：${e.message}`))
      .finally(() => setLoadingStatus(false));
  }, []);

  React.useEffect(() => {
    loadStatus();
  }, [loadStatus]);

  const ready = !!status && status.exists && status.configured && status.enabled;

  return (
    <div className="space-y-4">
      <DataSourceCard status={status} loading={loadingStatus} onChanged={loadStatus} />
      {ready ? (
        <>
          <SyncScopeCard />
          <SyncWorkbench />
        </>
      ) : (
        <Card>
          <CardContent className="py-8 text-center text-muted-foreground text-sm">
            数据源就绪后即可选择项目 / 任务进行同步。
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ── 增量同步范围卡：定时/手动增量只拉勾选项目，未勾选 = 不同步 ────────────────

function SyncScopeCard() {
  const [projects, setProjects] = React.useState<ReconProject[]>([]);
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    Promise.all([api.reconProjects(1, 100), api.reconSelection()])
      .then(([p, sel]) => {
        setProjects(p.projects);
        setSelected(new Set(sel));
      })
      .catch((e) => toast.error(`加载同步范围失败：${e.message}`))
      .finally(() => setLoading(false));
  }, []);

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const save = async () => {
    setSaving(true);
    try {
      const r = await api.reconSetSelection([...selected]);
      toast.success(
        r.watermarks_reset > 0
          ? `已保存 ${selected.size} 个项目的同步范围；范围有变化，下一轮增量将全量补齐勾选项目`
          : `已保存 ${selected.size} 个项目的同步范围`,
      );
    } catch (e) {
      toast.error(`保存同步范围失败：${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <div className="space-y-1.5">
          <CardTitle className="text-base">增量同步范围</CardTitle>
          <p className="text-muted-foreground text-sm">
            定时增量与「增量同步」只拉取勾选项目的新资产，未勾选任何项目时增量不同步；手动目标全量不受此范围影响。
            更改范围并保存后，下一轮增量会全量补齐勾选项目。
          </p>
        </div>
        <Button size="sm" disabled={saving || loading} onClick={save}>
          {saving ? "保存中…" : "保存范围"}
        </Button>
      </CardHeader>
      <CardContent>
        {loading ? (
          <div className="text-muted-foreground text-sm">加载中…</div>
        ) : projects.length === 0 ? (
          <div className="text-muted-foreground text-sm">上游没有项目。</div>
        ) : (
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {projects.map((p) => (
              <label
                key={p.id}
                className="flex cursor-pointer items-center gap-2 rounded-md border px-3 py-2 text-sm hover:bg-accent"
              >
                <Checkbox checked={selected.has(p.id)} onCheckedChange={() => toggle(p.id)} />
                <span className="truncate">{p.name}</span>
                <span className="text-muted-foreground ml-auto pl-2 text-xs tabular-nums">{p.AssetCount ?? 0}</span>
              </label>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── 数据源状态卡 ─────────────────────────────────────────────────────────────

function DataSourceCard({
  status,
  loading,
  onChanged,
}: {
  status: ReconStatus | null;
  loading: boolean;
  onChanged: () => void;
}) {
  const [url, setUrl] = React.useState("");
  const [apiKey, setApiKey] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    if (status?.url) setUrl(status.url);
  }, [status?.url]);

  const create = async () => {
    setBusy(true);
    try {
      await api.reconDatasource({});
      toast.success("已创建 4zrecon 数据源，请填写地址与密钥");
      onChanged();
    } catch (e) {
      toast.error(`创建失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  const save = async () => {
    if (!url.trim()) return toast.error("请填写 MCP 地址");
    setBusy(true);
    try {
      const r = await api.reconDatasource({ url: url.trim(), api_key: apiKey.trim() });
      toast.success(r.enabled ? "已保存并启用数据源" : "已保存（尚未满足启用条件）");
      setApiKey("");
      onChanged();
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2 text-base">
          <PlugZapIcon className="size-4" /> 数据源状态
          <StatusBadge status={status} loading={loading} />
        </CardTitle>
        <Button variant="ghost" size="sm" onClick={onChanged} disabled={loading}>
          <RefreshCwIcon className={loading ? "size-4 animate-spin" : "size-4"} /> 刷新
        </Button>
      </CardHeader>
      <CardContent className="space-y-3">
        {!status?.exists ? (
          <div className="flex items-center justify-between gap-4">
            <p className="text-muted-foreground text-sm">
              尚未创建 4zrecon 数据源。创建后会新增一个占位 MCP（地址/密钥为空、未启用）。
            </p>
            <Button onClick={create} disabled={busy}>
              创建数据源
            </Button>
          </div>
        ) : (
          <>
            {!status.configured && (
              <p className="text-amber-600 text-sm dark:text-amber-500">
                数据源已创建但未配置，请填写 MCP 地址与 API Key 后启用。
              </p>
            )}
            {status.configured && !status.enabled && (
              <p className="text-amber-600 text-sm dark:text-amber-500">数据源已配置但未启用，保存后将自动启用。</p>
            )}
            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-1.5">
                <Label>MCP 地址</Label>
                <Input placeholder="http://<主机>:8082/mcp" value={url} onChange={(e) => setUrl(e.target.value)} />
              </div>
              <div className="space-y-1.5">
                <Label>API Key（X-API-Key，留空保留原值）</Label>
                <Input
                  type="password"
                  placeholder="ssk_..."
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                />
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button onClick={save} disabled={busy}>
                保存并启用
              </Button>
              {status.enabled && status.tools.length > 0 && (
                <span className="text-muted-foreground text-xs">已发现 {status.tools.length} 个工具</span>
              )}
            </div>
            {status.enabled && (status.sync_state?.length ?? 0) > 0 && (
              <div className="space-y-1 rounded-md border bg-muted/40 p-2.5">
                <p className="text-muted-foreground text-xs">
                  增量水位（每类型最近一轮；截断=达单轮上限，剩余下轮继续）
                </p>
                <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
                  {status.sync_state?.map((st) => (
                    <span key={st.asset_type}>
                      {typeLabels[st.asset_type] ?? st.asset_type}:{" "}
                      {st.last_run_at ? new Date(st.last_run_at).toLocaleString() : "未跑过"}
                      {st.truncated && <span className="text-amber-600 dark:text-amber-500">（截断）</span>}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

function StatusBadge({ status, loading }: { status: ReconStatus | null; loading: boolean }) {
  if (loading || !status) return <Badge variant="secondary">检测中…</Badge>;
  if (!status.exists) return <Badge variant="destructive">未创建</Badge>;
  if (!status.configured) return <Badge variant="outline">未配置</Badge>;
  if (!status.enabled) return <Badge variant="outline">未启用</Badge>;
  if (status.reachable)
    return (
      <Badge className="bg-emerald-600 hover:bg-emerald-600">
        <CheckCircle2Icon className="mr-1 size-3" /> 已连接
      </Badge>
    );
  return (
    <Badge variant="destructive">
      <AlertCircleIcon className="mr-1 size-3" /> 不可达
    </Badge>
  );
}

// ── 同步工作区（项目 / 任务维度）────────────────────────────────────────────────

function SyncWorkbench() {
  const [dimension, setDimension] = React.useState<Dimension>("project");
  const [assetTypes, setAssetTypes] = React.useState<Record<string, boolean>>({
    subdomain: true,
    root_domain: true,
    service: true,
    app: true,
  });
  const [createCompany, setCreateCompany] = React.useState(true);

  const [projects, setProjects] = React.useState<ReconProject[]>([]);
  const [tasks, setTasks] = React.useState<ReconTask[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [search, setSearch] = React.useState("");
  const [page, setPage] = React.useState(1);
  const [selected, setSelected] = React.useState<Set<string>>(new Set());

  const [syncing, setSyncing] = React.useState(false);
  const [result, setResult] = React.useState<Awaited<ReturnType<typeof api.reconSync>> | null>(null);

  const load = React.useCallback(() => {
    setLoading(true);
    setSelected(new Set());
    const fn =
      dimension === "project"
        ? api.reconProjects(page, 50, search).then((r) => setProjects(r.projects))
        : api.reconTasks(page, 50, search).then(setTasks);
    fn.catch((e) => toast.error(`加载列表失败：${e.message}`)).finally(() => setLoading(false));
  }, [dimension, page, search]);

  React.useEffect(() => {
    load();
  }, [load]);

  const rows = dimension === "project" ? projects : tasks;
  const idOf = (row: ReconProject | ReconTask) => (dimension === "project" ? (row as ReconProject).id : (row as ReconTask).name);

  const toggle = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  const toggleAll = () => {
    setSelected((prev) => (prev.size === rows.length ? new Set() : new Set(rows.map(idOf))));
  };

  const chosenTypes = ASSET_TYPES.filter((t) => assetTypes[t.key]).map((t) => t.key);

  const runSync = async () => {
    if (selected.size === 0) return toast.error(`请至少选择一个${dimension === "project" ? "项目" : "任务"}`);
    if (chosenTypes.length === 0) return toast.error("请至少选择一种资产类型");
    setSyncing(true);
    setResult(null);
    try {
      const r = await api.reconSync({
        mode: "full",
        dimension,
        targets: [...selected],
        asset_types: chosenTypes,
        create_company: dimension === "project" ? createCompany : false,
      });
      setResult(r);
      const total = Object.values(r.synced ?? {}).reduce((a, b) => a + b, 0);
      toast.success(`同步完成，共入库 ${total} 条资产`);
    } catch (e) {
      toast.error(`同步失败：${(e as Error).message}`);
    } finally {
      setSyncing(false);
    }
  };

  // 全局增量（同后台 ticker 的通道）：按水位只拉新数据，不选项目/任务。
  const runIncremental = async () => {
    setSyncing(true);
    setResult(null);
    try {
      const r = await api.reconSync({ mode: "inc" });
      setResult(r);
      const total = Object.values(r.synced ?? {}).reduce((a, b) => a + b, 0);
      toast.success(`增量同步完成，本轮入库 ${total} 条资产`);
    } catch (e) {
      toast.error(`增量同步失败：${(e as Error).message}`);
    } finally {
      setSyncing(false);
    }
  };

  const renderRows = () => {
    if (loading) {
      return (
        <TableRow>
          <TableCell colSpan={4} className="py-8 text-center text-muted-foreground text-sm">
            加载中…
          </TableCell>
        </TableRow>
      );
    }
    if (rows.length === 0) {
      return (
        <TableRow>
          <TableCell colSpan={4} className="py-8 text-center text-muted-foreground text-sm">
            无数据
          </TableCell>
        </TableRow>
      );
    }
    if (dimension === "project") {
      return projects.map((p) => (
        <TableRow key={p.id} className="cursor-pointer" onClick={() => toggle(p.id)}>
          <TableCell onClick={(e) => e.stopPropagation()}>
            <Checkbox checked={selected.has(p.id)} onCheckedChange={() => toggle(p.id)} />
          </TableCell>
          <TableCell className="font-medium">{p.name}</TableCell>
          <TableCell>{p.tag ? <Badge variant="secondary">{p.tag}</Badge> : "—"}</TableCell>
          <TableCell className="text-right">{p.AssetCount ?? 0}</TableCell>
        </TableRow>
      ));
    }
    return tasks.map((t) => (
      <TableRow key={t.id} className="cursor-pointer" onClick={() => toggle(t.name)}>
        <TableCell onClick={(e) => e.stopPropagation()}>
          <Checkbox checked={selected.has(t.name)} onCheckedChange={() => toggle(t.name)} />
        </TableCell>
        <TableCell className="font-medium">{t.name}</TableCell>
        <TableCell>
          <Badge variant={t.progress === 100 ? "secondary" : "outline"}>
            {t.progress != null ? `${t.progress}%` : "—"}
          </Badge>
        </TableCell>
        <TableCell className="text-muted-foreground text-xs">{t.endTime || t.creatTime || "—"}</TableCell>
      </TableRow>
    ));
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">选择数据同步</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* 维度切换 */}
        <Tabs
          value={dimension}
          onValueChange={(v) => {
            setDimension(v as Dimension);
            setPage(1);
          }}
        >
          <TabsList>
            <TabsTrigger value="project">项目维度</TabsTrigger>
            <TabsTrigger value="task">任务维度</TabsTrigger>
          </TabsList>
        </Tabs>

        {/* 资产类型 + 选项 */}
        <div className="flex flex-wrap items-center gap-4">
          <span className="font-medium text-sm">同步资产：</span>
          {ASSET_TYPES.map((t) => (
            <label key={t.key} htmlFor={`at-${t.key}`} className="flex items-center gap-1.5 text-sm">
              <Checkbox
                id={`at-${t.key}`}
                checked={!!assetTypes[t.key]}
                onCheckedChange={(c) => setAssetTypes((prev) => ({ ...prev, [t.key]: !!c }))}
              />
              {t.label}
            </label>
          ))}
          {dimension === "project" && (
            <label htmlFor="create-company" className="flex items-center gap-1.5 text-sm">
              <Checkbox id="create-company" checked={createCompany} onCheckedChange={(c) => setCreateCompany(!!c)} />
              按项目建立企业并写入资产范围
            </label>
          )}
        </div>

        {/* 搜索 + 操作 */}
        <div className="flex items-center gap-2">
          <div className="relative max-w-xs flex-1">
            <SearchIcon className="absolute top-1/2 left-2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              className="pl-8"
              placeholder={dimension === "project" ? "搜索项目名" : "搜索任务名"}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  setPage(1);
                  load();
                }
              }}
            />
          </div>
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCwIcon className={loading ? "size-4 animate-spin" : "size-4"} />
          </Button>
          <div className="flex-1" />
          <span className="text-muted-foreground text-xs">已选 {selected.size}</span>
          <Button variant="outline" onClick={runIncremental} disabled={syncing}>
            <RefreshCwIcon className={syncing ? "size-4 animate-spin" : "size-4"} /> 增量同步全部
          </Button>
          <Button onClick={runSync} disabled={syncing || selected.size === 0}>
            <DownloadIcon className={syncing ? "size-4 animate-pulse" : "size-4"} /> 同步选中
          </Button>
        </div>

        {/* 列表 */}
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-10">
                  <Checkbox checked={rows.length > 0 && selected.size === rows.length} onCheckedChange={toggleAll} />
                </TableHead>
                <TableHead>{dimension === "project" ? "项目名" : "任务名"}</TableHead>
                {dimension === "project" ? (
                  <>
                    <TableHead>标签</TableHead>
                    <TableHead className="text-right">资产数</TableHead>
                  </>
                ) : (
                  <>
                    <TableHead>状态</TableHead>
                    <TableHead>时间</TableHead>
                  </>
                )}
              </TableRow>
            </TableHeader>
            <TableBody>{renderRows()}</TableBody>
          </Table>
        </div>

        {/* 分页 */}
        <div className="flex items-center justify-end gap-2">
          <Button variant="outline" size="sm" disabled={page <= 1 || loading} onClick={() => setPage((p) => p - 1)}>
            上一页
          </Button>
          <span className="text-muted-foreground text-xs">第 {page} 页</span>
          <Button
            variant="outline"
            size="sm"
            disabled={rows.length < 50 || loading}
            onClick={() => setPage((p) => p + 1)}
          >
            下一页
          </Button>
        </div>

        {/* 结果 */}
        {result && <SyncResult result={result} />}
      </CardContent>
    </Card>
  );
}

function SyncResult({ result }: { result: Awaited<ReturnType<typeof api.reconSync>> }) {
  const synced = result.synced ?? {};
  return (
    <div className="space-y-2 rounded-md border bg-muted/40 p-3 text-sm">
      <div className="flex flex-wrap gap-3">
        {Object.entries(synced).map(([k, v]) => (
          <Badge key={k} variant="secondary">
            {typeLabels[k] ?? k}: {v}
          </Badge>
        ))}
      </div>
      {result.companies && result.companies.length > 0 && (
        <p className="text-muted-foreground">新建/更新企业：{result.companies.join("、")}</p>
      )}
      {result.warnings && result.warnings.length > 0 && (
        <ul className="list-inside list-disc text-amber-600 dark:text-amber-500">
          {result.warnings.map((wm) => (
            <li key={wm}>{wm}</li>
          ))}
        </ul>
      )}
      {result.errors && result.errors.length > 0 && (
        <ul className="list-inside list-disc text-destructive">
          {result.errors.slice(0, 20).map((em) => (
            <li key={em}>{em}</li>
          ))}
          {result.errors.length > 20 && <li>…共 {result.errors.length} 条错误</li>}
        </ul>
      )}
    </div>
  );
}
