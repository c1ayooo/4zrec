"use client";

import * as React from "react";

import { ArrowDownToLineIcon, Loader2Icon, RefreshCwIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import type { AssetSyncResult, AssetSyncSourceProject, Project } from "@/lib/types";

import { ZrearkConnectionBar } from "./zreark-connection-bar";

// 资产同步弹窗：通过 4zreark 的 MCP 接口读取站点，写入 4zrec 的 service 资产。
// 连接信息（地址 + API Key）持久化在 4zrec，连接条里管理，操作不再需要每次粘贴 key。
// 可选同时拉取站点路由（爬虫沉淀的 site_routes）落成 endpoint 资产。
export function AssetSyncDialog({ projects, onSynced }: { projects: Project[]; onSynced: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [configured, setConfigured] = React.useState(false);
  const [sourceProjects, setSourceProjects] = React.useState<AssetSyncSourceProject[]>([]);
  const [sourceProjectID, setSourceProjectID] = React.useState("all");
  const [targetProjectID, setTargetProjectID] = React.useState("0");
  const [catalog, setCatalog] = React.useState<"all" | "verified">("all");
  const [limit, setLimit] = React.useState("500");
  const [includeRoutes, setIncludeRoutes] = React.useState(true);
  const [busy, setBusy] = React.useState<"projects" | "preview" | "sync" | null>(null);
  const [preview, setPreview] = React.useState<AssetSyncResult | null>(null);
  const [result, setResult] = React.useState<AssetSyncResult | null>(null);
  const [error, setError] = React.useState("");

  const working = busy !== null;

  function resetLoaded() {
    setSourceProjects([]);
    setSourceProjectID("all");
    setPreview(null);
    setResult(null);
    setError("");
  }

  async function loadProjects() {
    if (!configured || working) return;
    setBusy("projects");
    setError("");
    setPreview(null);
    setResult(null);
    try {
      const res = await api.assetSyncProjects({});
      const items = res.projects ?? [];
      setSourceProjects(items);
      if (items.length === 1) setSourceProjectID(String(items[0].id));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  async function run(dryRun: boolean) {
    if (!configured || working) return;
    setBusy(dryRun ? "preview" : "sync");
    setError("");
    if (dryRun) setPreview(null);
    else setResult(null);
    try {
      const res = await api.assetSync({
        source_project_id: sourceProjectID === "all" ? 0 : Number(sourceProjectID),
        target_project_id: Number(targetProjectID) || 0,
        catalog,
        limit: Number(limit) || 500,
        dry_run: dryRun,
        include_routes: includeRoutes,
      });
      if (dryRun) {
        setPreview(res);
      } else {
        setResult(res);
        onSynced();
        toast.success(`已同步 ${res.imported} 条资产`);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) {
          setPreview(null);
          setResult(null);
          setError("");
        }
      }}
    >
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          <ArrowDownToLineIcon className="size-4" /> 资产同步
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>从 4zreark 同步资产</DialogTitle>
          <DialogDescription>
            通过 4zreark 的 MCP 接口读取站点资产，写入 4zrec 资产库。重复站点会按 URL 合并。
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4">
          <ZrearkConnectionBar
            onChanged={(cfg) => {
              setConfigured(cfg.configured);
              if (!cfg.configured) resetLoaded();
            }}
          />

          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => void loadProjects()} disabled={!configured || working}>
              {busy === "projects" ? (
                <Loader2Icon className="size-4 animate-spin" />
              ) : (
                <RefreshCwIcon className="size-4" />
              )}
              读取项目
            </Button>
            <span className="text-muted-foreground text-xs">
              在 4zreark「系统设置 → MCP 接入」创建带 assets:read 的 Key，填到上方连接配置即可长期使用。
            </span>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label>源项目</Label>
              <Select
                value={sourceProjectID}
                onValueChange={(value) => {
                  setSourceProjectID(value);
                  setPreview(null);
                  setResult(null);
                }}
              >
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="源项目" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部项目</SelectItem>
                  {sourceProjects.map((project) => (
                    <SelectItem key={project.id} value={String(project.id)}>
                      {project.name}
                      {typeof project.asset_count === "number" ? ` · ${project.asset_count} 资产` : ""}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label>写入 4zrec 项目</Label>
              <Select
                value={targetProjectID}
                onValueChange={(value) => {
                  setTargetProjectID(value);
                  setPreview(null);
                  setResult(null);
                }}
              >
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="目标项目" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="0">不归属项目</SelectItem>
                  {projects.map((project) => (
                    <SelectItem key={project.id} value={String(project.id)}>
                      {project.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label>同步范围</Label>
              <Select
                value={catalog}
                onValueChange={(value) => {
                  setCatalog(value as "all" | "verified");
                  setPreview(null);
                  setResult(null);
                }}
              >
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部站点</SelectItem>
                  <SelectItem value="verified">仅已确认站点</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="asset-sync-limit">最多同步条数</Label>
              <Input
                id="asset-sync-limit"
                type="number"
                min={1}
                max={5000}
                value={limit}
                onChange={(e) => {
                  setLimit(e.target.value);
                  setPreview(null);
                  setResult(null);
                }}
              />
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Switch id="asset-sync-routes" checked={includeRoutes} onCheckedChange={setIncludeRoutes} />
            <Label htmlFor="asset-sync-routes" className="cursor-pointer font-normal">
              同时同步站点路由
              <span className="text-muted-foreground ml-2 text-xs">
                爬虫沉淀的路由（site_routes）落成 endpoint 资产，仅对有路由的站点逐站拉取
              </span>
            </Label>
          </div>

          {error ? <p className="text-destructive text-sm">{error}</p> : null}
          {result ? <SyncSummary result={result} /> : preview ? <SyncSummary result={preview} /> : null}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => void run(true)} disabled={!configured || working}>
            {busy === "preview" ? <Loader2Icon className="size-4 animate-spin" /> : null}
            预览
          </Button>
          <Button onClick={() => void run(false)} disabled={!configured || working}>
            {busy === "sync" ? <Loader2Icon className="size-4 animate-spin" /> : null}
            开始同步
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function SyncSummary({ result }: { result: AssetSyncResult }) {
  return (
    <div className="bg-muted/20 rounded-lg border p-3 text-sm">
      <div className="flex flex-wrap gap-x-4 gap-y-1 tabular-nums">
        <span>源端 {result.total} 项</span>
        <span>读取 {result.fetched} 项</span>
        <span>可导入 {result.would_import} 项</span>
        {!result.dry_run ? <span className="font-medium">已写入 {result.imported} 项</span> : null}
        {!result.dry_run && result.routes > 0 ? <span>路由 {result.routes} 条</span> : null}
        {!result.dry_run && result.assigned > 0 ? <span>归属项目 {result.assigned} 项</span> : null}
        {result.skipped > 0 ? <span className="text-warning">跳过 {result.skipped} 项</span> : null}
      </div>
      {result.sample.length > 0 ? (
        <div className="mt-2 space-y-1 border-t pt-2 text-xs">
          {result.sample.map((item) => (
            <div key={`${item.url}-${item.host}`} className="flex items-center justify-between gap-2">
              <span className="truncate font-mono">{item.url}</span>
              <span className="text-muted-foreground shrink-0 tabular-nums">{item.status_code || "—"}</span>
            </div>
          ))}
        </div>
      ) : null}
      {result.errors.length > 0 ? (
        <ul className="text-destructive mt-2 space-y-0.5 border-t pt-2 text-xs">
          {result.errors.map((message, index) => (
            <li key={`${index}-${message}`}>{message}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
