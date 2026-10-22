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
import { api } from "@/lib/api";
import { getLocalStorageValue, setLocalStorageValue } from "@/lib/local-storage.client";
import type { AssetSyncResult, AssetSyncSourceProject, Project } from "@/lib/types";

const BASE_URL_KEY = "4zrec_asset_sync_base_url";
const DEFAULT_BASE_URL = "http://127.0.0.1:8080";

// 资产同步弹窗：通过 4zreark 的 MCP 接口读取站点，写入 4zrec 的 service 资产。
// API Key 只保存在组件内存里，仅随本次请求发给 4zrec 后端。
export function AssetSyncDialog({ projects, onSynced }: { projects: Project[]; onSynced: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [baseURL, setBaseURL] = React.useState(() => getLocalStorageValue(BASE_URL_KEY) ?? DEFAULT_BASE_URL);
  const [apiKey, setAPIKey] = React.useState("");
  const [sourceProjects, setSourceProjects] = React.useState<AssetSyncSourceProject[]>([]);
  const [sourceProjectID, setSourceProjectID] = React.useState("all");
  const [targetProjectID, setTargetProjectID] = React.useState("0");
  const [catalog, setCatalog] = React.useState<"all" | "verified">("all");
  const [limit, setLimit] = React.useState("500");
  const [busy, setBusy] = React.useState<"projects" | "preview" | "sync" | null>(null);
  const [preview, setPreview] = React.useState<AssetSyncResult | null>(null);
  const [result, setResult] = React.useState<AssetSyncResult | null>(null);
  const [error, setError] = React.useState("");

  const canConnect = baseURL.trim() !== "" && apiKey.trim() !== "";
  const working = busy !== null;

  function resetLoaded() {
    setSourceProjects([]);
    setSourceProjectID("all");
    setPreview(null);
    setResult(null);
    setError("");
  }

  async function loadProjects() {
    if (!canConnect || working) return;
    setBusy("projects");
    setError("");
    setPreview(null);
    setResult(null);
    try {
      const res = await api.assetSyncProjects({ base_url: baseURL.trim(), api_key: apiKey.trim() });
      const items = res.projects ?? [];
      setSourceProjects(items);
      if (items.length === 1) setSourceProjectID(String(items[0].id));
      setLocalStorageValue(BASE_URL_KEY, baseURL.trim());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  async function run(dryRun: boolean) {
    if (!canConnect || working) return;
    setBusy(dryRun ? "preview" : "sync");
    setError("");
    if (dryRun) setPreview(null);
    else setResult(null);
    try {
      const res = await api.assetSync({
        base_url: baseURL.trim(),
        api_key: apiKey.trim(),
        source_project_id: sourceProjectID === "all" ? 0 : Number(sourceProjectID),
        target_project_id: Number(targetProjectID) || 0,
        catalog,
        limit: Number(limit) || 500,
        dry_run: dryRun,
      });
      setLocalStorageValue(BASE_URL_KEY, baseURL.trim());
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
          setAPIKey("");
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
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="asset-sync-base">4zreark 地址</Label>
              <Input
                id="asset-sync-base"
                value={baseURL}
                placeholder={DEFAULT_BASE_URL}
                onChange={(e) => {
                  setBaseURL(e.target.value);
                  resetLoaded();
                }}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="asset-sync-key">API Key</Label>
              <Input
                id="asset-sync-key"
                type="password"
                autoComplete="off"
                value={apiKey}
                placeholder="zr_..."
                onChange={(e) => {
                  setAPIKey(e.target.value);
                  resetLoaded();
                }}
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => void loadProjects()} disabled={!canConnect || working}>
              {busy === "projects" ? (
                <Loader2Icon className="size-4 animate-spin" />
              ) : (
                <RefreshCwIcon className="size-4" />
              )}
              读取项目
            </Button>
            <span className="text-muted-foreground text-xs">
              在 4zreark「系统设置 → MCP 接入」创建带 assets:read 的 Key；Key 只用于本次请求。
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

          {error ? <p className="text-destructive text-sm">{error}</p> : null}
          {result ? <SyncSummary result={result} /> : preview ? <SyncSummary result={preview} /> : null}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => void run(true)} disabled={!canConnect || working}>
            {busy === "preview" ? <Loader2Icon className="size-4 animate-spin" /> : null}
            预览
          </Button>
          <Button onClick={() => void run(false)} disabled={!canConnect || working}>
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
        {!result.dry_run && result.assigned > 0 ? <span>归属项目 {result.assigned} 项</span> : null}
        {result.skipped > 0 ? (
          <span className="text-amber-700 dark:text-amber-300">跳过 {result.skipped} 项</span>
        ) : null}
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
