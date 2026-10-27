"use client";

import * as React from "react";

import { CopyIcon, KeyRoundIcon, PlusIcon, RefreshCwIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { ConfirmDialog } from "@/components/confirm-dialog";
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
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { APIKeyRecord, Project } from "@/lib/types";

function fmtTime(v?: string): string {
  if (!v) return "—";
  return new Date(v).toLocaleString("zh-CN", {
    year: "2-digit",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function keyState(k: APIKeyRecord): { label: string; variant: "default" | "secondary" | "destructive" | "outline" } {
  if (!k.enabled) return { label: "已禁用", variant: "secondary" };
  if (k.expires_at && new Date(k.expires_at).getTime() < Date.now()) {
    return { label: "已过期", variant: "destructive" };
  }
  return { label: "有效", variant: "default" };
}

// API 密钥:给 Hermes 等外部 agent 的持久凭据。明文只显示一次;
// scope=global 全平台,scope=project 只能访问绑定项目的业务数据。
export default function APIKeysPage() {
  const [keys, setKeys] = React.useState<APIKeyRecord[]>([]);
  const [projects, setProjects] = React.useState<Project[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [createOpen, setCreateOpen] = React.useState(false);
  const [creating, setCreating] = React.useState(false);
  const [deleting, setDeleting] = React.useState(0);
  const [revokeTarget, setRevokeTarget] = React.useState<APIKeyRecord | null>(null);
  const [created, setCreated] = React.useState<{ key: APIKeyRecord; token: string } | null>(null);
  const [form, setForm] = React.useState({
    name: "",
    scope: "project" as "global" | "project",
    project_id: "",
    expires_in_days: "365",
  });

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [ks, ps] = await Promise.all([api.apiKeys(), api.projects()]);
      setKeys(ks);
      setProjects(ps.filter((p) => p.status === "active"));
    } catch (e) {
      toast.error(`加载失败：${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const projectName = (id?: number) => projects.find((p) => p.id === id)?.name ?? (id ? `#${id}` : "—");

  const create = async () => {
    const name = form.name.trim();
    if (!name) {
      toast.error("名称不能为空");
      return;
    }
    if (form.scope === "project" && !form.project_id) {
      toast.error("项目级密钥必须选择项目");
      return;
    }
    setCreating(true);
    try {
      const res = await api.createAPIKey({
        name,
        scope: form.scope,
        project_id: form.scope === "project" ? Number(form.project_id) : undefined,
        expires_in_days: Number(form.expires_in_days) || 0,
      });
      setCreated(res);
      setCreateOpen(false);
      setForm({ name: "", scope: "project", project_id: "", expires_in_days: "365" });
      await load();
    } catch (e) {
      toast.error(`创建失败：${(e as Error).message}`);
    } finally {
      setCreating(false);
    }
  };

  const revoke = async () => {
    if (!revokeTarget) return;
    setDeleting(revokeTarget.id);
    try {
      await api.deleteAPIKey(revokeTarget.id);
      toast.success("已撤销");
      setRevokeTarget(null);
      await load();
    } catch (e) {
      toast.error(`撤销失败：${(e as Error).message}`);
    } finally {
      setDeleting(0);
    }
  };

  const copyToken = async () => {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.token);
      toast.success("已复制");
    } catch {
      toast.error("复制失败，请手动选择复制");
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">API 密钥</h1>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
            <RefreshCwIcon className={loading ? "animate-spin" : undefined} />
            刷新
          </Button>
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <PlusIcon />
            新建密钥
          </Button>
        </div>
      </div>

      <Card>
        <CardContent className="px-0">
          {loading ? (
            <div className="flex flex-col gap-3">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : keys.length === 0 ? (
            <Empty>
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <KeyRoundIcon />
                </EmptyMedia>
                <EmptyTitle>还没有 API 密钥</EmptyTitle>
                <EmptyDescription>新建一个项目级密钥给外部 agent 使用。</EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>名称</TableHead>
                  <TableHead>前缀</TableHead>
                  <TableHead>范围</TableHead>
                  <TableHead>项目</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>有效期</TableHead>
                  <TableHead>最后使用</TableHead>
                  <TableHead>创建时间</TableHead>
                  <TableHead className="text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {keys.map((k) => {
                  const st = keyState(k);
                  return (
                    <TableRow key={k.id}>
                      <TableCell className="font-medium">{k.name}</TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{k.prefix}…</TableCell>
                      <TableCell>
                        <Badge variant={k.scope === "global" ? "outline" : "secondary"}>
                          {k.scope === "global" ? "全局" : "项目级"}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm">
                        {k.scope === "global" ? "—" : projectName(k.project_id)}
                      </TableCell>
                      <TableCell>
                        <Badge variant={st.variant}>{st.label}</Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground text-sm">
                        {k.expires_at ? fmtTime(k.expires_at) : "永不过期"}
                      </TableCell>
                      <TableCell className="text-muted-foreground text-sm">{fmtTime(k.last_used_at)}</TableCell>
                      <TableCell className="text-muted-foreground text-sm">{fmtTime(k.created_at)}</TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={deleting === k.id}
                          onClick={() => setRevokeTarget(k)}
                        >
                          <Trash2Icon className="text-destructive" />
                          撤销
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* 新建 */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>新建 API 密钥</DialogTitle>
            <DialogDescription>创建后明文只显示一次；请立即保存到 Hermes 的安全配置里。</DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="key-name">名称</Label>
              <Input
                id="key-name"
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="hermes-huya"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label>权限范围</Label>
              <Select
                value={form.scope}
                onValueChange={(v) => setForm((f) => ({ ...f, scope: v as "global" | "project" }))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="project">项目级（只能访问绑定项目）</SelectItem>
                    <SelectItem value="global">全局（全平台）</SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
            </div>
            {form.scope === "project" ? (
              <div className="flex flex-col gap-1.5">
                <Label>绑定项目</Label>
                <Select value={form.project_id} onValueChange={(v) => setForm((f) => ({ ...f, project_id: v }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="选择项目…" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      {projects.map((p) => (
                        <SelectItem key={p.id} value={String(p.id)}>
                          {p.name}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </div>
            ) : null}
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="key-expires">有效期（天）</Label>
              <Input
                id="key-expires"
                type="number"
                min="0"
                value={form.expires_in_days}
                onChange={(e) => setForm((f) => ({ ...f, expires_in_days: e.target.value }))}
              />
              <p className="text-muted-foreground text-xs">0 = 永不过期；建议按委托周期设置。</p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              取消
            </Button>
            <Button onClick={() => void create()} disabled={creating}>
              {creating ? "创建中…" : "创建"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 撤销确认(统一弹窗) */}
      <ConfirmDialog
        open={revokeTarget !== null}
        onOpenChange={(open) => (!open ? setRevokeTarget(null) : undefined)}
        title="撤销 API 密钥"
        description={`撤销「${revokeTarget?.name ?? ""}」？使用该 token 的调用会立即失效，且无法恢复。`}
        confirmText="撤销"
        destructive
        busy={deleting !== 0}
        onConfirm={() => void revoke()}
      />

      {/* 一次性展示 token */}
      <Dialog open={!!created} onOpenChange={(open) => (!open ? setCreated(null) : undefined)}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>密钥已创建</DialogTitle>
            <DialogDescription>这是明文 token 的唯一一次展示，关闭后无法再次查看。请立即保存。</DialogDescription>
          </DialogHeader>
          <div className="min-w-0 rounded-lg border bg-muted/40 p-3">
            <p className="break-all font-mono text-xs">{created?.token}</p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => void copyToken()}>
              <CopyIcon data-icon="inline-start" />
              复制 token
            </Button>
            <Button onClick={() => setCreated(null)}>我已保存</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
