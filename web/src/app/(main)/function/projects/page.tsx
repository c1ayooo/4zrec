"use client";

import * as React from "react";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";

import {
  EyeIcon,
  FolderIcon,
  PencilIcon,
  PlusIcon,
  RefreshCwIcon,
  ShieldCheckIcon,
  SparklesIcon,
  Trash2Icon,
} from "lucide-react";
import { toast } from "sonner";

import { ConfirmDialog } from "@/components/confirm-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { Project } from "@/lib/types";
import { useProjectStore } from "@/stores/project/project-provider";

function fmtTime(iso: string): string {
  const t = new Date(iso).getTime();
  if (!t) return "-";
  return new Date(t).toLocaleString("zh-CN", {
    year: "2-digit",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

const SCOPE_HINT =
  "一行一条，自动识别：根域名(如 example.com，含全部子域) / 单个IP / CIDR网段(如 10.0.0.0/16) / ICP备案号 / 关键词。\n护栏：拒绝裸 TLD 与过宽网段(IPv4 需 >= /16)。域名/CIDR 参与资产围栏判定，ICP/关键词仅作提示。";

export default function ProjectsPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const projects = useProjectStore((s) => s.projects);
  const projectId = useProjectStore((s) => s.projectId);
  const setProject = useProjectStore((s) => s.setProject);
  const reloadProjects = useProjectStore((s) => s.reloadProjects);
  // 页面本地列表（含编辑面板用的 scope 快照），与全局 store 同源。
  const [list, setList] = React.useState<Project[]>([]);
  const [loading, setLoading] = React.useState(true);
  // 支持外部入口带 ?create=1 直达新建弹窗(对话页项目下拉的「新建项目」跳转)。
  const [createOpen, setCreateOpen] = React.useState(() => searchParams.get("create") === "1");
  const [newName, setNewName] = React.useState("");
  const [newDesc, setNewDesc] = React.useState("");
  const [creating, setCreating] = React.useState(false);

  // 编辑态含基本信息(名称/描述)+ 范围追加
  const [edit, setEdit] = React.useState<{
    project: Project;
    name: string;
    desc: string;
    scope: string;
    reason: string;
  } | null>(null);
  const [savingInfo, setSavingInfo] = React.useState(false);
  const [savingScope, setSavingScope] = React.useState(false);
  // 从资产生成的范围候选:勾选集 + 加载态。LLM 建议(带依据)由后端合并进同一清单。
  const [candidates, setCandidates] = React.useState<{ domain: string; assets: number; llm_reason?: string }[]>([]);
  const [picked, setPicked] = React.useState<Set<string>>(new Set());
  const [loadingCandidates, setLoadingCandidates] = React.useState(false);

  // 删除项目确认框:可勾选连带删除任务/资产。
  const [deleteTarget, setDeleteTarget] = React.useState<Project | null>(null);
  const [deleteTasks, setDeleteTasks] = React.useState(false);
  const [deleteAssets, setDeleteAssets] = React.useState(false);
  const [deleting, setDeleting] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [ps, fresh] = await Promise.all([api.projects(), reloadProjects()]);
      setList(ps);
      // 全局 store 刷新后 projects 已更新；本页列表以拉取结果为准。
      if (fresh.length > 0) setList(fresh);
    } catch (e) {
      toast.error(`加载项目失败: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setLoading(false);
    }
  }, [reloadProjects]);

  React.useEffect(() => {
    void load();
  }, [load]);

  // 项目详情页向导「录入范围」深链:?edit=<id> 加载完直接打开该项目的编辑面板。
  // 用掉即清地址栏参数,刷新不会重开。
  React.useEffect(() => {
    const q = new URLSearchParams(window.location.search);
    const eid = Number(q.get("edit"));
    if (!eid) return;
    window.history.replaceState(null, "", window.location.pathname);
    void api.projects().then((ps) => {
      const p = ps.find((x) => x.id === eid);
      if (p) openEdit(p);
    });
    // biome-ignore lint/correctness/useExhaustiveDependencies: openEdit 是组件内稳定函数,只在深链时跑一次。
  }, []);

  const createProject = async () => {
    const name = newName.trim();
    if (!name) return;
    setCreating(true);
    try {
      const created = await api.createProject(name, null, newDesc.trim());
      toast.success(`项目「${name}」已创建`);
      setCreateOpen(false);
      setNewName("");
      setNewDesc("");
      await load();
      // Cooper 链路:新建即切换,并跳到该项目的任务界面。
      if (created?.id) {
        setProject(created.id);
        router.push(`/function/tasks?project_id=${created.id}`);
      }
    } catch (e) {
      toast.error(`创建失败: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setCreating(false);
    }
  };

  const openEdit = (p: Project) => {
    setCandidates([]);
    setPicked(new Set());
    setEdit({
      project: p,
      name: p.name,
      desc: p.description ?? "",
      scope: "",
      reason: "",
    });
  };

  // 从资产生成范围候选:拉取预览并默认全选(生成的是发现实证,人工可再剔)。
  const loadCandidates = async (projectID: number) => {
    setLoadingCandidates(true);
    try {
      const list = await api.scopeCandidates(projectID);
      setCandidates(list);
      setPicked(new Set(list.map((c) => c.domain)));
    } catch (e) {
      toast.error(`生成候选失败: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setLoadingCandidates(false);
    }
  };

  // 导入勾选的候选 → 范围,随后触发认领(后端联动),刷新视图。
  const importCandidates = async () => {
    if (!edit || picked.size === 0) return;
    setSavingScope(true);
    try {
      const domains = candidates.filter((c) => picked.has(c.domain)).map((c) => c.domain);
      const r = await api.importScope(edit.project.id, domains, edit.reason.trim() || "从项目资产自动生成");
      if (r.invalid > 0) {
        toast.warning(`导入 ${r.added} 条,${r.invalid} 条无效被跳过`, {
          description: r.errors?.slice(0, 3).join("\n"),
        });
      } else {
        toast.success(`已导入 ${r.added} 条范围,认领 ${r.claimed} 条资产归属本项目`);
      }
      setCandidates([]);
      setPicked(new Set());
      await load();
      const fresh = await api.projects();
      const p = fresh.find((x) => x.id === edit.project.id);
      if (p) setEdit((v) => (v ? { ...v, project: p } : v));
    } catch (e) {
      toast.error(`导入失败: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setSavingScope(false);
    }
  };

  // 保存基本信息(名称/描述/归属企业)。PATCH 是整体替换:name/description 必须
  // 回填,status 不改也要带上(服务端缺省会强制回 active);company "" → 0 = 解绑。
  const saveInfo = async () => {
    if (!edit) return;
    const name = edit.name.trim();
    if (!name) {
      toast.error("项目名称不能为空");
      return;
    }
    setSavingInfo(true);
    try {
      const updated = await api.updateProject(edit.project.id, {
        name,
        company_id: null, // 企业概念已移除:保存不再携带(0 会撞外键)
        description: edit.desc.trim(),
        status: edit.project.status,
      });
      toast.success("项目信息已保存");
      await load();
      setEdit((v) => (v ? { ...v, project: updated } : v));
    } catch (e) {
      toast.error(`保存失败: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setSavingInfo(false);
    }
  };

  const openDelete = (p: Project) => {
    setDeleteTarget(p);
    setDeleteTasks(false);
    setDeleteAssets(false);
  };

  // 卡片上的「切换到此项目」:写全局上下文并跳到该项目的任务界面。
  const switchTo = (p: Project) => {
    setProject(p.id);
    toast.success(`已切到项目「${p.name}」`);
    router.push(`/function/tasks?project_id=${p.id}`);
  };

  const confirmDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      const r = await api.deleteProject(deleteTarget.id, { deleteTasks, deleteAssets });
      const extra = [
        r.deleted_tasks ? `任务 ${r.deleted_tasks}` : "",
        r.deleted_assets ? `资产 ${r.deleted_assets}` : "",
      ]
        .filter(Boolean)
        .join(" · ");
      toast.success(extra ? `项目已删除（${extra}）` : "项目已删除");
      setDeleteTarget(null);
      await load();
      // 全局 store 同步:若删的是当前项目,自动回落到第一个项目。
      await reloadProjects();
    } catch (e) {
      toast.error(`删除失败: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setDeleting(false);
    }
  };

  const saveScope = async () => {
    if (!edit) return;
    setSavingScope(true);
    try {
      const r = await api.addProjectScope(edit.project.id, edit.scope, edit.reason);
      if (r.invalid > 0) {
        toast.warning(`新增 ${r.added} 条，${r.invalid} 条无效被跳过`, {
          description: r.errors?.slice(0, 3).join("\n"),
        });
      } else if (r.claimed > 0) {
        toast.success(`范围已更新：新增 ${r.added} 条，已认领/授权 ${r.claimed} 条命中资产（含原待审批）`);
      } else {
        toast.success(`范围已更新：新增 ${r.added} 条`);
      }
      setEdit(null);
      await load();
    } catch (e) {
      toast.error(`保存失败: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setSavingScope(false);
    }
  };

  const removeScope = async (p: Project, sid: number) => {
    try {
      await api.deleteProjectScope(p.id, sid);
      await load();
    } catch (e) {
      toast.error(`删除失败: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">项目管理</h1>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
            <RefreshCwIcon className={loading ? "animate-spin" : undefined} />
            刷新
          </Button>
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <PlusIcon />
            新建项目
          </Button>
        </div>
      </div>

      {/* 项目列表 */}
      {loading ? (
        <div className="flex flex-col gap-3">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      ) : list.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyTitle>还没有项目</EmptyTitle>
            <EmptyDescription>创建一个项目并录入授权范围，任务/对话挂到项目下即启用资产围栏。</EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
          {list.map((p) => {
            const isCurrent = p.id === projectId;
            return (
              <Card key={p.id} className={isCurrent ? "border-primary ring-primary/30 ring-2" : undefined}>
                <CardContent className="flex flex-col gap-2">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <FolderIcon className="text-muted-foreground size-4 shrink-0" />
                        <Link
                          href={`/function/projects/detail?id=${p.id}`}
                          className="truncate font-medium hover:underline"
                        >
                          {p.name}
                        </Link>
                        {isCurrent ? (
                          <Badge className="shrink-0">
                            <ShieldCheckIcon className="size-3" /> 使用中
                          </Badge>
                        ) : null}
                        {p.status === "archived" && <Badge variant="secondary">已归档</Badge>}
                      </div>
                      {p.description && (
                        <p className="text-muted-foreground mt-1 line-clamp-2 text-xs">{p.description}</p>
                      )}
                    </div>
                    <div className="flex shrink-0 gap-1">
                      <Button variant="ghost" size="icon" className="size-7" asChild title="详情(任务/资产/漏洞聚合)">
                        <Link href={`/function/projects/detail?id=${p.id}`}>
                          <EyeIcon />
                        </Link>
                      </Button>
                      <Button
                        aria-label="编辑项目"
                        variant="ghost"
                        size="icon"
                        className="size-7"
                        onClick={() => openEdit(p)}
                      >
                        <PencilIcon />
                      </Button>
                      <Button
                        aria-label="删除项目"
                        variant="ghost"
                        size="icon"
                        className="size-7"
                        onClick={() => openDelete(p)}
                      >
                        <Trash2Icon />
                      </Button>
                    </div>
                  </div>
                  <div className="text-muted-foreground flex gap-3 text-xs">
                    <span>资产 {p.asset_count}</span>
                    {p.pending_count > 0 ? (
                      <Link
                        href={`/function/approvals?project_id=${p.id}`}
                        className="font-medium text-warning hover:underline"
                        title="待审批资产在「安全与审批 → 资产审批」处理"
                      >
                        待审批 {p.pending_count}
                      </Link>
                    ) : (
                      <span>待审批 0</span>
                    )}
                    <span>任务 {p.task_count}</span>
                    <span>范围 {p.scope?.length ?? 0} 条</span>
                  </div>
                  {p.scope?.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {p.scope.slice(0, 2).map((r) => (
                        <Badge key={r.id} variant="outline" className="font-mono text-[11px]">
                          {r.raw}
                        </Badge>
                      ))}
                      {p.scope.length > 2 && (
                        <Badge variant="secondary" className="text-[11px]">
                          +{p.scope.length - 2}
                        </Badge>
                      )}
                    </div>
                  )}
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-muted-foreground text-xs">创建于 {fmtTime(p.created_at)}</span>
                    {isCurrent ? (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => router.push(`/function/tasks?project_id=${p.id}`)}
                      >
                        去任务界面
                      </Button>
                    ) : (
                      <Button size="sm" variant="outline" onClick={() => switchTo(p)}>
                        切换到此项目
                      </Button>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* 新建对话框 */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>新建项目</DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-3">
            <Input
              placeholder="项目名称（如：XX单位渗透测试）"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
            />
            <Input placeholder="描述（可选）" value={newDesc} onChange={(e) => setNewDesc(e.target.value)} />
            <p className="text-muted-foreground text-xs">
              创建后进入编辑录入授权范围；任务/对话挂到该项目即启用资产围栏。
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              取消
            </Button>
            <Button onClick={() => void createProject()} disabled={!newName.trim() || creating}>
              创建
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 项目设置弹窗(居中卡片):基本信息 + 授权范围 + 已有范围 */}
      <Dialog open={!!edit} onOpenChange={(o) => !o && setEdit(null)}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>项目设置 — {edit?.project.name}</DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-2 border-b pb-4">
            <p className="text-sm font-medium">基本信息</p>
            <Input
              placeholder="项目名称"
              value={edit?.name ?? ""}
              onChange={(e) => setEdit((v) => (v ? { ...v, name: e.target.value } : v))}
            />
            <Input
              placeholder="描述（可选）"
              value={edit?.desc ?? ""}
              onChange={(e) => setEdit((v) => (v ? { ...v, desc: e.target.value } : v))}
            />
            <p className="text-muted-foreground text-xs" />
            <div className="flex justify-end">
              <Button size="sm" onClick={() => void saveInfo()} disabled={!edit?.name.trim() || savingInfo}>
                {savingInfo ? "保存中…" : "保存信息"}
              </Button>
            </div>
          </div>
          <div>
            <div className="mb-2 flex items-center justify-between">
              <p className="text-sm font-medium">授权范围（围栏白名单）</p>
              <Button
                size="sm"
                variant="outline"
                disabled={loadingCandidates || !edit}
                onClick={() => edit && void loadCandidates(edit.project.id)}
              >
                <SparklesIcon className={loadingCandidates ? "animate-pulse" : undefined} />
                从资产生成
              </Button>
            </div>
            {candidates.length > 0 && (
              <div className="mb-3 rounded-md border p-2">
                <div className="text-muted-foreground mb-2 flex items-center justify-between text-xs">
                  <span>
                    从项目 {candidates.length} 个资产根域生成,默认全选——确认后写入即自动认领命中的待审批资产。
                  </span>
                  <span className="flex shrink-0 gap-2">
                    <button
                      className="hover:text-foreground"
                      onClick={() => setPicked(new Set(candidates.map((c) => c.domain)))}
                    >
                      全选
                    </button>
                    <button className="hover:text-foreground" onClick={() => setPicked(new Set())}>
                      清空
                    </button>
                  </span>
                </div>
                <div className="grid max-h-40 grid-cols-1 gap-1 overflow-y-auto sm:grid-cols-2">
                  {candidates.map((c) => (
                    <label
                      key={c.domain}
                      className="flex cursor-pointer items-center gap-2 rounded px-1 py-0.5 text-sm hover:bg-muted/60"
                      title={c.llm_reason || ""}
                    >
                      <Checkbox
                        checked={picked.has(c.domain)}
                        onCheckedChange={(v) =>
                          setPicked((prev) => {
                            const next = new Set(prev);
                            if (v === true) next.add(c.domain);
                            else next.delete(c.domain);
                            return next;
                          })
                        }
                      />
                      <span className="truncate font-mono text-xs">{c.domain}</span>
                      {c.llm_reason && (
                        <Badge variant="outline" className="shrink-0 text-[11px] font-normal text-info">
                          LLM
                        </Badge>
                      )}
                      <span className="text-muted-foreground ml-auto shrink-0 text-xs">
                        {(c.assets ?? 0) > 0 ? c.assets : ""}
                      </span>
                    </label>
                  ))}
                </div>
                <div className="mt-2 flex justify-end">
                  <Button size="sm" onClick={() => void importCandidates()} disabled={picked.size === 0 || savingScope}>
                    {savingScope ? "导入中…" : `导入选中 (${picked.size})`}
                  </Button>
                </div>
              </div>
            )}
            <p className="text-muted-foreground mb-2 text-xs whitespace-pre-line">{SCOPE_HINT}</p>
            <Textarea
              rows={5}
              placeholder={"example.com\n10.0.0.0/16\n203.0.113.7"}
              value={edit?.scope ?? ""}
              onChange={(e) => setEdit((v) => (v ? { ...v, scope: e.target.value } : v))}
            />
            <Input
              className="mt-2"
              placeholder="归属依据（可选，建议填写，如：合同编号/委托书）"
              value={edit?.reason ?? ""}
              onChange={(e) => setEdit((v) => (v ? { ...v, reason: e.target.value } : v))}
            />
            <div className="mt-3 flex justify-end">
              <Button size="sm" onClick={() => void saveScope()} disabled={!edit?.scope.trim() || savingScope}>
                {savingScope ? "保存中…" : "追加范围"}
              </Button>
            </div>
          </div>
          <div>
            <p className="mb-2 text-sm font-medium">已有范围（{edit?.project.scope?.length ?? 0}）</p>
            <div className="flex flex-col gap-1">
              {edit?.project.scope?.map((r) => (
                <div key={r.id} className="flex items-center justify-between gap-2 rounded-md border px-2 py-1.5">
                  <div className="min-w-0">
                    <span className="font-mono text-sm">{r.raw}</span>
                    <span className="text-muted-foreground ml-2 text-xs">
                      {r.kind === "domain"
                        ? "域名"
                        : r.kind === "icp"
                          ? "ICP"
                          : r.kind === "keyword"
                            ? "关键词"
                            : r.kind === "ip"
                              ? "IP"
                              : "CIDR"}
                      {r.reason ? ` · ${r.reason}` : ""}
                    </span>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-7 shrink-0"
                    onClick={() => void removeScope(edit.project, r.id)}
                  >
                    <Trash2Icon />
                  </Button>
                </div>
              ))}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEdit(null)}>
              取消
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 删除项目：可勾选连带删除任务/资产 */}
      <Dialog open={!!deleteTarget} onOpenChange={(open) => (!open ? setDeleteTarget(null) : undefined)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>删除项目</DialogTitle>
            <DialogDescription>
              删除「{deleteTarget?.name}」不可撤销。范围规则和项目级 API Key 会随项目一起删除。
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-3">
            <label className="flex items-start gap-2 rounded-md border p-3">
              <Checkbox checked={deleteTasks} onCheckedChange={(v) => setDeleteTasks(v === true)} className="mt-0.5" />
              <span>
                <span className="text-sm font-medium">同时删除该项目的任务（{deleteTarget?.task_count ?? 0} 个）</span>
                <span className="text-muted-foreground mt-0.5 block text-xs">
                  不勾选：任务保留，但解除项目归属（资产围栏不再生效）。
                </span>
              </span>
            </label>
            <label className="flex items-start gap-2 rounded-md border p-3">
              <Checkbox
                checked={deleteAssets}
                onCheckedChange={(v) => setDeleteAssets(v === true)}
                className="mt-0.5"
              />
              <span>
                <span className="text-sm font-medium">同时删除该项目的资产（{deleteTarget?.asset_count ?? 0} 条）</span>
                <span className="text-muted-foreground mt-0.5 block text-xs">
                  不勾选：资产保留，但变为未归属。已关联到任务的资产不会被单独删除。
                </span>
              </span>
            </label>
            {deleteTarget && (deleteTarget.task_count > 0 || deleteTarget.asset_count > 0) ? (
              <p className="text-muted-foreground text-xs">
                当前项目有 {deleteTarget.task_count} 个任务、{deleteTarget.asset_count} 条资产。
              </p>
            ) : null}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>
              取消
            </Button>
            <Button variant="destructive" onClick={() => void confirmDelete()} disabled={deleting}>
              {deleting ? "删除中…" : "确认删除"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
