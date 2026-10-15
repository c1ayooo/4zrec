"use client";

import * as React from "react";
import Link from "next/link";
import {
  CheckIcon,
  FolderIcon,
  PencilIcon,
  PlusIcon,
  RefreshCwIcon,
  ShieldAlertIcon,
  SparklesIcon,
  Trash2Icon,
  XIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Sheet,
  SheetContent,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { api } from "@/lib/api";
import type { Asset, Company, Project } from "@/lib/types";

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

function assetTarget(a: Asset): string {
  return a.domain || a.url || a.ip || `#${a.id}`;
}

const SCOPE_HINT =
  "一行一条，自动识别：根域名(如 example.com，含全部子域) / 单个IP / CIDR网段(如 10.0.0.0/16) / ICP备案号 / 关键词。\n护栏：拒绝裸 TLD 与过宽网段(IPv4 需 >= /16)。域名/CIDR 参与资产围栏判定，ICP/关键词仅作提示。";

export default function ProjectsPage() {
  const [projects, setProjects] = React.useState<Project[]>([]);
  const [companies, setCompanies] = React.useState<Company[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [createOpen, setCreateOpen] = React.useState(false);
  const [newName, setNewName] = React.useState("");
  const [newDesc, setNewDesc] = React.useState("");
  // "" = 不绑定企业;String(company.id) = 创建时挂到该企业
  const [newCompany, setNewCompany] = React.useState("");
  const [creating, setCreating] = React.useState(false);

  // 编辑态含基本信息(名称/描述/归属企业)+ 范围追加;company ""=解绑(发 0)
  const [edit, setEdit] = React.useState<{
    project: Project;
    name: string;
    desc: string;
    company: string;
    scope: string;
    reason: string;
  } | null>(null);
  const [savingInfo, setSavingInfo] = React.useState(false);
  const [savingScope, setSavingScope] = React.useState(false);
  // 从资产生成的范围候选:勾选集 + 加载态。LLM 建议(带依据)由后端合并进同一清单。
  const [candidates, setCandidates] = React.useState<{ domain: string; assets: number; llm_reason?: string }[]>([]);
  const [picked, setPicked] = React.useState<Set<string>>(new Set());
  const [loadingCandidates, setLoadingCandidates] = React.useState(false);

  const [pending, setPending] = React.useState<Asset[]>([]);
  const [pendingTotal, setPendingTotal] = React.useState(0);
  const [pendingProject, setPendingProject] = React.useState(0);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [ps, cs] = await Promise.all([api.projects(), api.companies()]);
      setProjects(ps);
      setCompanies(cs);
    } catch (e) {
      toast.error(`加载项目失败: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadPending = React.useCallback(async (projectID: number) => {
    try {
      const r = await api.pendingAssets(projectID, 100, 0);
      setPending(r.assets);
      setPendingTotal(r.total);
    } catch (e) {
      toast.error(`加载待审批失败: ${e instanceof Error ? e.message : String(e)}`);
    }
  }, []);

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

  React.useEffect(() => {
    void loadPending(pendingProject);
  }, [pendingProject, loadPending]);

  const createProject = async () => {
    const name = newName.trim();
    if (!name) return;
    setCreating(true);
    try {
      await api.createProject(name, newCompany ? Number(newCompany) : null, newDesc.trim());
      toast.success(`项目「${name}」已创建`);
      setCreateOpen(false);
      setNewName("");
      setNewDesc("");
      setNewCompany("");
      await load();
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
      company: p.company_id ? String(p.company_id) : "",
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
        company_id: edit.company ? Number(edit.company) : 0,
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

  const deleteProject = async (p: Project) => {
    if (!confirm(`删除项目「${p.name}」？范围规则随之删除；任务/对话/资产保留但解除归属。`)) return;
    try {
      await api.deleteProject(p.id);
      toast.success("项目已删除");
      await load();
      void loadPending(pendingProject);
    } catch (e) {
      toast.error(`删除失败: ${e instanceof Error ? e.message : String(e)}`);
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
        toast.success(`范围已更新：新增 ${r.added} 条，已认领 ${r.claimed} 条命中资产归属本项目`);
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

  const decide = async (ids: number[], action: "approve" | "reject") => {
    try {
      await api.setAssetAuthz(ids, action, pendingProject);
      toast.success(action === "approve" ? "已批准，资产可测试" : "已拒绝");
      await load();
      await loadPending(pendingProject);
    } catch (e) {
      toast.error(`操作失败: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">项目管理</h1>
          <p className="text-muted-foreground text-sm">
            项目 = 一次渗透委托的授权根。项目范围内资产自动授权；渗透发现的范围外资产进入待审批，批准前不可测试（意图绑定拒绝、命令执行拦截）。
          </p>
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

      {/* 待审批队列 */}
      <Card>
        <CardContent className="pt-4">
          <div className="mb-3 flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <ShieldAlertIcon className="size-4 text-amber-500" />
              <span className="font-medium">待审批资产</span>
              <Badge variant={pendingTotal > 0 ? "destructive" : "secondary"}>{pendingTotal}</Badge>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <span className="text-muted-foreground">按项目过滤</span>
              <Select
                value={pendingProject ? String(pendingProject) : "all"}
                onValueChange={(v) => setPendingProject(v === "all" ? 0 : Number(v))}
              >
                <SelectTrigger className="h-8 w-36" aria-label="按项目过滤待审批">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部项目</SelectItem>
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
          </div>
          {pending.length === 0 ? (
            <p className="text-muted-foreground py-4 text-center text-sm">没有待审批资产</p>
          ) : (
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>目标</TableHead>
                    <TableHead>类型</TableHead>
                    <TableHead>项目</TableHead>
                    <TableHead>发现时间</TableHead>
                    <TableHead className="text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pending.map((a) => (
                    <TableRow key={a.id}>
                      <TableCell className="font-mono text-sm">{assetTarget(a)}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{a.type}</Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground text-sm">
                        {projects.find((p) => p.id === a.project_id)?.name ?? "-"}
                      </TableCell>
                      <TableCell className="text-muted-foreground text-sm">{fmtTime(a.last_seen)}</TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => void decide([a.id], "approve")}
                          >
                            <CheckIcon className="text-green-600" />
                            批准
                          </Button>
                          <Button size="sm" variant="outline" onClick={() => void decide([a.id], "reject")}>
                            <XIcon className="text-red-600" />
                            拒绝
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* 项目列表 */}
      {loading ? (
        <p className="text-muted-foreground py-8 text-center text-sm">加载中…</p>
      ) : projects.length === 0 ? (
        <Card>
          <CardContent className="text-muted-foreground py-10 text-center text-sm">
            还没有项目。创建一个项目并录入授权范围，任务/对话挂到项目下即启用资产围栏。
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {projects.map((p) => (
            <Card key={p.id}>
              <CardContent className="flex flex-col gap-2 pt-4">
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
                      {p.status === "archived" && <Badge variant="secondary">已归档</Badge>}
                    </div>
                    {p.company_name && (
                      <p className="text-muted-foreground mt-1 text-xs">客户：{p.company_name}</p>
                    )}
                    {p.description && (
                      <p className="text-muted-foreground mt-1 line-clamp-2 text-xs">{p.description}</p>
                    )}
                  </div>
                  <div className="flex shrink-0 gap-1">
                    <Button variant="ghost" size="icon" className="size-7" onClick={() => openEdit(p)}>
                      <PencilIcon />
                    </Button>
                    <Button variant="ghost" size="icon" className="size-7" onClick={() => void deleteProject(p)}>
                      <Trash2Icon />
                    </Button>
                  </div>
                </div>
                <div className="text-muted-foreground flex gap-3 text-xs">
                  <span>资产 {p.asset_count}</span>
                  <span className={p.pending_count > 0 ? "font-medium text-amber-600" : ""}>
                    待审批 {p.pending_count}
                  </span>
                  <span>任务 {p.task_count}</span>
                  <span>范围 {p.scope?.length ?? 0} 条</span>
                </div>
                {p.scope?.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {p.scope.slice(0, 5).map((r) => (
                      <Badge key={r.id} variant="outline" className="font-mono text-[11px]">
                        {r.raw}
                      </Badge>
                    ))}
                    {p.scope.length > 5 && (
                      <Badge variant="secondary" className="text-[11px]">
                        +{p.scope.length - 5}
                      </Badge>
                    )}
                  </div>
                )}
                <div className="text-muted-foreground text-xs">创建于 {fmtTime(p.created_at)}</div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* 新建对话框 */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>新建项目</DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-3">
            <Input placeholder="项目名称（如：XX单位渗透测试）" value={newName} onChange={(e) => setNewName(e.target.value)} />
            <Input placeholder="描述（可选）" value={newDesc} onChange={(e) => setNewDesc(e.target.value)} />
            <Select value={newCompany || "none"} onValueChange={(v) => setNewCompany(v === "none" ? "" : v)}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">不绑定企业</SelectItem>
                <SelectGroup>
                  {companies.map((c) => (
                    <SelectItem key={c.id} value={String(c.id)}>
                      {c.name}
                    </SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
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

      {/* 范围编辑 Sheet */}
      <Sheet open={!!edit} onOpenChange={(o) => !o && setEdit(null)}>
        <SheetContent className="flex w-full flex-col gap-4 overflow-y-auto sm:max-w-xl">
          <SheetHeader>
            <SheetTitle>项目设置 — {edit?.project.name}</SheetTitle>
          </SheetHeader>
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
            <Select
              value={edit?.company || "none"}
              onValueChange={(val) => setEdit((cur) => (cur ? { ...cur, company: val === "none" ? "" : val } : cur))}
            >
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">不绑定企业</SelectItem>
                <SelectGroup>
                  {companies.map((c) => (
                    <SelectItem key={c.id} value={String(c.id)}>
                      {c.name}
                    </SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
            <p className="text-muted-foreground text-xs">
              项目可挂到客户主体（企业）下，便于按企业归集；不绑定也不影响围栏。
            </p>
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
                    <label key={c.domain} className="flex cursor-pointer items-center gap-2 rounded px-1 py-0.5 text-sm hover:bg-muted/60" title={c.llm_reason || ""}>
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
                        <Badge variant="outline" className="shrink-0 text-[10px] font-normal text-blue-600">
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
                      {r.kind === "domain" ? "域名" : r.kind === "icp" ? "ICP" : r.kind === "keyword" ? "关键词" : r.kind === "ip" ? "IP" : "CIDR"}
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
          <SheetFooter />
        </SheetContent>
      </Sheet>
    </div>
  );
}
