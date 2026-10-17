"use client";

import * as React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  ArrowLeftIcon,
  BugIcon,
  CheckIcon,
  FolderIcon,
  NetworkIcon,
} from "lucide-react";

import { ApprovalRecords } from "@/components/approval-records";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import { assetProvenance } from "@/lib/asset-provenance";
import type { Asset, Finding, Project, Task } from "@/lib/types";

function fmtTime(iso?: string): string {
  const t = iso ? new Date(iso).getTime() : 0;
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
  return a.domain || a.url || a.ip || a.app_name || `#${a.id}`;
}

const TYPE_LABEL: Record<string, string> = {
  root_domain: "根域名",
  ip: "IP",
  subdomain: "子域名",
  app: "应用",
  service: "服务",
  endpoint: "接口",
};

const SEVERITY_CLASS: Record<string, string> = {
  critical: "bg-red-100 text-red-700",
  high: "bg-orange-100 text-orange-700",
  medium: "bg-amber-100 text-amber-700",
  low: "bg-blue-100 text-blue-700",
};

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={`inline-block shrink-0 rounded px-1.5 py-0.5 text-[11px] font-semibold leading-none ${
        SEVERITY_CLASS[severity] ?? "bg-muted text-muted-foreground"
      }`}
    >
      {severity || "—"}
    </span>
  );
}

function AuthzBadge({ authz }: { authz?: string }) {
  if (!authz || authz === "approved") return null;
  if (authz === "pending") return <Badge variant="outline" className="text-amber-600">待审批</Badge>;
  if (authz === "rejected") return <Badge variant="outline" className="text-red-600">已拒绝</Badge>;
  return null;
}

// WizardStep 是向导条的一步:完成态给绿色对勾+计数,待办态给入口链接。
function WizardStep({
  index,
  done,
  title,
  doneText,
  href,
  linkText,
  hint,
}: {
  index: number;
  done: boolean;
  title: string;
  doneText: string;
  href: string;
  linkText: string;
  hint: string;
}) {
  return (
    <div className="flex flex-col gap-1 rounded-lg border p-3">
      <div className="flex items-center gap-2">
        {done ? (
          <span className="flex size-5 shrink-0 items-center justify-center rounded-full bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-400">
            <CheckIcon className="size-3" />
          </span>
        ) : (
          <span className="bg-muted text-muted-foreground flex size-5 shrink-0 items-center justify-center rounded-full text-[11px] font-semibold">
            {index}
          </span>
        )}
        <span className={`text-sm font-medium ${done ? "" : ""}`}>{title}</span>
        {done ? (
          <span className="text-muted-foreground ml-auto text-xs">{doneText}</span>
        ) : (
          <Link href={href} className="text-primary ml-auto text-xs hover:underline">
            {linkText} →
          </Link>
        )}
      </div>
      {!done && <p className="text-muted-foreground pl-7 text-xs leading-relaxed">{hint}</p>}
    </div>
  );
}

// ProjectDetail 以项目为轴聚合它名下的全部信息:任务(经 task.project_id)、
// 资产(经 asset.project_id,全部类型混合)、漏洞(finding 经任务归属项目,
// 服务端 project_id 过滤)。
function ProjectDetail({ id }: { id: number }) {
  const [project, setProject] = React.useState<Project | null>(null);
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [assets, setAssets] = React.useState<Asset[]>([]);
  const [assetsTotal, setAssetsTotal] = React.useState(0);
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [findingsTotal, setFindingsTotal] = React.useState(0);
  const [loaded, setLoaded] = React.useState(false);

  React.useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [projects, taskRes, assetRes, findingRes] = await Promise.all([
          api.projects(),
          api.tasks(),
          api.assets("", 200, 0, "", String(id)),
          api.findingsPage({ page: 1, pageSize: 100, sort: "severity", projectId: id }),
        ]);
        if (!alive) return;
        setProject(projects.find((p) => p.id === id) ?? null);
        setTasks(taskRes.tasks.filter((t) => t.project_id === id));
        setAssets(assetRes.assets);
        setAssetsTotal(assetRes.total);
        setFindings(findingRes.items);
        setFindingsTotal(findingRes.total);
      } finally {
        if (alive) setLoaded(true);
      }
    };
    void load();
    return () => {
      alive = false;
    };
  }, [id]);

  if (!loaded) {
    return <p className="text-muted-foreground py-10 text-center text-sm">加载中…</p>;
  }
  if (!project) {
    return (
      <Card>
        <CardContent className="text-muted-foreground py-10 text-center text-sm">
          项目不存在(可能已被删除)。
          <Link href="/function/projects" className="ml-1 underline">
            返回项目列表
          </Link>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <Button variant="ghost" size="sm" asChild className="text-muted-foreground -ml-2 mb-1">
            <Link href="/function/projects">
              <ArrowLeftIcon className="size-4" /> 项目
            </Link>
          </Button>
          <h1 className="flex items-center gap-2 text-lg font-semibold">
            <FolderIcon className="text-muted-foreground size-5 shrink-0" />
            <span className="truncate">{project.name}</span>
            {project.status === "archived" && <Badge variant="secondary">已归档</Badge>}
          </h1>
          {project.company_name && (
            <p className="text-muted-foreground mt-1 text-sm">客户:{project.company_name}</p>
          )}
          {project.description && (
            <p className="text-muted-foreground mt-1 text-sm">{project.description}</p>
          )}
        </div>
        <div className="text-muted-foreground flex shrink-0 gap-4 pt-6 text-sm">
          <span>任务 {tasks.length}</span>
          <span>资产 {assetsTotal}</span>
          <span className={project.pending_count > 0 ? "font-medium text-amber-600" : ""}>
            待审批 {project.pending_count}
          </span>
        </div>
      </div>

      {/* 工作流向导:建项目→资产进项目→建任务。三步齐活后整条隐去(引导完成即退场)。 */}
      {(!project.scope || project.scope.length === 0 || assetsTotal === 0 || tasks.length === 0) && (
        <Card>
          <CardContent className="flex flex-col gap-3 pt-4 sm:flex-row sm:items-center">
            <div className="grid flex-1 gap-2 sm:grid-cols-3">
              <WizardStep
                index={1}
                done={!!project.scope && project.scope.length > 0}
                title="录入授权范围"
                doneText={`${project.scope?.length ?? 0} 条规则`}
                href={`/function/projects?edit=${project.id}`}
                linkText="去录入"
                hint="项目 = 授权根。范围(域名/IP/CIDR)决定围栏白名单,命中的存量资产会被自动认领。"
              />
              <WizardStep
                index={2}
                done={assetsTotal > 0}
                title="资产进项目"
                doneText={`${assetsTotal} 条资产`}
                href="/function/assets"
                linkText="去资产页"
                hint="在资产页管理资产或让任务执行中发现——范围命中的会自动归属本项目并授权。"
              />
              <WizardStep
                index={3}
                done={tasks.length > 0}
                title="创建任务"
                doneText={`${tasks.length} 个任务`}
                href={`/function/tasks?create=1&project_id=${project.id}`}
                linkText="去创建"
                hint="任务挂到项目即启用资产围栏;产出的资产/漏洞聚合在本页。"
              />
            </div>
          </CardContent>
        </Card>
      )}

      <Tabs defaultValue="overview" className="flex flex-col gap-4">
        <TabsList>
          <TabsTrigger value="overview">总览</TabsTrigger>
          <TabsTrigger value="tasks">任务 ({tasks.length})</TabsTrigger>
          <TabsTrigger value="assets">资产 ({assetsTotal})</TabsTrigger>
          <TabsTrigger value="findings">漏洞 ({findingsTotal})</TabsTrigger>
          <TabsTrigger value="approvals">审批</TabsTrigger>
        </TabsList>

        {/* 总览:范围(围栏白名单)+ 说明 */}
        <TabsContent value="overview" className="mt-0">
          <Card>
            <CardContent className="flex flex-col gap-3 pt-4">
              <div>
                <p className="mb-2 text-sm font-medium">授权范围(资产围栏白名单,{project.scope?.length ?? 0} 条)</p>
                {project.scope?.length ? (
                  <div className="flex flex-wrap gap-1">
                    {project.scope.map((r) => (
                      <Badge key={r.id} variant="outline" className="font-mono text-[11px]">
                        {r.raw}
                      </Badge>
                    ))}
                  </div>
                ) : (
                  <p className="text-muted-foreground text-sm">
                    未录入范围。回到项目列表编辑该项目,录入域名/IP/CIDR/ICP/关键词。
                  </p>
                )}
              </div>
              <p className="text-muted-foreground text-xs leading-relaxed">
                项目 = 一次渗透委托的授权根。范围内发现资产自动授权;范围外资产进待审批,批准前不可测试。任务/对话挂到项目下即启用围栏。
              </p>
              <p className="text-muted-foreground text-xs">创建于 {fmtTime(project.created_at)}</p>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 任务 */}
        <TabsContent value="tasks" className="mt-0">
          <Card>
            <CardContent className="pt-2">
              {tasks.length === 0 ? (
                <p className="text-muted-foreground py-8 text-center text-sm">
                  该项目下还没有任务。创建任务时选择归属本项目。
                </p>
              ) : (
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>任务</TableHead>
                        <TableHead>状态</TableHead>
                        <TableHead>漏洞</TableHead>
                        <TableHead>目标达成</TableHead>
                        <TableHead>创建时间</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {tasks.map((t) => {
                        const f = t.findings;
                        const vulnCount = f ? f.critical + f.high + f.medium + f.low : 0;
                        return (
                          <TableRow key={t.id}>
                            <TableCell>
                              <Link
                                href={`/function/tasks/detail?id=${t.id}`}
                                className="font-medium hover:underline"
                              >
                                {t.name || t.description || t.id}
                              </Link>
                            </TableCell>
                            <TableCell>
                              <Badge variant="outline">{t.status}</Badge>
                            </TableCell>
                            <TableCell className="text-sm tabular-nums">{vulnCount}</TableCell>
                            <TableCell className="text-muted-foreground text-sm tabular-nums">
                              {t.goals_met ?? 0}/{t.goals_total ?? 0}
                            </TableCell>
                            <TableCell className="text-muted-foreground text-sm">
                              {fmtTime(t.created_at)}
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* 资产:全部类型混合,按项目过滤 */}
        <TabsContent value="assets" className="mt-0">
          <Card>
            <CardContent className="pt-2">
              {assets.length === 0 ? (
                <p className="text-muted-foreground py-8 text-center text-sm">
                  该项目还没有归属资产。同步/发现的资产经审批归属后出现在这里。
                </p>
              ) : (
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>目标</TableHead>
                        <TableHead>类型</TableHead>
                        <TableHead>出处</TableHead>
                        <TableHead>授权状态</TableHead>
                        <TableHead>最后发现</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {assets.slice(0, 200).map((a) => (
                        <TableRow key={a.id}>
                          <TableCell className="font-mono text-xs font-medium">{assetTarget(a)}</TableCell>
                          <TableCell>
                            <Badge variant="outline">{TYPE_LABEL[a.type] ?? a.type}</Badge>
                          </TableCell>
                          <TableCell
                            className="text-muted-foreground max-w-48 truncate text-xs"
                            title={assetProvenance(a)}
                          >
                            {assetProvenance(a)}
                          </TableCell>
                          <TableCell>
                            <AuthzBadge authz={a.authz} />
                          </TableCell>
                          <TableCell className="text-muted-foreground text-xs">
                            {fmtTime(a.last_seen)}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
              {assetsTotal > 200 && (
                <p className="text-muted-foreground mt-2 flex items-center gap-1 text-xs">
                  <NetworkIcon className="size-3.5" />
                  显示前 200 条,共 {assetsTotal} 条 —— 资产页选「按项目筛选」可翻页查看全部。
                </p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* 漏洞:finding 经任务归属项目 */}
        <TabsContent value="findings" className="mt-0">
          <Card>
            <CardContent className="pt-2">
              {findings.length === 0 ? (
                <p className="text-muted-foreground py-8 text-center text-sm">
                  该项目下还没有登记漏洞。
                </p>
              ) : (
                <div className="rounded-md border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-20">严重度</TableHead>
                        <TableHead>漏洞</TableHead>
                        <TableHead>任务</TableHead>
                        <TableHead>时间</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {findings.map((f) => (
                        <TableRow key={f.id}>
                          <TableCell>
                            <SeverityBadge severity={f.severity} />
                          </TableCell>
                          <TableCell className="max-w-96">
                            <Link
                              href={
                                f.finding_id
                                  ? `/function/findings/detail?id=${f.finding_id}${f.task_id ? `&context_task=${f.task_id}` : ""}`
                                  : `/function/findings/detail?id=${f.id}`
                              }
                              className="block truncate font-medium hover:underline"
                              title={f.summary}
                            >
                              {f.name || f.vulnclass}
                            </Link>
                            <span className="text-muted-foreground block truncate text-xs" title={f.summary}>
                              {f.summary}
                            </span>
                          </TableCell>
                          <TableCell className="text-muted-foreground max-w-48 truncate text-xs">
                            {f.task_description || f.task_id || "—"}
                          </TableCell>
                          <TableCell className="text-muted-foreground text-xs">{fmtTime(f.ts)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
              {findingsTotal > 100 && (
                <p className="text-muted-foreground mt-2 flex items-center gap-1 text-xs">
                  <BugIcon className="size-3.5" />
                  显示前 100 条,共 {findingsTotal} 条 —— 发现页可按项目进一步筛选导出。
                </p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* 审批:与任务详情里的「拦截审批」是同一个组件、同一份数据——这里按项目
            聚合该项目下所有任务/会话的审批,目标可逐条勾选授权。 */}
        <TabsContent value="approvals" className="mt-0">
          <ApprovalRecords projectId={project.id} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

export default function ProjectDetailPage() {
  // useSearchParams must sit under a Suspense boundary for static export.
  return (
    <React.Suspense fallback={null}>
      <ProjectDetailInner />
    </React.Suspense>
  );
}

function ProjectDetailInner() {
  const searchParams = useSearchParams();
  const id = Number(searchParams.get("id") ?? 0);
  if (!id) {
    return (
      <Card>
        <CardContent className="text-muted-foreground py-10 text-center text-sm">
          缺少项目 id。
          <Link href="/function/projects" className="ml-1 underline">
            返回项目列表
          </Link>
        </CardContent>
      </Card>
    );
  }
  return <ProjectDetail id={id} />;
}
