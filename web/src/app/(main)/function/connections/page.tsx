"use client";

import * as React from "react";

import { useRouter } from "next/navigation";

import { ExternalLinkIcon, Loader2Icon, PlayIcon, PlusIcon, SquareTerminalIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api } from "@/lib/api";
import type { Connection, Project } from "@/lib/types";
import { cn } from "@/lib/utils";

import { SshTerminalDialog } from "./_components/ssh-terminal-dialog";

// 连接管理:SSH/数据库(SMB/WinRM/LDAP/VNC/FTP 等)凭据台账。明文存储(用户口径),
// 必须绑定项目;worker 任务中验证成功的凭据自动落库(source=discovered)。
const KIND_LABELS: Record<string, string> = {
  ssh: "SSH",
  postgres: "PostgreSQL",
  mysql: "MySQL",
  redis: "Redis",
  mongodb: "MongoDB",
  elasticsearch: "Elasticsearch",
  smb: "SMB",
  winrm: "WinRM",
  ldap: "LDAP",
  vnc: "VNC",
  ftp: "FTP",
  proxy: "代理",
  tunnel: "隧道",
  webshell: "WebShell",
};

const DEFAULT_PORTS: Record<string, number> = {
  ssh: 22,
  postgres: 5432,
  mysql: 3306,
  redis: 6379,
  mongodb: 27017,
  elasticsearch: 9200,
  smb: 445,
  winrm: 5985,
  ldap: 389,
  vnc: 5900,
  ftp: 21,
  proxy: 1080,
  webshell: 80,
};

// 从落点 URL 里取展示用的主机/端口(URL 型目标的 host/port 就是它)。
function urlHost(raw: string): string {
  try {
    return new URL(raw).hostname;
  } catch {
    return raw;
  }
}

function urlPort(raw: string): number {
  try {
    const u = new URL(raw);
    return Number(u.port) || (u.protocol === "https:" ? 443 : 80);
  } catch {
    return 80;
  }
}

export default function ConnectionsPage() {
  const router = useRouter();
  const [rows, setRows] = React.useState<Connection[] | null>(null);
  const [projects, setProjects] = React.useState<Project[]>([]);
  const [projectFilter, setProjectFilter] = React.useState("");
  const [kindFilter, setKindFilter] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [addOpen, setAddOpen] = React.useState(false);
  const [consoleRow, setConsoleRow] = React.useState<Connection | null>(null);
  const [consoleInput, setConsoleInput] = React.useState("");
  const [consoleLog, setConsoleLog] = React.useState<{ cmd: string; out: string; ok: boolean }[]>([]);
  const [consoleBusy, setConsoleBusy] = React.useState(false);
  const [draft, setDraft] = React.useState({
    project_id: "",
    kind: "ssh",
    host: "",
    port: "",
    username: "",
    secret: "",
    note: "",
    // WebShell 的落点与协议细节；URL 型目标没有端口/用户名语义。
    url: "",
    cmdParam: "cmd",
    passParam: "pass",
    method: "GET",
    shellType: "",
    protocol: "plain",
  });

  React.useEffect(() => {
    api
      .projects()
      .then(setProjects)
      .catch(() => {
        // 项目列表加载失败不影响凭据台账主流程，筛选器会退化为「全部项目」。
      });
  }, []);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.connections({
        projectId: projectFilter ? Number(projectFilter) : undefined,
        kind: kindFilter || undefined,
      });
      setRows(list);
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    } finally {
      setLoading(false);
    }
  }, [projectFilter, kindFilter]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const add = async () => {
    if (!draft.project_id || !draft.host) {
      toast.error("项目与主机必填");
      return;
    }
    try {
      const isShell = draft.kind === "webshell";
      const url = draft.url.trim();
      if (isShell && !url) {
        toast.error("WebShell 必须填落点 URL");
        return;
      }
      await api.createConnection({
        project_id: Number(draft.project_id),
        kind: draft.kind,
        // WebShell 的连接对象是那个 URL:host/port 只是台账里的展示字段,
        // 取 URL 的 hostname/port,保证列表上看到的就是实际落点。
        host: isShell ? urlHost(url) : draft.host.trim(),
        port: isShell ? urlPort(url) : Number(draft.port) || DEFAULT_PORTS[draft.kind] || 0,
        username: isShell ? "" : draft.username,
        secret: draft.secret,
        note: draft.note,
        source: "manual",
        extra: isShell
          ? {
              url,
              cmd_param: draft.cmdParam || "cmd",
              pass_param: draft.passParam || "pass",
              method: draft.method,
              // 空 = 后端按落点扩展名推断;协议影响会话层,默认 plain。
              shell_type: draft.shellType || undefined,
              protocol: draft.protocol || "plain",
            }
          : undefined,
      });
      toast.success("已登记");
      setAddOpen(false);
      setDraft({
        project_id: "",
        kind: "ssh",
        host: "",
        port: "",
        username: "",
        secret: "",
        note: "",
        url: "",
        cmdParam: "cmd",
        passParam: "pass",
        method: "GET",
        shellType: "",
        protocol: "plain",
      });
      await load();
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    }
  };

  const [terminalRow, setTerminalRow] = React.useState<Connection | null>(null);
  const consoleKinds = new Set(["ssh", "postgres", "mysql", "redis", "webshell"]);
  // 这些类型的台账行可以直接开成终端会话(凭据录一次,两处可用)。
  const sessionKinds = new Set(["ssh", "webshell", "postgres", "mysql", "smb"]);

  const openSession = async (c: Connection) => {
    try {
      const res = await api.openSessionFromConnection(c.id);
      toast.success(res.reused ? `复用会话 ${res.id}` : `已开会话 ${res.id},正在打开终端`);
      router.push(`/function/sessions?session=${encodeURIComponent(res.id)}`);
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    }
  };
  const runConsole = async () => {
    if (!consoleRow || !consoleInput.trim()) return;
    const cmd = consoleInput.trim();
    setConsoleBusy(true);
    setConsoleInput("");
    try {
      if (consoleRow.kind === "webshell") {
        const res = await api.connWebShellExec(consoleRow.id, cmd);
        setConsoleLog((l) => [
          ...l,
          res.ok ? { cmd, out: res.output || "(无输出)", ok: true } : { cmd, out: res.error || "执行失败", ok: false },
        ]);
      } else if (consoleRow.kind === "ssh") {
        const res = await api.connSSHExec(consoleRow.id, cmd);
        setConsoleLog((l) => [
          ...l,
          res.ok ? { cmd, out: res.output || "(无输出)", ok: true } : { cmd, out: res.error || "执行失败", ok: false },
        ]);
      } else {
        const res = await api.connDBQuery(consoleRow.id, cmd);
        if (!res.ok) {
          setConsoleLog((l) => [...l, { cmd, out: res.error || "执行失败", ok: false }]);
        } else if (res.columns) {
          const header = res.columns.join(" | ");
          const body = (res.rows ?? []).map((r) => r.join(" | ")).join("\n");
          setConsoleLog((l) => [
            ...l,
            {
              cmd,
              out: `${header}\n${body || "(0 行)"}\n[${res.rows?.length ?? 0} 行, ${res.elapsed_ms}ms]`,
              ok: true,
            },
          ]);
        } else {
          setConsoleLog((l) => [...l, { cmd, out: `${res.output || ""} [${res.elapsed_ms}ms]`, ok: true }]);
        }
      }
      await load();
    } catch (err) {
      setConsoleLog((l) => [...l, { cmd, out: String(err instanceof Error ? err.message : err), ok: false }]);
    } finally {
      setConsoleBusy(false);
    }
  };

  const del = async (id: number) => {
    try {
      await api.deleteConnection(id);
      await load();
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    }
  };

  const credentialStats = React.useMemo(() => {
    const list = rows ?? [];
    return {
      total: list.length,
      alive: list.filter((c) => c.status === "alive").length,
      dead: list.filter((c) => c.status === "dead").length,
      unverified: list.filter((c) => c.status !== "alive" && c.status !== "dead").length,
    };
  }, [rows]);

  const connectionStatus = (c: Connection) => (
    <Badge
      variant="outline"
      className={
        c.status === "alive"
          ? "border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
          : c.status === "dead"
            ? "border-red-500/25 bg-red-500/10 text-red-700 dark:text-red-300"
            : "text-muted-foreground"
      }
    >
      {c.status === "alive" ? "有效" : c.status === "dead" ? "失效" : "未验证"}
    </Badge>
  );

  const connectionActions = (c: Connection) => (
    <div className="flex flex-wrap items-center gap-1">
      {c.kind === "ssh" ? (
        <Button size="sm" variant="outline" onClick={() => setTerminalRow(c)}>
          <SquareTerminalIcon className="size-3.5" /> 终端
        </Button>
      ) : null}
      {sessionKinds.has(c.kind) ? (
        <Button
          size="sm"
          variant="ghost"
          title="用这条凭据开一个终端会话"
          aria-label="用这条凭据开一个终端会话"
          onClick={() => void openSession(c)}
        >
          <ExternalLinkIcon className="size-3.5" />
        </Button>
      ) : null}
      {consoleKinds.has(c.kind) ? (
        <Button
          size="sm"
          variant="outline"
          onClick={() => {
            setConsoleRow(c);
            setConsoleLog([]);
            setConsoleInput("");
          }}
        >
          <SquareTerminalIcon className="size-3.5" /> {c.kind === "ssh" ? "命令" : "控制台"}
        </Button>
      ) : null}
      <Button
        size="sm"
        variant="ghost"
        className="text-muted-foreground hover:text-destructive"
        title="删除凭据"
        aria-label="删除凭据"
        onClick={() => void del(c.id)}
      >
        <Trash2Icon className="size-3.5" />
      </Button>
    </div>
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">连接管理</h1>
          <p className="text-muted-foreground mt-1 max-w-3xl text-sm leading-relaxed">
            SSH / 数据库 / 协议（SMB/WinRM/LDAP/VNC/FTP）凭据台账，按项目归集。worker 任务中验证成功的凭据
            自动落库（source=discovered），也可手工登记；凭据明文存储，用于任务中的连接复用与凭据利用。
          </p>
        </div>
        <Button size="sm" onClick={() => setAddOpen(true)}>
          <PlusIcon className="size-4" /> 登记凭据
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Select value={projectFilter || "all"} onValueChange={(v) => setProjectFilter(v === "all" ? "" : v)}>
          <SelectTrigger className="w-44">
            <SelectValue placeholder="项目" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部项目</SelectItem>
            {projects.map((p) => (
              <SelectItem key={p.id} value={String(p.id)}>
                {p.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={kindFilter || "all"} onValueChange={(v) => setKindFilter(v === "all" ? "" : v)}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="类型" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部类型</SelectItem>
            {Object.entries(KIND_LABELS).map(([k, v]) => (
              <SelectItem key={k} value={k}>
                {v}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {loading ? <Loader2Icon className="text-muted-foreground size-4 animate-spin" /> : null}
        <span className="text-muted-foreground text-xs tabular-nums">共 {rows?.length ?? 0} 条</span>
      </div>

      <div className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border bg-border sm:grid-cols-4">
        {[
          { label: "凭据总数", value: credentialStats.total, dot: "bg-foreground" },
          { label: "有效", value: credentialStats.alive, dot: "bg-emerald-600" },
          { label: "失效", value: credentialStats.dead, dot: "bg-red-600" },
          { label: "未验证", value: credentialStats.unverified, dot: "bg-slate-400" },
        ].map((stat) => (
          <div key={stat.label} className="bg-card px-4 py-3">
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <span className={cn("size-1.5 rounded-full", stat.dot)} aria-hidden="true" />
              {stat.label}
            </div>
            <div className="mt-1 text-2xl font-semibold text-foreground tabular-nums">{stat.value}</div>
          </div>
        ))}
      </div>

      <Card>
        <CardContent className="px-0">
          {rows === null ? (
            <p className="text-muted-foreground px-4 py-6 text-sm">加载中…</p>
          ) : rows.length === 0 ? (
            <div className="px-4 py-8">
              <div className="rounded-lg border border-dashed px-4 py-6">
                <p className="text-sm font-medium">暂无凭据</p>
                <p className="text-muted-foreground mt-1 text-sm">
                  worker 在任务中验证成功会自动落库；也可以手工登记第一条凭据。
                </p>
              </div>
            </div>
          ) : (
            <>
              <div className="hidden overflow-x-auto md:block">
                <table className="w-full text-sm tabular-nums">
                  <thead>
                    <tr className="border-b text-left text-xs font-medium text-muted-foreground">
                      <th className="px-4 py-2.5 font-medium">类型</th>
                      <th className="px-4 py-2.5 font-medium">目标</th>
                      <th className="px-4 py-2.5 font-medium">用户</th>
                      <th className="px-4 py-2.5 font-medium">凭据</th>
                      <th className="px-4 py-2.5 font-medium">项目</th>
                      <th className="px-4 py-2.5 font-medium">来源</th>
                      <th className="px-4 py-2.5 font-medium">状态</th>
                      <th className="px-4 py-2.5 font-medium">备注</th>
                      <th className="px-4 py-2.5" />
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((c) => (
                      <tr key={c.id} className="border-b last:border-0">
                        <td className="px-4 py-2.5">
                          <Badge variant="outline">{KIND_LABELS[c.kind] ?? c.kind}</Badge>
                        </td>
                        <td className="px-4 py-2.5 font-mono">
                          {c.host}:{c.port}
                        </td>
                        <td className="px-4 py-2.5 font-mono">{c.username || "-"}</td>
                        <td className="max-w-48 truncate px-4 py-2.5 font-mono text-xs">{c.secret || "-"}</td>
                        <td className="px-4 py-2.5">{c.project_name || `#${c.project_id}`}</td>
                        <td className="px-4 py-2.5">
                          <Badge variant={c.source === "discovered" ? "secondary" : "outline"}>
                            {c.source === "discovered" ? "任务发现" : "手工"}
                          </Badge>
                        </td>
                        <td className="px-4 py-2.5">{connectionStatus(c)}</td>
                        <td className="text-muted-foreground max-w-40 truncate px-4 py-2.5 text-xs">{c.note || "-"}</td>
                        <td className="px-4 py-2.5">{connectionActions(c)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* 手机上表格改为两行卡片：身份与关键数字在首行，其余字段不丢。 */}
              <div className="divide-y md:hidden">
                {rows.map((c) => (
                  <div key={c.id} className="space-y-2 px-4 py-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline">{KIND_LABELS[c.kind] ?? c.kind}</Badge>
                          <span className="truncate font-mono text-[13px]">
                            {c.host}:{c.port}
                          </span>
                        </div>
                        <div className="text-muted-foreground mt-1 truncate text-xs">
                          {c.username || "-"} · {c.project_name || `#${c.project_id}`}
                        </div>
                      </div>
                      {connectionStatus(c)}
                    </div>
                    <div className="text-muted-foreground truncate font-mono text-xs">{c.secret || "-"}</div>
                    <div className="text-muted-foreground flex flex-wrap items-center gap-2 text-xs">
                      <Badge variant={c.source === "discovered" ? "secondary" : "outline"}>
                        {c.source === "discovered" ? "任务发现" : "手工"}
                      </Badge>
                      <span className="min-w-0 truncate">{c.note || "-"}</span>
                    </div>
                    {connectionActions(c)}
                  </div>
                ))}
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>登记凭据</DialogTitle>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>项目</Label>
                <Select
                  value={draft.project_id || "none"}
                  onValueChange={(v) => setDraft((d) => ({ ...d, project_id: v === "none" ? "" : v }))}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="选择项目" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">选择项目</SelectItem>
                    {projects.map((p) => (
                      <SelectItem key={p.id} value={String(p.id)}>
                        {p.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label>类型</Label>
                <Select value={draft.kind} onValueChange={(v) => setDraft((d) => ({ ...d, kind: v }))}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {Object.entries(KIND_LABELS).map(([k, v]) => (
                      <SelectItem key={k} value={k}>
                        {v}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            {draft.kind === "webshell" ? (
              <>
                <div className="space-y-1">
                  <Label>落点 URL</Label>
                  <Input
                    className="font-mono"
                    placeholder="http://target/shell.php"
                    value={draft.url}
                    onChange={(e) => setDraft((d) => ({ ...d, url: e.target.value }))}
                  />
                </div>
                <div className="grid grid-cols-3 gap-3">
                  <div className="space-y-1">
                    <Label>命令参数</Label>
                    <Input
                      value={draft.cmdParam}
                      onChange={(e) => setDraft((d) => ({ ...d, cmdParam: e.target.value }))}
                    />
                  </div>
                  <div className="space-y-1">
                    <Label>口令参数</Label>
                    <Input
                      value={draft.passParam}
                      onChange={(e) => setDraft((d) => ({ ...d, passParam: e.target.value }))}
                    />
                  </div>
                  <div className="space-y-1">
                    <Label>方法</Label>
                    <Select value={draft.method} onValueChange={(v) => setDraft((d) => ({ ...d, method: v }))}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {["GET", "POST"].map((m) => (
                          <SelectItem key={m} value={m}>
                            {m}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <Label>Shell 类型</Label>
                    <Select
                      value={draft.shellType || "auto"}
                      onValueChange={(v) => setDraft((d) => ({ ...d, shellType: v === "auto" ? "" : v }))}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="auto">按扩展名推断</SelectItem>
                        {["jsp", "php", "asp", "aspx"].map((t) => (
                          <SelectItem key={t} value={t}>
                            {t}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1">
                    <Label>流量协议</Label>
                    <Select value={draft.protocol} onValueChange={(v) => setDraft((d) => ({ ...d, protocol: v }))}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {["plain", "behinder", "godzilla"].map((p) => (
                          <SelectItem key={p} value={p}>
                            {p}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </>
            ) : (
              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2 space-y-1">
                  <Label>主机</Label>
                  <Input value={draft.host} onChange={(e) => setDraft((d) => ({ ...d, host: e.target.value }))} />
                </div>
                <div className="space-y-1">
                  <Label>端口</Label>
                  <Input
                    type="number"
                    placeholder={String(DEFAULT_PORTS[draft.kind] ?? "")}
                    value={draft.port}
                    onChange={(e) => setDraft((d) => ({ ...d, port: e.target.value }))}
                  />
                </div>
              </div>
            )}
            <div className="grid grid-cols-2 gap-3">
              {draft.kind === "webshell" ? null : (
                <div className="space-y-1">
                  <Label>用户名</Label>
                  <Input
                    value={draft.username}
                    onChange={(e) => setDraft((d) => ({ ...d, username: e.target.value }))}
                  />
                </div>
              )}
              <div className={`space-y-1 ${draft.kind === "webshell" ? "col-span-2" : ""}`}>
                <Label>{draft.kind === "webshell" ? "Shell 口令" : "凭据(密码/私钥/令牌)"}</Label>
                <Input
                  type="password"
                  value={draft.secret}
                  onChange={(e) => setDraft((d) => ({ ...d, secret: e.target.value }))}
                />
              </div>
            </div>
            <div className="space-y-1">
              <Label>来源备注</Label>
              <Input
                placeholder="从哪发现的(配置文件/输出/弱口令等)"
                value={draft.note}
                onChange={(e) => setDraft((d) => ({ ...d, note: e.target.value }))}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddOpen(false)}>
              取消
            </Button>
            <Button onClick={() => void add()}>登记</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <SshTerminalDialog connection={terminalRow} onClose={() => setTerminalRow(null)} />

      <Dialog open={consoleRow !== null} onOpenChange={(v) => !v && setConsoleRow(null)}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>
              控制台 ·{" "}
              {consoleRow
                ? `${KIND_LABELS[consoleRow.kind] ?? consoleRow.kind} ${consoleRow.username ? `${consoleRow.username}@` : ""}${consoleRow.host}:${consoleRow.port}`
                : ""}
            </DialogTitle>
          </DialogHeader>
          <div className="bg-muted/40 h-80 overflow-y-auto rounded-md border p-3 font-mono text-xs">
            {consoleLog.length === 0 ? (
              <p className="text-muted-foreground">
                {consoleRow?.kind === "ssh" || consoleRow?.kind === "webshell"
                  ? "输入远程命令,回车执行(一次性 exec,非交互会话)"
                  : "输入查询:SQL(postgres/mysql)或 Redis 命令"}
              </p>
            ) : (
              consoleLog.map((entry, i) => (
                <div key={i} className="mb-2">
                  <div className="text-primary">$ {entry.cmd}</div>
                  <pre className={entry.ok ? "whitespace-pre-wrap" : "text-destructive whitespace-pre-wrap"}>
                    {entry.out}
                  </pre>
                </div>
              ))
            )}
            {consoleBusy ? <Loader2Icon className="size-3 animate-spin" /> : null}
          </div>
          <div className="flex items-center gap-2">
            <Input
              className="font-mono"
              placeholder={
                consoleRow?.kind === "redis"
                  ? "INFO server"
                  : consoleRow?.kind === "postgres" || consoleRow?.kind === "mysql"
                    ? "SELECT version()"
                    : "id && uname -a"
              }
              value={consoleInput}
              onChange={(e) => setConsoleInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void runConsole();
              }}
            />
            <Button disabled={consoleBusy} onClick={() => void runConsole()}>
              <PlayIcon className="size-4" /> 执行
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
