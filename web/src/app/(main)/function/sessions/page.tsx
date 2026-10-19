"use client";

// 会话页：capkit 桥接打开的 foothold（WebShell / SSH / WinRM / SMB / CLI）。
//
// 交互刻意是“一次性命令”而不是 PTY：capkit 的 session_exec 契约就是
// exec(command) → stdout/stderr/exit，浏览器这边若装成终端会让人误以为
// 有交互式 stdin。输出按调用追加，长命令靠滚动，不伪造 prompt。
import * as React from "react";

import { Loader2Icon, PlayIcon, PlusIcon, RefreshCwIcon, SquareTerminalIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { CapkitSession } from "@/lib/types";
import { cn } from "@/lib/utils";

interface LogEntry {
  id: number;
  command: string;
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
  at: string;
}

const KINDS = ["webshell", "ssh", "winrm", "smb", "cli"];

export default function SessionsPage() {
  const [sessions, setSessions] = React.useState<CapkitSession[]>([]);
  const [enabled, setEnabled] = React.useState(true);
  const [loading, setLoading] = React.useState(false);
  const [selected, setSelected] = React.useState<string>("");
  const [logs, setLogs] = React.useState<Record<string, LogEntry[]>>({});
  const [command, setCommand] = React.useState("id");
  const [running, setRunning] = React.useState(false);
  const [opening, setOpening] = React.useState(false);
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const logSeq = React.useRef(0);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.capkitSessions();
      setSessions(r.sessions ?? []);
      setEnabled(r.enabled);
      setSelected((cur) => (r.sessions?.some((s) => s.id === cur) ? cur : (r.sessions?.[0]?.id ?? "")));
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载会话失败");
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const current = sessions.find((s) => s.id === selected);
  const activeLogs = current ? (logs[current.id] ?? []) : [];

  const exec = async () => {
    if (!current || !command.trim()) return;
    setRunning(true);
    try {
      const r = await api.execCapkitSession(current.id, command.trim());
      logSeq.current += 1;
      const entry: LogEntry = {
        id: logSeq.current,
        command: r.command || command.trim(),
        stdout: r.stdout ?? "",
        stderr: r.stderr ?? "",
        exitCode: r.exit_code ?? 0,
        durationMs: r.duration_ms ?? 0,
        at: new Date().toLocaleTimeString("zh-CN"),
      };
      setLogs((prev) => ({ ...prev, [current.id]: [...(prev[current.id] ?? []), entry] }));
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "执行失败");
    } finally {
      setRunning(false);
    }
  };

  const close = async (s: CapkitSession) => {
    try {
      await api.closeCapkitSession(s.id);
      toast.success(`已关闭会话 ${s.id}`);
      setLogs((prev) => {
        const next = { ...prev };
        delete next[s.id];
        return next;
      });
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "关闭失败");
    }
  };

  const submitOpen = async (form: OpenForm) => {
    setOpening(true);
    try {
      const options: Record<string, string> = {};
      if (form.kind === "webshell") {
        options.shell_type = form.shellType;
        options.cmd_param = form.cmdParam || "cmd";
        options.method = form.method;
      }
      const created = await api.openCapkitSession({
        kind: form.kind,
        host: form.host.trim(),
        port: Number(form.port) || undefined,
        user: form.user.trim() || undefined,
        secret: form.secret || undefined,
        options: Object.keys(options).length ? options : undefined,
      });
      toast.success(`已打开 ${created.kind} 会话 ${created.id}`);
      setDialogOpen(false);
      setSelected(created.id);
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "打开会话失败");
    } finally {
      setOpening(false);
    }
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <SquareTerminalIcon className="h-5 w-5 text-muted-foreground" />
          <h1 className="text-xl font-semibold tracking-tight">会话</h1>
          <Badge variant="secondary">{sessions.length}</Badge>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
            <RefreshCwIcon className={cn("h-4 w-4", loading && "animate-spin")} />
            刷新
          </Button>
          <Button size="sm" onClick={() => setDialogOpen(true)}>
            <PlusIcon className="h-4 w-4" />
            打开会话
          </Button>
        </div>
      </div>

      {!enabled && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">capkit 桥接未启用</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            后端启动时未能构建 capkit runtime（原因见服务端日志中的 <code>[capkit] 桥接未启用</code>）。 工具目录里的
            capkit 工具也不会出现。
          </CardContent>
        </Card>
      )}

      <div className="grid min-h-0 flex-1 gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
        <Card className="min-h-0 overflow-hidden">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground">活动会话</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>会话</TableHead>
                  <TableHead>目标</TableHead>
                  <TableHead>类型</TableHead>
                  <TableHead className="text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={4} className="py-8 text-center text-sm text-muted-foreground">
                      {loading ? "加载中…" : "暂无活动会话。Agent 通过 session_open 打开的 foothold 也会出现在这里。"}
                    </TableCell>
                  </TableRow>
                )}
                {sessions.map((s) => (
                  <TableRow
                    key={s.id}
                    className={cn("cursor-pointer", selected === s.id && "bg-muted/50")}
                    onClick={() => setSelected(s.id)}
                  >
                    <TableCell>
                      <div className="font-mono text-xs">{s.id}</div>
                      {s.user && <div className="text-xs text-muted-foreground">{s.user}</div>}
                    </TableCell>
                    <TableCell>
                      <div className="max-w-[240px] truncate text-sm">{s.host || "—"}</div>
                      {s.project_id ? <div className="text-xs text-muted-foreground">项目 #{s.project_id}</div> : null}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-mono text-[11px]">
                        {s.kind}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="icon"
                        title="关闭会话"
                        onClick={(e) => {
                          e.stopPropagation();
                          void close(s);
                        }}
                      >
                        <Trash2Icon className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <Card className="flex min-h-0 flex-col overflow-hidden">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center justify-between text-sm text-muted-foreground">
              <span>命令</span>
              {current && <span className="font-mono text-xs">{current.id}</span>}
            </CardTitle>
          </CardHeader>
          <CardContent className="flex min-h-0 flex-1 flex-col gap-3">
            <div className="flex items-center gap-2">
              <Input
                value={command}
                onChange={(e) => setCommand(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    void exec();
                  }
                }}
                placeholder="id"
                className="font-mono"
                disabled={!current}
              />
              <Button onClick={() => void exec()} disabled={!current || running || !command.trim()}>
                {running ? <Loader2Icon className="h-4 w-4 animate-spin" /> : <PlayIcon className="h-4 w-4" />}
                执行
              </Button>
            </div>

            <div className="min-h-0 flex-1 overflow-auto rounded-md border bg-[#0b0e14] p-3 font-mono text-xs text-neutral-200">
              {!current && <div className="text-neutral-500">选择一个会话后执行命令。</div>}
              {current && activeLogs.length === 0 && (
                <div className="text-neutral-500">
                  会话已就绪。输入命令并回车；输出按调用追加，上方命令不会留在目标 shell 历史之外。
                </div>
              )}
              {activeLogs.map((entry) => (
                <div key={entry.id} className="mb-3">
                  <div className="text-sky-400">
                    <span className="text-neutral-500">[{entry.at}]</span> $ {entry.command}
                  </div>
                  {entry.stdout && <pre className="whitespace-pre-wrap break-words">{entry.stdout}</pre>}
                  {entry.stderr && <pre className="whitespace-pre-wrap break-words text-amber-300">{entry.stderr}</pre>}
                  <div className={cn("text-neutral-500", entry.exitCode !== 0 && "text-red-400")}>
                    exit {entry.exitCode} · {entry.durationMs}ms
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      <OpenSessionDialog
        open={dialogOpen}
        busy={opening}
        onOpenChange={setDialogOpen}
        onSubmit={(form) => void submitOpen(form)}
      />
    </div>
  );
}

interface OpenForm {
  kind: string;
  host: string;
  port: string;
  user: string;
  secret: string;
  shellType: string;
  cmdParam: string;
  method: string;
}

const emptyForm: OpenForm = {
  kind: "webshell",
  host: "",
  port: "",
  user: "",
  secret: "",
  shellType: "php",
  cmdParam: "cmd",
  method: "POST",
};

function OpenSessionDialog({
  open,
  busy,
  onOpenChange,
  onSubmit,
}: {
  open: boolean;
  busy: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (form: OpenForm) => void;
}) {
  const [form, setForm] = React.useState<OpenForm>(emptyForm);
  React.useEffect(() => {
    if (open) setForm(emptyForm);
  }, [open]);

  const set = <K extends keyof OpenForm>(key: K, value: OpenForm[K]) => setForm((prev) => ({ ...prev, [key]: value }));

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>打开会话</DialogTitle>
          <DialogDescription>
            webshell 的 host 填已落地 shell 的完整 URL；其余类型填主机。凭据只用于本次连接，不落库。
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="sess-kind">类型</Label>
              <Select value={form.kind} onValueChange={(v) => set("kind", v)}>
                <SelectTrigger id="sess-kind">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {KINDS.map((k) => (
                    <SelectItem key={k} value={k}>
                      {k}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="sess-port">端口（可选）</Label>
              <Input
                id="sess-port"
                value={form.port}
                onChange={(e) => set("port", e.target.value)}
                placeholder="22"
                inputMode="numeric"
              />
            </div>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="sess-host">{form.kind === "webshell" ? "Shell URL" : "主机"}</Label>
            <Input
              id="sess-host"
              value={form.host}
              onChange={(e) => set("host", e.target.value)}
              placeholder={form.kind === "webshell" ? "http://target/shell.php" : "10.0.0.5"}
              className="font-mono"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="sess-user">用户</Label>
              <Input id="sess-user" value={form.user} onChange={(e) => set("user", e.target.value)} />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="sess-secret">口令 / 私钥</Label>
              <Input
                id="sess-secret"
                type="password"
                autoComplete="off"
                value={form.secret}
                onChange={(e) => set("secret", e.target.value)}
              />
            </div>
          </div>
          {form.kind === "webshell" && (
            <div className="grid grid-cols-3 gap-3">
              <div className="grid gap-1.5">
                <Label htmlFor="sess-shell">Shell 类型</Label>
                <Select value={form.shellType} onValueChange={(v) => set("shellType", v)}>
                  <SelectTrigger id="sess-shell">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {["php", "asp", "aspx", "jsp"].map((t) => (
                      <SelectItem key={t} value={t}>
                        {t}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="sess-param">命令参数</Label>
                <Input id="sess-param" value={form.cmdParam} onChange={(e) => set("cmdParam", e.target.value)} />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="sess-method">方法</Label>
                <Select value={form.method} onValueChange={(v) => set("method", v)}>
                  <SelectTrigger id="sess-method">
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
          )}
        </div>
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button disabled={busy || !form.host.trim()} onClick={() => onSubmit(form)}>
            {busy && <Loader2Icon className="h-4 w-4 animate-spin" />}
            打开
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
