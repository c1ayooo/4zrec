"use client";

// SshTerminalDialog 全交互 SSH 终端(xterm.js + WebSocket):
// 协议与后端一致——二进制帧=stdin 字节,文本帧={"type":"resize",cols,rows}。
// 移植自 4zreco 的 SshTerminalDialog.vue(xterm + FitAddon + ResizeObserver)。
import * as React from "react";

import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";

import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import type { Connection } from "@/lib/types";

interface Props {
  connection: Connection | null;
  onClose: () => void;
}

export function SshTerminalDialog({ connection, onClose }: Props) {
  const hostRef = React.useRef<HTMLDivElement | null>(null);
  const termRef = React.useRef<Terminal | null>(null);
  const wsRef = React.useRef<WebSocket | null>(null);

  React.useEffect(() => {
    if (!connection || !hostRef.current) return;
    const term = new Terminal({
      cursorBlink: true,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
      fontSize: 13,
      theme: { background: "#0b0e14" },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(hostRef.current);
    fit.fit();
    termRef.current = term;

    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${window.location.host}/api/connections/${connection.id}/terminal`);
    ws.binaryType = "arraybuffer";
    wsRef.current = ws;
    term.writeln(`\x1b[90m连接 ${connection.username ? connection.username + "@" : ""}${connection.host}:${connection.port} …\x1b[0m`);

    ws.onopen = () => {
      ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      term.focus();
    };
    ws.onmessage = (ev) => {
      if (ev.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(ev.data));
      } else {
        term.write(String(ev.data));
      }
    };
    ws.onclose = () => term.writeln("\r\n\x1b[90m[会话已断开]\x1b[0m");
    ws.onerror = () => term.writeln("\r\n\x1b[31m[连接错误]\x1b[0m");

    const onData = term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(new TextEncoder().encode(data));
      }
    });
    const ro = new ResizeObserver(() => {
      try {
        fit.fit();
      } catch {
        /* ignore */
      }
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      }
    });
    ro.observe(hostRef.current);

    return () => {
      ro.disconnect();
      onData.dispose();
      ws.close();
      term.dispose();
      termRef.current = null;
      wsRef.current = null;
    };
  }, [connection]);

  return (
    <Dialog open={connection !== null} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle>
            SSH 终端 · {connection ? `${connection.username ? connection.username + "@" : ""}${connection.host}:${connection.port}` : ""}
          </DialogTitle>
        </DialogHeader>
        <div
          ref={hostRef}
          className="h-96 w-full overflow-hidden rounded-md border bg-[#0b0e14] p-1"
        />
        <p className="text-muted-foreground text-xs">
          全交互 PTY 会话(xterm.js);断开即随页面关闭。一次性命令用「命令执行」。
        </p>
      </DialogContent>
    </Dialog>
  );
}
