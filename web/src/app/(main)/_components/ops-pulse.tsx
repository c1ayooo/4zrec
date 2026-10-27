"use client";

import * as React from "react";

import Link from "next/link";

import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

// OpsPulse 全局态势条：顶栏下一行常驻的作业脉搏——运行中任务、待审批数、LLM 状态。
// 只让有内容的项发声（N=0 的待审批不渲染），保持 quiet；30s 轮询，出错静默保留旧值。
export function OpsPulse({ className }: { className?: string }) {
  const [running, setRunning] = React.useState<string | null>(null);
  const [known, setKnown] = React.useState(false);
  const [llm, setLlm] = React.useState<boolean | null>(null);
  const [interceptPending, setInterceptPending] = React.useState(0);
  const [assetPending, setAssetPending] = React.useState(0);

  React.useEffect(() => {
    let cancelled = false;
    async function load() {
      const [stats, intercept, assets] = await Promise.allSettled([
        api.stats(),
        api.interceptPending(),
        api.pendingAssets(0, 1, 0),
      ]);
      if (cancelled) return;
      if (stats.status === "fulfilled") {
        const task = stats.value.active_task;
        setRunning(task ? task.name || task.description || `任务 ${task.id}` : null);
        setLlm(stats.value.llm_configured);
        setKnown(true);
      }
      setInterceptPending(intercept.status === "fulfilled" ? intercept.value.length : 0);
      setAssetPending(assets.status === "fulfilled" ? assets.value.total : 0);
    }
    void load();
    const timer = setInterval(() => void load(), 30000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  return (
    <div
      className={cn(
        "flex h-8 shrink-0 items-center gap-4 border-b px-4 text-muted-foreground text-xs lg:px-6",
        className,
      )}
    >
      {known && running ? (
        <span className="flex min-w-0 items-center gap-1.5">
          <span className="size-1.5 shrink-0 animate-pulse rounded-full bg-success" />
          <span className="truncate text-foreground">{running}</span>
        </span>
      ) : null}
      {known && !running ? (
        <span className="flex items-center gap-1.5">
          <span className="size-1.5 shrink-0 rounded-full bg-border" />
          空闲
        </span>
      ) : null}
      {interceptPending > 0 ? (
        <Link
          href="/system/intercept/approvals"
          className="flex items-center gap-1 tabular-nums transition-colors hover:text-foreground"
        >
          拦截待审批 {interceptPending}
        </Link>
      ) : null}
      {assetPending > 0 ? (
        <Link
          href="/function/approvals"
          className="flex items-center gap-1 tabular-nums transition-colors hover:text-foreground"
        >
          资产待审批 {assetPending}
        </Link>
      ) : null}
      {llm != null && <span className="ml-auto tabular-nums">{llm ? "LLM 就绪" : "LLM 未配置"}</span>}
    </div>
  );
}
