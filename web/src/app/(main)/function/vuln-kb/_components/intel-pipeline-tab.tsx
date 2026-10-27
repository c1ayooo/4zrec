"use client";

import * as React from "react";

import { AlertTriangleIcon, Loader2Icon, RefreshCwIcon, SparklesIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import type { VulnPipelineStatus } from "@/lib/types";

type ToggleKey = "analyze_enabled" | "auto_translate" | "auto_nuclei" | "auto_fingerprint" | "notify_enabled";

// 四个开关的说明。顺序即展示顺序：先决定要不要分析，再是中文化、模板化、通知。
const TOGGLES: { key: ToggleKey; title: string; desc: string }[] = [
  {
    key: "analyze_enabled",
    title: "AI 分析",
    desc: "用 LLM 为情报生成中文简介、漏洞原理、攻击范围与可运行的验证 PoC。需要先在「系统 → LLM 配置」激活一个模型。",
  },
  {
    key: "auto_translate",
    title: "自动中文化",
    desc: "把英文情报的标题与描述翻成中文，CVE 编号与组件名保留原文。关闭 AI 分析时，这是唯一的补全路径。",
  },
  {
    key: "auto_nuclei",
    title: "分析后自动生成 nuclei 模板草稿",
    desc: "生成检测模板草稿，但不写入模板库。草稿集中在「模板待确认」页，逐条看过 YAML 再点「确认入库」才会落进 data/nuclei/custom-templates/ 并参与扫描。",
  },
  {
    key: "auto_fingerprint",
    title: "分析后自动生成资产指纹草稿",
    desc: "生成资产指纹规则草稿，但不写指纹库。指纹决定「这台机器装的是不是受影响产品」，直接影响 fingerprint_scan 的资产归类；草稿集中在「产物待确认」页，确认后才进统一指纹库。",
  },
  {
    key: "notify_enabled",
    title: "高危情报 IM 通知",
    desc: "单轮抓取新增高危/严重情报时，推一条汇总通知（复用「系统 → 通知」里已配的渠道）。",
  },
];

export function IntelPipelineTab() {
  const [status, setStatus] = React.useState<VulnPipelineStatus | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState<ToggleKey | null>(null);
  const [error, setError] = React.useState("");

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .vulnIntelPipeline()
      .then((r) => {
        setStatus(r.pipeline);
        setError("");
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, []);

  React.useEffect(() => {
    load();
  }, [load]);

  const toggle = async (key: ToggleKey, value: boolean) => {
    if (!status) return;
    setSaving(key);
    // 乐观更新：开关立刻响应，失败再回滚。
    setStatus({ ...status, [key]: value });
    try {
      const r = await api.setVulnIntelPipeline({ [key]: value });
      setStatus(r.pipeline);
      setError("");
    } catch (e) {
      setStatus((s) => (s ? { ...s, [key]: !value } : s));
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(null);
    }
  };

  if (loading && !status) {
    return (
      <Card className="flex h-32 items-center justify-center text-muted-foreground">
        <Loader2Icon className="mr-2 size-4 animate-spin" /> 加载流水线状态…
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        {status?.llm_ready ? (
          <Badge variant="outline" className="border-success/30 bg-success/10 text-success">
            <SparklesIcon className="mr-1 size-3" /> LLM 已就绪
          </Badge>
        ) : (
          <Badge variant="outline" className="border-warning/30 bg-warning/10 text-warning">
            <AlertTriangleIcon className="mr-1 size-3" /> 未配置 LLM，分析会跳过
          </Badge>
        )}
        {status ? (
          <>
            <span className="text-muted-foreground text-xs">
              已分析 {status.analyzed} 条 · 待分析 {status.pending} 条
            </span>
            {status.running ? (
              <span className="flex items-center gap-1 text-muted-foreground text-xs">
                <Loader2Icon className="size-3 animate-spin" /> 正在分析…
              </span>
            ) : null}
            {status.last_run ? (
              <span className="text-muted-foreground text-xs">
                · 上轮成功 {status.last_done} / 失败 {status.last_failed}
              </span>
            ) : null}
          </>
        ) : null}
        <Button variant="outline" size="sm" className="ml-auto" onClick={load}>
          <RefreshCwIcon className="mr-1 size-3.5" /> 刷新
        </Button>
      </div>

      {error ? (
        <p className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-destructive text-xs">
          {error}
        </p>
      ) : null}

      <Card className="divide-y">
        {TOGGLES.map((t) => (
          <div key={t.key} className="flex items-start justify-between gap-4 p-4">
            <div className="space-y-1">
              <p className="font-medium text-sm">{t.title}</p>
              <p className="max-w-2xl text-muted-foreground text-xs leading-relaxed">{t.desc}</p>
            </div>
            <Switch
              checked={Boolean(status?.[t.key])}
              disabled={saving === t.key}
              onCheckedChange={(v) => toggle(t.key, v)}
            />
          </div>
        ))}
      </Card>

      <p className="text-muted-foreground text-xs leading-relaxed">
        分析按 10 分钟一轮在后台跑，每轮处理 {5} 条。单条失败会记录原因并在下一轮重试，不影响整批。模板草稿不落库：
        在漏洞详情或「模板待确认」页点「确认入库」后，模板才写进{" "}
        <code className="rounded bg-muted px-1">data/nuclei/custom-templates/</code>（带{" "}
        <code className="rounded bg-muted px-1">info.author: 4zrec</code>），之后可在「nuclei 模板」页编辑或用于扫描。
      </p>
    </div>
  );
}
