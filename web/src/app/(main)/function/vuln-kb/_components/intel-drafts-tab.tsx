"use client";

import * as React from "react";

import {
  AlertTriangleIcon,
  CheckIcon,
  FileCode2Icon,
  FingerprintIcon,
  Loader2Icon,
  RefreshCwIcon,
  Trash2Icon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { IntelDraft } from "@/lib/types";

// severityTone 给等级徽章配色,与漏洞库列表保持一致。
function severityTone(v: string): string {
  if (v.includes("严重") || v.includes("critical")) return "border-destructive/30 bg-destructive/10 text-destructive";
  if (v.includes("高危") || v.includes("high")) return "border-warning/30 bg-warning/10 text-warning";
  if (v.includes("中危") || v.includes("medium")) return "border-info/30 bg-info/10 text-info";
  return "";
}

// IntelDraftsTab 列出「已生成但未入库」的流水线产物:漏洞模板(nuclei)与资产
// 指纹。两者都由模型补全、都会影响扫描链路,所以入库必须逐条由人点;不可用
// 的产物(如只拿 CVE 编号当 matcher)会标出来并要求重新生成。
export function IntelDraftsTab() {
  const [drafts, setDrafts] = React.useState<IntelDraft[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState<string | null>(null);
  const [openNuclei, setOpenNuclei] = React.useState<number | null>(null);
  const [openFp, setOpenFp] = React.useState<number | null>(null);

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .vulnIntelDrafts()
      .then((r) => {
        setDrafts(r.drafts ?? []);
        setError("");
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, []);

  React.useEffect(() => {
    load();
  }, [load]);

  const run = async (key: string, fn: () => Promise<unknown>) => {
    setBusy(key);
    setError("");
    try {
      await fn();
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  let body: React.ReactNode;
  if (loading && drafts.length === 0) {
    body = (
      <Card className="flex h-32 items-center justify-center text-muted-foreground">
        <Loader2Icon className="mr-2 size-4 animate-spin" /> 加载中…
      </Card>
    );
  } else if (drafts.length === 0) {
    body = (
      <Card className="flex h-32 items-center justify-center text-muted-foreground text-sm">
        暂无待确认产物。在漏洞详情里点「生成模板草稿」/「生成指纹草稿」,或在流水线设置里打开自动生成。
      </Card>
    );
  } else {
    body = (
      <div className="space-y-3">
        {drafts.map((d) => {
          const nucleiOpen = openNuclei === d.vuln_intel_id;
          const fpOpen = openFp === d.vuln_intel_id;
          const nucleiConfirmed = Boolean(d.nuclei_tpl_id);
          const fpConfirmed = Boolean(d.fingerprint_id);
          const hasNuclei = Boolean(d.nuclei_yaml) && !nucleiConfirmed;
          const hasFp = Boolean(d.fingerprint) && !fpConfirmed;
          return (
            <Card key={d.vuln_intel_id} className="overflow-hidden">
              <div className="flex flex-wrap items-center gap-2 p-3">
                <span className="min-w-0 flex-1 truncate font-medium text-sm" title={d.title}>
                  {d.title_zh || d.title}
                </span>
                {d.severity ? (
                  <Badge variant="outline" className={severityTone(d.severity)}>
                    {d.severity}
                  </Badge>
                ) : null}
                {d.cve ? <span className="font-mono text-[11px] text-muted-foreground">{d.cve}</span> : null}
              </div>

              <div className="divide-y border-t">
                {/* ---- nuclei 模板 ---- */}
                <div className="flex flex-wrap items-center gap-2 px-3 py-2">
                  <FileCode2Icon className="size-3.5 text-muted-foreground" />
                  <span className="font-medium text-xs">nuclei 模板</span>
                  {nucleiConfirmed ? (
                    <Badge variant="outline" className="font-mono text-[11px]">
                      已入库 {d.nuclei_tpl_id}
                    </Badge>
                  ) : hasNuclei ? (
                    <>
                      {d.nuclei_usable ? (
                        <Badge className="bg-success/15 text-[11px] text-success">可入库</Badge>
                      ) : (
                        <Badge className="flex items-center gap-1 bg-warning/15 text-[11px] text-warning">
                          <AlertTriangleIcon className="size-3" /> 不可用
                        </Badge>
                      )}
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 px-2"
                        onClick={() => setOpenNuclei(nucleiOpen ? null : d.vuln_intel_id)}
                      >
                        {nucleiOpen ? "收起" : "查看 YAML"}
                      </Button>
                      <div className="ml-auto flex items-center gap-1">
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={busy === `nuclei-draft-${d.vuln_intel_id}`}
                          onClick={() =>
                            run(`nuclei-draft-${d.vuln_intel_id}`, () => api.vulnIntelNucleiDraft(d.vuln_intel_id))
                          }
                        >
                          <RefreshCwIcon className="mr-1 size-3.5" />
                          重新生成
                        </Button>
                        <Button
                          size="sm"
                          disabled={!d.nuclei_usable || busy === `nuclei-ok-${d.vuln_intel_id}`}
                          onClick={() =>
                            run(`nuclei-ok-${d.vuln_intel_id}`, () => api.vulnIntelNucleiConfirm(d.vuln_intel_id))
                          }
                        >
                          <CheckIcon className="mr-1 size-3.5" />
                          确认入库
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={busy === `nuclei-del-${d.vuln_intel_id}`}
                          onClick={() =>
                            run(`nuclei-del-${d.vuln_intel_id}`, () => api.vulnIntelNucleiDiscard(d.vuln_intel_id))
                          }
                        >
                          <Trash2Icon className="mr-1 size-3.5" />
                          丢弃
                        </Button>
                      </div>
                    </>
                  ) : (
                    <span className="text-muted-foreground text-xs">未生成模板草稿</span>
                  )}
                </div>
                {nucleiOpen && d.nuclei_yaml ? (
                  <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all bg-muted/40 px-3 py-2 font-mono text-xs">
                    {d.nuclei_yaml}
                  </pre>
                ) : null}
                {hasNuclei && !d.nuclei_usable && d.nuclei_issue ? (
                  <p className="px-3 pb-2 text-[11px] text-warning">{d.nuclei_issue}</p>
                ) : null}

                {/* ---- 指纹规则 ---- */}
                <div className="flex flex-wrap items-center gap-2 px-3 py-2">
                  <FingerprintIcon className="size-3.5 text-muted-foreground" />
                  <span className="font-medium text-xs">资产指纹</span>
                  {fpConfirmed ? (
                    <Badge variant="outline" className="font-mono text-[11px]">
                      已入库 {d.fingerprint_id}
                    </Badge>
                  ) : hasFp ? (
                    <>
                      {d.fingerprint_usable ? (
                        <Badge className="bg-success/15 text-[11px] text-success">可入库</Badge>
                      ) : (
                        <Badge className="flex items-center gap-1 bg-warning/15 text-[11px] text-warning">
                          <AlertTriangleIcon className="size-3" /> 不可用
                        </Badge>
                      )}
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 px-2"
                        onClick={() => setOpenFp(fpOpen ? null : d.vuln_intel_id)}
                      >
                        {fpOpen ? "收起" : "查看规则"}
                      </Button>
                      <div className="ml-auto flex items-center gap-1">
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={busy === `fp-draft-${d.vuln_intel_id}`}
                          onClick={() =>
                            run(`fp-draft-${d.vuln_intel_id}`, () => api.vulnIntelFingerprintDraft(d.vuln_intel_id))
                          }
                        >
                          <RefreshCwIcon className="mr-1 size-3.5" />
                          重新生成
                        </Button>
                        <Button
                          size="sm"
                          disabled={!d.fingerprint_usable || busy === `fp-ok-${d.vuln_intel_id}`}
                          onClick={() =>
                            run(`fp-ok-${d.vuln_intel_id}`, () => api.vulnIntelFingerprintConfirm(d.vuln_intel_id))
                          }
                        >
                          <CheckIcon className="mr-1 size-3.5" />
                          确认入库
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={busy === `fp-del-${d.vuln_intel_id}`}
                          onClick={() =>
                            run(`fp-del-${d.vuln_intel_id}`, () => api.vulnIntelFingerprintDiscard(d.vuln_intel_id))
                          }
                        >
                          <Trash2Icon className="mr-1 size-3.5" />
                          丢弃
                        </Button>
                      </div>
                    </>
                  ) : (
                    <span className="text-muted-foreground text-xs">未生成指纹草稿</span>
                  )}
                </div>
                {fpOpen && d.fingerprint ? (
                  <div className="bg-muted/40 px-3 py-2 font-mono text-xs">
                    <div>name: {d.fingerprint_name || "-"}</div>
                    <div>category: {d.fingerprint_category || "-"}</div>
                    <div className="whitespace-pre-wrap break-all">expression: {d.fingerprint_expression || "-"}</div>
                  </div>
                ) : null}
                {hasFp && !d.fingerprint_usable && d.fingerprint_issue ? (
                  <p className="px-3 pb-2 text-[11px] text-warning">{d.fingerprint_issue}</p>
                ) : null}
              </div>
            </Card>
          );
        })}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-muted-foreground text-xs">
          {drafts.length > 0
            ? `${drafts.length} 条情报有产物待确认 —— 确认后模板写入 nuclei 模板库、指纹写入指纹规则库并参与扫描`
            : "没有待确认的产物"}
        </p>
        <Button variant="outline" size="sm" className="ml-auto" onClick={load}>
          <RefreshCwIcon className="mr-1 size-3.5" /> 刷新
        </Button>
      </div>

      {error ? (
        <p className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-destructive text-xs">
          {error}
        </p>
      ) : null}

      {body}

      <p className="text-muted-foreground text-xs leading-relaxed">
        nuclei 模板落在 <code className="rounded bg-muted px-1">data/nuclei/custom-templates/</code>（带{" "}
        <code className="rounded bg-muted px-1">info.author: 4zrec</code>），指纹规则以{" "}
        <code className="rounded bg-muted px-1">source=custom</code> 写进统一指纹库，两者都走各自的索引/缓存热加载。
        「不可用」表示 matcher / 表达式无法在真实目标上命中（例如只拿 CVE 编号当特征），需要重新生成或丢弃。
      </p>
    </div>
  );
}
