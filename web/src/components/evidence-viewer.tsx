"use client";

import * as React from "react";

import { InfoIcon, WrapTextIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { type EvidenceBlock, type EvidenceSegment, extractJsonBlob, parseEvidence } from "@/lib/evidence-parse";
import { JsonBody, statusTone } from "@/lib/http-highlight";
import type { FindingReproduction } from "@/lib/types";
import { cn } from "@/lib/utils";

// compact: 行内展开(任务发现 tab)用——限高更矮、间距/内边距/字号整体收一档,
// 换行开关浮动不占行。详情页用默认档。
const CompactCtx = React.createContext(false);

// EvidenceViewer —— 漏洞详情页「证据 / PoC」的分层渲染:
// 1. agent 上报的结构化 reproduction(确定性,零解析,权威复现过程);
// 2. evidence 文本按生成侧规范(report_finding 工具描述里约定的
//    「## N. 标题 + ```bash/```json 围栏 + > 引用结论」)块化渲染;
// 3. 存量自由文本由 parseEvidence 的 legacy 规则容错切分;
// 4. 什么都识别不出时回退原始 <pre>。
// 命令/响应默认不换行(横向滚动),避免长 URL 被折断,可切换。

// ---------- 语法着色(与 HttpCodeBlock 同一套配色) ----------

function CommandHighlight({ text }: { text: string }) {
  const parts: React.ReactNode[] = [];
  let body = text;
  const prompt = /^([$%])\s+/.exec(body);
  if (prompt) {
    parts.push(
      <span key="prompt" className="text-muted-foreground/70">
        {prompt[1]}{" "}
      </span>,
    );
    body = body.slice(prompt[0].length);
  }
  let first = true;
  for (const m of body.matchAll(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|[^\s'"]+|\s+/g)) {
    const tok = m[0];
    let cls: string | undefined;
    if (/https?:\/\//.test(tok) || tok.startsWith("/")) cls = "text-chart-2";
    else if (/^curl(?:\.exe)?$/.test(tok) || (first && /\S/.test(tok) && !tok.startsWith("-")))
      cls = "font-medium text-primary";
    else if (/^-{1,2}[\w-]+$/.test(tok)) cls = "text-chart-3";
    else if (/^(['"]).*\1$/.test(tok)) cls = "text-chart-4";
    parts.push(
      <span key={m.index} className={cls}>
        {tok}
      </span>,
    );
    if (tok.trim()) first = false;
  }
  return parts;
}

function ResponseHighlight({ text }: { text: string }) {
  const parts: React.ReactNode[] = [];
  let rest = text;
  const status = /^(HTTP(?:\/[\d.]+)?)\s+(\d{3})/.exec(rest);
  const bare = /^(\d{3})\b/.exec(rest);
  if (status) {
    parts.push(
      <span key="http" className="text-muted-foreground">
        {status[1]}{" "}
      </span>,
      <span key="code" className={statusTone(Number(status[2]))}>
        {status[2]}
      </span>,
    );
    rest = rest.slice(status[0].length);
  } else if (bare) {
    parts.push(
      <span key="code" className={statusTone(Number(bare[1]))}>
        {bare[1]}
      </span>,
    );
    rest = rest.slice(bare[0].length);
  }
  const blob = extractJsonBlob(rest);
  if (blob) {
    if (blob.before) parts.push(blob.before);
    parts.push(<JsonBody key="json" body={blob.json} />);
    if (blob.after) parts.push(blob.after);
  } else {
    parts.push(rest);
  }
  return parts;
}

// ---------- 块渲染 ----------

function CodeBlock({ kind, text, wrap }: { kind: "command" | "response"; text: string; wrap: boolean }) {
  const compact = React.useContext(CompactCtx);
  return (
    <div
      className={cn(
        "min-w-0 overflow-x-auto rounded-md border font-mono text-xs leading-relaxed",
        compact ? "px-2.5 py-1" : "px-3 py-2",
        kind === "command" ? "bg-muted/40" : "bg-background",
      )}
    >
      <code className={cn("block", wrap ? "break-words whitespace-pre-wrap" : "whitespace-pre")}>
        {kind === "command" ? <CommandHighlight text={text} /> : <ResponseHighlight text={text} />}
      </code>
    </div>
  );
}

// ParaView 渲染一个段落:连续 text 段合并成正文段落(用 sep 还原被切分的 → 箭头),
// 连续同类 command/response 段合并为一个代码块(命令的多行输出)。
function ParaView({ segs, wrap }: { segs: EvidenceSegment[]; wrap: boolean }) {
  const compact = React.useContext(CompactCtx);
  const out: React.ReactNode[] = [];
  let text = "";
  let code: { kind: "command" | "response"; lines: string[] } | null = null;
  const flushText = () => {
    if (text) {
      out.push(
        <p key={`t${out.length}`} className={compact ? "text-[13px] leading-snug" : "text-sm leading-relaxed"}>
          {text}
        </p>,
      );
      text = "";
    }
  };
  const flushCode = () => {
    if (code) {
      out.push(<CodeBlock key={`c${out.length}`} kind={code.kind} text={code.lines.join("\n")} wrap={wrap} />);
      code = null;
    }
  };
  for (const seg of segs) {
    if (seg.kind === "text") {
      flushCode();
      text += (text ? (seg.sep ?? " ") : "") + seg.text;
    } else {
      flushText();
      if (code && code.kind === seg.kind) code.lines.push(seg.text);
      else {
        flushCode();
        code = { kind: seg.kind, lines: [seg.text] };
      }
    }
  }
  flushText();
  flushCode();
  return <div className={cn("flex flex-col", compact ? "gap-1" : "gap-1.5")}>{out}</div>;
}

function StepBadge({ index }: { index: number }) {
  const compact = React.useContext(CompactCtx);
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center justify-center rounded-full border bg-primary/10 px-1 font-mono text-[0.7rem] font-semibold text-primary tabular-nums",
        compact ? "h-4 min-w-4" : "h-5 min-w-5",
      )}
    >
      {index}
    </span>
  );
}

function StepView({ index, title, children }: { index: number; title?: string; children: React.ReactNode }) {
  const compact = React.useContext(CompactCtx);
  return (
    <section className={cn("flex flex-col", compact ? "gap-1" : "gap-1.5")}>
      <div className="flex items-center gap-2">
        <StepBadge index={index} />
        {title ? <span className="text-xs font-medium leading-5">{title}</span> : null}
      </div>
      <div className={cn("flex flex-col gap-1.5", compact ? "pl-6" : "pl-7")}>{children}</div>
    </section>
  );
}

function NoteView({ label, children }: { label: string; children: React.ReactNode }) {
  const compact = React.useContext(CompactCtx);
  return (
    <section
      className={cn("rounded-lg border border-dashed bg-muted/30", compact ? "px-2.5 py-1.5" : "px-3 py-2.5")}
    >
      <div className="mb-1 flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
        <InfoIcon className="size-3.5 shrink-0" />
        {label}
      </div>
      <div className={cn("flex flex-col", compact ? "gap-1" : "gap-1.5")}>{children}</div>
    </section>
  );
}

function BlocksView({ blocks, wrap }: { blocks: EvidenceBlock[]; wrap: boolean }) {
  const compact = React.useContext(CompactCtx);
  return (
    <div className={cn("flex flex-col", compact ? "gap-2.5" : "gap-4")}>
      {blocks.map((b, i) => {
        const paras = b.paras.map((p, j) => <ParaView key={j} segs={p} wrap={wrap} />);
        if (b.kind === "step") {
          return (
            <StepView key={i} index={b.index} title={b.title}>
              {paras}
            </StepView>
          );
        }
        if (b.kind === "note") {
          return (
            <NoteView key={i} label={b.label}>
              {paras}
            </NoteView>
          );
        }
        return (
          <div key={i} className={cn("flex flex-col", compact ? "gap-1" : "gap-1.5")}>
            {paras}
          </div>
        );
      })}
    </div>
  );
}

// ---------- 结构化 reproduction(权威复现过程,确定性渲染) ----------

function StructuredReproView({ repro, wrap }: { repro: FindingReproduction; wrap: boolean }) {
  const compact = React.useContext(CompactCtx);
  return (
    <div className={cn("flex flex-col", compact ? "gap-2.5" : "gap-4")}>
      {repro.entry_point ? (
        <div className="flex flex-col gap-1">
          <span className="text-xs font-medium text-muted-foreground">复现入口</span>
          <CodeBlock kind="command" text={repro.entry_point} wrap={wrap} />
        </div>
      ) : null}
      {repro.prerequisites?.length ? (
        <div className="flex flex-col gap-1">
          <span className="text-xs font-medium text-muted-foreground">前置条件</span>
          <ul className={cn("ml-4 list-disc text-sm leading-relaxed", compact ? "space-y-0.5" : "space-y-1")}>
            {repro.prerequisites.map((p, i) => (
              <li key={i}>{p}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {repro.steps?.length ? (
        <div className={cn("flex flex-col", compact ? "gap-2.5" : "gap-4")}>
          {repro.steps.map((s, i) => (
            <section key={i} className={cn("flex flex-col", compact ? "gap-1" : "gap-1.5")}>
              <div className="flex items-center gap-2">
                <StepBadge index={i + 1} />
                {s.proves ? <span className="text-xs font-medium leading-5">{s.proves}</span> : null}
              </div>
              {(s.request || s.expected) && (
                <div className={cn("flex flex-col gap-1.5", compact ? "pl-6" : "pl-7")}>
                  {s.request ? <CodeBlock kind="command" text={s.request} wrap={wrap} /> : null}
                  {s.expected ? <CodeBlock kind="response" text={s.expected} wrap={wrap} /> : null}
                </div>
              )}
              {s.proves && !s.request && !s.expected ? (
                <p className={cn(compact ? "pl-6 text-[13px] leading-snug" : "pl-7 text-sm leading-relaxed")}>
                  {s.proves}
                </p>
              ) : null}
            </section>
          ))}
        </div>
      ) : null}
      {repro.provenance ? (
        <NoteView label="来源">
          <p className={compact ? "text-[13px] leading-snug" : "text-sm leading-relaxed"}>{repro.provenance}</p>
        </NoteView>
      ) : null}
    </div>
  );
}

// ---------- 入口 ----------

export function EvidenceViewer({
  text,
  reproduction,
  compact: compactMode,
}: {
  text: string;
  reproduction?: FindingReproduction;
  compact?: boolean;
}) {
  const [wrap, setWrap] = React.useState(false);
  const blocks = React.useMemo(() => parseEvidence(text), [text]);
  // reproduction 来自 LLM 上报的 jsonb,字段宽松校验:至少要有步骤或入口才值得切到结构化视图。
  const showRepro = Boolean(
    reproduction &&
      ((Array.isArray(reproduction.steps) && reproduction.steps.some((s) => s && (s.request || s.expected))) ||
        reproduction.entry_point),
  );

  const toggle = (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="icon-xs"
          aria-label={wrap ? "关闭自动换行" : "开启自动换行"}
          aria-pressed={wrap}
          onClick={() => setWrap((v) => !v)}
        >
          <WrapTextIcon />
        </Button>
      </TooltipTrigger>
      <TooltipContent side="bottom">{wrap ? "命令/响应改为横向滚动" : "命令/响应改为自动换行"}</TooltipContent>
    </Tooltip>
  );

  return (
    <CompactCtx.Provider value={!!compactMode}>
      {/* 紧凑模式(行内展开)下开关浮动到右上角,不再单独占一行 */}
      {compactMode ? null : <div className="flex justify-end">{toggle}</div>}
      <div className={cn("relative", compactMode ? "max-h-[40vh]" : "max-h-[65vh]", "overflow-y-auto pr-1")}>
        {compactMode ? <div className="absolute top-0 right-0 z-10">{toggle}</div> : null}
        {showRepro && reproduction ? (
          <>
            <StructuredReproView repro={reproduction} wrap={wrap} />
            {text.trim() ? (
              <details className="group mt-4 rounded-md border">
                <summary className="cursor-pointer select-none px-3 py-2 text-xs text-muted-foreground">
                  原始证据文本(evidence)
                </summary>
                <div className="border-t px-3 py-3">
                  {blocks ? <BlocksView blocks={blocks} wrap={wrap} /> : <FallbackPre text={text} />}
                </div>
              </details>
            ) : null}
          </>
        ) : (
          <EvidenceBlocksOrPre blocks={blocks} text={text} wrap={wrap} />
        )}
      </div>
    </CompactCtx.Provider>
  );
}

function EvidenceBlocksOrPre({
  blocks,
  text,
  wrap,
}: {
  blocks: ReturnType<typeof parseEvidence>;
  text: string;
  wrap: boolean;
}) {
  if (blocks) return <BlocksView blocks={blocks} wrap={wrap} />;
  return <FallbackPre text={text} />;
}

function FallbackPre({ text }: { text: string }) {
  const compact = React.useContext(CompactCtx);
  return (
    <pre
      className={cn(
        "overflow-auto rounded-md bg-muted font-mono text-xs whitespace-pre-wrap",
        compact ? "max-h-[40vh] px-2.5 py-1.5" : "max-h-[46vh] px-3 py-2",
      )}
    >
      {text}
    </pre>
  );
}
