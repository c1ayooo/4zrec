import type * as React from "react";

// HTTP/JSON 语法着色的共享实现：HttpCodeBlock(原始报文)与 EvidenceViewer(证据文本中
// 内嵌的响应片段)共用，避免两份手写 tokenizer 漂移。

export function statusTone(status: number) {
  if (status >= 500) return "text-red-500";
  if (status >= 400) return "text-amber-500";
  if (status >= 300) return "text-blue-500";
  if (status >= 200) return "text-emerald-500";
  return "text-muted-foreground";
}

export function JsonBody({ body }: { body: string }) {
  const parts: React.ReactNode[] = [];
  const tokens = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
  let cursor = 0;
  for (const match of body.matchAll(tokens)) {
    const index = match.index ?? 0;
    if (index > cursor) parts.push(body.slice(cursor, index));
    let className = "text-chart-4";
    if (match[1]) className = match[2] ? "text-primary" : "text-chart-2";
    else if (match[3]) className = "text-chart-3";
    parts.push(
      <span key={`${index}-${match[0].length}`} className={className}>
        {match[0]}
      </span>,
    );
    cursor = index + match[0].length;
  }
  if (cursor < body.length) parts.push(body.slice(cursor));
  return parts;
}

export function MarkupBody({ body }: { body: string }) {
  const parts: React.ReactNode[] = [];
  const tags = /<\/?[A-Za-z][^>]*>|<!--[\s\S]*?-->/g;
  let cursor = 0;
  for (const match of body.matchAll(tags)) {
    const index = match.index ?? 0;
    if (index > cursor) parts.push(body.slice(cursor, index));
    parts.push(
      <span key={`${index}-${match[0].length}`} className="text-primary">
        {match[0]}
      </span>,
    );
    cursor = index + match[0].length;
  }
  if (cursor < body.length) parts.push(body.slice(cursor));
  return parts;
}

export type BodyFormat = "json" | "markup" | "plain";

export function detectBodyFormat(body: string): BodyFormat {
  const trimmed = body.trimStart();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) return "json";
  if (trimmed.startsWith("<")) return "markup";
  return "plain";
}
