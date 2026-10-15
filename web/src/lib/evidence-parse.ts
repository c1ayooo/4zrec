// evidence-parse.ts — 证据 / PoC 文本的结构化解析(纯逻辑,供 EvidenceViewer 渲染)。
// evidence 由 LLM 产出,库内真实样本呈高度模式化:步骤标记(① / 请求1： / 1)) +
// curl 命令 + "→" 引出的响应 + 尾部结论段(对照实验 / 影响面提示 / 说明)。
// 按这些启发式把自由文本切成块;一条结构都识别不出时返回 null,
// 调用方回退原始 <pre> 展示,保证输出格式漂移时始终可读。

export type SegmentKind = "text" | "command" | "response";

export type EvidenceSegment = {
  kind: SegmentKind;
  text: string;
  // 同段落内与前一段拼接时的连接符(还原被 " → " 切分吞掉的箭头),仅 text 段使用。
  sep?: string;
};

export type EvidenceBlock =
  | { kind: "step"; index: number; title: string; paras: EvidenceSegment[][] }
  | { kind: "note"; label: string; paras: EvidenceSegment[][] }
  | { kind: "plain"; paras: EvidenceSegment[][] };

const CIRCLED = "①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳";

// 行首步骤标记:① / 请求1： / 请求2（同凭证…）： / 第2步： / 3) / 4) / "# 1." / "## 2、"
function matchStep(line: string): { index: number; rest: string; title?: string } | null {
  let m = /^([①-⑳])\s*/.exec(line);
  if (m) {
    const n = CIRCLED.indexOf(m[1]) + 1;
    return n > 0 ? { index: n, rest: line.slice(m[0].length) } : null;
  }
  m = /^(?:请求|步骤)\s*(\d+)\s*(?:[（(]([^（()）]{1,40})[）)])?\s*[：:]\s*/.exec(line);
  if (m) return { index: Number(m[1]), rest: line.slice(m[0].length), title: m[2] };
  m = /^第\s*(\d+)\s*步\s*[：:]?\s*/.exec(line);
  if (m) return { index: Number(m[1]), rest: line.slice(m[0].length) };
  m = /^(\d{1,2})\s*[)）]\s*/.exec(line);
  if (m) return { index: Number(m[1]), rest: line.slice(m[0].length) };
  // markdown 风格编号标题(# 1. / ## 2、),标题即步骤名
  m = /^#{1,3}\s*(\d{1,2})\s*[.、)）]?\s*/.exec(line);
  if (m) {
    const rest = line.slice(m[0].length).trim();
    if (rest.length <= 120) return { index: Number(m[1]), rest: "", title: rest };
  }
  return null;
}

// 行首结论段标记,两种形态:裸形式「对照: …」与规范引用形式「> **对照**: …」。
// 长词在前,避免「对照实验」被「对照」抢先匹配。
const NOTE_LABELS = "文件名勘误|对照实验|影响面提示|影响面|风险提示|合规声明|合规|结论|说明|备注|勘误|对照|注意";
const NOTE_RE = new RegExp(`^(${NOTE_LABELS})\\s*[：:]\\s*`);
const NOTE_QUOTE_RE = new RegExp(`^>\\s*\\*\\*(${NOTE_LABELS})\\*\\*\\s*[：:]\\s*`);

function matchNote(line: string): { label: string; rest: string } | null {
  const m = NOTE_QUOTE_RE.exec(line) ?? NOTE_RE.exec(line);
  if (!m) return null;
  return { label: m[1], rest: line.slice(m[0].length) };
}

function isCommandStart(t: string): boolean {
  return (
    /^[$%]\s+\S/.test(t) ||
    /^curl(?:\.exe)?(?:\s|$)/.test(t) ||
    /^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S/.test(t)
  );
}

function classifySegment(t: string, allowHttp: boolean): SegmentKind {
  if (isCommandStart(t)) return "command";
  if (t.startsWith("{") || t.startsWith("[")) return "response";
  if (allowHttp && (/^HTTP\b/.test(t) || /^\d{3}\b/.test(t))) return "response";
  return "text";
}

// 把一行按 " → " 切成段并分类。全为 text 时保留原行(箭头属于正文,如 enc(...)→解密 链式
// 叙述);一旦判出 command/response,行内剩余 text 段再按状态码开头(HTTP 200 / 401"…")
// 放宽复核——它们处于响应链上下文里,而"2022 年…"这类散文不会出现在这种行上。
function segmentsForLine(line: string): EvidenceSegment[] {
  const parts = line
    .split(/\s*→\s*/)
    .map((p) => p.trim())
    .filter(Boolean);
  if (parts.length <= 1) {
    const t = line.trim();
    if (!t) return [];
    const kind: SegmentKind = classifySegment(t, /^HTTP\b/.test(t));
    return [{ kind, text: t }];
  }
  let kinds = parts.map((p) => classifySegment(p, false));
  if (kinds.every((k) => k === "text")) kinds = parts.map((p) => classifySegment(p, true));
  else kinds = kinds.map((k, idx) => (k === "text" ? classifySegment(parts[idx], true) : k));
  if (kinds.every((k) => k === "text")) return [{ kind: "text", text: line.trim() }];
  return parts.map((p, idx) => ({ kind: kinds[idx], text: p, ...(idx > 0 ? { sep: " → " } : {}) }));
}

export function parseEvidence(raw: string): EvidenceBlock[] | null {
  const lines = raw.replace(/\r\n?/g, "\n").split("\n");
  const blocks: EvidenceBlock[] = [];
  let cur: EvidenceBlock | null = null;
  let hasStructure = false;
  let contCommand = false;

  const ensureBlock = (): EvidenceBlock => {
    if (!cur) {
      cur = { kind: "plain", paras: [] };
      blocks.push(cur);
    }
    return cur;
  };
  const pushSeg = (seg: EvidenceSegment) => {
    const b = ensureBlock();
    if (!b.paras.length) b.paras.push([]);
    b.paras[b.paras.length - 1].push(seg);
  };
  const newPara = () => {
    if (cur && cur.paras.length && cur.paras[cur.paras.length - 1].length) cur.paras.push([]);
  };
  const lastSeg = (): EvidenceSegment | null => {
    if (!cur || !cur.paras.length) return null;
    const p = cur.paras[cur.paras.length - 1];
    return p.length ? p[p.length - 1] : null;
  };

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    // ``` 围栏:生成侧将来输出 markdown 时前端零改动受益。bash 类按命令、其余按代码输出。
    const fence = /^```(\w*)/.exec(trimmed);
    if (fence) {
      const lang = fence[1].toLowerCase();
      const body: string[] = [];
      i += 1;
      while (i < lines.length && !lines[i].trim().startsWith("```")) {
        body.push(lines[i]);
        i += 1;
      }
      i += 1;
      pushSeg({
        kind: /^(?:bash|sh|zsh|shell|console|curl)$/.test(lang) ? "command" : "response",
        text: body.join("\n"),
      });
      hasStructure = true;
      continue;
    }

    if (!trimmed) {
      newPara();
      contCommand = false;
      i += 1;
      continue;
    }

    // 命令续行:上一段命令以 \ 结尾时并入同一段。
    if (contCommand) {
      contCommand = false;
      const last = lastSeg();
      if (last && last.kind === "command") {
        last.text += `\n${trimmed}`;
        if (trimmed.endsWith("\\")) contCommand = true;
        i += 1;
        continue;
      }
    }

    const step = matchStep(trimmed);
    if (step) {
      hasStructure = true;
      let title = step.title ?? "";
      let rest = step.rest.trim();
      if (!title) {
        const t = /^(.{1,60}?)[：:]\s*$/.exec(rest);
        if (t) {
          title = t[1];
          rest = "";
        }
      }
      cur = { kind: "step", index: step.index, title, paras: [] };
      blocks.push(cur);
      if (rest) segmentsForLine(rest).forEach(pushSeg);
      i += 1;
      continue;
    }

    const note = matchNote(trimmed);
    if (note) {
      hasStructure = true;
      cur = { kind: "note", label: note.label, paras: [] };
      blocks.push(cur);
      if (note.rest.trim()) segmentsForLine(note.rest).forEach(pushSeg);
      i += 1;
      continue;
    }

    // 引用续行:结论段的下一行仍以 > 开头时并入该结论段。
    if (/^>\s?/.test(trimmed) && cur?.kind === "note") {
      const l = trimmed.replace(/^>\s?/, "");
      if (l.trim()) segmentsForLine(l).forEach(pushSeg);
      else newPara();
      i += 1;
      continue;
    }

    // 命令/响应的缩进输出行(如 curl 下一行的 JS 代码)。
    const last = lastSeg();
    if (last && (last.kind === "command" || last.kind === "response") && /^(?: {2,}|\t)/.test(line)) {
      pushSeg({ kind: "response", text: trimmed });
      i += 1;
      continue;
    }

    // 行首箭头:独立响应行。
    if (/^(?:→|->)/.test(trimmed)) {
      hasStructure = true;
      segmentsForLine(trimmed.replace(/^(?:→|->)\s*/, "")).forEach(pushSeg);
      i += 1;
      continue;
    }

    const segs = segmentsForLine(trimmed);
    segs.forEach(pushSeg);
    if (segs.some((s) => s.kind === "command" || s.kind === "response")) hasStructure = true;
    if (segs.length && segs[segs.length - 1].kind === "command" && trimmed.endsWith("\\")) contCommand = true;
    i += 1;
  }

  for (const b of blocks) {
    while (b.paras.length && !b.paras[b.paras.length - 1].length) b.paras.pop();
  }
  return hasStructure ? blocks : null;
}

// extractJsonBlob 在一段文本里定位第一个平衡的 {...} / [...] 片段(跳过字符串字面量
// 内的括号),返回其前后文本;找不到则返回 null。用于「→ HTTP 200 {"code":…}（注释）」
// 这类响应段:JSON 部分着色,前后缀原样保留。
export function extractJsonBlob(text: string): { before: string; json: string; after: string } | null {
  const start = text.search(/[{[]/);
  if (start < 0) return null;
  const open = text[start];
  const close = open === "{" ? "}" : "]";
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === open) depth++;
    else if (ch === close) {
      depth--;
      if (depth === 0) {
        return { before: text.slice(0, start), json: text.slice(start, i + 1), after: text.slice(i + 1) };
      }
    }
  }
  return null;
}
