"use client";

import * as React from "react";

import { PlusIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import type { LLMPricing } from "@/lib/types";

// 一行编辑态：数值用字符串承接输入，保存时再转 number。
type Row = {
  key: string;
  model_pattern: string;
  input_per_mtok: string;
  output_per_mtok: string;
  cache_read_per_mtok: string;
  cache_write_per_mtok: string;
  currency: string;
};

function toRow(p: LLMPricing): Row {
  const num = (n: number) => (n > 0 ? String(n) : "");
  return {
    key: p.model_pattern,
    model_pattern: p.model_pattern,
    input_per_mtok: num(p.input_per_mtok),
    output_per_mtok: num(p.output_per_mtok),
    cache_read_per_mtok: num(p.cache_read_per_mtok),
    cache_write_per_mtok: num(p.cache_write_per_mtok),
    currency: p.currency || "CNY",
  };
}

function emptyRow(model = "", currency = "CNY"): Row {
  return {
    key: `${model || "new"}-${Math.random().toString(36).slice(2, 8)}`,
    model_pattern: model,
    input_per_mtok: "",
    output_per_mtok: "",
    cache_read_per_mtok: "",
    cache_write_per_mtok: "",
    currency,
  };
}

// LLMPricingDialog 配置每 1M token 的单价（未命中输入 / 输出 / 缓存读 / 缓存写）。
// 账本里出现过但没有规则的模型会自动预填成一行，保存后仪表盘立即重算费用。
export function LLMPricingDialog({
  open,
  onOpenChange,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSaved?: () => void;
}) {
  const [rows, setRows] = React.useState<Row[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [error, setError] = React.useState("");

  React.useEffect(() => {
    if (!open) return;
    let alive = true;
    setLoading(true);
    setError("");
    api
      .llmPricing()
      .then((book) => {
        if (!alive) return;
        const byPattern = new Map(book.rules.map((r) => [r.model_pattern, r]));
        const rowsOut: Row[] = book.rules.map(toRow);
        // 账本里有消耗、但还没配单价的模型追加空行，方便直接填写。
        for (const m of book.models) {
          if (!m.model || byPattern.has(m.model)) continue;
          const used = m.input_tokens + m.output_tokens + m.cache_read_tokens + m.cache_write_tokens > 0;
          if (used) rowsOut.push(emptyRow(m.model));
        }
        if (rowsOut.length === 0) rowsOut.push(emptyRow());
        setRows(rowsOut);
      })
      .catch((e) => alive && setError((e as Error).message || "加载单价失败"))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [open]);

  const patch = (key: string, field: keyof Row, value: string) => {
    setRows((prev) => prev.map((r) => (r.key === key ? { ...r, [field]: value } : r)));
  };

  const save = async () => {
    const rules: LLMPricing[] = [];
    for (const r of rows) {
      const pattern = r.model_pattern.trim();
      if (!pattern) continue;
      const num = (v: string) => {
        const n = Number(v.trim() === "" ? 0 : v);
        return Number.isFinite(n) && n >= 0 ? n : 0;
      };
      rules.push({
        model_pattern: pattern,
        input_per_mtok: num(r.input_per_mtok),
        output_per_mtok: num(r.output_per_mtok),
        cache_read_per_mtok: num(r.cache_read_per_mtok),
        cache_write_per_mtok: num(r.cache_write_per_mtok),
        currency: r.currency.trim() || "CNY",
      });
    }
    if (rules.length === 0) {
      toast.error("至少保留一条有效单价规则");
      return;
    }
    setSaving(true);
    try {
      await api.saveLLMPricing(rules);
      toast.success(`已保存 ${rules.length} 条模型单价`);
      onSaved?.();
      onOpenChange(false);
    } catch (e) {
      toast.error((e as Error).message || "保存失败");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>模型单价</DialogTitle>
          <DialogDescription>
            按每 100 万 tokens 计价。缓存命中通常远低于未命中输入，填你实际账单的单价即可；支持
            <code className="mx-1 rounded bg-muted px-1">deepseek-*</code>
            这类前缀通配。保存后仪表盘按 model 匹配规则实时重算费用。
          </DialogDescription>
        </DialogHeader>

        {error ? <p className="text-destructive text-sm">{error}</p> : null}
        {loading ? (
          <div className="flex flex-col gap-2">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        ) : (
          <div className="max-h-[55vh] overflow-auto rounded-lg border">
            <div className="grid grid-cols-[1.4fr_repeat(4,minmax(0,0.85fr))_64px_36px] gap-2 border-b bg-muted/40 px-3 py-2 text-[11px] text-muted-foreground">
              <span>模型 / 通配</span>
              <span>输入(未命中)</span>
              <span>输出</span>
              <span>缓存读</span>
              <span>缓存写</span>
              <span>币种</span>
              <span />
            </div>
            {rows.map((r) => (
              <div
                key={r.key}
                className="grid grid-cols-[1.4fr_repeat(4,minmax(0,0.85fr))_64px_36px] items-center gap-2 border-b px-3 py-2 last:border-b-0"
              >
                <Input
                  value={r.model_pattern}
                  onChange={(e) => patch(r.key, "model_pattern", e.target.value)}
                  placeholder="deepseek-*"
                  className="h-8 font-mono text-xs"
                />
                {(
                  ["input_per_mtok", "output_per_mtok", "cache_read_per_mtok", "cache_write_per_mtok"] as const
                ).map((field) => (
                  <Input
                    key={field}
                    type="number"
                    min="0"
                    step="0.0001"
                    value={r[field]}
                    onChange={(e) => patch(r.key, field, e.target.value)}
                    placeholder="0"
                    className="h-8 font-mono text-xs"
                  />
                ))}
                <Input
                  value={r.currency}
                  onChange={(e) => patch(r.key, "currency", e.target.value)}
                  className="h-8 text-xs"
                />
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label="删除该行"
                  onClick={() => setRows((prev) => prev.filter((x) => x.key !== r.key))}
                >
                  <Trash2Icon />
                </Button>
              </div>
            ))}
          </div>
        )}

        <div className="flex items-center justify-between">
          <Button variant="outline" size="sm" onClick={() => setRows((prev) => [...prev, emptyRow()])}>
            <PlusIcon data-icon="inline-start" />
            新增规则
          </Button>
          <p className="text-muted-foreground text-[11px]">
            只对在线账本（llm_usage）计价；历史归档任务没有 model 维度，费用不含它们。
          </p>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button onClick={() => void save()} disabled={loading || saving}>
            {saving ? "保存中…" : "保存"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
