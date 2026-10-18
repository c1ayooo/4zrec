"use client";

import * as React from "react";

import { Loader2Icon } from "lucide-react";
import { toast } from "sonner";

import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api } from "@/lib/api";
import type { ProxyGallery, ProxySelections } from "@/lib/types";

interface Props {
  slot: keyof ProxySelections;
  label?: string;
  className?: string;
}

// 功能页上的代理选择器：从代理库读取命名代理，手动选择当前用途走哪个代理。
// 自定义 URL 仍由系统设置 → 代理库维护。
export function ProxySlotSelect({ slot, label, className }: Props) {
  const [gallery, setGallery] = React.useState<ProxyGallery | null>(null);
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    api
      .proxyProfiles()
      .then(setGallery)
      .catch(() => undefined);
  }, []);

  const value = gallery?.selections[slot] || (gallery?.urls[slot] ? "custom" : "direct");

  const onChange = async (v: string) => {
    if (v === "custom") {
      toast.info("自定义代理 URL 请在「系统设置 → 代理库」中编辑");
      return;
    }
    setSaving(true);
    try {
      const g = await api.selectProxyProfile(slot, v === "direct" ? "" : v);
      setGallery(g);
      toast.success(v === "direct" ? "已切换为直连" : "代理已切换");
    } catch (err) {
      toast.error("切换失败：" + (err instanceof Error ? err.message : String(err)));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className={`flex items-center gap-2 ${className ?? ""}`}>
      {label ? <span className="text-muted-foreground text-xs">{label}</span> : null}
      <Select value={value} onValueChange={(v) => void onChange(v)} disabled={saving}>
        <SelectTrigger className="w-48">
          <SelectValue placeholder="代理" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="direct">直连</SelectItem>
          {(gallery?.profiles ?? []).map((p) => (
            <SelectItem key={p.id} value={p.id}>
              {p.name}
            </SelectItem>
          ))}
          <SelectItem value="custom">自定义（系统设置）</SelectItem>
        </SelectContent>
      </Select>
      {saving ? <Loader2Icon className="size-4 animate-spin" /> : null}
    </div>
  );
}
