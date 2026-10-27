"use client";

import * as React from "react";

import { Loader2Icon, PencilIcon, TrashIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import type { ZrearkConfig } from "@/lib/types";

// 4zreark 连接配置条：展示当前连接（key 只回掩码）并支持就地修改/清除。
// 凭据持久化在 4zrec settings 里，弹窗操作不再需要每次粘贴 key。
// onChanged 在配置加载/变更后回传最新配置，宿主据此控制操作按钮可用性。
export function ZrearkConnectionBar({ onChanged }: { onChanged?: (cfg: ZrearkConfig) => void }) {
  const [cfg, setCfg] = React.useState<ZrearkConfig | null>(null);
  const [editing, setEditing] = React.useState(false);
  const [baseURL, setBaseURL] = React.useState("");
  const [apiKey, setAPIKey] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const [error, setError] = React.useState("");

  const load = React.useCallback(async () => {
    try {
      const res = await api.zrearkConfig();
      setCfg(res);
      setBaseURL(res.base_url ?? "");
      onChanged?.(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [onChanged]);

  React.useEffect(() => {
    void load();
  }, [load]);

  async function save(clearKey: boolean) {
    if (saving) return;
    setSaving(true);
    setError("");
    try {
      const res = await api.zrearkConfigSet({
        base_url: baseURL.trim(),
        api_key: clearKey ? "clear" : apiKey.trim(),
      });
      setCfg(res);
      setAPIKey("");
      setEditing(false);
      onChanged?.(res);
      toast.success(clearKey ? "已清除 4zreark API Key" : "4zreark 连接已保存");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  if (!cfg) {
    return error ? <p className="text-destructive text-sm">{error}</p> : null;
  }

  return (
    <div className="bg-muted/20 rounded-lg border p-3">
      {editing ? (
        <div className="grid gap-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="zreark-conn-base">4zreark 地址</Label>
              <Input
                id="zreark-conn-base"
                value={baseURL}
                placeholder="http://127.0.0.1:8080"
                onChange={(e) => setBaseURL(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="zreark-conn-key">API Key（留空=保持不变）</Label>
              <Input
                id="zreark-conn-key"
                type="password"
                autoComplete="off"
                value={apiKey}
                placeholder={cfg.configured ? cfg.api_key_masked : "zr_..."}
                onChange={(e) => setAPIKey(e.target.value)}
              />
            </div>
          </div>
          {cfg.from_env ? (
            <p className="text-warning text-xs">当前 Key 来自环境变量 ZREARK_API_KEY，页面修改不生效。</p>
          ) : null}
          {error ? <p className="text-destructive text-sm">{error}</p> : null}
          <div className="flex items-center gap-2">
            <Button size="sm" onClick={() => void save(false)} disabled={saving}>
              {saving ? <Loader2Icon className="size-4 animate-spin" /> : null} 保存
            </Button>
            <Button variant="outline" size="sm" onClick={() => setEditing(false)} disabled={saving}>
              取消
            </Button>
          </div>
        </div>
      ) : (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className={cfg.configured ? "" : "text-warning"}>
            {cfg.configured ? `已连接 ${cfg.base_url} · Key ${cfg.api_key_masked}` : "尚未配置 4zreark API Key"}
          </span>
          <span className="text-muted-foreground ml-auto flex items-center gap-1">
            <Button variant="ghost" size="sm" onClick={() => setEditing(true)}>
              <PencilIcon className="size-3.5" /> 修改
            </Button>
            {cfg.configured && !cfg.from_env ? (
              <Button variant="ghost" size="sm" onClick={() => void save(true)} disabled={saving}>
                <TrashIcon className="size-3.5" /> 清除 Key
              </Button>
            ) : null}
          </span>
        </div>
      )}
    </div>
  );
}
