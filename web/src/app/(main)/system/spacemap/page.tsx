"use client";

import * as React from "react";

import { KeyRoundIcon, Loader2Icon, SaveIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import type { SpacemapEngine } from "@/lib/types";

// 空间测绘引擎 key 配置:agent 的 space_search/space_search_batch 工具读这里的 key。
// 与 LLM 配置同风格:保存服务端、回显掩码、环境变量优先(来自 env 时页面修改不生效)。
export default function SpacemapPage() {
  const [engines, setEngines] = React.useState<SpacemapEngine[] | null>(null);
  const [drafts, setDrafts] = React.useState<Record<string, { key: string; baseUrl: string }>>({});
  const [saving, setSaving] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    try {
      const list = await api.spacemapEngines();
      setEngines(list);
      setDrafts(
        Object.fromEntries(
          list.map((e) => [e.provider, { key: "", baseUrl: e.base_url ?? "" }]),
        ),
      );
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const save = async (provider: string) => {
    const draft = drafts[provider];
    if (!draft) return;
    setSaving(provider);
    try {
      const list = await api.saveSpacemapEngine({
        provider,
        api_key: draft.key.trim() === "" ? undefined : draft.key.trim(),
        base_url: draft.baseUrl.trim(),
      });
      setEngines(list);
      setDrafts(
        Object.fromEntries(
          list.map((e) => [e.provider, { key: "", baseUrl: e.base_url ?? "" }]),
        ),
      );
      toast.success("已保存");
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    } finally {
      setSaving(null);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">空间测绘</h1>
        <p className="text-muted-foreground mt-1 text-sm">
          五引擎空间测绘的 API Key 配置。信息收集 agent 的 space_search /
          space_search_batch 工具读这里的凭据；环境变量（FOFA_API_KEY 等）优先于页面配置。
        </p>
      </div>
      {engines === null ? (
        <div className="text-muted-foreground flex items-center gap-2 text-sm">
          <Loader2Icon className="size-4 animate-spin" /> 加载中…
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {engines.map((e) => {
            const draft = drafts[e.provider] ?? { key: "", baseUrl: "" };
            const busy = saving === e.provider;
            return (
              <Card key={e.provider}>
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <KeyRoundIcon className="text-muted-foreground size-4" />
                      <span className="font-medium">{e.display}</span>
                    </div>
                    {e.configured ? (
                      <Badge variant="default">{e.from_env ? "环境变量" : "已配置"}</Badge>
                    ) : (
                      <Badge variant="outline">未配置</Badge>
                    )}
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor={`key-${e.provider}`}>
                      API Key{e.key_masked ? `（当前 ${e.key_masked}）` : ""}
                    </Label>
                    <Input
                      id={`key-${e.provider}`}
                      type="password"
                      placeholder={e.configured ? "留空保持不变" : "粘贴 API Key"}
                      value={draft.key}
                      disabled={e.from_env}
                      onChange={(ev) =>
                        setDrafts((d) => ({ ...d, [e.provider]: { ...draft, key: ev.target.value } }))
                      }
                    />
                    {e.from_env ? (
                      <p className="text-muted-foreground text-xs">
                        key 来自环境变量，页面修改不生效。
                      </p>
                    ) : null}
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor={`url-${e.provider}`}>自定义端点（可选，默认官方）</Label>
                    <Input
                      id={`url-${e.provider}`}
                      placeholder="https://…（自建反代时填）"
                      value={draft.baseUrl}
                      onChange={(ev) =>
                        setDrafts((d) => ({ ...d, [e.provider]: { ...draft, baseUrl: ev.target.value } }))
                      }
                    />
                  </div>
                  <div className="text-muted-foreground text-xs">
                    域名查询语法：<code>{e.default_query}</code>
                  </div>
                  <Button size="sm" disabled={busy} onClick={() => void save(e.provider)}>
                    {busy ? <Loader2Icon className="size-4 animate-spin" /> : <SaveIcon className="size-4" />}
                    保存
                  </Button>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
