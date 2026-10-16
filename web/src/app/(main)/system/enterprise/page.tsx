"use client";

import * as React from "react";

import { Building2Icon, CookieIcon, Loader2Icon, SaveIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import type { EntProvider } from "@/lib/types";

// 企业数据源会话配置:Cookie 只进服务端加密 vault,页面永不回显明文(保存后
// 仅显示"已配置")。与空间测绘 key 页同风格。未配置时 agent 侧仅 ICP 反查可用。
export default function EnterprisePage() {
  const [providers, setProviders] = React.useState<EntProvider[] | null>(null);
  const [draft, setDraft] = React.useState<Record<string, { cookie: string; username: string; password: string }>>({});
  const [saving, setSaving] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    try {
      const list = await api.entProviders();
      setProviders(list);
      setDraft(Object.fromEntries(list.map((p) => [p.name, { cookie: "", username: "", password: "" }])));
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const save = async (name: string, useAccount: boolean) => {
    const d = draft[name];
    if (!d) return;
    const config: Record<string, string> = {};
    if (useAccount) {
      if (!d.username || !d.password) {
        toast.error("账号密码必填");
        return;
      }
      config.username = d.username;
      config.password = d.password;
    } else if (d.cookie.trim()) {
      config.cookie = d.cookie.trim();
    }
    setSaving(name);
    try {
      await api.saveEntSession({ provider: name, config });
      toast.success(config.cookie || config.username ? "会话已保存(加密存储)" : "会话已清除");
      await load();
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    } finally {
      setSaving(null);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">企业数据源</h1>
        <p className="text-muted-foreground mt-1 text-sm">
          企业关系采集（enterprise_collect）的上游数据源会话。Cookie/账号只进服务端加密库，页面不回显明文；
          未配置时信息收集走 ICP 备案反查路径（icp_expand，零会话成本）。小蓝本依赖内嵌浏览器，本平台未迁移。
        </p>
      </div>
      {providers === null ? (
        <div className="text-muted-foreground flex items-center gap-2 text-sm">
          <Loader2Icon className="size-4 animate-spin" /> 加载中…
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {providers.map((p) => {
            const d = draft[p.name] ?? { cookie: "", username: "", password: "" };
            const useAccount = p.auth === "account";
            const busy = saving === p.name;
            return (
              <Card key={p.name}>
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Building2Icon className="text-muted-foreground size-4" />
                      <span className="font-medium">{p.label}</span>
                    </div>
                    {p.configured ? <Badge>已配置</Badge> : <Badge variant="outline">未配置</Badge>}
                  </div>
                  <p className="text-muted-foreground text-xs">{p.hint}</p>
                  {p.available ? (
                    useAccount ? (
                      <div className="grid gap-2">
                        <div className="space-y-1">
                          <Label htmlFor={`u-${p.name}`}>账号</Label>
                          <Input
                            id={`u-${p.name}`}
                            value={d.username}
                            onChange={(e) => setDraft((x) => ({ ...x, [p.name]: { ...d, username: e.target.value } }))}
                          />
                        </div>
                        <div className="space-y-1">
                          <Label htmlFor={`p-${p.name}`}>密码</Label>
                          <Input
                            id={`p-${p.name}`}
                            type="password"
                            value={d.password}
                            onChange={(e) => setDraft((x) => ({ ...x, [p.name]: { ...d, password: e.target.value } }))}
                          />
                        </div>
                      </div>
                    ) : (
                      <div className="space-y-1">
                        <Label htmlFor={`c-${p.name}`}>
                          <CookieIcon className="mr-1 inline size-3" />
                          Cookie{p.configured ? "（已保存,输入以更换;留空保存=清除）" : ""}
                        </Label>
                        <textarea
                          id={`c-${p.name}`}
                          className="border-input bg-background min-h-16 w-full rounded-md border px-3 py-2 text-sm"
                          placeholder="粘贴网页版登录 Cookie 全量"
                          value={d.cookie}
                          onChange={(e) => setDraft((x) => ({ ...x, [p.name]: { ...d, cookie: e.target.value } }))}
                        />
                      </div>
                    )
                  ) : (
                    <p className="text-muted-foreground text-xs">不可用</p>
                  )}
                  {p.available ? (
                    <Button size="sm" disabled={busy} onClick={() => void save(p.name, useAccount)}>
                      {busy ? <Loader2Icon className="size-4 animate-spin" /> : <SaveIcon className="size-4" />}
                      保存
                    </Button>
                  ) : null}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
