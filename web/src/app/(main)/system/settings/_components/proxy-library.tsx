"use client";

import * as React from "react";

import { Loader2Icon, PencilIcon, PlusIcon, ServerIcon, Trash2Icon, WifiIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api } from "@/lib/api";
import type { ProxyProfile, ProxySelections } from "@/lib/types";

interface Props {
  profiles: ProxyProfile[];
  selections: ProxySelections;
  urls: ProxySelections;
  updateProxyInput: string;
  setUpdateProxyInput: (v: string) => void;
  saveUpdateProxy: () => Promise<void>;
  savingUpdate: boolean;
  onRefresh: () => Promise<void> | void;
}

export function ProxyLibrary({
  profiles,
  selections,
  urls,
  updateProxyInput,
  setUpdateProxyInput,
  saveUpdateProxy,
  savingUpdate,
  onRefresh,
}: Props) {
  const [open, setOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<ProxyProfile | null>(null);
  const [name, setName] = React.useState("");
  const [url, setURL] = React.useState("");
  const [note, setNote] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const [testing, setTesting] = React.useState(false);
  const [customUpdate, setCustomUpdate] = React.useState(false);

  const openCreate = () => {
    setEditing(null);
    setName("");
    setURL("");
    setNote("");
    setOpen(true);
  };

  const openEdit = (p: ProxyProfile) => {
    setEditing(p);
    setName(p.name);
    setURL(p.url);
    setNote(p.note ?? "");
    setOpen(true);
  };

  const saveProfile = async () => {
    if (!name.trim() || !url.trim()) {
      toast.error("名称和代理地址不能为空");
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        await api.updateProxyProfile(editing.id, { name: name.trim(), url: url.trim(), note: note.trim() });
        toast.success("代理配置已更新");
      } else {
        await api.createProxyProfile({ name: name.trim(), url: url.trim(), note: note.trim() });
        toast.success("代理配置已添加");
      }
      setOpen(false);
      await onRefresh();
    } catch (err) {
      toast.error("保存失败：" + (err instanceof Error ? err.message : String(err)));
    } finally {
      setSaving(false);
    }
  };

  const testProfile = async () => {
    if (!url.trim()) {
      toast.error("先填写代理地址");
      return;
    }
    setTesting(true);
    try {
      const r = await api.testProxyProfile(url.trim());
      if (r.ok) {
        const warn = r.warning ? ` · ${r.warning}` : "";
        toast.success(`代理连通 · HTTP ${r.status ?? 200} · ${r.elapsed_ms ?? 0}ms${warn}`);
      } else {
        toast.error("代理不可用：" + (r.error || "未知错误"));
      }
    } catch (err) {
      toast.error("代理测试失败：" + (err instanceof Error ? err.message : String(err)));
    } finally {
      setTesting(false);
    }
  };

  const removeProfile = async (p: ProxyProfile) => {
    if (!window.confirm(`确认删除代理「${p.name}」？使用它的用途会切回直连。`)) return;
    try {
      await api.deleteProxyProfile(p.id);
      toast.success("已删除代理配置");
      await onRefresh();
    } catch (err) {
      toast.error("删除失败：" + (err instanceof Error ? err.message : String(err)));
    }
  };

  const showCustomUpdate = customUpdate || (!selections.update && !!urls.update);
  const updateSelectValue = selections.update || (showCustomUpdate ? "custom" : "direct");

  const switchUpdateProxy = async (value: string) => {
    if (value === "custom") {
      setCustomUpdate(true);
      return;
    }
    setCustomUpdate(false);
    try {
      if (value === "direct") {
        await api.setSettings({ update_proxy: "" });
        toast.success("平台更新改为直连");
      } else {
        await api.selectProxyProfile("update", value);
        toast.success("平台更新代理已切换");
      }
      await onRefresh();
    } catch (err) {
      toast.error("切换失败：" + (err instanceof Error ? err.message : String(err)));
    }
  };

  return (
    <>
      <Card className="mb-4 break-inside-avoid md:mb-6">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ServerIcon className="size-4" />
            代理库
          </CardTitle>
          <CardDescription>
            集中管理命名代理（http / https / socks5）。目标流量、网络搜索、nuclei 下载更新、平台更新各自手动选择；
            内网和出海可以分别指向不同代理。
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {profiles.length === 0 && (
            <p className="text-muted-foreground text-sm">还没有代理配置，点下方「新增代理」添加。</p>
          )}
          {profiles.map((p) => (
            <div key={p.id} className="flex flex-wrap items-start justify-between gap-2 rounded-md border p-3">
              <div className="min-w-0">
                <p className="text-sm font-medium">{p.name}</p>
                <p className="text-muted-foreground truncate font-mono text-xs">{p.url}</p>
                {p.note && <p className="text-muted-foreground mt-1 text-xs">{p.note}</p>}
              </div>
              <div className="flex shrink-0 items-center gap-1">
                <Button variant="ghost" size="sm" onClick={() => openEdit(p)}>
                  <PencilIcon className="size-4" /> 编辑
                </Button>
                <Button variant="ghost" size="sm" onClick={() => void removeProfile(p)}>
                  <Trash2Icon className="size-4" /> 删除
                </Button>
              </div>
            </div>
          ))}
          <div>
            <Button variant="outline" onClick={openCreate}>
              <PlusIcon className="size-4" /> 新增代理
            </Button>
          </div>

          <div className="flex flex-col gap-2 border-t pt-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <Label htmlFor="proxy-update-select" className="text-sm font-normal text-muted-foreground">
                平台更新代理
              </Label>
              <Select value={updateSelectValue} onValueChange={(v) => void switchUpdateProxy(v)}>
                <SelectTrigger id="proxy-update-select" className="w-64">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="direct">直连</SelectItem>
                  {profiles.map((p) => (
                    <SelectItem key={p.id} value={p.id}>
                      {p.name}
                    </SelectItem>
                  ))}
                  <SelectItem value="custom">自定义 URL</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {showCustomUpdate ? (
              <div className="flex items-center gap-2">
                <Input
                  placeholder="http://127.0.0.1:7890（留空=直连）"
                  value={updateProxyInput}
                  onChange={(e) => setUpdateProxyInput(e.target.value)}
                />
                <Button onClick={() => void saveUpdateProxy()} disabled={savingUpdate}>
                  保存
                </Button>
              </div>
            ) : (
              <p className="text-muted-foreground text-xs">当前：{urls.update || "直连（未选择时沿用全局代理）"}</p>
            )}
          </div>
        </CardContent>
      </Card>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editing ? "编辑代理" : "新增代理"}</DialogTitle>
            <DialogDescription>支持 http://、https://、socks5://，可带 user:pass 认证。</DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-3">
            <div className="flex flex-col gap-2">
              <Label htmlFor="proxy-name">名称</Label>
              <Input
                id="proxy-name"
                placeholder="例如：内网 SOCKS / mihomo 出海"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="proxy-url">代理地址</Label>
              <Input
                id="proxy-url"
                placeholder="socks5://127.0.0.1:1080 或 http://127.0.0.1:7890"
                value={url}
                onChange={(e) => setURL(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="proxy-note">备注（可选）</Label>
              <Input id="proxy-note" value={note} onChange={(e) => setNote(e.target.value)} />
            </div>
          </div>
          <DialogFooter className="flex flex-wrap items-center justify-between gap-2 sm:justify-between">
            <Button variant="outline" onClick={() => void testProfile()} disabled={testing || saving}>
              {testing ? <Loader2Icon className="size-4 animate-spin" /> : <WifiIcon className="size-4" />} 测试连通性
            </Button>
            <div className="flex items-center gap-2">
              <Button variant="outline" onClick={() => setOpen(false)} disabled={saving}>
                取消
              </Button>
              <Button onClick={() => void saveProfile()} disabled={saving}>
                {saving ? <Loader2Icon className="size-4 animate-spin" /> : null} 保存
              </Button>
            </div>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
