"use client";

import * as React from "react";

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
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { auth } from "@/lib/auth";

export function ChangePasswordDialog({
  open,
  onOpenChange,
}: {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
}) {
  const [oldPassword, setOldPassword] = React.useState("");
  const [newPassword, setNewPassword] = React.useState("");
  const [confirmPassword, setConfirmPassword] = React.useState("");
  const [username, setUsername] = React.useState("");
  const [currentUsername, setCurrentUsername] = React.useState("");
  const [saving, setSaving] = React.useState(false);

  // 打开时拉当前登录名做预填;关闭清空输入(用户名回填当前值)。
  React.useEffect(() => {
    if (open) {
      api
        .authStatus()
        .then((r) => {
          setCurrentUsername(r.username);
          setUsername(r.username);
        })
        .catch(() => {});
      return;
    }
    setOldPassword("");
    setNewPassword("");
    setConfirmPassword("");
    setUsername("");
  }, [open]);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!oldPassword || !newPassword) {
      toast.error("请填写当前密码和新密码");
      return;
    }
    if (newPassword !== confirmPassword) {
      toast.error("两次输入的新密码不一致");
      return;
    }
    setSaving(true);
    const renamed = username.trim() !== currentUsername;
    api
      .changePassword(oldPassword, newPassword, renamed ? username.trim() : undefined)
      .then((res) => {
        // 改密会轮换 JWT 签名密钥，旧 token 立即失效；用后端返回的新 token 续上当前会话。
        if (res.token) auth.setToken(res.token);
        toast.success(renamed ? "密码与用户名已修改（其他设备需重新登录）" : "密码已修改（其他设备需重新登录）");
        onOpenChange(false);
      })
      .catch((err) => toast.error(`修改失败：${(err as Error).message}`))
      .finally(() => setSaving(false));
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>修改密码</DialogTitle>
            <DialogDescription>
              可同时修改登录用户名。需先输入当前密码验证；修改后旧 token 会立即失效，其他设备需要重新登录。
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-3 py-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="cp-username">用户名</Label>
              <Input
                id="cp-username"
                autoComplete="username"
                value={username}
                disabled={saving}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="cp-old">当前密码</Label>
              <Input
                id="cp-old"
                type="password"
                autoComplete="current-password"
                value={oldPassword}
                disabled={saving}
                onChange={(e) => setOldPassword(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="cp-new">新密码</Label>
              <Input
                id="cp-new"
                type="password"
                autoComplete="new-password"
                value={newPassword}
                disabled={saving}
                onChange={(e) => setNewPassword(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="cp-confirm">确认新密码</Label>
              <Input
                id="cp-confirm"
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                disabled={saving}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
              取消
            </Button>
            <Button type="submit" disabled={saving}>
              {saving ? "修改中…" : "确认修改"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
