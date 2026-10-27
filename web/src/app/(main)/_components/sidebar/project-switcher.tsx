"use client";

import * as React from "react";

import { useRouter } from "next/navigation";

import { CheckIcon, ChevronsUpDownIcon, FolderKanbanIcon, PlusIcon, Settings2Icon } from "lucide-react";
import { toast } from "sonner";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem } from "@/components/ui/sidebar";
import { useProjectStore } from "@/stores/project/project-provider";

// 左上角全局项目切换器：切到哪个项目，全站项目相关页面只显示该项目内容。
// 切换后自动跳转到该项目的任务界面；「管理项目」「新建项目」入口在菜单底部。
export function ProjectSwitcher() {
  const router = useRouter();
  const projects = useProjectStore((s) => s.projects);
  const projectId = useProjectStore((s) => s.projectId);
  const status = useProjectStore((s) => s.status);
  const setProject = useProjectStore((s) => s.setProject);

  const current = projects.find((p) => p.id === projectId) ?? null;

  function switchTo(id: number) {
    if (id === projectId) return;
    const target = projects.find((p) => p.id === id);
    setProject(id);
    toast.success(`已切到项目「${target?.name ?? id}」`);
    router.push(`/function/tasks?project_id=${id}`);
  }

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton size="lg" className="data-[state=open]:bg-sidebar-accent" disabled={status !== "ready"}>
              <span className="bg-primary/10 text-primary flex size-8 shrink-0 items-center justify-center rounded-lg">
                <FolderKanbanIcon className="size-4" />
              </span>
              <span className="grid min-w-0 flex-1 text-left leading-tight">
                <span className="text-muted-foreground text-[11px]">当前项目</span>
                <span className="truncate font-medium">
                  {status !== "ready" ? "加载中…" : (current?.name ?? "未选择项目")}
                </span>
              </span>
              <ChevronsUpDownIcon className="text-muted-foreground ml-auto size-4 shrink-0" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-64" align="start" side="right">
            <DropdownMenuLabel className="text-muted-foreground text-xs">切换项目</DropdownMenuLabel>
            <div className="max-h-64 overflow-y-auto">
              {projects.length === 0 ? (
                <div className="text-muted-foreground px-2 py-3 text-center text-xs">还没有项目，先新建一个</div>
              ) : (
                projects.map((p) => (
                  <DropdownMenuItem key={p.id} onClick={() => switchTo(p.id)} className="gap-2">
                    <span className="min-w-0 flex-1 truncate">{p.name}</span>
                    <span className="text-muted-foreground shrink-0 text-[11px] tabular-nums">
                      {p.asset_count} 资产
                    </span>
                    {p.id === projectId ? <CheckIcon className="text-primary size-4 shrink-0" /> : null}
                  </DropdownMenuItem>
                ))
              )}
            </div>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => router.push("/function/projects")}>
              <Settings2Icon className="size-4" /> 管理项目
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => router.push("/function/projects?create=1")}>
              <PlusIcon className="size-4" /> 新建项目
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
