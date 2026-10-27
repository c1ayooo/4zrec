import { createStore } from "zustand/vanilla";

import { api } from "@/lib/api";
import type { Project } from "@/lib/types";

export const PROJECT_ID_STORAGE_KEY = "artex_project_id";

export type ProjectStatus = "idle" | "loading" | "ready";

// 全局项目上下文：左上角切换器写入，各页面读取。
// 强制单项目口径（无「全部项目」）：projectId=0 仅出现在项目列表为空或加载失败时。
export type ProjectState = {
  projects: Project[];
  projectId: number;
  status: ProjectStatus;
  booted: boolean;
  /** 首次挂载拉项目列表并恢复上次选中（无效则回落第一个项目）。 */
  boot: () => Promise<void>;
  /** 切换当前项目并持久化（跳转由调用方负责）。 */
  setProject: (id: number) => void;
  /** 重拉项目列表；当前项目被删时自动回落第一个。返回最新列表。 */
  reloadProjects: () => Promise<Project[]>;
};

function readSavedProjectId(): number {
  try {
    return Number(window.localStorage.getItem(PROJECT_ID_STORAGE_KEY) || "0") || 0;
  } catch {
    return 0;
  }
}

function persistProjectId(id: number) {
  try {
    window.localStorage.setItem(PROJECT_ID_STORAGE_KEY, String(id));
  } catch {
    /* 隐私模式等场景写不进就只留在内存 */
  }
}

export const createProjectStore = () =>
  createStore<ProjectState>()((set, get) => ({
    projects: [],
    projectId: 0,
    status: "idle",
    booted: false,
    boot: async () => {
      if (get().booted) return;
      set({ booted: true, status: "loading" });
      try {
        const list = await api.projects();
        const saved = readSavedProjectId();
        const next = list.some((p) => p.id === saved) ? saved : (list[0]?.id ?? 0);
        set({ projects: list, projectId: next, status: "ready" });
      } catch {
        // 拉取失败保持空态，reloadProjects 可重试。
        set({ status: "ready" });
      }
    },
    setProject: (id) => {
      set({ projectId: id });
      persistProjectId(id);
    },
    reloadProjects: async () => {
      try {
        const list = await api.projects();
        const prev = get().projectId;
        const next = list.some((p) => p.id === prev) ? prev : (list[0]?.id ?? 0);
        set({ projects: list, projectId: next });
        if (next !== prev) persistProjectId(next);
        return list;
      } catch {
        return get().projects;
      }
    },
  }));
