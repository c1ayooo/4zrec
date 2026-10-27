"use client";

import { createContext, type ReactNode, useContext, useEffect, useState } from "react";

import { type StoreApi, useStore } from "zustand";

import { createProjectStore, type ProjectState } from "./project-store";

const ProjectStoreContext = createContext<StoreApi<ProjectState> | null>(null);

export function ProjectStoreProvider({ children }: { children: ReactNode }) {
  const [store] = useState<StoreApi<ProjectState>>(() => createProjectStore());

  useEffect(() => {
    void store.getState().boot();
  }, [store]);

  return <ProjectStoreContext.Provider value={store}>{children}</ProjectStoreContext.Provider>;
}

export const useProjectStore = <T,>(selector: (state: ProjectState) => T): T => {
  const store = useContext(ProjectStoreContext);
  if (!store) throw new Error("Missing ProjectStoreProvider");
  return useStore(store, selector);
};
