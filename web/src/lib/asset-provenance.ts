import type { Asset } from "@/lib/types";

// assetProvenance 资产出处：空间测绘引擎 + 查询语法 / 解析自哪些域名 / 哪个任务发现。
// 审批时据此判断资产是否真的落在授权范围内（尤其是空间测绘导入的 IP）。
export function assetProvenance(a: Asset): string {
  const parts: string[] = [];
  if (a.source) parts.push(a.source);
  const query = typeof a.extra?.source_query === "string" ? a.extra.source_query.trim() : "";
  if (query) parts.push(query);
  if (a.bound_domains?.length) {
    const shown = a.bound_domains.slice(0, 2).join("、");
    parts.push(`解析自 ${shown}${a.bound_domains.length > 2 ? " 等" : ""}`);
  }
  if (a.task_ids?.length) parts.push(`任务 #${a.task_ids.slice(0, 3).join(",")}`);
  return parts.join(" · ") || "—";
}
