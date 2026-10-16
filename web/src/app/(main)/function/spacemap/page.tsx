"use client";

import * as React from "react";

import { Loader2Icon, RadarIcon, SearchIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api } from "@/lib/api";
import type { Project, SpacemapSearchRow } from "@/lib/types";

// 空间测绘搜索台:手工调用五引擎查询,直接看引擎返回(不自动入库);
// 需要沉淀进资产库时选项目「查询并入库」。历史资产在资产页按项目看,不在本页。
const ENGINE_SYNTAX: Record<string, { display: string; hint: string; sample: string }> = {
  fofa: { display: "FOFA", hint: 'domain="example.com"', sample: 'domain="example.com" && status_code="200"' },
  zoomeye: { display: "ZoomEye", hint: 'domain="example.com"', sample: 'hostname:"example.com"' },
  quake: { display: "Quake", hint: 'domain:"example.com"', sample: 'domain:"example.com"' },
  shodan: { display: "Shodan", hint: "hostname:example.com", sample: "org:Example Inc" },
  hunter: { display: "Hunter", hint: 'domain.suffix="example.com"', sample: 'icp.number="京ICP备xxxx号"' },
};

export default function SpacemapSearchPage() {
  const [engine, setEngine] = React.useState("fofa");
  const [query, setQuery] = React.useState("");
  const [size, setSize] = React.useState("100");
  const [projectID, setProjectID] = React.useState("");
  const [projects, setProjects] = React.useState<Project[]>([]);
  const [rows, setRows] = React.useState<SpacemapSearchRow[] | null>(null);
  const [total, setTotal] = React.useState(0);
  const [importedNote, setImportedNote] = React.useState("");
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => {
    api
      .projects()
      .then(setProjects)
      .catch(() => {});
  }, []);

  const run = async (autoImport: boolean) => {
    if (!query.trim()) {
      toast.error("输入查询语句");
      return;
    }
    setLoading(true);
    setImportedNote("");
    try {
      const res = await api.spacemapSearch({
        engine,
        query: query.trim(),
        size: Math.max(1, Number(size) || 100),
        project_id: projectID ? Number(projectID) : undefined,
        auto_import: autoImport,
      });
      setRows(res.rows);
      setTotal(res.total);
      if (res.imported) {
        setImportedNote(
          `已入库:域名 ${res.imported.domains} / IP ${res.imported.ips} / 服务 ${res.imported.services}` +
            (res.imported.project_id > 0 ? ` → 项目 ${res.imported.project_id}` : " → 未挂项目(仅入库)"),
        );
      }
    } catch (err) {
      toast.error(String(err instanceof Error ? err.message : err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">空间测绘</h1>
        <p className="text-muted-foreground mt-1 text-sm">
          手工调用空间测绘引擎,直接看引擎返回结果(不自动入库)。需要沉淀进资产库时选项目「查询并入库」;
          历史采集内容在资产页按项目看。引擎 Key 在 系统管理 → 空间测绘配置 维护。
        </p>
      </div>

      <Card>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            {Object.entries(ENGINE_SYNTAX).map(([key, meta]) => (
              <Button
                key={key}
                variant={engine === key ? "default" : "outline"}
                size="sm"
                onClick={() => setEngine(key)}
              >
                {meta.display}
              </Button>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative min-w-72 flex-1">
              <SearchIcon className="text-muted-foreground absolute top-2.5 left-2.5 size-4" />
              <Input
                className="pl-8 font-mono"
                placeholder={ENGINE_SYNTAX[engine]?.sample}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") void run(false);
                }}
              />
            </div>
            <Input
              className="w-24"
              type="number"
              title="返回条数"
              value={size}
              onChange={(e) => setSize(e.target.value)}
            />
            <Select value={projectID || "none"} onValueChange={setProjectID}>
              <SelectTrigger className="w-44">
                <SelectValue placeholder="入库项目(可选)" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">不入库</SelectItem>
                {projects.map((p) => (
                  <SelectItem key={p.id} value={String(p.id)}>
                    {p.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button variant="outline" disabled={loading} onClick={() => void run(false)}>
              {loading ? <Loader2Icon className="size-4 animate-spin" /> : <SearchIcon className="size-4" />}
              查询
            </Button>
            <Button disabled={loading || !projectID} onClick={() => void run(true)}>
              查询并入库
            </Button>
          </div>
          <p className="text-muted-foreground text-xs">
            {engine.toUpperCase()} 语法示例:<code>{ENGINE_SYNTAX[engine]?.hint}</code>
            {projectID ? " · 已选入库项目,「查询并入库」结果自动归属该项目(范围内自动授权)" : ""}
          </p>
        </CardContent>
      </Card>

      {rows === null ? (
        <div className="text-muted-foreground flex flex-col items-center gap-2 py-12 text-sm">
          <RadarIcon className="size-6 opacity-40" />
          输入查询语句开始搜索
        </div>
      ) : (
        <Card>
          <CardContent className="px-0">
            <div className="flex flex-wrap items-center gap-2 px-4 pb-2">
              <Badge variant="outline">{ENGINE_SYNTAX[engine]?.display}</Badge>
              <span className="text-muted-foreground text-xs">
                引擎命中 {total} 条,本次返回 {rows.length} 条
              </span>
              {importedNote ? <Badge variant="default">{importedNote}</Badge> : null}
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-muted-foreground border-b text-left">
                    <th className="px-4 py-2 font-medium">主机</th>
                    <th className="px-4 py-2 font-medium">域名</th>
                    <th className="px-4 py-2 font-medium">IP</th>
                    <th className="px-4 py-2 font-medium">端口</th>
                    <th className="px-4 py-2 font-medium">标题</th>
                    <th className="px-4 py-2 font-medium">协议</th>
                    <th className="px-4 py-2 font-medium">Server</th>
                    <th className="px-4 py-2 font-medium">位置</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r, i) => (
                    <tr key={i} className="border-b last:border-0">
                      <td className="px-4 py-2 font-mono">{r.host || "-"}</td>
                      <td className="px-4 py-2 font-mono">{r.domain || "-"}</td>
                      <td className="px-4 py-2 font-mono">{r.ip || "-"}</td>
                      <td className="px-4 py-2">{r.port || "-"}</td>
                      <td className="max-w-60 truncate px-4 py-2">{r.title || "-"}</td>
                      <td className="px-4 py-2">{r.protocol || "-"}</td>
                      <td className="max-w-40 truncate px-4 py-2">{r.server || "-"}</td>
                      <td className="text-muted-foreground px-4 py-2 whitespace-nowrap">
                        {[r.country, r.city].filter(Boolean).join(" ") || "-"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
