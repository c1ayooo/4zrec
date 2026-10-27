// zreark_mcp_seed.go 启动种子:已配置 4zreark 连接(settings: zreark.base_url /
// zreark.api_key)时,幂等注册 4zreark 的 MCP 端点为本平台 MCP Server
// (transport=http,env 即认证头),并把采集/资产类工具授予 recon/worker/auto 三类
// agent。key 未配置则跳过——平台自身基础收集闭环,不依赖外部。key 轮换后重启
// 自动同步请求头;工具发现由 discoverEmptyMCPsOnStartup 兜底。
package server

import (
	"encoding/json"
	"log"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// zrearkMCPName 注册到 mcp_servers 的固定名(幂等 upsert 的查找键)。
const zrearkMCPName = "zreark"

// zrearkMCPToolAllowlist 授予 agent 的工具白名单:采集任务与资产读取。
// 不含 4zreark 的漏洞/POC/攻击扫描类工具(连接 key 的 scope 也不含它们)。
var zrearkMCPToolAllowlist = []string{
	"create_task", "start_task", "wait_task", "get_task", "list_tasks",
	"get_task_results", "get_task_result_stats",
	"list_projects", "list_assets", "get_asset", "list_asset_routes",
}

// ensureZrearkMCPServer 启动时幂等接入(调用点在 orchestration 装配序列)。
func (s *Server) ensureZrearkMCPServer() {
	pg := s.m.pg
	if pg == nil {
		return
	}
	var get func(string) (string, bool, error)
	get = pg.GetSetting
	key := resolveZrearkAPIKey(get)
	if key == "" {
		return
	}
	endpoint, err := normalizeAssetSyncBaseURL(resolveZrearkBaseURL(get))
	if err != nil {
		log.Printf("[zreark-mcp] 地址不合法,跳过接入: %v", err)
		return
	}
	env, _ := json.Marshal(map[string]string{"Authorization": "Bearer " + key})

	servers, err := pg.ListMCP()
	if err != nil {
		log.Printf("[zreark-mcp] 读取 MCP 列表失败: %v", err)
		return
	}
	row := &db.MCPServer{Name: zrearkMCPName}
	for _, srv := range servers {
		if srv.Name == zrearkMCPName {
			row = srv // 已存在:仅同步连接驱动字段,保留用户其它改动
			break
		}
	}
	row.Name = zrearkMCPName
	row.Transport = "http"
	row.URL = endpoint
	row.Env = env
	row.Enabled = true
	id, err := pg.SaveMCP(row)
	if err != nil {
		log.Printf("[zreark-mcp] 保存失败: %v", err)
		return
	}
	bound := 0
	for _, agentKey := range []string{"recon", "worker", "auto"} {
		a, err := pg.GetAgentByKey(agentKey)
		if err != nil || a == nil {
			continue
		}
		// 增量授予:用户在 UI 关掉的条目不会被重新打开(DO NOTHING 语义)。
		if err := pg.GrantMCPTools(a.ID, id, zrearkMCPToolAllowlist); err == nil {
			bound++
		}
	}
	log.Printf("[zreark-mcp] 已接入 4zreark MCP(%s),工具白名单 %d 项,授予 %d 类 agent", endpoint, len(zrearkMCPToolAllowlist), bound)
}
