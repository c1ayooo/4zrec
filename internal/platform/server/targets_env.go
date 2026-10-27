package server

import (
	"log"
	"strconv"
	"strings"
)

// targets_env.go 把项目授权目标注入 agent 的 Bash 环境变量 ZREC_TARGETS，
// 落实「目标先声明、再引用」的围栏约定：
//
//   - 值 = 项目授权范围(domain/ip/cidr 三类，icp/keyword 是提示规则不参与) ∪
//     本项目 approved 资产(domain/root_domain/ip)，与围栏 AuthorizedTarget
//     的授权语义同源——引用变量即引用已授权目标；
//   - 任务侧(planner/worker/mainagent)按任务解析项目，chat 侧按会话
//     ("conv-<id>")解析项目；无项目上下文不注入；
//   - 目标数封顶 zrecTargetsMaxEntries：范围超大时截断并记日志，agent 仍可
//     用平台工具(scope 查询)拿到全量，变量只是便利约定不是权威清单。
//
// 围栏侧无需感知这个变量：`$ZREC_TARGETS` 这类 `$` 形态 token 本就不产生
// 提取对象（宁漏勿扰口径），注入值按构造就是授权集，两者叠加即「引用即放行」。
const (
	zrecTargetsEnvKey     = "ZREC_TARGETS"
	zrecTargetsMaxEntries = 500
)

// targetsEnvForTask 是任务侧 agent(Worker/Planner/MainAgent)的注入闭包：
// 按任务解析归属项目，逐 run 重读(任务改挂项目后下一轮即生效)。
func (s *Server) targetsEnvForTask(taskID string) func(string) []string {
	return func(string) []string {
		if s.m == nil || s.m.pg == nil {
			return nil
		}
		id, err := strconv.ParseInt(strings.TrimSpace(taskID), 10, 64)
		if err != nil || id <= 0 {
			return nil
		}
		pid, err := s.m.pg.TaskProjectID(id)
		if err != nil || pid <= 0 {
			return nil
		}
		return s.zrecTargetsEnv(pid)
	}
}

// targetsEnvForConv 是 ChatAgent 的注入闭包：sessionID 形如 "conv-<id>"，
// 按会话解析归属项目(挂项目=围栏启用=变量有值)。
func (s *Server) targetsEnvForConv() func(string) []string {
	return func(sessionID string) []string {
		if s.m == nil || s.m.pg == nil {
			return nil
		}
		rest, ok := strings.CutPrefix(sessionID, "conv-")
		if !ok {
			return nil
		}
		id, err := strconv.ParseInt(rest, 10, 64)
		if err != nil || id <= 0 {
			return nil
		}
		pid, err := s.m.pg.ConvProjectID(id)
		if err != nil || pid <= 0 {
			return nil
		}
		return s.zrecTargetsEnv(pid)
	}
}

// zrecTargetsEnv 组装一条 "ZREC_TARGETS=<值>"；无目标返回 nil。
func (s *Server) zrecTargetsEnv(projectID int64) []string {
	v, ok := s.projectTargetsValue(projectID)
	if !ok || v == "" {
		return nil
	}
	return []string{zrecTargetsEnvKey + "=" + v}
}

// projectTargetsValue 汇总项目授权目标(范围 ∪ approved 资产)，空格分隔。
// ok=false 表示读取失败(调用方按无变量处理，不阻断会话)。
func (s *Server) projectTargetsValue(projectID int64) (string, bool) {
	pg := s.m.pg
	seen := map[string]bool{}
	out := make([]string, 0, 32)
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		if len(out) >= zrecTargetsMaxEntries {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	rules, err := pg.ProjectScopeRules(projectID)
	if err != nil {
		return "", false
	}
	for _, r := range rules {
		switch r.Kind {
		case "domain":
			add(r.Domain)
		case "ip", "cidr":
			add(r.Net)
		}
	}
	// approved 资产：批准即授权的目标也进变量(批准动作发生后的下一轮 run 生效)。
	rows, err := pg.Query(`SELECT COALESCE(NULLIF(domain,''), NULLIF(root_domain,''), ''), COALESCE(ip,'')
FROM assets WHERE authz='approved' AND (project_id=$1 OR project_id IS NULL)`, projectID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var dom, ip string
			if rows.Scan(&dom, &ip) == nil {
				add(dom)
				add(ip)
			}
		}
	}
	if len(out) >= zrecTargetsMaxEntries {
		log.Printf("[targets-env] 项目 #%d 授权目标超过 %d 条，ZREC_TARGETS 已截断(以项目页清单为准)", projectID, zrecTargetsMaxEntries)
	}
	return strings.Join(out, " "), true
}
