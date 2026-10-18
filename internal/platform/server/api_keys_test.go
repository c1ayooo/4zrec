package server

import "testing"

// TestProjectKeyPathAllowed 项目级 API Key 的路由白名单:业务面允许,
// 平台配置面(LLM/设置/Agent/MCP/拦截规则/Key 管理)一律拒绝。
func TestProjectKeyPathAllowed(t *testing.T) {
	allowed := [][2]string{
		{"GET", "/api/projects"},
		{"GET", "/api/projects/7/scope/candidates"},
		{"GET", "/api/tasks"},
		{"POST", "/api/tasks"},
		{"POST", "/api/tasks/control/batch"},
		{"GET", "/api/tasks/167/scope"},
		{"GET", "/api/assets"},
		{"GET", "/api/assets/pending"},
		{"POST", "/api/assets/probe"},
		{"POST", "/api/assets/bind"},
		{"GET", "/api/exploration/findings"},
		{"GET", "/api/exploration/findings/export"},
		{"GET", "/api/exploration/findings/groups"},
		{"GET", "/api/exploration/findings/asset-tree"},
		{"GET", "/api/exploration/findings/273"},
		{"GET", "/api/exploration/findings/273/export"},
		{"GET", "/api/intercept/pending"},
		{"GET", "/api/intercept/project/7"},
		{"GET", "/api/intercept/history"},
	}
	for _, c := range allowed {
		if !projectKeyPathAllowed(c[0], c[1]) {
			t.Errorf("%s %s 应允许", c[0], c[1])
		}
	}
	denied := [][2]string{
		{"POST", "/api/projects"},
		{"PATCH", "/api/projects/7"},
		{"DELETE", "/api/projects/7"},
		{"GET", "/api/projects/7"},
		{"POST", "/api/projects/7/scope"},
		{"POST", "/api/projects/7/scope/import"},
		{"DELETE", "/api/projects/7/scope/9"},
		{"POST", "/api/assets/authz"},
		{"POST", "/api/assets"},
		{"DELETE", "/api/assets"},
		{"POST", "/api/intercept/pending/1/decide"},
		{"POST", "/api/tasks/archive/batch"},
		{"POST", "/api/tasks/category/batch"},
		{"GET", "/api/assets/counts"},
		{"GET", "/api/exploration/findings/stats"},
		{"GET", "/api/exploration/findings/273/lineage"},
		{"GET", "/api/intercept/history/1"},
		{"GET", "/api/intercept/history/1/execution"},
		{"GET", "/api/llm/profiles"},
		{"GET", "/api/settings"},
		{"GET", "/api/agents"},
		{"GET", "/api/api-keys"},
		{"POST", "/api/api-keys"},
		{"GET", "/api/intercept/rules"},
		{"PUT", "/api/intercept/judge"},
		{"GET", "/api/logs"},
		{"POST", "/api/exploration/findings/273/deepen"},
	}
	for _, c := range denied {
		if projectKeyPathAllowed(c[0], c[1]) {
			t.Errorf("%s %s 应拒绝", c[0], c[1])
		}
	}
}
