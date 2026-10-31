package server

import (
	"context"
	"encoding/json"
	"fmt"

	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

// chat_platform_tools.go 给 ChatAgent 注入四个平台工具，把 Hermes 的 API 编排
// （skills/4zrec-api/SKILL.md §8 的最小子集）搬进对话：列项目、列任务、绑定会话、
// 查绑定。工具按会话注入（sessionID 形如 conv-<id>），自然语言「绑到虎牙项目」
// 与斜杠 /bond 走同一落库函数 setConversationBinding，语义一致。
const chatTaskListCap = 30

// chatPlatformTools 返回该会话可用的平台工具；非对话会话返回 nil（不注入）。
func (s *Server) chatPlatformTools(sessionID string) []actool.CoreTool {
	convID := convIDFromSession(sessionID)
	if convID <= 0 || s.m == nil || s.m.pg == nil {
		return nil
	}
	pg := s.m.pg
	return []actool.CoreTool{
		actool.Build(actool.Spec{
			Name:        "list_projects",
			Description: "列出 4zrec 平台的授权项目（编号、名称、任务数、资产数）。给会话绑定项目前先看这里有哪些项目。",
			Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
			ReadOnly:    func(json.RawMessage) bool { return true },
			Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
			Run: func(_ context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
				ps, err := pg.Projects().ListProjects()
				if err != nil {
					return actool.Errorf("读取项目失败：" + err.Error()), nil
				}
				if len(ps) == 0 {
					return actool.Text("平台还没有项目，请先在 Web「项目」页创建。"), nil
				}
				return actool.Text(formatProjectList(ps)), nil
			},
		}),
		actool.Build(actool.Spec{
			Name:        "list_tasks",
			Description: "列出任务（编号、名称、状态）。project_id 省略时优先列当前会话绑定项目的任务，未绑定则列全平台最近任务。",
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"project_id": map[string]any{"type": "integer", "description": "按项目过滤（可选）"},
				},
			},
			ReadOnly:    func(json.RawMessage) bool { return true },
			Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
			Run: func(_ context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
				var in struct {
					ProjectID int64 `json:"project_id"`
				}
				_ = json.Unmarshal(input, &in)
				pid := in.ProjectID
				scope := ""
				if pid <= 0 {
					if c, _ := pg.GetConversation(convID); c != nil && c.ProjectID != nil && *c.ProjectID > 0 {
						pid = *c.ProjectID
						scope = fmt.Sprintf("（当前会话绑定项目 #%d）", pid)
					}
				} else {
					scope = fmt.Sprintf("（项目 #%d）", pid)
				}
				tasks, err := pg.ListTasks()
				if err != nil {
					return actool.Errorf("读取任务失败：" + err.Error()), nil
				}
				if pid > 0 {
					tasks = tasksOfProject(tasks, pid)
				}
				if len(tasks) == 0 {
					return actool.Text("没有任务。" + scope), nil
				}
				note := ""
				if len(tasks) > chatTaskListCap {
					tasks = tasks[len(tasks)-chatTaskListCap:]
					note = "\n（仅显示最近 " + fmt.Sprint(chatTaskListCap) + " 个，可用 project_id 收窄）"
				}
				return actool.Text(formatTaskList(tasks) + note), nil
			},
		}),
		actool.Build(actool.Spec{
			Name:        "bind_conversation",
			Description: "把当前会话绑定到项目和/或任务（等价于斜杠 /bond）。只给 task_id 时自动对齐任务所属项目；project_id 与 task_id 同时给出且任务归属不一致会报错；两个都传 0 解绑。绑定后资产围栏随项目授权范围生效。",
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"project_id": map[string]any{"type": "integer", "description": "项目编号（0=清除）"},
					"task_id":    map[string]any{"type": "integer", "description": "任务编号（0=清除）"},
				},
			},
			Run: func(_ context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
				var in struct {
					ProjectID *int64 `json:"project_id"`
					TaskID    *int64 `json:"task_id"`
				}
				if err := json.Unmarshal(input, &in); err != nil {
					return actool.Errorf("参数解析失败：" + err.Error()), nil
				}
				if in.ProjectID == nil && in.TaskID == nil {
					return actool.Errorf("project_id 与 task_id 至少提供一个"), nil
				}
				text, err := setConversationBinding(pg, convID, in.ProjectID, in.TaskID)
				if err != nil {
					return actool.Errorf("绑定失败：" + err.Error()), nil
				}
				return actool.Text(text), nil
			},
		}),
		actool.Build(actool.Spec{
			Name:        "get_binding",
			Description: "查看当前会话绑定的项目和任务。",
			Schema:      map[string]any{"type": "object", "properties": map[string]any{}},
			ReadOnly:    func(json.RawMessage) bool { return true },
			Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
			Run: func(_ context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
				c, err := pg.GetConversation(convID)
				if err != nil || c == nil {
					return actool.Errorf("读取会话失败"), nil
				}
				return actool.Text(bindingLine(pg, c) + "。"), nil
			},
		}),
	}
}

// chatBindingSpec 每轮重读绑定状态拼进 system prompt，绑定变化下一轮即生效。
func (s *Server) chatBindingSpec(sessionID string) string {
	convID := convIDFromSession(sessionID)
	if convID <= 0 || s.m == nil || s.m.pg == nil {
		return ""
	}
	pg := s.m.pg
	base := "\n\n**平台操作**：可用 list_projects / list_tasks 查询项目与任务，bind_conversation 把本会话绑定到项目/任务（解绑两个参数都传 0），get_binding 查看当前绑定。"
	c, err := pg.GetConversation(convID)
	if err != nil || c == nil {
		return base
	}
	if !conversationBound(c) {
		return base + "当前会话未绑定项目和任务。"
	}
	return base + bindingLine(pg, c) + "。"
}
