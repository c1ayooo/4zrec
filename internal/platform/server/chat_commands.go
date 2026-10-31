package server

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// chat_commands.go 对话内斜杠命令：/bond（绑定项目/任务）、/new（新会话）、
// /commands（指令清单）。平台直接处理，不经 LLM——指令与回复都以活动进对话流
// （kind='text' 渲染成回复气泡），agent 的上下文来自独立 transcript 文件，不受影响。
// 自然语言绑定走 ChatAgent 平台工具（chat_platform_tools.go），写路径共用
// setConversationBinding，两条路径语义一致。

const (
	bondTaskListLimit  = 15
	bondProjectListMax = 20
)

type chatCommand struct {
	raw  string   // 原样首 token（/bond、/bondx…）
	name string   // bond / new / commands / help；"" = 未知的形似指令
	args []string // 其余空白分隔参数
}

// parseChatCommand 识别 "/cmd args…"。ok=false 表示不是指令（含 /etc/passwd 这类
// 路径），原样交给 agent。形如指令但未知的（/bondx 这类纯字母 token）也按已处理
// 返回、由调用方回复指令清单——纯字母 token 几乎不可能是想粘贴的路径。
func parseChatCommand(msg string) (chatCommand, bool) {
	fields := strings.Fields(strings.TrimSpace(msg))
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "/") {
		return chatCommand{}, false
	}
	name := strings.ToLower(strings.TrimPrefix(fields[0], "/"))
	switch name {
	case "bond", "new", "commands", "help":
		return chatCommand{raw: fields[0], name: name, args: fields[1:]}, true
	}
	if isCommandName(name) {
		return chatCommand{raw: fields[0], args: fields[1:]}, true
	}
	return chatCommand{}, false
}

// isCommandName 报告 s 是否为纯小写字母 token（指令名形态）。
func isCommandName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

// handleConversationCommand 处理一条斜杠指令并把指令+回复落进对话流。
func (s *Server) handleConversationCommand(w http.ResponseWriter, pg *db.DB, c *db.Conversation, msg string) {
	cmd, _ := parseChatCommand(msg)
	if cmd.name == "new" {
		s.handleNewConversationCommand(w, pg, c, msg)
		return
	}
	reply := chatCommandHelp()
	switch cmd.name {
	case "bond":
		reply = applyBondCommand(pg, c.ID, cmd.args)
	case "commands", "help":
	default: // 形似指令但未知：回复清单，避免打错字被静默喂给 LLM
		reply = "未知指令 " + cmd.raw + "。\n\n" + chatCommandHelp()
	}
	appendCommandExchange(pg, c, msg, reply)
	_ = pg.TouchConversation(c.ID)
	writeJSON(w, 200, map[string]any{"status": "handled"})
}

// handleNewConversationCommand 开新会话：旧会话不落任何记录（保持干净），说明性
// 回复写进新会话；响应带 new_conversation_id，前端收到后切换过去。
func (s *Server) handleNewConversationCommand(w http.ResponseWriter, pg *db.DB, c *db.Conversation, msg string) {
	nc, err := createSuccessorConversation(pg, c)
	if err != nil {
		appendCommandExchange(pg, c, msg, "创建新会话失败："+err.Error())
		_ = pg.TouchConversation(c.ID)
		writeJSON(w, 200, map[string]any{"status": "handled"})
		return
	}
	_, _ = pg.AppendConvActivity(nc.ID, db.Activity{
		Worker: c.AgentKey, Kind: "text", Summary: firstLine(successorNote(pg, c), 200), Detail: successorNote(pg, c)})
	_ = pg.TouchConversation(nc.ID)
	writeJSON(w, 200, map[string]any{"status": "handled", "new_conversation_id": nc.ID})
}

// createSuccessorConversation 为当前会话开一个后继会话（同 agent、同 LLM pin；
// pin 的配置已删时退回全局配置）。IM 的 /new 与对话页共用。
func createSuccessorConversation(pg *db.DB, c *db.Conversation) (*db.Conversation, error) {
	nc, err := pg.CreateConversation(c.AgentKey, "新对话", c.LLMProfileID)
	if err != nil {
		nc, err = pg.CreateConversation(c.AgentKey, "新对话", nil)
	}
	return nc, err
}

// successorNote 写进新会话的说明：上一会话编号与绑定状态。
func successorNote(pg *db.DB, old *db.Conversation) string {
	note := "新会话已创建。"
	if conversationBound(old) {
		note += "\n上一会话 #" + strconv.FormatInt(old.ID, 10) + "：" + bindingLine(pg, old) + "。"
	}
	note += "\n/bond 可重新绑定项目和任务。"
	return note
}

// appendCommandExchange 把用户指令与平台回复成对落进对话流。
func appendCommandExchange(pg *db.DB, c *db.Conversation, msg, reply string) {
	ua := db.Activity{Worker: c.AgentKey, Kind: "user", Summary: firstLine(msg, 200), Detail: msg}
	if _, err := pg.AppendConvActivity(c.ID, ua); err != nil {
		log.Printf("[conv %d] append command msg failed: %v", c.ID, err)
	}
	if reply == "" {
		return
	}
	ra := db.Activity{Worker: c.AgentKey, Kind: "text", Summary: firstLine(reply, 200), Detail: reply}
	if _, err := pg.AppendConvActivity(c.ID, ra); err != nil {
		log.Printf("[conv %d] append command reply failed: %v", c.ID, err)
	}
}

func chatCommandHelp() string {
	return "可用指令：\n" +
		"- /bond — 查看会话绑定；/bond <项目>、/bond <项目> <任务> 绑定；/bond off 解绑\n" +
		"- /new — 开启新会话（绑定需重新设置）\n" +
		"- /commands — 本清单\n" +
		"自然语言也可以：直接说「绑到虎牙项目」即可。"
}

// ---- /bond ----

func applyBondCommand(pg *db.DB, convID int64, args []string) string {
	switch {
	case len(args) == 0:
		return bondOverview(pg, convID)
	case len(args) == 1:
		return bondOne(pg, convID, args[0])
	default:
		return bondTwo(pg, convID, args[0], args[1])
	}
}

// bondOverview 无参 /bond：当前绑定 + 下一步引导（未绑列项目，绑了项目列任务）。
func bondOverview(pg *db.DB, convID int64) string {
	cur, err := pg.GetConversation(convID)
	if err != nil || cur == nil {
		return "读取会话失败，请重试。"
	}
	var b strings.Builder
	b.WriteString(bindingLine(pg, cur))
	tasks, _ := pg.ListTasks()
	switch {
	case cur.TaskID != nil && *cur.TaskID > 0:
		if pid := cur.ProjectID; pid != nil && *pid > 0 {
			b.WriteString("\n\n本项目任务：\n" + formatTaskList(tasksOfProject(tasks, *pid)))
		}
		b.WriteString("\n\n/bond <任务> 换绑任务；/bond <项目> 换绑项目；/bond off 解绑。")
	case cur.ProjectID != nil && *cur.ProjectID > 0:
		pt := tasksOfProject(tasks, *cur.ProjectID)
		if len(pt) == 0 {
			b.WriteString("\n\n该项目暂无任务，创建后可 /bond <任务> 关联。")
		} else {
			b.WriteString("\n\n本项目任务：\n" + formatTaskList(pt))
			b.WriteString("\n\n/bond <任务> 关联任务；/bond off 解绑。")
		}
	default:
		projects, err := pg.Projects().ListProjects()
		if err != nil {
			b.WriteString("\n\n读取项目失败：" + err.Error())
			return b.String()
		}
		if len(projects) == 0 {
			b.WriteString("\n\n还没有项目，先到「项目」页创建。")
			return b.String()
		}
		b.WriteString("\n\n" + formatProjectList(projects))
		b.WriteString("\n\n/bond <项目> 绑定项目（编号或名称）。")
	}
	return b.String()
}

// bondOne 单参数：off=解绑；先按项目匹配（编号/名称），没命中再在已绑项目
// （无则全量）的任务里找。绑任务自动把项目对齐到任务所属项目。
func bondOne(pg *db.DB, convID int64, q string) string {
	if q == "off" || q == "解绑" || q == "解除" {
		if _, err := setConversationBinding(pg, convID, bondIntPtr(0), bondIntPtr(0)); err != nil {
			return "解绑失败：" + err.Error()
		}
		return "已解除绑定。/bond 可重新绑定。"
	}
	projects, err := pg.Projects().ListProjects()
	if err != nil {
		return "读取项目失败：" + err.Error()
	}
	p, amb, pok := matchProject(projects, q)
	if pok {
		text, err := setConversationBinding(pg, convID, &p.ID, bondIntPtr(0)) // 换绑项目清旧任务
		if err != nil {
			return "绑定失败：" + err.Error()
		}
		return text + "\n\n" + projectTasksBlock(pg, p.ID)
	}
	if len(amb) > 0 {
		return "「" + q + "」匹配到多个项目，请用编号：\n" + formatProjectList(amb)
	}
	tasks, err := pg.ListTasks()
	if err != nil {
		return "读取任务失败：" + err.Error()
	}
	cur, _ := pg.GetConversation(convID)
	scope := tasks
	boundProject := ""
	if cur != nil && cur.ProjectID != nil && *cur.ProjectID > 0 {
		scope = tasksOfProject(tasks, *cur.ProjectID)
		boundProject = projectName(pg, *cur.ProjectID)
	}
	t, tamb, tok := matchTask(scope, q)
	if !tok {
		if len(tamb) > 0 {
			return "「" + q + "」匹配到多个任务，请用编号：\n" + formatTaskList(tamb)
		}
		if boundProject != "" {
			return "没有匹配「" + q + "」的任务。\n\n当前项目「" + boundProject + "」内的任务：\n" +
				formatTaskList(scope) + "\n\n换项目用 /bond <项目>。"
		}
		return "没有匹配「" + q + "」的项目或任务。\n\n" + formatProjectList(projects) + "\n\n/bond <项目> 绑定项目。"
	}
	text, err := setConversationBinding(pg, convID, t.ProjectID, &t.ID)
	if err != nil {
		return "绑定失败：" + err.Error()
	}
	return text + bondAlignNote(pg, cur, t)
}

// bondTwo 双参数：先项目后任务，任务必须属于该项目，不做静默对齐。
func bondTwo(pg *db.DB, convID int64, pq, tq string) string {
	projects, err := pg.Projects().ListProjects()
	if err != nil {
		return "读取项目失败：" + err.Error()
	}
	p, amb, ok := matchProject(projects, pq)
	if !ok {
		if len(amb) > 0 {
			return "「" + pq + "」匹配到多个项目，请用编号：\n" + formatProjectList(amb)
		}
		return "没有找到项目「" + pq + "」。\n\n" + formatProjectList(projects)
	}
	tasks, err := pg.ListTasks()
	if err != nil {
		return "读取任务失败：" + err.Error()
	}
	pt := tasksOfProject(tasks, p.ID)
	t, tamb, tok := matchTask(pt, tq)
	if !tok {
		if len(tamb) > 0 {
			return "「" + tq + "」匹配到多个任务，请用编号：\n" + formatTaskList(tamb)
		}
		if len(pt) == 0 {
			return "项目「" + p.Name + "」暂无任务。"
		}
		return "项目「" + p.Name + "」里没有匹配「" + tq + "」的任务。\n\n" + formatTaskList(pt)
	}
	text, err := setConversationBinding(pg, convID, &p.ID, &t.ID)
	if err != nil {
		return "绑定失败：" + err.Error()
	}
	return text
}

// bondAlignNote 绑任务引起项目变化时给一句同步说明；未变则空串。
func bondAlignNote(pg *db.DB, cur *db.Conversation, t *db.Task) string {
	if t.ProjectID == nil || *t.ProjectID <= 0 {
		return ""
	}
	if cur != nil && cur.ProjectID != nil && *cur.ProjectID == *t.ProjectID {
		return ""
	}
	if pn := projectName(pg, *t.ProjectID); pn != "" {
		return "\n项目已同步为「" + pn + "」。"
	}
	return ""
}

// setConversationBinding 校验并写入会话绑定。projectID/taskID 非 nil 才更新
// （指向 0 = 清除）。只给任务时自动对齐任务所属项目；两者都显式给出且任务
// 归属不一致时报错，不静默改写用户指定的项目。
func setConversationBinding(pg *db.DB, convID int64, projectID, taskID *int64) (string, error) {
	if taskID != nil && *taskID > 0 {
		t, err := pg.GetTask(*taskID)
		if err != nil {
			return "", err
		}
		if t == nil {
			return "", fmt.Errorf("任务 #%d 不存在", *taskID)
		}
		if t.ProjectID != nil && *t.ProjectID > 0 {
			if projectID == nil || *projectID == 0 {
				projectID = t.ProjectID // 对齐任务所属项目（围栏跟随）
			} else if *t.ProjectID != *projectID {
				return "", fmt.Errorf("任务 #%d 属于项目「%s」，与项目「%s」不一致",
					*taskID, projectName(pg, *t.ProjectID), projectName(pg, *projectID))
			}
		}
	}
	if projectID != nil && *projectID > 0 {
		p, err := pg.Projects().GetProject(*projectID)
		if err != nil {
			return "", err
		}
		if p.ID == 0 {
			return "", fmt.Errorf("项目 #%d 不存在", *projectID)
		}
	}
	updated, err := pg.UpdateConversation(convID, db.ConversationPatch{ProjectID: projectID, TaskID: taskID})
	if err != nil {
		return "", err
	}
	if updated == nil {
		return "", fmt.Errorf("会话不存在")
	}
	return bindingLine(pg, updated) + "。", nil
}

// bindingLine 渲染一行绑定状态（不含句号，调用方按语境拼接）。
func bindingLine(pg *db.DB, c *db.Conversation) string {
	if c == nil || !conversationBound(c) {
		return "当前未绑定项目和任务"
	}
	if c.TaskID != nil && *c.TaskID > 0 {
		tname, status := "未命名任务", ""
		if t, _ := pg.GetTask(*c.TaskID); t != nil {
			if t.Name != "" {
				tname = t.Name
			}
			status = "（" + taskStatusZH(t) + "）"
		}
		if c.ProjectID != nil && *c.ProjectID > 0 {
			return fmt.Sprintf("当前绑定：项目「%s」· 任务 #%d「%s」%s",
				projectName(pg, *c.ProjectID), *c.TaskID, tname, status)
		}
		return fmt.Sprintf("当前绑定：任务 #%d「%s」%s", *c.TaskID, tname, status)
	}
	return fmt.Sprintf("当前绑定：项目「%s」", projectName(pg, *c.ProjectID))
}

// conversationBound 报告会话是否绑定了项目或任务。
func conversationBound(c *db.Conversation) bool {
	return (c.ProjectID != nil && *c.ProjectID > 0) || (c.TaskID != nil && *c.TaskID > 0)
}

// projectName 项目名；查不到回退 "#id"。
func projectName(pg *db.DB, id int64) string {
	if p, err := pg.Projects().GetProject(id); err == nil && p.ID != 0 {
		return p.Name
	}
	return "#" + strconv.FormatInt(id, 10)
}

// ---- 匹配与格式化（纯函数，chat_commands_test.go 覆盖）----

// matchProject 编号 → 精确名（不分大小写）→ 子串；子串命中多个返回候选清单。
func matchProject(ps []db.Project, q string) (match *db.Project, candidates []db.Project, ok bool) {
	if id, err := strconv.ParseInt(q, 10, 64); err == nil {
		for i := range ps {
			if ps[i].ID == id {
				return &ps[i], nil, true
			}
		}
		return nil, nil, false
	}
	for i := range ps {
		if strings.EqualFold(ps[i].Name, q) {
			return &ps[i], nil, true
		}
	}
	lq := strings.ToLower(q)
	for i := range ps {
		if strings.Contains(strings.ToLower(ps[i].Name), lq) {
			candidates = append(candidates, ps[i])
		}
	}
	if len(candidates) == 1 {
		return &candidates[0], nil, true
	}
	return nil, candidates, false
}

// matchTask 同 matchProject，作用于任务切片。
func matchTask(ts []*db.Task, q string) (match *db.Task, candidates []*db.Task, ok bool) {
	if id, err := strconv.ParseInt(q, 10, 64); err == nil {
		for _, t := range ts {
			if t.ID == id {
				return t, nil, true
			}
		}
		return nil, nil, false
	}
	for _, t := range ts {
		if strings.EqualFold(t.Name, q) {
			return t, nil, true
		}
	}
	lq := strings.ToLower(q)
	for _, t := range ts {
		if strings.Contains(strings.ToLower(t.Name), lq) {
			candidates = append(candidates, t)
		}
	}
	if len(candidates) == 1 {
		return candidates[0], nil, true
	}
	return nil, candidates, false
}

func tasksOfProject(ts []*db.Task, pid int64) []*db.Task {
	out := make([]*db.Task, 0, len(ts))
	for _, t := range ts {
		if t.ProjectID != nil && *t.ProjectID == pid {
			out = append(out, t)
		}
	}
	return out
}

func projectTasksBlock(pg *db.DB, pid int64) string {
	tasks, _ := pg.ListTasks()
	pt := tasksOfProject(tasks, pid)
	if len(pt) == 0 {
		return "项目「" + projectName(pg, pid) + "」暂无任务，创建后可 /bond <任务> 关联。"
	}
	return "本项目任务：\n" + formatTaskList(pt)
}

func formatProjectList(ps []db.Project) string {
	if len(ps) == 0 {
		return "（无项目）"
	}
	lines := make([]string, 0, len(ps))
	for i := range ps {
		if i >= bondProjectListMax {
			lines = append(lines, fmt.Sprintf("…（另有 %d 个项目略）", len(ps)-bondProjectListMax))
			break
		}
		lines = append(lines, fmt.Sprintf("- #%d %s（任务 %d · 资产 %d）", ps[i].ID, ps[i].Name, ps[i].TaskCount, ps[i].AssetCount))
	}
	return strings.Join(lines, "\n")
}

func formatTaskList(ts []*db.Task) string {
	if len(ts) == 0 {
		return "（无任务）"
	}
	lines := make([]string, 0, len(ts))
	for i, t := range ts {
		if i >= bondTaskListLimit {
			lines = append(lines, fmt.Sprintf("…（另有 %d 个任务略）", len(ts)-bondTaskListLimit))
			break
		}
		name := t.Name
		if name == "" {
			name = "未命名任务"
		}
		lines = append(lines, fmt.Sprintf("- #%d %s（%s）", t.ID, name, taskStatusZH(t)))
	}
	return strings.Join(lines, "\n")
}

// taskStatusZH 任务状态中文标签；排队/暂停优先于生命周期状态。
func taskStatusZH(t *db.Task) string {
	switch {
	case t.Queued:
		return "排队中"
	case t.Paused:
		return "已暂停"
	}
	switch t.Status {
	case "created":
		return "已创建"
	case "running":
		return "运行中"
	case "done":
		return "已完成"
	case "failed":
		return "已失败"
	case "timeout":
		return "已超时"
	}
	return t.Status
}

// convIDFromSession 从 transcript sessionID（"conv-<id>"）取会话 id；非对话 run 返回 0。
func convIDFromSession(sessionID string) int64 {
	rest, ok := strings.CutPrefix(sessionID, "conv-")
	if !ok {
		return 0
	}
	id, err := strconv.ParseInt(rest, 10, 64)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}

func bondIntPtr(v int64) *int64 { return &v }
