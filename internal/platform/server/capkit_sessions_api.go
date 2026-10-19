package server

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	capkit "github.com/c1ayooo/capkit/core"

	"github.com/c1ayooo/4zrec/internal/capkitbridge"
)

// Session API for the web console. These handlers are thin: they translate the
// request into the same capkit tool calls an agent makes, so a session opened
// from the UI is indistinguishable from one opened by an agent (same gate chain,
// same evidence, same close semantics).
//
// Project isolation: capkit's session manager is process-wide, so the bridge
// records the opening project and these handlers filter on it. A project-scoped
// API key can never see or drive another project's foothold.

type capkitSessionDTO struct {
	ID        string            `json:"id"`
	Kind      string            `json:"kind"`
	Host      string            `json:"host,omitempty"`
	Port      int               `json:"port,omitempty"`
	User      string            `json:"user,omitempty"`
	OS        string            `json:"os,omitempty"`
	Arch      string            `json:"arch,omitempty"`
	Elevated  bool              `json:"elevated,omitempty"`
	Labels    []string          `json:"labels,omitempty"`
	Meta      map[string]string `json:"meta,omitempty"`
	ProjectID int64             `json:"project_id,omitempty"`
}

type capkitOpenInput struct {
	Kind    string            `json:"kind"`
	Host    string            `json:"host"`
	Port    int               `json:"port"`
	User    string            `json:"user"`
	Secret  string            `json:"secret"`
	Domain  string            `json:"domain"`
	Options map[string]string `json:"options"`
	Labels  []string          `json:"labels"`
}

// capkitKindDTO is one entry of the session-type catalogue the UI builds its
// form from. Availability is decided by the bridge (which transports are
// actually registered), not by this list: a kind declared here but not
// registered is reported unavailable instead of failing at open time.
type capkitKindDTO struct {
	ID        string   `json:"id"`
	Label     string   `json:"label"`
	Category  string   `json:"category"`
	Available bool     `json:"available"`
	Hint      string   `json:"hint,omitempty"`
	Fields    []string `json:"fields"`
}

// capkitKindCatalog is the UI's session-type taxonomy. Fields name the inputs
// the open form should show for that kind; the dialog renders only these, so a
// kind never shows a field its transport ignores. Whether a kind can actually
// be opened is decided at runtime by capkitKinds, not declared here.
var capkitKindCatalog = []capkitKindDTO{
	{
		ID: "webshell", Label: "WebShell", Category: "webshell",
		Fields: []string{"url", "password", "shell_type", "cmd_param", "method"},
		Hint:   "填已落地 shell 的完整 URL；口令与命令参数名需与 payload 一致",
	},
	{
		ID: "ssh", Label: "SSH", Category: "remote",
		Fields: []string{"host", "port", "user", "secret"},
		Hint:   "口令或 PEM 私钥；支持 exec/上传/下载/端口转发",
	},
	{
		ID: "winrm", Label: "WinRM", Category: "windows",
		Fields: []string{"host", "port", "user", "secret", "domain"},
		Hint:   "默认走 http/5985；NTLM/Kerberos 需宿主在 HTTPDoer 侧终止认证",
	},
	{
		ID: "smb", Label: "SMB 共享", Category: "share",
		Fields: []string{"host", "port", "user", "secret", "share", "domain"},
		Hint:   "无远程 shell，exec 执行的是 smbclient 子命令（ls/get/put/del）",
	},
	{
		ID: "mysql", Label: "MySQL", Category: "database",
		Fields: []string{"host", "port", "user", "secret", "database"},
		Hint:   "command 是一条 SQL 语句；库名在 database 字段。写操作会在输出里标注。",
	},
	{
		ID: "postgres", Label: "PostgreSQL", Category: "database",
		Fields: []string{"host", "port", "user", "secret", "database", "sslmode"},
		Hint:   "command 是一条 SQL 语句；sslmode 默认 disable（靶场/内网多无有效证书），WAL/复制类语句请自行确认目标角色。",
	},
	{
		ID: "cli", Label: "本地 Shell", Category: "local",
		Fields: []string{"shell"},
	},
}

// capkitUnsupported marks kinds the platform deliberately does not offer, with
// the reason shown in the UI. Listing them beats leaving an unexplained gap.
// "本地 Shell" is the case: the platform host is not a project target, so a
// local session cannot pass the scope fence.
var capkitUnsupported = map[string]string{
	"cli": "本地 Shell 运行在平台主机上，而平台主机不是项目授权目标，过不了 scope 围栏；本地命令请用带护栏的 Bash 工具。",
}

// capkitKinds resolves the catalogue against the transports the bridge really
// registered.
func capkitKinds(bridge *capkitbridge.Bridge) []capkitKindDTO {
	live := map[string]bool{}
	if bridge != nil {
		for _, k := range bridge.AvailableKinds() {
			live[k] = true
		}
	}
	out := make([]capkitKindDTO, 0, len(capkitKindCatalog))
	for _, k := range capkitKindCatalog {
		if reason, unsupported := capkitUnsupported[k.ID]; unsupported {
			k.Available, k.Hint = false, reason
		} else {
			k.Available = live[k.ID]
		}
		out = append(out, k)
	}
	return out
}

// capkitKindAvailable reports whether a kind can be opened right now. Unknown
// kinds are unavailable, so a typo is rejected with the same message as a
// transport that is switched off.
func capkitKindAvailable(bridge *capkitbridge.Bridge, kind string) bool {
	for _, k := range capkitKinds(bridge) {
		if k.ID == kind {
			return k.Available
		}
	}
	return false
}

// GET /api/capkit/sessions
func (s *Server) capkitSessionList(w http.ResponseWriter, r *http.Request) {
	bridge := s.capkitBridgeOrNil()
	if bridge == nil {
		writeJSON(w, http.StatusOK, map[string]any{"sessions": []capkitSessionDTO{}, "enabled": false, "kinds": capkitKinds(nil)})
		return
	}
	list := bridge.LiveSessions(scopedProjectID(r.Context()))
	out := make([]capkitSessionDTO, 0, len(list))
	for _, info := range list {
		out = append(out, capkitSessionDTO{
			ID: info.ID, Kind: info.Kind, Host: info.Host, Port: info.Port,
			User: info.User, OS: info.OS, Arch: info.Arch, Elevated: info.Elevated,
			Labels: info.Labels, Meta: info.Meta, ProjectID: info.ProjectID,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sessions": out, "enabled": true, "kinds": capkitKinds(bridge),
	})
}

// POST /api/capkit/sessions/open
func (s *Server) capkitSessionOpen(w http.ResponseWriter, r *http.Request) {
	bridge := s.capkitBridgeOrNil()
	if bridge == nil {
		writeErr(w, http.StatusServiceUnavailable, "capkit 桥接未启用")
		return
	}
	var in capkitOpenInput
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Kind == "" || in.Host == "" {
		writeErr(w, http.StatusBadRequest, "kind 与 host 必填")
		return
	}
	if !capkitKindAvailable(bridge, in.Kind) {
		writeErr(w, http.StatusBadRequest, "不支持的会话类型: "+in.Kind)
		return
	}
	cc := capkit.CallContext{ProjectID: scopedProjectID(r.Context()), Actor: capkitActor(r)}
	raw, _ := json.Marshal(in)
	res, err := bridge.Call(r.Context(), "session_open", raw, cc)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if !res.OK {
		writeCapkitFailure(w, res)
		return
	}
	var out struct {
		SessionID string `json:"session_id"`
		Kind      string `json:"kind"`
		Host      string `json:"host"`
		User      string `json:"user"`
		OS        string `json:"os"`
		Elevated  bool   `json:"elevated"`
	}
	_ = json.Unmarshal(res.Data, &out)
	writeJSON(w, http.StatusOK, capkitSessionDTO{
		ID: out.SessionID, Kind: out.Kind, Host: out.Host, User: out.User,
		OS: out.OS, Elevated: out.Elevated, ProjectID: cc.ProjectID,
	})
}

// POST /api/capkit/sessions/{id}/exec
func (s *Server) capkitSessionExec(w http.ResponseWriter, r *http.Request) {
	bridge := s.capkitBridgeOrNil()
	if bridge == nil {
		writeErr(w, http.StatusServiceUnavailable, "capkit 桥接未启用")
		return
	}
	id := r.PathValue("id")
	if !capkitOwnsSession(bridge, r, id) {
		writeErr(w, http.StatusNotFound, "会话不存在: "+id)
		return
	}
	var in struct {
		Command   string `json:"command"`
		TimeoutMS int    `json:"timeout_ms"`
		Dir       string `json:"dir"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Command == "" {
		writeErr(w, http.StatusBadRequest, "command 必填")
		return
	}
	raw, _ := json.Marshal(map[string]any{
		"session_id": id, "command": in.Command,
		"timeout_ms": in.TimeoutMS, "dir": in.Dir,
	})
	cc := capkit.CallContext{ProjectID: scopedProjectID(r.Context()), Actor: capkitActor(r)}
	res, err := bridge.Call(r.Context(), "session_exec", raw, cc)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if !res.OK {
		writeCapkitFailure(w, res)
		return
	}
	var out struct {
		Command    string `json:"command"`
		Stdout     string `json:"stdout"`
		Stderr     string `json:"stderr"`
		ExitCode   int    `json:"exit_code"`
		DurationMS int64  `json:"duration_ms"`
		Truncated  bool   `json:"truncated"`
	}
	_ = json.Unmarshal(res.Data, &out)
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": id, "command": out.Command, "stdout": out.Stdout,
		"stderr": out.Stderr, "exit_code": out.ExitCode,
		"duration_ms": out.DurationMS, "truncated": out.Truncated,
		"summary": res.Summary, "evidence": res.Evidence,
	})
}

// POST /api/capkit/sessions/{id}/close
func (s *Server) capkitSessionClose(w http.ResponseWriter, r *http.Request) {
	bridge := s.capkitBridgeOrNil()
	if bridge == nil {
		writeErr(w, http.StatusServiceUnavailable, "capkit 桥接未启用")
		return
	}
	id := r.PathValue("id")
	if !capkitOwnsSession(bridge, r, id) {
		writeErr(w, http.StatusNotFound, "会话不存在: "+id)
		return
	}
	cc := capkit.CallContext{ProjectID: scopedProjectID(r.Context()), Actor: capkitActor(r)}
	raw, _ := json.Marshal(map[string]string{"session_id": id})
	res, err := bridge.Call(r.Context(), "session_close", raw, cc)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if !res.OK {
		writeCapkitFailure(w, res)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "session_id": id})
}

// capkitBridgeOrNil returns the built bridge without forcing construction. The
// UI shows an explanatory empty state rather than a 500 when the bridge could
// not start (the startup error is already in the server log).
func (s *Server) capkitBridgeOrNil() *capkitbridge.Bridge {
	s.capkitMu.Lock()
	defer s.capkitMu.Unlock()
	if s.capkitBridge == nil && s.capkitErr != nil {
		return nil
	}
	if s.capkitBridge == nil {
		// First call builds it, exactly like hostTools() would.
		s.capkitBridge, s.capkitErr = s.buildCapkitBridge()
		if s.capkitErr != nil {
			log.Printf("[capkit] 桥接未启用: %v", s.capkitErr)
			return nil
		}
	}
	return s.capkitBridge
}

// capkitOwnsSession enforces project isolation. A global caller (no project
// scope) may drive any session; a project-scoped caller only its own.
func capkitOwnsSession(bridge *capkitbridge.Bridge, r *http.Request, id string) bool {
	scope := scopedProjectID(r.Context())
	if scope <= 0 {
		return true
	}
	owner, ok := bridge.SessionProject(id)
	return ok && owner == scope
}

// writeCapkitFailure maps capkit's fixed error codes onto HTTP statuses. The
// hint goes to the caller so the UI can tell the user what to change.
func writeCapkitFailure(w http.ResponseWriter, res capkit.Result) {
	code, msg, hint := "", res.Summary, ""
	if res.Error != nil {
		code, msg, hint = res.Error.Code, res.Error.Message, res.Error.Hint
	}
	status := http.StatusBadGateway
	switch code {
	case capkit.CodeInvalidInput:
		status = http.StatusBadRequest
	case capkit.CodeNotFound:
		status = http.StatusNotFound
	case capkit.CodeScopeDenied, capkit.CodeApprovalRequired:
		status = http.StatusForbidden
	case capkit.CodeRateLimited:
		status = http.StatusTooManyRequests
	case capkit.CodeUnavailable, capkit.CodeToolMissing:
		status = http.StatusServiceUnavailable
	case capkit.CodeTargetUnreachable, capkit.CodeTimeout:
		status = http.StatusGatewayTimeout
	}
	body := map[string]any{"error": msg, "code": code, "status": string(res.Status)}
	if hint != "" {
		body["hint"] = hint
	}
	writeJSON(w, status, body)
}

// capkitActor is best-effort attribution: the API key id when present, "web"
// otherwise. It never carries credentials.
func capkitActor(r *http.Request) string {
	if sc := APIScopeFrom(r.Context()); sc.KeyID > 0 {
		return "apikey:" + strconv.FormatInt(sc.KeyID, 10)
	}
	return "web"
}
