// connections_tools.go 连接台账:worker 任务中发现/验证成功的凭据自动落库
// (source=discovered,绑定任务所属项目),手工登记与台账查询工具。
// 明文存储不做加密(用户口径);挂项目是入库硬前提——无项目上下文不落库,
// 结果里明确提示 agent 挂项目。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

// autoCaptureConnection 验证成功后的自动落库(幂等合并)。返回提示文案(空=未落库)。
func (s *Server) autoCaptureConnection(ctx context.Context, c *db.Connection) string {
	if s.m == nil || s.m.pg == nil {
		return ""
	}
	// 连接台账存的是"可复用的已验证凭据",空 secret 没有复用价值,还会让
	// 台账出现一条看起来验证成功、实际无法认证的假记录。
	if strings.TrimSpace(c.Secret) == "" {
		return "(空凭据不写入连接台账)"
	}
	projectID := s.roeProjectID(ctx, 0)
	if projectID <= 0 {
		return "(未挂项目,凭据未入连接台账——在对话/任务上挂载项目后验证可自动落库)"
	}
	c.ProjectID = projectID
	c.Source = "discovered"
	if c.Status == "" {
		c.Status = "alive"
	}
	id, created, err := s.m.pg.UpsertConnection(ctx, c)
	if err != nil {
		return fmt.Sprintf("(连接台账写入失败: %v)", err)
	}
	if created {
		return fmt.Sprintf("已自动登记连接台账 #%d(项目 %d,source=discovered)", id, projectID)
	}
	return fmt.Sprintf("已更新连接台账 #%d(项目 %d)", id, projectID)
}

// toolConnectionsList 连接台账查询。
func (s *Server) toolConnectionsList() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "connections_list",
		Description: "连接台账查询:项目下的 SSH/数据库/WebShell(SMB/WinRM/LDAP/VNC/FTP 等)凭据清单——" +
			"worker 任务中验证成功的凭据自动落库(source=discovered),也有手工登记的。带凭据原文(明文),可用于后续连接复用。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"kind":       map[string]any{"type": "string", "description": "类型过滤(ssh/postgres/mysql/redis/mongodb/elasticsearch/smb/winrm/ldap/vnc/ftp/proxy/tunnel/webshell;空=全部)"},
				"project_id": map[string]any{"type": "integer", "description": "项目过滤(缺省=当前挂载项目;0 且无上下文=全部)"},
			},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Concurrent:  func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Kind      string `json:"kind"`
				ProjectID int64  `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			projectID := s.roeProjectID(ctx, in.ProjectID)
			rows, err := s.m.pg.ListConnections(ctx, projectID, strings.TrimSpace(in.Kind), 200)
			if err != nil {
				return actool.Errorf("db: " + err.Error()), nil
			}
			if len(rows) == 0 {
				return actool.Text("连接台账为空(该过滤集)。"), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "连接台账 %d 条:\n", len(rows))
			for _, c := range rows {
				pw := c.Secret
				if pw == "" {
					pw = "(无)"
				}
				fmt.Fprintf(&b, "- [#%d] %s %s@%s:%d 口令:%s status=%s source=%s",
					c.ID, c.Kind, c.Username, c.Host, c.Port, pw, c.Status, c.Source)
				if c.ProjectName != "" {
					fmt.Fprintf(&b, " (项目:%s)", c.ProjectName)
				}
				if len(c.Extra) > 2 && string(c.Extra) != "{}" {
					fmt.Fprintf(&b, " extra=%s", string(c.Extra))
				}
				b.WriteString("\n")
			}
			return actool.Text(b.String()), nil
		},
	})
}

// toolCredentialRegister 手工登记凭据(可用性未知时 source=manual,status=unknown)。
func (s *Server) toolCredentialRegister() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "credential_register",
		Description: "手工登记凭据到连接台账(项目必挂):用于从文件/输出/漏洞证据里拿到的、暂未验证的凭据先存底。" +
			"验证请用 credential_verify_* 工具(验证成功也会自动更新台账状态)。" +
			"WebShell 用 kind=webshell 传 url(落点),口令放 secret,命令/口令参数名放 cmd_param/pass_param(默认 cmd/pass)," +
			"协议细节放 shell_type(jsp/php/asp/aspx)、protocol(plain/behinder/godzilla)。" +
			"其它类型的附加字段(数据库名 database、域 domain、共享 share 等)放 extra。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"kind":       map[string]any{"type": "string", "description": "类型(ssh/postgres/mysql/redis/mongodb/elasticsearch/smb/winrm/ldap/vnc/ftp/proxy/tunnel/webshell)"},
				"host":       map[string]any{"type": "string", "description": "主机;kind=webshell 时可直接给落点 URL(等价于 url)"},
				"port":       map[string]any{"type": "integer"},
				"username":   map[string]any{"type": "string"},
				"secret":     map[string]any{"type": "string", "description": "密码/私钥/令牌;WebShell 的 shell 口令"},
				"note":       map[string]any{"type": "string", "description": "来源说明(从哪发现的)"},
				"project_id": map[string]any{"type": "integer", "description": "项目(缺省=当前挂载)"},
				"url":        map[string]any{"type": "string", "description": "WebShell 落点 URL(kind=webshell 必填)"},
				"cmd_param":  map[string]any{"type": "string", "description": "WebShell 命令参数名(默认 cmd)"},
				"pass_param": map[string]any{"type": "string", "description": "WebShell 口令参数名(默认 pass)"},
				"method":     map[string]any{"type": "string", "description": "WebShell 请求方法(GET/POST,默认 GET)"},
				"shell_type": map[string]any{"type": "string", "description": "WebShell 语言(jsp/php/asp/aspx;缺省按落点扩展名推断)"},
				"protocol":   map[string]any{"type": "string", "description": "WebShell 流量协议(plain/behinder/godzilla;默认 plain)"},
				"extra":      map[string]any{"type": "object", "description": "kind 专属附加字段(database/domain/share/sslmode 等)"},
			},
			"required": []string{"kind"},
		},
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Kind      string         `json:"kind"`
				Host      string         `json:"host"`
				Port      int            `json:"port"`
				Username  string         `json:"username"`
				Secret    string         `json:"secret"`
				Note      string         `json:"note"`
				ProjectID int64          `json:"project_id"`
				URL       string         `json:"url"`
				CmdParam  string         `json:"cmd_param"`
				PassParam string         `json:"pass_param"`
				Method    string         `json:"method"`
				ShellType string         `json:"shell_type"`
				Protocol  string         `json:"protocol"`
				Extra     map[string]any `json:"extra"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			projectID := s.roeProjectID(ctx, in.ProjectID)
			if projectID <= 0 {
				return actool.Errorf("需要项目上下文:在对话/任务上挂载项目,或传 project_id"), nil
			}
			kind := strings.ToLower(strings.TrimSpace(in.Kind))
			conn := &db.Connection{
				ProjectID: projectID, Kind: kind, Host: strings.TrimSpace(in.Host), Port: in.Port,
				Username: in.Username, Secret: in.Secret, Source: "manual", Status: "unknown", Note: in.Note,
			}
			if kind == "webshell" {
				// URL 型目标:落点才是身份,host/port 由 URL 推导。允许 agent 把
				// URL 直接塞进 host(它的直觉就是"主机")。
				rawURL := strings.TrimSpace(in.URL)
				if rawURL == "" && strings.Contains(in.Host, "://") {
					rawURL = strings.TrimSpace(in.Host)
				}
				if rawURL == "" {
					return actool.Errorf("kind=webshell 需要 url(落点 URL)"), nil
				}
				built, berr := newWebshellConnection(rawURL, webshellParams{
					Password: in.Secret, CmdParam: in.CmdParam, PassParam: in.PassParam,
					Method: in.Method, ShellType: in.ShellType, Protocol: in.Protocol,
				})
				if berr != nil {
					return actool.Errorf(berr.Error()), nil
				}
				conn.Kind, conn.Host, conn.Port = built.Kind, built.Host, built.Port
				conn.Extra = built.Extra
			} else {
				if conn.Host == "" {
					return actool.Errorf("host 必填"), nil
				}
				if conn.Port <= 0 {
					conn.Port = db.DefaultConnectionPort(kind)
				}
				if len(in.Extra) > 0 {
					raw, merr := json.Marshal(in.Extra)
					if merr != nil {
						return actool.Errorf("extra 序列化失败: " + merr.Error()), nil
					}
					conn.Extra = raw
				}
			}
			id, created, err := s.m.pg.UpsertConnection(ctx, conn)
			if err != nil {
				return actool.Errorf("db: " + err.Error()), nil
			}
			verb := "更新"
			if created {
				verb = "登记"
			}
			return actool.Text(fmt.Sprintf("已%s连接台账 #%d(项目 %d)。可用 credential_verify_ssh/db 验证有效性。", verb, id, projectID)), nil
		},
	})
}

// ---------- HTTP: 连接管理页 ----------

func (s *Server) connList(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	pid, _ := strconv.ParseInt(r.URL.Query().Get("project_id"), 10, 64)
	rows, err := pg.ListConnections(r.Context(), pid, strings.TrimSpace(r.URL.Query().Get("kind")), 500)
	if err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"connections": rows})
}

func (s *Server) connCreate(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var in db.Connection
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if in.ProjectID <= 0 || strings.TrimSpace(in.Kind) == "" || strings.TrimSpace(in.Host) == "" {
		writeErr(w, 400, "project_id/kind/host 必填")
		return
	}
	if in.Port <= 0 {
		in.Port = db.DefaultConnectionPort(in.Kind)
	}
	in.Kind = strings.ToLower(strings.TrimSpace(in.Kind))
	if in.Source == "" {
		in.Source = "manual"
	}
	// status 有 CHECK 约束(unknown/alive/dead),空串会被库直接拒掉——新增表单
	// 不带状态,这里必须补默认值,否则「新增凭据」按钮必然失败。
	if in.Status == "" {
		in.Status = "unknown"
	}
	id, _, err := pg.UpsertConnection(r.Context(), &in)
	if err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": id})
}

func (s *Server) connDelete(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	if err := pg.DeleteConnection(r.Context(), id); err != nil {
		writeErr(w, 500, "db: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

// toolConnections 连接台账工具族。
func (s *Server) connTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolConnectionsList(),
		s.toolCredentialRegister(),
	}
}
