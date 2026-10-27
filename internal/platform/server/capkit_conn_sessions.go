package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	capkit "github.com/c1ayooo/4zrec/internal/capkit/core"

	"github.com/c1ayooo/4zrec/internal/capkitbridge"
	"github.com/c1ayooo/4zrec/internal/domain/db"
)

var (
	errLedgerConnectionNotFound = errors.New("台账里没有这条连接(检查项目归属)")
	errLedgerConnectionNoURL    = errors.New("该 WebShell 连接没填 URL(extra.url)")
)

// 从连接台账开会话。
//
// 凭据录一次,两处可用:台账页的控制台(一次性手工操作)和终端页的会话(持续操作、
// 带证据)。这条接口把台账行翻成 session_open 的入参,因此会话走的是同一条
// 门禁链(scope/审批/限速/审计),而不是另开一条旁路。
//
// 会话归属:台账行属于哪个项目,会话就归哪个项目——capkit 的 session manager
// 是进程级的,项目归属是宿主按 CallContext 记录的。

type capkitSessionFromConn struct {
	// ConnectionID 台账行 id;ID 或 Kind+Host 至少给一个。
	ConnectionID int64 `json:"connection_id"`
	Kind         string
	Host         string
}

// capkitSessionFromConnection opens (or reuses) a session for a ledger row.
//
//	POST /api/capkit/sessions/from-connection
func (s *Server) capkitSessionFromConnection(w http.ResponseWriter, r *http.Request) {
	bridge := s.capkitBridgeOrNil()
	if bridge == nil {
		writeErr(w, http.StatusServiceUnavailable, "capkit 桥接未启用")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var in capkitSessionFromConn
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	conn, err := s.resolveLedgerConnection(r, in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// 已开过就直接复用:同一条凭据反复开会话会在终端页堆出一串重复条目,
	// 而且每个会话都要过一次审批。
	if id := s.liveSessionFor(bridge, conn); id != "" {
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "reused": true})
		return
	}

	openInput, err := sessionOpenInputFor(conn)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// 归属跟着台账行走,而不是请求的 scope:项目级 Key 只能打开本项目的凭据,
	// 全局调用者打开时会话归台账行所属项目。
	cc := capkit.CallContext{ProjectID: conn.ProjectID, Actor: capkitActor(r)}
	res, err := bridge.Call(r.Context(), "session_open", openInput, cc)
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
	}
	_ = json.Unmarshal(res.Data, &out)
	if out.SessionID == "" {
		writeErr(w, http.StatusBadGateway, "session_open 未返回 session_id")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": out.SessionID, "reused": false})
}

// resolveLedgerConnection finds the ledger row the caller means: by id when
// given, otherwise by kind+host. Only rows the caller may see are accepted.
func (s *Server) resolveLedgerConnection(r *http.Request, in capkitSessionFromConn) (*db.Connection, error) {
	rows, err := s.m.pg.ListConnections(r.Context(), scopedProjectID(r.Context()), "", 500)
	if err != nil {
		return nil, err
	}
	for _, c := range rows {
		if in.ConnectionID > 0 {
			if c.ID == in.ConnectionID {
				return c, nil
			}
			continue
		}
		if in.Kind != "" && strings.EqualFold(c.Kind, in.Kind) && c.Host == in.Host {
			return c, nil
		}
	}
	return nil, errLedgerConnectionNotFound
}

// liveSessionFor returns an existing session id for the same target, so the
// console does not open a duplicate foothold per click.
func (s *Server) liveSessionFor(bridge *capkitbridge.Bridge, c *db.Connection) string {
	for _, info := range bridge.LiveSessions(c.ProjectID) {
		if info.Kind == c.Kind && info.Host == c.Host {
			return info.ID
		}
	}
	return ""
}

// sessionOpenInputFor maps a ledger row onto session_open's payload.
func sessionOpenInputFor(c *db.Connection) (json.RawMessage, error) {
	kind := strings.ToLower(strings.TrimSpace(c.Kind))
	in := map[string]any{
		"kind":   kind,
		"host":   c.Host,
		"user":   c.Username,
		"secret": c.Secret,
	}
	if c.Port > 0 {
		in["port"] = c.Port
	}
	var extra struct {
		URL       string            `json:"url"`
		CmdParam  string            `json:"cmd_param"`
		PassParam string            `json:"pass_param"`
		Method    string            `json:"method"`
		Proxy     string            `json:"proxy"`
		ShellType string            `json:"shell_type"`
		Protocol  string            `json:"protocol"`
		Database  string            `json:"database"`
		SSLMode   string            `json:"sslmode"`
		Extra     map[string]string `json:"-"`
	}
	if c.Extra != nil {
		_ = json.Unmarshal(c.Extra, &extra)
	}
	switch kind {
	case "webshell":
		if extra.URL == "" {
			return nil, errLedgerConnectionNoURL
		}
		in["host"] = extra.URL
		delete(in, "port")
		delete(in, "user")
		opts := map[string]string{}
		if extra.CmdParam != "" {
			opts["cmd_param"] = extra.CmdParam
		}
		if extra.PassParam != "" {
			opts["pass_param"] = extra.PassParam
		}
		if extra.Method != "" {
			opts["method"] = extra.Method
		}
		if extra.ShellType != "" {
			opts["shell_type"] = extra.ShellType
		}
		if extra.Protocol != "" {
			opts["protocol"] = extra.Protocol
		}
		if extra.Proxy != "" {
			opts["proxy"] = extra.Proxy
		}
		in["options"] = opts
	case "mysql", "postgres":
		opts := map[string]string{}
		if extra.Database != "" {
			opts["database"] = extra.Database
		}
		if extra.SSLMode != "" {
			opts["sslmode"] = extra.SSLMode
		}
		if len(opts) > 0 {
			in["options"] = opts
		}
	case "smb":
		if share := strings.TrimSpace(extraFromMap(c.Extra, "share")); share != "" {
			in["options"] = map[string]string{"share": share}
		}
	}
	return json.Marshal(in)
}

// extraFromMap reads one string key from a raw JSON object.
func extraFromMap(raw json.RawMessage, key string) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]string
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	return m[key]
}
