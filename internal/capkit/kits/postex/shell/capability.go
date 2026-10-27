package shell

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Capability exposes foothold management and session operations as tools.
// Everything routes through core.SessionManager, so a WebShell, SSH or WinRM
// session is used identically.
type Capability struct {
	deps core.Deps
	// deployer is the host boundary for webshell_deploy. It is optional: a host
	// that only drives existing sessions leaves it nil, and the tool reports
	// tool_missing rather than pretending to have a delivery channel.
	deployer WebShellDeployer
}

// NewCapability builds the session capability.
func NewCapability(deps core.Deps) (core.Capability, error) {
	return &Capability{deps: deps}, nil
}

// NewCapabilityWithDeployer builds the session capability with a host-supplied
// delivery channel, which is what enables webshell_deploy. The deployer cannot
// ride in core.Deps because it is shellkit-specific (the same reason
// enterprisekit takes its resolver separately).
func NewCapabilityWithDeployer(deps core.Deps, deployer WebShellDeployer) (core.Capability, error) {
	return &Capability{deps: deps, deployer: deployer}, nil
}

// Manifest declares the session and delivery tools.
func Manifest() core.Manifest {
	return core.Manifest{
		Name: "shellkit", Version: "0.3.0", APIVersion: "v1",
		Requires: []string{"scope", "limiter", "audit", "sessions"},
		Tools: []core.ToolSpec{
			sessionOpenSpec(), sessionExecSpec(), sessionUploadSpec(),
			sessionDownloadSpec(), tunnelOpenSpec(), sessionListSpec(), sessionCloseSpec(),
			webshellDeploySpec(),
		},
	}
}

// Manifest implements core.Capability.
func (c *Capability) Manifest() core.Manifest { return Manifest() }

// Call dispatches the session tools.
func (c *Capability) Call(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "session_open":
		return c.open(ctx, call)
	case "session_exec":
		return c.exec(ctx, call)
	case "session_upload":
		return c.upload(ctx, call)
	case "session_download":
		return c.download(ctx, call)
	case "tunnel_open":
		return c.tunnel(ctx, call)
	case "session_list":
		return c.list(ctx, call)
	case "session_close":
		return c.close(ctx, call)
	case "webshell_deploy":
		return c.deploy(ctx, call)
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (c *Capability) manager() (core.SessionManager, *core.Error) {
	if c.deps.Sessions == nil {
		return nil, core.ToolMissing("SessionManager 未注入（宿主需提供 core.Deps.Sessions）")
	}
	return c.deps.Sessions, nil
}

// --- tool specs ---

func sessionOpenSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "session_open",
		Description: "打开一个后渗透会话（ssh/winrm/smb/cli/webshell）。kind 决定使用哪个 SessionOpener，secret 为密码或私钥，webshell 的 shell 参数放 options。成功返回 session_id，供 session_exec 等工具复用。",
		Risk:        core.RiskHigh,
		RateLimit:   core.RateLimitSpec{PerSecond: 2, Burst: 2, Concurrency: 1},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "kind":{"type":"string","enum":["ssh","winrm","smb","cli","webshell"]},
    "host":{"type":"string","description":"主机或 URL"},
    "port":{"type":"integer"},
    "user":{"type":"string"},
    "secret":{"type":"string","description":"密码或 PEM 私钥"},
    "domain":{"type":"string"},
    "protocol":{"type":"string"},
    "proxy":{"type":"string"},
    "timeout_ms":{"type":"integer"},
    "labels":{"type":"array","items":{"type":"string"}},
    "options":{"type":"object","additionalProperties":{"type":"string"}}
  },
  "required":["kind","host"]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{"session_id":{"type":"string"},"kind":{"type":"string"},"host":{"type":"string"},"user":{"type":"string"},"os":{"type":"string"},"elevated":{"type":"boolean"}}
}`),
		ExtractTargets: func(input json.RawMessage) ([]core.Target, error) {
			var in struct {
				Host string `json:"host"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return nil, err
			}
			if strings.TrimSpace(in.Host) == "" {
				return nil, fmt.Errorf("host 必填")
			}
			return core.TargetsFromStrings(0, []string{in.Host})
		},
	}
}

func sessionExecSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "session_exec",
		Description: "在一个已打开的会话里执行单条命令并回显。返回 stdout/stderr/exit_code，原始交换作为证据记录。",
		Risk:        core.RiskHigh,
		RateLimit:   core.RateLimitSpec{PerSecond: 5, Burst: 3, Concurrency: 2},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string"},
    "command":{"type":"string"},
    "timeout_ms":{"type":"integer"},
    "dir":{"type":"string"},
    "max_output":{"type":"integer"}
  },
  "required":["session_id","command"]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{"command":{"type":"string"},"stdout":{"type":"string"},"stderr":{"type":"string"},"exit_code":{"type":"integer"},"duration_ms":{"type":"integer"},"truncated":{"type":"boolean"},"evidence_id":{"type":"string"}}
}`),
	}
}

func sessionUploadSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "session_upload",
		Description: "把内容（base64 或文本）写入会话对端文件。仅在会话实现 Uploader 时可用，否则报 tool_missing。",
		Risk:        core.RiskHigh,
		RateLimit:   core.RateLimitSpec{PerSecond: 3, Burst: 2, Concurrency: 1},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string"},
    "remote":{"type":"string"},
    "content_base64":{"type":"string"},
    "content":{"type":"string","description":"纯文本内容，content_base64 缺省时使用"}
  },
  "required":["session_id","remote"]
}`),
		OutputSchema: json.RawMessage(`{"type":"object","properties":{"remote":{"type":"string"},"bytes":{"type":"integer"},"ok":{"type":"boolean"}}}`),
	}
}

func sessionDownloadSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "session_download",
		Description: "读取会话对端文件。文件内容进证据库并以 EvidenceRef 返回（含 size/sha256/≤200 字 preview），Data 只带引用与哈希，不内联正文；仅在会话实现 Downloader 时可用。",
		Risk:        core.RiskHigh,
		RateLimit:   core.RateLimitSpec{PerSecond: 3, Burst: 2, Concurrency: 1},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string"},
    "remote":{"type":"string"},
    "max_bytes":{"type":"integer","description":"默认 6144"}
  },
  "required":["session_id","remote"]
}`),
		OutputSchema: json.RawMessage(`{"type":"object","properties":{"remote":{"type":"string"},"bytes":{"type":"integer"},"sha256":{"type":"string"},"evidence_id":{"type":"string","description":"证据库引用 id；未接证据池时为空"},"truncated":{"type":"boolean"}}}`),
	}
}

func tunnelOpenSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "tunnel_open",
		Description: "通过会话打开一条隧道（当前支持 remote 直连语义）。返回本地地址供后续使用。仅在会话实现 Tunneler 时可用。",
		Risk:        core.RiskHigh,
		RateLimit:   core.RateLimitSpec{PerSecond: 3, Burst: 2, Concurrency: 1},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string"},
    "remote_addr":{"type":"string","description":"host:port"},
    "local_addr":{"type":"string"},
    "network":{"type":"string","enum":["tcp","udp"]}
  },
  "required":["session_id","remote_addr"]
}`),
		OutputSchema: json.RawMessage(`{"type":"object","properties":{"local_addr":{"type":"string"},"remote_addr":{"type":"string"}}}`),
	}
}

func sessionListSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:         "session_list",
		Description:  "列出当前所有存活会话的元信息。只读。",
		Risk:         core.RiskLow,
		InputSchema:  json.RawMessage(`{"type":"object","properties":{}}`),
		OutputSchema: json.RawMessage(`{"type":"object","properties":{"count":{"type":"integer"},"sessions":{"type":"array","items":{"type":"object"}}}}`),
	}
}

func sessionCloseSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:         "session_close",
		Description:  "关闭并释放一个会话。幂等：关闭不存在的 id 也返回成功。",
		Risk:         core.RiskLow,
		InputSchema:  json.RawMessage(`{"type":"object","properties":{"session_id":{"type":"string"}},"required":["session_id"]}`),
		OutputSchema: json.RawMessage(`{"type":"object","properties":{"session_id":{"type":"string"},"closed":{"type":"boolean"}}}`),
	}
}

// --- handlers ---

func (c *Capability) open(ctx context.Context, call core.Call) (core.Result, error) {
	mgr, e := c.manager()
	if e != nil {
		return core.FailResult(e), nil
	}
	var in struct {
		Kind      string            `json:"kind"`
		Host      string            `json:"host"`
		Port      int               `json:"port"`
		User      string            `json:"user"`
		Secret    string            `json:"secret"`
		Domain    string            `json:"domain"`
		Protocol  string            `json:"protocol"`
		Proxy     string            `json:"proxy"`
		TimeoutMS int               `json:"timeout_ms"`
		Labels    []string          `json:"labels"`
		Options   map[string]string `json:"options"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	spec := core.SessionSpec{
		Kind: in.Kind, Host: in.Host, Port: in.Port, User: in.User, Secret: in.Secret,
		Domain: in.Domain, Protocol: in.Protocol, ProxyURL: in.Proxy,
		Timeout: time.Duration(in.TimeoutMS) * time.Millisecond,
		Labels:  in.Labels, Options: in.Options,
	}
	info, err := mgr.Open(ctx, spec)
	if err != nil {
		return core.FailResult(core.TargetUnreachable(err.Error())), nil
	}
	res, _ := core.SuccessResult(
		fmt.Sprintf("已打开 %s 会话 %s（%s）", info.Kind, info.ID, info.Host),
		map[string]any{
			"session_id": info.ID, "kind": info.Kind, "host": info.Host,
			"user": info.User, "os": info.OS, "elevated": info.Elevated,
		},
	)
	return res, nil
}

func (c *Capability) exec(ctx context.Context, call core.Call) (core.Result, error) {
	mgr, e := c.manager()
	if e != nil {
		return core.FailResult(e), nil
	}
	var in struct {
		SessionID string `json:"session_id"`
		Command   string `json:"command"`
		TimeoutMS int    `json:"timeout_ms"`
		Dir       string `json:"dir"`
		MaxOutput int    `json:"max_output"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	s, ok := mgr.Get(in.SessionID)
	if !ok {
		return core.FailResult(core.NotFound("会话不存在: " + in.SessionID)), nil
	}
	out, err := s.Exec(ctx, in.Command, core.ExecOpts{
		Timeout: time.Duration(in.TimeoutMS) * time.Millisecond,
		Dir:     in.Dir, MaxOutput: core.FirstPositive(in.MaxOutput, 64<<10),
	})
	if err != nil {
		return core.FailResult(core.UpstreamError(err.Error())), nil
	}
	data, _ := core.DataResult(out)
	data.Summary = core.ClampSummary(fmt.Sprintf("会话 %s 执行完毕（exit %d，%d 字节）", in.SessionID, out.ExitCode, len(out.Stdout)))
	if out.EvidenceID != "" {
		// The transport stored the traffic itself and handed back its id.
		data.Evidence = []core.EvidenceRef{{ID: out.EvidenceID, Kind: "command_output", Size: len(out.Stdout)}}
	} else if ref := c.recordOutput(ctx, "session_exec", in.SessionID, out.Stdout, out.Stderr); ref.Size > 0 {
		// The transport has no store of its own, so the tool stores the output:
		// Data keeps the clamped view and the ref points at the full text.
		data.Evidence = []core.EvidenceRef{ref}
	}
	return data, nil
}

// recordOutput describes command output as evidence, storing it when an
// evidence sink is injected. The reference always carries size/sha256/preview;
// its ID is empty when there is no sink, so the caller can tell "stored" from
// "known but not persisted".
func (c *Capability) recordOutput(ctx context.Context, tool, sessionID string, stdout, stderr string) core.EvidenceRef {
	body := stdout
	if stderr != "" {
		body += "\n--- stderr ---\n" + stderr
	}
	if body == "" {
		return core.EvidenceRef{}
	}
	sum := sha256.Sum256([]byte(body))
	ref := core.EvidenceRef{
		Kind: "command_output", Size: len(body),
		SHA256: hex.EncodeToString(sum[:]), Preview: core.PreviewRunes(body, 200),
	}
	if c.deps.Evidence == nil {
		return ref
	}
	id, err := c.deps.Evidence.Record(ctx, core.Evidence{
		Kind: "command_output", Title: tool + " " + sessionID,
		Response: []byte(body), CreatedAt: time.Now(),
		Metadata: map[string]string{"tool": tool, "session_id": sessionID},
	})
	if err == nil && id != "" {
		ref.ID = id
	}
	return ref
}

func (c *Capability) upload(ctx context.Context, call core.Call) (core.Result, error) {
	mgr, e := c.manager()
	if e != nil {
		return core.FailResult(e), nil
	}
	var in struct {
		SessionID     string `json:"session_id"`
		Remote        string `json:"remote"`
		ContentBase64 string `json:"content_base64"`
		Content       string `json:"content"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	s, ok := mgr.Get(in.SessionID)
	if !ok {
		return core.FailResult(core.NotFound("会话不存在: " + in.SessionID)), nil
	}
	up, ok := s.(core.Uploader)
	if !ok {
		return core.FailResult(core.ToolMissing("该会话不支持 Upload")), nil
	}
	data := []byte(in.Content)
	if in.ContentBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(in.ContentBase64)
		if err != nil {
			return core.FailResult(core.InvalidInput("content_base64 解码失败: " + err.Error())), nil
		}
		data = decoded
	}
	if err := up.Upload(ctx, strings.NewReader(string(data)), in.Remote); err != nil {
		return core.FailResult(core.UpstreamError(err.Error())), nil
	}
	res, _ := core.SuccessResult(fmt.Sprintf("已写入 %s（%d 字节）", in.Remote, len(data)), map[string]any{
		"remote": in.Remote, "bytes": len(data), "ok": true,
	})
	return res, nil
}

func (c *Capability) download(ctx context.Context, call core.Call) (core.Result, error) {
	mgr, e := c.manager()
	if e != nil {
		return core.FailResult(e), nil
	}
	var in struct {
		SessionID string `json:"session_id"`
		Remote    string `json:"remote"`
		MaxBytes  int    `json:"max_bytes"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	s, ok := mgr.Get(in.SessionID)
	if !ok {
		return core.FailResult(core.NotFound("会话不存在: " + in.SessionID)), nil
	}
	dl, ok := s.(core.Downloader)
	if !ok {
		return core.FailResult(core.ToolMissing("该会话不支持 Download")), nil
	}
	rc, err := dl.Download(ctx, in.Remote)
	if err != nil {
		return core.FailResult(core.UpstreamError(err.Error())), nil
	}
	defer func() { _ = rc.Close() }()
	limit := core.FirstPositive(in.MaxBytes, 6144)
	buf, err := io.ReadAll(io.LimitReader(rc, int64(limit)+1))
	if err != nil {
		return core.FailResult(core.UpstreamError(err.Error())), nil
	}
	truncated := len(buf) > limit
	if truncated {
		buf = buf[:limit]
	}
	sum := sha256.Sum256(buf)
	sumHex := hex.EncodeToString(sum[:])
	// File content never rides in Data (docs §5.5.4): it is stored as evidence
	// and Data carries only the reference plus hashes. Without a sink the ref
	// has no id, so the caller still knows exactly what was read but the bytes
	// stay out of the envelope.
	ref := core.EvidenceRef{
		Kind: "file", Size: len(buf), SHA256: sumHex,
		Preview: core.PreviewRunes(string(buf), 200),
	}
	if c.deps.Evidence != nil {
		if id, rerr := c.deps.Evidence.Record(ctx, core.Evidence{
			Kind: "file", Title: "session_download " + in.Remote,
			Response: buf, CreatedAt: time.Now(),
			Metadata: map[string]string{"remote": in.Remote, "sha256": sumHex},
		}); rerr == nil && id != "" {
			ref.ID = id
		}
	}
	res, _ := core.SuccessResult(fmt.Sprintf("读取 %s（%d 字节%s）", in.Remote, len(buf), truncLabel(truncated)), map[string]any{
		"remote": in.Remote, "bytes": len(buf), "sha256": sumHex,
		"evidence_id": ref.ID, "truncated": truncated,
	})
	res.Evidence = []core.EvidenceRef{ref}
	res.Truncated = truncated
	return res, nil
}

func (c *Capability) tunnel(ctx context.Context, call core.Call) (core.Result, error) {
	mgr, e := c.manager()
	if e != nil {
		return core.FailResult(e), nil
	}
	var in struct {
		SessionID  string `json:"session_id"`
		RemoteAddr string `json:"remote_addr"`
		LocalAddr  string `json:"local_addr"`
		Network    string `json:"network"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	s, ok := mgr.Get(in.SessionID)
	if !ok {
		return core.FailResult(core.NotFound("会话不存在: " + in.SessionID)), nil
	}
	t, ok := s.(core.Tunneler)
	if !ok {
		return core.FailResult(core.ToolMissing("该会话不支持 Tunnel")), nil
	}
	tun, err := t.Tunnel(ctx, core.TunnelSpec{Kind: "remote", RemoteAddr: in.RemoteAddr, LocalAddr: in.LocalAddr, Network: in.Network})
	if err != nil {
		return core.FailResult(core.UpstreamError(err.Error())), nil
	}
	local := tun.LocalAddr()
	res, _ := core.SuccessResult(fmt.Sprintf("隧道已建立 %s → %s", local, in.RemoteAddr), map[string]any{
		"local_addr": local, "remote_addr": in.RemoteAddr,
	})
	return res, nil
}

func (c *Capability) list(ctx context.Context, call core.Call) (core.Result, error) {
	mgr, e := c.manager()
	if e != nil {
		return core.FailResult(e), nil
	}
	infos := mgr.List()
	res, _ := core.SuccessResult(fmt.Sprintf("%d 个存活会话", len(infos)), map[string]any{
		"count": len(infos), "sessions": infos,
	})
	return res, nil
}

func (c *Capability) close(ctx context.Context, call core.Call) (core.Result, error) {
	mgr, e := c.manager()
	if e != nil {
		return core.FailResult(e), nil
	}
	var in struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	if in.SessionID == "" {
		return core.FailResult(core.InvalidInput("session_id 必填")), nil
	}
	if err := mgr.Close(in.SessionID); err != nil {
		return core.FailResult(core.UpstreamError(err.Error())), nil
	}
	res, _ := core.SuccessResult("会话已关闭: "+in.SessionID, map[string]any{
		"session_id": in.SessionID, "closed": true,
	})
	return res, nil
}

func truncLabel(b bool) string {
	if b {
		return "，已截断"
	}
	return ""
}
