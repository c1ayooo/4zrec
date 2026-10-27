package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// WinRMOpener opens a Windows Remote Management foothold. WinRM is a SOAP
// protocol over HTTP(S), so it rides the host's core.HTTPDoer port: scope,
// rate limiting and audit apply to every WSMan call exactly as they do to any
// other HTTP request (docs §3.1: sessionkit owns SSH/WinRM/SMB/CLI transports).
//
// Authentication is HTTP Basic over a TLS endpoint by default, which is the
// documented "unencrypted on 5986/TLS" setup. Hosts that need NTLM/Kerberos
// terminate the auth in their HTTPDoer (a proxying Doer) and pass the target
// URL through unchanged.
type WinRMOpener struct {
	// HTTP is required and must be the gate-aware client.
	HTTP core.HTTPDoer
	// TLS selects https (5986) over http (5985).
	TLS bool
	// Port overrides the default for the chosen scheme.
	Port int
	// OperationTimeoutMS bounds one WSMan call; default 60000.
	OperationTimeoutMS int
}

// Open creates a remote shell on the target and returns a session bound to it.
func (o *WinRMOpener) Open(ctx context.Context, spec core.SessionSpec) (core.Session, error) {
	if o.HTTP == nil {
		return nil, core.Unavailable("WinRM 需要 HTTPDoer 端口（scope+rate+audit 网关）")
	}
	scheme := "http"
	port := 5985
	if o.TLS {
		scheme, port = "https", 5986
	}
	if spec.Port > 0 {
		port = spec.Port
	}
	if o.Port > 0 {
		port = o.Port
	}
	endpoint := fmt.Sprintf("%s://%s:%d/wsman", scheme, hostFor(spec.Host), port)

	s := &WinRMSession{
		http:     o.HTTP,
		endpoint: endpoint,
		auth:     basicAuth(spec.Domain, spec.User, spec.Secret),
		timeout:  time.Duration(core.FirstPositive(o.OperationTimeoutMS, 60000)) * time.Millisecond,
		info: core.SessionInfo{
			Kind: "winrm", Host: spec.Host, Port: port, User: spec.User,
			OS: "windows", Labels: spec.Labels,
			Meta: map[string]string{"endpoint": endpoint, "auth": "basic"},
		},
	}
	if spec.Timeout > 0 && spec.Timeout < s.timeout {
		s.timeout = spec.Timeout
	}
	// Fail fast: an unreachable or unauthorized target should not look like an
	// opened session.
	if err := s.createShell(ctx); err != nil {
		return nil, err
	}
	if s.shellID == "" {
		return nil, fmt.Errorf("WinRM 会话创建失败：响应缺少 ShellId")
	}
	s.info.Meta["shell_id"] = s.shellID
	return s, nil
}

// WinRMSession is a live WinRM foothold. Each Exec runs cmd.exe /c through the
// remote shell.
type WinRMSession struct {
	http     core.HTTPDoer
	endpoint string
	auth     string
	timeout  time.Duration
	shellID  string
	info     core.SessionInfo
}

func (s *WinRMSession) Info() core.SessionInfo { return s.info }

// Close deletes the remote shell; the WinRM protocol has no connection to drop.
func (s *WinRMSession) Close() error {
	if s.shellID == "" {
		return nil
	}
	if _, err := s.call(context.Background(), "<rsp:Delete/>", 20*time.Second); err != nil {
		return err
	}
	s.shellID = ""
	return nil
}

// Exec runs a command line through cmd.exe /c and returns its output.
func (s *WinRMSession) Exec(ctx context.Context, cmd string, opts core.ExecOpts) (core.Output, error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return core.Output{}, fmt.Errorf("命令为空")
	}
	if s.shellID == "" {
		return core.Output{}, fmt.Errorf("WinRM 会话已关闭")
	}
	timeout := s.timeout
	if opts.Timeout > 0 && opts.Timeout < timeout {
		timeout = opts.Timeout
	}
	if opts.Dir != "" {
		cmd = "cd /d " + opts.Dir + " && " + cmd
	}
	started := time.Now()

	shell := core.FirstNonEmpty(opts.Shell, "cmd.exe")
	runBody := "<rsp:CommandLine><rsp:Command>" + xmlEscape(shell) +
		"</rsp:Command><rsp:Arguments>/c " + xmlEscape(cmd) + "</rsp:Arguments></rsp:CommandLine>"
	resp, err := s.call(ctx, runBody, timeout)
	if err != nil {
		return core.Output{}, err
	}
	if f := resp.Body.Fault; f.Reason != "" || f.Code != "" {
		return core.Output{}, core.UpstreamError("WinRM fault: " + core.FirstNonEmpty(f.Reason, f.Code))
	}
	commandID := resp.Body.CommandResponse.CommandID
	if commandID == "" {
		return core.Output{}, fmt.Errorf("WinRM 未返回 CommandId")
	}

	var stdout, stderr bytes.Buffer
	exit := 0
	done := false
	// WSMan streams output in chunks; poll until the command reports Done.
	for i := 0; i < 128 && !done; i++ {
		recvBody := `<rsp:Receive><rsp:DesiredStream CommandId="` + xmlEscape(commandID) + `">stdout stderr</rsp:DesiredStream></rsp:Receive>`
		rr, rerr := s.call(ctx, recvBody, timeout)
		if rerr != nil {
			return core.Output{}, rerr
		}
		st := rr.Body.ReceiveResponse
		for _, stream := range st.Streams {
			chunk, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(stream.Text))
			if derr != nil {
				continue
			}
			if stream.Name == "stderr" {
				stderr.Write(chunk)
			} else {
				stdout.Write(chunk)
			}
		}
		if st.CommandState.ExitCode != nil {
			exit = *st.CommandState.ExitCode
		}
		if isCommandDone(st.CommandState.State) {
			done = true
		}
	}
	dur := time.Since(started)
	if !done {
		out := core.OutputFor(cmd, stdout.String(), stderr.String(), exit, dur, opts.MaxOutput)
		out.Truncated = true
		return out, fmt.Errorf("WinRM 命令未在轮询预算内结束（command_id=%s）", commandID)
	}
	return core.OutputFor(cmd, stdout.String(), stderr.String(), exit, dur, opts.MaxOutput), nil
}

// --- WSMan plumbing ---

const (
	resourceURI = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"
	wsmanNS     = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
	shellNS     = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
	soapNS      = "http://www.w3.org/2003/05/soap-envelope"
)

func (s *WinRMSession) createShell(ctx context.Context) error {
	body := "<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams>" +
		"<rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>"
	resp, err := s.call(ctx, body, s.timeout)
	if err != nil {
		return err
	}
	if f := resp.Body.Fault; f.Reason != "" || f.Code != "" {
		return core.UpstreamError("WinRM fault: " + core.FirstNonEmpty(f.Reason, f.Code))
	}
	s.shellID = resp.Body.Shell.ShellID
	return nil
}

// call wraps body in a WSMan envelope (with the shell selector when a shell is
// live) and posts it.
func (s *WinRMSession) call(ctx context.Context, body string, timeout time.Duration) (*wsmanEnvelope, error) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<s:Envelope xmlns:s="` + soapNS + `" xmlns:rsp="` + shellNS + `" xmlns:wsman="` + wsmanNS + `">`)
	b.WriteString(`<s:Header><wsman:ResourceURI s:mustUnderstand="true">` + resourceURI + `</wsman:ResourceURI>`)
	if s.shellID != "" {
		b.WriteString(`<wsman:SelectorSet><wsman:Selector Name="ShellId">` + xmlEscape(s.shellID) + `</wsman:Selector></wsman:SelectorSet>`)
	}
	b.WriteString(`<wsman:OperationTimeout>PT` + strconv.Itoa(int(timeout/time.Second)) + `S</wsman:OperationTimeout>`)
	b.WriteString(`</s:Header><s:Body>` + body + `</s:Body></s:Envelope>`)

	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	if ctx == nil {
		ctx = context.Background()
	}
	headers := map[string]string{"Content-Type": `application/soap+xml;charset=UTF-8`}
	if s.auth != "" {
		headers["Authorization"] = s.auth
	}
	resp, err := s.http.Do(ctx, core.Request{
		Method: "POST", URL: s.endpoint, Headers: headers,
		Body: []byte(b.String()), Timeout: timeout,
	})
	if err != nil {
		return nil, err
	}
	if resp.Status >= 400 {
		return nil, core.UpstreamError(fmt.Sprintf("WinRM HTTP %d: %s", resp.Status, core.Truncate(string(resp.Body), 200)))
	}
	var out wsmanEnvelope
	if err := xml.Unmarshal(resp.Body, &out); err != nil {
		return nil, core.UpstreamError("WinRM 响应无法解析: " + err.Error())
	}
	return &out, nil
}

// wsmanEnvelope decodes the parts of a WSMan SOAP reply the session needs. The
// decoder matches on local names, so the rsp:/wsman:/s: prefixes are irrelevant.
type wsmanEnvelope struct {
	Body struct {
		Shell struct {
			ShellID string `xml:"ShellId"`
		} `xml:"Shell"`
		CommandResponse struct {
			CommandID string `xml:"CommandId"`
		} `xml:"CommandResponse"`
		ReceiveResponse struct {
			Streams []struct {
				Name string `xml:"Name,attr"`
				Text string `xml:",chardata"`
			} `xml:"Stream"`
			CommandState struct {
				State    string `xml:"State,attr"`
				ExitCode *int   `xml:"ExitCode"`
			} `xml:"CommandState"`
		} `xml:"ReceiveResponse"`
		Fault struct {
			Code   string `xml:"Code>Value"`
			Reason string `xml:"Reason>Text"`
		} `xml:"Fault"`
	} `xml:"Body"`
}

func isCommandDone(state string) bool {
	return strings.HasSuffix(strings.TrimSpace(state), "/Done")
}

func basicAuth(domain, user, secret string) string {
	if user == "" && secret == "" {
		return ""
	}
	if domain != "" {
		user = domain + `\` + user
	}
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+secret))
}

func hostFor(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	if i := strings.IndexAny(host, "/:"); i >= 0 {
		host = host[:i]
	}
	return host
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
